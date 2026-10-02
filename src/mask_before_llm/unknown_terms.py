"""辞書に無い固有名詞「候補」を検知して人間に提示する（置換はしない）。

番人辞書(redaction/*.yaml)は既知の固有名しか消せない。新しいプロダクト名や
ブランチ名のように辞書に載っていない語は素通りする。実際に職務経歴書へ
ブランチ名が漏れた事例があり、その多くは「Merge pull request #N from 組織/ブランチ名」
というマージコミット件名が出所だった。

このモジュールは**自動置換しない**。理由は誤検知のコストが非対称だから:
  - 拾いすぎ → 一般技術語(Laravel 等)が消えて記事価値が壊れる。しかも静かに起きる
  - 取りこぼし → 漏洩
自動で消すより「怪しい語を人間に出す」方が安全side。辞書に足すかどうかは人間が決める。

使い方:
  python -m mask_before_llm.unknown_terms --project acme --text-file notes.md
  python -m mask_before_llm.unknown_terms --project acme --weekly   # 直近のコミットログを対象
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .masking import load_project_dict

# 構造的に「固有名を含むことが確定している」パターン。
# これらは候補ではなく確定扱いで強く警告する（実際の漏洩経路だったもの）。
STRUCTURAL_PATTERNS: list[tuple[str, str]] = [
    ("merge_pr_org_branch", r"Merge pull request #\d+ from ([\w.\-]+)/(\S+)"),
    ("merge_branch", r"Merge branch '([^']+)'"),
    ("merge_remote", r"Merge branch '[^']+' of \S+"),
    ("branch_like", r"\b(?:feature|feat|fix|hotfix|release|chore|bugfix|epic)/[A-Za-z0-9._\-]+"),
    ("ticket_id", r"\b[A-Z]{2,10}-\d{1,6}\b"),
]

# ticket_id パターン(大文字-数字)に形が一致してしまう一般技術語の接頭辞。
# UTF-8 / SHA-256 / ISO-8601 のような語を「確定」で出すと exit 1 が日常的に起き、
# 確定枠そのものが信用されなくなる(オオカミ少年化して本物の漏洩が無視される)ので除く。
TICKET_ID_EXCLUDE_PREFIXES = {
    "UTF", "SHA", "MD", "ISO", "RFC", "HTTP", "HTTPS", "GPT", "BASE", "AES", "RSA", "EC",
    "TLS", "SSL", "IPV", "IEEE", "ES", "PEP", "CVE", "ARM", "AMD", "X", "UTC", "GMT",
}

# 一般的な技術語。ここに載っている語は候補から除く（除外しすぎると検知漏れになるので
# 「まず間違いなく一般語」だけを入れる。判断に迷う語は候補に残して人間に見せる）。
COMMON_TECH_WORDS = {
    # 言語・ランタイム
    "python", "javascript", "typescript", "java", "kotlin", "swift", "ruby", "php", "golang", "rust",
    "node", "nodejs", "deno", "bun",
    # フレームワーク
    "django", "flask", "fastapi", "rails", "laravel", "symfony", "spring", "express", "nestjs",
    "react", "vue", "angular", "svelte", "next", "nuxt", "remix", "astro",
    # インフラ・ミドルウェア
    "aws", "gcp", "azure", "docker", "kubernetes", "terraform", "ansible", "nginx", "apache",
    "lambda", "dynamodb", "s3", "rds", "ec2", "cloudfront", "cognito", "sqs", "sns", "eventbridge",
    "mysql", "postgres", "postgresql", "redis", "mongodb", "elasticsearch", "kafka", "rabbitmq",
    # ツール・その他
    "git", "github", "gitlab", "bitbucket", "jenkins", "circleci", "webpack", "vite", "eslint",
    "prettier", "jest", "pytest", "phpunit", "rspec", "cypress", "playwright", "storybook",
    "graphql", "rest", "grpc", "oauth", "jwt", "saml", "openapi", "swagger",
    "api", "sdk", "cli", "ui", "ux", "css", "html", "json", "yaml", "xml", "csv", "sql",
    "http", "https", "tcp", "ssl", "tls", "dns", "cdn", "vpc", "iam", "ssm",
    "readme", "changelog", "license", "dockerfile", "makefile",
    # 略語（ALLCAPS パターンに当たるが一般語。除かないと候補がノイズで埋まる）
    "utf", "ascii", "sha", "md5", "uuid", "guid", "crud", "cors", "csrf", "xss", "sqli",
    "orm", "mvc", "mvp", "spa", "ssr", "csr", "ssg", "dto", "dao", "poc", "mvvm",
    "todo", "fixme", "note", "warn", "info", "debug", "error", "trace", "fatal",
    "url", "uri", "urn", "pdf", "png", "jpg", "jpeg", "gif", "svg", "zip", "gzip",
    "env", "dev", "stg", "prod", "qa", "ci", "cd", "vcs", "npm", "pip", "ide",
    "cpu", "gpu", "ram", "ssd", "hdd", "os", "vm", "k8s", "eks", "ecs", "vpn",
    "rfc", "iso", "gmt", "utc", "jst", "ttl", "fifo", "lifo", "acl", "abac", "rbac",
    "gpt", "llm", "rag", "mcp", "ocr", "nlp", "ai", "ml",
    # 開発語彙（コミット件名に頻出）
    "fix", "feat", "add", "update", "remove", "delete", "refactor", "test", "docs", "chore",
    "merge", "revert", "release", "build", "deploy", "init", "wip",
}

# 候補として拾う語の形。独自の造語が現れやすい形だけを対象にする。
CANDIDATE_PATTERNS: list[tuple[str, str]] = [
    ("CamelCase", r"\b[A-Z][a-z]+(?:[A-Z][a-z]+)+\b"),
    ("snake_case", r"\b[a-z]+(?:_[a-z0-9]+){1,}\b"),
    ("kebab-case", r"\b[a-z]+(?:-[a-z0-9]+){1,}\b"),
    ("ALLCAPS", r"\b[A-Z]{3,}\b"),
]


def _known_terms(project_key: str | None) -> set[str]:
    """辞書が既に知っている語（置換キーと置換後の値の両方）を小文字で返す。"""
    d = load_project_dict(project_key)
    known: set[str] = set()
    for src, dst in (d.get("replace") or {}).items():
        known.add(str(src).lower())
        known.add(str(dst).lower())
    for src, dst in (d.get("replace_paths") or {}).items():
        known.add(str(src).lower())
        known.add(str(dst).lower())
    return known


def find_structural(text: str) -> list[tuple[str, str]]:
    """組織名・ブランチ名・チケットIDなど、構造的に確定できる漏洩を返す。"""
    found: list[tuple[str, str]] = []
    for name, pat in STRUCTURAL_PATTERNS:
        for m in re.finditer(pat, text):
            hit = m.group(0)
            if name == "ticket_id" and hit.split("-", 1)[0] in TICKET_ID_EXCLUDE_PREFIXES:
                continue  # UTF-8 / SHA-256 等。チケットIDではなく一般技術語
            found.append((name, hit))
    return found


def find_candidates(text: str, project_key: str | None) -> dict[str, list[str]]:
    """辞書にも一般技術語にも無い語を、形ごとに分類して返す。"""
    known = _known_terms(project_key)
    out: dict[str, list[str]] = {}
    for name, pat in CANDIDATE_PATTERNS:
        hits: set[str] = set()
        for m in re.finditer(pat, text):
            w = m.group(0)
            base = w.lower()
            if base in COMMON_TECH_WORDS or base in known:
                continue
            # 区切りで分解した各片が全部一般語なら、組み合わせ語とみなして除く
            parts = [p for p in re.split(r"[_\-]", base) if p]
            if parts and all(p in COMMON_TECH_WORDS for p in parts):
                continue
            hits.add(w)
        if hits:
            out[name] = sorted(hits)
    return out


def report(text: str, project_key: str | None) -> tuple[str, bool]:
    """人間が読むレポートと、「確定漏洩があったか」を返す。"""
    structural = find_structural(text)
    candidates = find_candidates(text, project_key)

    lines: list[str] = []
    if structural:
        lines.append("■ 確定: 構造的に固有名を含む（辞書に足すか、そもそも取り込まない）")
        seen: set[str] = set()
        for name, hit in structural:
            if hit in seen:
                continue
            seen.add(hit)
            lines.append(f"  [{name}] {hit}")
        lines.append("")

    if candidates:
        lines.append("■ 候補: 辞書にも一般技術語にも無い語（誤検知を含む。人間が判断する）")
        for name, ws in candidates.items():
            lines.append(f"  [{name}] {', '.join(ws[:30])}" + (" …" if len(ws) > 30 else ""))
        lines.append("")

    if not lines:
        lines.append("検知なし（確定漏洩・候補ともに0件）")

    return "\n".join(lines), bool(structural)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="辞書に無い固有名詞の候補を検知（置換はしない）")
    ap.add_argument("--project", help="案件キー（番人辞書の既知語を候補から除くために使う）")
    ap.add_argument("--text-file", help="対象テキストファイル")
    ap.add_argument("--weekly", action="store_true", help="今週のコミットログを対象にする")
    ap.add_argument("--days", type=int, default=7, help="--weekly の対象日数（既定7）")
    args = ap.parse_args(argv)

    if args.weekly:
        from .config import Config
        from . import weekly_harvest as wh

        cfg = Config.load()
        projects = wh.fetch_active_projects(cfg)
        # --project は収穫の「前」に絞る。harvest は案件ごとに git log を回すので、
        # 後で捨てると1案件見たいだけで全稼働案件を走査することになる。
        if args.project:
            if args.project not in projects:
                ap.error(f"稼働中の案件に見つからない: {args.project}")
            projects = {args.project: projects[args.project]}
        data = wh.harvest(projects, args.days)
        rc = 0
        for key, c in data["companies"].items():
            msgs: list[str] = []
            for log in (c.get("commits") or {}).values():
                msgs.extend(log)
            if not msgs:
                continue
            text = "\n".join(msgs)
            body, leaked = report(text, key)
            print(f"=== {key} （コミット件名 {len(msgs)} 件）===")
            print(body)
            print()
            if leaked:
                rc = 1
        return rc

    if not args.text_file:
        ap.error("--text-file か --weekly のどちらかが必要")
    text = Path(args.text_file).read_text(encoding="utf-8")
    body, leaked = report(text, args.project)
    print(body)
    return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
