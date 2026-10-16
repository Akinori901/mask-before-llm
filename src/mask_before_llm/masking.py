"""ローカルマスキング — LLM にテキストを渡す前の最後の砦。

秘密保持契約のある案件コード由来のテキストを、LLM に渡す *前に* ローカルで匿名化する。
このモジュールは AI を一切呼ばない（ルールベースのみ）。呼び出し側の鉄則:

    masked = mask_text(raw, project_key="foo")   # ← LLM に渡すのはこの戻り値だけ
    # raw を LLM / オブジェクトストレージ / クラウドに渡してはならない

処理順:
  1. 案件別辞書 (redaction/<key>.yaml) の replace / replace_paths で固有名を汎用名へ
  2. 共通 (_common.yaml) + 案件別の mask_regex で秘匿値をダミー化
  3. 検証ゲート (verify_deny): 消しきれない秘匿値が残っていたら MaskingError を送出
     → 呼び出し側は処理を中断し、絶対に LLM へ渡さない

辞書が無い案件は既定で例外にする（strict_project）。「辞書が無いから素通し」を
構造的に起こさないための fail-closed 設計。

依存: PyYAML のみ（re は標準）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit("PyYAML が必要です: pip install pyyaml") from e

REDACTION_DIR = Path(__file__).parent / "redaction"
COMMON_FILE = REDACTION_DIR / "_common.yaml"

# テキストを LLM へ渡してよい decision
PUBLISHABLE_DECISIONS = {"anonymize", "as_is"}

# 案件キーとして受け付ける形。"_" で始まるキーは _common / _template などの
# 予約ファイルを指してしまうので受け付けない（_common.yaml は必ず存在するため、
# project_key="_common" で「案件辞書あり」と誤判定されて strict を素通りしていた）。
# "/" や ".." も通さない（REDACTION_DIR の外の YAML を読ませない）。
_PROJECT_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def _check_project_key(project_key: str) -> None:
    if not isinstance(project_key, str) or not _PROJECT_KEY.fullmatch(project_key):
        raise MaskingError(
            f"案件キーが不正: {project_key!r}（英小文字・数字で始まり、英小文字・数字・_・- のみ）"
        )


class MaskingError(Exception):
    """マスキング後も秘匿値が残った/利用不可の案件だった等、LLM に渡してはいけない状態。"""


@dataclass
class MaskReport:
    """マスキング結果の監査ログ（人間レビュー・ジョブ記録用）。"""
    project_key: str | None
    replacements_applied: int = 0
    regex_masked: dict[str, int] = field(default_factory=dict)
    verify_passed: bool = False
    notes: list[str] = field(default_factory=list)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_replacements(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    """単純文字列置換。長い鍵から適用して部分一致の取りこぼしを防ぐ。"""
    count = 0
    for src in sorted(mapping.keys(), key=len, reverse=True):
        dst = mapping[src]
        if src and src in text:
            count += text.count(src)
            text = text.replace(src, dst)
    return text, count


def _apply_mask_regex(text: str, rules: list[dict[str, str]]) -> tuple[str, dict[str, int]]:
    hits: dict[str, int] = {}
    for rule in rules or []:
        pat = rule.get("pattern")
        if not pat:
            continue
        repl = rule.get("replacement", "***REDACTED***")
        name = rule.get("name", pat[:20])
        text, n = re.subn(pat, repl, text)
        if n:
            hits[name] = hits.get(name, 0) + n
    return text, hits


def _run_verify_gate(text: str, rules: list[dict[str, str]]) -> list[str]:
    """残存したら失敗させる。ヒットしたルール名を返す（空なら合格）。"""
    failed = []
    for rule in rules or []:
        pat = rule.get("pattern")
        if pat and re.search(pat, text):
            failed.append(rule.get("name", pat[:20]))
    return failed


def load_project_dict(project_key: str | None) -> dict[str, Any]:
    """共通ルール + 案件別辞書をマージして返す。"""
    common = _load_yaml(COMMON_FILE)
    merged: dict[str, Any] = {
        "replace": {},
        "replace_paths": {},
        "mask_regex": list(common.get("mask_regex", [])),
        "verify_deny": list(common.get("verify_deny", [])),
        "decision": None,
    }
    if project_key is not None:
        _check_project_key(project_key)
        proj = _load_yaml(REDACTION_DIR / f"{project_key}.yaml")
        merged["replace"].update(proj.get("replace", {}) or {})
        merged["replace_paths"].update(proj.get("replace_paths", {}) or {})
        merged["mask_regex"].extend(proj.get("mask_regex", []) or [])
        merged["decision"] = proj.get("decision")
    return merged


def mask_text(
    raw: str,
    project_key: str | None = None,
    *,
    strict_project: bool = True,
) -> tuple[str, MaskReport]:
    """raw を匿名化して (masked_text, report) を返す。

    strict_project=True のとき:
      - 案件辞書が見つからない、decision が無い、または利用不可(metadata_only/pending)なら MaskingError。
        「辞書が無いから素通し」を防ぐ安全側の既定。公開情報だけで書く記事は project_key=None で呼ぶ。
    検証ゲートに残存があれば常に MaskingError。
    """
    report = MaskReport(project_key=project_key)
    cfg = load_project_dict(project_key)

    if project_key is not None:
        proj_path = REDACTION_DIR / f"{project_key}.yaml"
        if not proj_path.exists():
            msg = f"案件辞書が無い: {proj_path}（固有名を消せないため処理を中止）"
            if strict_project:
                raise MaskingError(msg)
            report.notes.append("WARNING: " + msg)
        decision = cfg.get("decision")
        # decision の書き忘れは「許可」ではなく「未判断」。strict では止める。
        if decision is None and strict_project:
            raise MaskingError(f"案件辞書に decision がありません（未判断として中止）: {project_key}")
        if decision is not None and decision not in PUBLISHABLE_DECISIONS:
            raise MaskingError(
                f"decision={decision} は利用不可（anonymize/as_is のみ許可）: {project_key}"
            )

    text, n_repl = _apply_replacements(raw, cfg["replace"])
    text, n_paths = _apply_replacements(text, cfg["replace_paths"])
    report.replacements_applied = n_repl + n_paths

    text, hits = _apply_mask_regex(text, cfg["mask_regex"])
    report.regex_masked = hits

    failed = _run_verify_gate(text, cfg["verify_deny"])
    if failed:
        raise MaskingError(
            "検証ゲート失敗: マスキング後も秘匿値が残存 "
            f"({', '.join(failed)})。辞書を修正するまで Claude に渡さない。"
        )
    report.verify_passed = True
    return text, report


def mask_file(path: Path, project_key: str | None = None, **kw) -> tuple[str, MaskReport]:
    return mask_text(path.read_text(encoding="utf-8"), project_key, **kw)
