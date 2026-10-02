"""辞書に無い固有名詞の検知テスト。

「確定」枠は exit 1 を返しゲートに使える想定なので、一般技術語で誤爆しないことを
重点的に見る（誤爆が続くと確定枠そのものが信用されなくなるため）。

実行: .venv/bin/python -m pytest tests/test_unknown_terms.py -v
   または .venv/bin/python tests/test_unknown_terms.py （pytest 無しでも走る簡易ランナー付き）
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from mask_before_llm.unknown_terms import find_candidates, find_structural, report


def _hits(text: str, kind: str) -> list[str]:
    return [h for name, h in find_structural(text) if name == kind]


# --- 確定: 本物の漏洩を取りこぼさないこと ---

def test_merge_pr_org_branch():
    hits = _hits("Merge pull request #12 from acme-corp/feature/secret-thing", "merge_pr_org_branch")
    assert hits and "acme-corp" in hits[0]


def test_merge_branch_quoted():
    assert _hits("Merge branch 'develop' into 'main'", "merge_branch")


def test_branch_like():
    assert "feature/private-x" in _hits("Merge remote-tracking branch 'origin/feature/private-x'", "branch_like")


def test_ticket_id_detected():
    assert "MAINT-630" in _hits("MAINT-630 の対応", "ticket_id")


def test_structural_sets_leaked_flag():
    _, leaked = report("Merge pull request #3 from acme/dev", None)
    assert leaked


# --- 確定: 一般技術語で誤爆しないこと（本テストの主眼） ---

def test_ticket_id_ignores_common_tech_words():
    text = "UTF-8 で扱い SHA-256 でハッシュ化。ISO-8601 の日付、GPT-4 を利用、HTTP-2 で配信。"
    assert _hits(text, "ticket_id") == []


def test_benign_text_is_clean_and_exits_zero():
    text = (
        "本文は UTF-8 で扱う。SHA-256 でハッシュ化し、ISO-8601 の日付を使う。\n"
        "CORS と CSRF 対策済み。TODO: リトライ処理。レスポンスは JSON。"
    )
    body, leaked = report(text, None)
    assert not leaked, f"漏洩ゼロの文章で確定判定が出た:\n{body}"
    assert "検知なし" in body, f"一般技術語が候補に残った:\n{body}"


def test_real_ticket_still_detected_alongside_excluded():
    # 除外接頭辞と本物のチケットIDが同居しても、本物だけ残る
    hits = _hits("UTF-8 対応と MAINT-630 の修正", "ticket_id")
    assert hits == ["MAINT-630"]


# --- 候補 ---

def test_candidates_pick_up_coined_words():
    c = find_candidates("ChibicSystem と acme-corp-internal を改修", None)
    assert "ChibicSystem" in c.get("CamelCase", [])
    assert "acme-corp-internal" in c.get("kebab-case", [])


def test_candidates_drop_common_tech_words():
    c = find_candidates("react と typescript と dynamodb を使う", None)
    assert c == {}


def test_candidates_drop_compound_of_common_words():
    # 区切りの各片が全部一般語なら組み合わせ語として除く
    c = find_candidates("aws-lambda と github-api を更新", None)
    assert c == {}


def test_candidates_drop_common_allcaps():
    c = find_candidates("CORS と CSRF と TODO と UUID と ORM を確認", None)
    assert c == {}


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {t.__name__}: {e}")
        except Exception as e:  # noqa
            print(f"  💥 {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    return passed == len(tests)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
