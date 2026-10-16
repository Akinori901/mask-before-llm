"""共通ルール（_common.yaml）でマスクされる秘匿値のテスト。

トークンはソースに直接書かず、実行時に組み立てる。本物と同じ形の文字列を
コミットすると、GitHub の push protection や secret scanning に引っかかるため。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from mask_before_llm import masking
from mask_before_llm.masking import mask_text

REAL_DIR = Path(__file__).parent.parent / "src" / "mask_before_llm" / "redaction"


@pytest.fixture(autouse=True)
def _real_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    # 他のテストが REDACTION_DIR を差し替えたままでも、本物の共通ルールを使う
    monkeypatch.setattr(masking, "REDACTION_DIR", REAL_DIR)
    monkeypatch.setattr(masking, "COMMON_FILE", REAL_DIR / "_common.yaml")


def _fake(prefix: str, n: int, alphabet: str = "aB3dE5fG7h") -> str:
    return prefix + (alphabet * (n // len(alphabet) + 1))[:n]


TOKENS = {
    "anthropic": _fake("sk-" + "ant-", 40),
    "openai": _fake("sk-" + "proj-", 40),
    "github_classic": _fake("gh" + "p_", 36),
    "github_fine_grained": _fake("github" + "_pat_", 40),
    "slack": _fake("xo" + "xb-", 30),
    "google": _fake("AI" + "za", 35),
    "stripe": _fake("sk" + "_live_", 24),
    "jwt": ".".join([_fake("ey" + "J", 20), _fake("ey" + "J", 20), _fake("", 20)]),
}


@pytest.mark.parametrize("name", sorted(TOKENS))
def test_bare_tokens_are_masked(name: str) -> None:
    token = TOKENS[name]
    masked, report = mask_text(f"設定値は {token} です")
    assert token not in masked
    assert report.verify_passed


def test_base64_secret_is_masked_to_the_end() -> None:
    """値の文字に / + = を含む秘密（base64）が途中までしか消えなかった。"""
    secret = "abcDEF123/ghi+JKL456==" * 2
    masked, _ = mask_text(f"secret: {secret}")
    assert "ghi+JKL" not in masked and "==" not in masked


def test_aws_secret_access_key_is_masked() -> None:
    value = _fake("", 40, "Ab/9+Cd8=")
    masked, _ = mask_text(f"aws_secret_access_key = {value}")
    assert value not in masked


@pytest.mark.parametrize("phone", ["03-1234-5678", "090-1234-5678", "+81-90-1234-5678"])
def test_phone_numbers_are_masked(phone: str) -> None:
    masked, _ = mask_text(f"連絡先 {phone} まで")
    assert phone not in masked


@pytest.mark.parametrize("text", ["2026-10-17 にリリース", "v0.1.2", "ポート 8080-8090"])
def test_dates_and_versions_are_not_phone_numbers(text: str) -> None:
    masked, _ = mask_text(text)
    assert masked == text
