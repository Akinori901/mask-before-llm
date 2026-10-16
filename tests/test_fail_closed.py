"""fail-closed の抜け道を塞いだことを固定するテスト。

案件辞書の確認をすり抜けると、固有名を消さないまま LLM に渡ってしまう。
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from mask_before_llm import masking
from mask_before_llm.masking import MaskingError, mask_text

REAL_DIR = Path(__file__).parent.parent / "src" / "mask_before_llm" / "redaction"


@pytest.fixture
def redaction_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """本物の _common.yaml / _template.yaml を置いた一時ディレクトリに差し替える。"""
    for name in ("_common.yaml", "_template.yaml"):
        shutil.copy(REAL_DIR / name, tmp_path / name)
    monkeypatch.setattr(masking, "REDACTION_DIR", tmp_path)
    monkeypatch.setattr(masking, "COMMON_FILE", tmp_path / "_common.yaml")
    return tmp_path


@pytest.mark.parametrize("key", ["_common", "_template"])
def test_reserved_files_are_not_project_dicts(redaction_dir: Path, key: str) -> None:
    """_common.yaml は必ず存在するので、以前は「辞書あり」と誤判定されて素通りした。"""
    with pytest.raises(MaskingError):
        mask_text("AcmeCorp の話", project_key=key)


@pytest.mark.parametrize("key", ["../outside", "a/b", "..", "Acme", "", "x" * 65])
def test_malformed_project_key_is_rejected(redaction_dir: Path, key: str) -> None:
    (redaction_dir.parent / "outside.yaml").write_text("decision: as_is\n", encoding="utf-8")
    with pytest.raises(MaskingError):
        mask_text("text", project_key=key)


def test_missing_decision_is_not_permission(redaction_dir: Path) -> None:
    """decision の書き忘れは「許可」ではなく「未判断」。"""
    (redaction_dir / "acme.yaml").write_text('replace:\n  "AcmeCorp": "某社"\n', encoding="utf-8")
    with pytest.raises(MaskingError):
        mask_text("AcmeCorp の話", project_key="acme")


def test_missing_decision_only_warns_when_not_strict(redaction_dir: Path) -> None:
    (redaction_dir / "acme.yaml").write_text('replace:\n  "AcmeCorp": "某社"\n', encoding="utf-8")
    masked, _ = mask_text("AcmeCorp の話", project_key="acme", strict_project=False)
    assert "AcmeCorp" not in masked


def test_valid_key_still_works(redaction_dir: Path) -> None:
    (redaction_dir / "acme-2.yaml").write_text(
        'decision: anonymize\nreplace:\n  "AcmeCorp": "某社"\n', encoding="utf-8"
    )
    masked, report = mask_text("AcmeCorp の話", project_key="acme-2")
    assert masked == "某社 の話"
    assert report.verify_passed


@pytest.mark.parametrize(
    "variant", ["AcmeCorp", "ACMECORP", "acmecorp", "ＡｃｍｅＣｏｒｐ", "ＡＣＭＥＣＯＲＰ"]
)
def test_proper_noun_variants_are_replaced(redaction_dir: Path, variant: str) -> None:
    """辞書の表記と大文字小文字・全角半角が違うだけで素通りしていた。"""
    (redaction_dir / "acme.yaml").write_text(
        'decision: anonymize\nreplace:\n  "AcmeCorp": "某社"\n', encoding="utf-8"
    )
    masked, report = mask_text(f"{variant} の案件", project_key="acme")
    assert masked == "某社 の案件"
    assert report.replacements_applied == 1


def test_replacement_text_is_literal(redaction_dir: Path) -> None:
    r"""置換後の文字列に \1 や \g<0> があっても、正規表現の参照として解釈しない。"""
    (redaction_dir / "acme.yaml").write_text(
        'decision: anonymize\nreplace:\n  "AcmeCorp": "\\\\1社"\n', encoding="utf-8"
    )
    masked, _ = mask_text("AcmeCorp", project_key="acme")
    assert masked == "\\1社"
