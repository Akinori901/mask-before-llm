"""①ローカルマスキングのテスト（NDAの生命線なので手厚く）。

実行: .venv/bin/python -m pytest tests/test_masking.py -v
   または .venv/bin/python tests/test_masking.py （pytest 無しでも走る簡易ランナー付き）
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from mask_before_llm import masking
from mask_before_llm.masking import MaskingError, mask_text


def _write_dict(tmp: Path, key: str, body: str) -> None:
    (tmp / f"{key}.yaml").write_text(body, encoding="utf-8")


def _use_tmp_redaction(tmp: Path, monkeypatch=None):
    """masking モジュールの REDACTION_DIR を一時ディレクトリに差し替える。"""
    masking.REDACTION_DIR = tmp
    masking.COMMON_FILE = tmp / "_common.yaml"
    # 本物の _common.yaml をコピーして共通ルールを効かせる
    real_common = Path(__file__).parent.parent / "src" / "mask_before_llm" / "redaction" / "_common.yaml"
    (tmp / "_common.yaml").write_text(real_common.read_text(encoding="utf-8"), encoding="utf-8")


def test_replace_proper_nouns(tmp_path):
    _use_tmp_redaction(tmp_path)
    _write_dict(tmp_path, "acme", """
key: acme
decision: anonymize
replace:
  "AcmeCorp": "某社"
  "TurboClock": "ある勤怠管理SaaS"
replace_paths:
  "acme-app/": "project-a/"
""")
    raw = "AcmeCorp の TurboClock を acme-app/src/main.ts で改修した"
    out, rep = mask_text(raw, "acme")
    assert "AcmeCorp" not in out and "TurboClock" not in out and "acme-app/" not in out
    assert "某社" in out and "ある勤怠管理SaaS" in out and "project-a/" in out
    assert rep.replacements_applied == 3
    assert rep.verify_passed


def test_mask_secrets(tmp_path):
    _use_tmp_redaction(tmp_path)
    _write_dict(tmp_path, "acme", "key: acme\ndecision: anonymize\nreplace: {}\n")
    raw = 'api_key="abcd1234efgh5678" して postgres://user:pw@db.local:5432/app に接続'
    out, rep = mask_text(raw, "acme")
    assert "abcd1234efgh5678" not in out
    assert "REDACTED" in out
    assert "user:pw@db.local" not in out
    assert rep.verify_passed


def test_private_key_block_masked_without_false_positive(tmp_path):
    """秘密鍵ブロックが、本番の共通ルール(_common.yaml)で最後まで通ること。

    回帰防止: 置換後ダミーが '-----BEGIN PRIVATE KEY-----' を含んでいた頃は、
    検証ゲート leftover_private_key が「自分が書いたダミー」を残存秘密鍵として
    検知し、実際には漏れていないのに匿名化ゲートで止まっていた。
    """
    raw = (
        "デプロイ鍵はこれです。\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAsecretkeymaterial1234567890\n"
        "-----END RSA PRIVATE KEY-----\n"
        "以上。"
    )
    # 本番の共通ルールをそのまま使う（差し替えない）のが本テストの要点。
    out, rep = mask_text(raw, None)
    assert "MIIEowIBAAKCAQEAsecretkeymaterial1234567890" not in out, "鍵本体が残っている"
    assert "REDACTED" in out
    assert rep.verify_passed, "ダミー文字列を残存秘密鍵と誤検知している"


def test_verify_gate_still_catches_real_private_key(tmp_path):
    """ダミーを変えても、マスクされなかった本物の秘密鍵は必ず止まること。

    誤検知を直す過程でゲートを緩めていないことの確認（NDAの生命線）。
    """
    _use_tmp_redaction(tmp_path)
    # mask_regex を空にして「マスクされず素通しした」状況を作る → ゲートが捕まえるべき
    (tmp_path / "_common.yaml").write_text("""
mask_regex: []
verify_deny:
  - name: leftover_private_key
    pattern: '-----BEGIN [A-Z ]*PRIVATE KEY-----'
""", encoding="utf-8")
    raw = "-----BEGIN OPENSSH PRIVATE KEY-----\nrealkeymaterial\n-----END OPENSSH PRIVATE KEY-----"
    try:
        mask_text(raw, None)
        assert False, "検証ゲートが本物の秘密鍵を見逃した"
    except MaskingError:
        pass


def test_verify_gate_catches_leftover_secret(tmp_path):
    """辞書で消しきれなかった秘匿値が残ったら MaskingError で止まること（最重要）。"""
    _use_tmp_redaction(tmp_path)
    # mask_regex を空にした共通ルールに差し替え、検知だけ残す → マスクされず残存 → ゲートが捕まえる
    (tmp_path / "_common.yaml").write_text("""
mask_regex: []
verify_deny:
  - name: leftover_secret_keyword
    pattern: '(?i)\\b(api[_-]?key|secret)\\b\\s*[:=]\\s*["'']?[A-Za-z0-9_\\-\\.]{8,}'
""", encoding="utf-8")
    _write_dict(tmp_path, "acme", "key: acme\ndecision: anonymize\nreplace: {}\n")
    raw = 'secret = "supersecret_value_123"'
    try:
        mask_text(raw, "acme")
        assert False, "検証ゲートが残存秘匿値を見逃した"
    except MaskingError as e:
        assert "検証ゲート失敗" in str(e)


def test_reject_non_publishable_decision(tmp_path):
    """decision=metadata_only / pending の案件は処理を拒否すること。"""
    _use_tmp_redaction(tmp_path)
    for bad in ("metadata_only", "pending"):
        _write_dict(tmp_path, "acme", f"key: acme\ndecision: {bad}\nreplace: {{}}\n")
        try:
            mask_text("なんらかのコード", "acme")
            assert False, f"decision={bad} を通してしまった"
        except MaskingError as e:
            assert "利用不可" in str(e)


def test_missing_dict_is_blocked_by_default(tmp_path):
    """案件辞書が無いのに project_key 指定 → strict で MaskingError（素通し防止）。"""
    _use_tmp_redaction(tmp_path)
    try:
        mask_text("some code", "no-such-project")
        assert False, "辞書欠如を素通しした"
    except MaskingError as e:
        assert "案件辞書が無い" in str(e)


def test_public_info_no_project_key(tmp_path):
    """公開情報だけの記事は project_key=None で通る（案件辞書不要）。"""
    _use_tmp_redaction(tmp_path)
    out, rep = mask_text("これは公開情報だけで書いた一般的な技術解説です", None)
    assert rep.verify_passed
    assert "公開情報" in out


def _run_all():
    import tempfile
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for t in tests:
        with tempfile.TemporaryDirectory() as d:
            # 各テストごとに REDACTION_DIR を復元
            orig_dir, orig_common = masking.REDACTION_DIR, masking.COMMON_FILE
            try:
                t(Path(d))
                print(f"  ✅ {t.__name__}")
                passed += 1
            except AssertionError as e:
                print(f"  ❌ {t.__name__}: {e}")
            except Exception as e:  # noqa
                print(f"  💥 {t.__name__}: {type(e).__name__}: {e}")
            finally:
                masking.REDACTION_DIR, masking.COMMON_FILE = orig_dir, orig_common
    print(f"\n{passed}/{len(tests)} passed")
    return passed == len(tests)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
