# mask-before-llm

秘密保持契約のあるコードを LLM に渡す前に、ローカルで匿名化する。

LLM は便利だが、他社から預かったコードをそのまま投げるわけにはいかない。
このツールは「渡す前にローカルで固有名と秘匿値を落とし、**落としきれていなければ処理を止める**」ための小さな部品である。

AI は一切呼ばない。ルールベースの `re` と PyYAML だけで動く。

```python
from mask_before_llm.masking import mask_text, MaskingError

try:
    masked = mask_text(raw_text, project_key="acme")
except MaskingError as e:
    # 匿名化しきれなかった。LLM には渡さない
    raise

send_to_llm(masked)   # 渡すのはこの戻り値だけ
```

## なぜ「検知」ではなく「検知して止める」のか

秘匿値の検知スクリプトはよくある。しかし検知した後どうするかが運用に委ねられていると、
急いでいるときに「たぶん大丈夫」で通してしまう。

このツールは3段構えで、最後が**検証ゲート**になっている。

1. **置換** — 案件別辞書の `replace` / `replace_paths` で固有名を汎用名へ
2. **マスク** — 共通ルール + 案件別の `mask_regex` で秘匿値をダミー化
3. **検証ゲート** — それでも秘匿値が残っていたら `MaskingError` を投げる

3 で例外が飛ぶと、呼び出し側は LLM に渡せない。人間が辞書を直すまで通らない。

### fail-closed であること

辞書が無い案件は、既定で**例外になる**（`strict_project=True`）。

```python
mask_text(raw, project_key="unknown-project")   # → MaskingError
```

「辞書を用意していない案件が、何も置換されずに素通りする」のが一番怖い事故なので、
そこを構造的に塞いでいる。`decision` が `metadata_only` / `pending` の案件も同様に止まる。

## 案件辞書

`redaction/<案件key>.yaml` に置く。雛形は [`_template.yaml`](src/mask_before_llm/redaction/_template.yaml)。

```yaml
key: acme
decision: anonymize        # anonymize | as_is | metadata_only | pending

replace:                   # 長い順に適用される
  "AcmeCorp": "某社"
  "TurboClock": "ある勤怠管理SaaS"

replace_paths:
  "acme-app/": "project-a/"

mask_regex: []             # 案件固有の秘匿パターン（共通ルールは常に走る）
```

**この辞書ファイル自体が、隠すべき生の値の一覧になる。** コミットしてはいけない。
同梱の [`.gitignore`](.gitignore) は `redaction/*.yaml` を除外し、雛形と共通ルールだけを追跡する設定になっている。

共通の秘匿パターン（API キー、AWS アクセスキー、秘密鍵ブロック、DB 接続 URI、
Bearer トークン、メールアドレス、IPv4）は [`_common.yaml`](src/mask_before_llm/redaction/_common.yaml) にあり、
案件辞書の有無に関わらず常に適用される。

## 辞書の書き漏れを見つける

辞書は既知の固有名しか消せない。新しいプロダクト名やブランチ名は素通りする。

`unknown_terms` は「辞書に無い固有名詞の候補」を検知して人間に提示する。
**自動では置換しない。**

```
python -m mask_before_llm.unknown_terms --project acme --text-file notes.md
```

置換しないのは、誤検知のコストが非対称だからである。

- 拾いすぎ → 一般技術語（Laravel 等）が消えて文章の価値が壊れる。しかも静かに起きる
- 取りこぼし → 漏洩

自動で消すより「怪しい語を人間に出す」方が安全side。辞書に足すかは人間が決める。

なお `Merge pull request #N from 組織/ブランチ名` のようなマージコミット件名は、
構造的に固有名を含むことが確定しているので、候補ではなく確定扱いで強く警告する。
これは実際にブランチ名が外部へ漏れた経路だった。

## 使い方

依存は PyYAML のみ。

```
pip install pyyaml
```

テストは pytest でも、pytest 無しの簡易ランナーでも走る。

```
python tests/test_masking.py
python tests/test_unknown_terms.py
```

## ライセンス

MIT
