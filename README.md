# Security Digest

Security Digestは、金融機関のサイバーセキュリティ担当者・管理者・担当役員向けに、国内外のサイバーセキュリティニュースを整理して公開する日次ニュースダイジェストです。

公開サイト: https://matkei31.github.io/security-digest/

## 概要

本システムは、設定されたRSSや構造化データの取得元から記事を収集し、Geminiで各記事の分析（ARTICLE）と当日全体の要点（BRIEF）を生成します。生成結果は、機械可読なdaily JSONとGitHub Pages向けの静的HTMLとして保存・公開されます。

主な処理は次のとおりです。

1. RSS、Atom、CISA KEV等から記事・脆弱性情報を収集する
2. Geminiで記事ごとの重要度、確認目安、要約、理由、推奨確認事項等を生成する
3. 判定済み記事の分布を踏まえてBRIEFを生成する
4. daily JSON、トップページ、日別アーカイブを生成する
5. GitHub Actionsが生成物をcommitし、GitHub Pagesから公開する

現在のprompt version、schema version、取得元の有効状態、既知問題は[STATUS.md](STATUS.md)を参照してください。恒久的な設計・運用判断は[DECISIONS.md](DECISIONS.md)に記録します。

## 主要ファイルとディレクトリ

| パス | 役割 |
|---|---|
| `fetch.py` | 取得、ARTICLE／BRIEF生成、HTML生成の中心処理 |
| `daily_json.py` | daily JSONの構築、version定義、validation、原子的保存 |
| `vulnerability_facts.py` | CVE、NVD、CISA KEVのfacts取得とcache処理 |
| `source_definitions.json` | 取得元、URL、有効・保留状態、分類等の正本 |
| `.github/workflows/fetch.yml` | schedule／workflow_dispatchによる日次生成 |
| `data/` | daily JSON、index、facts cache |
| `docs/` | GitHub Pagesへ公開する生成済みHTML等 |
| `test_*.py` | unittestによる回帰テスト |
| `AGENTS.md` | 実装エージェントが守る開発・安全上の制約 |

取得元を追加・変更・無効化する場合は、`fetch.py`内の互換変数を直接編集せず、[source_definitions.json](source_definitions.json)を変更してください。

## 開発時の安全な入口

最初にworking treeと現在branchを確認し、専用feature branchまたはworktreeで作業してください。

```bash
git status --short --branch
git fetch origin
python3 -m unittest discover -p "test_*.py"
```

`python3 fetch.py`はプレビュー専用コマンドではありません。実行環境によっては、外部取得、Gemini API呼び出し、`data/`と`docs/`の生成・上書き、翻訳cache更新等の副作用があります。実Gemini API、workflow_dispatch、本番生成を伴う確認は、明示的な承認を得た場合だけ実施してください。

本リポジトリには`--dry-run`オプションはありません。

開発・レビュー時の詳細な制約と標準確認項目は[AGENTS.md](AGENTS.md)を参照してください。
