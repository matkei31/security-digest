# Security Digest バックログ

`BACKLOG.md`は、未完了・部分対応・ユーザー受入待ちの要求事項および課題を管理する正本である。現在の運用状態は[STATUS.md](STATUS.md)に、恒久的な決定事項は[DECISIONS.md](DECISIONS.md)に記録する。

## 出所種別

- **ユーザー原文:** ユーザーから直接回収できた文言。文字づかい・語尾・曖昧さを訂正せずそのまま保持する。
- **ユーザー確認済み要約:** 実装関係者が作成し、ユーザーが明示的に確認した要約。原文として提示しない。
- **復元要約:** 原文が入手できない場合に、過去の記録から意味を再構成したもの。かぎ括弧では表記せず、`原文未回収`と明記する。
- **技術上の発見事項:** ユーザーコメントに由来しない、テスト失敗・警告・実装上の制約・設計上の発見。

## 状態の定義

- **記録済み:** 記録はされているが、まだ完全には仕様化されていない。
- **仕様化済み:** 計画に十分な完了条件が定義されている。
- **進行中:** 承認済みの作業が開始されている。
- **実装済み:** 実装は存在するが、受入がまだ必要な場合がある。
- **ユーザー受入待ち:** 実装または設計がユーザーによる明示的なレビューを待っている。
- **完了:** 必要な実装と受入がいずれも完了している。
- **保留:** 意図的に先送りされている。
- **置換済み:** 元の記録を削除せずに、別の記録済み項目へ置き換えられている。

状態は組み合わせて使用してよい（例:`実装済み / ユーザー受入待ち`）。初期登録では次の明示的な修飾語も用いる:

- **方針承認済み:** 方向性・決定事項が承認されている。実装完了を意味しない。
- **未実装:** この項目を満たす実装がまだ存在しない。
- **未完了:** 記録された作業または監査が完了していない。
- **前提条件が整うまで保留:** 記録された依存関係が満たされるまで先送りする。

## 完了ルール

1. 原文と実装解釈を同じ欄に混在させない。
2. 原文が回収できていない場合、それをユーザー発言として引用しない。
3. 実装PRがmergeされただけでは、主観的なUIや文章品質に関する項目を`完了`にはしない。
4. UI・文章品質・ブランド表現は、ユーザーによる明示的な受入を必要とする。
5. 部分対応の項目は残作業を保持し、`完了`にはしない。
6. 項目を分割・統合、または`置換済み`とする場合、元のコメントと旧IDを保持する。
7. 完了済み項目の再オープンには新しい証跡を必要とする。
8. 実装上の都合で、具体的なコメントをより広い一般化表現に置き換えない。

## 初期移行範囲

- BL-001からBL-013は、正本バックログへの初期取り込みである。
- 過去のユーザーコメントを完全に監査した結果ではない。
- BL-014は、体系的な移行監査と網羅性レビューを追跡する。
- 追加の過去コメントが見つかった場合は、原文と出所とともに追記する。これは初期バックログの保持における誤りではなく、移行監査が未完了であったことを示す。

## 未完了バックログ

## BL-001 — プルリクエストCI

- **ID:** BL-001
- **タイトル:** プルリクエストCI
- **優先度:** P0
- **状態:** 完了
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — 技術上の発見事項。
- **ユーザー確認済み要約:** 未定義。
- **解釈:** production作業を一切行わず、全PRに対してfull unittest suiteと`git diff --check`を実行する通常の`pull_request` CIを追加する。
- **完了条件:** CIがfull unittest suiteと`git diff --check`を実行する。Geminiを呼ばず、secretsを受け取らず、`data/`や`docs/`を生成・commitせず、production publicationを行わない。
- **依存関係:** GitHub Actions workflowの設計とrepository権限のレビュー。
- **実装証跡:** 実装前は未実装であり、[STATUS.md](STATUS.md)と[`.github/workflows/fetch.yml`](.github/workflows/fetch.yml)に、通常の`pull_request` CIが存在しないことが記録されていた。[PR #26](https://github.com/matkei31/security-digest/pull/26)で[`.github/workflows/pr-ci.yml`](.github/workflows/pr-ci.yml)を新設し、main向けの通常の`pull_request`で、repository権限を`contents: read`だけに限定し、資格情報を永続化しないcheckout、Python 3.12でのfull unittest suite、base SHAとhead SHAの実差分に対する`git diff --check`、同一PRの旧runを中止するconcurrencyを実装した。draft PR上の[Pull Request CI run 29640129033](https://github.com/matkei31/security-digest/actions/runs/29640129033)でfull unittest 1,107件とPRのbase/head実差分に対する`git diff --check`が成功し、実効権限は`Contents: read`と暗黙の`Metadata: read`のみだった。このrunではrepository Secrets、Gemini/NVD、`fetch.py`、生成、commit、push、Pages publicationを実行していない。ChatGPT独立レビューでBlockerなしと判断された後、通常のmerge commit `f5bbd04f42643d4a87f999d01f538d574fe39f17`でmergeされた。
- **ユーザー受入証跡:** 実装前は「実装が存在しないため、現時点では該当なし。」と記録。実装後の最終受入発言は存在しない。「オッケー、進めて。」は実装着手を進める指示であり、実装後の受入発言としては扱わない。本項目は技術上の発見事項であり、客観的な完了条件と上記のmerge証跡により完了した。
- **残作業:** なし。
- **注記:** 実装前は、既存のローカルテストと独立レビューの証跡を代替としていた。merge前はPR上のCI結果と独立レビューを受入判断の証跡とし、完了後は上記の客観的完了条件とmerge証跡を正本とする。

## BL-002 — 記事カードの楕円バッジ多用を見直す

- **ID:** BL-002
- **タイトル:** 記事カードの楕円バッジ多用を見直す
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「楕円が並んでる見た目が気に入らないみたいなことを言った気がするんだよね。」
- **ユーザー確認済み要約:** 出元別の色分けや、楕円形のバッジが横に並ぶ見た目は要らない。全体として再設計したい。
- **解釈:** 既存のバッジ色や角丸自体が本質的な問題ではない。記事カードの情報階層とラベル表現そのものを再設計する。
- **完了条件:** 確定したB案（2026-07-17）に基づき具体化: (1) 取得元/重要度/確認目安/カテゴリは、通常の記事カードで楕円（角丸ピル）バッジを使用しない; (2) 取得元と公開日はプレーンテキストで表示する; (3) 重要度と確認目安は、共有された無差別なバッジ行ではなく、それぞれ独立したラベル付きの軸としてプレーンテキストで表示する; (4) 強調は重要度「高」と確認目安「本日確認」のみに限定し、他の値には同等の視覚的重みを与えない; (5) カテゴリはカードの表示から削除するが、その保存・レスポンススキーマ・検証・dashboard集計は変更しない; (6) 関連タグのみ、丸く低コントラストな`<span>`表現を維持し、カード下部に配置する; (7) 関連タグはクリック不可のままとする（`<a>`／button／クリックハンドラ／`role="button"`なし）; (8) 本チケットにより記事検索やタグ検索機能は導入しない; (9) 実際のPCおよび390px実装（モックのみでなく）をユーザーが目視レビュー・承認したうえで、本項目を`完了`とする。
- **依存関係:** BL-004；BL-003と調整する。
- **実装証跡:** 実装済み。dashboardは、3つの重いバッジ状カードから単一の軽量ブロックへ再設計され、新しい優先確認（priority index）セクションでは重要度/確認目安を楕円バッジではなくプレーンテキストで表示する（「feat: dashboard v2 + priority index + reason contract」チケット参照）。後続チケット（branch `feature/article-card-variant-b`、[PR #18](https://github.com/matkei31/security-digest/pull/18)）では、通常の記事カードのsource-color pill、`.importance-badge`、`.urgency-badge`、`.category-badge`をさらに完全に削除する: 取得元と公開日はプレーンテキストのmeta行として表示し、重要度/確認目安は高/本日確認に限定した軽いtext-color/left-borderアクセント付きのプレーンテキストで表示し（楕円形状なし）、カテゴリは通常カードでは一切表示されなくなる（daily-JSONの保存、レスポンススキーマ、検証、dashboard集計は変更しない）。ユーザーの明示的なB案選択に従い、`.article-tag`（関連タグ）はカード下部のfooterへ再配置されたまま、丸いピル形状を維持する唯一のラベルとなる。
- **ユーザー受入証跡:** Dashboard v2と優先確認の理由付きインデックス: 2026-07-17のプロジェクト会話でユーザーが受入。記事カードB案の方向性: レビューされた2案モックに基づき、2026-07-17のプロジェクト会話でユーザーが明示的に承認。実際のPC/390px実装（リポジトリ外でユーザーがレビューしたscreenshot）は、2026-07-17にユーザーが目視で受入、verbatim: 「見られたけど、いいと思うよ」。
- **残作業:** なし。
- **注記:** 将来のチケットでタグ検索やタグランディングページが導入される場合、現在のクリック不可の関連タグの扱いはその時点で再評価すべきである（それ以前ではない）。

## BL-003 — AIで機械処理された印象を弱める

- **ID:** BL-003
- **タイトル:** AIで機械処理された印象を弱める
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー確認済み要約
- **ユーザー原文:** 原文未回収。
- **ユーザー確認済み要約:** AIで機械処理された印象を弱める。
- **解釈:** 機械処理であることを隠すのではない。繰り返されるバッジ形状、密な分類metadata、過度に均一な記事カードによって生じる不要な「AI処理された」見た目を軽減する。
- **完了条件:** 確定したB案（2026-07-17）に基づき具体化: (1) 取得元/重要度/確認目安/カテゴリは、同一形状・同一処理の分類ラベルの行としてはもはや表示されない; (2) 読者の目が分類metadataより先に記事タイトルと本文へ到達し、それらと競合しない; (3) 関連タグのみ、カード下部の丸く低コントラストな補助情報として残り、タイトル/本文と注意を奪い合うようには再スタイルされない; (4) 実際のPCおよび390px実装をユーザーが目視レビューし、「AI処理された」印象が十分に軽減されたことを確認したうえで、本項目を`完了`とする。
- **依存関係:** BL-002およびBL-004。
- **実装証跡:** 実装済み。dashboardの密で反復的な3カード構成は、より明確な情報階層を持つ単一の軽量ブロック（重要度/確認目安を主軸とし、カテゴリは視覚的に控えめな補助行とする）へ置き換えられ、優先確認セクションは全記事metadataの密な反復的な再掲ではなく、短い理由付きインデックスへ再構成された。後続チケット（branch `feature/article-card-variant-b`、[PR #18](https://github.com/matkei31/security-digest/pull/18)）は、さらに通常の記事カードを見直す: source/importance/urgency/categoryはもはや同一形状の色付きピルの行として表示されない — source+dateはプレーンテキスト、重要度/確認目安は高/本日確認に限定した軽いアクセント付きのプレーンテキストとなり、カテゴリは表示されない。ユーザーの明示的なB案選択に従い、関連タグのみがカード下部で丸く低コントラストなピル表現を維持する。
- **ユーザー受入証跡:** Dashboard v2と優先確認の理由付きインデックス: 2026-07-17のプロジェクト会話でユーザーが受入。記事カードB案の方向性: レビューされた2案モックに基づき、2026-07-17のプロジェクト会話でユーザーが明示的に承認。実際のPC/390px実装（リポジトリ外でユーザーがレビューしたscreenshot）は、2026-07-17にユーザーが目視で受入、verbatim: 「見られたけど、いいと思うよ」。
- **残作業:** なし。
- **注記:** BL-002と関連するが、別のユーザー品質要求であった; 同じ2026-07-17の実装と受入が両方を独立して満たす。

## BL-004 — Fable 5によるUIレビューとUI設計書

- **ID:** BL-004
- **タイトル:** Fable 5によるUIレビューとUI設計書
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー原文 / ユーザー確認済み要約
- **ユーザー原文:** 「設計書は作成済みの理解で合ってる？」
- **ユーザー確認済み要約:** Fable 5に現行画面をレビューさせ、名称・色・形・配置・重複・導線を検討したうえでUI仕様を作る。
- **解釈:** ラベル・記事カード・視覚的階層に関する専用のUI設計仕様書を作成する；README・AGENTS・STATUS・DECISIONSはその仕様書ではない。2026-07-18の追加発言は、UI全体に対する一般的な感想ではなく、UI_SPEC.md Draft 0.1で未決だった7項目への明示的なユーザー裁定として扱う。
- **完了条件:** Fable 5が現行UIをレビューする；提案される仕様書が名称・色・形・配置・重複・導線・受入例を網羅する；ユーザーが仕様書を明示的に承認する。
- **依存関係:** 現行画面のレビュー資料；BL-002およびBL-003の実装の前提条件。
- **実装証跡:** Phase 1着手前は専用の仕様書が未実装だった。通常の記事カードを含む、現行UIのFable 5レビューは完了している。リポジトリ外で生成されたdashboardモックがレビューされ、2026-07-17のプロジェクト会話でユーザーに明示的に承認された；その承認がdashboard v2実装に反映され、結果として生じた用語決定（確認優先度ではなく重要度/確認目安）は[DECISIONS.md](DECISIONS.md)に記録されている。別途、リポジトリ外で生成された2案（A/B）の通常記事カードモックがユーザーによってレビューされ、ユーザーはvariant A（全分類ラベルを削除）ではなくvariant B（source/importance/urgency/categoryから丸ラベルを削除；関連タグのみ丸くクリック不可のまま維持）を明示的に選択した — この選択は上記BL-002/BL-003のもとに記録され、branch `feature/article-card-variant-b`で実装されている。これらのレビューは、当時は独立してリポジトリに常駐するUI設計仕様書（受入例付きの名称/色/形/配置/重複/導線契約）を生み出しておらず、モックレビューと明示的なユーザー決定に留まっていた。Phase 1として、これらの受入済み判断、BL-016〜BL-018、現行`main`実装と回帰テスト、Fable 5提案の採否・未決を統合した[UI_SPEC.md](UI_SPEC.md) Draft 0.1を[PR #30](https://github.com/matkei31/security-digest/pull/30)へ追加した。7項目のユーザー裁定を反映して[UI_SPEC.md](UI_SPEC.md)をVersion 1.0／承認済みへ更新し、最終成果物とした。7項目の確定判断、変更に必要な新しいユーザー判断とSupersedes契約を[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)へ記録した。[Pull Request CI run 29647361707](https://github.com/matkei31/security-digest/actions/runs/29647361707)が成功した[PR #30](https://github.com/matkei31/security-digest/pull/30)は、通常のmerge commit `198b5a6dc723870b691575ba89c2aaae89e35b8c`でmergeされた。merge後のfull unittest 1,120件と`git diff --check`が成功し、[Pages deployment run 29648894119](https://github.com/matkei31/security-digest/actions/runs/29648894119)も成功した。この作業ではUI実装、CSS／HTML、`docs/`、`data/`、workflow、Gemini prompt／schema／versionを変更していない。
- **ユーザー受入証跡:** Dashboardスコープ: 2026-07-17に受入。記事カードスコープ: ユーザーは2026-07-17のプロジェクト会話で通常記事カードのvariant（B）を明示的に選択し、別途2026-07-17にPC/390px実装を目視で受入（verbatim: 「見られたけど、いいと思うよ」；[BL-002](#bl-002--記事カードの楕円バッジ多用を見直す)/[BL-003](#bl-003--aiで機械処理された印象を弱める)参照）。これはdashboardと記事カードの*決定事項*自体に関するBL-004の完了条件を満たすが、依然として不足している専用の仕様書の代替にはならない（残作業を参照）。
- **追加のユーザー受入証跡:** 2026-07-18、ユーザーはUI_SPEC.md Draft 0.1で未決だった7項目の方針を、原文のまま次のとおり承認した：「7点ともこの方針でOK」。この発言は7項目の明示的な裁定であり、「UI全体が良い」などの一般的な受入発言へ言い換えない。
- **残作業:** なし。
- **注記:** Phase 1着手前に確認済みだった事実: README・AGENTS・STATUS・DECISIONSは存在したが、ラベル・記事カード・視覚的階層を定義する専用のUI設計文書は作成されていなかった。Fable 5レビュー自体は完了している（記事カードを含む）；ユーザーはその後、レビュー済みモックからdashboard（v2）と通常記事カード（variant B）の両方について、正式な仕様書を作成することなく具体的で明示的な選択を行った。この具体的なレビューと決定活動を反映するため、状態は`記録済み`から`仕様化済み / 進行中`へ移した。BL-004の完了は、既存UIの受入、UI_SPEC.md Version 1.0／承認済み、7項目の明示的な裁定を記録したSD-016、PR #30のmergeとmerge後検証を合わせた客観的証跡による。存在しない最終受入発言は追加していない。

## BL-005 — editorial-style-v1とtoday-brief-v4

- **ID:** BL-005
- **タイトル:** editorial-style-v1とtoday-brief-v4
- **優先度:** P1
- **状態:** 実装試行済み（v4/v5/v6）／No-Go／main未反映
- **出所種別:** ユーザー確認済み要約 (project decision)
- **ユーザー原文:** 原文未回収。
- **ユーザー確認済み要約:** Security Digest独自の`editorial-style-v1`を作り、最初はBRIEFへ部分導入し、`today-brief-v4`でGemini promptへ本文を埋め込む。ARTICLEへは初期適用しない。
- **解釈:** 設計と比較評価にはFable 5を用い、production向けBRIEF生成にはGeminiを維持する。外部Gistを全面的にコピーしない。
- **完了条件:** 十分には定義されていない。別途承認されない限り、決定論的なBRIEFのstate/count logic、trusted-context境界、ARTICLEとの分離、およびschemaを維持しなければならない。
- **依存関係:** [SD-007](DECISIONS.md#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first)；[SD-017](DECISIONS.md#sd-017--do-not-merge-prompt-only-todays-brief-experiments-redesign-semantic-validation-separately)；Fable 5デザインレビュー。
- **実装証跡:** 目的: Today's Briefへ構造ガードを追加しつつ、v3相当以上の編集品質と意味忠実性を維持できるかを検証した。試行結果: v4は構造ガードが成立したが編集品質Gate未達だった；v5はv3 promptへ戻し最小限の忠実性指示を追加し、API・構造・比較Gateは通過したが、外部主体の記事から金融機関自身の統制・支援施策を導く問題が発生した；v6は上記変換を禁止するprompt文を追加したが、同種の問題が両runで再発し、加えて2026年を2024年へ変更する事実改変が発生した。成功した事項: Gemini API 10/10 success、決定論的ガード262/262 pass、highlight適格性検証、source ID validation、public list[str] projection、未判定記事除外、public JSON／HTML／archive互換、ID laundering 0件、semanticな孤児参照0件、Run 1比較Gate通過、平均編集品質はv3を上回った。失敗した事項: 全run失格0を達成できなかった、入力にない金融機関主体・取引先関係・統制/支援施策を追加した、年月等の記事内事実を忠実に維持できなかった、prompt-only対策では再現性ある解消に至らなかった。実験commit（いずれもlocal-onlyであり、pushされておらずorigin/mainから到達できない。GitHub上で参照可能なcommitではない）: `2f35df1ead9255b441bfa17fb80f337ce4649052`（v4構造ガード実験）、`b2061d6f54005d16f19bc3838c95996f89b313b5`（v5構造ガード実装）、`a722d5471c91ba17e700b7fdb53133ad0f1f43bb`（Gemini schema互換修正）、`a97a9e9c2de05346ae0f1855b6d92143db21739e`（v6 prompt候補）。最終決定: BL-005はNo-Goとして終了する；experimental branch／commitはmainへ統合しない；v7のprompt-only再試行は行わない；構造ガードの知見は[BL-021](#bl-021--todays-briefの意味忠実性semantic-validation再設計)へ引き継ぐ；意味品質対策はBL-021で再設計する。詳細はSD-017を参照。
- **ユーザー受入証跡:** 編集品質・意味忠実性を改善する目的は維持する；ただし、editorial-style-v1をprompt-onlyでBRIEFへ導入する今回の実装経路はNo-Goであり、実装としてのユーザー受入は成立していない。
- **残作業:** なし（このBL-005自体の残作業はない）。意味品質対策は[BL-021](#bl-021--todays-briefの意味忠実性semantic-validation再設計)として別途再設計する。
- **注記:** Geminiはproduction向けBRIEF生成器であり続ける。ARTICLEは初期スコープ外である。この項目のGitHub上で追跡可能な唯一の出自は[PR #13](https://github.com/matkei31/security-digest/pull/13)の文書同期であり、そこでBL-005と[SD-007](DECISIONS.md#sd-007--create-security-digest-editorial-style-v1-and-introduce-it-to-brief-first)が同時に導入された；project conversation recordがこの方向性の実際の根拠であり、PR #13単独はユーザー受入の起点として扱わない（[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) Batch 2, Audit B参照）。原文は未回収のままである。今回のv4/v5/v6実装試行・screening・No-Go判定は、GitHub上のPRを経由せずローカルのexperimental branchで実施されたため、この注記に記録する（実験commit自体はGitHubへpushされていない）。

## BL-006 — Monomi Digestへのブランド変更

- **ID:** BL-006
- **タイトル:** Monomi Digestへのブランド変更
- **優先度:** P2
- **状態:** 方針承認済み / 未実装
- **出所種別:** ユーザー確認済み要約
- **ユーザー原文:** 原文未回収。
- **ユーザー確認済み要約:** 将来のサービス名は`Monomi Digest`とする。`Security Digest`と`Monomi Digest`のどちらにするかという未決定事項へ戻さない。
- **解釈:** 決定した将来のブランド名は`Monomi Digest`である。「Security DigestかMonomi Digestか」という未決定の命名選択として再オープンしない。
- **完了条件:** 未定義。実装範囲、移行timing、旧名称の扱いは未定のままである。
- **依存関係:** [SD-010](DECISIONS.md#sd-010--use-monomi-digest-as-the-future-public-brand)、BL-007；About、SEO、公開ナビゲーション、リポジトリおよび公開物の命名決定。
- **実装証跡:** 未実装。現行のproductおよびリポジトリ表示は`Security Digest`のままである。
- **ユーザー受入証跡:** 方向性は2026-07-17のプロジェクト会話で再確認された。実装受入は記録されていない。
- **残作業:** 全ブランド接点の棚卸し、移行と互換性の定義、実装、ユーザー受入の取得。
- **注記:** 本バックログへの導入は、現在表示されているブランドを変更してはならない。

## BL-007 — monomidigest.comへの移行

- **ID:** BL-007
- **タイトル:** monomidigest.comへの移行
- **優先度:** P2
- **状態:** 方針承認済み / 未実装
- **出所種別:** ユーザー原文 / ユーザー確認済み要約
- **ユーザー原文:** 「URLがgithubのユーザー名なのが気になる」
- **出所:** 2026-07-09 プロジェクト会話。
- **ユーザー確認済み要約:** 主ドメインは`monomidigest.com`とし、`monomi.jp`は不要とする。
- **解釈:** 主ドメインとして`monomidigest.com`を使用する。記録された決定では`monomi.jp`は不要とされている。
- **完了条件:** 未定義。実装前にドメインの所有権とDNSの状態を検証する必要がある。
- **依存関係:** [SD-011](DECISIONS.md#sd-011--use-monomidigestcom-as-the-primary-domain)、BL-006、Aboutコンテンツ、SEO、canonical URL、公開ナビゲーション。
- **実装証跡:** 未実装。ドメイン取得とDNS設定は未検証である。
- **ユーザー受入証跡:** 方向性は2026-07-17のプロジェクト会話で再確認された。ドメイン取得、設定、実装受入は記録されていない。
- **残作業:** 所有権の検証、DNS/Pages設定とredirectの定義、公開metadataの更新、テスト、ユーザー受入の取得。
- **注記:** ドメインが購入または設定済みであると推定しない。

## BL-008 — Fable 5による全体コードレビュー

- **ID:** BL-008
- **タイトル:** Fable 5による全体コードレビュー
- **優先度:** P2
- **状態:** 記録済み
- **出所種別:** 復元要約
- **ユーザー原文:** 原文未回収。
- **ユーザー確認済み要約:** 回収できていない。
- **解釈:** 適切な安定した時点で、構造・重複・責務・過剰実装・保守性についての批判的な全体コードレビューを行う。
- **完了条件:** 未定義。
- **依存関係:** 十分に安定した実装baseline、および合意されたレビューパッケージ。
- **実装証跡:** 未実装。
- **ユーザー受入証跡:** 記録なし。
- **残作業:** timing、レビューの観点、証跡パッケージ、評価者の役割、および発見事項をどのようにスコープ付きチケットへ落とし込むかを定義する。
- **注記:** 本項目により、Fable 5を通常の実装エージェントとして指定するものではない。

## BL-009 — SEOと閲覧者増加策

- **ID:** BL-009
- **タイトル:** SEOと閲覧者増加策
- **優先度:** P2
- **状態:** 記録済み / 前提条件が整うまで保留
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「あとでSEO対策や見てもらうための工夫について相談」
- **追加のユーザー原文:** 「そういう話をするタイミングになったら教えて」
- **出所:** 2026-07-13 プロジェクト会話。
- **ユーザー確認済み要約:** 該当なし — 原文は上記のとおり回収済み。
- **解釈:** 後日、SEOと閲覧者増加策を見直し、前提条件が整った適切なtimingでこの話題を取り上げる。
- **完了条件:** 未定義。
- **依存関係:** Ticket 14a-3およびTicket 14a-4は完了しており、再オープンの前提条件ではない。SEO開始時に、新たなP0/P1のデータ品質課題が未対応でないことを確認する。また、BL-006、BL-007、日本語版の編集仕様、BL-002〜BL-004、Aboutコンテンツ、metadata、公開ナビゲーションにも依存する。
- **実装証跡:** 未実装。
- **ユーザー受入証跡:** 記録なし。
- **残作業:** 読者層と目標の定義、技術/コンテンツSEOの監査、施策の優先順位付け、個別実装、成果の測定。
- **注記:** 前提条件が整うまで保留。原文はBL-014の最終完了パス（2026-07-18）で回収された；[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)を参照。

## BL-010 — 多言語対応の意義判断

- **ID:** BL-010
- **タイトル:** 多言語対応の意義判断
- **優先度:** P3
- **状態:** 記録済み / 前提条件が整うまで保留
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「このサイトを多言語対応する意味はあるか相談しよう。そのうち」
- **出所:** 2026-07-13 プロジェクト会話。
- **ユーザー確認済み要約:** 該当なし — 原文は上記のとおり回収済み。
- **解釈:** 日本語版が安定した後、多言語対応がコストに見合う十分な価値を提供するかを判断する。
- **完了条件:** 未定義。これは当初、実装チケットではなく決定事項の検討である。
- **依存関係:** 日本語版の安定、BL-009、対象読者層の定義、規制上のmapping需要。
- **実装証跡:** 未実装。
- **ユーザー受入証跡:** 記録なし。
- **残作業:** 候補言語、読者層にとっての価値、編集/翻訳コスト、規制上の影響、SEOへの影響、決定基準の定義。
- **注記:** 前提となる決定の前に実装を開始しない。原文はBL-014の最終完了パス（2026-07-18）で回収された；[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)を参照。

## BL-011 — standalone NIST NVD記事取得の保留理由・再開条件

- **ID:** BL-011
- **タイトル:** standalone NIST NVD記事取得の保留理由・再開条件
- **優先度:** P2
- **状態:** 記録済み
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — 技術上の発見事項。
- **ユーザー確認済み要約:** 未定義。
- **解釈:** standalone NIST NVD記事収集が無効化されている理由を文書化し、NVD脆弱性factsの取得と混同しない形で、証跡に基づく再開条件を定義する。
- **完了条件:** 保留理由、担当者、レビューのトリガー、再開条件、検証計画が記録されている；別経路のNVD facts取得は稼働を継続し、明確に区別されている。
- **依存関係:** ソースの履歴と現行の`source_definitions.json`の挙動。
- **実装証跡:** 未実装。このgapは[STATUS.md](STATUS.md)に記録されている；NVD factsは別経路で継続している。
- **ユーザー受入証跡:** 現時点では該当なし。
- **残作業:** 元の運用上の理由の回収、再開条件の仕様化、該当するsource/status記録の更新。
- **注記:** 本項目は、直ちにsourceを再有効化することを求めるものではない。

## BL-012 — Gemini応答エラー分類の細分化

- **ID:** BL-012
- **タイトル:** Gemini応答エラー分類の細分化
- **優先度:** P2
- **状態:** 記録済み
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — 技術上の発見事項。
- **ユーザー確認済み要約:** 未定義。
- **解釈:** 現行の`schema_parse_error`分類は、JSONデコード、response-schema不一致、strict validation、semantic/action-lint失敗を十分に区別できていない。
- **完了条件:** 未定義。分類体系、互換性、observability上の効果、コスト、移行時の挙動について仕様化が必要である。
- **依存関係:** ARTICLEのstatus/fallback契約と運用上の報告要件。
- **実装証跡:** 未実装。Ticket 17aは1件のlint誤検知を修正したが、汎用的なエラー分類体系は導入していない。
- **ユーザー受入証跡:** 現時点では該当なし。
- **残作業:** 失敗経路の棚卸し、安定した分類の提案、schema/logging影響の評価、テストの定義、承認の取得。
- **注記:** 本項目のもとでTicket 17aを再オープン・再実装しない。

## BL-013 — GitHub Actions Node.js警告

- **ID:** BL-013
- **タイトル:** GitHub Actions Node.js警告
- **優先度:** P3
- **状態:** 保留
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — 技術上の発見事項。
- **ユーザー確認済み要約:** 未定義。
- **解釈:** GitHub Pagesのbuild/deployは現在成功しているが、actionsからNode.js runtimeの非推奨警告が出力されている。警告内容、サポート対象version、期限が検証されるまで、投機的なアップグレードを開始しない。
- **完了条件:** workflowを変更する前に、影響を受けるaction version、GitHubの期限、サポートされる置換経路、回帰計画を確認する。
- **依存関係:** GitHub Actions/Pagesの公式ガイダンスと承認されたworkflow保守スコープ。
- **実装証跡:** 是正は実施していない。直近のPages build/deploymentは、警告が出ているにもかかわらず成功している。
- **ユーザー受入証跡:** 現時点では該当なし。
- **残作業:** 緊急度の検証、必要な場合のサポート対象action versionの選定、build/deploy挙動のテスト、workflow変更の承認取得。
- **注記:** 保留の理由は、現行のbuildが成功しており、ここに検証済みの期限が記録されていないためである。

## BL-014 — 過去ユーザーコメントの体系的棚卸し

- **ID:** BL-014
- **タイトル:** 過去ユーザーコメントの体系的棚卸し
- **優先度:** P0
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「うん。他に未対応と見られる私のコメントある？同じように汎化してるなら私自身のコメントに立ち返って確認して。本来、指摘コメントを勝手に書き換えて対応済み扱いするのありえないから。ちゃんとバックログ管理して」
- **ユーザー確認済み要約:** 過去のプロジェクト会話にある指摘・要望を原文へ立ち返って棚卸しし、実装済み、部分対応、未対応、受入待ち、置換済み、バックログ対象外のいずれかへ根拠付きで分類する。実装側が作った一般化表現で原コメントを置き換えない。
- **解釈:** PR #16のBL-001〜BL-013は初期登録であり、過去のユーザーコメントを網羅的に監査した結果ではない。会話履歴、PRコメント、既存文書、完了記録を照合して、取りこぼしと誤完了を確認する。
- **完了条件:** 棚卸し対象の会話範囲と期間を明示する。原文を取得できたコメントは原文のまま記録し、原文未回収は引用しない。各コメントを既存BL ID、新規BL ID、完了済み参照、置換済み、対象外のいずれかへ割り当てる。部分対応は残作業を残す。完了判断にはPRだけでなく、必要に応じてユーザー受入を確認する。棚卸し結果をユーザーがレビューし、未分類コメントが残っていないかを明記する。
- **依存関係:** プロジェクト会話履歴、GitHub PR／コメント、README／STATUS／DECISIONS／BACKLOG、実装証跡へのアクセス。
- **実装証跡:** PR #16は管理方式と初期項目を作成した。2026-07-17、第1バッチ（Candidate A〜F）の監査を実施し、A→BL-007更新、B→SD-014、C→BL-015、D→完了済み参照、E→対応不要（新規BLなし）、F→BL-015スコープ内で評価対象として記録、へそれぞれ分類した。2026-07-18、第2バッチを実施し、PR化以前のdirect push 149 commitsを21機能グループ（PRE-00〜PRE-20）へ分類し、BL-005／BL-008／BL-009／BL-010をGitHub上で確認できる証跡の範囲に限定して監査した。PR #1／#2／#3／#8を完了済み参照へ追加し、PR #6（Ticket 15a）を履歴・置換済み参照として記録し、Ticket 5／7／11bを置換済み参照として記録した。PR #8の内部識別子漏洩修正を一般化してSD-015として記録し、PR #9（Ticket 15c）の目視受入未確認をBL-016として記録した。2026-07-18、最終完了パスを実施し、BL-009へ原文2件、BL-010へ原文1件をそれぞれ別フィールドで追記した。BL-005・BL-008は原文未回収のまま確定した（今後の追加回収を前提としない最終状態として記録）。現時点で把握している未分類の過去コメントはない。PR #11〜#16／PR #19を最終確認し、新規の管理項目（BL／完了済み参照／置換済み参照）は不要と判断した。Aboutコンテンツ／metadata／公開ナビゲーションは、既存の[BL-006](#bl-006--monomi-digestへのブランド変更)／[BL-007](#bl-007--monomidigestcomへの移行)／[BL-009](#bl-009--seoと閲覧者増加策)の範囲で管理する。監査範囲・手法・各分類の根拠は[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)に記録。
- **ユーザー受入証跡:** バックログ管理方式の導入には同意済み。第1・第2バッチの分類記録は実施済み。2026-07-18、ユーザーはBL-014全体の完了について次のとおり明示的に承認した（verbatim）：「BL-014は拾えるだけ拾ったから完了にするってことね。まあいいよ」
- **残作業:** BL-014（過去ユーザーコメントの体系的棚卸しという工程）自体の残作業はない。BL-005・BL-008の原文は未回収のまま確定した恒久的な記録であり、今後の再回収を前提としない。個別の未完了項目（[BL-001](#bl-001--プルリクエストci)、[BL-004](#bl-004--fable-5によるuiレビューとui設計書)、[BL-006](#bl-006--monomi-digestへのブランド変更)、[BL-007](#bl-007--monomidigestcomへの移行)、[BL-015](#bl-015--公開サイトと生成基盤のセキュリティ要件を定義する)、[BL-017](#bl-017--過去ダイジェストの回遊性と一覧表示を改善する)等）は、BL-014の完了と独立してそれぞれ継続する。
- **注記:** BL-014の完了は、現時点で把握している範囲での棚卸し完了を意味する。今後、新たに過去コメントの存在が判明した場合は、原文とともに追記する（[初期移行範囲](#初期移行範囲)の原則を維持）。第1・第2バッチおよび最終完了パスの実施内容は[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)に記録されている。

## BL-015 — 公開サイトと生成基盤のセキュリティ要件を定義する

- **ID:** BL-015
- **タイトル:** 公開サイトと生成基盤のセキュリティ要件を定義する
- **優先度:** P2
- **状態:** 記録済み / 未完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「セキュリティ要件みたいなのも後で決めよう」
- **追加のユーザー原文:** 「OK.ここはfable5にもレビューしてもらおう。公開情報を扱うものだから厳しいセキュリティ対策をする必要はないと思うが、必要なものは網羅しつつ過剰じゃないように整理して、fable5にレビューさせられる形にして。」
- **ユーザー確認済み要約:** 記録なし。
- **解釈:** 静的な公開サイト、GitHub Actions、外部fetching、Gemini、保存データ、secrets、将来のcustom domain利用について、現行アーキテクチャに見合ったセキュリティ要件一式を、専用文書（候補名`SECURITY_REQUIREMENTS.md`、GitHubの脆弱性報告用`SECURITY.md`とは別）として定義する。過剰な対策を一律に導入しない；各項目について必要性と再評価条件を明示的に述べる。
- **完了条件:** 文書は次を定義する: 対象systemとdata flow；trusted/untrusted境界；保存してよいものといけないもの；外部URLの扱い、HTMLエスケープ、`safe_url`；secrets管理；GitHub Actions権限；ログ/artifactsの扱い；依存関係とGitHub Actionsのsupply chain管理（full commit SHA pinningおよびGitHub Actions向けDependabotの明示的な必要性評価を含む）；現行のleast privilegeの状態；custom domain採用時の再評価トリガー；forms・認証・データベース・永続storageを追加する際の再評価トリガー；現行の対策・特定されたgap・特定の対策を採用しない理由の明確な区別；Fable 5レビューパス；最終的なユーザー承認。full commit SHA pinning、Dependabot、および同様の具体的対策は、この段階で必須と決定するものではない — 上記の評価が特定のgap対応を承認した場合にのみ、別チケットとなる。
- **依存関係:** 現行アーキテクチャ；[BL-001](#bl-001--プルリクエストci)（プルリクエストCI）と調整；[BL-007](#bl-007--monomidigestcomへの移行)（monomidigest.comへの移行）と調整；`AGENTS.md`（「Security requirements」節）と`DECISIONS.md`にすでに記録されている既存のセキュリティルール。
- **実装証跡:** 個別のルールはすでに存在する（`AGENTS.md`: HTMLエスケープ、`http`/`https`のみのリンク、`rel="noopener noreferrer"`、承認なしでのforms/認証/データベース/新規外部依存/永続storageの追加禁止、標準ライブラリ/既存依存のみの方針、静的GitHub Pagesとの互換性）が、包括的で専用の要件文書は存在しない。`.github/workflows/fetch.yml`は現在、`actions/checkout@v4`と`actions/setup-python@v5`をversion tagで参照しており（full commit SHAではない）、`.github/dependabot.yml`は存在しない — ここでは評価対象項目として記録するにとどめ（[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)のBL014-F参照）、確定した要件としては扱わない。
- **ユーザー受入証跡:** 記録なし。方向性（後で決める、Fable 5にレビューさせる、という点）は元のコメントから把握しているが、要件案はまだユーザーによるレビュー・承認を受けていない。
- **残作業:** 要件案の作成、証跡のmapping、比例性のレビュー、Fable 5レビュー、承認された具体的対策に対するgapチケットの判断、ユーザー受入。
- **注記:** 本チケットの評価が完了する前に、SHA pinning、Dependabot、その他個別のActions supply chain対策を必須と決定しない。本項目の出典となった監査記録は[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) Batch 1（BL014-C、BL014-F）を参照。

## BL-016 — 本日の要点の表示階層を目視受入する

- **ID:** BL-016
- **タイトル:** 本日の要点の表示階層を目視受入する
- **優先度:** P2
- **状態:** 完了
- **出所種別:** 技術上の発見事項 / 過去の受入ギャップ
- **ユーザー原文:** 該当なし — 技術上の発見事項。
- **ユーザー確認済み要約:** 該当なし — 技術上の発見事項。
- **解釈:** Ticket 15c（[PR #9](https://github.com/matkei31/security-digest/pull/9)）は、現行の「本日の要点」表示を実装した: トップページと日別archiveでの親見出しの改称、`overview`の残り部分からの決定論的な状態行の分離、`discussion_points`/`check_items`が空の場合のセクション非表示動作。この表示のコードとテストは存在するが、PR #9の本文はmerge時点でproduction受入が実施されていないことを明記しており、本監査ではこの特定の表示変更について、GitHub履歴上のいかなる場所にも、その後の明示的なユーザー受入記録を見つけられなかった。
- **完了条件:** 現行productionで目視確認する: PC表示；390px表示；「本日の要点」見出し；決定論的な状態行の背景・境界線・余白；状態行と概況本文の視覚的階層；`discussion_points`/`check_items`が空の場合に非表示となること；長文および件数の折返し挙動；archive表示との整合性；明示的なユーザー受入。
- **依存関係:** 現行production表示；[PR #9](https://github.com/matkei31/security-digest/pull/9)；現行`fetch.py`；archive表示。
- **実装証跡:** [PR #9](https://github.com/matkei31/security-digest/pull/9), merge commit `82b23c720b5871c5f46d068813defc12af164e4a`；現行実装（`fetch.py`内の`split_brief_overview_status_line()`と「本日の要点」見出し）；`test_fetch.py`/`test_archive.py`の回帰テスト。BL-016残対応として、決定論的な状態行を「本日の状態」ラベル・括弧・コロン・文末の句点を除いた｜区切り形式（`掲載{件数}件｜重要度「高」{件数}件｜本日確認{件数}件｜今週確認{件数}件`、未判定区分は既存条件のまま0件超の場合のみ付加）へ変更した（`format_brief_status_line()`）。新規生成するoverviewでは、`apply_deterministic_brief_context()`が状態行の直後に改行を1つ挿入し、daily JSON上の明示的な境界とする（HTML表示では改行自体は見せず、従来どおり別要素へ分離する）。`split_brief_overview_status_line()`は、現行形式について「改行または文字列末尾」を正しい境界として要求し（数字列の途中などをprefix matchしない）、既存data/JSONに保存済みの旧形式（句点終端）overviewは書き換えず、表示時にのみ数値を保ったまま現行形式へ変換する後方互換ロジックを維持する。加えて、決定論的状態行を一切含まない旧BRIEF（Ticket 15b以前の自由文のみのoverview）については、`synthesize_legacy_brief_status_line_from_digest()`が`digest_items_for_html()`で保存済み記事を復元し、`is_article_evaluated()`／`compute_brief_trusted_context()`と共通の記事単位判定で状態行を算出し、archive表示（`build_daily_archive_html()`）に限り補完する（overview文字列自体・トップページの通常生成には適用しない）。既存の全日別archive HTML（`docs/archive/2026-07-11.html`〜`2026-07-18.html`および`docs/archive/index.html`）をGemini・外部HTTP・記事再分析を行わずに既存daily JSONと現行テンプレートから再生成した。決定論的状態行を含む2026-07-15〜2026-07-18の4ファイルは状態行の表記のみ変更し、旧BRIEF（自由文のみ）の2026-07-11・07-12・07-14の3ファイルはarchive表示専用のbrief-status-line要素が新たに補完された。記事内容・概況本文・件数・順序・分析結果および`data/`配下のJSON内容は変更していない（2026-07-13はbrief自体が存在しないため、既存挙動のまま変更なし）。[PR #23](https://github.com/matkei31/security-digest/pull/23), merge commit `b8c0ab0fa5411930fc55b1b9f97cfda016c29373`。
- **ユーザー受入証跡:** PC/390px実装の見た目について、ユーザーは原文のまま次のとおり述べた：「見た目いいと思うよ。「本日の状態」という言葉があんまりかっこよくないから、いくつか案出して検討したいね。」。ラベル案の検討を経て、ユーザーは次のとおり明示的に文言決定した：「うん。「本日の状態」は「1. ラベルをなくす — 最有力」でいこう」。この2件の原文のままの発言により、PC/390px表示自体の受入と、「本日の状態」ラベルを除去する文言変更方針の受入は得られている。最終受入証跡として、ユーザーは原文のまま次のとおり述べた：「新しい表示もPC・390px・過去ダイジェストとも問題なし」
- **残作業:** なし。
- **注記:** 本項目は新規UI実装を提案するものではなく、[BL-014](#bl-014--過去ユーザーコメントの体系的棚卸し) Batch 2で確認された既存の受入ギャップを記録するものである。監査の詳細は[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) Batch 2を参照。ラベル除去案は、ユーザーが複数案から明示的に選択した文言決定であり、上記ユーザー受入証跡の原文のままの発言を出典とする。

## BL-017 — 過去ダイジェストの回遊性と一覧表示を改善する

- **ID:** BL-017
- **タイトル:** 過去ダイジェストの回遊性と一覧表示を改善する
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「あと、過去のダイジェストについて、ワンクリックで前日分とかに行き来できる改修はこれから？」
- **追加のユーザー原文:** 「だけど、この画面で「本日の要点あり」の記載は必要かな？不要な気がする」
- **ユーザー確認済み要約:** 該当なし — 原文は上記2件のとおり回収済み。
- **解釈:** 過去ダイジェスト一覧から「本日の要点あり」「本日の要点なし」の行を両方削除し、代替ラベルは追加しない。一覧カードは日付、記事数、重要度「高」の件数のみ表示する。日別archiveのカレンダー上の前日・翌日ではなく、実在するarchive日付（daily JSONが存在し、archiveが生成されている日）の前後へ、ワンクリックで移動できるナビゲーションを追加する。既存の「最新のダイジェストへ戻る」「過去のダイジェスト一覧へ戻る」は維持する。
- **完了条件:** 過去ダイジェスト一覧に「本日の要点あり」「本日の要点なし」および代替ラベルを表示せず、各カードが日付、記事数、重要度「高」の件数だけを表示する；各日別archiveページのページ上部と最下部の両方に前後ナビゲーションを配置する；移動先は実在するarchive日付のみとし、カレンダー上の前日・翌日ではない；最古のarchiveでは「前」方向のリンクを表示せず、最新のarchiveでは「次」方向のリンクを表示しない；既存の「最新のダイジェストへ戻る」「過去のダイジェスト一覧へ戻る」を維持する；daily JSONを変更せず、実装コードとテストで検証し、ユーザー受入を得る。
- **依存関係:** 既存の`docs/archive/*.html`生成ロジック（`build_daily_archive_html()`、`generate_archive_outputs()`）；`data/index.json`のarchive日付一覧。
- **実装証跡:** `archive_summary_from_digest()`から不要な`brief_status`生成を削除し、`build_archive_index_html()`の一覧カードを日付、記事数、重要度「高」の件数だけにした。`generate_archive_outputs()`は検証済みdaily JSONを先に読み込んで実在日付の前後関係を作り、`build_daily_archive_html()`へ直前・直後の日付を渡す。日別archiveの上部と最下部には`render_archive_adjacent_links()`が境界条件に応じた前後リンクを生成し、既存の戻りリンクは維持する。日付欠損、最古・最新、中間日、上下両方のナビゲーション、一覧表示、daily JSON不変を`test_archive.py`で検証した。Gemini・外部HTTP・記事再分析を行わず、既存daily JSONから`docs/archive/2026-07-11.html`〜`2026-07-18.html`と`docs/archive/index.html`を再生成した。[PR #24](https://github.com/matkei31/security-digest/pull/24), merge commit `8cb8e95639d125fec31057737bb4c445252433f7`。
- **ユーザー受入証跡:** 2026-07-18、ユーザーはBL-017の一覧表示と前後ナビゲーションの両方について、原文のまま次のとおり完了を承認した。

「読み直したらできたわ。以下どちらも完了でOK


過去ダイジェスト一覧
「本日の要点あり／なし」が消え、日付・記事数・重要度だけになっているか
7月14日など途中の日別ページ
上部と最下部に「前のダイジェスト」「次のダイジェスト」があり、実際に移動できるか」
- **残作業:** なし。
- **注記:** 前後リンクの対象日付は、生成時に検証を通過した既存daily JSONの日付一覧から決定する。

## BL-018 — トップページとJSON再構築時の記事時刻表示を一致させる

- **ID:** BL-018
- **タイトル:** トップページとJSON再構築時の記事時刻表示を一致させる
- **優先度:** P1
- **状態:** 完了
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — 技術上の発見事項。
- **ユーザー確認済み要約:** 該当なし — 技術上の発見事項。
- **解釈:** 再現テストにより、通常生成のin-memory itemでは`parse_date()`が記事日時をUTC-naiveの`date`として保持する一方、daily JSONには同じ瞬間をJST aware（`+09:00`）の`published_at`として保存し、`digest_items_for_html()`はそのoffsetを保持したaware datetimeへ復元することを確認した。従来の`build_html()`が経路の異なる`date`をタイムゾーン正規化せず直接`strftime()`していたため、同一記事の`article-meta`が通常生成ではUTC相当、JSON復元ではJSTとして9時間ずれていた。
- **完了条件:** 原因を再現テストで確定する；表示時刻の基準をJSTへ統一する；通常生成とdaily JSON再構築で同一表示になる；記事順、`published_at`の保存値、日付判定を意図せず変更しない。
- **依存関係:** 現行`fetch.py`（`digest_items_for_html()`、`main()`内のトップページ生成、`parse_archive_datetime()`）；`data/`配下の既存daily JSON。
- **実装証跡:** 発見時の経緯として、BL-016残対応PRの作業中に`digest_items_for_html()`経由のトップページ再構築と本番生成時の時刻差を確認し、当時は対象外としてフル再構築を行わなかった。本対応では既存`data/2026-07-18.json`の「New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code」（`https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html`）を使い、同じ瞬間が通常生成相当のUTC-naive `2026-07-17 21:20:10`（表示`07/17 21:20`）とJSON復元相当のJST aware `2026-07-18 06:20:10+09:00`（表示`07/18 06:20`）に分かれる9時間差を先に失敗する回帰テストで固定した。`normalize_datetime_for_display()`へaware datetimeのJST変換を集約し、`format_article_meta_time()`は`published_at_jst`、`published_at`、`date`の順に有効な日時を選んで表示する。ISO 8601の`Z`、`+00:00`、`+09:00`はoffsetを保持して解釈し、UTC/JST awareは同じJST表示へ正規化する。実データ調査では既存daily JSONの非null `published_at` 59件は全件`+09:00`でnaive値はなく、legacy naive値は根拠のないUTC/JST推定をせず従来どおりwall-clock値として扱う。保存値、記事順、当日判定、不正日時fallbackを不変とするテストと既存daily JSON回帰テストを追加した。既存JSONから一時生成した全9個のarchive HTMLはcommit済み版と完全一致し、`docs/index.html`だけは8記事の`article-meta`をJSTへ最小修正した（記事内容、順序、BRIEF、分析結果、件数は不変）。Gemini、外部HTTP、RSS再取得、記事再分析、daily JSON／`data/index.json`更新は実行していない。[PR #28](https://github.com/matkei31/security-digest/pull/28)は通常のmerge commit `196c77bcc2b71f8aecd9d0c6aef03388ffd5edf1`でmergeされた。[Pull Request CI run 29642324466](https://github.com/matkei31/security-digest/actions/runs/29642324466)ではfull unittest 1,113件とPRのbase/head差分に対する`git diff --check`が成功した。merge後もBL-018関連テスト8件、full unittest 1,113件、`git diff --check`が成功し、daily JSON、`data/index.json`、記事順、digest日付、当日判定が不変であることを確認した。[Pages deployment run 29643207764](https://github.com/matkei31/security-digest/actions/runs/29643207764)も成功した。
- **ユーザー受入証跡:** 2026-07-18、ユーザーはトップページの代表2記事のJST時刻、記事順、本文を確認し、原文のまま次のとおり受け入れた。

「トップページの時刻はWP2Shellが07/18 06:20、Gold Eagle Clearinghouseが07/17 22:00で、記事順・本文も問題なし。」
- **残作業:** なし。
- **注記:** 本項目は技術上の発見事項であり、実装・merge・表示確認・ユーザー受入の完了を確認して完了へ移した。

## BL-019 — 収集元見出し件数と列挙対象を一致させる

- **ID:** BL-019
- **タイトル:** 収集元見出し件数と列挙対象を一致させる
- **優先度:** P2
- **状態:** 完了
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — 技術上の発見事項
- **ユーザー確認済み要約:** 未定義。
- **解釈:** 収集元フッターは、`source_definitions.json`で`enabled=true`の全取得元を`collection_method`にかかわらず定義順で列挙し、見出し件数も必ず同じ集合から算出する。CISA KEVは含め、無効化中のCISA advisory RSSとstandalone NIST NVD記事収集は除外する。NISTニュースRSSは含め、別経路のNVD vulnerability factsは記事収集元一覧へ含めない。各取得元の有効状態、取得方法、再開条件は変更しない。
- **完了条件:** 見出し件数と収集元`li`数が一致する；表示集合が`enabled=true`の全定義と定義順まで一致する；CISA KEVとNISTニュースRSSを含む；無効化中のCISA advisory RSSとstandalone NIST NVD記事収集を除外する；通常トップページとdaily JSONから再構築した日別Archiveで収集元表示が一致する；daily JSON、`data/index.json`、source定義、schema、ARTICLE／BRIEF prompt、workflowを変更しない；既存daily JSONと現行設定だけで対象HTMLを再生成し、収集元見出し以外の記事内容・順序・BRIEF・時刻・件数を変更しない；関連テスト、full unittest、Pull Request CI、`git diff --check`が成功する；Pages公開表示で、見出し件数と列挙件数が一致し、期待する収集元集合が表示されることを確認する。
- **依存関係:** 現行`source_definitions.json`；[SD-003](DECISIONS.md#sd-003--disable-cisa-advisory-rss-and-obtain-cisa-kev-from-the-official-github-mirror)；[BL-011](#bl-011--standalone-nist-nvd記事取得の保留理由再開条件)と意味を共有するが、その完了には依存しない。
- **実装証跡:** `build_footer_sources()`が`enabled=true`の定義を定義順で返し、`build_html()`はその同じ戻り値から見出し件数と`li`一覧を生成する。固定の`len(RSS_FEEDS) + 2`とCISA KEVの個別追加を削除し、通常トップページとdaily JSON復元Archive、enabled／disabledのRSS・非RSSを混在させたfixtureで契約を検証した。既存daily JSONと現行設定から、外部HTTP、Gemini、RSS取得、ARTICLE／BRIEF再生成なしでトップページと全9日別Archive（2026-07-11〜2026-07-19）を再生成した。[PR #32](https://github.com/matkei31/security-digest/pull/32)を通常のmerge commit `d08a1b00d43488892ba6ef74b184340ab14a72c0`として2026-07-20 00:06:16 JSTにmergeした。merge後のfull unittest 1,122件、`git diff --check`、Markdownリンク確認が成功した。[Pages workflow run 29692162999](https://github.com/matkei31/security-digest/actions/runs/29692162999)のbuild／deploy／report-build-statusはすべてsuccessだった。公開トップページと最新Archive（2026-07-19）は「収集元 (15ソース)」かつ展開後15項目で、CISA KEVを含み、CISA advisory RSSとstandalone NIST NVD記事収集を含まないことを確認した。2026-07-18の記事、BRIEF、時刻、件数、前後ナビに変更がないことも確認した。
- **ユーザー受入証跡:** 公開画面確認後のユーザー原文は「うん。バックログに入れるなりしてどこかで直せるように管理しよう。んで、次進もう」。この発言は、15ソースへの件数修正について別途やり直しを求めておらず、色分けをBL-019とは別の後続課題として管理して次へ進む、という範囲だけの受入として記録する。UI全体を包括的に承認した発言として一般化しない。
- **残作業:** なし。
- **注記:** 2026-07-18のFable 5サイトレビューで検出された技術上の発見事項であり、Fable 5の指摘をユーザー発言として扱わない。発見時の現行設定は全17定義、`enabled=true` 15件、`enabled=false` 2件だった。

## BL-020 — 収集元一覧の取得元別カラーを廃止する

- **ID:** BL-020
- **タイトル:** 収集元一覧の取得元別カラーを廃止する
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー原文 / ユーザー確認済み要約
- **ユーザー原文:** 「なんで色分けしてるんだっけ？」
- **追加のユーザー原文:** 「うん。バックログに入れるなりしてどこかで直せるように管理しよう。んで、次進もう」
- **ユーザー確認済み要約:** ページ末尾の折りたたみ式「収集元」一覧について、取得元ごとの背景色と色付きpill表現を廃止し、無彩色で低強調のプレーンな一覧表示へ変更する。後続のUI修正として管理し、BL-019の件数修正とは分離する。
- **解釈:** 対象はページ末尾の「収集元」一覧である。記事カード内の`article-meta`は既にプレーン表示であり、今回の対象外とする。収集元の名称、件数、`enabled`判定、定義順は変更せず、トップページと日別Archiveで同一表示にする。色に意味体系や凡例がなく、複数ソースが同じ色であるため、識別機能より装飾性が上回っている。[BL-002](#bl-002--記事カードの楕円バッジ多用を見直す)／[BL-003](#bl-003--aiで機械処理された印象を弱める)の「色付き楕円ラベルの多用を避ける」という方向へ整合させる。現行[UI_SPEC.md](UI_SPEC.md) 12.1の「取得元別カラーを維持する」と競合するため、実装時に正式に置換する。
- **完了条件:** 各収集元`li`から取得元別のinline `background`指定を削除する；色付きpillではなく、無彩色・低強調のプレーンな一覧として表示する；15ソースという件数、列挙対象、定義順を変更しない；CISA KEVも他の収集元と同じ通常表示にする；トップページとすべての日別Archiveで同じ表示になる；[UI_SPEC.md](UI_SPEC.md) 12.1を新仕様へ更新する；必要な[DECISIONS.md](DECISIONS.md)の`Supersedes`関係を記録する；PCと390pxで折返し、可読性、横スクロールを確認する；関連テスト、full unittest、Pull Request CI、`git diff --check`が成功する；ユーザーがmerge前の生成screenshotsを目視受入し、merge後の公開Pagesがその受入済み表示と一致することを客観確認する。
- **依存関係:** [BL-002](#bl-002--記事カードの楕円バッジ多用を見直す)；[BL-003](#bl-003--aiで機械処理された印象を弱める)；[BL-004](#bl-004--fable-5によるuiレビューとui設計書)／[UI_SPEC.md](UI_SPEC.md) Version 1.3；[BL-019](#bl-019--収集元見出し件数と列挙対象を一致させる)；[SD-023](DECISIONS.md#sd-023--remove-source-specific-colors-and-pill-styling-from-the-source-footer)；現行`build_footer_sources()`および`build_html()`。
- **実装証跡:** `build_html()`の収集元`li`から取得元別inline backgroundを削除し、背景・border・pill状radius・chip状paddingを持たない補助テキスト色のプレーン一覧へ変更した。件数、enabledな15ソースの集合、定義順、CISA KEVの表示、`ul`／`li`構造、トップページ／日別Archiveの共通表示は維持する。PCは3列、600px以下は1列とし、既存daily JSONだけからトップページと全日別Archiveをoffline再生成した。[UI_SPEC.md](UI_SPEC.md) Version 1.3と[SD-023](DECISIONS.md#sd-023--remove-source-specific-colors-and-pill-styling-from-the-source-footer)へ表示契約を記録し、関連33 tests、full unittest 1156 tests、Markdown内部リンク、全15生成ページのフッター契約、`git diff --check`が成功し、`data/`と`data/index.json`は不変である。repository-external `BL-020/neutral-source-footer/`にトップページ／日別ArchiveそれぞれのPC 1280px／390px screenshotsを保存した。実装commit `f6990564de8f84dabdd2e614a7fe72996cf961fe`、最終受入記録head `1d55897e1241138d6bbb0bd2bd2381e10bc05f2e`を含む[PR #41](https://github.com/matkei31/security-digest/pull/41)をmerge commit `d16a2ce28c05a2381d98ed3dbb28599ebd317b7b`で通常mergeした。[Pull Request CI run 30068786053](https://github.com/matkei31/security-digest/actions/runs/30068786053)と[Pages deployment run 30068840298](https://github.com/matkei31/security-digest/actions/runs/30068840298)は成功した。merge後の公開トップページ／2026-07-24日別ArchiveをPC 1280px／390pxで客観確認し、15ソース、集合、定義順、CISA KEVの通常表示、PC 3列／390px 1列、色なし、pillなし、折返し、低強調、横スクロール・重なり・文字切れなし、`details`／`summary`とbrowser標準focus表示が受入済みscreenshotsと一致した。productionの表示変更は完了した。
- **ユーザー受入証跡:** repository-external `BL-020/neutral-source-footer/`のトップページ／日別ArchiveそれぞれのPC 1280px／390px生成screenshotsに対し、ユーザーは「この表示でOK、進めて」と目視受入した。ユーザーが確認したのはmerge前の生成screenshotsである。merge後の公開PagesはWorkが客観確認し、公開表示が受入済みscreenshotsと一致した。ユーザーが公開サイトを目視したとは記録しない。
- **残作業:** なし。
- **注記:** BL-019を再オープンしない。収集元の有効・無効状態や取得処理を変更しない。BL-020登録時点ではUI_SPEC.mdやDECISIONS.mdを変更せず、UI_SPECの置換はBL-020実装と同じPRで行う。

## BL-021 — Today's Briefの意味忠実性・semantic validation再設計

- **ID:** BL-021
- **タイトル:** Today's Briefの意味忠実性・semantic validation再設計
- **優先度:** P1（提案）。[BL-005](#bl-005--editorial-style-v1とtoday-brief-v4)の直接の後継であり、BL-005自体がP1だったことと整合させて提案する。他ticketとの優先順位付けは別途ユーザー判断を要する。
- **状態:** 完了
- **出所種別:** BL-005実装試行・Gate未達からの派生
- **ユーザー原文:** 該当なし（BL-005のNo-Go判定を受けた派生ticketであり、独立したユーザー原文はない）。
- **ユーザー確認済み要約:** 該当なし。
- **解釈:** 検討時の作業呼称は「BL-005b」だったが、正式なbacklog IDはBL-021とする。BL-005で試行したprompt-onlyの忠実性指示（v5/v6）だけでは、外部主体から自組織への主体・対象範囲変更や、記事内の年月等の事実改変を再現性をもって防げなかった（[SD-017](DECISIONS.md#sd-017--do-not-merge-prompt-only-todays-brief-experiments-redesign-semantic-validation-separately)参照）。Phase 1ではsemantic validator v1/v2を固定データでlive評価し、既知の重大違反検出は成功したが、忠実な出力を安定して過剰rejectしたためblocking方式をNo-Goとした。追加prompt調整は終了し、v1/v2を本番採用しない。次の候補Bは、BRIEFで新しい横断的意味を生成せず、既存ARTICLE分析の`summary`／`financial_impact`／`recommended_actions`を無加工で決定論的に選択・配置し、overviewを既存trusted contextだけから構成する。
- **完了条件:** B案について、BRIEF用Gemini APIがproduction経路から到達不能であること、overviewと各listの決定論的選択・provenance・上限・完全一致重複除外・public `list[str]` projection・過去v3 archive互換をテストし、既存daily JSON 5日分のoffline screeningとPC／390px目視用screenshotを作成すること。full unittest、`git diff --check`、pre-commit scope reviewを完了し、ユーザー受入前はproduction実装済みまたは完了と扱わない。
- **依存関係:** [BL-005](#bl-005--editorial-style-v1とtoday-brief-v4)のNo-Go記録；[SD-017](DECISIONS.md#sd-017--do-not-merge-prompt-only-todays-brief-experiments-redesign-semantic-validation-separately)。
- **実装証跡:** Phase 1のsemantic validator blocking方式はrepository外の固定pilot／shadow／final live成果物でSafety Gate PASS・Usability Gate未達となりNo-Go。prompt調整は終了し、validator v1/v2を本番採用しない。B案のlocal implementation、既存daily JSON 5日分のoffline screening、PC／390px表示確認を完了し、[PR #35](https://github.com/matkei31/security-digest/pull/35)を通常のmerge commit `d1755d413cd554d6905715af26521e9e3169001c`として2026-07-23にmergeした。[Pull Request CI run 29990255618](https://github.com/matkei31/security-digest/actions/runs/29990255618)とmerge後の[Pages deployment run 30011612439](https://github.com/matkei31/security-digest/actions/runs/30011612439)は成功した。許可された1回の[Daily Security Digest run 30012552188](https://github.com/matkei31/security-digest/actions/runs/30012552188)はretryなしで成功し、生成commit `1afbd0e7f5b008ea3051af676e57fb2951b648ed`を作成した。[Pages deployment run 30012791302](https://github.com/matkei31/security-digest/actions/runs/30012791302)も成功した。公開daily JSONはBRIEF model `deterministic-extractive`／composition contract `today-brief-extractive-v1`、ARTICLE prompt `article-analysis-v8`、9記事すべてARTICLE status `success`である。「金融機関との関連」「本日の確認事項」はPC 1280px／390pxの双方で表示され、横スクロールがないことを確認した。check itemsは本日確認→今週確認→既存表示順を維持しながら、各記事から1件ずつ選んだ後に残りを補う二段階選択とした。ARTICLE prompt・version・API・validation・fallbackは変更していない。
- **ユーザー受入証跡:** 本プロジェクト会話において、BL-021を正式完了として扱い、次の作業へ進む整理に対し、ユーザーは「ok」、続けて「ok,go」と応答した。これを最終受入証跡とする。
- **残作業:** なし。
- **注記:** `main`および最新の公開daily JSONのBRIEF composition contractは`today-brief-extractive-v1`、BRIEF modelは`deterministic-extractive`である。ARTICLE promptは`article-analysis-v8`のままで、ARTICLE分析契約・daily JSON `schema_version`は変更していない。Phase 1のdeterministic guardと評価成果物は回帰資産として保持する。

## BL-022 — 前日ダイジェスト直接リンク

- **ID:** BL-022
- **タイトル:** 前日ダイジェスト直接リンク
- **優先度:** 未設定（ユーザー順位付け待ち）
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:**
  > 前日ダイジェスト直接リンク
  >
  > - 現在の「過去のダイジェストを見る」に加え、前日分が存在する場合は直接移動できるリンクを表示
  > - 日付欠落時のリンク先仕様は実装前に整理
  > - UIの小規模Ticketとして扱う
- **追加のユーザー原文（PR #37公開機能の確認）:**
  > 左上に「←　前日のダイジェスト」が表示されるようになって機能することも確認した。これはgood。
- **追加のユーザー原文（文言統一の提案）:**
  > 「前日のダイジェスト」「前回のダイジェスト」「前のダイジェスト」と書き分けないで、「前のダイジェスト」に統一でいいんじゃないかな。日付も入れなくてんじゃないかな
- **追加のユーザー承認原文:**
  > うん。いいと思うよ。他の修正の方向性もok
- **ユーザー確認済み要約:** トップページと日別Archiveのナビゲーションを、前方向「← 前のダイジェスト」、次方向「次のダイジェスト →」、最新ページ「最新のダイジェスト」、一覧「過去のダイジェスト」の4用語へ統一し、リンク文言に日付を含めない。PCでは方向移動を左、全体導線を右へ分け、390pxではグループの区別とDOM順を保って自然に折り返す。
- **解釈:** [SD-020](DECISIONS.md#sd-020--link-the-top-page-to-the-latest-validated-earlier-digest)の日付選択と検証は維持する。日付配列の保存順には依存せず、現在の`digest_date`より前の最大の有効公開日をトップページの移動先とする。日別Archiveも実在する直前・直後の公開日だけを移動先とし、欠けた方向のみ省略する。トップページの「過去のダイジェスト」と、日別Archive上部・最下部の「最新のダイジェスト」「過去のダイジェスト」は常に維持する。
- **完了条件:** トップページの前日あり／日付欠落／過去日なし、日別Archiveの前後あり／前のみ／次のみ／前後なしを検証する；4用語を統一しリンク文言に日付や廃止文言を残さない；hrefは従来どおり検証済みの実在日を指す；方向移動と全体導線を別DOMグループにする；PC 1280px／390pxで左右配置または自然な折返しとなり、横スクロール、重なり、不自然に狭いタップ領域を生じない；focus表示を維持し、内部リンクへ外部用`target`／`rel`を加えない；既存daily JSONから全生成HTMLを再生成し、差分をナビゲーションと必要CSSに限定する；`data/`、ARTICLE／BRIEF、prompt／model／schema／validation／fallback、source、workflowを変更しない；関連テスト、full unittest、Markdownリンク、`git diff --check`、PR CI、Pages deployment、公開PC／390px確認を成功させる。
- **依存関係:** [BL-017](#bl-017--過去ダイジェストの回遊性と一覧表示を改善する)；[SD-020](DECISIONS.md#sd-020--link-the-top-page-to-the-latest-validated-earlier-digest)；[SD-021](DECISIONS.md#sd-021--unify-digest-navigation-labels-and-separate-direction-from-global-navigation)；[UI_SPEC.md](UI_SPEC.md) Version 1.2；既存daily JSON／archive日付一覧。
- **実装証跡:** PR #37の直前公開日選択はmerge commit `d43c563a9a59506aaaa4a41cc6297620cbb6f276`、[Pages deployment run 30022728319](https://github.com/matkei31/security-digest/actions/runs/30022728319)、production生成commit `e8183bd9ee6bb8288dc329eaf68c412225eecbc8`を経て公開済みで、ユーザーがリンクの表示と動作を確認した。改訂仕様は[PR #38](https://github.com/matkei31/security-digest/pull/38)、merge commit `85e1b3e3cd4bb3c8927c9b1608652c77a9ebb6e9`で実装し、[Pull Request CI run 30061712600](https://github.com/matkei31/security-digest/actions/runs/30061712600)と[Pages deployment run 30061770611](https://github.com/matkei31/security-digest/actions/runs/30061770611)が成功した。公開トップページと日別Archiveの上部・最下部をPC 1280px／390pxで客観確認し、4用語、左右または折返し配置、正しいhref、横スクロールなしを確認した。
- **ユーザー受入証跡:** PR #37の既存機能は公開画面で動作確認済み。今回の正確な文言・日付非表示・配置仕様は上記原文で承認済み。承認済み仕様との完全一致、全検証、Pages公開表示の客観確認を完了したため、追加のユーザー確認を要しない完了条件を満たした。改訂後画面をユーザーが目視済みとは記録しない。
- **残作業:** なし。
- **注記:** ARTICLE／BRIEF prompt・model・schema、daily JSON、`data/`、記事内容、日付選択ロジックは変更していない。

## BL-023 — ARTICLE編集品質改善

- **ID:** BL-023
- **タイトル:** ARTICLE編集品質改善
- **優先度:** 未設定（ユーザー順位付け待ち）
- **状態:** 保留／prompt-only改善No-Go／production変更なし
- **出所種別:** ユーザー原文
- **ユーザー原文:**
  > ARTICLE編集品質改善
  >
  > - financial_impactでは、読者組織の製品・サービス利用状況を記事から確認できないという自明な断り書きを出力しない
  > - 条件付きで関係する場合は、条件と想定影響だけを簡潔に記載
  > - recommended_actionsにはCVE IDを原則含めない
  > - 対象製品・サービスと確認内容を簡潔に記載
  > - CVE IDはtitle、summary、facts等の識別用途では維持
  > - Brief側の後処理やCVE文字列削除は行わない
  > - 単純な禁止語・語彙ルールにはしない
- **ユーザー確認済み要約:** 未定義。
- **解釈:** ARTICLE生成の編集品質契約を対象とする。`financial_impact`は利用有無を記事から確認できないという自明な断り書きを避け、条件付きの関連では条件と想定影響を簡潔に示す。`recommended_actions`はCVE IDを原則として本文へ含めず、対象製品・サービスと確認内容を中心にする。一方、CVE IDは`title`、`summary`、facts等の識別用途では維持する。BRIEF側での後処理、CVE文字列削除、単純な禁止語・語彙規則による実現は対象外とする。
- **完了条件:** ARTICLE prompt契約として各fieldの期待を仕様化する；prompt versionへの影響を評価する；`financial_impact`の条件付き関連と`recommended_actions`のCVE ID原則非掲載を、単純な禁止語・汎用regex削除ではなくfixtureとmock request／responseで検証する；CVE IDが`title`、`summary`、facts等の識別用途で維持されることを確認する；BRIEF後処理を追加しない；ARTICLEのsuccess／fallback／failed／not_attempted契約を維持する；実装後にユーザー受入を記録する。
- **依存関係:** 現行ARTICLE prompt／version契約；[SD-015](DECISIONS.md#sd-015--project-trusted-context-through-an-explicit-allowlist-and-do-not-expose-internal-identifiers)；[AGENTS.md](AGENTS.md)のprompt／schemaおよびARTICLE validation契約。
- **実装証跡:** `article-analysis-v9`候補をrepository外の固定15 fixture（targeted 11／control 4）に対し、`gemini-2.5-flash`で2 logical runs・30 attempts・retry 0として評価した。Technical GateはPASSしたが、financial_impact Gate、recommended_actions Gate、Safety／Non-regression GateはFAIL。sourceにない主体・対象等の主張追加、複数脆弱性や複数製品に関する重要条件の欠落、control fixtureの重要度・緊急度悪化を確認した。repository変更は0件で、評価成果物はrepository外の`BL-023/article-editorial-quality-pilot/`にNo-Go証跡として保持する。
- **追加評価証跡:** `article-analysis-v10`固定候補をrepository外の17 fixtureに対し、`gemini-2.5-flash`で2 logical runs・34 attempts・retry 0として評価した。HTTP 200およびschema parseは34/34、technical error・field欠落・内部識別子漏えいは0件でTechnical GateはPASSしたが、financial_impact Gate、Safety／Non-regression Gate、mandatory Zimbra／NCSC記事はFAIL。sourceにない情報漏えい、業務停止、普及度、委託関係、与信／決済影響の追加、具体的な関連を生成できない場合の抽象化、適用条件やrecommended actionの欠落、importance等の変更対象外fieldの悪化を確認し、source限定性と他field非回帰を安定保証できなかった。v10候補は採用・実装せず、repository変更は0件、productionは`article-analysis-v8`を維持し、評価結果を受けた追加prompt調整も行わない。この結論は今回固定したv10候補に限定し、簡素化の方向やpromptによる改善一般を不可能とは判断しない。評価成果物はrepository-external `BL-023/article-financial-impact-v10-screening/`にNo-Go証跡として保持する。
- **ユーザー受入証跡:** 2026-07-23、ユーザーがNo-Go状態とproduction非変更の記録を指示した。
- **残作業:** prompt-only案の再調整は行わない。ARTICLE fieldの構造化設計、またはfactsを使った限定的な決定論的compositionを別ticketとして設計する場合のみ再検討する。
- **注記:** v9およびv10候補は本番採用せず、productionは`article-analysis-v8`を維持する。regex削除、禁止語ルール、Brief側の後処理は導入しない。

## 完了済み参照

これらの参照記録は、完了済みの作業が誤って未完了バックログとして再オープンされることを防ぐためだけに存在する。

### Ticket 14a-3 — Atom日付解析と日付未設定記事の除外

- **状態:** 完了
- **証跡:** [PR #4](https://github.com/matkei31/security-digest/pull/4), merge commit `9ae5240b4e1b00e74f4b7af7a03e6d5769d53511`
- **完了範囲:** 分数秒付きAtom日付解析、UTC比較、published優先のupdated選択、および欠落・解析不能な日付のフィルタリングに対するfix-forward。
- **再オープン条件:** 新しい証跡なしに、この完了済みチケットを未完了バックログへ戻さない。

### Ticket 14a-4 — 2026-07-11〜13の古い履歴修復

- **状態:** 完了
- **証跡:** [PR #5](https://github.com/matkei31/security-digest/pull/5), merge commit `0e7a5d26dafaca6a8f7d65bb07144d5da31369c0`
- **完了範囲:** Atom日付修正後の、2026-07-11から2026-07-13までの古い履歴の修復。
- **再オープン条件:** 新しい証跡なしに、この完了済みチケットを未完了バックログへ戻さない。

### ARTICLE内部識別子漏洩の修正

- **状態:** 完了
- **出所種別:** 技術上の発見事項 / 本番インシデント
- **証跡:** [PR #8](https://github.com/matkei31/security-digest/pull/8), merge commit `d1518910cd1a685cffc5d526ec65f6e708a4d535`; 現行の`fetch.py`内`build_verified_context_for_prompt`; `test_fetch.py`/`test_article_v5.py`の関連回帰テスト。
- **完了範囲:** ARTICLEのGemini入力から内部キー`recent_kev_additions`および他の内部識別子を削除；内部container/field名、flag値、status値を人間可読なラベルへ変換する明示的なallowlist projectionを導入；未知のfacts key、CVEフィールド、rule flagがpromptへ自動的に伝播することを停止；この入力契約変更に対応してARTICLE prompt versionを更新；PRが実際のproduction runsに対して再現した`reason`/daily-JSON/トップページ/日別archiveの再露出経路を閉じた。
- **インシデント自体の証跡:** PR #8の本文は、脆弱性/パッチカテゴリの4記事について、2件のproduction run ID（`29367843566`、`29374504304`）とその生成commitに対する再現を記録しており、漏洩は`analysis.reason`、daily JSON、トップページ、当日archiveに現れた。
- **再オープン条件:** 新しいtrusted-context入力がallowlist projectionを回避する場合、内部key/status/flag値が利用者へ露出した場合、raw AI responseが新たに保存または表示された場合、または類似の入力契約漏洩が確認された場合に再オープンする。このインシデントが確立した一般化された境界ルールについては[SD-015](DECISIONS.md#sd-015--project-trusted-context-through-an-explicit-allowlist-and-do-not-expose-internal-identifiers)を参照。

### Ticket 12c — 記事分析への脆弱性情報の活用

- **状態:** 完了
- **証跡:** [PR #1](https://github.com/matkei31/security-digest/pull/1), merge commit `8f6c5dfdcfc2113cba410a7059d230026d6d1a7a`
- **完了範囲（PR本文より）:** 検証済みのCVE/CVSS/KEV factsをGemini ARTICLE分析へ渡した；verified contextをuntrustedな記事内容から分離した；CVSSをsoft signal、KEVをstrongだが非決定論的なsignalとして使用した；既存のresponse schema、Brief prompt、HTML、facts取得の挙動を維持した；prompt-injectionとdecision-boundaryのテストを追加した。
- **現行実装への残存:** 本PRが導入したvulnerability-facts取得とCVSS/KEVをsignalとして扱うロジックは、現行ARTICLEパイプラインの基盤であり続けている。
- **後続作業による置換:** 本PRが導入した具体的なverified-context構築は、[SD-015](DECISIONS.md#sd-015--project-trusted-context-through-an-explicit-allowlist-and-do-not-expose-internal-identifiers)（[PR #8](https://github.com/matkei31/security-digest/pull/8)）に記録されているallowlist-projectionアプローチによって置き換えられた。
- **再オープン条件:** 新しい証跡なしに、この完了済みチケットを未完了バックログへ戻さない。

### Ticket 13c — フィード取得失敗とゼロ件取得の区別

- **状態:** 完了
- **証跡:** [PR #2](https://github.com/matkei31/security-digest/pull/2), merge commit `a8b551818443f2ca9deb2df160fc661aab8faf77`
- **完了範囲（PR本文より）:** 成功したゼロ件取得のfeedとHTTP/XML失敗を区別した；HTTP 429および特定の5xxレスポンスに限り、RSSリクエストを一度だけ再試行した；`fetch_feed()`のlist-returning互換性を維持した；ゼロ件取得に成功したCISA KEV収集をOKとして報告した；内部file-path露出を防ぐためエラーメッセージをsanitizeした；実際のHTTPレスポンスstatusを記録した。
- **現行実装への残存:** はい — `RSS_RETRYABLE_HTTP_STATUSES = {429, 500, 502, 503, 504}`とその関連するretryロジックは`fetch.py`に残っており、コードコメントで「Ticket 13c」とタグ付けされている。
- **後続作業による置換:** 特定されていない。
- **再オープン条件:** 新しい証跡なしに、この完了済みチケットを未完了バックログへ戻さない。

### Ticket 14a — Atom記事リンク選択の修正

- **状態:** 完了
- **証跡:** [PR #3](https://github.com/matkei31/security-digest/pull/3), merge commit `d90fa3986a541aafbdf76bc6e6b4d8f0130ed19c`
- **完了範囲（PR本文より）:** Element真偽値評価によりAtomの`rel=alternate`記事リンク選択が無視され、`rel=replies`のコメントfeed URLへフォールバックしていた問題を修正した；rel未指定または`alternate`の安全なhttp/https記事URLのみを選択した；コメントfeed、feed/XML形式のリンク、非HTTP URLを除外した；安全なURLがないentryをskipした；`MAX_PER_FEED`を有効なentryのみへ適用した。これはfix-forwardの変更であった；既に影響を受けていた既存記事は、Ticket 14a-3/14a-4で別途修復された。
- **現行実装への残存:** はい — このlink選択の修正は`fetch.py`で有効なまま残っており、コードコメントで「Ticket 14a」とタグ付けされている。
- **後続作業による置換:** なし；Ticket 14a-3（日付解析）とTicket 14a-4（2026-07-11〜13の履歴修復）によって拡張されている（置換ではない）— いずれも上記にそれぞれ独立した完了済み参照entryとしてすでに記録されている。
- **再オープン条件:** 新しい証跡なしに、この完了済みチケットを未完了バックログへ戻さない。

### 取得時証跡と内部日付別アーカイブ

- **状態:** 完了
- **原文:** 原文未回収。
- **出所種別:** 復元要約 / ユーザー承認済みのアプローチ
- **証跡:** `daily_json.py`（`build_raw_excerpt()` — 取得したfeed descriptionから200文字に制限、記事ページのscrapingなし；`compute_content_hash()` — `canonical_url`＋`raw_title`＋`raw_excerpt`のSHA-256）；`fetch.py`（`build_daily_archive_html()`、`generate_archive_outputs()` — daily JSONから構築される内部の日付別archive）；`test_daily_json.py`、`test_archive.py`；commit `1c65be67eaaa223d65ca1056313fb933d31f1ec4`（「feat: add daily JSON schema and storage (Ticket 3)」）、commit `b51de673b3ea15347413d905f32d473e6f92712e`（「feat: add daily archive pages」、Ticket 9、`fbba0b8e57a68adafa0bcabe69a621a3f0c08e54`でmerge）
- **完了範囲:** 記事ごとに、`url`/`canonical_url`、`title`、`published_at`、`fetched_at`、範囲制限された`raw_excerpt`、`content_hash`を、将来のlink rotに対する最小限のprovenanceとして保存する。daily JSONから内部の日付別archive（`docs/archive/YYYY-MM-DD.html`）を構築する。記事全文やrich contentは保存しない（SD-002と整合）。取得したURLを外部archiveサービスへ送信しない（コードベースにWayback/archive.org連携は存在しない）。
- **再オープン条件:** 新しい証跡なしに、この完了済み範囲を未完了バックログへ戻さない。次のいずれかが提案された場合は再オープン・再評価する: 現行の範囲制限された、description-basedの契約を超えて`raw_excerpt`の長さや取得元を拡大すること；記事全文の保存；rich contentの保存；取得したURLの外部archiveサービスへの自動送信；private/認証feedへの対応；保存データの外部提供。
