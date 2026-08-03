# Monomi Digest バックログ

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
- **状態:** 完了
- **出所種別:** ユーザー確認済み要約
- **ユーザー原文:** 原文未回収。
- **ユーザー確認済み要約:** 将来のサービス名は`Monomi Digest`とする。`Security Digest`と`Monomi Digest`のどちらにするかという未決定事項へ戻さない。
- **解釈:** 決定した将来のブランド名は`Monomi Digest`である。「Security DigestかMonomi Digestか」という未決定の命名選択として再オープンしない。BL-006／BL-007合同preflight（read-only調査）の結果を受け、ユーザーはB案（ブランド変更を先行させ、custom domain移行は別Ticketで後追いする）と本Ticketの実装方針を承認した。
- **完了条件:**
  1. 現在公開されるトップページ・Archive一覧・全日別Archive HTMLの表示ブランドを`Monomi Digest`へ統一する。
  2. header絵文字`🔐`は維持し、title／H1間の絵文字表記の不整合（従来、日別ArchiveのtitleにはあったがH1になかった）を解消する。
  3. `fetch.py`・`README.md`・`AGENTS.md`・`STATUS.md`・`DECISIONS.md`（SD-010）・`SECURITY_OPERATIONS.md`・`SECURITY_REQUIREMENTS.md`・`UI_SPEC.md`の現行・将来を語る記述を`Monomi Digest`へ更新する。
  4. 既存daily JSON（`data/*.json`）は遡及変更しない。
  5. `generator.application`は内部識別子として`"security-digest"`を維持する。
  6. repository名`matkei31/security-digest`は変更しない。
  7. `.github/workflows/fetch.yml`のworkflow display name（`Daily Security Digest`）とconcurrency group（`daily-security-digest-production`）は変更しない。
  8. custom domain・CNAME・DNS・canonical・公開URL変更は行わない（BL-007の範囲）。
  9. meta description・OG・Twitter Card・favicon・manifest・sitemap・robots.txt・About・analyticsは追加しない（BL-009の範囲）。
  10. 過去のユーザー原文・過去PR／commit／workflowへのリンク・過去の名称を説明する履歴記録・anchor・内部識別子は単純置換しない。
  11. 関連test更新とfull unittest成功。
  12. merge前にPC 1280px／390pxでのトップページ・Archive一覧・代表的な日別Archiveの目視受入をユーザーから得る。
  13. merge後、GitHub Pagesでの公開反映を客観確認し、ユーザー受入をもって完了とする。
- **依存関係:** [SD-010](DECISIONS.md#sd-010--use-monomi-digest-as-the-future-public-brand)、BL-007（custom domain移行、別Ticket・別scope）、BL-009（SEO、本Ticketの完了後に前提条件を再評価）；About、SEO、公開ナビゲーション、リポジトリおよび公開物の命名決定。
- **実装証跡:** `fetch.py`のブランド文字列4箇所（トップページtitle・H1既定値、日別Archive H1呼び出し引数、Archive一覧title）を`Monomi Digest`へ変更し、`<title>`タグを`page_title`引数に連動させてtitle／H1間の絵文字不整合を解消した（`🔐 Monomi Digest`で統一）。`README.md`・`AGENTS.md`・`STATUS.md`・`DECISIONS.md`（表題および[SD-010](DECISIONS.md#sd-010--use-monomi-digest-as-the-future-public-brand)のStatus／Consequences）・`SECURITY_OPERATIONS.md`・`SECURITY_REQUIREMENTS.md`・`UI_SPEC.md`（Version 1.4）の現行・将来を語る記述を更新した。過去のユーザー原文・過去PR／workflow runへのリンク・SD-007等の履歴決定記録・`generator.application`（`daily_json.py`）・repository名・workflow display name／concurrency groupは変更していない。既存`data/*.json`は無変更（`git diff origin/main...HEAD -- data/`で確認。`origin/main`の定期実行が追加した2026-07-26分の日次JSON・`data/index.json`・`vulnerability_facts_cache.json`・`docs/translate_cache.json`は内容を変更せず通常mergeで取り込んだ）。`docs/index.html`・`docs/archive/index.html`・全16件の日別Archive HTML（2026-07-26分を含む）は、外部HTTP／Gemini／RSS／NVD／CISA KEVを呼ばず、既存daily JSONのみを用いてoffline再生成し、生成差分はブランド表示・title／H1絵文字統一に限定した（`最終更新`表示等の他フィールドは元のdaily JSON由来の値のまま変更なし）。関連test更新: `test_archive.py`、`test_security_operations.py`、`test_security_requirements.py`、`test_ui_spec.py`。custom domain・CNAME・DNS・canonical・meta description・OG・Twitter Card・favicon・manifest・sitemap・robots.txt・Aboutは追加・変更していない。production workflowとworkflow_dispatchは未実行。
- **ユーザー受入証跡:** 方向性は2026-07-17のプロジェクト会話で再確認され、BL-006／BL-007合同preflightの結果を受けてB案と本Ticketの実装方針が承認された。実装受入は2026-07-26に取得済み。
  - **受入日:** 2026-07-26
  - **ユーザー原文:** 「6枚とも確認した。ブランド変更の表示は問題なし。BL-006として受入。」
  - **受入対象の実装head:** `802781b31b5cc381a5bc4438d025f9af1c3a32e4`（[PR #57](https://github.com/matkei31/security-digest/pull/57)）
  - **受入対象:** トップページ、Archive一覧、2026-07-26日別Archive、PC 1280px／390px、`🔐 Monomi Digest`表示、title／H1絵文字統一。
  - **受入対象外:** BL-007（custom domain移行）、BL-009（SEO）、repository rename、ナビゲーション再設計、ARTICLE／BRIEF情報設計再検討（別途BL-028／BL-029として記録予定）。
- **公開反映証跡:** [PR #57](https://github.com/matkei31/security-digest/pull/57)（final head `0bd70c4c22cb27c2705bf87e01fcbf0bb6c0362b`、[Pull Request CI run 30203686978](https://github.com/matkei31/security-digest/actions/runs/30203686978)成功）を通常merge（squash・rebase不使用）でmerge commit `ea79ae12f5ddca2b241420f0c06cdfe3c6badf27`としてmainへ統合した。[Pages deployment run 30203750940](https://github.com/matkei31/security-digest/actions/runs/30203750940)が成功し、公開トップページ・Archive一覧・2026-07-26日別ArchiveをHTTP 200・`🔐 Monomi Digest`表示・title／H1一致・Archive一覧全16日分・07-25/07-26間の前後ナビゲーションで客観確認した。公開`docs/index.html`はmerge直後のbranch内容とbyte-identicalであり、`Security Digest`の残存はない。merge起因のDaily Security Digest production workflow実行および`workflow_dispatch`実行はなかった。
- **残作業:** なし。custom domain移行はBL-007、SEOはBL-009で別途扱う。ナビゲーション再設計・ARTICLE／BRIEF情報設計再検討はBL-028／BL-029として別途record-onlyで登録予定（本Ticketには含めない）。
- **注記:** repository rename、custom domain、meta description等のBL-007／BL-009範囲の判断は本Ticketに含めない。BL-006／BL-007合同preflight調査の詳細（ブランド接点棚卸し、URL/custom domainリスク、A/B/C案比較）はセッション記録を参照。implementation branch `claude/bl006-brand-monomi`、closure branch `claude/bl006-close`。

## BL-007 — monomidigest.comへの移行

- **ID:** BL-007
- **タイトル:** monomidigest.comへの移行
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー原文 / ユーザー確認済み要約
- **ユーザー原文:** 「URLがgithubのユーザー名なのが気になる」
- **出所:** 2026-07-09 プロジェクト会話。
- **ユーザー確認済み要約:** 主ドメインは`monomidigest.com`とし、`monomi.jp`は不要とする。
- **解釈:** 主ドメインとして`monomidigest.com`を使用する。記録された決定では`monomi.jp`は不要とされている。
- **外部状態(ユーザー確認済み):**
  - `monomidigest.com`をXServerドメインで取得済み(契約期間1年、初年度0円、WHOIS代理公開有効、自動更新1年ごと・クレジットカード、ドメインプロテクション有効)。
  - XServerアカウントの二段階認証・SMS認証・SMS通知は設定済み。
  - ネームサーバーは`ns1.xdomain.ne.jp`／`ns2.xdomain.ne.jp`／`ns3.xdomain.ne.jp`。
  - GitHub Pages所有権確認用TXTをXServer DNSへ登録済みで、GitHub個人アカウントのPagesで`monomidigest.com`がVerifiedになった。検証用TXTは削除せず維持する。
  - apex A×4はGitHub Pages公式4 IP、www CNAMEは`matkei31.github.io`へ設定済み。repository側Custom domainは`monomidigest.com`(`protected_domain_state: verified`)。
  - GitHub PagesのHTTPS証明書は`https_certificate.state: approved`(対象ドメイン: `monomidigest.com`／`www.monomidigest.com`)、`https_enforced: true`。
  - 本Ticketの実装・cutover・closure作業自体はproduction生成・`workflow_dispatch`を新たに起動していない。独自ドメイン切替後、最初の通常scheduled production run(digest: 2026-07-29 07:58 JST、commit `b8463c0f10734097c4a431ce69be808d371e4e3b`)は、本Ticket作業とは独立して通常scheduleにより実行され、success(8記事、AI success 8、fallback 0、failed 0)となった。
- **完了条件:** ユーザーと確定した方針は次のとおり。
  1. 正規URLは`https://monomidigest.com/`とする。
  2. `https://www.monomidigest.com/`は正規URLへリダイレクトさせる。
  3. GitHub Pagesを継続使用する。XServerレンタルサーバーは使用しない。
  4. DNS管理はXServerドメインで行う。
  5. repository名`security-digest`は変更しない。
  6. GitHub Pagesの公開元は引き続き`main` branchの`/docs`とする。
  7. wildcard DNSは使用しない。
  8. GitHub Pages所有権確認用の検証TXTは保持する。
  9. `docs/CNAME`を新設し、内容は`monomidigest.com`の1行のみ・末尾改行ありとする。URL scheme・path・`www`を含めない。
  10. 日次production生成・全Archive offline再生成のいずれでも`docs/CNAME`が削除されないことを保証する。
  11. `data/`・daily JSON・記事内容・ARTICLE／BRIEF prompt・schema・versionは変更しない。workflowは原則変更せず、repository renameも行わない。
  12. **承認済みの計画:** cutoverの順序は、repository準備 → PR #64 merge → merge-triggered Pages確認 → repository Custom domain設定 → XServer DNS設定 → DNS伝播・TLS発行確認 → Enforce HTTPS確認 → closureとする。
  13. **実際に観測された順序:** PR #64をmergeし、`docs/CNAME`を含むmerge-triggered Pages deploymentが成功した時点で、手動のrepository Settings操作を待たずにCustom domainが`monomidigest.com`として自動的に有効化され、旧URL(`matkei31.github.io/security-digest`)のredirectも同時に開始された。この時点ではXServer DNSがまだ設定されておらず、一時的に新旧いずれのURLも到達不能な状態(`InvalidDNSError`)となった。その後、ユーザーがXServer DNS(apex A×4・www CNAME×1)を設定し、DNS伝播・GitHub PagesのDNS check・TLS証明書発行(`approved`)を経て、この一時的な`InvalidDNSError`は解消し、Enforce HTTPSを有効化し、apex／www／旧URLの公開状態を確認した。計画どおりの順序で実施したとは記録しない。この差異は誤りや失敗ではなく、`docs/CNAME`を含むmergeとPages deploymentだけでrepositoryのCustom domainが自動的に有効化されるという、本repositoryで観測されたGitHub Pagesの挙動として記録する(GitHub Pages全体の普遍的仕様とは断定しない)。mainへの意図しない追加commitは発生していない(`docs/CNAME`以外の差分なし)。詳細は[SD-028](DECISIONS.md#sd-028--migrate-github-pages-to-monomidigestcom-as-the-primary-custom-domain)を参照。
  14. 本Ticketの実装・cutover・closure作業では、production生成・`workflow_dispatch`・real Gemini・外部記事取得を新たに起動していない。2026-07-29のproduction runは通常scheduleによって独立して実行されたものである。
  15. BL-009(SEO・閲覧者増加策)はmeta description／canonical／OG／Twitter Card／favicon／manifest／sitemap／robots.txt／analytics／Search Console／Aboutコンテンツを扱う別Ticketとし、本Ticketでは扱わない。現時点でこれらはいずれも未実装であり(`sitemap.xml`／`robots.txt`／`favicon.ico`はいずれも404)、ドメイン移行によって壊れた既存metadataはない。BL-009は本closureにより着手・完了したものではなく、引き続き別スコープ・未着手のまま残す。
  16. PR #64は、ユーザーによる最終内容確認とrunbookの最終確認を得たうえで、通常merge(merge commit、squash/rebaseなし)された。
- **依存関係:** [SD-011](DECISIONS.md#sd-011--use-monomidigestcom-as-the-primary-domain)(実装Decisionを新設し部分的に補完)、BL-006(完了済み・ブランド名)、BL-009(SEO、別Ticket・scope外・未着手のまま)。
- **実装証跡:** `docs/CNAME`を新設し、内容を`monomidigest.com`の1行(末尾改行あり、URL scheme・path・`www`なし)とした。`fetch.py`のHTML生成関数(`atomic_write_text`)は対象パスのみを原子的に書き換え、`docs/`ディレクトリ全体のクリアや削除を一切行わないため、日次production生成・全Archive offline再生成のいずれでも`docs/CNAME`は自然に維持されることを確認した(コード変更は不要)。`README.md`の公開サイト記載を`https://monomidigest.com/`へ更新し、旧URL`https://matkei31.github.io/security-digest/`が本ドメインへ自動redirectされる旨を明記した。`data/`・daily JSON・記事内容・ARTICLE／BRIEF prompt・schema・versionは変更していない。workflowは変更していない。repository renameは行っていない。関連test追加・更新。
- **ユーザー受入証跡:** ユーザーがPR #64の最終内容とrunbookを確認し、本メッセージをmerge承認として明示した。PR #64は通常merge(merge commit `616d58e8a924338f596c54f9717f0ff96f48d9e6`)され、merge-triggered Pages deployment(`pages-build-deployment`)が成功した。ユーザーから提供・確認された公開後の外部状態: apex `https://monomidigest.com/`が200、`http://monomidigest.com/`・`https://www.monomidigest.com/`・旧URL`https://matkei31.github.io/security-digest/`がいずれもapexへ301 redirect、GitHub Pages API `status: built` / `cname: monomidigest.com` / `protected_domain_state: verified` / `https_certificate.state: approved`(対象ドメイン`monomidigest.com`・`www.monomidigest.com`) / `https_enforced: true`。トップページ・archive一覧・日別archiveの内容はrepository上の`docs/`と一致し、`/security-digest/`絶対パスや旧ドメインの残存参照はない。
- **残作業:** なし。BL-007は完了。BL-009(SEO・閲覧者増加策)は別Ticketとして引き続き未着手のまま残る。
- **注記:** 現在の公開URLは`https://monomidigest.com/`であり、`https://matkei31.github.io/security-digest/`・`https://www.monomidigest.com/`はいずれもこのapexへredirectされる。DNS(apex A×4・www CNAME×1)・repository Custom domain・Enforce HTTPS・TLS証明書はすべて設定・発行済み。GitHub所有権確認用TXTは維持されている。独自ドメイン切替後、最初の通常scheduled production run(digest: 2026-07-29 07:58 JST、commit [`b8463c0f10734097c4a431ce69be808d371e4e3b`](https://github.com/matkei31/security-digest/commit/b8463c0f10734097c4a431ce69be808d371e4e3b)、total_items 8、AI success 8／fallback 0／failed 0)成功後も、`docs/CNAME`・repository Custom domain・redirect・Enforce HTTPSはいずれも維持された。このrunは本Ticket作業による手動実行ではなく、通常scheduleによって独立して実行されたものである。implementation branch `claude/bl007-custom-domain`、closure branch `claude/bl007-close`。

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
- **状態:** 進行中（BL-034で閲覧計測基盤を先行）
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「あとでSEO対策や見てもらうための工夫について相談」
- **追加のユーザー原文:** 「そういう話をするタイミングになったら教えて」
- **出所:** 2026-07-13 プロジェクト会話。BL-034分離は2026-08-03のプロジェクト会話。
- **ユーザー確認済み要約:** 該当なし — 原文は上記のとおり回収済み。
- **解釈:** 前提条件（BL-006・BL-007・BL-002〜BL-004・BL-028〜BL-033完了、新たな未対応P0/P1データ品質課題なし）が整ったため着手した。umbrella Ticketとして本Ticketを維持し、残作業のうち「成果の測定」の基盤となる閲覧計測を、独立Ticket [BL-034](#bl-034--閲覧計測基盤)（閲覧計測基盤）として先行させる。BL-034はCloudflare Web AnalyticsとGoogle Search Consoleの導入を扱い、robots.txt・sitemap・canonical・OG・favicon・About全体・コンテンツSEOはBL-034のscope外とし、本Ticket配下に残す。本Ticket自体は、[BL-034](#bl-034--閲覧計測基盤)完了(2026-08-03)を受け、基準値取得期間中(計測開始日2026-08-03)を経て、残る作業へ進む前提で進行中とする。
- **完了条件:** 未定義。BL-034は完了した。残作業の各項目ごとに個別Ticketまたは追加の完了条件を今後定義する。
- **依存関係:** Ticket 14a-3およびTicket 14a-4は完了しており、再オープンの前提条件ではない。BL-006、BL-007、日本語版の編集仕様、BL-002〜BL-004、Aboutコンテンツ、metadata、公開ナビゲーションはいずれも完了済みで、着手前提条件を満たした。[BL-034](#bl-034--閲覧計測基盤)（閲覧計測基盤）は本Ticketから分離した先行Ticketであり、その進捗はBACKLOG.md上のBL-034自身の状態を正本とする（本項目では複製しない）。
- **実装証跡:** 未実装（BL-034の実装証跡はBL-034自身を参照）。
- **ユーザー受入証跡:** 記録なし。
- **残作業:** 対象読者と目標の定義、技術/コンテンツSEOの監査、metadata（meta description等）、robots.txt、sitemap、canonical、OG／共有（Open Graph・Twitter Card）、favicon、About全体、施策の優先順位付け、個別実装、Cloudflare Web AnalyticsとGoogle Search Consoleを用いた成果測定の継続（BL-034は完了し2026-08-03に計測を開始した。基準値取得期間を経て評価を継続する）。
- **注記:** 前提条件は整い、umbrella Ticketとして進行中。原文はBL-014の最終完了パス（2026-07-18）で回収された；[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md)を参照。

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
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「セキュリティ要件みたいなのも後で決めよう」
- **追加のユーザー原文:** 「OK.ここはfable5にもレビューしてもらおう。公開情報を扱うものだから厳しいセキュリティ対策をする必要はないと思うが、必要なものは網羅しつつ過剰じゃないように整理して、fable5にレビューさせられる形にして。」
- **ユーザー確認済み要約:** 記録なし。
- **解釈:** 静的な公開サイト、GitHub Actions、外部fetching、Gemini、保存データ、secrets、将来のcustom domain利用について、現行アーキテクチャに見合ったセキュリティ要件一式を、専用文書（候補名`SECURITY_REQUIREMENTS.md`、GitHubの脆弱性報告用`SECURITY.md`とは別）として定義する。過剰な対策を一律に導入しない；各項目について必要性と再評価条件を明示的に述べる。
- **完了条件:** 文書は次を定義する: 対象systemとdata flow；trusted/untrusted境界；保存してよいものといけないもの；外部URLの扱い、HTMLエスケープ、`safe_url`；secrets管理；GitHub Actions権限；ログ/artifactsの扱い；依存関係とGitHub Actionsのsupply chain管理（full commit SHA pinningおよびGitHub Actions向けDependabotの明示的な必要性評価を含む）；現行のleast privilegeの状態；custom domain採用時の再評価トリガー；forms・認証・データベース・永続storageを追加する際の再評価トリガー；現行の対策・特定されたgap・特定の対策を採用しない理由の明確な区別；Fable 5レビューパス；最終的なユーザー承認。full commit SHA pinning、Dependabot、および同様の具体的対策は、この段階で必須と決定するものではない — 上記の評価が特定のgap対応を承認した場合にのみ、別チケットとなる。
- **依存関係:** 現行アーキテクチャ；[BL-001](#bl-001--プルリクエストci)（プルリクエストCI）と調整；[BL-007](#bl-007--monomidigestcomへの移行)（monomidigest.comへの移行）と調整；`AGENTS.md`（「Security requirements」節）と`DECISIONS.md`にすでに記録されている既存のセキュリティルール。
- **実装証跡:** 個別のルールはすでに存在する（`AGENTS.md`: HTMLエスケープ、`http`/`https`のみの表示リンク、`rel="noopener noreferrer"`、承認なしでのforms/認証/データベース/新規外部依存/永続storageの追加禁止、標準ライブラリ/既存依存のみの方針、静的GitHub Pagesとの互換性）。これらと現行実装、daily JSON、GitHub Actions、テスト、公開／保存境界を照合した[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Draft 0.1をFable 5がレビューし、Critical 0、High 0、Medium F-001〜F-003、Low／Editorial F-004〜F-009を報告した。ユーザー裁定によりF-001〜F-003およびF-005〜F-009を採用または修正して採用し、F-004のSR統合は不採用として、Draft 0.2へSR-043、register Classification、GAP-014、GAP-015、例外出力と外部response sizeの全数棚卸し、custom-domain preflight、translation cacheリスク、Current control mappingの個別状態集計を反映した。Fable 5が取得できなかった`STATUS.md`と`test_security_requirements.py`はPR headで独立確認したため、Fableレビュー済みとは扱わない。GAP-010 repository-owner checklistはread-onlyで完了し、必須項目にowner-access未確認を残さず、重大・High相当の新規findingもなかった。Version 1.0はowner確認結果と限定dispositionを記録し、[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap)を追加した。承認された後続範囲は[BL-024](#bl-024--最小security-operationsと公開済み生成物の訂正手順を定義する)、[BL-025](#bl-025--収集元urlをhttphttps-schemeへ制限する)、[BL-026](#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する)へ登録した。[PR #44](https://github.com/matkei31/security-digest/pull/44)はfinal head `eef80a3a589bbaee8dbb373c4a0ee0f75038546d`、[Pull Request CI run 30095261901](https://github.com/matkei31/security-digest/actions/runs/30095261901)成功後、merge commit `3f1803388161495f9145150e760d91b03821ad80`としてmergeされた。Draft 0.1からVersion 1.0までsecurity-control実装、runtime、workflow、`data/`、`docs/`、productionは変更していない。
- **ユーザー受入証跡:** 2026-07-24、ユーザーは提示されたdecision brief全体に「ok」と回答し、Security Requirements Version 1.0の方針、GAP-010 read-only確認、限定disposition、後続Ticket化を承認した。この承認は各後続security-control PR、production実行、またはmergeの包括的な事前承認ではない。
- **残作業:** BL-015自体はなし。未実装のcontrol、operations文書、residual／deferred項目はBL-024〜BL-026、BL-007、GAP-009、GAP-015でそれぞれ管理し、各Ticketでscope、test、review、merge手続を必要とする。
- **注記:** Version 1.0はsecurity-control実装を含まない。GAP-009は未解決のまま後日優先順位を決め、GAP-015はtriggerまで保留する。GAP-011はBL-007へ統合し、GAP-012は公開情報用途に限定したaccepted residual riskである。本項目の出典となった監査記録は[BACKLOG_AUDIT.md](BACKLOG_AUDIT.md) Batch 1（BL014-C、BL014-F）を参照。

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

## BL-024 — 最小Security Operationsと公開済み生成物の訂正手順を定義する

- **ID:** BL-024
- **タイトル:** 最小Security Operationsと公開済み生成物の訂正手順を定義する
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー承認済み方針
- **ユーザー原文:** 該当なし — BL-015 decision brief全体への承認「ok」に基づく後続Ticket。
- **ユーザー確認済み要約:** GAP-006、GAP-008、GAP-013、GAP-014を1つの短い`SECURITY_OPERATIONS.md`へ統合する。
- **解釈:** secret rotation、credential revocation、suspected leakage、minimal incident response、evidence preservation、published-output correction／withdrawal／regeneration、daily JSON／HTML／repository historyの扱い、repository-external artifact retention／disposal／exception approvalを、runtimeやworkflowを変更しない最小運用文書として定義する。
- **完了条件:** 詳細なraw request／response artifactは原則90日、評価要約・manifest・BL／SD意思決定証跡は必要期間保持、secret・credential・不要なlocal absolute pathは保存禁止、90日超の例外は評価単位で理由と対象を記録する；既存artifactをこのTicketで自動削除しない；訂正・撤回・再生成の対象と証跡をSD-014と整合させる；ユーザー承認を記録する。
- **依存関係:** [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.1；[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap)；[SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy)。
- **実装証跡:** [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) Draft 0.1はGAP-006／008／013／014を統合した。Fable 5レビューはCritical 0、High 1（F-001）、Medium F-002〜F-007、Low／Editorial F-008〜F-010で、test取得制約をF-011として扱った。ユーザー裁定に基づきF-001〜F-011をDraft 0.2へ反映し、incident evidence／artifact等へのsecret類の無条件保存禁止とapproved secret storeの区別、immediate revocation／controlled rotationの2経路、該当時だけ適用するclosure条件、`docs/translate_cache.json`の訂正、GitHub account compromise手順、公開secretの失効優先、sanitized derivative／manifestを優先する長期証跡規則、個人管理projectでのrole兼任を明確化した。その後、承認済みVersion 1.0へ、(1) review／CIを省略しない通常fast-trackと厳格なdirect public hotfix例外・24時間以内のafter-action、(2) notice→blank→deleteのwithdrawal優先順と初回別Ticket、(3) daily JSON／index／HTML／translation cacheを整合させる決定論的訂正と証跡、(4) correction notice schema／UIを現時点で追加しない判断、(5) 詳細artifactの90日原則と承認記録付き延長を確定した。[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.1はSR-015／020／032／043をMet、GAP-006／008／013／014を`Completed by documentation`として記録し、[SD-025](DECISIONS.md#sd-025--approve-security-operations-version-10-and-the-minimal-incident-and-correction-policy)と[AGENTS.md](AGENTS.md)の最小参照を追加した。Fable 5は`test_security_operations.py`を取得できず同fileをレビューしていないため、PR headで独立確認しF-011のcontractを強化した。[PR #46](https://github.com/matkei31/security-digest/pull/46) final head `a04e3a3b6c5789d0a2e4de983054035080f0ce75`は[Pull Request CI run 30102905467](https://github.com/matkei31/security-digest/actions/runs/30102905467)成功後、merge commit `047534601d8d15419a8d3b45142d8828bc655ad4`としてmergeされ、automatic [Pages deployment run 30103074821](https://github.com/matkei31/security-digest/actions/runs/30103074821)も成功した。runtime、workflow、schema、prompt、model、validation、production、`data/`、`docs/`、security-controlは未変更で、既存repository-external artifactは変更・実行・削除していない。
- **ユーザー受入証跡:** 2026-07-24、ユーザーは提示された最終decision brief全体へ「ok」と回答し、上記Version 1.0方針、Security Requirements Version 1.1のmaintenance更新、SD-025、AGENTS最小参照を承認した。実際のincident操作、production実行、GitHub設定変更、個別control実装への包括的承認ではない。
- **残作業:** なし。初回withdrawal、実incident、個別control実装、既存artifact inventoryはVersion 1.0のtriggerと別Ticket／承認境界に従い、BL-024の残作業ではない。
- **注記:** 公開済み誤情報への既知のcontent-integrity残余リスクへ先に最小手順を定義するP1文書Ticketである。Version 1.0はruntime／workflow／productionを変更せず、direct public hotfixを限定例外とし、withdrawal用schema／UIを現時点では追加しない。

## BL-025 — 収集元URLをhttp／https schemeへ制限する

- **ID:** BL-025
- **タイトル:** 収集元URLをhttp／https schemeへ制限する
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー承認済み方針
- **ユーザー原文:** 該当なし — BL-015 decision brief全体への承認「ok」に基づく後続Ticket。
- **ユーザー確認済み要約:** GAP-001を最小のsource-definition validation変更として実装する。
- **解釈:** `load_source_definitions()`でcollection URLを`http`／`https` schemeへ制限する。collection URL、display URL等の各URL fieldの役割を区別し、title・vendor・記事固有ruleを追加しない。
- **完了条件:** 非HTTP(S) collection URLを拒否する；各URL fieldの役割に沿ったsource-definition testsを追加する；現在の有効設定と取得挙動を非回帰確認する；runtime変更を最小化し、個別受入を記録する。
- **依存関係:** GAP-001；[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.2；[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap)。
- **実装証跡:** `fetch.py`のsource-definition loader境界へ、`URL_REQUIRED_COLLECTION_METHODS`をsource of truthとするcollection `url` validatorを追加した。`rss`／`cisa_kev_json`／`nist_nvd_json`はenabled状態にかかわらず、空でない文字列、前後whitespaceなし、absolute URL、`http`／`https` scheme、hostありを要求し、違反を外部取得前に`SourceDefinitionError`で拒否する。collection URLと表示用`display_url`は別役割のまま、CISA KEVのenabled時presence契約とrender-time `safe_url()`境界を変更していない。17件の現行source定義、active RSSの名前／順序／URL、trusted source set、CISA KEV／NIST NVDのstructured-source URLは不変である。hostname allowlist、private network／DNS／redirect／port／TLS検査、HTTPS-only化は非対象。関連source-definition tests 63件、受入状態のfocused tests 120件、full unittest 1,205件が成功した。[PR #48](https://github.com/matkei31/security-digest/pull/48)はfinal head `ffca290ba74f3002adf9f383bddfff80b42860b7`で[Pull Request CI run 30107009791](https://github.com/matkei31/security-digest/actions/runs/30107009791)成功後、merge commit `2f93556532c6600a0d650c93d388a237b98e7aaa`として通常mergeされた。Gemini、RSS、NVD、CISA KEV、translation、production、外部HTTPは実行していない。[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.2でSR-003を`Met`、GAP-001を`Implemented`へ更新した。
- **ユーザー受入証跡:** 2026-07-25、ユーザーはPR #48の完成実装へ「ok」と回答し、上記collection URL scheme validationを個別受入した。この受入はhostname allowlist、private IP、DNS、redirect、port、TLS等の将来対策、`display_url`への新validation、production実行を承認するものではない。
- **残作業:** なし。
- **注記:** runtime変更はsource-definition loader境界だけであり、source定義、取得対象、ARTICLE／BRIEF／daily schema、workflow、production、`data/`、`docs/`は不変。production実行や外部content requestを行わず、個別受入、CI、通常merge、完了記録まで完了した。

## BL-026 — GitHub Actions supply chainとproduction concurrencyを強化する

- **ID:** BL-026
- **タイトル:** GitHub Actions supply chainとproduction concurrencyを強化する
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー承認済み方針
- **ユーザー原文:** 該当なし — BL-015 decision brief全体への承認「ok」に基づく後続Ticket。
- **ユーザー確認済み要約:** GAP-002、GAP-003、GAP-004を1つのworkflow hardening Ticketとして扱う。
- **解釈:** `actions/checkout`と`actions/setup-python`を両workflowでfull commit SHAへ固定し、`github-actions` ecosystemだけのweekly Dependabotを追加し、production runを`cancel-in-progress: false`で直列化する。
- **完了条件:** 両workflowのAction参照を検証済みfull SHAへ固定する；weekly GitHub Actions Dependabotを追加する；production concurrencyを直列化し実行中runをcancelしない；workflow-specific testsとfull unittestを成功させる；production実行なしで個別受入を記録する。
- **依存関係:** GAP-002、GAP-003、GAP-004；[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.0；[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap)。
- **実装証跡:** `.github/workflows/fetch.yml`と`.github/workflows/pr-ci.yml`の両方で、`actions/checkout`をfull commit SHA `11d5960a326750d5838078e36cf38b85af677262`（`actions/checkout` v4.4.0、current v4 patchへのpinning、major upgradeなし）へ、`actions/setup-python`をfull commit SHA `a26af69be951a213d495a4c3e4e4022e16d87065`（v5.6.0、current major維持）へ固定し、両SHAをupstream tag参照（`git ls-remote`）で読み取り専用に確認した。当初のDraft実装は`actions/checkout`をv4.3.1（`34e114876b0b11c390a56381ad16ebd13914f8d5`）へ固定していたが、独立レビューでv4系の現行releaseがv4.4.0であり、直前まで使用していた浮動タグ`actions/checkout@v4`もv4.4.0へ解決されていたためv4.3.1固定は実質downgradeと判明し、merge前にv4.4.0へ修正した。新規`.github/dependabot.yml`は`package-ecosystem: "github-actions"`、`directory: "/"`、`schedule.interval: "weekly"`のみの最小構成とし、pip／npm／Docker ecosystem、reviewer／assignee／labels、`open-pull-requests-limit`等は追加していない。`.github/workflows/fetch.yml`のworkflow levelへ`concurrency: {group: daily-security-digest-production, cancel-in-progress: false}`を追加し、scheduleとworkflow_dispatchを同一groupで直列化し、実行中のproduction runをcancelしない。GitHub標準のpending-run semantics（`cancel-in-progress: false`でも新規pending runが既存pending runを置き換え得る点）は変更せず、独自queue実装は追加していない。groupはbranchやrun IDごとに分けておらず、PR CIのconcurrency group（`pr-ci-${{ github.event.pull_request.number }}`、`cancel-in-progress: true`）とは異なる。既存のcheckoutのfetch-depth、persist-credentials、Python version、permissions、timeout、PR CI concurrency、production commit／push処理、production checkoutのcredential persistenceは変更していない。production workflowとworkflow_dispatchは未実行。関連test: `test_workflow_action_pinning.py`（両workflowの40文字SHA contractと承認済みexact SHA、Dependabot構成）、`test_pr_ci_workflow.py`（pinning assertion）、`test_fetch.py`の`WorkflowStaticCheckTest`（concurrency／timeout／python version）、`test_security_requirements.py`・`test_security_operations.py`・`test_ui_spec.py`（BL-026／STATUS.md連動assertion）。
- **ユーザー受入証跡:** ユーザーが独立レビューと修正を完了したDraft PR #50のhead `394dd157395b69e86928d98a376386131474b20f`に対して「ok」と個別実装受入した。受入対象は、`actions/checkout` v4.4.0のfull commit SHA `11d5960a326750d5838078e36cf38b85af677262`固定、`actions/setup-python` v5.6.0のfull commit SHA `a26af69be951a213d495a4c3e4e4022e16d87065`固定（両workflowで同一SHA）、`github-actions` ecosystemだけのweekly Dependabot、production workflowのworkflow-level concurrency（`group: daily-security-digest-production`、`cancel-in-progress: false`）、GitHub標準のpending-run置換挙動の受容、production／`workflow_dispatch`を実行していないこと、Pages failure run 30107780883をBL-026のscope外とすることである。この受入は、将来のAction upgrade、runtime dependency導入、新しいthird-party Action、production実行、`workflow_dispatch`、Pages操作を包括承認するものではない。受入時点の[Pull Request CI run 30140958887](https://github.com/matkei31/security-digest/actions/runs/30140958887)は成功している。受入後の記録反映commitを含む最終head `4b1fcb3d940513e2b7407120d1953c029532f25c`は[Pull Request CI run 30141453440](https://github.com/matkei31/security-digest/actions/runs/30141453440)に成功し、[PR #50](https://github.com/matkei31/security-digest/pull/50)はmerge commit `5bfc73fcb4b814504906c0a224613426384aa144`としてmainへmergeされた。[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.3はSR-025／SR-028／SR-029を`Met`、GAP-002／GAP-003／GAP-004を`Implemented`として記録した。
- **残作業:** なし。将来のAction update、Dependabot PR、runtime dependency導入、新しいthird-party Actionは、それぞれ通常のreviewまたはtrigger時の別判断であり、BL-026の残作業としては扱わない。
- **注記:** 低優先のworkflow hardeningであり、本Ticket実装時にもproduction executionは行わない。BL-025 closure後のautomatic Pages deployment run 30107780883（artifact upload failure、deploy skipped）はBL-026と独立した一時的事象として扱い、本Ticketのscopeへ含めなかった。PR #50 merge直後、Dependabotが`actions/checkout`と`actions/setup-python`のmajor upgrade提案PRを自動作成したが、本Ticketでは処理していない（ユーザー指示により対象外）。

## BL-027 — GitHub Actions checkout／setup-pythonをv7系へmajor upgradeする

- **ID:** BL-027
- **タイトル:** GitHub Actions checkout／setup-pythonをv7系へmajor upgradeする
- **優先度:** P2
- **状態:** 完了
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — BL-026 merge直後にDependabotが作成した[PR #51](https://github.com/matkei31/security-digest/pull/51)／[PR #52](https://github.com/matkei31/security-digest/pull/52)の評価brief（read-only調査）を受けたユーザー承認「ok」に基づくTicket。
- **ユーザー確認済み要約:** checkoutとsetup-pythonを1つのcombined Ticketでv7へ更新する；Dependabot PR #51／#52を直接mergeせずreplacement PRを作る；exact-SHA契約testを新versionへ更新する；merge後は手動dispatchではなく次回の通常schedule runでproduction経路を確認する；production検証成功後にTicketをclosureする。今回の「ok」は実装着手と上記方針への承認であり、完成したDraft PRの個別実装受入ではない。将来のAction update、Dependabot PRの自動merge、新しいthird-party Action、runtime dependency、workflow_dispatch、production実行、Pages操作、GitHub設定変更を包括承認するものでもない。
- **追加のユーザー確認済み要約:** merge後、ユーザーは従来承認していた「手動`workflow_dispatch`を使用せず、次回の通常schedule runで検証する」という方針を明示的に変更し、今回に限り`workflow_dispatch`によるproduction validationを承認した。この変更は本Ticketの一回限りの実施であり、`workflow_dispatch`を将来のAction更新に対する標準的な検証手段として包括承認するものではない。
- **解釈:** [BL-026](#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する)でfull-SHA pinningとweekly GitHub Actions Dependabotを導入した。Dependabotが`actions/checkout` v7.0.1と`actions/setup-python` v7.0.0を提案した。major upgradeはBL-026の「current major維持」という受入境界を超えるため、別Ticketとして扱う。現在のPR #51／#52のCI failureはAction incompatibilityではなく、承認済みexact SHA／versionを固定するrepository testによるmanual review gateであり、想定どおりの動作である。2つのActionはNode 24移行、対象workflow、対象test、承認境界を共有するためcombined Ticketで扱う。
- **完了条件:**
  1. 両workflow（`.github/workflows/fetch.yml`、`.github/workflows/pr-ci.yml`）で`actions/checkout`をv7.0.1の同一full SHAへ固定する。
  2. 両workflowで`actions/setup-python`をv7.0.0の同一full SHAへ固定する。
  3. exact-SHA／version契約test（`test_workflow_action_pinning.py`等）を新versionへ更新する。
  4. Pull Request CIを成功させる。
  5. ユーザーによる完成実装の個別受入を得る。
  6. replacement PRをmergeする。
  7. production環境でv7 Actionsが起動し、生成処理が完了することを確認する（ユーザーが方針を変更し、次回の通常schedule runではなく一回限りの`workflow_dispatch`で検証することを承認した）。
  8. その検証runが実際に変更を生成した場合、commit／pushまで成功することを確認する。
  9. 検証runが変更なしでcommit／pushを通らなかった場合、push経路の検証は次の変更発生runまで未完了として残す。
  10. production検証成功後に[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) maintenance update（Version 1.4）とBL-027 closureを行う。

  完了条件7〜10はいずれも達成された。production validationは、ユーザーが承認した一回限りの`workflow_dispatch`（[run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)）により行われ、次回の通常schedule runでは検証していない。
- **依存関係:** [BL-026](#bl-026--github-actions-supply-chainとproduction-concurrencyを強化する)；[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.3；[SD-024](DECISIONS.md#sd-024--approve-security-requirements-version-10-and-the-proportionate-security-roadmap)；[PR #51](https://github.com/matkei31/security-digest/pull/51)；[PR #52](https://github.com/matkei31/security-digest/pull/52)。
- **実装証跡:** `.github/workflows/fetch.yml`と`.github/workflows/pr-ci.yml`の両方で、`actions/checkout`をfull commit SHA `3d3c42e5aac5ba805825da76410c181273ba90b1`（v7.0.1）へ、`actions/setup-python`をfull commit SHA `5fda3b95a4ea91299a34e894583c3862153e4b97`（v7.0.0）へ固定し、両SHAをupstream tag参照（`git ls-remote`）で読み取り専用に再確認した（Dependabot提案SHAと完全一致）。production workflowのschedule／workflow_dispatch／`contents: write`／timeout-minutes: 20／Python 3.12／secrets参照／`python3 fetch.py`／commit・push処理／production concurrency（`daily-security-digest-production`、`cancel-in-progress: false`）、PR CIのpull_requestのみ／`contents: read`／`persist-credentials: false`／`fetch-depth: 0`／secretsなし／full unittest／diff check／PR単位concurrencyは変更していない。checkout v7のcredential保存先変更（`.git/config`から`$RUNNER_TEMP`下の別ファイルへ）に対する独自workaroundは追加していない。`.github/dependabot.yml`は変更していない。関連test: `test_workflow_action_pinning.py`（定数・test名・exact SHA／versionをv7へ）、`test_pr_ci_workflow.py`、`test_fetch.py`の`WorkflowStaticCheckTest`、`test_security_requirements.py`（workflow実ファイルを直接検証するassertionのみ更新、`SECURITY_REQUIREMENTS.md`本文はVersion 1.3のまま変更なし）、`test_security_operations.py`・`test_ui_spec.py`（STATUS.md Active work／Next candidates連動assertion）。[Pull Request CI run 30143743247](https://github.com/matkei31/security-digest/actions/runs/30143743247)が成功し、GitHub-hosted runner上でv7 Action（checkout・setup-python）の起動が実証された。ユーザー受入後の記録反映commitを含む最終head `241e7f69c9c843fc212c1c590f3a328da5946579`は[Pull Request CI run 30144069410](https://github.com/matkei31/security-digest/actions/runs/30144069410)に成功し、[PR #54](https://github.com/matkei31/security-digest/pull/54)はmerge commit `69f7da859e1856beffac9fa381f0f0cc92564e36`としてmainへmergeされた。merge後の自動[Pages deployment run 30144096081](https://github.com/matkei31/security-digest/actions/runs/30144096081)は成功した。PR #51は[close comment](https://github.com/matkei31/security-digest/pull/51#issuecomment-5076938850)を残しsuperseded closeし（ignore commandなし、mergeなし）、PR #52も同様に[close comment](https://github.com/matkei31/security-digest/pull/52#issuecomment-5076938941)を残しsuperseded closeした（ignore commandなし、mergeなし）。

  **production validation（一回限りのworkflow_dispatch）:** ユーザーが方針を変更し承認したことを受け、merge済みmain（head `226db6285021d9daf98fe2941248b7f5b20ba143`より前のhead `db6c4bf9907acd1f04a4ad85fd094e7d850b1b6d`）に対して`gh workflow run fetch.yml --ref main`で`Daily Security Digest`を1回だけ起動した。[run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)（event: `workflow_dispatch`、head SHA `db6c4bf9907acd1f04a4ad85fd094e7d850b1b6d`、conclusion: success）で、Checkout（v7.0.1）、Setup Python（v7.0.0）、Fetch RSS and generate HTML、Commit and pushの全stepが成功した。RSS収集はsuccess=4/zero=9/failed=1（Microsoft Security HTTP 403、既知のpre-existing事象でBL-027と無関係）、AI要約は7件試行・7件成功・fallback 0・failed 0、facts該当CVEなし。生成差分が検出され、`git commit`と`git push`が実行された：commit `226db6285021d9daf98fe2941248b7f5b20ba143`（author: `github-actions[bot] <github-actions[bot]@users.noreply.github.com>`、message: `digest: 2026-07-25 15:23 JST`）、変更ファイルは`data/2026-07-25.json`・`data/index.json`・`docs/archive/2026-07-25.html`・`docs/archive/index.html`・`docs/index.html`の5件で、いずれも通常の`data/`／`docs/`生成物に限定された。pushは`db6c4bf..226db62 main -> main`として成功した。merge後の自動[Pages deployment run 30147402699](https://github.com/matkei31/security-digest/actions/runs/30147402699)は成功し、公開トップページ（`https://matkei31.github.io/security-digest/`）と当日archive（`/archive/2026-07-25.html`）はいずれもHTTP 200を返した。生成されたdaily JSON（`data/2026-07-25.json`）はARTICLE prompt `article-analysis-v8`、BRIEF `today-brief-extractive-v1`、`schema_version: 1`、`run.status: success`、`total_items: 7`、`ai_success_count: 7`／`ai_fallback_count: 0`／`ai_failed_count: 0`を記録しており、公開HTMLに内部識別子漏洩や表示異常は確認されなかった。checkout v7のcredential保存先変更（`$RUNNER_TEMP`下の別ファイル）は`git push`の成功を妨げず、Post Checkoutステップでcredential configが正しくcleanupされたことをログで確認した。
- **ロールバック:** v7でrunner、checkout、credential、setup-python、commit／pushの問題が確認された場合は、承認済みの次のSHAへ戻す。
  - `actions/checkout` v4.4.0: `11d5960a326750d5838078e36cf38b85af677262`
  - `actions/setup-python` v5.6.0: `a26af69be951a213d495a4c3e4e4022e16d87065`
- **ユーザー受入証跡:** ユーザーが独立レビュー済みのDraft PR #54のhead `d7461b9adfe474793a60f61cd6fe8b219153b499`に対して「ok」と個別実装受入した。受入対象は、`actions/checkout` v7.0.1（full SHA `3d3c42e5aac5ba805825da76410c181273ba90b1`）へのmajor upgrade、`actions/setup-python` v7.0.0（full SHA `5fda3b95a4ea91299a34e894583c3862153e4b97`）へのmajor upgrade、両workflowで同一version／SHAの使用、exact-SHA／version契約testの更新、PR CI安全境界の維持、production workflowのcommit／push処理・credential設定・concurrencyを変更しないこと、PR #51／#52を直接mergeせずPR #54で置換すること、PR #54 merge後にPR #51／#52をsuperseded closeすることである。受入時点の[Pull Request CI run 30143743247](https://github.com/matkei31/security-digest/actions/runs/30143743247)は成功している。その後、ユーザーは別途「BL-027のproduction validationを、通常schedule待ちからworkflow_dispatchによる手動検証へ変更して実施してください」と明示的に指示し、従来承認していた「手動workflow_dispatchを使用せず、次回の通常schedule runで検証する」という方針を今回に限り変更して、一回限りの`workflow_dispatch`によるproduction validationを承認した。この一連の受入は、今後のAction update、Dependabot PRの自動merge、新しいthird-party Action、runtime dependency、`workflow_dispatch`を将来の標準的な検証手段とすること、Pages操作、GitHub設定変更を包括承認するものではない。
- **残作業:** なし。
- **注記:** production commit／push経路の検証は、ユーザーが明示的に変更・承認した一回限りの`workflow_dispatch`（[run 30147337332](https://github.com/matkei31/security-digest/actions/runs/30147337332)）により実施し、次回の通常schedule runでの検証は行っていない。この`workflow_dispatch`使用は本Ticket限りの承認であり、将来のAction更新やその他のTicketに対する標準的な検証手段としての包括承認ではない。implementation branch `claude/bl027-actions-v7-upgrade`（merge済み）；記録用branch `claude/bl027-await-schedule-validation`（merge済み）；closure branch `claude/bl027-close`。

## BL-028 — ダイジェストナビゲーションの配置を再設計する

- **ID:** BL-028
- **タイトル:** ダイジェストナビゲーションの配置を再設計する
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「『前のダイジェスト』『最新のダイジェスト』を右に持っていってもらったけど、実際見ると違和感あるね。左側で二段で表示するとか、何かイケてるUI考えてほしい」
- **出所:** 2026-07-26 プロジェクト会話（BL-006実装着手後、ユーザー受入・closure前）。
- **解釈:**
  - BL-022／[SD-021](DECISIONS.md#sd-021--unify-digest-navigation-labels-and-separate-direction-from-global-navigation)で実装した左右分離ナビゲーションについて、公開後の実画面確認で新たな違和感が判明した。
  - BL-022やSD-021を未完了扱いに戻さず、公開後の新しいユーザー評価に基づく別Ticketとして扱う。
  - 左寄せ二段構成は候補の一つであり、現時点では採用決定ではない。
  - 前後移動と全体導線の意味上のグルーピング、PC／390px、折返し、視線移動、アクセシビリティを含めて再検討する。
- **完了条件:** ユーザーと確定した仕様(A案「左寄せ二段・ラベルなし」)は次のとおり。
  1. PC／390pxともに、ナビゲーションを左寄せの縦二段構造とする。方向移動グループを1段目、全体導線グループを2段目とする。
  2. 日別Archiveの1段目は`← 前のダイジェスト`／`次のダイジェスト →`の順とする。
  3. 日別Archiveの2段目は`過去のダイジェスト`／`最新のダイジェスト`の順とする(左側を過去方向、右側を新しい方向へ統一)。
  4. トップページは1段目に利用可能な場合だけ`← 前のダイジェスト`、2段目に`過去のダイジェスト`を置く。
  5. Archive一覧は単独の全体導線`最新のダイジェスト`を左寄せで表示する(右端配置は維持しない)。
  6. 日別Archiveの上部ナビゲーションと下部ナビゲーションへ同じDOM順・配置契約を適用する。
  7. PCと390pxで情報構造とDOM順を変えない。
  8. 説明ラベル、囲み、背景色、区切り線、追加アイコンを導入しない。
  9. リンクが一つもないグループ(方向移動グループなど)は描画せず、空の`div`による余白を残さない。一方向だけ存在する場合はそのリンクを左端へ置く。
  10. 4文言(`← 前のダイジェスト`／`次のダイジェスト →`／`最新のダイジェスト`／`過去のダイジェスト`)、リンク文言への日付非表示、前後日付の選定ロジック、欠落日をまたぐ既存日探索、daily JSON／`data/index.json`の検証、現在日・未来日・不正日付の除外、存在しない方向リンクだけを省略する挙動、各リンクのhref、`aria-label`、keyboard操作、browser default focus、sticky header、上部／下部ナビゲーションの存在は変更しない。
  11. sticky headerが二段ナビゲーションで高くなることに合わせ、`--anchor-offset`をPC・390pxそれぞれ実測に基づき調整する。
  12. 全Archiveへ遡及適用する。
  13. merge前にPC 1280px／390pxでの目視受入をユーザーから得る。
  14. BL-022・BL-017を再オープンしない。BL-029・BL-007は本Ticketのscopeに含めない。
- **依存関係:** BL-022（前日ダイジェスト直接リンク、実装済み・再オープンしない）、BL-017（過去ダイジェストの回遊性、実装済み・再オープンしない）、[SD-021](DECISIONS.md#sd-021--unify-digest-navigation-labels-and-separate-direction-from-global-navigation)（部分的にsupersede）、BL-029（完了済み・scope外）、BL-007（custom domain移行、別Ticket・scope外）。
- **実装証跡:** `fetch.py`の`render_archive_nav_groups()`を、リンクが空のグループを描画しないよう変更した(方向移動グループが無い場合は全体導線グループを上へ詰める)。`build_daily_archive_html()`の`global_links`を`過去のダイジェスト`→`最新のダイジェスト`の順へ入れ替えた(既存の`render_archive_adjacent_links()`が生成する`前→次`の順は変更していない)。共有CSS`.archive-nav`をPC専用の`justify-content:space-between`(左右端分離・単一行)から、PC／390px共通の`flex-direction:column;align-items:flex-start`(左寄せ二段)へ変更し、390px専用だった`align-items:stretch`／`.archive-nav-group{width:100%}`／`.archive-global-nav{margin-left:0}`のmedia query上書きを削除した(PCと390pxで同一構造になったため不要)。Archive一覧(`build_archive_index_html()`)の単独リンクは元々右端寄せのCSSを持たず、変更なしで左寄せ契約を満たしていることを確認した。sticky headerがPC/390pxとも一段から二段ナビゲーションへ変わり実高が112px前提から202pxへ増えたため、`--anchor-offset`をPC 112px→218px(実測header高202px+16px)、390px 168px→226px(実測header高202px+24px)へ調整し、記事カードへのアンカー遷移でheading全体が隠れないことをbrowser実測で確認した。既存daily JSON全17日分をoffline再生成し(外部HTTP／Gemini／RSS／NVD／CISA KEV呼び出しなし、`data/`・`docs/translate_cache.json`は無変更)、全日で新ナビゲーション配置を適用した。関連test更新: `test_archive.py`(新規`Bl028NavigationLayoutTest`8件含む)。full unittest 1250件 OK、`git diff --check` clean、Markdown内部リンク全件成功、BL／SD ID一意性確認済み。
- **ユーザー受入証跡:** ユーザー原文「10枚とも確認した。BL-028の左寄せ二段配置、前→次／過去→最新の順序、上部・下部ナビゲーション、単一方向ケース、PC 1280px／390pxの表示に問題なし。BL-028として受入。」。受入対象は、A案「左寄せ二段・ラベルなし」、日別Archive上段(`← 前のダイジェスト`／`次のダイジェスト →`)、日別Archive下段(`過去のダイジェスト`／`最新のダイジェスト`)、日別Archive上部・下部ナビゲーション、トップページ、Archive一覧、最古日の単一方向ケース、PC 1280px／390pxの計10画面(`top-page-nav-1280px.png`、`top-page-nav-390px.png`、`daily-archive-top-nav-1280px.png`、`daily-archive-top-nav-390px.png`、`daily-archive-bottom-nav-1280px.png`、`daily-archive-bottom-nav-390px.png`、`archive-index-nav-1280px.png`、`archive-index-nav-390px.png`、`daily-archive-oldest-single-direction-1280px.png`、`daily-archive-oldest-single-direction-390px.png`)。accepted head `77b4106618c29b9220012fd10e9ff616d773fa56`。anchor offset(PC 218px／390px 226px)はブラウザ計測・テストによる技術確認済みであり、ユーザー受入対象には含まれない。BL-022・BL-017・SD-021は本受入によって再オープンしない。BL-029(完了済み)・BL-007は本Ticketのscopeに含めない。
- **公開反映証跡:** [PR #62](https://github.com/matkei31/security-digest/pull/62)(final head `a723dadaa4282db98060e83ef981b776b5742445`、[Pull Request CI run 30237446269](https://github.com/matkei31/security-digest/actions/runs/30237446269)成功)を通常merge(squash・rebase不使用)でmerge commit `fae9b682c97106c4ff9b45507aebf18db09fd77a`としてmainへ統合した。[Pages deployment run 30237477070](https://github.com/matkei31/security-digest/actions/runs/30237477070)が成功し、公開トップページ(HTTP 200、`🔐 Monomi Digest`、1段目`← 前のダイジェスト`／2段目`過去のダイジェスト`の左寄せ二段構造)、記事あり日別Archive(2026-07-26: 上部・下部とも1段目`← 前のダイジェスト`→`次のダイジェスト →`、2段目`過去のダイジェスト`→`最新のダイジェスト`)、Archive一覧(単独`最新のダイジェスト`が左寄せ)、最古日(2026-07-11: 方向移動グループに`次のダイジェスト →`のみ、空の予約領域なし)を客観確認した。旧CSS(`justify-content:space-between`によるarchive-nav左右端分離、`.archive-global-nav{margin-left:auto}`)が公開ページに残っていないことも確認した。公開anchor確認として、記事あり日別Archive(2026-07-26)の`#article-1`遷移をPC 1280px・390px相当それぞれで実施し、sticky header下端と記事カード上端の間に正の余白(PC 17px、390px 25px)があり見出しが隠れないこと、横スクロールが発生しないこと(`scrollWidth === clientWidth`)を確認した。これは技術的な公開後確認であり、ユーザー目視受入の対象ではない。merge起因のDaily Security Digest production workflow実行および`workflow_dispatch`実行はなかった(直近のDaily Security Digest runは2026-07-26のscheduleのみ)。
- **残作業:** なし。
- **注記:** BL-022・BL-017・SD-021を再オープンしない。BL-007(custom domain移行)・BL-029(完了済み)は本Ticketのscopeに含めない。implementation branch `claude/bl028-nav-two-row-left`はmerge済み。

## BL-029 — 「金融機関との関連」とARTICLE見出しの情報設計を再検討する

- **ID:** BL-029
- **タイトル:** 「金融機関との関連」とARTICLE見出しの情報設計を再検討する
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「『金融機関との関連』のところは、どういった事項について関連を記載しているのかが不明。このままだったら消した方がいい。使うなら、本文側の『何が起きた』『なぜ金融機関に関係する』をまとめた文章にする必要がある。」
- **追加のユーザー原文:** 「あと、『何が起きた』『なぜ金融機関に関係する』というタイトルはダサい。他の文言を提案してほしい」
- **出所:** 2026-07-26 プロジェクト会話（BL-006実装着手後、ユーザー受入・closure前）。
- **解釈:**
  - 現在の「金融機関との関連」は、記事全体との関連、金融機関への影響、確認理由、横断的論点のどれを示す欄か判然としない。
  - 意味を明確化できない場合は削除も選択肢とする。
  - 維持する場合は、事象の概要と金融機関にとっての意味を結びつけた文章として再設計する。
  - 現在の`financial_impact`を単に名称変更または再掲するだけでは対応完了としない。
  - 「何が起きた」「なぜ金融機関に関係する」という見出しも再検討する。
  - 代替見出しは現時点で確定しない。
  - ARTICLE、deterministic BRIEF、重複表示、source忠実性、daily JSON field、prompt／runtime境界を確認してから仕様化する。
  - 完了済みBL-021を再オープンしない。
  - prompt-only改善No-GoのBL-023とも統合せず、関係を整理した上で別Ticketとして扱う。
- **完了条件:** ユーザーと確定した仕様は次のとおり。
  1. 公開見出しを「本日の要点」の子見出し3つ（概況／重要・優先事項／確認事項）、記事カードの3見出し（概要／金融機関との関連／確認すべきこと）へ統一する。
  2. 「重要・優先事項」は、現行`discussion_points`の対象条件（`importance=="高"`または`urgency`が`"本日確認"`／`"今週確認"`）を維持して選定する。
  3. 選定された記事ごとに同一記事の`analysis.summary`と`analysis.financial_impact`をverbatimで使用し、一項目一`<li>`・summaryとfinancial_impactを別`<p>`として表示する。
  4. field欠損時は、両方存在→2段落、片方のみ→片方だけ、両方欠損→その記事を除外する。
  5. 重複除外は`(summary, financial_impact)`の完全一致pair単位のみとする。
  6. ARTICLE prompt・ARTICLE response schema・`ARTICLE_PROMPT_VERSION`・ARTICLE model・validation・fallback契約は変更しない。
  7. public daily JSON schemaは変更しない。`overview`は単一のテキスト値（成功時は`string`、`not_attempted`等ではnullになり得る）、`important_highlights`／`discussion_points`／`check_items`は`list[str]`を維持する。`important_highlights`は表示せず現行のまま維持する。
  8. 新規生成分のinternal composition identifierを`today-brief-extractive-v2`とする。過去daily JSON（`prompt_version`・`discussion_points`含む）は書き換えない。
  9. 過去Archiveは原則、既存daily JSONのofflineHTML再生成で新仕様を適用する。`items[].analysis`から安全に再構成できない日だけ、見出し「注目論点」で保存済み`discussion_points`を一項目一段落のまま互換表示する。
  10. merge前にPC 1280px／390pxでの目視受入をユーザーから得る。
  11. BL-021を再オープンしない。BL-023を再オープン・統合しない。BL-028・BL-007は本Ticketのscopeに含めない。
- **依存関係:** BL-021（Today's Briefの意味忠実性・semantic validation再設計、完了済み・再オープンしない）、BL-023（ARTICLE編集品質改善、prompt-only改善No-Go・統合しない別Ticket）、[SD-018](DECISIONS.md#sd-018--screen-deterministic-extractive-todays-brief-without-a-semantic-blocking-validator)（部分的にsupersede）、ARTICLE／BRIEF prompt、daily JSON schema。
- **実装証跡:** `fetch.py`へ新しい共有helper `select_priority_items()` を追加し、新規Brief生成（`compose_extractive_brief()`）とHTML描画（`build_html()`）の両方から呼び出すことで選定ロジックを一元化した。ARTICLE分析済み記事のうち`importance=="高"`または`urgency`が`"本日確認"`／`"今週確認"`の記事を対象に、同一記事の`analysis.summary`と`analysis.financial_impact`をverbatimで`(summary, financial_impact)`ペア単位の完全一致dedupeを適用して選定し、`<li class="brief-priority-item">`内の`<p class="brief-priority-summary">`／`<p class="brief-priority-impact">`として2段落表示する。field欠損時は存在する方だけを表示し、両方欠損の記事は除外する。「本日の要点」の子見出しを概況／重要・優先事項／確認事項へ、記事カードの見出しを概要／金融機関との関連／確認すべきことへ変更した（表示順・ARTICLE field内容は変更していない）。HTML描画は`brief.prompt_version`に依存せず、`items[].ai_analysis`が有効な限り過去Archive（`today-brief-extractive-v1`、`today-brief-v3`含む）でも新見出しを再現する。再構成不能（分析済み記事なし）かつ保存済み`discussion_points`が存在する日だけ、見出し「注目論点」で一項目一段落のまま互換表示する。`daily_json.BRIEF_PROMPT_VERSION`を`today-brief-extractive-v2`へbumpした（`ARTICLE_PROMPT_VERSION`・ARTICLE response schema・daily JSON `schema_version`は変更なし）。実装後にorigin/mainが本番自動生成コミット`cfe2c97f42c2e53980594b0d7f6f83977e2f4736`（2026-07-27 07:57 JST生成、0記事）へ進んだため、通常mergeで取り込んだ（rebase・force-push不使用、`data/`はmain側をそのまま採用しPR固有の変更なし）。merge後のdataから既存daily JSON全17日分をoffline再生成した（外部HTTP／Gemini／RSS／NVD／CISA KEV呼び出しなし、`data/`・`docs/translate_cache.json`は無変更）。記事あり14日（2026-07-11・12・14〜18・20〜26）は全日で新仕様「重要・優先事項」の再構成に成功した。0記事3日（2026-07-13、2026-07-19、2026-07-27）は元々「本日の要点」非表示となる既存のempty-day挙動であり、再構成不能による互換表示とは異なる。再構成不能・互換表示（見出し「注目論点」）に該当した日は0件。関連test更新: `test_fetch.py`、`test_archive.py`、`test_todays_brief.py`（新規`SelectPriorityItemsTest`を追加）、`test_daily_json.py`、`test_article_analysis.py`、`test_article_v5.py`、`test_vulnerability_facts_prompt.py`、`test_ui_spec.py`、`test_security_requirements.py`、`test_security_operations.py`。full unittest 1240件 OK、`git diff --check` clean、Markdown内部リンク全件成功、BL／SD ID一意性確認済み。
- **ユーザー受入証跡:** ユーザー原文「8枚とも確認した。BL-029の見出し、重要・優先事項の2段落表示、過去Archiveへの適用、0記事日の表示に問題なし。BL-029として受入。」。受入対象は、本日の要点の見出し、重要・優先事項の2段落表示、過去Archiveへの適用、0記事日の表示、PC 1280px／390pxの8画面（`top-page-2026-07-27-1280px.png`、`top-page-2026-07-27-390px.png`、`daily-archive-2026-07-27-1280px.png`、`daily-archive-2026-07-27-390px.png`、`daily-archive-2026-07-26-1280px.png`、`daily-archive-2026-07-26-390px.png`、`daily-archive-2026-07-25-1280px.png`、`daily-archive-2026-07-25-390px.png`）。accepted head `c4ca053b176c93fba3588c1f0aaf4116ab3fbc33`。BL-021・BL-023は本受入によって再オープンしない。BL-028・BL-007は本Ticketのscopeに含めない。
- **公開反映証跡:** [PR #60](https://github.com/matkei31/security-digest/pull/60)(final head `a458888f45ff1521a0eb59117994ac3122fb2b83`、[Pull Request CI run 30231386446](https://github.com/matkei31/security-digest/actions/runs/30231386446)成功)を通常merge(squash・rebase不使用)でmerge commit `2a191828462731bf5204cdd83e867c0d29aec6e8`としてmainへ統合した。[Pages deployment run 30231414580](https://github.com/matkei31/security-digest/actions/runs/30231414580)が成功し、公開トップページ(HTTP 200、`🔐 Monomi Digest`表示)、記事あり日別Archive(2026-07-26: `本日の要点`／`概況`／`重要・優先事項`(項目2件)／`確認事項`／`概要`／`金融機関との関連`／`確認すべきこと`いずれも表示)、遡及適用対象の過去Archive(2026-07-25も新見出しを表示)、0記事日別Archive(2026-07-27: 「本日の新着はありません」の既存empty state)、Archive一覧(17日分)を客観確認した。merge起因のDaily Security Digest production workflow実行および`workflow_dispatch`実行はなかった(mergeの前後で直近のDaily Security Digest run は2026-07-26のscheduleのみ)。
- **残作業:** なし。
- **注記:** BL-021・BL-023を再オープンまたは統合しない。BL-007（custom domain移行）・BL-028（ナビゲーション再設計）は本Ticketのscopeに含めない。implementation branch `claude/bl029-priority-items`はmerge済み。

## BL-030 — 取得元・翻訳経路の緊急リスク低減

- **ID:** BL-030
- **タイトル:** 取得元・翻訳経路の緊急リスク低減
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー指示（包括的な取得元規約監査に先立つ暫定措置）
- **解釈:** 包括的な取得元規約監査（BL-031候補）に先立ち、現行実装で確認された高優先度のリスクだけを、小さく可逆的な変更で一時的に低減する。**これは最終的な法的判断ではなく、公式条件の精査・許可確認までの暫定的なリスク低減である。**
- **完了条件:**
  1. 非公式Google翻訳経路（`translate.googleapis.com/translate_a/single`、`client=gtx`、`load_cache()`／`save_cache()`／`translate()`）を`fetch.py`から完全に削除する。
  2. `resolve_display_title()`を、AI成功時の`title_ja`表示、それ以外はraw_titleまたは取得時の原題への表示という契約へ単純化し、外部翻訳・translate cacheのいずれも参照しない。
  3. AI分析が無い／failedの場合のsummary表示は、取得済みRSS descriptionのプレーンテキストを既存表示上限内で英語のまま表示する（空欄にしない）。
  4. `docs/translate_cache.json`を現在のrepository treeから削除する。git history rewriteはしない。日次生成・Archive再生成・テスト実行で再作成されないことを保証する。docs配下・data配下等へ翻訳cacheや原文抜粋cacheを別名で新設・移動しない。
  5. `source_definitions.json`のCrowdStrike（`crowdstrike`）を`enabled: false`・`planned_phase: "保留"`へ変更し、公式Website Termsの適用範囲・許諾確認を条件とする`activation_condition`を記録する。
  6. `source_definitions.json`のCloudflare（`cloudflare`）を`enabled: false`・`planned_phase: "保留"`へ変更し、書面による明示的な許諾が得られる場合を除き、(a) AI用途bot User-AgentがCloudflareのrobots.txtで明示的にallowedとされていること、(b) そのUser-Agentが検索等との多目的ではなくAI用途botの識別だけに使用されていること、の両方に加えRSS自動取得・外部AI処理・公開要約・保存の利用条件が確認できることを条件とする`activation_condition`を記録する。
  7. CrowdStrike・Cloudflare以外の全source設定（Microsoft Security、Mandiant、Google TAG、Cisco Talos、Dark Reading、The Hacker News、Krebs on Security、公共機関等）は変更しない。
  8. `content:encoded`／Atom contentの共通処理、ARTICLE prompt、response schema、`ARTICLE_PROMPT_VERSION`、Gemini入力上限（4000文字）は変更しない。
  9. production、`workflow_dispatch`、Gemini API、RSS/API/記事ページ/robots.txt等への外部アクセスは行わない。DNS・GitHub Pages・Custom domain・Enforce HTTPSは変更しない。
  10. 本PRの直接差分として、過去の`data/*.json`・`docs/archive/*.html`は変更しない。CrowdStrike・Cloudflareの過去記事も削除しない。docs配下の直接差分は`docs/translate_cache.json`削除のみ。ただし、merge後の**最初の通常production run**では、`generate_archive_outputs()`が保存済みdaily JSON全日分からArchive HTMLを再生成するため、各Archiveの「収集元」footerは過去時点のsource一覧ではなく実行時点のenabled source一覧（13ソース）を反映するよう更新される。この結果、過去ArchiveのCrowdStrike・Cloudflare記事カード自体・source名・daily JSON・AI分析結果は維持されたまま、「収集元」footerだけが13ソースへ更新され、この差分が通常production commitに含まれる可能性が高い。これは削除や履歴改変ではなく、既存のArchive全件再生成・current-source footer仕様（`build_footer_sources()`が`fetch.SOURCE_DEFINITIONS`の実行時点の値を参照する既存の設計）による結果であり、本PRが新たに導入する挙動ではない。
  11. `SECURITY_REQUIREMENTS.md`（system scope・data flow・GAP-012）・`SECURITY_OPERATIONS.md`は本PRでは変更しない。両文書は非公式翻訳経路・`docs/translate_cache.json`を現行アーキテクチャの一部として記載しており、本PRのmerge後はこれらの記載が実装と不整合になる。緊急リスク低減を遅らせないため本PRでは改訂しないが、**BL-031の最初の工程として**、正式なversion bump・レビュー・ユーザー受入を伴う両文書の整合化を行うことをBL-031のscopeに明示的に含める。BL-031完了まで、この不整合は既知の文書上の残課題として扱う。
- **依存関係:** 情報取得・AI入力・保存・公開データフローのread-only棚卸し(本Ticket着手直前にユーザーへ提供済み、repositoryへは非コミット)。後続候補: **BL-031**（全取得元の公式規約監査・`source_definitions.json`への`content_usage_mode`等の設定項目実装に加え、その最初の工程として`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`のversion bump・レビューを伴う整合化を含む）、**BL-032**（取得元別ポリシーの実装反映）。About／出典／免責／訂正窓口は[BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策)へ連携する（本Ticketでは実装しない）。
- **実装証跡:** `fetch.py`から`CACHE_PATH`定数・`load_cache()`・`save_cache()`・`translate()`を削除し、`resolve_display_title()`をcache引数なしの単純な`title_ja`→`raw_title`fallback契約へ書き換えた。`main()`の翻訳ループから`translate()`呼び出しと`cache`の読み書きを削除し、summaryは取得済み英語descriptionのまま保持する（既存のHTML生成側120文字fallback表示は変更していない）。`docs/translate_cache.json`をrepository treeから削除した（`git rm`、history rewriteなし）。`source_definitions.json`のCrowdStrike・Cloudflareを`enabled: false`へ変更し、`activation_condition`・`notes`（公式Website Terms URL・暫定停止の根拠・「法的違反を確定したものではなく…BL-030」の記載）を追加した。両sourceの`trusted_cyber_source`／`color`／`source_tier`／`url`等は変更していない。`RSS_FEEDS`・`build_footer_sources()`はいずれも`enabled`フィルタ経由で自動的にCrowdStrike・Cloudflareを除外する（コード変更不要）。`content:encoded`／Atom content処理、ARTICLE prompt、response schema、`ARTICLE_PROMPT_VERSION`、Gemini入力上限は変更していない。Cloudflareの`activation_condition`は、独立レビュー指摘に基づき、書面許諾がない限りrobots.txtでの明示的allowとAI用途bot専用(多目的でない)User-Agentの両方を要求する表現へ精密化した。関連test更新: `test_article_v5.py`（`DisplayTitleFlowTest`をcacheなし契約へ書き換え）、`test_archive.py`（footer件数を15→13、CrowdStrike・Cloudflare不在assertion追加、`load_cache`/`save_cache`のmock削除、新規`Bl030ArchiveRegenerationCurrentFooterTest`でArchive全件再生成後も記事カード・source名が維持されfooterのみ13ソースへ更新されることを一時ディレクトリ内で決定論的に検証）、`test_source_definitions.py`（`EXPECTED_ACTIVE_RSS_FEEDS`からCrowdStrike・Cloudflareを除外、新規`Bl030SourceRiskContainmentTest`追加、Cloudflareのrobots.txt/AI専用User-Agent両条件を固定するtest追加）。
- **ユーザー受入証跡:** 2026-07-29、[PR #66](https://github.com/matkei31/security-digest/pull/66) head `9757ae98c2f5ef9f13da667be5677d870a6e2cd1` に対するChatGPT独立レビューで実装上のBlockerなし。ユーザーが本指示をClaude Codeへ送付することで、BL-030の受入、Ready化、通常mergeを承認した。CI: [run 30428514818](https://github.com/matkei31/security-digest/actions/runs/30428514818) success。focused tests: `test_source_definitions` 77、`test_archive` 57、`test_article_v5` 101、`test_feed_rich_content` 71。full unittest: 1307 tests OK。
- **残作業:** BL-030の実装上の残作業はなし。次回通常scheduled production runで確認する事項は、BL-030の完了条件ではなく追加の運用証跡として区別する。この確認内容は、その次回runがBL-031([PR #67](https://github.com/matkei31/security-digest/pull/67))のmerge前に発生するか後に発生するかで異なるため、固定値ではなく実行順序に応じて次のいずれかとして確認する: **(A) BL-031merge前に次回runが発生した場合** — (1) CrowdStrike・Cloudflareが収集されないこと、(2) enabled sourceが13であること、(3) 過去Archiveの記事カード・daily JSONが維持されること、(4) 全Archiveの「収集元」footerが13ソースへ更新されること。**(B) BL-031merge後に次回runが発生した場合** — (1) CrowdStrike・Cloudflare・Dark Readingが収集されないこと、(2) enabled sourceが12であること、(3) 過去Archiveの記事カード・daily JSONが維持されること、(4) 全Archiveの「収集元」footerが12ソースへ更新されること。いずれの場合も共通して(5)`docs/translate_cache.json`が再生成されないことを確認する。BL-031（全取得元規約監査、`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`整合化を含む）・BL-032（取得元別ポリシー実装）・BL-009（About／出典／免責／訂正窓口）は後続Ticketであり、BL-030自体の残作業ではない。
- **注記:** 本暫定停止はrollback可能で、rollbackはsourceの再有効化（`enabled: true`へ戻す）と、承認済みの正式翻訳経路を別途実装することを想定する。本PRの直接差分として過去の`data/*.json`・`docs/archive/*.html`（CrowdStrike・Cloudflare記事を含む）は変更していないが、merge後最初の通常production runでのArchive全件再生成により、各Archiveの「収集元」footerが更新される（記事カード・daily JSON自体は維持される）。その更新後の件数は、次回runがBL-031([PR #67](https://github.com/matkei31/security-digest/pull/67))のmerge前なら13ソース、merge後なら12ソース(Dark Reading分も除外)であり、runとmergeの時系列で決まる（上記「残作業」参照）。`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`は本PR(BL-030)merge直後の時点では非公式翻訳経路・`docs/translate_cache.json`を現行構成として記載したままであり、実装と不整合であったが、この不整合はBL-031の最初の工程として対応済み([PR #67](https://github.com/matkei31/security-digest/pull/67)としてユーザー受入・merge済み、`SECURITY_REQUIREMENTS.md`Version 1.5、`SECURITY_OPERATIONS.md`Version 1.1、いずれもStatus Approved、2026-07-31)。implementation branch `fix/bl030-source-risk-containment`。

## BL-031 — 全取得元の公式規約監査とセキュリティ文書整合化

- **ID:** BL-031
- **タイトル:** 全取得元の公式規約監査とセキュリティ文書整合化
- **優先度:** P1
- **状態:** 完了
- **出所種別:** ユーザー指示（BL-030完了条件11で明示的に予約された後続チケット）
- **解釈:** 現行17 sourceすべてについて、公式に確認できる利用規約・ライセンス・robots.txt・AI提供者データ利用条件を監査し、`SOURCE_USAGE_POLICY.md`として記録する。あわせて、BL-030（非公式翻訳経路・cache削除）とmonomidigest.comカスタムドメイン稼働を反映するよう`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`を整合化する。本Ticketは監査・ポリシー文書・文書整合化のみを scope とし、`source_definitions.json`への`content_usage_mode`等のfield追加やfetch.pyでの共通enforcement実装は行わない（**BL-032へ明示的に委譲**）。production・`workflow_dispatch`・Gemini API・RSS/記事ページ/robots.txt等への外部アクセスは行わない。
- **完了条件:**
  1. `SOURCE_USAGE_POLICY.md`（Version 0.1、Status Draft、As of 2026-07-30）を新設し、目的・法的位置づけ・5つのcontent usage mode定義・17 source監査表・Gemini data-use gate・attribution要件・output-similarity/quotation control要件（BL-032実装事項）・recheck trigger・unknowns・BL-032/BL-009との関係を記載する。
  2. 5つのcontent usage mode（`structured_open`5 source、`feed_summary`4 source、`limited_feed_analysis`2 source、`metadata_only`2 source、`disabled_legal_review`4 source、計17）を、許可・禁止事項を明記して定義する。全17 sourceで`allow_rich_content=false`とする。`limited_feed_analysis`（`the_hacker_news`、`krebs_on_security`）は、公式RSSの提供は確認できるが包括的な再利用許諾までは確認できていない2 sourceについて、`metadata_only`への一律格下げによる実用性低下を避けるための、明示的な運用上のリスク受容であり、利用許諾を確認したという判断ではない。`metadata_only`（`microsoft_security`、`cisco_talos`）は、公式Feedからの原題・取得元・公開日時・原記事URLという最小メタデータの取得・リンク掲載は継続しつつ、description等の内容利用・外部AI処理・AI評価要約の公開について十分な根拠を確認できていないためproduction上の処理を最小メタデータへ限定する区分であり、人による閲覧やsource自体の独自報道・論評を禁止する趣旨ではない。
  3. `nist_nvd`は`structured_open`に分類するが、standalone記事収集の`enabled`は`false`のまま変更しない（既存のNVD CVE facts経路である`vulnerability_facts.py`のみを許可する既存状態を維持）。`cisa`は`cisa_kev`と別に`disabled`のまま維持する。
  4. Dark Reading（`dark_reading`）を`source_definitions.json`で`enabled: false`・`planned_phase: "保留"`へ変更し、Informa TechTarget Termsの確認結果を根拠とする`activation_condition`・`notes`（法的違反を確定したものではない旨を明記）を追加する。CrowdStrike・Cloudflareを含む他16 sourceの設定は変更しない。結果として総数17、enabled 12、disabled 5（`cisa`、`crowdstrike`、`cloudflare`、`dark_reading`、`nist_nvd`）となる。
  5. Gemini data-use gateとして`gemini_data_use_status`（`paid_verified`/`unpaid`/`unknown`）の概念を記録する。2026-07-29、repository ownerがGoogle AI StudioのAPI Keys画面で、Monomi Digest productionで使用するAPIキーが属する`security-digest` Google Cloud Projectにactive billingが関連付けられ「Tier 1・前払い」であることを確認したため、`gemini_data_use_status`は`paid_verified`として記録する。記録した非機密情報は「`security-digest` Project」「active billing確認」「Tier 1・前払い」「owner確認日2026-07-29」のみであり、APIキー名・APIキー末尾・APIキー値・Project ID・請求先アカウントID・課金額・画面のスクリーンショットは一切保存していない。`feed_summary`・`limited_feed_analysis` sourceの発行者由来descriptionは、この`paid_verified`確認により実質的な`metadata_only`扱いを解除できるが、取得元自身の規約条件は別途維持される。
  6. 2026-07-30発効のGoogle利用規約について、Google公式のTerms of Serviceアーカイブページで2026-07-30版が最新版として掲載されていることを確認し、repository ownerの通常ブラウザでも日本向け現行規約ページの表示が2026年版へ切り替わったことを確認した。一部取得環境で旧2024年版表示が一時的に残ったことは事実として記録するが、原因は特定しておらず、規約発効自体の確認を妨げるものではない。新規約は引き続きmachine-readable instructionsに反する自動収集を禁止する条件を含み、一般規約のみでAI公開要約が包括的に許諾されたとは断定しない。この確認にAPIキー・billing情報等は関係しない。`google_tag`・`mandiant`の`checked_at`を2026-07-30へ更新し、分類（`feed_summary`, conditional）・confidence（medium）は変更しない。
  7. `SECURITY_REQUIREMENTS.md`をVersion 1.5（Status Draft、As of 2026-07-30）へ更新し、非公式翻訳経路・`docs/translate_cache.json`の現行アーキテクチャ記載を削除し、稼働中のカスタムドメイン（`monomidigest.com`）を記録し、`SOURCE_USAGE_POLICY.md`への参照を追加し、取得元別policy enforcementを「Met」と記載しない（BL-032未実装）新規SR-044〜SR-046・GAP-016・GAP-017を追加する。SR-044は5モードを反映し、SR-045は`Met`（Gemini owner verification完了）、SR-046は`Partially met`（`nist_nvd`の`activation_condition`が空欄）とし、control mapping tallyを`Met 1 / Partial 2 / Not met 0 / Unverified 0`とする。既存のSR/GAP IDは変更・欠番にしない。既存Version 1.0〜1.4のApproved履歴は変更しない。
  8. `SECURITY_OPERATIONS.md`をVersion 1.1（Status Draft、As of 2026-07-30）へ更新し、`docs/translate_cache.json`関連の記載を削除し、取得元規約変更時の暫定停止手順・`limited_feed_analysis`降格手順を追加し、source停止・降格が過去`data/*.json`・`docs/archive/*.html`を遡って書き換えないことを明記する。
  9. `BACKLOG.md`（本エントリ）・`STATUS.md`のActive workへBL-031を追加する。`DECISIONS.md`へ新規Accepted decision（SD-030相当）は本PRでは追加しない（ユーザー受入前のため）。
  10. `SOURCE_USAGE_POLICY.md`の構造的contract、`source_definitions.json`のDark Reading/件数contract、両セキュリティ文書のVersion/Draft/現行アーキテクチャ記載に関するtestを追加する。
  11. Ready化・mergeは行わず、Draft PRのまま停止する。
- **依存関係:** [BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減)完了条件11で予約された後続チケット。後続Ticket: [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)（`content_usage_mode`等のfield実装とfetch.pyでの取得元別policy enforcement、output-similarity/quotation detection含む。本BACKLOG内へ正式登録済み、要件定義済み／未着手）、**BL-009**（About／出典／免責／訂正窓口）。
- **実装証跡:** `SOURCE_USAGE_POLICY.md`（Version 0.1、Status Draft、As of 2026-07-30）を新設し、目的・法的位置づけ・5 content usage mode定義（`structured_open`5／`feed_summary`4／`limited_feed_analysis`2／`metadata_only`2／`disabled_legal_review`4、計17、全17でallow_rich_content=false）・17 source監査表・Gemini data-use gate（`gemini_data_use_status: paid_verified`、2026-07-29 owner verification）・attribution要件（5モード対応）・output-similarity/quotation control要件（BL-032実装事項、機械的に強制可能な要件と、翻訳・意味的近接言い換え・代替要約評価等の自動完全検出を約束しない残余リスクを区別して記録）・recheck trigger・unknowns・BL-032/BL-009関係を記録した。`source_definitions.json`のDark Reading(`dark_reading`)を`enabled: false`・`planned_phase: "保留"`へ変更し、Informa TechTarget Terms(公式URL・確認日2026-07-29・具体的な禁止事項・「法的違反を確定したものではなく」の明記)を根拠とする`activation_condition`・`notes`を追加した。他16 source(CrowdStrike・Cloudflareを含む)の設定は変更していない。結果、総数17・enabled 12・disabled 5(`cisa`、`crowdstrike`、`cloudflare`、`dark_reading`、`nist_nvd`)。`SECURITY_REQUIREMENTS.md`をVersion 1.5(Status Draft、As of 2026-07-30)へ更新し、非公式翻訳経路・`docs/translate_cache.json`の現行アーキテクチャ記載を削除し、稼働中のカスタムドメイン(`monomidigest.com`)記録・`SOURCE_USAGE_POLICY.md`参照を追加し、新規SR-044〜SR-046（SR-044は5モード反映、SR-045は`Met`、SR-046は`Partially met`）・GAP-016・GAP-017（`Completed owner verification`）を追加した(既存SR/GAP IDは変更・欠番なし)。control mapping tallyは`Met 1 / Partial 2 / Not met 0 / Unverified 0`。GAP-011・GAP-012の記述も現状に合わせて更新した(GAP-012は`Resolved by BL-030`)。`SECURITY_OPERATIONS.md`をVersion 1.1(Status Draft、As of 2026-07-30)へ更新し、「Translation cache」節を「Source suspension」節へ置き換え、`limited_feed_analysis`降格手順を追加し、`docs/translate_cache.json`関連の記載を削除した。外部確認手順は、production・Gemini・大量取得を伴わない、承認済みread-only調査としての公式terms/robots.txt/公式Feed案内ページの確認(確認日・URL・確認事項の記録を伴う)を許容する契約とした。`BACKLOG.md`(本エントリ)・`STATUS.md`のActive workへBL-031を追加した。`STATUS.md`の最新daily JSON記録を2026-07-30 08:00 JST生成分(9記事、run.status success、AI success 9/fallback 0/failed 0、commit `8884786`)へ更新し、BL-030のscheduled production run評価を「本PR merge前に発生し13-source footerとなった」確定済みの時系列として記録した。`DECISIONS.md`は変更していない(SD-030は追加せず)。新規`test_source_usage_policy.py`、`test_source_definitions.py`への`Bl031SourceTermsAuditTest`、`test_security_requirements.py`への`Bl031SecurityRequirementsReconciliationTest`、`test_security_operations.py`への`Bl031SecurityOperationsReconciliationTest`を追加・更新し、既存testを現状へ整合させた。`fetch.py`／`daily_json.py`／`vulnerability_facts.py`／`data/*.json`／`docs/index.html`／`docs/archive/*.html`／`.github/workflows/`は変更していない。production・`workflow_dispatch`・Gemini API・外部URLアクセスは行っていない。
- **ユーザー受入証跡:** [PR #67](https://github.com/matkei31/security-digest/pull/67) accepted head `897fc9db365e890318fc694a7fbf9cd8eab65ae1` に対するChatGPTによる最終独立レビューで、実装・文書上のBlockerなし。CI: [run 30557479373](https://github.com/matkei31/security-digest/actions/runs/30557479373) success。full unittest: 1391 tests OK。ユーザーが本指示をClaude Codeへ送付することで、BL-031の受入、Ready化、通常のmerge-commit方式によるmergeを承認した。merge commit `61feb679fad6bd2252c58cd8acb4696294032629`。merge完了報告後、2026-07-31にユーザーが「ok進もう」と回答し、BL-031完了状態から次工程（`SOURCE_USAGE_POLICY.md`／`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`のApproved確定、SD-030追加、BL-032正式登録）へ進むことを承認した。
- **残作業:** BL-031自体の実装上の残作業はない。以下は独立した後続事項であり、BL-031の未完了作業ではない: [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)による`content_usage_mode`実装とfetch.py enforcement、BL-009によるAbout/出典/訂正窓口の実装、Cisco Talos規約適用範囲の確認(一般Cisco規約のbot条項がブログドメインへ適用されるか未解決。適用が確認された場合は`disabled_legal_review`を含め再評価する)、Krebs on Securityの公式terms確認(現状は`limited_feed_analysis`としてリスク受容運用)。
- **注記:** 本Ticketは監査・ポリシー文書の作成と既存2文書の整合化に限定される。取得元別のcontent usage mode enforcementをproduction code（`source_definitions.json`のfield追加、`fetch.py`の共通処理）へ反映することは、本Ticketでは実施しておらず、[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)として正式登録した。BL-031は2026-07-31時点で完了しており、監査・文書は3文書ともApproved、[SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032)としてユーザー承認済みである。

## BL-032 — 取得元別content usage policy enforcement

- **ID:** BL-032
- **タイトル:** 取得元別content usage policy enforcement
- **優先度:** P1
- **状態:** 完了／[PR #69](https://github.com/matkei31/security-digest/pull/69) merge済み
- **出所種別:** Approved [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) Version 0.1、[SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032)、[BL-031](BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)後続。
- **解釈:** [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)がBL-031で監査・提案した17 source分のcontent usage mode(3章)を、取得・Gemini入力・保存・daily JSON生成・Today's Brief集計・HTML表示の各段階でproduction共通処理として強制する。同文書3章・5章・6章・7章・10章を正本とし、以下を完了条件とする。本Ticketの登録自体はdocumentation-only PRとして行い、実装はこのPR自体では着手しない。
- **完了条件:**
  1. `source_definitions.json`の全17 sourceへcontent usage mode関連のpolicy fieldを追加し、[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) 4章の監査表(`proposed_mode`列を含む各列)と機械的に一致することをテストで固定する。
  2. `disabled_legal_review`分類のsourceは、現行同様network fetch対象外(`allow_network_fetch=false`相当)を強制し続ける。
  3. `metadata_only`分類のsourceは、原題・取得元・公開日時・original URLという最小メタデータの取得・保存・リンク掲載のみを行い、Geminiへの送信、AI評価(importance／urgency／financial_impact／recommended_actions等の生成)、AI翻訳(`title_ja`生成を含む)、publisher由来description／excerptの保存のいずれも行わない。
  4. `feed_summary`／`limited_feed_analysis`分類のsourceは、5章のGemini `paid_verified` gateを実装上も強制し、`gemini_data_use_status`が`unpaid`または`unknown`の場合は自動的に`metadata_only`相当の挙動へfallbackする。
  5. `feed_summary`／`limited_feed_analysis`分類のGemini description inputは最大1000文字・transient(永続保存しない)とする契約を実装・テストする。
  6. BL-032の実装で、[SD-002](DECISIONS.md#sd-002--use-feed-native-rich-content-without-additional-article-http-requests)に基づく現行の共通rich-content利用(`content:encoded`／Atom content等をfeed-native richとしてGemini入力へ用いる処理)を変更または無効化し、全17 sourceについてrich contentがGemini入力・保存・公開のいずれにも使用されないことを機械的に保証する。具体的な実装方式(共通処理の削除、無効化、またはsource-policyによる迂回／gateの追加等のいずれか)は、本PR(documentation-only)では決定・実装せず、BL-032の実装PRでコードとテストとともに決定する。
  7. 記事ページへの追加HTTP取得(scraping)を、いずれの分類でも行わない。
  8. `limited_feed_analysis`分類のsourceでは、原見出しの日本語翻訳タイトル(直訳に近いタイトル生成)を公開しない。
  9. output field(summary、financial_impact、recommended_actions等)ごとの文字数上限、原文との長い連続完全一致(verbatim long match)検出、機械的な違反を検出した場合の`metadata_only`相当表示への自動fallbackを実装する。
  10. attribution、original title、original URL、および[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md) 6章が定めるmode別の必要な限界注記(「詳細と正確性は元記事で確認」等)を、mode別に表示する。
  11. `metadata_only`分類の記事は、通常の記事一覧(AI評価済み記事)へ公開日時順で簡易リンクカードとして混在させるが、Today's Brief、importance／urgency／category集計、AI成功率の分母、fallback／failed／未判定のいずれにも含めない(意図的なpolicy非評価とAI処理の失敗を混同しない)。
  12. publisher由来のdescription／excerptを、`feed_summary`・`limited_feed_analysis`・`metadata_only`のいずれの分類についても、daily JSONへ永続保存しない。
  13. 既存の`data/*.json`・`docs/archive/*.html`を本Ticketの実装によって遡及変更しない。
  14. schema変更が必要な場合は、後方互換性と既存Archiveの再生成契約(過去日付分の再生成結果が変わらないこと)を明示し、テストで固定する。
  15. 具体的なthreshold(文字数上限、類似度スコア等の数値)は、BL-032の実装PRにおいてコード・fixture・テストとともに決定する。本登録PR(登録のみ)では数値を発明・記載しない。
  16. production、`workflow_dispatch`、実Gemini API呼び出し、通常の外部収集は、別途承認されたacceptance planなしに実行しない。
  17. [BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策)が対象とするAbout／出典ページ・免責・訂正窓口の包括的なUI整備は本Ticketのscope外とする。ただし、BL-032のenforcementに不可欠な記事カード内attribution表示・content usage mode区分の表示は本Ticketのscope内とする。
- **依存関係:** [BL-031](BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)(監査・方針決定)、[SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032)(policy承認)。後続で[BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策)のattribution UIと連携する。
- **実装証跡:** branch `feature/bl032-content-usage-enforcement`。`source_definitions.json`の全17 sourceへ`policy`オブジェクト(content_usage_mode／allow_network_fetch／allow_description／allow_rich_content／allow_ai_processing／allow_excerpt_storage／allow_public_summary／attribution_requirement／attribution_url／checked_at／confidence／unresolved_issue／recheck_trigger／official_evidence_url／evidence_type)と、トップレベル`gemini_data_use_status_record`(policy_version／gemini_data_use_status／checked_at／checked_by／verification_method／recorded_facts、APIキー等の機密情報は含まない)を追加した。分類・件数はSOURCE_USAGE_POLICY.md 4章と完全一致(structured_open 5／feed_summary 4／limited_feed_analysis 2／metadata_only 2／disabled_legal_review 4、計17)。`fetch.py`にfail-closedなpolicy validation(`_validate_source_policy`、`validate_content_usage_mode_distribution`)を追加した(暗黙のdefaultで補わない)。`daily_json.py`へcontent usage mode関連の一元管理された定数・関数(`CONTENT_USAGE_MODES`、`compute_effective_content_usage_mode`、`is_ai_eligible_content_usage_mode`、`OUTPUT_FIELD_MAX_CHARS`、`VERBATIM_LONG_MATCH_MIN_CHARS`、`TRANSIENT_INPUT_MAX_CHARS`、`detect_verbatim_long_match`、`validate_output_policy`、`DOWNGRADE_REASONS`)を追加した。`collect_recent()`／`collect_non_rss_items()`が収集直後に各itemへ`source_id`・`content_policy`(configured_mode／effective_mode／ai_eligible／downgrade_reason)を付与する(`annotate_item_content_policy`)。`enrich_with_ai()`はpolicy.ai_eligible=falseの記事でGeminiを一切呼ばず(metadata_only相当は0回)、feed_summary／limited_feed_analysisは最大1000文字のtransient inputに限定し、全17 sourceでrich content(`content:encoded`／Atom content)をpolicy(allow_rich_content、現状すべてfalse)に従って使用しない(SD-002の共通rich-content利用をpolicy gateで置き換えた)。limited_feed_analysisでは`title_ja`を機械的に無効化する。Gemini応答受領後に`validate_output_policy`で出力文字数上限・verbatim long-match・限界翻訳タイトル・attribution充足を検証し、違反時は当該記事をmetadata-only相当へ即時downgradeし(`downgrade_reason`を記録)、分析を公開しない。`vulnerability_facts`取得は`build_scoped_vulnerability_facts()`によりmetadata-only相当の記事を完全に対象外とし、feed_summary／limited_feed_analysisはpublisher descriptionをCVE抽出へ使わない(title／linkのみ)。daily JSON `SCHEMA_VERSION`を2へbumpし(`LEGACY_SCHEMA_VERSION=1`を維持)、`run.policy_excluded_count`／`run.ai_eligible_count`を新設して意図的なpolicy非評価とAI処理失敗を分離し、`compute_counts()`はpolicy-excluded記事を「未判定」にも加算しない。`validate_daily_digest()`はv1／v2を判別して検証する。`build_article_entry()`は`policy`サブオブジェクトを記録し、`allow_excerpt_storage`に従って`raw_excerpt`をgateする(structured_open以外は保存しない)。`compute_dashboard_counts()`・HTML生成(`build_html`)はpolicy-excluded記事をimportance／urgency／category集計・Today's Brief対象から除外しつつ掲載総数には含め、metadata-only相当の記事は簡易カード(original title／source／published date／original URL／簡潔な注記のみ)として表示し、mode別attribution(`render_source_attribution_html`、structured_openはsource定義の`attribution_requirement`をそのまま使用)を追加した。`digest_items_for_html()`はschema v2の`policy`を`content_policy`へ復元しつつ、schema v1(policyキーなし)はNoneのままとし、v1記事へmodeを推測して適用しない(既存v1 Archiveの表示・raw_excerpt・AI分析は遡及変更されない)。新規`test_content_usage_policy.py`(60件超)と既存test群(`test_source_definitions.py`、`test_daily_json.py`、`test_article_analysis.py`、`test_article_v5.py`、`test_feed_rich_content.py`、`test_feed_fetch_status.py`、`test_history_repair.py`、`test_custom_domain.py`、`test_vulnerability_facts_prompt.py`、`test_todays_brief.py`)を更新した。`data/*.json`・`docs/archive/*.html`・`.github/workflows/`・ARTICLE/BRIEF prompt本文・response schemaは変更していない。production・`workflow_dispatch`・実Gemini API・通常の外部収集は行っていない。具体的なthreshold値(title_ja 60文字、summary/financial_impact 200文字、reason 150文字、category_reason 100文字、recommended_actions各要素150文字、verbatim long-match最小40文字、transient input最大1000文字)は本PRでコード・テストとともに決定し、選定理由をコード内コメントおよびPR本文に記録した。

**独立レビューによる修正(2件のBlocker):** 初回実装では、(1) `feed_summary`／`limited_feed_analysis`でGemini呼出しが未実施・失敗(HTTP error・APIキー未設定を含む)だった場合に既存のraw_summary表示fallbackへ進んでしまい、publisher由来descriptionがHTMLへ表示され得た、(2) `structured_open`のattribution表示が、監査記述である`attribution_requirement`列の文字列をそのままUI文言として表示するだけで、実際のOGL v3リンク・実際の利用日・実際の免責文になっていなかった、という2件のBlockerが独立レビューで指摘された。これに対し、(1) `_downgrade_to_metadata_only_and_purge()`と新規`purge_publisher_text_for_ineligible_items()`を追加し、Gemini成功・fallback・failed・未試行(APIキー未設定)・policy違反のすべての経路で、後段(HTML生成・daily JSON構築・Today's Brief)より前にpublisher由来description(`summary`／`raw_summary`)と`rich_content`を確実に破棄するよう修正した(新規downgrade理由`analysis_unavailable`を追加、`structured_open`の既存fallbackは変更しない)。`build_html()`にも同じ制約を二重に保証するguardを追加した。(2) `render_structured_open_attribution_html()`を新設し、`fsa`/`nist`/`ncsc`/`cisa_kev`/`nist_nvd`のsource_idごとに実際の表示(NCSCの実OGL v3リンク、FSAの実利用日〔digest生成日、JST、YYYY-MM-DD〕、NVD/CISA KEVの実免責文)を組み立てるよう修正し、`attribution_ok`もそのmode/sourceの表示が実際に生成可能かを検証するよう強化した(未知のsource_idはmissing_attributionとしてmetadata-only相当へdowngradeする)。両修正について、新規regression test(`test_content_usage_policy.py`の`PublisherTextTransientPurgeTest`・`StructuredOpenRealAttributionRenderingTest`、計17件)を追加した。

**独立再レビューによる追加修正(round 2、2件):** 上記修正後の独立再レビューで、主要部分は改善済みだが以下の2点が未解消と判断された。(1) `feed_summary`／`limited_feed_analysis`でGemini結果がsuccessまたはfallbackとしてpolicy検証(`validate_output_policy`)を通過した場合、`item["ai_analysis"]`設定後もpublisher由来の`summary`／`raw_summary`／`rich_content`がitemに残ったままToday's Brief・HTML・daily JSON生成へ渡されていた(failed/not_attempted/policy違反経路はround 1で対応済みだったが、success/fallback経路は未対応だった)。(2) `_attribution_is_available()`がstructured_openについてsource_idが既知集合に含まれるかだけで判定しており、`ncsc`のOGL v3 URLが`safe_url()`を通らない場合でも`render_structured_open_attribution_html()`がリンクなし平文へfallbackし、この状態でも`attribution_ok=true`となって「実際のクリック可能なOGL v3リンク」という必須構成の欠如を検出できなかった。これに対し、(1) publisher由来本文(`summary`／`raw_summary`／`rich_content`)だけを消去する共通helper`_purge_publisher_text()`を新設し、`_downgrade_to_metadata_only_and_purge()`・`purge_publisher_text_for_ineligible_items()`双方の重複定義を解消したうえで、`enrich_with_ai()`がsuccess/fallbackでpolicy検証を通過した直後にもこのhelperを呼ぶよう修正した(`ai_analysis`／`ai_analysis_meta`は維持、`structured_open`は従来どおりpublisher本文を保持し既存fallbackも維持)。`purge_publisher_text_for_ineligible_items()`も、呼び出し順序に依存せず`raw_summary`を無条件に消去するよう修正した。(2) `ncsc`のOGL v3 URLを`source_definitions.json`の`ncsc.policy.attribution_url`へ設定し(既存field、新規正本を追加しない)、`render_structured_open_attribution_html()`はこのfieldを参照して`safe_url()`を通過した場合のみリンク化するよう修正した。新設した`_can_render_structured_open_attribution()`を、`attribution_ok`判定とHTML描画の両方が共通で参照するよう一元化し、URLが欠落・空・不正schemeの場合はリンクなし平文へfallbackせず`missing_attribution`としてmetadata-only相当へdowngradeするよう修正した(fail-closed)。両修正について、新規regression test(`PublisherTextTransientPurgeTest`へ8件、`StructuredOpenRealAttributionRenderingTest`へ6件、計14件)を追加した。full unittest: 1493 tests OK。

**独立レビューによる追加修正(round 3、2件):** PR全体の独立レビューで、次の2件が新たなBlockerと判断された。(1) 完了条件11は、metadata-only相当の記事をToday's Brief・fallback・failed・未判定のいずれにも含めない契約だが、`compose_extractive_brief()`が`compute_brief_trusted_context(items)`へ全記事(metadata-only相当を含む)を渡していたため、`published_total`/`unclassified`がmetadata-only相当を誤って加算していた。(2) `enrich_with_ai()`時の`missing_attribution` downgradeはfail-closedだったが、保存済みschema v2 daily JSONからArchiveを再生成する経路では、`digest_items_for_html()`が保存済みの`ai_analysis`と`policy.ai_eligible=true`をそのまま復元するため、NCSC attribution URLが後日欠落・不正になった場合でも、通常のAI分析カードがOGLリンク無しで再生成され得た。これに対し、(1) `select_brief_eligible_items()`を新設し、`compose_extractive_brief()`内の`select_brief_input_items`・`compute_brief_trusted_context`・`_build_brief_source_ids`・`sort_items_for_display`・`select_priority_items`のすべてが、同じfiltered(ai_eligible=trueのみ)item集合を参照するよう修正した。`build_todays_brief()`は`compose_extractive_brief()`が返す`context`をそのまま使い、二重計算を廃止した。`is_article_evaluated()`・`select_important_items()`にも`item_is_ai_eligible()`チェックを追加し、Archive再生成時のfail-closed downgrade後も派生表示(優先確認・重要・優先事項)がmetadata-only相当を一貫して除外するようにした。(2) `daily_json.build_article_entry()`が、`ncsc`のstructured_open記事について生成時に実際に使用可能だった安全なURLを`policy.attribution_url`へsnapshotとして保存し、`daily_json.validate_daily_digest()`がschema v2でこのsnapshotの存在・安全性を必須検証するよう修正した。`fetch.py`の`digest_items_for_html()`はこのsnapshotだけを`content_policy`へ復元し、`render_structured_open_attribution_html()`はArchive再生成時に現在の`source_definitions.json`を参照せずsnapshotだけを使う(生成後にsource policyが変更されても既存Archiveの再生成結果は変わらない)。改変・破損によりsnapshotが欠落・不正なdaily JSONを直接`digest_items_for_html()`へ渡した場合は、記事カード・Dashboard集計・優先確認・items由来の重要事項をmetadata-only相当へdowngradeする(`downgrade_reason: archive_attribution_snapshot_invalid`)。**この時点では、保存済みBrief(overview/discussion_points/check_items)自体はこのdowngradeの対象外であり、round 4で指摘・修正するまでこの点が未解消だった(下記参照)。** schema v1・schema versionそのもの(引き続き2)・SD-002・prompt versionは変更していない。両修正について、新規regression test(`TodaysBriefEligibilityExclusionTest`へ5件、`ArchiveAttributionSnapshotTest`へ5件、計10件)を追加した。full unittest: 1503 tests OK。

**独立レビューによる追加修正(round 4、2件):** round 3の修正後、Brief eligibility側は解消済みと判断されたが、Archive attribution snapshot対応について次の2件のBlockerが指摘された。(1) `generate_archive_outputs()`は各daily JSONについて`load_daily_digest()`(JSON形式・トップレベル型・digest_date・ファイル名程度の緩い検証)だけを呼び、`daily_json.validate_daily_digest()`を実行していなかった。そのため、NCSC attribution_url snapshotが欠落・不正なschema v2 digestもArchive生成へ進んでしまい、`digest_items_for_html()`のitem単位downgradeは記事カード・Dashboard・優先確認・items由来の重要事項は除外できても、`build_daily_archive_html()`が独立に読む保存済みBrief(overview・discussion_points・check_items)には及ばなかった。(2) `daily_json._is_safe_http_scheme_url()`(旧名)は、schemeプレフィックスが`http(s)://`で始まるかとASCII制御文字の有無しか見ておらず、`https://`・`https:///missing-host`・`http://?query`のようなhostを持たないscheme-only値も安全なURLとして通過させてしまっていた。これに対し、(1) `generate_archive_outputs()`の`load_daily_digest()`直後に`daily_json.validate_daily_digest(digest)`を追加し、検証に失敗したdigestは既存の警告・skip経路(日別Archive HTML・Archive summary・index entryのいずれも生成・更新しない)へ進めるよう修正した。`build_daily_archive_html()`のdocstringへ「検証済みdigestを受け取る契約」であることを明記した。これにより、保存済みBriefも含めた完全な保護は、`digest_items_for_html()`側のitem単位downgrade(検証を経由しない直接呼び出しに対する二次的backstop)ではなく、**このvalidationによるArchive生成対象からの除外そのもの**によって担保する設計へ修正した(前述のround 3の記述を訂正)。この変更に伴い、`test_archive.py`の`make_digest()`ヘルパーへ欠落していた`facts`fieldを追加し、`test_custom_domain.py`の`make_digest()`ヘルパーの`run`/`counts`をitems件数(常に0件)と一致させるよう修正した(これらは本来のvalidate_daily_digest契約に元々違反していた、Archive生成が緩い検証しか行っていなかったために露見していなかった既存fixtureの不備であり、production側の検証仕様を緩めたものではない)。(2) `daily_json._is_safe_http_scheme_url()`を`daily_json.is_safe_attribution_url()`へ改名したうえで`urllib.parse.urlsplit()`ベースへ書き換え、scheme(http/https)・netloc・hostnameがすべて存在することを必須とするよう修正した(記事リンク全般に使う`fetch.safe_url()`の仕様はこのTicketの対象外として変更していない)。`fetch.py`の`_resolve_ncsc_ogl_url()`・`digest_items_for_html()`の防御的checkの両方をこの新しい検証関数経由に統一した。両修正について、新規regression test(`test_archive.py`の`ArchiveGenerationFullValidationTest`へ5件、`test_content_usage_policy.py`の`AttributionUrlValidationTest`へ10件、計15件)を追加した。full unittest: 1518 tests OK。**round 4のこの`validate_daily_digest()`呼び出し自体が新たな後方互換性regressionを含んでいたため、round 5で修正した(下記参照)。**

**独立レビューによる追加修正(round 5、2件):** round 4の修正意図(Archive生成前full validation、attribution snapshot URLのscheme/netloc/hostname検証)自体は正しく実装されていたが、次の2件のBlockerが指摘された。(1) round 4で追加した`generate_archive_outputs()`の`daily_json.validate_daily_digest()`呼び出しは、現行の閾値(例: `BRIEF_MAX_CHECK_ITEMS=2`)をschema v1(レガシー)の実在ファイルへも遡及適用してしまい、実在する`data/2026-07-14.json`(schema_version=1、生成当時は正当だった4件の`brief.check_items`を保存)がArchive生成対象から誤って脱落する後方互換性破壊を引き起こしていた。round 4で追加した新規schema v1回帰テストは現行の上限内に収まるsynthetic fixtureしか使っておらず、この破壊を検出できていなかった。(2) invalid digestは`continue`でskipするだけで、既存のstale日別Archive HTML(過去の有効な生成で既に存在するファイル)を削除せず、`update_index_archive_paths()`もglobal `fetch.DOCS_DIR`に依存していたため、staleなHTMLが直接アクセス可能なまま残り、「Archive生成対象から完全に除外した」という説明と実態が一致しない状態だった。これに対し、(1) `daily_json.validate_daily_digest_for_archive_read()`を新設し、schema v2は保存前と完全に同じstrict validation(`validate_daily_digest()`、現行生成物の検証は緩めない)をそのまま適用しつつ、schema v1は現行の閾値・enumを遡及適用しない最小限の構造検証(トップレベル型・digest_date形式・items配列・brief型)だけを行うよう修正し、`generate_archive_outputs()`をこの新関数経由へ切り替えた。この変更に伴い判明した、`test_archive.py`/`test_custom_domain.py`の`make_digest()`ヘルパー自体の既存不備(前回のBlockerで修正済み)は変更していない。(2) `generate_archive_outputs()`でvalid/invalidな日付を明示的に分け、invalidな日付に対応する既存の日別Archive HTMLがあれば(その日付と厳密に一致するファイルだけを対象に)削除するよう修正した。`update_index_archive_paths()`へ`docs_dir`引数を追加し、global `DOCS_DIR`依存を解消した(既存の「ファイルが存在しない場合はarchive_pathをnullにする」ロジックが、削除後は正しく発火する)。invalid digestのindexエントリ自体は削除せず、`archive_path:null`とする(既存index契約に合わせる)。両修正について、新規regression test(`test_archive.py`の`RealSchemaV1DataArchiveEligibilityTest`へ2件〔実在する全`data/*.json`のread-only走査を含む〕、`ArchiveInvalidDigestCleanupTest`へ2件、計4件)を追加した。full unittest: 1522 tests OK。

**独立レビューによる追加修正(round 6、1件):** round 5で`validate_daily_digest_for_archive_read()`のschema v1分岐は「トップレベル型・digest_date形式・items配列・brief型」という最小限の構造検証だけを行っていたが、この検証は`run`/`counts`/`brief`各fieldの**値の型**までは保証しておらず、`run`自体が文字列、`run.total_items`が文字列／bool／負数、`counts`自体が文字列、`counts.importance`が文字列、`counts.importance["高"]`が文字列／bool／負数、`brief.overview`が非文字列、`brief.check_items`が非配列またはlist内に非文字列を含む、といった型不正なschema v1値がvalidatorを通過し得た。これらは`archive_summary_from_digest()`(`run.get("total_items")`への`int()`適用、`counts.get("importance").get("高")`への`dict`アクセス)や`brief_for_html_from_digest()`で`AttributeError`/`ValueError`/`TypeError`を送出し得るため、1件のmalformedなschema v1 daily JSONが混在するだけで、その日付だけをskipする設計に反して`generate_archive_outputs()`全体が未捕捉例外で停止し、stale HTML削除・index更新も完了しないおそれがあった。これに対し、`validate_daily_digest_for_archive_read()`のschema v1分岐へ、現行の閾値・enum・件数上限を遡及適用しない範囲で、下流処理が前提とする最低限の型・構造検証を追加した: (1) `digest_date`は`YYYY-MM-DD`形式に加え`datetime.date.fromisoformat()`で実在する暦日であることを検証する(`2026-99-99`・`2026-02-30`等を拒否)。(2) `run`は欠落/nullなら既存fallbackへ委ね、存在する場合はdictであること、`total_items`は存在する場合bool以外の0以上intであることを検証する。(3) `counts`は欠落/nullなら既存fallbackへ委ね、存在する場合はdictであること、`counts.importance`は存在する場合dictであること、`counts.importance["高"]`は存在する場合bool以外の0以上intであることを検証する。(4) `brief`は`overview`が欠落/null/str、`important_highlights`/`discussion_points`/`check_items`が欠落/null/list(list要素はすべてstr)であることを検証する。現行の件数整合性・enum値・件数上限・field完全性はschema v1へ遡及適用しない(`data/2026-07-14.json`の4件の`check_items`は引き続き許容する)。これらの不正値は`DailyJsonError`として検出されるため、`generate_archive_outputs()`の既存skip経路(その日付だけskip、stale Archive HTML削除、Archive一覧除外、`data/index.json`の当該`archive_path`をnull化)がそのまま機能し、他の正常なschema v1／v2 digestの生成は継続する。新規regression test(`test_archive.py`の`ArchiveReadValidatorTypeContractTest`へ2件〔schema v1想定14種の型不正値をtable-driven/subTestで検証〕、`ArchiveInvalidTypeCleanupLifecycleTest`へ1件〔同14種を、正常生成→改変→再生成→該当日のみskip・stale削除・index null化・他日付維持・全体停止しないことをlifecycleとして検証〕、計3件)を追加した。full unittest: 1525 tests OK。round 6のこの修正は独立再確認済みである。

**独立レビューによる追加修正(round 7、1件):** round 6でschema v1 Archive読込validatorの型・構造検証を強化したが、同じschema v1互換性契約を適用すべきもう1つの呼出箇所が未対応のまま残っていた。`generate_archive_outputs()`はschema-awareな`daily_json.validate_daily_digest_for_archive_read()`を使うが、トップページのArchive navigation用に公開済み日付を取得する`load_validated_published_digest_dates()`は、保存直前用のstrict validation(`daily_json.validate_daily_digest()`、schema v1へも現行のBrief件数上限・enum・field契約を遡及適用する)を依然として使っていた。実在する`data/2026-07-14.json`(schema v1、生成当時は正当だった4件の`brief.check_items`)は、`validate_daily_digest_for_archive_read()`では有効だが`validate_daily_digest()`では現行上限超過として無効となるため、日別Archive HTMLと`data/index.json`の`archive_path`が正常に存在していても、`main()`が`render_top_archive_nav_html()`へ渡すトップページの「前回のダイジェスト」候補からは誤って除外されていた(単なる未使用helperの不備ではなく、実際にトップページ生成経路で使われている)。これに対し、`load_validated_published_digest_dates()`のdaily JSON検証を`daily_json.validate_daily_digest_for_archive_read()`へ切り替えた。既存の他条件(`data/index.json`自体が有効、index entryがdict、`digest_date`が実在する正規化済み日付、`archive_path == docs/archive/{date}.html`、対応するArchive HTMLが実在、daily JSONファイル名と内部`digest_date`が一致)は変更していない。`build_daily_archive_html()`・`load_validated_published_digest_dates()`のdocstringを、実際の契約(`validate_daily_digest_for_archive_read()`使用、schema v2はstrict validation、schema v1は後方互換Archive読込validation)に合わせて修正した。新規regression test(`test_archive.py`の`PublishedDigestDatesSchemaCompatibilityTest`へ5件〔実在する`data/2026-07-14.json`の4件check_itemsが公開済み日付として維持されること、round 6の代表的な型不正3種(`run.total_items`/`counts.importance["高"]`/`brief.check_items`)を持つschema v1が除外されること、NCSC attribution snapshot欠落のschema v2が除外されること、正常なschema v2は維持されること、schema v1の旧形式digestだけが直前の公開日であるケースで`render_top_archive_nav_html()`が正しくリンクを生成すること〕)を追加した。既存の`TopPageArchiveLinkTest`(archive HTML欠落・archive_path不一致・filename/digest_date不一致・不正なindex・future/不正日付を検証する既存テストを含む)は変更せず、全件引き続き成功する。full unittest: 1530 tests OK。**round 7のこの修正について独立再確認が完了し、新たなBlockerは指摘されなかった。**

**受入:** 独立レビュー7ラウンド(round 1〜4は各2件・round 5は2件・round 6は1件・round 7は1件)で指摘された合計12件のBlockerは、すべて修正・独立再確認まで完了した。round 1〜6の11件は各round内で独立再確認済み、round 7の1件(`load_validated_published_digest_dates()`のschema v1互換性)も本受入確認で独立再確認済みである。ユーザーが本受入指示をClaude Codeへ送付することで、round 7修正の独立再確認完了・新規Blockerなしを確認したうえで、PR #69(head `1c169339dff8b98213bf389272ffe0d9c6fd5853`、CI success、mergeability CLEAN、unresolved review threads 0)の受入、Ready化、通常のmerge-commit方式によるmergeを承認した。
- **ユーザー受入証跡:** [PR #69](https://github.com/matkei31/security-digest/pull/69)(branch `feature/bl032-content-usage-enforcement`、accepted head `0f8286a558f514e37ac153cdf636e35b9c3c4aff`)に対する独立レビュー7ラウンド・合計12件のBlockerがすべて修正・独立再確認済みであることを、ユーザーが確認した(「round 7修正について、独立再確認が完了しました。新たなBlockerはなく、受入可能です」「独立レビュー7ラウンドで指摘された合計12件のBlockerは、すべて修正・独立再確認まで完了しました」)。受入記録commit `0f8286a558f514e37ac153cdf636e35b9c3c4aff`。CI: [run 30664641629](https://github.com/matkei31/security-digest/actions/runs/30664641629) success。full unittest: 1530 tests OK。mergeability CLEAN、unresolved review threads 0。ユーザーが本指示をClaude Codeへ送付することで、BL-032の受入、PR #69のReady化、通常のmerge-commit方式によるmergeを承認した。PR #69はReady化のうえ通常のmerge-commit方式でmergeされ、merge commit `cd5e6ec5d08542d6eb76a134944d1729e5d5f4dd`として`origin/main`へ反映された。
- **残作業:** 上記完了条件1〜17は本PRで実装済み(具体的なthreshold値も本PRで決定済み)。独立レビュー7ラウンド・合計12件のBlockerは、いずれも修正・独立再確認まで完了し、PR #69はReady化・merge済みである。BL-032の完了条件としての残作業はない。PR #69／PR #70 merge後最初の通常scheduled production run(commit `982a261b15afd695486fffe50fadf9209cc0faa5`)により、schema v2 enforcementが実運用で正しく稼働することのoperational observationは既に成功済みである(schema_version `2`、run.status `success`を確認済み。詳細は[BL-033](BACKLOG.md#bl-033--statusmdの動的公開実績を正本へ委譲する)・[STATUS.md](STATUS.md#5-recently-completed-work)を参照)。policy enforcementの実運用上の問題は確認されなかった。この確認はBL-032を再オープンするものではなく、今後問題が発見された場合は別Ticketで扱う。BL-009の包括的About／訂正窓口UI整備は引き続きscope外・別Ticket。
- **注記:** 本PR(branch `feature/bl032-content-usage-enforcement`、[PR #69](https://github.com/matkei31/security-digest/pull/69))は`fetch.py`・`daily_json.py`・`source_definitions.json`・関連static contract testを変更する実装PRであり、merge済みである。`data/*.json`・`docs/archive/*.html`・`.github/workflows/`・ARTICLE/BRIEF prompt本文・response schema・GitHub設定は変更していない。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集(RSS/API/記事ページ/robots.txt等)は、本PRの実装・レビュー・merge作業の一環としては行っていない(merge契機の通常のGitHub Pages自動デプロイのみが発生し、成功した)。

## BL-033 — STATUS.mdの動的公開実績を正本へ委譲する

- **ID:** BL-033
- **タイトル:** STATUS.mdの動的公開実績を正本へ委譲する
- **優先度:** P2
- **状態:** 完了／ユーザー受入済み
- **出所種別:** ユーザー確認済み要約
- **ユーザー原文:** 「ok。進めよう」(方針・着手承認。実装後の最終受入は別途記録、下記ユーザー受入証跡参照)
- **原文の意味:** STATUS.mdの最新公開実績を固定値で持たず、`data/index.json`と最新daily JSONを正本とする方針で作業を進めることへの承認。この時点では実装後の最終受入ではなかった。
- **解釈:** [PR #70](https://github.com/matkei31/security-digest/pull/70)でSTATUS.mdの「Latest published daily JSON」等を2026-07-31 runの固定値へ更新した直後、次の通常scheduled runで`data/2026-08-01.json`(schema v2)が生成され、STATUS.mdが再び古くなった。これはBL-032の実装不具合ではなく、日次で変化する動的値(最新公開日時・記事数・AI件数・production commit・最新公開schema)を手動管理文書と固定値testへ複製していた管理設計そのものの問題である。本Ticketは次の設計変更を行う。
  - STATUS.mdのCurrent versionsから、日次で変化する最新公開日時・記事数・AI件数・production commit・最新公開schemaの固定値複製を廃止する。
  - `data/index.json`と、それが参照するdaily JSONを最新公開実績の正本とする。
  - production commitはGit履歴を正本とする。
  - `main`上のcurrent generator schema、ARTICLE prompt、BRIEF contract、BRIEF modelなど、明示的な設計変更時だけ変わる安定したcontractはSTATUS.mdに引き続き記載する。
  - 過去runの受入証跡・初回稼働証跡([BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減)・[BL-031](BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)・[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)等)は削除せず、歴史的記録として保持する。
  - [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)の初回schema v2 scheduled run(commit `982a261b15afd695486fffe50fadf9209cc0faa5`)によるoperational observationの成功を、BL-032のRecently completed記録へ固定証跡として追加する。
  - 毎日のscheduled runごとにSTATUS.mdや固定値testを更新する運用そのものを廃止する。
- **完了条件:**
  1. STATUS.mdのCurrent versionsに、最新公開runの日時・記事数・AI件数・commit・最新公開schemaの固定値が存在しない。
  2. STATUS.mdが`data/index.json`と参照先daily JSONを最新公開実績の正本として明記する。
  3. production commitの確認先がGit履歴であることを明記する。
  4. current generator schema、ARTICLE prompt、BRIEF composition contract、BRIEF model等の安定したcontractは維持する。
  5. STATUS.mdの「As of」は「文書自体の最終更新日」であり、「最新production run日」ではないと明記する。
  6. BL-032の最初のschema v2 scheduled runである`982a261`の成功を、歴史的なoperational observationとして記録する。
  7. testが特定の最新公開日、記事数、production commit、最新公開schemaを要求しない。
  8. testが`data/index.json`／参照先daily JSONへの正本委譲を検査する。
  9. 過去の[BL-030](BACKLOG.md#bl-030--取得元翻訳経路の緊急リスク低減)／[BL-031](BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)／[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)等の歴史的run証跡は削除しない。
  10. runtime code、data、Archive、workflow、prompt、schema定数を変更しない。
  11. production、`workflow_dispatch`、実Gemini API呼び出し、通常の外部収集を実行しない。
  12. ユーザーによる実装後の受入までは完了扱いにしない。
- **依存関係:** [BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)(実装・PR #69・post-merge closeout PR #70がいずれもmerge済みであることが前提)。[SD-031](DECISIONS.md#sd-031--delegate-volatile-publication-state-to-generated-data-instead-of-duplicating-it-in-statusmd)が本Ticketの設計判断を記録する。
- **実装証跡:** branch `docs/bl033-status-source-of-truth`。STATUS.mdの「Current versions」テーブルから`Latest published daily JSON`・`Latest published daily JSON schema`という2つのvolatile rowを削除し、`Latest publication source of truth`という1行(`data/index.json`の最新entryと、そのentryが参照する`data/YYYY-MM-DD.json`を正本とし、production commitは対象ファイルのGit履歴を参照する旨)へ置き換えた。直後の説明段落を、日次snapshotの重複複製ではなく正本分担(generator contractはmainのコード、latest publicationは`data/index.json`と参照先daily JSON、production commitはGit履歴)を説明する内容へ全面的に書き換えた。「As of」を2026-08-01へ更新し、文書自体の最終更新日であり最新production run日ではないことを明記した。`## Active work`へBL-033を追加し、`## 5. Recently completed work`のBL-032 entryへ、PR #69/PR #70 merge後最初の通常scheduled production run(commit `982a261b15afd695486fffe50fadf9209cc0faa5`、`data/2026-08-01.json`、schema v2、run.status success、total_items 5、ai_attempted 4/ai_success 4/ai_fallback 0/ai_failed 0、policy_excluded_count 1、ai_eligible_count 4、Microsoft Securityのmetadata_only itemがAI非対象(`analysis.status: not_attempted`)として保存、The Hacker Newsのlimited_feed_analysis itemがAI対象として処理)が成功したことをoperational observationとして追記した(いずれも`data/2026-08-01.json`・`data/index.json`のread-only確認による実測値)。`## 7. Next candidates`でBL-033をcurrent Active work itemとして記載した。`test_custom_domain.py`の`Bl007ClosureRecordTest`から、固定の最新公開日・記事数・source数を要求していた2件のtest(`test_status_latest_published_daily_json_reflects_the_latest_run`・`test_status_current_versions_paragraph_reflects_the_latest_run`)を、新設した`StatusSourceOfTruthTest`(新規`test_status.py`)へ正本委譲契約の検査として置き換えた。`test_source_definitions.py`・`test_security_requirements.py`のActive work／Recently completed／Next candidates検査を、BL-033追加とBL-032 operational observation追記に合わせて更新した(BL-032固有のcomplete契約・BL-031/BL-030との一般語区別は維持)。SD-031の一意性・Date/Status/Decision/Evidence記録を検査する新規`Sd031DecisionTest`を`test_status.py`へ追加した。`test_fetch.py`のBL/SD ID網羅性チェックをBL-033・SD-031追加に合わせてBL-001〜033・SD-001〜031へ更新した。`fetch.py`・`daily_json.py`・`source_definitions.json`・`vulnerability_facts.py`・`SOURCE_USAGE_POLICY.md`・`SECURITY_REQUIREMENTS.md`・`SECURITY_OPERATIONS.md`・ARTICLE/BRIEF prompt・response schema・schema定数・`data/*.json`・`docs/index.html`・`docs/archive/*.html`・`docs/archive/index.html`・`.github/workflows/`は変更していない。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集は行っていない。
- **ユーザー受入証跡:** [PR #71](https://github.com/matkei31/security-digest/pull/71)(branch `docs/bl033-status-source-of-truth`、accepted implementation head `82ae62af3d522a7095748b591476566ac21b9036`)に対する独立レビューround 1〜3で指摘されたBlockerがすべて修正・独立再確認済みであることを、ユーザーが確認した(「PR #71の実装について、独立レビューround 1〜3で指摘されたBlockerはすべて修正・独立再確認されました。最新head 82ae62af3d522a7095748b591476566ac21b9036について、新たなBlockerはなく、BL-033の実装は受入可能です」)。CI: [run 30690090491](https://github.com/matkei31/security-digest/actions/runs/30690090491) success。full unittest: 1555 tests OK。focused: 520 tests OK。unresolved review threads: 0。PR全体のchanged files: 8ファイル。runtime code・data・Archive・workflow差分: ゼロ。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集: 未実行。ユーザーが本指示をClaude Codeへ送付することで、BL-033の実装後受入と、この受入記録commitの作成を承認した。受入記録commit自体の独立再確認のため、PR #71はDraftのまま維持し、今回のReady化・mergeは行わない。
- **残作業:** BL-033の設計・実装・test・ユーザー受入について残作業はない。[PR #71](https://github.com/matkei31/security-digest/pull/71)のReady化・merge等のdelivery lifecycleはGitHub上のPR状態を正本とし、BL-033の残作業としては管理しない――delivery lifecycleの状態(Draft／Ready／merge待ち／merge済みのいずれであっても)は、BL-033の機能的・設計上の完了状態を変更しない。merge後に別のpost-merge closeout PRは不要な最終状態を、本Ticketの記録として既に準備済みである。
- **注記:** 本Ticketはdocumentation／management-onlyであり、`data/*.json`・`docs/archive/*.html`・`.github/workflows/`・runtime code(`fetch.py`・`daily_json.py`・`source_definitions.json`・`vulnerability_facts.py`)への変更は行っていない。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集(RSS/API/記事ページ/robots.txt等)は行っていない。[PR #71](https://github.com/matkei31/security-digest/pull/71)のReady化・merge等のPR delivery lifecycleはGitHubを正本とする(本注記では追跡しない)。BL-033はユーザー受入済みであり、機能的・設計上の残作業はない。

## BL-034 — 閲覧計測基盤

- **ID:** BL-034
- **タイトル:** 閲覧計測基盤
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「閲覧数わかるようにするのは？」「訪問数をカウントするにしては過剰じゃない？妥当？ 費用はかからない？Cloudflareじゃなくてxサーバーを使ってるけど問題ない？」「ok。進めよう」
- **出所:** 2026-08-03 プロジェクト会話。[BL-009](#bl-009--seoと閲覧者増加策)着手前調査として行った、Monomi Digestの閲覧数計測基盤に関する検討。
- **ユーザー確認済み要約:** [BL-009](#bl-009--seoと閲覧者増加策)(SEOと閲覧者増加策)の残作業のうち「成果の測定」に相当する、サイト全体の閲覧計測を最初に検討し、独立Ticketとして分離する。SEOや施策の効果を測るには、施策前の基準値が必要であるため、[BL-009](#bl-009--seoと閲覧者増加策)本体(読者層定義・技術/コンテンツSEO監査・施策優先順位付け・robots.txt/sitemap/canonical/OG/favicon/About全体・コンテンツSEO)より先行して着手する。
- **解釈:** [BL-009](#bl-009--seoと閲覧者増加策)をumbrella Ticketとして維持し、閲覧計測基盤を新規連番Ticket(BL-034)として分離する。独立調査の結果、次の方針をユーザーが承認した。
  - Cloudflare Web Analyticsを、サイト全体の軽量な閲覧計測として採用する(Page views・Visits・参照元・国・デバイス種別・時系列を把握する基礎計測。unique人数の厳密な把握、UTM campaign計測、custom eventsには向かない)。
  - Google Search Consoleも、Google検索での表示・クリック・query確認のため併用する(サイト全体の閲覧数とは測定対象が異なる別系統)。
  - XServerのDNS管理・ネームサーバーは変更せず、CloudflareへDNSやproxyを移行しない(Cloudflare Web Analyticsのmanual/非proxy方式を使う)。
  - GA4・Umami・Plausible・Google Tag Managerは現時点では導入しない。
  - 長大な独立privacy policyは作らず、footerへ短いアクセス解析説明(利用サービス名・目的・Cookie/localStorage不使用というCloudflare側の説明・取得できる集計情報・送信先)を掲載する。法的な断定はしない。
  - 大規模なCSP整備は行わず、third-party script追加に伴う必要最小限のsecurity確認のみ[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)へ記録する。
  - robots.txt、sitemap、canonical、OG、favicon、About全体、コンテンツSEOは本Ticketのscopeに含めない([BL-009](#bl-009--seoと閲覧者増加策)配下の後続Ticket候補として残す)。
- **完了条件:**
  1. Cloudflare Web Analyticsのmanual JavaScript beacon(DNS/proxy移行なし)を、トップページ・Archive一覧・全日別Archiveへ追加する。
  2. footerへ、利用サービス名・目的・Cookie/localStorage不使用というCloudflare側の説明・取得できる集計情報・送信先を短く開示する記述を追加する。断定的な法的評価はしない。
  3. GA4・Umami・Plausible・Google Tag Managerは追加しない。
  4. 大規模なCSP導入は行わず、third-party script追加に伴う必要最小限のsecurity再評価を[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md)へ記録する。
  5. robots.txt・sitemap・canonical・OG・favicon・About全体・コンテンツSEOは変更・追加しない。
  6. XServerのDNS・ネームサーバー・既存のGitHub Pages所有権確認用TXTは変更しない。
  7. Google Search ConsoleのDomain property登録・DNS TXT verificationはユーザーがブラウザで行う外部作業とし、その完了は本Ticketのrepository実装のblockerにしない。
  8. `data/*.json`、ARTICLE/BRIEF prompt・response schema・schema定数、`.github/workflows/`は変更しない。
  9. production、`workflow_dispatch`、実Gemini API呼び出し、通常の外部収集は実行しない。
  10. 関連test追加とfull unittest成功。
  11. **merge前(round 1レビューで訂正):** 実装・文書の独立レビュー、full unittest成功、`git diff --check`成功、PC 1280px／390pxでの表示確認を完了し、ユーザーが表示・scopeを受入れ、Ready化・mergeを明示的に承認する。Cloudflare dashboardでのデータ受信確認はこの時点では要求しない(公開前のため受信しようがない)。
  12. **merge後:** GitHub Pagesへの公開反映を確認し、`monomidigest.com`の公開HTML上でbeaconが正確に1件存在することを確認したうえで、Cloudflare dashboardでの実データ受信確認、Google Search Console verification結果の確認、計測開始日の記録を行い、4週間程度の基準値取得期間を開始する。
- **依存関係:** [BL-009](#bl-009--seoと閲覧者増加策)(umbrella Ticket、本Ticketの完了後も別スコープ・未着手のまま残る)。[BL-006](#bl-006--monomi-digestへのブランド変更)・[BL-007](#bl-007--monomidigestcomへの移行)・[BL-002](#bl-002--記事カードの楕円バッジ多用を見直す)〜[BL-004](#bl-004--fable-5によるuiレビューとui設計書)・[BL-028](#bl-028--ダイジェストナビゲーションの配置を再設計する)〜[BL-033](#bl-033--statusmdの動的公開実績を正本へ委譲する)(いずれも完了済み、着手前提条件)。[SD-032](DECISIONS.md#sd-032--adopt-cloudflare-web-analytics-and-google-search-console-for-bl-034)が採用方針を記録する。
- **実装証跡:** branch `feature/bl034-cloudflare-web-analytics`。`fetch.py`に`CLOUDFLARE_WEB_ANALYTICS_BEACON_TOKEN`定数(Cloudflareのmanual setupが発行した、公開HTMLへ埋め込む前提の識別子であり、account password・API secret等の秘密情報ではない)、`render_cloudflare_web_analytics_html()`(Cloudflare発行のmanual beacon snippetをそのまま出力)、`render_analytics_footer_html()`(短いアクセス解析説明の`<footer>`)を追加し、`build_html()`(トップページ・全日別Archiveで共用)と`build_archive_index_html()`の`</body>`直前へ配線した(CSS `.site-footer`/`.analytics-notice`を両テンプレートへ追加)。既存の`docs/index.html`・`docs/archive/index.html`・日別Archive HTML23件を、外部HTTP/Gemini/RSS/NVD/CISA KEVを呼ばず、既存daily JSON(`generate_archive_outputs()`・`digest_items_for_html()`/`brief_for_html_from_digest()`)のみを用いてoffline再生成した(`data/*.json`・`docs/CNAME`は無変更、`git diff`で確認)。inline JS・onclick等が一切無いことを検証していた既存test(`test_fetch.py` `test_no_javascript_is_emitted_anywhere_in_the_page`)を、Cloudflare beacon 1個のみを許容する契約(`test_only_the_documented_cloudflare_beacon_script_is_emitted`)へ更新し、HTMLコメントが皆無であることを検証していた既存test(`test_fetch.py` `test_no_html_comment_carries_brief_content`、`test_archive.py` `test_internal_and_external_links_are_safe`)を、Cloudflareの静的な2個のdocumentedコメントのみを許容する契約へ更新した。新規`Bl034CloudflareWebAnalyticsTest`(`test_archive.py`)で、トップページ・日別Archive・Archive一覧それぞれにbeacon・footer開示が1回だけ出現すること、footer開示が断定的な法的評価をしていないことを検証した。full unittest 1563 tests OK。`SECURITY_REQUIREMENTS.md`をVersion 1.7(Draft、pending user acceptance)へ更新し、新規SR-047(third-party browser scripts and client-side analytics)・新規GAP-018(この追加自体をDraft実装として記録)・section 9のMandatory CSP行・section 10のre-evaluation triggerへBL-034を参照する補足を追加した。`test_security_requirements.py`をVersion 1.7・SR-047・GAP-018に合わせて更新した。`source_definitions.json`・`daily_json.py`・`vulnerability_facts.py`・ARTICLE/BRIEF prompt・response schema・schema定数・`.github/workflows/`・`SECURITY_OPERATIONS.md`・`SOURCE_USAGE_POLICY.md`は変更していない。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集は行っていない。
- **ユーザー受入証跡:** 「ok。進めよう」は方針・実装着手の承認だった(Draft PR作成前の最終受入ではない)。2026-08-03、ユーザーは[PR #72](https://github.com/matkei31/security-digest/pull/72)への独立レビューround 2完了(新たなBlockerなし)を確認し、本メッセージの送付をもって次を明示的に承認した: BL-034のrepository実装受入、[SD-032](DECISIONS.md#sd-032--adopt-cloudflare-web-analytics-and-google-search-console-for-bl-034)の採用判断の維持、[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md) Version 1.7の内容承認、PR #72のReady化と通常のmerge commit方式によるmerge、merge後の公開状態確認。
  - accepted implementation head: `6d032e702e1b118bc6da86b981a4189b4a85e15b`
  - 独立レビューround 1・2で指摘されたBlockerはすべて修正・独立再確認済み
  - full unittest 1577 tests OK
  - Pull Request CI run [30765873879](https://github.com/matkei31/security-digest/actions/runs/30765873879) success
  - `git diff --check` success
  - changed files 35件
  - unresolved review threads 0
  - UIはトップページ・Archive一覧・日別Archiveのそれぞれについて1280px・390pxの計6組み合わせでDOM検査(footer要素・script要素それぞれ正確に1件、横スクロールなし)を行い、取得できた範囲でscreenshotによる目視確認も行った証跡をユーザーが受入れた
  - 本受入時点ではCloudflare dashboardでのデータ受信確認とGoogle Search Console verification確認を含んでいなかった。これらは公開後の運用確認として、以下のとおり別途完了した。
  - [PR #72](https://github.com/matkei31/security-digest/pull/72)は通常のmerge commit方式でmerge済み。merge commit `8cd98e52bfe6164bffa8e10cdbf708eef76d43a1`。merge契機のGitHub Pages deploymentが成功した。
  - 公開トップページ・Archive一覧・代表的な日別Archive(`2026-07-31.html`)で、Cloudflare beacon(`type='module'`・正しいtoken・`static.cloudflareinsights.com`)とfooterアクセス解析説明が、各ページ正確に1件ずつ存在することをHTTP 200・DOM検査で確認済み。
  - 2026-08-03、ユーザーがCloudflare Web Analytics dashboardで実データ受信を確認した。初期確認値: Visits 3、Page views 3、Page load time 217ms。この数値は導入直後の初期観測値であり、現在値や恒久的な基準値ではない。Visitsはunique人数を意味しない(Cloudflare公式定義: 異なるwebsiteからのreferrerまたはdirect linkを起点とするpage view。1 Visitに複数page viewsが含まれ得る)。
  - 2026-08-03、ユーザーがGoogle Search ConsoleでDomain property `monomidigest.com` の所有権確認成功(「所有権を証明しました」の画面)を確認した。確認方法はDNSレコード／ドメイン名プロバイダ。Google verification TXTレコードは所有権維持のためXServer DNSに残し、TXT値そのものはrepositoryへ保存していない。
  - 計測開始日: `2026-08-03`。4週間程度の基準値取得期間を開始した。
  - 本closeout記録は[PR #73](https://github.com/matkei31/security-digest/pull/73)として作成され、独立レビューround 1・2で指摘されたBlockerがすべて修正・独立再確認済みと判断された。ユーザーは本指示の送付をもって、closeout記録の最終受入、PR #73のReady化、通常のmerge commit方式によるmergeを承認した。
  - accepted closeout head: `10867e1ec4573ea83b7f9c4572a9243c923f8db5`
  - full unittest 1601 tests OK
  - Pull Request CI run [30780371203](https://github.com/matkei31/security-digest/actions/runs/30780371203) success
  - `git diff --check` success
  - changed files 6件
  - unresolved review threads 0
- **残作業:** なし。4週間程度のデータ蓄積と評価は[BL-009](#bl-009--seoと閲覧者増加策)の成果測定として継続し、BL-034を再オープンしない。
- **注記:** [BL-009](#bl-009--seoと閲覧者増加策)のうちrobots.txt・sitemap・canonical・OG・favicon・About全体・コンテンツSEOは、本Ticketには含めず、[BL-009](#bl-009--seoと閲覧者増加策)配下の後続Ticket候補として別途記録する。Cloudflareのbeacon tokenはユーザーがCloudflareのmanual setup画面から取得し、チャット上で共有した公開識別子であり、account password・API token・session情報等は要求していない。

## BL-035 — BL-032後の運用手順とagent統制文書を現在状態へ同期する

- **ID:** BL-035
- **タイトル:** BL-032後の運用手順とagent統制文書を現在状態へ同期する
- **優先度:** P2
- **状態:** 完了
- **出所種別:** ユーザー原文
- **ユーザー原文:** 「おk。進めていこう」
- **原文の意味:** この原文単独では対象が曖昧なため、次を実装解釈として別記する――「Fable 5全体レビュー後に合意した優先順位に従い、最初にR-02とR-03の統制・運用文書同期へ進む。」
- **出所:** 2026-08-03、matkei31/security-digest repository全体に対するFable 5独立レビュー(`origin/main` `b5f04f5f500c6e3342cb0abdadd56d97165937d4`時点)。同レビューのFindings summaryのR-02(SECURITY_OPERATIONS.mdのcontent usage mode降格手順がBL-032実装後も旧前提のまま)・R-03(AGENTS.mdの固定Version参照とPR CI不在の誤記)を受けて登録した。
- **解釈:** 種別: Documentation inconsistency／Operational control correction／Fable 5 review R-02・R-03。次の問題を修正する。
  1. SECURITY_OPERATIONS.mdのcontent usage mode downgrade手順が、BL-032未実装時代の前提(「neither mode has production enforcement until BL-032」「metadata_onlyへの降格ではsource_definitions.json変更は不要」)のまま残っている。
  2. 現在は`source_definitions.json`の`policy.content_usage_mode`と関連policy fieldsがruntime挙動を実際に決める(BL-032実装・merge済み、[PR #69](https://github.com/matkei31/security-digest/pull/69))。
  3. 現行手順どおりに[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)だけを変更すると、運用者は降格したつもりでもproduction挙動が変わらない可能性がある。
  4. AGENTS.mdが「This repository currently has no ordinary `pull_request` or `push` CI workflow」とPR CIの存在を否定しているが、現在は`.github/workflows/pr-ci.yml`([BL-001](#bl-001--プルリクエストci)、2026-07-18以降)が存在する。
  5. AGENTS.md／STATUS.mdに複製されたUI_SPEC／SECURITY_REQUIREMENTS／SECURITY_OPERATIONSのVersion番号が、各正本fileの実際のVersionから陳腐化している(UI_SPEC 1.0→実際1.6、SECURITY_REQUIREMENTS 1.2→実際1.7、SECURITY_OPERATIONS 1.0→実際1.1)。
- **Scope:**
  - SECURITY_OPERATIONS.mdのcontent usage mode downgrade手順(section 7)を、BL-032のruntime enforcementへ同期する。mode変更時には`source_definitions.json`のpolicy fieldsだけでなく、SOURCE_USAGE_POLICY.md section 4の`content_usage_mode`別件数集計(「件数集計」行、合計17)と、`fetch.py`の`EXPECTED_CONTENT_USAGE_MODE_COUNTS`(`validate_content_usage_mode_distribution()`がfail-closedで照合するruntime定数)も同じ変更で同期する必要があることを手順へ明記する(今回`EXPECTED_CONTENT_USAGE_MODE_COUNTS`の実値は変更せず、将来の必要手順として記載するのみ)。
  - SECURITY_OPERATIONS.mdをVersion 1.2 Draftへ更新する(section 11のBL-032関連stale current-state記述の修正を含む)。
  - AGENTS.mdのCI説明を実workflow(`.github/workflows/pr-ci.yml`)へ同期する。
  - AGENTS.md／STATUS.mdのUI_SPEC／SECURITY_REQUIREMENTS／SECURITY_OPERATIONSへのVersion固定参照を、各正本fileのheaderへの委譲方式へ変更する。
  - 対応する文書test(`test_security_operations.py`・`test_security_requirements.py`・`test_status.py`・必要な範囲の`test_source_definitions.py`のActive work検査)の更新。
- **Out of scope:**
  - `source_definitions.json`の実際のmode変更。
  - [SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)のsource別policy変更。
  - runtime、workflow、production実行。
  - Fable 5レビューのR-01(attribution CSS)、R-04(文書test構造改革)、R-13(E2E test)。
  - [BL-009](#bl-009--seoと閲覧者増加策)、[BL-014](#bl-014--過去ユーザーコメントの体系的棚卸し)／BACKLOG構造整理。
  - 新しいsecurity controlまたはpolicy decision(DECISIONS.mdへのSD追加は行わない)。
- **完了条件:**
  1. 現行手順だけを読んで正しくmode downgradeできる(`source_definitions.json`の`policy.content_usage_mode`と関連boolean fieldsの変更が必要であることが明記されている)。
  1a. 現行手順が、mode変更時にSOURCE_USAGE_POLICY.md section 4の件数集計と`fetch.py`の`EXPECTED_CONTENT_USAGE_MODE_COUNTS`(および両者を固定する既存test)も同じ変更で更新する必要があることを明記している。
  2. BL-032を未実装／将来enforcementとするcurrent-state記述が残らない(Version 1.1承認当時の歴史的記録は区別して保持する)。
  3. PR CIの説明が実workflow(`.github/workflows/pr-ci.yml`)と一致する。
  4. AGENTS.md／STATUS.mdがUI_SPEC／SECURITY_REQUIREMENTS／SECURITY_OPERATIONSのVersion番号を重複保持しない。
  5. SECURITY_OPERATIONS Version 1.2がユーザー受入後にApprovedとなる(本Ticket登録時点ではDraft)。
  6. runtime／workflow／source定義／生成物(`data/`・`docs/`)に変更がない。
  7. 関連test更新とfull unittest成功、`git diff --check`成功。
- **依存関係:** [BL-032](#bl-032--取得元別content-usage-policy-enforcement)(実装・merge済みであることが前提)。[BL-030](#bl-030--取得元翻訳経路の緊急リスク低減)・[BL-031](#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)(SECURITY_OPERATIONS.md Version 1.1の内容の前提)。
- **実装証跡:** branch `docs/bl035-operations-agent-sync`、[PR #75](https://github.com/matkei31/security-digest/pull/75)。SECURITY_OPERATIONS.mdのcontent usage mode downgrade手順(section 7)をBL-032のruntime enforcementへ同期し、Version 1.2(当初Draft)へ更新した(mode件数分布の同期要件を含む)。AGENTS.mdのCI・workflow説明を実workflowへ同期し、UI_SPEC／SECURITY_REQUIREMENTS／SECURITY_OPERATIONSのVersion固定参照を各正本fileのheaderへの委譲方式へ変更した。独立レビューround 1(head `e06fd6e`)でmode件数分布同期手順の欠落とAGENTS.mdのfetch.yml誤記("only push/schedule workflow")を指摘され修正、round 2(head `420741d`)でAGENTS.mdのPR CI checkout対象の誤記("checks out the PR head")とfetch.yml/Pages記述の内部矛盾("or any other workflow")を指摘され修正した。round 2で新たなBlockerなしと確認された。
- **ユーザー受入証跡:** 独立レビューround 1・2で指摘されたBlockerはすべて修正・独立再確認済みであることを、ユーザーが確認した。ユーザーは本指示の送付をもって、BL-035の実装受入、SECURITY_OPERATIONS.md Version 1.2のApproved化、[PR #75](https://github.com/matkei31/security-digest/pull/75)の最終内容受入、Ready化、通常のmerge commit方式によるmergeを承認した。
  - accepted implementation head: `43bc14c584c05ed6539e20b9cba000e784d70bd3`
  - 独立レビューround 1・2で指摘されたBlockerはすべて修正・独立再確認済み
  - full unittest 1622 tests OK
  - Pull Request CI [run 30801691143](https://github.com/matkei31/security-digest/actions/runs/30801691143) success
  - `git diff --check` success
  - changed files 9件
  - unresolved review threads 0
  - Ready化・通常のmerge commit方式によるmergeはこのユーザー指示に基づき実行する(mergeそのものの記録は別途Git履歴・GitHub PR状態を正本とする)
- **残作業:** なし。BL-035の設計・実装・test・ユーザー受入について残作業はない。Fable 5レビューのR-01(attribution CSS)・R-04(文書test構造改革)・R-13(E2E test)・[BL-009](#bl-009--seoと閲覧者増加策)は、それぞれ別Ticketまたは既存Ticketのscopeとして扱い、本Ticketの残作業へ混入させない。
- **注記:** 本Ticketはdocumentation／governance-onlyであり、`fetch.py`・`daily_json.py`・`vulnerability_facts.py`・`source_definitions.json`・`SOURCE_USAGE_POLICY.md`・`SECURITY_REQUIREMENTS.md`・`UI_SPEC.md`・`DECISIONS.md`・`.github/workflows/`・`data/`・`docs/`への変更は行わない。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集は行わない。

## BL-036 — 記事カードのsource attribution注記を低強調表示へ整える

- **ID:** BL-036
- **タイトル:** 記事カードのsource attribution注記を低強調表示へ整える
- **優先度:** P2
- **状態:** 実装中／ユーザー目視受入待ち
- **出所種別:** 技術上の発見事項
- **ユーザー原文:** 該当なし — Fable 5の独立repositoryレビューR-01で確認された技術上の発見事項。ユーザーの「おk」はR-01の修正着手を承認する短い進行指示であり、問題内容の原文や実装後の受入発言としては扱わない。
- **問題:**
  1. [BL-032](#bl-032--取得元別content-usage-policy-enforcement)により、記事カードへsource policy別の`.article-attribution`(`render_source_attribution_html()`)が既に出力されている。
  2. 生成HTMLのinline CSS(`build_html()`内の`<style>`block)には`.article-attribution`のstyle定義が存在しない。
  3. そのため注記がブラウザ既定に近いサイズ・余白で表示され、AI analysis本文・recommended actions・元記事CTAとの情報階層が不明瞭である。
  4. [UI_SPEC.md](UI_SPEC.md) Version 1.6・[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)には、「現行UIへAI利用を明示する専用注記は追加しない。記事カード単位・分析区分単位の注記も採用しない」という方針が記録されている。
  5. ただし現在のattributionは、サイト全体への一般的なAI利用説明を追加したものではなく、[BL-031](#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)／BL-032のsource usage policyに基づく、source別・content usage mode別の表示要件として既に実装・稼働している。
  6. 現行実装とUI仕様・Stable Decisionの関係を、ユーザー目視受入を経て明示的に整理する必要がある。
- **Scope:**
  - `.article-attribution`の低強調CSS追加。
  - attribution内linkのCSS追加。
  - attributionのDOM位置・表示文言・安全性(HTML escape、safe URL、mode分岐)は変更せず維持する。
  - UI_SPEC.md Version 1.7 Draftへの更新(AI-use note原則の整理、CSS現行値の記載)。
  - BACKLOG.md／STATUS.md更新。
  - 関連testの更新。
  - PC 1280px／390pxのローカルreview screenshots作成(repositoryへcommitしない)。
  - ユーザー受入後、同PRのacceptance-recording commitで新規[SD-033](DECISIONS.md)を追加し、[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)のAI-use noteに関する部分だけを限定的にsupersedeする予定を記録する(今回はSD-033自体を作成しない)。
- **Out of scope:**
  - attribution文言の変更。
  - mode別attributionの追加・削除。
  - source policy値の変更、`source_definitions.json`、[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)。
  - ARTICLE prompt／schema／Gemini model、daily JSON schema、AI analysis本文、元記事CTA文言。
  - Aboutページ、サイト全体の一般的なAI利用説明、footerへのAI説明追加、generic AI badge／icon。
  - Fable 5レビューのR-04(文書test構造改革)・R-13(E2E test)、[BL-009](#bl-009--seoと閲覧者増加策)。
  - production／公開HTMLの即時更新。
- **完了条件:**
  1. attributionが本文より明確に低強調である。
  2. 小さすぎずPC／390px双方で読める。
  3. attribution内linkが識別できる。
  4. pill、badge、alert boxのような過剰な強調を使わない。
  5. DOM位置はAI analysisの後、元記事CTAの前を維持する。
  6. attribution文言とmode別表示条件を変更しない。
  7. UI_SPECとStable Decisionがユーザー受入後に現行実装と一致する。
  8. PC 1280px／390pxをユーザーが目視受入する。
  9. runtimeの収集・AI処理・policy enforcementは変更しない。
- **依存関係:** [BL-031](#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)・[BL-032](#bl-032--取得元別content-usage-policy-enforcement)(source usage policyとruntime enforcementの前提)。[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)(AI-use note方針の現在の正本、本Ticketではsupersedeしない)。
- **実装証跡:** （Draft PR作成後にこの節へ記録する。）
- **ユーザー受入証跡:** （未受入。PC 1280px／390pxのローカルreview screenshotsをユーザーが目視確認するまでDraft。）
- **残作業:** ユーザーによる目視受入、UI_SPEC Version 1.7のApproved化、SD-033の追加登録、Ready化・mergeが残っている。
- **注記:** 本TicketはCSS表示・UI_SPEC文書更新のみを対象とし、`daily_json.py`・`vulnerability_facts.py`・`source_definitions.json`・`SOURCE_USAGE_POLICY.md`・`SECURITY_REQUIREMENTS.md`・`SECURITY_OPERATIONS.md`・`DECISIONS.md`・`.github/workflows/`・tracked `data/`・tracked `docs/`への変更は行わない。production・`workflow_dispatch`・実Gemini API呼び出し・通常の外部収集は行わない。

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
