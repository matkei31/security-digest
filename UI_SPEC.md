# Monomi Digest UI Specification

- **文書名:** Monomi Digest UI Specification
- **バージョン:** 1.8（Draft）
- **状態:** Draft（Version 1.7までは承認済み）
- **最終受入日:** 2026-08-04（Version 1.7）。Version 1.8はユーザー目視受入前のDraftである
- **適用対象:** 現行Monomi Digest。BL-006のブランド名変更（Security Digest→Monomi Digest、`🔐`維持、title／H1絵文字統一）は、2026-07-26にユーザーがPC 1280px／390pxのトップページ・Archive一覧・日別Archive計6画面を目視受入し、Version 1.4として承認済みである。[PR #57](https://github.com/matkei31/security-digest/pull/57)はmainへmergeされ、GitHub Pagesでの公開反映を確認済みである。Version 1.5はBL-029の「本日の要点」子見出し・記事カード見出しの再設計を反映する。ユーザーは`top-page-2026-07-27-1280px.png`、`top-page-2026-07-27-390px.png`、`daily-archive-2026-07-27-1280px.png`、`daily-archive-2026-07-27-390px.png`、`daily-archive-2026-07-26-1280px.png`、`daily-archive-2026-07-26-390px.png`、`daily-archive-2026-07-25-1280px.png`、`daily-archive-2026-07-25-390px.png`の計8画面を目視確認し、「8枚とも確認した。BL-029の見出し、重要・優先事項の2段落表示、過去Archiveへの適用、0記事日の表示に問題なし。BL-029として受入。」と受入した（accepted head `c4ca053b176c93fba3588c1f0aaf4116ab3fbc33`、[PR #60](https://github.com/matkei31/security-digest/pull/60)）。Version 1.6はBL-028のダイジェストナビゲーション配置再設計（A案「左寄せ二段・ラベルなし」）を反映する。ユーザーは`top-page-nav-1280px.png`、`top-page-nav-390px.png`、`daily-archive-top-nav-1280px.png`、`daily-archive-top-nav-390px.png`、`daily-archive-bottom-nav-1280px.png`、`daily-archive-bottom-nav-390px.png`、`archive-index-nav-1280px.png`、`archive-index-nav-390px.png`、`daily-archive-oldest-single-direction-1280px.png`、`daily-archive-oldest-single-direction-390px.png`の計10画面を目視確認し、「10枚とも確認した。BL-028の左寄せ二段配置、前→次／過去→最新の順序、上部・下部ナビゲーション、単一方向ケース、PC 1280px／390pxの表示に問題なし。BL-028として受入。」と受入した（accepted head `77b4106618c29b9220012fd10e9ff616d773fa56`、[PR #62](https://github.com/matkei31/security-digest/pull/62)）。Version 1.7は[BL-036](BACKLOG.md#bl-036--記事カードのsource-attribution注記を低強調表示へ整える)(Fable 5レビューR-01)の`.article-attribution`低強調CSSを記録し、BL-032で既に実装・merge済みのsource-policy-required attributionを[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)のAI-use note方針に対する限定例外として正式に認める。[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)が、SD-016のうち記事カード単位のAI-use note条項だけを限定的にsupersedeし、SD-016のgeneric AI disclosure禁止と他の6項目は維持する。2026-08-03のDraft作成後、ユーザーは`bl036-attribution-page-1280px.png`、`bl036-attribution-page-390px.png`、`bl036-attribution-card-1280px.png`、`bl036-attribution-card-390px.png`、`bl036-attribution-card2-link-1280px.png`、`bl036-attribution-card2-link-390px.png`の計6画面(実`fetch.py`の`build_html()`が生成したHTML、10px CSS)を目視確認し、「おk」と受入した（原文の解釈: 直前に提示した6画面の目視受入結果と、[PR #76](https://github.com/matkei31/security-digest/pull/76)内での最終受入記録・UI_SPEC Approved化・SD-033追加・mergeへ進むことへの同意。ユーザーが「10px」等の具体的CSS値を明示発言したものとしては扱わない。accepted implementation head `12a6f502973c78e21dbe0b209073f824731a3e5d`、2026-08-04）。

## 1. 文書の目的と対象読者

本書は、Version 1.0〜1.4の受入済み仕様、安定した意思決定、現在の`main`実装と回帰テストを一つにまとめる。将来のUI変更で参照するリポジトリ常駐の正本とし、同じ論点を都度推測し直すこと、受入済みの判断を未決へ戻すこと、Fable 5提案を無条件に再採用することを防ぐ。

対象読者は、UIの設計・実装・レビュー・受入を行うユーザー、実装担当者、レビュー担当者である。本書は表示仕様を扱い、ARTICLE／BRIEF prompt、daily JSON schema、生成・公開workflow、ブランド名変更の仕様書ではない。

Version 1.0は、Draft 0.1で整理した確定仕様に加え、残っていた7項目のユーザー裁定を反映した承認済み文書である。Version 1.1は、BL-022で明示されたトップページの直前公開ダイジェストリンクを追加した。Version 1.2は、トップページと日別Archiveのナビゲーション用語を統一し、日付をリンク文言から除き、方向移動と全体導線を左右の別グループへ整理した。Version 1.3は、BL-020で収集元フッターの取得元別カラーとpill表現を廃止し、無彩色・低強調のプレーンテキスト一覧へ置き換えた。Version 1.4は、BL-006でブランド名をSecurity DigestからMonomi Digestへ変更し、`🔐`は維持したままtitle／H1の絵文字表記を統一した。2026-07-26、ユーザーがトップページ・Archive一覧・日別ArchiveのPC 1280px／390px計6画面を目視確認し受入した。Version 1.5は、BL-029でユーザーと確定した仕様に基づき、「本日の要点」の子見出しを概況／重要・優先事項／確認事項へ、記事カードの見出しを概要／金融機関との関連／確認すべきことへ統一する。「重要・優先事項」は同一記事の`summary`と`financial_impact`をverbatimで2段落表示する新しい構成契約であり、ARTICLE prompt・ARTICLE response schema・public daily JSON schemaは変更しない。2026-07-27、ユーザーがトップページ・日別Archive（記事あり2日・0記事1日）のPC 1280px／390px計8画面を目視確認し受入した。Version 1.6は、BL-028でユーザーと確定したA案「左寄せ二段・ラベルなし」に基づき、ダイジェストナビゲーションをPC／390px共通の左寄せ縦二段構造（1段目が方向移動、2段目が全体導線）へ再設計する。日別Archiveの全体導線は`過去のダイジェスト`→`最新のダイジェスト`の順へ変更する。2026-07-27、ユーザーがトップページ・日別Archive上部/下部・Archive一覧・最古日の単一方向ケースのPC 1280px／390px計10画面を目視確認し受入した。Version 1.7は、BL-036(Fable 5レビューR-01)に基づき、BL-032で既に実装済みだった記事カードの`.article-attribution`へ低強調CSSを追加する(BL-036のruntime変更はこのCSSのみで、attribution文言・mode分岐・HTML escape・URL安全性・DOM順序は変更していない)。§3.1のAI-use note原則を、サイト全体への一律generic AI note禁止(維持する方針)と、BL-032で実装済みのsource-policy-required attributionを[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)の一部に対する限定例外として正式に認める内容とに区別して明示する。2026-08-04、ユーザーがPC 1280px／390pxの実generator screenshots計6画面を目視受入し（「おk」、原文と解釈の記録は本章冒頭を参照）、[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)がSD-016のAI-use note条項だけを限定的にsupersedeした。

## 2. 正本と優先順位

仕様が衝突する場合は、次の順で優先する。

1. ユーザー原文、明示的なユーザー判断、ユーザー受入済みの実装
2. [DECISIONS.md](DECISIONS.md)と[BACKLOG.md](BACKLOG.md)に記録された確定事項
3. 現在の`main`実装と回帰テスト
4. Fable 5の提案

本書では、上記1〜3で根拠を確認できた項目を「確定仕様」、現行コードにある具体値を「現行値」と表記する。将来新たな未決事項が生じた場合は確定仕様へ混入させず、実装前にユーザー裁定を得る。Version 1.3時点の未決事項はない。

主要な根拠は[SD-012](DECISIONS.md#sd-012--dashboard-v2-priority-index-and-the-article-reason-no-imperative-contract)、[SD-013](DECISIONS.md#sd-013--ordinary-article-card-variant-b-remove-classification-label-badges-keep-関連タグ-round)、[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)、[SD-020](DECISIONS.md#sd-020--link-the-top-page-to-the-latest-validated-earlier-digest)、[SD-021](DECISIONS.md#sd-021--unify-digest-navigation-labels-and-separate-direction-from-global-navigation)、[SD-023](DECISIONS.md#sd-023--remove-source-specific-colors-and-pill-styling-from-the-source-footer)、[BL-016](BACKLOG.md#bl-016--本日の要点の表示階層を目視受入する)、[BL-017](BACKLOG.md#bl-017--過去ダイジェストの回遊性と一覧表示を改善する)、[BL-018](BACKLOG.md#bl-018--トップページとjson再構築時の記事時刻表示を一致させる)、[BL-020](BACKLOG.md#bl-020--収集元一覧の取得元別カラーを廃止する)、[BL-022](BACKLOG.md#bl-022--前日ダイジェスト直接リンク)、`fetch.py`、`test_fetch.py`、`test_archive.py`である。

## 3. UI設計原則

### 3.1 確定仕様

- 読者が「何が重要か」と「いつ確認するか」を別々に判断できるよう、「重要度」と「確認目安」を独立した軸として扱う。
- 表示用語は「確認優先度」ではなく「重要度」を使用する。「確認目安」は時間軸として維持する。
- 同じ記事の情報を複数のフルカードで重複させず、上位セクションは概要・索引、記事カードは詳細という役割分担にする。
- AI分析による解釈と、CVE・CVSS・CISA KEVの客観情報を視覚的・構造的に分ける。
- 現行UIへAI利用を明示する専用注記は追加しない。記事カード単位・分析区分単位の注記も採用しない。将来Aboutや公開導線を別スコープで設計する場合は、その時点で説明の必要性を改めて裁定する。（[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)、Version 1.0で確定。[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)が、下記のとおりこの方針のうち記事カード単位のAI-use note条項だけを限定的にsupersedeした。SD-016のgeneric AI disclosure禁止と他の6項目は維持されている。）
  - **維持する方針(SD-033によっても変更しない):** サイト全体へgenericな「AIを利用しています」badgeやalertを追加しない。全記事へsource policyと無関係な一律AI noteを追加しない。AI analysisの各見出し・各段落へ反復的なAI labelを追加しない。About／footer等の一般的AI説明はBL-036のscope外。AIであることを過剰に強調し、記事の可読性を損なわない。
  - **限定例外として認められた現行実装(BL-032で実装済み、BL-036のruntime変更はCSSのみ、[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)で正式化済み):** [BL-031](BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化)／[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)のsource usage policyで必要とされる、source別・content usage mode別のattribution note（`.article-attribution`）は、記事カードへの表示としてBL-032で既に実装・受入・merge済みであり、BL-036が新たに追加したruntime要素はCSSだけである。これはsource policy、利用条件、attribution、bounded AI analysisであること、原文代替ではないこと等を読者へ示すための限定的な注記であり、一律のgeneric AI badgeとは目的・表示条件・文言が異なる。source policy上不要な記事へ推測で表示しない。DOM位置はAI analysisの後、元記事CTAの前を維持する。見た目は本文より低強調であるが、判読可能性を維持する（現行値は3.2参照）。attribution文言と表示条件の正本は[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)、`source_definitions.json`の`policy`、`render_source_attribution_html()`である。UI_SPECは表示階層と見た目だけを規定し、文言・表示条件の正本を持たない。**この既に実装済みの表示は、2026-08-04のユーザー目視受入と[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)の追加により、[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)の「記事カード単位のAI-use noteを採用しない」という部分に対する限定例外として正式に確定した。SD-016のgeneric AI disclosure禁止と、AI-use note以外の6項目は、この限定例外によって変更しない。**
- 色と同一形状のラベルを過度に反復せず、強調は意味のある値に限定する。
- JavaScriptなしの静的HTMLとして、PCと390pxモバイルの双方で同じ情報へ到達できるようにする。

### 3.2 現行値

次は`fetch.py`に存在する現行の設計値であり、未承認のFable 5推奨値を確定値にしたものではない。

| 対象 | 現行値 |
|---|---|
| ページ背景／主要文字 | `#0d1117`／`#e6edf3` |
| 面背景／通常境界 | `#161b22`／`#21262d` |
| 補助文字／リンク | `#8b949e`／`#79c0ff` |
| 強調（高・本日確認） | `#f85149`、左境界`2px` |
| Brief境界／見出し | `#9e6a03`／`#f0b429` |
| 本文フォント | `-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif` |
| コンテンツ最大幅 | Brief、優先確認、dashboard、記事一覧、収集元とも`680px` |
| 通常カード | radius `10px`、padding `14px 16px`、カード間隔`10px` |
| 小ラベル | 関連タグとKEVはradius `100px`。用途とコントラストは別契約 |
| responsive breakpoint | `max-width: 600px` |
| anchor offset | 通常`218px`、600px以下`226px`(BL-028のナビゲーション二段化に伴い調整) |
| `.article-attribution` | font-size `10px`、color `#768496`、line-height `1.6`、margin-top `10px`。background／border／border-radius／pillなし。内部link color `#8b949e`、hoverで`#79c0ff`、underline。PC／390px共通(BL-036, Version 1.7で確定) |

これらの値を変更する場合は、見た目の抽象表現だけでなく、変更前後の具体値、PC／390pxへの影響、既存の強調階層への影響を示す。

## 4. ページ全体の情報構造と表示順

### 4.1 トップページと日別Archive

現行の表示順は次のとおりである。DOM上もこの順を維持する。

1. `header`: ページ名、日別Archiveの副題（該当時）、最終更新、記事件数、Archive導線
1.5. `.site-intro`: サイト説明（**トップページのみ**。Version 1.8）。sticky headerの外側、`header`の直後、「本日の要点」の前に置く。日別Archiveには表示しない
2. `.todays-brief`: 「本日の要点」。表示可能なBrief内容がある場合だけ表示
3. `.important-items`: 「優先確認」。0件でもセクション自体は表示
4. `.dashboard`: 「本日のダッシュボード」
5. `.article-list-header`: 「本日の情報」と並び順の説明
6. `.cards`: 記事カード一覧
7. `.sources`: 折りたたみ式の「収集元」一覧
8. 日別Archiveの最下部ナビゲーション。全体導線は常に表示し、実在しない方向のリンクだけを省略

Brief、優先確認、dashboardはそれぞれ「概況」「短い索引」「全体集計」を担当し、記事カード本文を複製しない。

### 4.2 Archive一覧

`header`に「過去のダイジェスト」、最終更新（値がある場合）、「最新のダイジェスト」を置き、その後に日付の新しい順でArchiveカードを並べる。

## 5. 用語

| 用語 | 意味と表示値 |
|---|---|
| 重要度 | 金融機関への影響・重みの軸。`高`、`中`、`低`。時間軸ではない |
| 確認目安 | 確認する時間の軸。`本日確認`、`今週確認`、`参考`。重要度とは独立 |
| 未判定 | その軸の有効な表示値を得られない状態。値がある場合だけdashboardへ追加 |
| 優先確認 | 重要度が`高`、または確認目安が`本日確認`の記事を本文へ導く理由付き索引 |
| 本日のダッシュボード | 掲載件数、重要度、確認目安、主なカテゴリの集計 |
| 原題 | `raw_title`に保持された取得元の題名。英語原題がある通常ケースでは主見出し |
| 日本語訳 | `title`に保持された日本語タイトル。英語原題の副行 |
| 脆弱性情報 | CVE、CVSS、CISA KEVからなる客観情報。AI分析本文とは別区分 |
| 関連タグ | カード下部の低コントラストな補助情報。検索・操作要素ではない |

「確認優先度」は生成HTMLの表示用語として使用しない。

## 6. ページヘッダー

### 6.1 確定仕様

- トップページの可視見出しは`🔐 Monomi Digest`、日別Archiveも`🔐 Monomi Digest`、Archive一覧は`過去のダイジェスト`である。`🔐`はBL-004・SD-016の決定どおりBL-006のブランド移行後も維持し、BL-006で従来title/H1間にあった絵文字表記の不整合（日別Archiveのtitleには`🔐`があるがH1になかった）も解消した。
- トップページは「最終更新」「記事件数」「過去のダイジェスト」を表示し、直前の公開日がある場合だけ「← 前のダイジェスト」も表示する。
- 日別Archiveは`日次ダイジェスト：YYYY年MM月DD日`、最終更新、記事件数、戻り導線と前後導線を表示する。
- ヘッダーは`position: sticky; top: 0; z-index: 10`である。

### 6.2 モバイルsticky header

ヘッダーpaddingはPC／モバイルとも`20px 16px 16px`、見出しは`18px`である。600px以下でも現在のstickyとpaddingを維持し、圧縮案は採用しない。sticky headerとアンカー移動の関係は第15章のanchor offset契約に従う(BL-028のナビゲーション二段化に伴いanchor offset値は調整済み)。

### 6.3 直前の公開ダイジェスト

- 直接リンクの対象は、検証済みdaily JSONと`data/index.json`に存在し、対応するArchive HTMLが生成済みである日付のうち、現在の`digest_date`より前で最も新しい日とする。
- 配列の保存順には依存せず、日付比較で選ぶ。現在日、未来日、不正日付、必要な成果物が欠ける日付は選ばない。
- 暦上の前日か欠落をまたぐかにかかわらず、直前の公開日への表示文言は「← 前のダイジェスト」とし、日付を含めない。
- 過去の公開日がない場合は直接リンクを表示しない。この場合も「過去のダイジェスト」は維持する。
- トップページの全体導線は「過去のダイジェスト」である。
- PC／390pxともに方向移動グループを1段目、全体導線グループを2段目とする左寄せの縦二段構造とする(§6.4のナビゲーション配置契約を参照)。

### 6.4 ナビゲーション配置(BL-028, Version 1.6)

- 採用案はA案「左寄せ二段・ラベルなし」である。方向移動グループ(`.archive-direction-nav`)を1段目、全体導線グループ(`.archive-global-nav`)を2段目とする縦二段構造を、PC／390pxで共通に使う。説明ラベル、囲み、背景色、区切り線、追加アイコンは導入しない。
- 日別Archiveの1段目は`← 前のダイジェスト`／`次のダイジェスト →`の順、2段目は`過去のダイジェスト`／`最新のダイジェスト`の順とする。左側を過去・戻る方向、右側を新しい・進む方向とし、上段と下段で左右の時間的意味を揃える。

  ```text
  ← 前のダイジェスト　　次のダイジェスト →
  過去のダイジェスト　　最新のダイジェスト
  ```

- トップページは1段目に利用可能な場合だけ`← 前のダイジェスト`、2段目に`過去のダイジェスト`のみを置く。前のダイジェストが存在しない場合は1段目そのものを描画しない。
- Archive一覧は単独の全体導線`最新のダイジェスト`を左寄せで表示する。右端配置は使わない。
- 日別Archiveの上部ナビゲーションと下部ナビゲーションへ同じDOM順・配置契約を適用する。
- グループ単位のDOM順は常に「方向移動→全体導線」である。リンクが一つもないグループは描画せず、空の`div`による余白を残さない。方向移動グループがない場合は全体導線グループを上へ詰める。一方向だけ存在する場合はそのリンクを左端へ置き、不在リンクの位置は予約しない。
- PCと390pxで情報構造とDOM順を変えない。390pxで横幅不足により段内で折返しが生じる場合も、方向移動段→全体導線段のDOM順は変えない。
- 4文言(`← 前のダイジェスト`／`次のダイジェスト →`／`最新のダイジェスト`／`過去のダイジェスト`)、リンク文言への日付非表示、前後日付の選定ロジック、欠落日をまたぐ既存日探索、現在日・未来日・不正日付の除外、存在しない方向リンクだけを省略する挙動、各リンクのhref、`aria-label`、keyboard操作、browser default focusは変更しない。
- sticky headerがPC／390pxとも二段ナビゲーションとなり実高が増えるため、記事カードへのアンカー遷移で見出しが隠れないよう`--anchor-offset`をPC 218px、390px 226px(実測header高202pxに対しそれぞれ16px／24pxの余白)へ調整する(第15章参照)。

## 7. 本日の要点

### 7.1 表示内容（Version 1.5）

表示可能なBrief内容が一つ以上ある場合だけ`.todays-brief > .brief-box`を表示し、見出しを「本日の要点」とする。内部は、値がある区分だけ次の順で表示する。

1. 「概況」: 決定論的な状態行と概況本文
2. 「重要・優先事項」: §7.3参照
3. 「確認事項」

状態行はBL-016で確定した次のプレーン形式とする。

`掲載N件｜重要度「高」N件｜本日確認N件｜今週確認N件`

未判定が1件以上の場合だけ末尾へ`｜未判定N件`を加える。「本日の状態」ラベル、括弧、コロン、文末の句点は付けない。旧daily JSONの表示互換では保存値を書き換えず、日別Archiveの表示時だけ同じ現行形式へ変換または補完する。

### 7.2 現行値

`.brief-box`は背景`#161b22`、アンバー境界`1px solid #9e6a03`、radius `10px`、padding `14px 16px`である。状態行自体は警告色にせず、背景`#0d1117`、境界`#30363d`の控えめな行として表示する。「重要・優先事項」の各項目(`.brief-priority-item`)は背景`#0d1117`、境界`1px solid #30363d`、radius `6px`、padding `10px 12px`のカード状とし、項目内の2段落間`gap`(4px)より項目間`gap`(12px)を明確に広くする。

### 7.3 重要・優先事項の構成契約（BL-029, Version 1.5）

- 対象記事は現行`discussion_points`の条件を維持する: 分析済み(`is_article_evaluated`)かつ`importance=="高"`または`urgency`が`"本日確認"`／`"今週確認"`。安定ソート・最大件数・source ID検証は既存契約を維持する。
- 選定された記事ごとに一つの`<li class="brief-priority-item">`を作り、同一記事の`analysis.summary`と`analysis.financial_impact`をverbatimで別々の`<p>`(`.brief-priority-summary`／`.brief-priority-impact`)として表示する。再要約・言い換え・接続詞追加・語尾変更・句読点補正・短縮・clamp・省略・記事間の文章結合は行わない。
- field欠損時: 両方存在すれば2段落、`summary`のみなら`summary`だけ、`financial_impact`のみなら`financial_impact`だけを表示する。両方とも存在しない記事はその項目を除外する。片方の欠損を理由にもう片方まで削除しない。
- 重複除外は、同一記事から構成された`(summary, financial_impact)`ペアの完全一致のみを対象とする。`summary`だけ一致、`financial_impact`だけ一致、一方の記事だけ片方が欠損、表記が一部異なる場合は別項目として維持する。
- 新規生成分の内部composition identifierは`today-brief-extractive-v2`(daily_json.BRIEF_PROMPT_VERSION)。public daily JSON schemaは変更せず、`discussion_points`は選定記事ごとに`summary + "\n" + financial_impact`(片方欠損時はその値のみ)を1文字列として保存する。`important_highlights`は既存互換のため保存を維持するが、HTMLには表示しない。
- HTML描画は`brief.prompt_version`に依存せず、`items[].ai_analysis`から`select_priority_items()`で常に再構成する。過去Archive（`today-brief-extractive-v1`、`today-brief-v3`等）でも、記事分析が有効な限り同じ新UIを再現する。`items[].ai_analysis`から安全に再構成できず、かつ保存済み`discussion_points`が存在する日だけ、見出し「注目論点」で保存済み値を一項目一段落のまま互換表示する（この日は新仕様適用日として扱わない）。保存済み`discussion_points`も存在しない場合はこの区分を非表示にする。

## 8. 優先確認

優先確認はフルカードの重複ではなく、理由付きの短い索引である。

- 選定対象は、重要度が`高`、または確認目安が`本日確認`の記事である。
- 表示順は確認目安、重要度、元の収集順による安定順序で、記事一覧と同じ番号を使う。
- 各項目は、主見出し／副行のタイトル、`重要度 <値> ・ 確認目安 <値>`、既存の`reason`、`本文を見る`アンカーだけを表示する。
- `reason`は再要約・省略しない。値がなければ固定の代替文を生成しない。
- category、関連タグ、取得元、確認事項、CVE／CVSS／KEV、外部記事リンクは索引へ重複表示しない。
- 1件以上の場合だけ「重要度が高い、または確認目安が本日確認の記事です。」を表示する。
- 0件の場合も「優先確認」セクションを残し、「本日の優先確認対象はありません。」と表示する。選定条件の説明は表示しない。
- `本文を見る`は対応する`#article-N`へ移動し、対象カードを`:target`で軽く強調する。

## 9. 本日のダッシュボード

dashboard v2は、複数の重いカードではなく`.dashboard`一つに統合した現行の情報階層を確定仕様とする。

1. `.dashboard-head`: 「本日のダッシュボード」と`掲載 N件`
2. `.dashboard-axes`: 主軸である「重要度」と「確認目安」
3. `.dashboard-categories`: 視覚的に弱い補助行「主なカテゴリ」

重要度は`高／中／低`、確認目安は`本日確認／今週確認／参考`を0件も含めて表示し、該当軸の未判定が1件以上の場合だけ`未判定`を末尾へ追加する。`高`と`本日確認`は件数が1件以上の場合だけ赤い左境界と文字色で軽く強調する。

カテゴリは通常記事カードではなくdashboardの補助集計に残す。件数が1件以上のカテゴリだけを定義順で表示し、全件0の場合は「該当する記事はありません。」と表示する。収集元件数、CISA KEV件数、楕円バッジ、JavaScriptはdashboardへ追加しない。

PCでは2軸を2列、600px以下では1列に積む。

## 10. 記事一覧と記事カード

### 10.1 記事一覧

見出しは「本日の情報」、補足は「確認目安、重要度、元の収集順で表示しています。」である。実際の安定ソートは確認目安（本日確認、今週確認、参考、その他）、重要度（高、中、低、その他）、元の入力順の順である。入力データ自体の順序は変更しない。

### 10.2 記事カードvariant B

通常カードは`<article class="card" id="article-N">`とし、次の順序を確定仕様とする。項目6・8の見出し文言はBL-029でユーザーと確定したVersion 1.5の表記であり、順序自体とARTICLE field（`summary`／`financial_impact`）の内容は変更しない。

1. 記事番号
2. 英語原題を主とするタイトル
3. 日本語訳（存在する場合）
4. 取得元とJST日時
5. 重要度と確認目安
6. 「概要」（ARTICLE `summary`）
7. 「脆弱性情報」（有効なfactsがある場合）
8. 「金融機関との関連」（ARTICLE `financial_impact`）
9. 「確認すべきこと」
10. 「元記事を読む」
11. 「関連タグ」（存在する場合）

カード全体を外部リンクにはしない。安全なURLがある場合、タイトルと「元記事を読む」を外部リンクにする。日別Archiveも`build_html()`を共用し、同じカード仕様を使用する。

## 11. タイトル・日本語訳・原題の扱い

- 英語原題がある通常ケースでは、原題を主見出し、日本語訳を小さい副行にする。後のユーザー受入済み実装で確定しており、Fable 5の「日本語訳を主見出し、英語原題を副行」案へ戻さない。
- 主見出しの言語が判定できる場合は`lang="en"`または`lang="ja"`、日本語訳の副行は`lang="ja"`を付ける。
- 原題がなく日本語訳がある場合は日本語訳を主見出しにする。
- 原題と日本語訳が同じ、または原題が日本語の場合は重複する副行を出さない。
- 表示可能なタイトルがない場合は「無題」とする。
- 現行CSSの`overflow-wrap:anywhere`による自然折返しを維持する。モバイルでも英語原題に行数制限やclampを設けず、原題の一部を省略しない。

## 12. 取得元・重要度・確認目安・カテゴリ・関連タグ

### 12.1 取得元と日時

取得元は色付き楕円ラベルではなく、`<p class="article-meta">取得元 ・ MM/DD HH:MM</p>`のプレーンテキストとしてタイトル直後へ置く。取得元または日時の片方だけがある場合はその値だけを表示し、両方ない場合は`article-meta`自体を省略する。末尾に単独の`・`を残さない。

記事時刻はBL-018の契約に従いJSTの`MM/DD HH:MM`で表示する。`published_at_jst`、`published_at`、`date`の順で解釈可能な値を選び、timezone-awareな日時はoffsetを保持して同じ瞬間のJSTへ変換する。`Z`、`+00:00`、`+09:00`を正しく解釈し、`+09:00`を二重変換しない。offsetのないlegacy naive値は根拠なくUTC／JSTを付与せず、従来のwall-clock表示を維持する。解釈不能値は日時を表示しない。保存済み`published_at`、記事順、digest日付、当日判定は表示変換によって変更しない。

記事カードとは別に、ページ末尾の折りたたみ式「収集元」一覧を維持する。取得元別カラー、背景、border、pill状の角丸、chip状の内部余白は使用せず、全取得元を同じ無彩色・低強調のプレーンテキスト一覧として表示する。件数、表示集合、定義順は`build_footer_sources()`の戻り値を唯一の基準とし、CISA KEVも他の取得元と同じ通常表示にする。トップページと日別Archiveは同じ`ul`／`li`構造と表示契約を使い、browser既定のfocus表示を維持する。

### 12.2 重要度と確認目安

`<p class="article-assessment">`内で、`重要度 <値>`と`確認目安 <値>`を独立して表示する。両軸を関連タグと同じ楕円形にしない。重要度`高`と確認目安`本日確認`だけを、それぞれ独立に`.is-accent`の文字色・左境界で軽く強調する。`中／低／今週確認／参考`には追加強調を付けない。

### 12.3 カテゴリ

カテゴリは通常記事カードに表示しない。daily JSONへの保存、validation、dashboardの「主なカテゴリ」集計は維持する。

### 12.4 関連タグ

関連タグはvariant Bで残す確定仕様であり、全面削除しない。カード最下部の低コントラストな補助情報として「元記事を読む」の後へ配置する。最大5件を`<span class="article-tag">`で表示し、`<a>`、`button`、click handler、`role="button"`、`cursor:pointer`を付けない。タグ検索、タグ別ページ、クリック操作は導入しない。

## 13. CVE・CVSS・CISA KEV

CVE・CVSS・CISA KEVは、AI分析とは別の客観情報として`.vulnerability-facts`に表示する。「概要」の後、「金融機関との関連」の前へ置く。

- 有効なCVEごとにNVD詳細へのリンクとCVSS表示を置く。
- CVSSは利用可能なscore、severity、version、提供元を組み合わせる。値がなければ「CVSS未評価」とする。
- CISA KEVは`status == "listed"`の場合だけ「CISA KEV掲載」を表示する。非掲載、unknown、内部status文字列は表示しない。
- 不正なCVE要素はその要素だけ省略し、有効なCVEがなければ見出し・空枠ごと省略する。
- 現行の`.kev-badge`はアンバー系の小さいpillとして維持する。これは「CISA KEV掲載」という客観的かつ重要な状態を示す例外的な強調である。関連タグとは意味・色・強調度が異なり、記事カードの分類pill多用を復活させるものではない。

現行の実表示例として、`docs/archive/2026-07-15.html`にはCVE-2026-56155、`CVSS 7.8 / High（v3.1・他機関）`、`CISA KEV掲載`が保存されている。

## 14. Archive一覧・日別ページ・前後移動

### 14.1 Archive一覧

BL-017で確定したとおり、各一覧カードは次の3要素だけを表示する。

1. 日付
2. 記事数
3. 重要度「高」の件数

「本日の要点あり」「本日の要点なし」と、その代替ラベルは表示しない。日付の新しい順に並べ、同一日付は重複表示しない。0件の場合は「公開済みのダイジェストはありません。」と表示する。「最新のダイジェスト」は維持する。

### 14.2 日別Archive

- 上部と最下部の両方で、1段目の方向移動グループに「← 前のダイジェスト」「次のダイジェスト →」、2段目の全体導線グループに「過去のダイジェスト」「最新のダイジェスト」を左寄せの縦二段構造で置く(BL-028, Version 1.6; §6.4参照)。リンク文言に日付を含めない。
- カレンダー上の前日・翌日ではなく、検証を通過したdaily JSONの日付一覧に存在する日だけをリンク対象にする。日付欠損を飛び越える。
- 最古の日は「前」を表示せず、最新の日は「次」を表示しない。方向移動グループが空になる場合はグループ自体を描画しない。
- 前後日が一つもない場合も全体導線グループは上部と最下部に表示する。
- daily JSONを書き換えずに表示を生成する。

## 15. PCと390pxモバイル

現在の基本レイアウトはPCと390pxでユーザー受入済みである。

- 本文ブロックは最大`680px`で中央寄せし、左右paddingは主に`12px`、カード内部は`14px 16px`とする。
- 記事カードはPC／390pxとも1列で、タイトルは折り返し、関連タグと脆弱性情報は`flex-wrap`する。
- 600px以下ではdashboardの重要度／確認目安を2列から1列へ変更する。
- アンカー移動時のsticky headerとの重なりを避けるため、`scroll-margin-top`は通常`218px`、600px以下`226px`である(BL-028のナビゲーション二段化によりsticky header実高が増えたため調整)。
- 390pxは受入対象のviewport幅であり、CSS breakpointそのものは600pxである。
- 現行ヘッダーは600px以下でもstickyで同じpaddingを使い、圧縮しない。
- 現行の英語原題はモバイルでもclampせず自然に折り返し、原題の一部を省略しない。
- ナビゲーションの方向移動グループと全体導線グループは390pxでも区別できるDOM構造を維持し、自然に折り返す。横スクロール、リンクの重なり、不自然に狭いタップ領域を生じさせない。
- 収集元一覧はPCで3列、600px以下で1列とし、同じ`ul`／`li`構造のまま名称を省略せず自然に折り返す。390pxで横スクロールや項目の重なりを生じさせず、タップ対象ではない項目を大きなchip状領域にしない。

## 16. 空状態・欠損状態・例外状態

| 状態 | 確定している表示 |
|---|---|
| 掲載0件 | 優先確認は「本日の優先確認対象はありません。」、dashboardは掲載0件・各軸0件・「該当する記事はありません。」、記事一覧は「本日の新着はありません。」 |
| Briefなし／全区分空 | 「本日の要点」全体を省略 |
| 優先確認0件 | セクションは残し、0件文言を表示。選定条件の注記は省略 |
| 分析なし／空／failed | 記事カード自体は残す。取得時summaryがあれば最大120文字と省略記号を表示し、有効な脆弱性factsは維持。assessment・AI分析・関連タグは値がなければ省略 |
| 重要度／確認目安の片方だけ欠損 | 存在する軸だけを表示し、`None`／`null`を露出しない |
| 取得元／日時欠損 | 存在する値だけを表示。両方なければmeta行を省略 |
| タイトル欠損 | 「無題」 |
| 不正または非HTTP(S) URL | 外部リンク要素を生成しない。記事本文は表示 |
| factsなし／不正 | 脆弱性情報の見出し・空枠を表示しない |
| Archive一覧0件 | 「公開済みのダイジェストはありません。」 |

掲載0件日は、現在テストされている優先確認、dashboard、記事一覧などの各セクション別の空状態を確定仕様として維持する。ページ全体を一つの専用空状態へ置き換えない。

## 17. リンク・focus・anchor・アクセシビリティ

- 文書言語は`<html lang="ja">`とし、タイトル部分には判定できる範囲で`lang`属性を付ける。
- 外部入力はHTML escapeし、外部リンクは`http`／`https`だけを許可する。
- 新しいタブで開く外部リンクには`target="_blank" rel="noopener noreferrer"`を付ける。
- 優先確認の内部リンクは`#article-N`へ移動し、対象カードは`:target`の青い境界とshadowで位置を示す。
- sticky headerを考慮した`scroll-margin-top`を維持する。
- 関連タグは操作要素に見せず、キーボードfocus対象にしない。
- ブラウザ既定のfocus表示を維持し、専用の`:focus-visible`意匠は追加しない。outlineやfocus表示を消してはならない。
- 将来focus意匠を変更する場合は、ブラウザ既定と同等以上に明確な代替表示を同時に定義する。
- 現行はlink hoverにunderlineを出す。

## 18. 受入例・チェックリスト

### 18.1 代表状態

- [ ] PC幅と390pxで、表示順が本日の要点 → 優先確認 → dashboard → 本日の情報になっている。
- [ ] dashboardは単一ブロックで、重要度と確認目安が別軸、カテゴリが補助行になっている。
- [ ] 優先確認がある場合、理由付き索引から同じ番号の記事カードへ移動できる。
- [ ] 優先確認0件の場合、「本日の優先確認対象はありません。」だけが適切に表示される。
- [ ] 通常カードはvariant Bで、取得元／日時と重要度／確認目安がpillにならず、関連タグだけが下部に残る。
- [ ] 関連タグをクリック・Tab移動しても操作対象にならない。
- [ ] CVE／CVSS／KEVがある記事では、客観情報がAI分析区分の間に独立表示される。実データ例は2026-07-15のCVE-2026-56155。
- [ ] 掲載0件で、優先確認・dashboard・記事一覧の現行空状態が壊れない。
- [ ] トップページで、前日が存在する場合も欠落をまたぐ場合も「← 前のダイジェスト」が最も新しい存在日へ移動し、日付を表示しない。
- [ ] 過去日がなくても「過去のダイジェスト」は残り、PC／390pxとも横スクロールがない。

### 18.2 Archiveと日時

- [ ] Archive一覧は日付、記事数、重要度「高」の件数だけを表示する。
- [ ] 2026-07-14のような中間日で、上部と最下部の「← 前のダイジェスト」「次のダイジェスト →」が実在Archiveへ移動する。
- [ ] 最古日に「前」、最新日に「次」がない。
- [ ] 前のみ、次のみ、前後なしの場合も、上部と最下部の「最新のダイジェスト」「過去のダイジェスト」は残る。
- [ ] 日付欠損をまたぐ場合、カレンダー上の隣の日ではなく実在する直前・直後へ移動する。
- [ ] トップページと日別Archiveで同じ4用語を使い、廃止文言やナビゲーション日付が生成HTMLに残らない。
- [ ] `article-meta`時刻はJSTである。同じ瞬間は通常生成とdaily JSON復元で一致する。
- [ ] 受入済み実例として、トップページのWP2Shellは`07/18 06:20`、Gold Eagle Clearinghouseは`07/17 22:00`である。

### 18.3 変更時の回帰確認

- [ ] 関連する静的・HTML生成テストとfull unittestが成功する。
- [ ] PCと390pxで情報欠落、横スクロール、不自然な折返し、sticky headerによるanchor隠れがない。
- [ ] 時刻以外の記事内容、記事順、Brief、分析結果、件数を意図せず変更していない。
- [ ] `git diff --check`が成功し、許可されていない生成物を変更していない。

## 19. 未決事項

**現時点の未決事項: なし。**

将来別スコープで再検討できることは、Version 1.3の未決事項を意味しない。確定仕様を変更する場合は、第20章の変更管理に従い、新しいユーザー判断とSupersedes記録を必要とする。

### 19.1 今回解決した7項目の決定表

| 項目 | Version 1.0の決定 | 反映箇所 |
|---|---|---|
| AI利用注記 | 現行UIには追加せず、記事カード単位・分析区分単位の注記も採用しない。将来Aboutや公開導線を別スコープで設計する場合に改めて裁定する | 3.1 |
| モバイルsticky header | 600px以下も現在のstickyとpaddingを維持し、圧縮しない。anchor offsetはBL-028のナビゲーション二段化に伴い調整済み | 6.2、15 |
| ヘッダー絵文字 | `🔐`を維持する。BL-006のMonomi Digestへのブランド移行後も置換していない | 6.1 |
| モバイル英語原題clamp | 採用せず、行数制限なしの自然折返しを維持し、原題を省略しない | 11、15 |
| KEV表示形状 | 現行のアンバー系pillを、客観的かつ重要なKEV掲載状態の例外的強調として維持する | 13 |
| 掲載0件日の全体表示 | 現在の各セクション別の空状態を維持し、専用の一括空状態へ置き換えない | 16 |
| focus意匠 | ブラウザ既定のfocus表示を維持し、専用`:focus-visible`を追加せず、outlineやfocus表示を消さない | 17 |

7項目へのユーザー裁定は、原文のまま次のとおりである。

> 「7点ともこの方針でOK」

### 19.2 採用・実装済みだったFable 5論点

| Fable 5の論点 | 現在の扱い | 根拠 |
|---|---|---|
| Briefのアンバー枠 | 現行実装に存在する | `.brief-box`の`#9e6a03`境界。状態行自体はアンバーにしない |
| 優先確認が埋まった状態 | dashboard v2とともに実装・受入済み | SD-012、PR #17、`ImportantItemsTest` |
| KEV掲載記事の実表示 | 実装済みで実データにも存在する | 2026-07-15 ArchiveのCVE-2026-56155、`VulnerabilityFactsHtmlRenderTest` |

「採用・実装済み」は、少なくとも現行`main`で実装を確認できる区分である。KEV表示形状は今回の7項目の裁定で現行pillの維持まで確定した。

### 19.3 後のユーザー判断で置換・不採用となった論点

| Fable 5の論点 | 後の確定仕様 | 根拠 |
|---|---|---|
| 日本語訳を主見出し、英語原題を副行にする案 | 英語原題を主見出し、日本語訳を副行にする | SD-012／SD-013、受入済みvariant B、`article_title_parts()` |
| 関連タグの全面削除案 | variant Aを採らず、variant Bとして関連タグをカード下部へ残す | ユーザーの明示的B案選択、SD-013、BL-002／BL-003 |

### 19.4 Fable 5成果物に関する履歴上の注意

リポジトリ内にはFable 5レビュー成果物そのものが保存されていない。このため、Draft 0.1作成時には次の提案詳細をリポジトリだけから復元できなかった。

- KEV表示についてFable 5が提案した正確な形状、色、文言
- AI利用注記の正確な文言と配置
- sticky header圧縮量、英語原題clamp行数
- Fable 5が推奨したfont-size、spacing、radius、色コード、breakpointの完全な値一覧
- 掲載0件日の提案レイアウトの具体的な表示順と残す情報

これらを推測で補わず、Version 1.0ではユーザーが承認した現行UI維持の方針を確定仕様とした。この履歴上の証跡欠落は、現在の未決事項を意味しない。

## 19.5 サイト説明とAboutページ（Version 1.8、Draft）

### 19.5.1 目的

公開トップページは、サイト名の直後に日次コンテンツが始まり、「誰向けの何のサイトか」が読み取れなかった。[BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策) Phase A-1で、トップに短いサイト説明を置き、詳細はAboutページへ分離する。

### 19.5.2 トップページのサイト説明

- **トップページにのみ表示する。** 日別Archive・Archive一覧には表示しない。日別Archiveは当時の記録の再現が目的であり、現在のサイト説明を持たない。
- sticky header（`<header>`）の**外側**に置く。headerの直後、「本日の要点」の**前**。
- 本文は次の2文とする（ユーザーが2026-08-14に承認した文言）。

  1. 金融機関のサイバーセキュリティ担当者・管理職・担当役員向けの日次ニュースダイジェストです。
  2. 国内外の公開情報を収集し、重要度・確認目安・金融機関との関連・確認すべきことを整理しています。

- その下にAboutページへの導線を**1箇所だけ**置く。文言は「このサイトについて →」。
- **トップページの説明はAI利用に言及しない。** AIの説明はAboutページだけが持つ。
- Aboutリンクをarchive navigation（方向移動／全体導線）へ追加しない。analytics footerへも追加しない。サイト全体で導線は1箇所である。

実装は`fetch.py`の`render_site_intro_html()`が生成し、`build_html(intro_html=...)`へ明示的に渡したcall siteだけが表示する。既定は非表示であり、日別Archiveの既存呼び出しは変更していない。

### 19.5.3 Aboutページ

- `docs/about.html`を**静的ファイル**として置く。日次generatorは生成せず、Archive再生成の削除対象にもならない。
- 情報構造は3節とする。導入（対象読者と目的、整理する5項目）／「情報の整理とAIの利用」／「原記事との関係」。
- Aboutからトップへ戻る簡潔な導線を持つ。
- **運営者情報は掲載しない。**
- 重複・弁解的な説明（「処理の失敗ではない」等）、独立した「掲載について」節、同趣旨の言い換え反復、法的な断定は置かない。
- 既存のdark UIへ揃える。新しいframework・JS・client-side routingは追加しない。About表示に必要な最小限のCSSだけを持ち、`build_html()`のstyle blockを丸ごと複製しない。
- **既存のsite-wide analytics契約をそのまま適用する。** [SD-032](DECISIONS.md#sd-032--adopt-cloudflare-web-analytics-and-google-search-console-for-bl-034)のCloudflare Web Analytics beaconとanalytics disclosure footerを、generatorの`render_cloudflare_web_analytics_html()`／`render_analytics_footer_html()`の出力そのままで持つ。About専用のtoken・送信先・文言は定義しない。

### 19.5.4 AI-use note原則（3.1）との関係

AboutページのAI説明は[SD-034](DECISIONS.md#sd-034--explain-the-sites-ai-use-on-a-dedicated-about-page-only)が承認したものである。3.1が禁止する**サイト全体へのgenericな「AIを利用しています」badge／alertではなく**、全記事へのuniform AI note・各分析sectionへの反復labelでもない。[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)が「将来Aboutや公開導線を別スコープで設計する場合に改めて裁定する」と留保した論点を、SD-034が決着させた。[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)のsource-policy-required attributionは変更せず、Aboutの説明とは目的・scopeが異なる。footerへの一般AI説明は本scopeでは追加しない。

### 19.5.5 目視受入の対象

PC 1280pxと390pxで、トップページとAboutページの計4画面を目視受入の対象とする。Version 1.8は受入前はDraftであり、受入時にApprovedへ移す。

## 20. 変更管理

1. UI変更を行うチケットは、着手時に本書の確定仕様、現行値、決定履歴を確認する。
2. 将来新しい未決事項が生じた場合はユーザー裁定前に実装しない。裁定内容はBACKLOGの原文・受入証跡と、必要に応じてDECISIONSへ記録する。
3. 受入済み仕様を変更する場合は、置換対象、変更理由、PC／390px、空状態、Archiveへの影響を明示し、DECISIONSの`Supersedes`関係を更新する。
4. DOM class、表示条件、具体的な設計値を変更した場合は、本書と対応する静的／HTML回帰テストを同じPRで更新する。
5. UI実装の受入では、少なくともPCと390px、優先確認0件／あり、分析欠損、KEVあり、Archive境界日と中間日を確認する。
6. `docs/`の再生成、daily JSON変更、prompt／schema／workflow変更は、UI仕様書更新だけを理由に行わない。各変更の承認範囲に従う。
7. Version 1.3は承認済みの確定仕様である。今回解消した7項目、ナビゲーション統一仕様、収集元フッターのプレーン表示を再び未決として扱わず、変更には新しいユーザー判断とSupersedes記録を必要とする。
8. Version 1.4はBL-006のブランド名変更（Security Digest→Monomi Digest、`🔐`維持、title／H1絵文字統一）を、2026-07-26のユーザーPC 1280px／390px目視受入により確定仕様とした。custom domain・DNS・canonical等（BL-007）およびAbout・meta description・analytics等（BL-009）は本書の対象外であり、Version 1.4では変更していない。
9. Version 1.5はBL-029の「本日の要点」子見出し（概況／重要・優先事項／確認事項）と記事カード見出し（概要／金融機関との関連／確認すべきこと）の再設計を記録したものであり、2026-07-27にユーザーがPC 1280px／390px計8画面を目視受入した（「8枚とも確認した。BL-029の見出し、重要・優先事項の2段落表示、過去Archiveへの適用、0記事日の表示に問題なし。BL-029として受入。」）。ARTICLE prompt・response schema・`ARTICLE_PROMPT_VERSION`・public daily JSON schemaは変更していない。[PR #60](https://github.com/matkei31/security-digest/pull/60) final head `a458888f45ff1521a0eb59117994ac3122fb2b83` は[Pull Request CI run 30231386446](https://github.com/matkei31/security-digest/actions/runs/30231386446)通過後、通常merge（squash・rebase不使用）でmerge commit `2a191828462731bf5204cdd83e867c0d29aec6e8`としてmainへ統合され、自動[Pages deployment run 30231414580](https://github.com/matkei31/security-digest/actions/runs/30231414580)が成功し、公開トップページ・記事あり日別Archive・0記事日別Archiveで新見出しの表示を客観確認した。
10. Version 1.6はBL-028のダイジェストナビゲーション配置再設計（A案「左寄せ二段・ラベルなし」）を記録したものであり、2026-07-27にユーザーがPC 1280px／390px計10画面を目視受入した（「10枚とも確認した。BL-028の左寄せ二段配置、前→次／過去→最新の順序、上部・下部ナビゲーション、単一方向ケース、PC 1280px／390pxの表示に問題なし。BL-028として受入。」）。SD-021のうち、PCで方向移動グループを左・全体導線グループを右端へ配置する契約と、日別Archiveの全体導線を`最新→過去`の順で表示する契約を部分的にsupersedeする。4文言・日付非表示・href・aria-label・前後日付選定ロジック・sticky headerの存在は変更していない。[PR #62](https://github.com/matkei31/security-digest/pull/62) final head `a723dadaa4282db98060e83ef981b776b5742445` は[Pull Request CI run 30237446269](https://github.com/matkei31/security-digest/actions/runs/30237446269)通過後、通常merge（squash・rebase不使用）でmerge commit `fae9b682c97106c4ff9b45507aebf18db09fd77a`としてmainへ統合され、自動[Pages deployment run 30237477070](https://github.com/matkei31/security-digest/actions/runs/30237477070)が成功し、公開トップページ・記事あり日別Archive（上部・下部）・Archive一覧・最古日で新しい左寄せ二段配置の表示を客観確認した。公開anchor確認として、記事あり日別Archiveの`#article-1`遷移をPC 1280px・390px相当で実施し、sticky header下端と記事カード上端の間に正の余白（PC 17px、390px 25px）があり見出しが隠れないことを確認した（技術的な公開後確認であり、ユーザー目視受入の対象ではない）。
11. Version 1.7はBL-036（Fable 5レビューR-01）に基づき、BL-032で既に実装・稼働していた記事カードの`.article-attribution`(source policy別のattribution note)へ、低強調のCSS(font-size 10px、color `#768496`、background／border／pillなし)を追加する。BL-036がruntime側に加えた変更はこのCSSだけであり、attribution文言・mode分岐・DOM順序（AI analysisの後、元記事CTAの前）・HTML escape・URL安全性は変更していない。3.1のAI-use note原則を、サイト全体への一律generic AI note禁止（変更しない方針）と、source usage policyが要求するsource別・mode別attribution（BL-032実装済みの表示を[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)の「記事カード単位のAI-use noteを採用しない」という部分に対する限定例外として正式に認めたもの）とに区別して明示する。2026-08-04、ユーザーがPC 1280px／390pxのローカルreview screenshots(`bl036-attribution-page-1280px.png`、`bl036-attribution-page-390px.png`、`bl036-attribution-card-1280px.png`、`bl036-attribution-card-390px.png`、`bl036-attribution-card2-link-1280px.png`、`bl036-attribution-card2-link-390px.png`の計6画面)を目視受入した（原文「おk」、原文と解釈の記録は3.1・本章冒頭を参照）。[BL-036](BACKLOG.md#bl-036--記事カードのsource-attribution注記を低強調表示へ整える)の受入記録commitで新規[SD-033](DECISIONS.md#sd-033--allow-source-policy-required-article-attribution-as-a-limited-exception-to-the-generic-ai-note-ban)を追加し、SD-016のAI-use note条項だけを限定的にsupersedeした（SD-016のgeneric AI disclosure禁止と他の6項目は対象外であり、この限定例外によって変更しない）。Version 1.7は2026-08-04付でApprovedである。accepted implementation head `12a6f502973c78e21dbe0b209073f824731a3e5d`、[PR #76](https://github.com/matkei31/security-digest/pull/76)。

### 20.1 版履歴

| 版 | 状態 | 内容 |
|---|---|---|
| Draft 0.1 | 初稿 | 確定仕様と未決事項を統合した初稿 |
| 1.0 | 承認済み | 7項目のユーザー裁定を反映し、未決事項を解消して承認 |
| 1.1 | 承認済み | BL-022の直前公開ダイジェストリンク、日付欠落時の選択、ラベル、responsive配置を追加 |
| 1.2 | 承認済み | ナビゲーションの4用語を統一し、リンク文言の日付を廃止し、方向移動と全体導線を左右の別グループへ整理 |
| 1.3 | 承認済み | 収集元フッターの取得元別カラーとpill表現を廃止し、PC 3列／600px以下1列のプレーンテキスト一覧へ変更 |
| 1.4 | 承認済み | BL-006でSecurity DigestからMonomi Digestへブランド名を変更し、`🔐`は維持したまま、トップページと日別Archiveのtitle／H1の絵文字表記を統一した |
| 1.5 | 承認済み | BL-029で「本日の要点」子見出しと記事カード見出しを再設計し、「重要・優先事項」を同一記事のsummary／financial_impactペアから構成する契約へ更新した。2026-07-27、ユーザーがPC 1280px／390px計8画面を目視受入した |
| 1.6 | 承認済み | BL-028でダイジェストナビゲーションをA案「左寄せ二段・ラベルなし」へ再設計し、日別Archiveの全体導線を`過去→最新`の順へ変更した。2026-07-27、ユーザーがPC 1280px／390px計10画面を目視受入した |
| 1.7 | 承認済み | BL-036(Fable 5レビューR-01)でBL-032実装済みの`.article-attribution`へ低強調CSSを追加(runtime変更はCSSのみ)。AI-use note原則(3.1)のうち一律generic note禁止は維持し、BL-032実装済みのsource-policy-required attributionをSD-016の一部への限定例外として正式に認めた(SD-033、SD-016のgeneric AI disclosure禁止と他の6項目は変更なし)。2026-08-04、ユーザーがPC 1280px／390px計6画面を目視受入した |
| 1.8 | Draft | BL-009 Phase A-1でトップページにサイト説明（2文＋「このサイトについて →」1箇所）を追加し、`docs/about.html`を静的ページとして新設した。introはトップのみでsticky header外、「本日の要点」の前。日別Archive・Archive一覧には表示しない。AboutのAI説明はSD-034で承認し、3.1のgeneric AI badge/alert禁止・uniform per-article note禁止・反復label禁止は維持する（SD-033は変更なし）。ユーザー目視受入前のDraft |
