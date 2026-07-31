# Monomi Digest — Source Usage Policy

- **Version:** 0.1
- **Status:** Approved
- **As of:** 2026-07-31
- **Scope:** Monomi Digestの外部取得元(RSS/Atom/structured JSON)、その内容のAI(Gemini)入力、`data/`・`docs/`への保存、公開要約、出典表示。
- **免責:** 本文書は法律意見ではない。各取得元の公式に公開された利用規約・ライセンス・FAQ等をChatGPTが2026-07-29に確認した内容、および2026-07-30発効のGoogle利用規約についてChatGPTとrepository ownerが2026-07-30に確認した内容に基づく、運用上の安全側判定の記録である。最終的な法的判断は、必要に応じて別途の法務確認によって行う。本文書のいずれの記述も、特定の取得元が現行実装によって規約違反を犯していると断定するものではない。

---

## 1. Purpose

- 包括的な取得元規約監査(BL-030で暫定停止したCrowdStrike・Cloudflareを含む、全17取得元)の結果を、repository内の監査記録として固定する。
- 各取得元についてcontent usage mode(5種類、後述)を提案し、根拠となる公式情報・確認日・確信度・未解決事項・再確認契機を記録する。
- BL-030で削除した非公式翻訳経路と、現在の独自ドメイン(`monomidigest.com`)運用を、`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`へ反映するための入力情報を提供する。
- 本Ticket(BL-031)は監査・方針文書の整備のみを対象とする。ここで提案するcontent usage modeをproductionコードで強制する実装(`source_definitions.json`への`content_usage_mode`等のfield追加、`fetch.py`側の共通処理)は、後続のBL-032で行う(BL-032は現在Draft実装済み・ユーザー受入前。10章参照)。

## 2. Legal and policy framework

- 本文書は次の階層で情報を扱う: (1) 各取得元の公式に公開された利用規約・ライセンス・FAQ、(2) Gemini APIの利用規約(Google AI Studio / Unpaid Services と Paid Services の区別)、(3) それらを踏まえた運用上の安全側判定。
- 公式規約の解釈に幅がある場合は、より保守的な側(利用を制限する側)を採用する。
- 「不明」「確認できなかった」事項は、断定的に「禁止」または「許可」とせず、`unresolved_issue`として明示し、後続の書面確認・追加調査を要求する形で記録する。
- 本文書はChatGPT側の外部調査結果を転記したものであり、本PRの作業自体は外部URLへの新規アクセスを行っていない。

## 3. Content usage modes

Monomi Digestの取得元は、次の5つのcontent usage modeのいずれかへ分類する。

### A. `structured_open`

**用途:** 公式のオープンライセンス、public-domain相当、または明示的なAPI利用条件がある取得元。

**許可:**
- 公式RSS description／summaryの取得
- 公式構造化データ(JSON API等)の取得
- Gemini ARTICLE分析への入力
- bounded raw excerpt(最大200文字)の保存
- AI要約・分析の公開

**禁止・条件:**
- `content:encoded`／Atom contentは、明示的な許可がない限り禁止する。
- 取得元が第三者著作物を含む場合(第三者引用・埋め込み等)、その部分は対象外とする。
- source固有のattribution(下記6章)を必須とする。

### B. `feed_summary`

**用途:** RSS利用は明示的に認められている、または公式に案内されているが、記事本文の再利用・AI公開要約まで包括的に許可されているとまでは確認できない取得元。

**許可:**
- title、date、source、original URL
- RSS description／summaryのみ(feed-native rich contentは含まない)
- Gemini ARTICLE分析への入力は、後述5章のGemini Paid Service確認を満たす場合のみ

**禁止・条件:**
- `content:encoded`／Atom contentは禁止する。
- 記事ページへの追加HTTP取得(scraping)は禁止する。
- publisher由来のexcerptをdaily JSONへ永続保存することは禁止する(bounded raw excerptであっても、この分類では保存しない)。
- Gemini入力へ回す場合、最大1000文字のtransient input(保存しない一時的な入力)に限定する。
- Gemini Paid Service状態が確認できない間(`gemini_data_use_status: unpaid` または `unknown`)は、`metadata_only`と同じ挙動として扱う。
- 出典・原記事リンク・「Monomi DigestによるAI要約・分析」の表示を必須とする。

### C. `limited_feed_analysis`

**用途:** 公式RSSの提供自体は確認できるが、記事本文の再利用・AI公開要約まで包括的に許可されているとまでは確認できず、かつ`metadata_only`へ一律に格下げすると実用性が大きく損なわれる取得元に対する、**明示的な運用上のリスク受容分類**。取得元が利用を明示的に許諾したと判断したものではない(2章参照)。

**許可:**
- 公式RSSのみ(記事ページへの追加アクセスは含まない)
- 原題、取得元、公開日時、original URL
- RSS descriptionのみ、最大1000文字
- Geminiへの一時入力(transient input、保存しない)。後述5章のGemini Paid Service確認を満たす場合のみ。
- 短い事実整理、金融機関との関連性、importance／urgency／category、recommended_actionsの生成
- 通常の記事カードおよびToday's Briefへの掲載

**禁止・条件:**
- 記事ページへの追加HTTP取得(scraping)は禁止する。
- `content:encoded`／Atom contentは禁止する。
- publisher由来のdescription／excerptをdaily JSONへ永続保存することは禁止する。
- 原見出しの日本語翻訳表示(直訳に近いタイトル生成)は禁止する。
- 長い直接引用は禁止する。
- 原記事を読まなくても済んでしまう代替的要約(記事の代替物になり得る詳細さ)は禁止する。
- Gemini Paid Service状態が確認できない間(`gemini_data_use_status: unpaid` または `unknown`)は、`metadata_only`と同じ挙動として扱う。
- 出典・原記事リンク・「Monomi Digestが公式RSSの概要をもとに生成したAI分析」の表示を必須とする。

**BL-032実装状況(Draft、ユーザー受入前。10章参照):**
- Gemini入力を最大1000文字、出力(要約等)にも文字数上限を設ける実装済み(`daily_json.py`の`TRANSIENT_INPUT_MAX_CHARS`・`OUTPUT_FIELD_MAX_CHARS`)。
- 原文との長い連続一致等、7章のoutput-similarity/quotation controlsに違反する出力を検出した場合、metadata-only相当の簡易表示へfallbackする実装済み。
- 原題・取得元・元記事リンクの必須表示、および「詳細と正確性は元記事で確認」等の限界注記の表示実装済み。
- 利用規約変更・machine-readable instruction変更・権利者からの申出等を契機に、`metadata_only`または`disabled_legal_review`へ即時降格できる運用手順(`SECURITY_OPERATIONS.md`参照)は引き続き人による運用手順であり、コード上の自動trigger化はしていない。

### D. `metadata_only`

**分類の意味:** 公式Feedからの原題・取得元・公開日時・原記事URLという最小メタデータの取得・リンク掲載は継続する。一方、description等の内容利用、外部AI処理、AI評価・要約の公開について十分な根拠を確認できていないため、production上の処理を最小メタデータに限定する区分である。`metadata_only`は自動処理を完全に行わない区分ではなく(最小メタデータの自動取得は継続する)、また人によるページ閲覧や当該source自体の独自の報道・論評を禁止する趣旨でもない。

**許可:**
- title、published date、source name、original URLという最小メタデータの自動取得・保存・リンク掲載。

**禁止:**
- description、summary、`content:encoded`、Atom contentのGeminiへの送信。
- ARTICLE分析(importance／urgency／financial_impact／recommended_actions等の生成)。
- publisher由来の本文・抜粋の保存。
- 原文に基づく日本語タイトル翻訳(Gemini生成の`title_ja`を含む)。

**Cisco Talosの残余リスク:** Cisco Site Content利用規約(internal use限定)がブログドメイン(`blog.talosintelligence.com`)へ直接適用されるかどうかは未解決であり(9章参照)、この分類が許可する最小メタデータの自動取得自体にも残余リスクが残る。適用が確認された場合は、`metadata_only`にとどまらず`disabled_legal_review`への降格を含めて再評価する。

**表示(BL-032実装状況、Draft・ユーザー受入前。10章参照):**
- 通常の記事一覧(AI評価済み記事)へ公開日時順で混在させ、AI分析カードとは異なる簡易リンクカード(原題・取得元・公開日時・原記事リンクのみ、description・AI翻訳・importance・urgency・category・tags・financial_impact・recommended_actions・factsを表示しない)として表示する実装済み。
- 掲載総数には含めるが、Today's Brief、importance／urgency／category集計、AI成功率の分母には含めず、「未判定」にも入れない実装済み。意図的なpolicy非評価(この区分に属すること)と、AI処理の失敗(`fallback`/`failed`)を混同しない。`fetch.py`の`select_brief_eligible_items()`が、Brief生成が対象とする記事集合(入力・trusted context・状態行・未判定件数・source ID・優先事項・provenance)を一元的に決定する共通helperとして実装済みであり、compose_extractive_brief()内のこれらの処理はすべて同じfiltered集合を参照する。
- AI評価済み記事と混同しないUI上の区別を実装済み。

### E. `disabled_legal_review`

- 外部ネットワークリクエストを行わない。
- `RSS_FEEDS`や取得処理から除外する(`enabled: false`)。
- 明示された再有効化条件(`activation_condition`)を満たすまで停止を維持する。

### `limited_feed_analysis`採用理由(リスク受容の明示)

`the_hacker_news`・`krebs_on_security`の2 sourceは、次の理由により、元仕様(RSS description+AI分析)を無修正で継続するのではなく、`metadata_only`へ一律に格下げするのでもなく、`limited_feed_analysis`という第3の運用形態を採用する。

- 両sourceとも公式RSSの提供自体は確認できるが、包括的なAI要約・公開再利用の許諾までは確認できていない(The Hacker Newsは"All Rights Reserved"表示、Krebs on Securityは包括的な公式再利用条件が未発見)。
- 一方、`microsoft_security`・`cisco_talos`も含めた4 source全てを`metadata_only`へ一律に格下げすると、記事本文相当の情報を一切AI処理できなくなり、実用性が大きく損なわれる。
- そこで、Microsoft SecurityとCisco Talosは`metadata_only`のまま維持し、The Hacker NewsとKrebs on Securityは、公式RSS descriptionへの限定・rich content/記事ページ取得の禁止・原文保存の禁止・近接翻訳や長い引用の禁止等、高リスクな処理を除去したうえで、`limited_feed_analysis`として限定的に運用を継続する。
- これは「利用条件を確認し許諾を得た」という判断ではなく、明示的な**運用上のリスク受容**である。本文書のいずれの記述も、この2 sourceについて規約上問題がないと断定するものではない。
- 将来、利用規約の変更、machine-readable instructionの変更、Feed経路の変更、権利者からの訂正・削除・停止の申出、output policy違反、attribution欠落、または当該source固有の利用条件の発見があった場合は、`metadata_only`または`disabled_legal_review`へ即時に降格できるようにする(`SECURITY_OPERATIONS.md`のsource suspension手順を参照)。

---

## 4. Source-by-source audit matrix

`checked_at`は各source行に個別列として記録する(ChatGPTまたはrepository ownerによる公式情報確認日。`google_tag`・`mandiant`は2026-07-30発効のGoogle Terms確認を反映して2026-07-30、他15 sourceは2026-07-29)。今後sourceごとに再確認日が異なり得るため、全件同じ日という表外の一括記述だけを正本とせず、行単位の`checked_at`列を正本とする。以下の全17件で`allow_rich_content`は`false`とする(BL-032のDraft実装〔ユーザー受入前〕により、この監査表の値が`fetch.py`のpolicy gateへ実際に読み込まれ、全17 sourceで`content:encoded`／Atom content共通処理〔従来のSD-002共通経路〕を経由しないことが強制されている。詳細は[BACKLOG.md](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)・[`test_content_usage_policy.py`](test_content_usage_policy.py)を参照)。

`official_evidence_url`にはURLそのもの、または証跡が存在しないことを示す単純な`—`だけを記載する。括弧書きの説明文・証跡の性質・未特定理由等、URLではない文言は`official_evidence_url`欄に入れず、`unresolved_issue`または`evidence_type`側に記載する。`evidence_type`はその性質を次のいずれかで明示する: `terms`(利用規約)、`license`(ライセンス)、`copyright_policy`(著作権ポリシー)、`faq`(公式FAQ)、`rss_usage_guidance`(RSS利用案内)、`source_page`(規約文書ではない参考ページ)、`terms_not_found`(包括的な公式terms文書が見つからなかった)、`terms_not_identified`(terms文書自体が特定できていない)、`terms_update_notice`(既存termsの改定・発効案内)。複数の証跡がある場合は、`official_evidence_url`・`evidence_type`の両方のセルで同じ個数のURL／typeを`；`区切りで同じ順序に並べ(1対1で対応させ)、主たる証跡でないものには`(supporting)`を付す。同一typeの証跡が複数URLにまたがる場合(例: 同種のRSS利用案内が複数ページに分かれている場合)は、`evidence_type`側を1つだけ記載し、対応するURLを`official_evidence_url`側に`；`区切りで複数列挙してよい(この場合のみ個数は一致しなくてよい)。

### structured_open (5件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fsa | 金融庁 | structured_open | true | true | true | false | true | true | true | 6章参照(PDL 1.0) | https://www.fsa.go.jp/rules/index.html | license | 2026-07-29 | high | なし | 個別資料でPDL以外のライセンスが明記された場合 |
| nist | NIST | structured_open | true | true | true | false | true | true | true | 6章参照(NIST source credit) | https://www.nist.gov/copyrights-disclaimers | copyright_policy | 2026-07-29 | high | 個別資料にcopyright表示がある場合の除外運用の具体化 | NIST copyright policyの変更 |
| ncsc | NCSC | structured_open | true | true | true | false | true | true | true | 6章参照(OGL v3) | https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions | terms | 2026-07-29 | high | なし | OGLのversion変更 |
| cisa_kev | CISA KEV | structured_open | true | true | true(shortDescriptionのみ) | false | true | true | true | 6章参照(CC0) | https://github.com/cisagov/kev-data | license | 2026-07-29 | high | なし | ライセンスファイル(LICENSE)の変更 |
| nist_nvd | NIST NVD | structured_open | **false**(standalone article collection) | **false**(standalone) | – | false | – | – | – | 6章参照(NVD notice) | https://nvd.nist.gov/developers/terms-of-use | terms | 2026-07-29 | high | standalone記事収集の再有効化は本Ticketの対象外。現行のNVD CVE facts経路(`vulnerability_facts.py`)のみをpolicy上許可対象とし、`nist_nvd`のstandalone article collection自体の`enabled`は変更しない | NVD API Termsの変更 |

**注記(nist_nvd):** policy分類上は`structured_open`(NVD API Termsがsearch/display/analyze/retrieve等のサービス開発を想定しているため)だが、これは`nist_nvd`の`enabled`を`true`へ戻すことを意味しない。現状すでに稼働しているCVE facts取得経路(`vulnerability_facts.py`の`fetch_nvd_batch`等)は、この監査によって新たに許可されるものではなく、既存のまま変更しない。

### feed_summary (4件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| jpcert_cc | JPCERT/CC | feed_summary | true | true | true | false | conditional(5章Gemini Paid Service gate) | false | conditional(gate) | 6章参照 | https://www.jpcert.or.jp/rss/index.html ； https://www.jpcert.or.jp/guide.html | rss_usage_guidance | 2026-07-29 | high | 転載・再配布時の連絡要否の具体運用 | JPCERT/CC利用ガイドの改定 |
| ipa | IPA | feed_summary | true | true | true | false | conditional(gate) | false | conditional(gate) | 6章参照 | https://www.ipa.go.jp/publish/faq.html ； https://www.ipa.go.jp/siteinfo.html | faq | 2026-07-29 | medium | 個別資料ごとの利用条件が本ポリシーと優先関係を持つ場合の具体運用 | IPA著作権FAQの改定 |
| mandiant | Mandiant | feed_summary | true | true | true | false | conditional(gate) | false | conditional(gate) | 6章参照 | https://policies.google.com/terms?hl=en-US ； https://policies.google.com/terms/update/embedded ； https://cloud.google.com/blog/topics/threat-intelligence | terms(primary) ； terms_update_notice(supporting) ； rss_usage_guidance(supporting) | 2026-07-30 | medium | Google全体利用規約のmachine-readable instructions条件の具体適用範囲。1・2番目のURL(Google Terms本文・更新案内)が利用条件そのものの証跡であり、3番目のURL(Threat Intelligenceページ)はRSS提供を示す証跡にすぎず、それ自体はterms文書ではない(両者を混同しない)。2026-07-30発効版の内容を確認済みだが、一般規約のみでAI公開要約の包括的許諾があるとは断定しない(8章参照) | Google Terms(2026-07-30発効版)のさらなる改定; 公式Feed URL／Feed経路の変更; Google Cloud Threat Intelligence固有の利用条件の変更; robots.txt等machine-readable instructionsの変更; 公式RSS案内の変更・終了 |
| google_tag | Google TAG | feed_summary | true | true | true | false | conditional(gate) | false | conditional(gate) | 6章参照 | https://policies.google.com/terms?hl=en-US ； https://policies.google.com/terms/update/embedded | terms | 2026-07-30 | medium | 2026-07-30発効の新規約の内容を確認済み(8章参照)。machine-readable instructionsに反する自動収集を禁止する条件は継続しており、一般規約のみでAI公開要約の包括的許諾があるとは断定しない | Google Terms(2026-07-30発効版)のさらなる改定; 公式Feed URL／Feed経路の変更; Google Security Blog/Blogger固有の利用条件の変更; robots.txt等machine-readable instructionsの変更; 公式RSS案内の変更・終了 |

**注記(feed_summary共通):** `allow_ai_processing`／`allow_public_summary`はいずれも5章のGemini data-use gateに従属する。`gemini_data_use_status`は2026-07-29にowner verificationにより`paid_verified`となったため、このGemini側の条件自体は満たされた。ただし`gemini_data_use_status`が`unpaid`または`unknown`へ戻った場合は、実運用上`metadata_only`と同じ挙動として扱う(3章B参照)。取得元自身の規約条件(各sourceの`unresolved_issue`、`google_tag`／`mandiant`の2026-07-30発効Google Termsの内容等)はこの確認と無関係に別途維持される。この挙動はBL-032のDraft実装(ユーザー受入前)により`fetch.py`の実行時gateとして反映されている(10章参照)。

### limited_feed_analysis (2件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| the_hacker_news | The Hacker News | limited_feed_analysis | true | true | true | false | conditional(5章Gemini Paid Service gate) | false | conditional(gate) | 6章参照 | https://thehackernews.com/p/copyright-policy.html | copyright_policy | 2026-07-29 | medium | 公式RSSは存在するが、All Rights Reserved明記のため、RSS提供のみを根拠に本文再利用・AI要約の包括的許諾があるとは解釈しない。`metadata_only`ではなく限定的な運用上のリスク受容(`limited_feed_analysis`、3章C参照)として扱い、許諾を確認したとは断定しない | copyright policyの変更、権利者からの訂正・削除・停止申出 |
| krebs_on_security | Krebs on Security | limited_feed_analysis | true | true | true | false | conditional(gate) | false | conditional(gate) | 6章参照 | — ； https://krebsonsecurity.com/about-this-blog/ | terms_not_found ； source_page(supporting) | 2026-07-29 | low | 公式の包括的な再利用条件を確認できなかった(terms_not_found)。2番目のURL(Aboutページ)はterms文書ではなくsource page。「禁止」と断定せず、限定的な運用上のリスク受容(`limited_feed_analysis`、3章C参照)として扱う | 公式terms発見時、権利者からの訂正・削除・停止申出 |

**注記(limited_feed_analysis共通):** `feed_summary`と同様、`allow_ai_processing`／`allow_public_summary`は5章のGemini data-use gateに従属する。この2 sourceは「利用が明示的に許諾された」という分類ではなく、`metadata_only`への一律格下げによる実用性低下を避けるための、限定された運用上のリスク受容である(3章C、4章のリスク受容根拠を参照)。利用規約変更・machine-readable instruction変更・Feed経路変更・権利者からの訂正/削除/停止の申出・output policy違反・attribution欠落・source固有termsの発見のいずれかを契機に、`metadata_only`または`disabled_legal_review`へ即時降格する(`SECURITY_OPERATIONS.md`参照)。

### metadata_only (2件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| microsoft_security | Microsoft Security | metadata_only | true | true | false | false | false | false | false | 6章参照(source名・URLのみ) | https://www.microsoft.com/en-us/legal/terms-of-use | terms | 2026-07-29 | medium | RSS配信自体が本文再利用・AI公開要約の別段の許諾となるかは未確認 | Microsoft Terms of Useの改定 |
| cisco_talos | Cisco Talos | metadata_only | true | true | false | false | false | false | false | 6章参照 | https://www.cisco.com/c/en/us/about/legal/terms-conditions.html | terms | 2026-07-29 | low〜medium | **この規約が`blog.talosintelligence.com`へ直接適用されるかどうか不明** | 書面確認、またはTalos固有のterms発見 |

### disabled_legal_review (4件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cisa | CISA | disabled_legal_review | false | false | false | false | false | false | false | n/a(非公開) | — | terms_not_identified | 2026-07-29 | n/a | 広範な公式取得経路・利用条件が未確定なためURLが特定できていない(terms_not_identified)。HTTP 403の技術的理由に加え、CISA KEVとは別sourceとして扱う。既存`activation_condition`は`source_definitions.json`の`cisa`定義を参照(本表のURL欄には転記しない) | 既存`activation_condition`の4条件(`source_definitions.json`の`cisa`定義を参照) |
| crowdstrike | CrowdStrike | disabled_legal_review | false | false | false | false | false | false | false | n/a(非公開) | https://www.crowdstrike.com/en-au/legal/website-terms-of-use/ | terms | 2026-07-29 | high | なし(automated device/robot/spiderによるmonitor/copy、derivative works、public display、republish、download、store、transmitを明確に制限) | `source_definitions.json`の`crowdstrike.activation_condition`(BL-030で記録済み) |
| cloudflare | Cloudflare | disabled_legal_review | false | false | false | false | false | false | false | n/a(非公開) | https://www.cloudflare.com/policies/terms/ | terms | 2026-07-29 | high | なし(該当条件はTerms Section 8。AI用途botはrobots.txtで明示的allowed、かつAI用途bot専用User-Agentの両方が必要だが未充足) | `source_definitions.json`の`cloudflare.activation_condition`(BL-030で記録済み) |
| dark_reading | Dark Reading | disabled_legal_review | **false(本PRで変更)** | false | false | false | false | false | false | n/a(非公開) | https://www.informatechtarget.com/terms-of-use/ ； https://www.darkreading.com/ | terms ； source_page(supporting) | 2026-07-29 | high | なし(Informa TechTarget Termsがdata mining／robots等の抽出方法、derivative works、無断copy／distributionを明確に禁止。2番目のURLはsource pageであり、terms文書ではない) | `source_definitions.json`の`dark_reading.activation_condition`(本PRで新設) |

**件数集計:** structured_open 5、feed_summary 4、limited_feed_analysis 2、metadata_only 2、disabled_legal_review 4、**合計17**(`source_definitions.json`の定義総数と一致)。

---

## 5. Gemini data-use gate

Gemini APIの公式Terms(https://ai.google.dev/gemini-api/terms)より:

- **Unpaid Services:** submitted contentおよびgenerated responsesが、Google製品・機械学習技術の改善に使用され得る。human reviewerがinput/outputを読む・注釈する場合がある。
- **Paid Services:** active Cloud Billing accountに関連付けられたCloud Project経由でGemini APIを利用する場合、prompts／responsesは製品改善に使用されない。

**現在のMonomi Digestの状態:** `gemini_data_use_status: paid_verified`

**owner verificationの許容値:**
- `paid_verified` — active Cloud Billing accountに関連付けられたProject経由での利用が確認された。
- `unpaid` — Unpaid Servicesとして利用されていることが確認された。
- `unknown` — 未確認。

**owner verification記録:**
- **checked_at:** 2026-07-29
- **checked_by:** repository owner
- **verification method:** Google AI StudioのAPI Keys画面で、Monomi Digest productionで使用するAPIキーが属する`security-digest` Google Cloud Projectにactive billingが関連付けられ、「Tier 1・前払い」と表示されていることを確認した。
- **記録した情報:** 「`security-digest` Project」「active billing確認」「Tier 1・前払い」「owner確認日」のみ。APIキー名・APIキー末尾・APIキー値・Project ID・請求先アカウントID・課金額・画面のスクリーンショットはいずれもrepositoryへ保存していない。

**契約:**
- `gemini_data_use_status`が`paid_verified`になるまで、`feed_summary`および`limited_feed_analysis`分類のsourceのpublisher由来descriptionをGeminiへ送らない。上記owner verificationにより、この条件自体は満たされた。
- `unpaid`または`unknown`の場合、`feed_summary`および`limited_feed_analysis`は`metadata_only`と同じ挙動として動作させる。この`paid_verified`確認は、Gemini側のdata-use gateによる`metadata_only`強制を解除できることを意味するが、取得元自身の規約条件(各sourceの`official_evidence_url`／`evidence_type`／`unresolved_issue`、`google_tag`／`mandiant`の2026-07-30発効Google Termsの内容、`limited_feed_analysis`分類2sourceのリスク受容根拠(3章C、4章参照)等)は本確認と無関係に別途維持される。
- API key、請求情報、金額、アカウント画面のスクリーンショット等の機微情報はrepositoryへ一切保存しない。
- ownerは「active billingの有無」という非機密情報のみを回答すればよい(具体的な金額・アカウントID・契約詳細は不要)。

**本Ticket(BL-031)は監査・方針文書の更新にとどまり、このowner verification結果をproductionコードのenforcementへ反映する実装(`source_definitions.json`への`content_usage_mode`等のfield追加、`fetch.py`側の共通処理)は行わない。** この文書更新だけで現在のproduction挙動が変わるものではない。後続の[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)が、この確認結果を`feed_summary`および`limited_feed_analysis`有効化判断の入力として使用する実装を行った(現在Draft、ユーザー受入前。10章参照)。

---

## 6. Attribution requirements

| 対象 | 表示内容 |
|---|---|
| `fsa` | 「金融庁ウェブサイトをもとにMonomi Digestが加工」+ 原ページURL + 利用日 |
| `nist` | NIST source credit。third-party copyright表示がある個別資料は対象から除外する。 |
| `nist_nvd` | "This product uses the NVD API but is not endorsed or certified by the NVD." 加工した分析をNVD作成物であるかのように表示しない。 |
| `ncsc` | source acknowledgement + OGL v3 link。 |
| `cisa_kev` | "CISA KEV" + CC0の旨。 |
| `jpcert_cc` / `ipa` / `mandiant` / `google_tag`(`feed_summary`) | source name、original URL、「Monomi DigestによるAI要約・分析」の表示、要約・分析に正確性の限界がある旨。 |
| `the_hacker_news` / `krebs_on_security`(`limited_feed_analysis`) | source name、original title、original URL、「Monomi Digestが公式RSSの概要をもとに生成したAI分析」の表示、「詳細と正確性は元記事で確認」の旨、AI分析であって原文の転載・代替を目的としない旨。 |
| `metadata_only`分類の2source | source name、original title、original URLのみ。AIによる要約・評価を行っていない旨を明示する。 |
| `disabled_legal_review`分類の4source | 非公開のため表示なし。 |

**実装状況(BL-032、Draft・ユーザー受入前。10章参照):** 上表は監査上の要件記述であり、UI文言そのものではない。`fetch.py`の`render_structured_open_attribution_html()`が、`fsa`/`nist`/`ncsc`/`cisa_kev`/`nist_nvd`のsource_idごとに実際の表示(実URL・実日付・実免責文)を組み立てる(監査記述である`attribution_requirement`列の文字列をそのままUI文言として表示しない)。`fsa`の「利用日」はdigest生成日(JST、YYYY-MM-DD)を正本とする。`ncsc`のOGL v3リンクは、`source_definitions.json`の`ncsc.policy.attribution_url`(`https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/`)を正本とし、`safe_url()`でスキーム検証を通過した場合にのみリンク化する。この可否判定は`fetch.py`の`_can_render_structured_open_attribution()`が一元的に行い、`attribution_ok`(実装状況、7章参照)とHTML描画の両方がこの1つの関数だけを参照する。`attribution_url`が欠落・空・不正schemeの場合、リンクなしの平文へfallbackして公開を継続することはせず、`missing_attribution`としてmetadata-only相当へ自動downgradeする(fail-closed)。`fsa`/`nist`/`nist_nvd`/`cisa_kev`は固定文言のみで完結するため常に生成可能である。この5 source以外のstructured_open source_idが将来追加された場合も、対応する表示が実装されるまでattribution_okはfalseとなり、`missing_attribution`としてmetadata-only相当へ自動downgradeされる。

**Archive再生成時のattribution snapshot(BL-032実装状況、Draft・ユーザー受入前):** schema v2 daily JSON生成時、`ncsc`のstructured_open記事については、生成時点で実際に使用可能だった(source_definitions.json側で設定済み、かつ`daily_json.is_safe_attribution_url()`を通過した)attribution URLを`daily_json.build_article_entry()`が`policy.attribution_url`へsnapshotとして保存する。`is_safe_attribution_url()`は、記事リンク全般に使う`fetch.safe_url()`とは別の、このattribution snapshot契約専用のより厳密な検証であり、`urllib.parse.urlsplit()`でscheme(http/https)・netloc・hostnameがすべて存在することまで要求する(`https://`単体・`https:///missing-host`・`http://?query`のようなhostを持たない値は拒否する)。`fetch.py`の`digest_items_for_html()`は、Archive再生成時にこのsnapshotだけを`content_policy`へ復元し、現在のsource_definitions.jsonを参照しない。これにより、生成後にsource_definitions.jsonのNCSC設定が変更・削除されても、既存Archiveの再生成結果(AI分析カード・OGL v3リンク)は生成時点のまま変わらない。

`daily_json.validate_daily_digest()`は、schema v2でncsc・structured_open・ai_eligible=trueの記事について、このsnapshotが`is_safe_attribution_url()`を通過することを保存前に必須検証する(この保存前strict validationは緩めていない)。

`fetch.py`の`generate_archive_outputs()`は、Archive生成の直前に`daily_json.validate_daily_digest_for_archive_read()`(Archive読込専用のschema-version-awareなvalidator)を実行する。schema v2は保存前と完全に同じstrict validation(`validate_daily_digest()`、NCSC attribution snapshot検証を含む)をそのまま適用するが、schema v1(レガシー)は、現行の閾値・enum・field構成(例: 現行の`BRIEF_MAX_CHECK_ITEMS`、件数の相互整合性、field完全性)を実在ファイルへ遡及適用しない――これは、生成当時は正当だった実データ(例: 現行upper boundより多い件数のBrief check_itemsを保存している実在のschema v1ファイル)が、後日の閾値変更を理由に誤ってArchive生成対象から除外されないようにするためである。ただし単なる「トップレベル型・items・briefがdict/null」という緩い検証にとどまらず、`archive_summary_from_digest()`・`brief_for_html_from_digest()`等の下流処理が安全に描画するために前提とする最低限の型・構造は検証する(round 6): `digest_date`が`YYYY-MM-DD`形式かつ`datetime.date.fromisoformat()`で実在する暦日であること、`run`が存在する場合はdictで`total_items`は存在する場合bool以外の0以上intであること、`counts`が存在する場合はdictで`counts.importance`は存在する場合dict・`counts.importance["高"]`は存在する場合bool以外の0以上intであること、`brief`の`overview`が欠落/null/str・`important_highlights`/`discussion_points`/`check_items`が欠落/null/list(list要素はすべてstr)であること。`run`/`counts`/`brief`各fieldの欠落・nullは既存fallback(例: `run.get("total_items") or len(items)`)が安全なため許容する。この検証を通過しないdaily JSON(schema v1で上記型が不正な場合、schema v2でNCSC attribution snapshotが欠落・不正な場合等)は、その日付だけをArchive生成(日別Archive HTML・Archive一覧・index entryのいずれも)の対象から除外し、既存のstale Archive HTMLがあれば削除する――1件のmalformedなdigestが混在してもArchive生成全体は停止せず、他の正常なschema v1／v2 digestの生成・index更新は継続する。

除外の実際の契約は次のとおり: (1) 該当日付の日別Archive HTMLは生成しない。既に(過去の有効な生成から)同じ日付のファイルが存在する場合は削除する。(2) Archive一覧HTMLには掲載しない。(3) `data/index.json`では、当該digestのエントリ自体は残すが、`archive_path`を`null`にする(既存index契約に合わせ、記録を削除せず`archive_path:null`とする)。`digest_items_for_html()`側のitem単位のdowngrade(記事カード・Dashboard集計・優先確認等、`downgrade_reason: archive_attribution_snapshot_invalid`)は、この保存前validationを経由しない直接呼び出し(テスト等)に対する二次的な防御的backstopであり、単独では保存済みBrief(overview/discussion_points/check_items)までは保護しない――保存済みBriefも含めた完全な保護は、Archive生成対象からの除外そのものによって担保する。schema v1の既存daily JSON・Archiveの内容自体はこの仕組みの対象外であり、遡及変更しない(生成済みで現在有効なArchive HTMLの削除は行わない)。

**トップページのArchive導線判定も同一validatorを使用する(round 7):** 日別Archive生成(`generate_archive_outputs()`)だけでなく、トップページの「前回のダイジェスト」リンク・Archive導線が参照する公開済み日付一覧を取得する`fetch.load_validated_published_digest_dates()`も、同じ`daily_json.validate_daily_digest_for_archive_read()`を使う。round 6まではこの関数が保存直前用のstrict validation(`daily_json.validate_daily_digest()`)を使っており、`archive_path`・日別Archive HTMLが正常に揃っているschema v1 digestであっても、現行のBrief件数上限等を理由にトップページの候補から誤って除外され得た(実在する`data/2026-07-14.json`の4件の`brief.check_items`が該当)。`load_validated_published_digest_dates()`は、daily JSON自体の型・構造検証をこのArchive読込validatorへ委ねたうえで、index/archive_path/ファイル名整合性等の既存条件(上記とは独立)を維持する。

---

## 7. Output-similarity and quotation controls (BL-032必須要件・Draft実装済み、ユーザー受入前。10章参照)

このcontrolは、決定論的な仕組みで機械的に強制できる要件と、追加のモデルなしでは完全な自動検出を約束できない意味的な残余リスクとを区別して記録する。両者を同列に「すべて自動検出する」と扱わない。

### A. 機械的に強制可能なBL-032要件

次は、決定論的な処理(文字数制限、文字列一致検出、必須フィールド検証)で機械的に強制できる要件として記録する。BL-032のDraft実装(ユーザー受入前)により、以下は`daily_json.py`／`fetch.py`で実装済みである(具体的な閾値・実装箇所は[BACKLOG.md](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)・[`test_content_usage_policy.py`](test_content_usage_policy.py)参照)。

- rich content(`content:encoded`／Atom content)を`feed_summary`／`limited_feed_analysis`分類のsourceで使用しない。
- 記事ページへの追加HTTP取得(scraping)を行わない。
- `feed_summary`／`limited_feed_analysis`のGemini入力を最大1000文字のtransient inputに限定する。
- 出力field(summary、financial_impact、recommended_actions等)ごとに文字数上限を設ける。
- publisher由来のdescription／excerptを永続保存しない。
- `limited_feed_analysis`分類のsourceで、原見出しの日本語翻訳タイトルを公開しない。
- 原文との長い連続完全一致(verbatim long match)を検出する。
- source名・original title・original URLがattributionとして出力に含まれることを必須検証する。
- 上記いずれかへの機械的な違反を検出した場合、`metadata_only`相当の簡易表示へ自動的に降格する。

### B. 自動的な完全検出を約束しない残余リスク

次は、意味内容の評価を要するため、追加のモデルを伴わない決定論的処理だけでは完全な自動検出を約束できない。

- 異言語間の近接翻訳(直訳に近いタイトル・文章生成)。
- lead paragraph(冒頭段落)の意味的な近接言い換え。
- 生成物が原記事の代替物になり得るかという意味的評価。

これらの残余リスクは、次によって低減する契約とし、自動検出のみに依存しない。

- bounded input／bounded output(文字数上限、上記A参照)による絶対的な生成量の制限。
- prompt上で近接翻訳・言い換え・原文代替的な詳細さを明示的に禁止する指示。
- 原題・出典・原記事リンクの必須表示(「詳細と正確性は元記事で確認」等の限界注記を含む)。
- 生成内容が原文を代替するものではない旨の表示。
- 定期的なspot review(抜き取り確認)による人的な事後チェック。
- 権利者・読者からの訂正・削除申出窓口(`SECURITY_OPERATIONS.md`参照)。
- 違反が発見された場合の降格・訂正手順(`SECURITY_OPERATIONS.md`のcontent usage mode downgrade手順、および published-output correction手順)。

具体的な閾値(文字数・verbatim long match最小長等)は、BL-032のDraft実装(ユーザー受入前)で決定・テストと共に一元管理済みである(意味的類似度スコアのような追加モデルは導入していない)。本文書(BL-031)自体は監査・方針の記録にとどまる。

---

## 8. Recheck triggers(まとめ)

| トリガー | 対象 |
|---|---|
| Google Terms(2026-07-30発効版)のさらなる改定 | `google_tag`、間接的に`mandiant`(Google Cloud blog) |
| 書面確認またはTalos固有termsの発見 | `cisco_talos` |
| 公式terms発見、利用規約変更、machine-readable instruction変更、Feed経路変更、権利者からの訂正・削除・停止申出、output policy違反、attribution欠落 | `the_hacker_news`、`krebs_on_security`(`limited_feed_analysis`、metadata_only／disabledへの降格契機。3章C・4章参照) |
| CrowdStrike/Cloudflare/Dark Readingの`activation_condition`充足確認 | `crowdstrike`、`cloudflare`、`dark_reading` |
| CISAの4条件充足確認 | `cisa` |
| NVD API Termsの変更 | `nist_nvd`、`nist` |
| Gemini APIのUnpaid/Paid Services規約変更 | 全`feed_summary`／`limited_feed_analysis`分類source |
| `security-digest` Projectのbilling解除・Project変更・APIキー移行(`paid_verified`の再確認要) | 全`feed_summary`／`limited_feed_analysis`分類source |
| 各sourceの利用規約・ライセンス・FAQ・robots.txtの実際の変更 | 該当source |

### Google Terms再確認(2026-07-30発効版、完了)

- **checked_at:** 2026-07-30
- **確認方法:** Google公式のTerms of Serviceアーカイブページで、2026-07-30版が最新版として掲載されていることを確認した。あわせて、repository ownerの通常ブラウザでも、日本向け現行規約ページの表示が2026年版へ切り替わったことを確認した。
- **一部環境での表示差:** 一部の取得環境では、確認時点で旧2024年版の表示が一時的に残っていたことを事実として記録する。原因は特定していない(cache・CDNエッジ等を含め、断定的な原因は未確認)。この表示差は、規約が2026-07-30に発効し、その内容を確認できたという事実を否定するものではない。
- **確認した内容:** 新規約は、引き続きrobots.txt等のmachine-readable instructionsに反する自動収集を禁止する条件を含む。一般的なGoogle利用規約のみをもって、AI要約・公開再利用が包括的に許諾されたとは断定しない。
- **反映:** `google_tag`・`mandiant`の`checked_at`を2026-07-30へ更新し、confidence(medium)・分類(`feed_summary`, conditional)は変更していない。BL-032のDraft実装(ユーザー受入前)は、公式Feedのみの利用・記事ページ追加取得の禁止・rich content不使用をコードで機械的に強制するが、machine-readable instructionsの変更をrecheck triggerとして自動検知する仕組みは実装しておらず、引き続き`SECURITY_OPERATIONS.md`の人による運用手順に依る。
- **機密情報:** この確認にAPI key・billing情報等は関係しない。記録した情報はいずれも公開されている規約ページの内容と確認日のみである。

## 9. Unknowns and owner verification

**Owner-verified(未解決事項から除外):**
- **Gemini `gemini_data_use_status`**: 2026-07-29、repository ownerがGoogle AI StudioのAPI Keys画面で確認し、`paid_verified`として記録した(5章参照)。将来billing状態・Project・APIキーが変更された場合は再確認が必要。

**確認完了(未解決事項から除外):**
- **Google TAG / Mandiant(Google Cloud blog)**: 2026-07-30発効の新しいGoogle利用規約の内容を2026-07-30に確認した(8章参照)。machine-readable instructionsに反する自動収集を禁止する条件は継続しており、一般規約のみでAI公開要約が包括的に許諾されたとは断定しない。次回の規約改定時に再確認する。

**未解決のまま維持する事項:**
- **Cisco Talos**: Cisco Site Content利用規約(internal use限定)がブログドメイン(`blog.talosintelligence.com`)へ直接適用されるかどうか、書面での確認またはTalos固有の利用規約発見が必要。分類は`metadata_only`のまま。
- **Krebs on Security**: 公式の包括的な再利用条件が見つからなかった。禁止と断定せず、`limited_feed_analysis`(3章C・4章のリスク受容根拠を参照)として限定的に運用し、要確認として記録する。
- **CISA(通常RSS、`cisa_kev`とは別)**: 広範な公式機械可読アドバイザリー取得経路自体が未確定(既存`activation_condition`参照)。

## 10. Relationship to BL-032 and BL-009

- **[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)(Draft実装済み、ユーザー受入前)**: 本文書で提案したcontent usage modeを、`source_definitions.json`への`content_usage_mode`等の設定項目追加と、`fetch.py`側の共通処理(取得・Gemini入力・保存・公開の各段階でのmode強制)として実装した。Gemini data-use gate(5章)の`paid_verified`確認結果を反映済み。output-similarity/quotation controls(7章)を実装しテスト済み(`test_content_usage_policy.py`)。ユーザーが受入するまでは、本文書の監査結果・方針自体(Version 0.1 Approved)は変更されないが、このenforcement実装自体はDraftであり、production・`workflow_dispatch`・実Gemini API呼び出しに対する事前承認ではない。
- **BL-009**: About／出典表示ページ、免責事項、訂正申出窓口の実装。本文書のattribution要件(6章)を実際のUIへ反映する。
- 本文書(BL-031)自体は、監査結果と方針の記録にとどまり、上記いずれの実装も行わない。Dark Readingの暫定停止(`source_definitions.json`の`enabled: false`)のみを例外的にこのTicketで実施する(本文書の章番号ではなく、BL-031チケット記述内の実施phaseを指す。詳細は下記BACKLOG.mdのBL-031記載を参照)。

---

## 11. Approval and maintenance

- Version 0.1は、2026-07-30のDraft公開後、[PR #67](https://github.com/matkei31/security-digest/pull/67)への複数回のChatGPT独立レビューと修正を経て、最終独立レビューで実装・文書上のBlockerなしと判断された。accepted head `897fc9db365e890318fc694a7fbf9cd8eab65ae1`。[Pull Request CI run 30557479373](https://github.com/matkei31/security-digest/actions/runs/30557479373) success。full unittest: 1391 tests OK。unresolved review threads: 0。
- ユーザーが本指示をClaude Codeへ送付することで、BL-031の受入・Ready化・通常のmerge-commit方式によるmergeを承認した(merge commit `61feb679fad6bd2252c58cd8acb4696294032629`)。merge完了報告後、2026-07-31にユーザーが「ok進もう」と回答し、本文書Version 0.1をApprovedとすることを承認した([SD-030](DECISIONS.md#sd-030--approve-source-usage-policy-version-01-and-defer-runtime-enforcement-to-bl-032)参照)。
- **この承認の範囲:** 本承認は、17 source監査結果・5つのcontent usage mode定義・Gemini data-use gate・attribution要件・output-similarity/quotation control方針(7章)という**監査結果と運用方針の承認**である。`source_definitions.json`への`content_usage_mode`等fieldの追加、`fetch.py`での取得元別enforcement実装、production・`workflow_dispatch`・実Gemini API呼び出しを本承認によって事前承認するものではない。これらの実装は[BL-032](BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement)として別途登録され、別途の実装・レビュー・受入を経る。
- 4章の監査表にある`proposed_mode`列は、このApproved監査に基づく分類提案を示す列名として維持する。BL-032のDraft実装は、この提案値をそのまま`source_definitions.json`の`content_usage_mode`へ反映し`fetch.py`で強制しているが、BL-032自体がユーザー受入・merge済みではないため、列名は`proposed_mode`のままとする。ユーザーがBL-032を受入・merge済みとするまでは、提案(proposed)の位置づけのままである。
- 各source行の`checked_at`は、本承認によって一括変更しない。将来の再確認は、8章の recheck triggers、または各source行の`recheck_trigger`列に従って個別に行う。
