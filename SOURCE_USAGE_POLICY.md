# Monomi Digest — Source Usage Policy

- **Version:** 0.1
- **Status:** Draft
- **As of:** 2026-07-29
- **Scope:** Monomi Digestの外部取得元(RSS/Atom/structured JSON)、その内容のAI(Gemini)入力、`data/`・`docs/`への保存、公開要約、出典表示。
- **免責:** 本文書は法律意見ではない。各取得元の公式に公開された利用規約・ライセンス・FAQ等をChatGPTが2026-07-29に確認した内容に基づく、運用上の安全側判定の記録である。最終的な法的判断は、必要に応じて別途の法務確認によって行う。本文書のいずれの記述も、特定の取得元が現行実装によって規約違反を犯していると断定するものではない。

---

## 1. Purpose

- 包括的な取得元規約監査(BL-030で暫定停止したCrowdStrike・Cloudflareを含む、全17取得元)の結果を、repository内の監査記録として固定する。
- 各取得元についてcontent usage mode(4種類、後述)を提案し、根拠となる公式情報・確認日・確信度・未解決事項・再確認契機を記録する。
- BL-030で削除した非公式翻訳経路と、現在の独自ドメイン(`monomidigest.com`)運用を、`SECURITY_REQUIREMENTS.md`／`SECURITY_OPERATIONS.md`へ反映するための入力情報を提供する。
- 本Ticket(BL-031)は監査・方針文書の整備のみを対象とする。ここで提案するcontent usage modeをproductionコードで強制する実装(`source_definitions.json`への`content_usage_mode`等のfield追加、`fetch.py`側の共通処理)は、後続のBL-032で行う。

## 2. Legal and policy framework

- 本文書は次の階層で情報を扱う: (1) 各取得元の公式に公開された利用規約・ライセンス・FAQ、(2) Gemini APIの利用規約(Google AI Studio / Unpaid Services と Paid Services の区別)、(3) それらを踏まえた運用上の安全側判定。
- 公式規約の解釈に幅がある場合は、より保守的な側(利用を制限する側)を採用する。
- 「不明」「確認できなかった」事項は、断定的に「禁止」または「許可」とせず、`unresolved_issue`として明示し、後続の書面確認・追加調査を要求する形で記録する。
- 本文書はChatGPT側の外部調査結果を転記したものであり、本PRの作業自体は外部URLへの新規アクセスを行っていない。

## 3. Content usage modes

Monomi Digestの取得元は、次の4つのcontent usage modeのいずれかへ分類する。

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

### C. `metadata_only`

**許可:**
- title、published date、source name、original URL

**禁止:**
- description、summary、`content:encoded`、Atom contentのGeminiへの送信。
- ARTICLE分析(importance／urgency／financial_impact／recommended_actions等の生成)。
- publisher由来の本文・抜粋の保存。
- 原文に基づく日本語タイトル翻訳(Gemini生成の`title_ja`を含む)。

**将来表示(BL-032検討事項):**
- 「参考リンク」等、AI評価済み記事とは別枠の表示。
- AI評価済み記事と混同しないUI上の区別。

### D. `disabled_legal_review`

- 外部ネットワークリクエストを行わない。
- `RSS_FEEDS`や取得処理から除外する(`enabled: false`)。
- 明示された再有効化条件(`activation_condition`)を満たすまで停止を維持する。

---

## 4. Source-by-source audit matrix

`checked_at`は各source行に個別列として記録する(現時点ではいずれも2026-07-29、ChatGPTによる公式情報確認日)。今後sourceごとに再確認日が異なり得るため、全件同じ日という表外の一括記述だけを正本とせず、行単位の`checked_at`列を正本とする。以下の全17件で`allow_rich_content`は`false`とする(現行の`content:encoded`／Atom content共通処理自体は変更しない。BL-032でsource別強制を実装する際の入力とする)。

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
| mandiant | Mandiant | feed_summary | true | true | true | false | conditional(gate) | false | conditional(gate) | 6章参照 | https://policies.google.com/terms?hl=en-US ； https://policies.google.com/terms/update/embedded ； https://cloud.google.com/blog/topics/threat-intelligence | terms(primary) ； terms_update_notice(supporting) ； rss_usage_guidance(supporting) | 2026-07-29 | medium | Google全体利用規約のmachine-readable instructions条件の具体適用範囲。1・2番目のURL(Google Terms本文・更新案内)が利用条件そのものの証跡であり、3番目のURL(Threat Intelligenceページ)はRSS提供を示す証跡にすぎず、それ自体はterms文書ではない(両者を混同しない) | Google Cloud blogのterms変更、またはGoogle Termsの変更 |
| google_tag | Google TAG | feed_summary | true | true | true | false | conditional(gate) | false | conditional(gate) | 6章参照 | https://policies.google.com/terms?hl=en-US ； https://policies.google.com/terms/update/embedded | terms | 2026-07-29 | medium | 2026-07-30発効の新規約の最終内容が未確認 | **2026-07-30以降、Google Terms(新規約発効後)の公式再確認が必須** |

**注記(feed_summary共通):** `allow_ai_processing`／`allow_public_summary`はいずれも5章のGemini data-use gateに従属する。`gemini_data_use_status`は2026-07-29にowner verificationにより`paid_verified`となったため、このGemini側の条件自体は満たされた。ただし`gemini_data_use_status`が`unpaid`または`unknown`へ戻った場合は、実運用上`metadata_only`と同じ挙動として扱う(3章B参照)。取得元自身の規約条件(各sourceの`unresolved_issue`、`google_tag`／`mandiant`のGoogle Terms再確認pending等)はこの確認と無関係に別途維持され、production enforcement自体はBL-032まで未実装のままである。

### metadata_only (4件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| microsoft_security | Microsoft Security | metadata_only | true | true | false | false | false | false | false | 6章参照(source名・URLのみ) | https://www.microsoft.com/en-us/legal/terms-of-use | terms | 2026-07-29 | medium | RSS配信自体が本文再利用・AI公開要約の別段の許諾となるかは未確認 | Microsoft Terms of Useの改定 |
| cisco_talos | Cisco Talos | metadata_only | true | true | false | false | false | false | false | 6章参照 | https://www.cisco.com/c/en/us/about/legal/terms-conditions.html | terms | 2026-07-29 | low〜medium | **この規約が`blog.talosintelligence.com`へ直接適用されるかどうか不明** | 書面確認、またはTalos固有のterms発見 |
| the_hacker_news | The Hacker News | metadata_only | true | true | false | false | false | false | false | 6章参照 | https://thehackernews.com/p/copyright-policy.html | copyright_policy | 2026-07-29 | medium | All Rights Reserved明記のため、RSS提供のみを根拠に本文再利用・AI要約を許可とは解釈しない | copyright policyの変更 |
| krebs_on_security | Krebs on Security | metadata_only | true | true | false | false | false | false | false | 6章参照 | — ； https://krebsonsecurity.com/about-this-blog/ | terms_not_found ； source_page(supporting) | 2026-07-29 | low | **公式の包括的な再利用条件を確認できなかった(terms_not_found)。2番目のURL(Aboutページ)はterms文書ではなくsource pageであり、terms URLとしては扱わない。「禁止」と断定せず要確認として記録** | 公式terms発見時 |

### disabled_legal_review (4件)

| source_id | source_name | proposed_mode | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_evidence_url | evidence_type | checked_at | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cisa | CISA | disabled_legal_review | false | false | false | false | false | false | false | n/a(非公開) | — | terms_not_identified | 2026-07-29 | n/a | 広範な公式取得経路・利用条件が未確定なためURLが特定できていない(terms_not_identified)。HTTP 403の技術的理由に加え、CISA KEVとは別sourceとして扱う。既存`activation_condition`は`source_definitions.json`の`cisa`定義を参照(本表のURL欄には転記しない) | 既存`activation_condition`の4条件(`source_definitions.json`の`cisa`定義を参照) |
| crowdstrike | CrowdStrike | disabled_legal_review | false | false | false | false | false | false | false | n/a(非公開) | https://www.crowdstrike.com/en-au/legal/website-terms-of-use/ | terms | 2026-07-29 | high | なし(automated device/robot/spiderによるmonitor/copy、derivative works、public display、republish、download、store、transmitを明確に制限) | `source_definitions.json`の`crowdstrike.activation_condition`(BL-030で記録済み) |
| cloudflare | Cloudflare | disabled_legal_review | false | false | false | false | false | false | false | n/a(非公開) | https://www.cloudflare.com/policies/terms/ | terms | 2026-07-29 | high | なし(該当条件はTerms Section 8。AI用途botはrobots.txtで明示的allowed、かつAI用途bot専用User-Agentの両方が必要だが未充足) | `source_definitions.json`の`cloudflare.activation_condition`(BL-030で記録済み) |
| dark_reading | Dark Reading | disabled_legal_review | **false(本PRで変更)** | false | false | false | false | false | false | n/a(非公開) | https://www.informatechtarget.com/terms-of-use/ ； https://www.darkreading.com/ | terms ； source_page(supporting) | 2026-07-29 | high | なし(Informa TechTarget Termsがdata mining／robots等の抽出方法、derivative works、無断copy／distributionを明確に禁止。2番目のURLはsource pageであり、terms文書ではない) | `source_definitions.json`の`dark_reading.activation_condition`(本PRで新設) |

**件数集計:** structured_open 5、feed_summary 4、metadata_only 4、disabled_legal_review 4、**合計17**(`source_definitions.json`の定義総数と一致)。

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
- `gemini_data_use_status`が`paid_verified`になるまで、`feed_summary`分類のsourceのpublisher由来descriptionをGeminiへ送らない。上記owner verificationにより、この条件自体は満たされた。
- `unpaid`または`unknown`の場合、`feed_summary`は`metadata_only`と同じ挙動として動作させる。この`paid_verified`確認は、Gemini側のdata-use gateによる`feed_summary`→`metadata_only`強制を解除できることを意味するが、取得元自身の規約条件(各sourceの`official_evidence_url`／`evidence_type`／`unresolved_issue`、および`google_tag`／`mandiant`の2026-07-30 Google Terms再確認pending)は本確認と無関係に別途維持される。
- API key、請求情報、金額、アカウント画面のスクリーンショット等の機微情報はrepositoryへ一切保存しない。
- ownerは「active billingの有無」という非機密情報のみを回答すればよい(具体的な金額・アカウントID・契約詳細は不要)。

**本Ticket(BL-031)は監査・方針文書の更新にとどまり、このowner verification結果をproductionコードのenforcementへ反映する実装(`source_definitions.json`への`content_usage_mode`等のfield追加、`fetch.py`側の共通処理)は行わない。** この文書更新だけで現在のproduction挙動が変わるものではない。BL-032が、この確認結果を`feed_summary`有効化判断の入力として使用する。

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
| `metadata_only`分類の4source | source nameとoriginal URLのみ。AIによる評価・要約は付けない。 |
| `disabled_legal_review`分類の4source | 非公開のため表示なし。 |

---

## 7. Output-similarity and quotation controls (BL-032必須要件・本PRでは実装しない)

BL-032の実装時に、次の状態を検出し、拒否またはfallbackする仕組みを必須要件として記録する。

- 原文との長い連続一致(verbatim long match)。
- 原文見出しの近接翻訳(直訳に近いタイトル生成)。
- 長い直接引用。
- lead paragraph(冒頭段落)の近接言い換え。
- 原記事を読まなくても済んでしまう代替的要約(記事の代替物になり得る詳細さ)。
- source attributionの欠落。

具体的な閾値(文字数・類似度スコア等)は、BL-032でテストとともに決定する。本PR(BL-031)では実装しない。

---

## 8. Recheck triggers(まとめ)

| トリガー | 対象 |
|---|---|
| 2026-07-30以降、Google Terms(新規約発効後)の公式再確認 | `google_tag`、間接的に`mandiant`(Google Cloud blog) |
| 書面確認またはTalos固有termsの発見 | `cisco_talos` |
| 公式terms発見時 | `krebs_on_security` |
| CrowdStrike/Cloudflare/Dark Readingの`activation_condition`充足確認 | `crowdstrike`、`cloudflare`、`dark_reading` |
| CISAの4条件充足確認 | `cisa` |
| NVD API Termsの変更 | `nist_nvd`、`nist` |
| Gemini APIのUnpaid/Paid Services規約変更 | 全`feed_summary`分類source |
| `security-digest` Projectのbilling解除・Project変更・APIキー移行(`paid_verified`の再確認要) | 全`feed_summary`分類source |
| 各sourceの利用規約・ライセンス・FAQ・robots.txtの実際の変更 | 該当source |

## 9. Unknowns and owner verification

**Owner-verified(未解決事項から除外):**
- **Gemini `gemini_data_use_status`**: 2026-07-29、repository ownerがGoogle AI StudioのAPI Keys画面で確認し、`paid_verified`として記録した(5章参照)。将来billing状態・Project・APIキーが変更された場合は再確認が必要。

**未解決のまま維持する事項:**
- **Cisco Talos**: Cisco Site Content利用規約(internal use限定)がブログドメイン(`blog.talosintelligence.com`)へ直接適用されるかどうか、書面での確認またはTalos固有の利用規約発見が必要。
- **Krebs on Security**: 公式の包括的な再利用条件が見つからなかった。禁止と断定せず、`metadata_only`(保守的な側)として扱い、要確認として記録する。
- **Google TAG / Mandiant(Google Cloud blog)**: 2026-07-30発効の新しいGoogle利用規約の内容が最終確認されていない。発効後の再確認が必須(pendingのまま)。
- **CISA(通常RSS、`cisa_kev`とは別)**: 広範な公式機械可読アドバイザリー取得経路自体が未確定(既存`activation_condition`参照)。

## 10. Relationship to BL-032 and BL-009

- **BL-032(候補)**: 本文書で提案したcontent usage modeを、`source_definitions.json`への`content_usage_mode`等の設定項目追加と、`fetch.py`側の共通処理(取得・Gemini入力・保存・公開の各段階でのmode強制)として実装する。Gemini data-use gate(5章)の`paid_verified`確認結果を反映する。output-similarity/quotation controls(7章)を実装しテストする。
- **BL-009**: About／出典表示ページ、免責事項、訂正申出窓口の実装。本文書のattribution要件(6章)を実際のUIへ反映する。
- 本文書(BL-031)自体は、監査結果と方針の記録にとどまり、上記いずれの実装も行わない。Dark Readingの暫定停止(`source_definitions.json`の`enabled: false`)のみを例外的にこのTicketで実施する(本文書の章番号ではなく、BL-031チケット記述内の実施phaseを指す。詳細は下記BACKLOG.mdのBL-031記載を参照)。
