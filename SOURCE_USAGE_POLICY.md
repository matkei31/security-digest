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
- source固有のattribution(下記7章)を必須とする。

### B. `feed_summary`

**用途:** RSS利用は明示的に認められている、または公式に案内されているが、記事本文の再利用・AI公開要約まで包括的に許可されているとまでは確認できない取得元。

**許可:**
- title、date、source、original URL
- RSS description／summaryのみ(feed-native rich contentは含まない)
- Gemini ARTICLE分析への入力は、後述6章のGemini Paid Service確認を満たす場合のみ

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

`checked_at`はいずれも2026-07-29(ChatGPTによる公式情報確認日)。以下の全17件で`allow_rich_content`は`false`とする(現行の`content:encoded`／Atom content共通処理自体は変更しない。BL-032でsource別強制を実装する際の入力とする)。

### structured_open (5件)

| source_id | source_name | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_terms_url | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fsa | 金融庁 | true | true | true | false | true | true | true | 7章参照(PDL 1.0) | https://www.fsa.go.jp/rules/index.html | high | なし | 個別資料でPDL以外のライセンスが明記された場合 |
| nist | NIST | true | true | true | false | true | true | true | 7章参照(NIST source credit) | https://www.nist.gov/copyrights-disclaimers | high | 個別資料にcopyright表示がある場合の除外運用の具体化 | NIST copyright policyの変更 |
| ncsc | NCSC | true | true | true | false | true | true | true | 7章参照(OGL v3) | https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions | high | なし | OGLのversion変更 |
| cisa_kev | CISA KEV | true | true | true(shortDescriptionのみ) | false | true | true | true | 7章参照(CC0) | https://github.com/cisagov/kev-data | high | なし | ライセンスファイル(LICENSE)の変更 |
| nist_nvd | NIST NVD | **false**(standalone article collection) | **false**(standalone) | – | false | – | – | – | 7章参照(NVD notice) | https://nvd.nist.gov/developers/terms-of-use | high | standalone記事収集の再有効化は本Ticketの対象外。現行のNVD CVE facts経路(`vulnerability_facts.py`)のみをpolicy上許可対象とし、`nist_nvd`のstandalone article collection自体の`enabled`は変更しない | NVD API Termsの変更 |

**注記(nist_nvd):** policy分類上は`structured_open`(NVD API Termsがsearch/display/analyze/retrieve等のサービス開発を想定しているため)だが、これは`nist_nvd`の`enabled`を`true`へ戻すことを意味しない。現状すでに稼働しているCVE facts取得経路(`vulnerability_facts.py`の`fetch_nvd_batch`等)は、この監査によって新たに許可されるものではなく、既存のまま変更しない。

### feed_summary (4件)

| source_id | source_name | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_terms_url | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| jpcert_cc | JPCERT/CC | true | true | true | false | conditional(6章Gemini Paid Service gate) | false | conditional(gate) | 7章参照 | https://www.jpcert.or.jp/rss/index.html ／ https://www.jpcert.or.jp/guide.html | high | 転載・再配布時の連絡要否の具体運用 | JPCERT/CC利用ガイドの改定 |
| ipa | IPA | true | true | true | false | conditional(gate) | false | conditional(gate) | 7章参照 | https://www.ipa.go.jp/publish/faq.html ／ https://www.ipa.go.jp/siteinfo.html | medium | 個別資料ごとの利用条件が本ポリシーと優先関係を持つ場合の具体運用 | IPA著作権FAQの改定 |
| mandiant | Mandiant | true | true | true | false | conditional(gate) | false | conditional(gate) | 7章参照 | https://cloud.google.com/blog/topics/threat-intelligence | medium | Google全体利用規約のmachine-readable instructions条件の具体適用範囲 | Google Cloud blogのterms変更 |
| google_tag | Google TAG | true | true | true | false | conditional(gate) | false | conditional(gate) | 7章参照 | https://policies.google.com/terms?hl=en-US ／ https://policies.google.com/terms/update/embedded | medium | 2026-07-30発効の新規約の最終内容が未確認 | **2026-07-30以降、Google Terms(新規約発効後)の公式再確認が必須** |

**注記(feed_summary共通):** `allow_ai_processing`／`allow_public_summary`はいずれも6章のGemini data-use gateに従属する。`gemini_data_use_status`が`paid_verified`になるまでは、実運用上は`metadata_only`と同じ挙動として扱う(3章B参照)。

### metadata_only (4件)

| source_id | source_name | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_terms_url | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| microsoft_security | Microsoft Security | true | true | false | false | false | false | false | 7章参照(source名・URLのみ) | https://www.microsoft.com/en-us/legal/terms-of-use | medium | RSS配信自体が本文再利用・AI公開要約の別段の許諾となるかは未確認 | Microsoft Terms of Useの改定 |
| cisco_talos | Cisco Talos | true | true | false | false | false | false | false | 7章参照 | https://www.cisco.com/c/en/us/about/legal/terms-conditions.html | low〜medium | **この規約が`blog.talosintelligence.com`へ直接適用されるかどうか不明** | 書面確認、またはTalos固有のterms発見 |
| the_hacker_news | The Hacker News | true | true | false | false | false | false | false | 7章参照 | https://thehackernews.com/p/copyright-policy.html | medium | All Rights Reserved明記のため、RSS提供のみを根拠に本文再利用・AI要約を許可とは解釈しない | copyright policyの変更 |
| krebs_on_security | Krebs on Security | true | true | false | false | false | false | false | 7章参照 | https://krebsonsecurity.com/about-this-blog/ | low | **公式の包括的な再利用条件を確認できなかった(terms_not_found)。「禁止」と断定せず要確認として記録** | 公式terms発見時 |

### disabled_legal_review (4件)

| source_id | source_name | current_enabled | allow_network_fetch | allow_description | allow_rich_content | allow_ai_processing | allow_excerpt_storage | allow_public_summary | attribution_requirement | official_terms_url | confidence | unresolved_issue | recheck_trigger |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cisa | CISA | false | false | false | false | false | false | false | n/a(非公開) | (既存`activation_condition`参照) | n/a | 広範な公式取得経路・利用条件が未確定。HTTP 403の技術的理由に加え、CISA KEVとは別sourceとして扱う | 既存`activation_condition`の4条件(BACKLOG.md BL-007等参照は不要、`source_definitions.json`の`cisa`定義を参照) |
| crowdstrike | CrowdStrike | false | false | false | false | false | false | false | n/a(非公開) | https://www.crowdstrike.com/en-au/legal/website-terms-of-use/ | high | なし(automated device/robot/spiderによるmonitor/copy、derivative works、public display、republish、download、store、transmitを明確に制限) | `source_definitions.json`の`crowdstrike.activation_condition`(BL-030で記録済み) |
| cloudflare | Cloudflare | false | false | false | false | false | false | false | n/a(非公開) | https://www.cloudflare.com/policies/terms/ (Section 8) | high | なし(AI用途botはrobots.txtで明示的allowed、かつAI用途bot専用User-Agentの両方が必要だが未充足) | `source_definitions.json`の`cloudflare.activation_condition`(BL-030で記録済み) |
| dark_reading | Dark Reading | **false(本PRで変更)** | false | false | false | false | false | false | n/a(非公開) | https://www.informatechtarget.com/terms-of-use/ ／ https://www.darkreading.com/ | high | なし(Informa TechTarget Termsがdata mining／robots等の抽出方法、derivative works、無断copy／distributionを明確に禁止) | `source_definitions.json`の`dark_reading.activation_condition`(本PRで新設) |

**件数集計:** structured_open 5、feed_summary 4、metadata_only 4、disabled_legal_review 4、**合計17**(`source_definitions.json`の定義総数と一致)。

---

## 5. Gemini data-use gate

Gemini APIの公式Terms(https://ai.google.dev/gemini-api/terms)より:

- **Unpaid Services:** submitted contentおよびgenerated responsesが、Google製品・機械学習技術の改善に使用され得る。human reviewerがinput/outputを読む・注釈する場合がある。
- **Paid Services:** active Cloud Billing accountに関連付けられたCloud Project経由でGemini APIを利用する場合、prompts／responsesは製品改善に使用されない。

**現在のMonomi Digestの状態:** `gemini_data_use_status: unknown`

**owner verificationの許容値:**
- `paid_verified` — active Cloud Billing accountに関連付けられたProject経由での利用が確認された。
- `unpaid` — Unpaid Servicesとして利用されていることが確認された。
- `unknown` — 未確認(現状)。

**契約:**
- `gemini_data_use_status`が`paid_verified`になるまで、`feed_summary`分類のsourceのpublisher由来descriptionをGeminiへ送らない。
- `unpaid`または`unknown`の場合、`feed_summary`は`metadata_only`と同じ挙動として動作させる。
- API key、請求情報、金額、アカウント画面のスクリーンショット等の機微情報はrepositoryへ一切保存しない。
- ownerは「active billingの有無」という非機密情報のみを回答すればよい(具体的な金額・アカウントID・契約詳細は不要)。

**この確認は本PR(BL-031)のmerge条件にはしない。** BL-032の実装・有効化判断の入力として扱う。

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
| 各sourceの利用規約・ライセンス・FAQ・robots.txtの実際の変更 | 該当source |

## 9. Unknowns and owner verification

- **Gemini `gemini_data_use_status`**: `unknown`。ownerによる「active billingの有無」の非機密情報回答が必要(5章参照)。
- **Cisco Talos**: Cisco Site Content利用規約(internal use限定)がブログドメイン(`blog.talosintelligence.com`)へ直接適用されるかどうか、書面での確認またはTalos固有の利用規約発見が必要。
- **Krebs on Security**: 公式の包括的な再利用条件が見つからなかった。禁止と断定せず、`metadata_only`(保守的な側)として扱い、要確認として記録する。
- **Google TAG / Mandiant(Google Cloud blog)**: 2026-07-30発効の新しいGoogle利用規約の内容が最終確認されていない。発効後の再確認が必須。
- **CISA(通常RSS、`cisa_kev`とは別)**: 広範な公式機械可読アドバイザリー取得経路自体が未確定(既存`activation_condition`参照)。

## 10. Relationship to BL-032 and BL-009

- **BL-032(候補)**: 本文書で提案したcontent usage modeを、`source_definitions.json`への`content_usage_mode`等の設定項目追加と、`fetch.py`側の共通処理(取得・Gemini入力・保存・公開の各段階でのmode強制)として実装する。Gemini data-use gate(5章)の`paid_verified`確認結果を反映する。output-similarity/quotation controls(7章)を実装しテストする。
- **BL-009**: About／出典表示ページ、免責事項、訂正申出窓口の実装。本文書のattribution要件(6章)を実際のUIへ反映する。
- 本文書(BL-031)自体は、監査結果と方針の記録にとどまり、上記いずれの実装も行わない。Dark Readingの暫定停止(`source_definitions.json`の`enabled: false`)のみを例外的にこのTicketで実施する(9章相当、下記BACKLOG.md記載を参照)。
