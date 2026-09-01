# Monomi Digest Topic Pages Specification

- **Version:** 0.1
- **Status:** Implementation approved / visual acceptance pending
- **Backlog ID:** BL-051
- **Approved scope:** topic-page v0.1, documentation synchronization, dedicated branch, commit, and PR
- **Approval evidence:** 2026-09-01 user message: 「書同期とテーマページv0.1、branch作成・commit・PRまで進めてOK」

## 1. Purpose

Monomi Digest currently publishes a daily top page and date-oriented Archive. Topic pages add a second navigation axis so past articles can be found by subject across multiple dates. The first version is deliberately small: it reuses classifications already present in the public daily JSON rather than creating a new taxonomy pipeline.

The purpose is information architecture and reuse of accumulated articles. Search discovery is a secondary benefit; v0.1 is not justified by an assumption that topic pages themselves improve ranking.

## 2. v0.1 classification contract

1. Existing ARTICLE `category` is the primary classification signal.
2. Existing ARTICLE `tags` are cross-cutting signals. A topic may therefore contain an article whose primary category differs when a registered tag matches the topic.
3. No new Gemini request, prompt, response schema, daily JSON field, or historical data rewrite is introduced.
4. `Entity` extraction is not part of v0.1. It remains a future option after actual use and Search Console data justify it.
5. `その他` is not a public topic. A low-specificity fallback category must not become a navigation page merely because it exists in the schema.
6. Topics are curated in an explicit registry; every possible tag does not automatically become a page.

## 3. Initial topic registry

| slug | label | primary category signal | cross-cutting tag signals |
|---|---|---|---|
| `vulnerabilities` | 脆弱性・パッチ | 脆弱性・パッチ | CVE, KEV, ゼロデイ, 悪用確認済み, パッチ |
| `threats` | 攻撃・脅威動向 | 攻撃・脅威動向 | APT, フィッシング |
| `incidents` | インシデント | インシデント | インシデント, 情報漏えい, 業務停止 |
| `regulation-governance` | 規制・ガバナンス | 規制・ガバナンス | 規制, ガイドライン, 監督, DORA, NIST, SWIFT, CSCF |
| `identity-access` | 認証・IAM | — | 認証, IAM |
| `cloud-supply-chain` | クラウド・サプライチェーン | クラウド・サプライチェーン | クラウド, SaaS, サプライチェーン, 委託先管理 |
| `ai` | AI・新技術リスク | AI・新技術リスク | AI, LLM, AIエージェント |
| `ransomware` | ランサムウェア | — | ランサムウェア |

The registry represents the qualitative condition that the theme is expected to remain useful. Publication is still conditional on corpus evidence as described below.

## 4. Publication gate

A registered topic is public only when both are true:

- at least **5 matching articles** exist; and
- the matches span at least **2 distinct digest dates**.

The topic index itself is always generated. A registered topic that does not meet the gate is omitted from the index and topic-detail output. If a previously public registered topic falls below the gate because historical data is deliberately removed, its generated directory is removed on the next topic generation.

## 5. URL and navigation contract

- Topic index: `/topics/`
- Topic detail: `/topics/{slug}/`
- The top page adds one global navigation link: `テーマから探す` → `topics/`.
- Existing `過去のダイジェスト` and previous-digest navigation remain unchanged.
- Topic-detail article links point back to the canonical daily Archive card: `/archive/{YYYY-MM-DD}.html#article-N`.
- `N` is computed using the same `fetch.sort_items_for_display()` result as the daily Archive, rather than assuming daily JSON order equals visible card order.
- Existing article-card tag pills remain non-clickable. v0.1 does not silently change the accepted article-card interaction contract.

## 6. Topic page content

### Topic index

Each public topic shows:

- label;
- article count;
- number of distinct digest dates;
- latest matching digest date; and
- one deterministic topic description.

### Topic detail

Each matching article shows:

- article title;
- digest date;
- source;
- importance and confirmation timing when present;
- existing ARTICLE summary when present; and
- a link to the exact card in the daily Archive.

The page does not duplicate `financial_impact`, `recommended_actions`, NVD/KEV facts, or the full daily card. The daily Archive remains the canonical reading surface for the full analysis.

## 7. Search metadata, crawl discovery, and measurement

- Every topic page has a deterministic unique `<title>` and meta description.
- Every topic page has one absolute HTTPS apex canonical URL.
- v0.1 **does not modify `docs/sitemap.xml`**. The existing BL-009 Phase A-3 sitemap generator/contract remains unchanged; topic pages are discoverable from the public top page through `テーマから探す`.
- Adding `/topics/` URLs to the sitemap is a follow-up only if the project deliberately supersedes the accepted Phase A-3 crawl-file contract. This avoids treating a post-generator rewrite as though `fetch.py` still fully owned the committed sitemap.
- The same Cloudflare Web Analytics footer/beacon renderers already used by the existing public pages are reused. No new analytics provider, token, cookie flow, or third-party script is added.

## 8. Generation architecture

`fetch.py` remains the primary daily collector/generator and is not modified by BL-051 v0.1. A new deterministic post-generator, `topic_pages.py`, runs after `python3 fetch.py` and before the normal `git add docs/ data/` production commit.

The post-generator:

1. reads only validated published digest dates;
2. derives topic matches from the existing display items;
3. writes `docs/topics/...`;
4. injects the single top-page topic link using a narrowly scoped exact marker; and
5. leaves the Phase A-3 sitemap byte-for-byte untouched.

This separation is intentional: no network request, Gemini call, source collection rule, or daily JSON schema change is needed for topic pages.

## 9. Scope boundaries

### Allowed files

- `topic_pages.py`
- `test_topic_pages.py`
- `TOPIC_PAGES_SPEC.md`
- `.github/workflows/fetch.yml`
- `.github/workflows/pr-ci.yml`
- project-state/documentation synchronization required by BL-051
- narrowly scoped correction of a pre-existing test whose analytics-copy assertion accidentally scans article body/title content rather than the analytics notice itself

### Prohibited changes

- ARTICLE/Brief prompt content or versions
- `daily_json.py` schema or stored `data/*.json`
- `source_definitions.json` or `SOURCE_USAGE_POLICY.md`
- collection/relevance/promotion rules
- Gemini/NVD/KEV network behavior
- existing daily Archive article-card markup/interaction contract
- BL-009 Phase A-3 sitemap ownership/URL-set contract in v0.1
- production `workflow_dispatch`, repository settings, DNS, Pages settings, or manual production generation
- Entity extraction, article-unit URLs, or automatic page creation for every tag

## 10. Verification and acceptance

Implementation verification requires:

- topic matching and publication-gate unit tests;
- exact daily-Archive anchor alignment test;
- HTML escaping tests;
- canonical/title/description tests;
- analytics renderer reuse test;
- top-navigation idempotence/fail-closed tests;
- an explicit regression that topic generation leaves the existing sitemap unchanged;
- stale registered-topic cleanup without sweeping unknown siblings;
- workflow ordering test (`fetch.py` → `topic_pages.py` → commit);
- full existing unittest suite; and
- PR-CI execution of topic generation against the committed corpus before the full tests, so existing repository contracts are tested against the realistic post-generation working tree.

Creating the branch, commits, and PR is authorized by the user message above. Merge, production execution, manual workflow dispatch, and final visual acceptance remain separate actions and are not authorized by this approval.
