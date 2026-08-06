# Monomi Digest Deferred Commitments

## Purpose

This file is the canonical index of user-requested follow-ups that were intentionally deferred for a later decision or implementation stage.

- [BACKLOG.md](BACKLOG.md) remains the source of truth for each Ticket's detailed scope, state, evidence, and acceptance.
- [DECISIONS.md](DECISIONS.md) remains the source of truth for stable decisions.
- [STATUS.md](STATUS.md) remains the source of truth for current, changeable project state.
- This index exists so that a deferred user commitment is not lost merely because it is not the active Ticket.

The user approved creating this index on 2026-08-06 with the message: 「ok。そうして」. That approval authorizes this record-only index; it does not approve implementation of any item below.

## Deferred commitments

| ID | Commitment | Current state | Existing source of truth | Revisit trigger | Next decision or action |
|---|---|---|---|---|---|
| DC-001 | Complete the remaining SEO and audience-growth work | Ready for planning | [BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策) | Brand, primary domain, Japanese UI/information design, and measurement foundation are complete. The trigger has been met. | Define the target reader and measurable objective first; then split technical SEO, content SEO, discovery/distribution, and measurement follow-up into reviewable Tickets. |
| DC-002 | Create the About, transparency, correction, and contact experience | Ready for planning under BL-009 | [BL-009](BACKLOG.md#bl-009--seoと閲覧者増加策) | The public brand/domain and navigation are stable enough to publish durable explanatory content. The trigger has been met. | Define the About information architecture: intended readers, service purpose, collection/selection/summary process, AI use, relationship to original sources, source-use policy, disclaimer, correction requests, removal/contact route, and navigation placement. |
| DC-003 | Decide whether multilingual support is worth doing | Waiting for evidence | [BL-010](BACKLOG.md#bl-010--多言語対応の意義判断) | Target readers and goals are defined; Japanese SEO/About strategy is settled; enough measurement data exists to estimate demand and cost-effectiveness. | Compare candidate languages, reader value, editorial/translation cost, regulatory mapping demand, maintenance risk, and SEO impact. Record an explicit Go/No-Go decision before any implementation Ticket. |
| DC-004 | Reassess the future role of `editorial-style-v1` | Decision only; no active implementation | [BL-005](BACKLOG.md#bl-005--editorial-style-v1とtoday-brief-v4), [BL-021](BACKLOG.md#bl-021--todays-briefの意味忠実性semantic-validation再設計), [SD-017](DECISIONS.md#sd-017--do-not-merge-prompt-only-todays-brief-experiments-redesign-semantic-validation-separately) | A concrete editorial-quality gap is observed under the current deterministic BRIEF composition, or a materially different safe integration path is proposed. | Decide whether to close the concept permanently, adopt only selected editorial principles, or register a new Ticket. Do not silently reopen BL-005 or retry the rejected prompt-only path. |

## Completed prerequisites and related work

The following are completed and must not be re-listed as deferred work unless new evidence justifies reopening them:

| Area | Completed record |
|---|---|
| Public brand migration to Monomi Digest | [BL-006](BACKLOG.md#bl-006--monomi-digestへのブランド変更) |
| Primary domain migration to `monomidigest.com` | [BL-007](BACKLOG.md#bl-007--monomidigestcomへの移行) |
| Archive/navigation redesign | [BL-028](BACKLOG.md#bl-028--前後ナビゲーションとarchive導線の再設計) |
| Financial-institution-relevance information design | [BL-029](BACKLOG.md#bl-029--金融機関との関連情報設計) |
| Cloudflare Web Analytics and Google Search Console foundation | [BL-034](BACKLOG.md#bl-034--閲覧計測基盤) |
| Repository governance documents (`BACKLOG.md`, `STATUS.md`, `DECISIONS.md`) | Established and in active use |

## Maintenance rules

1. Add an item only when the user explicitly asks to revisit something later, or explicitly confirms a reconstructed deferred commitment.
2. Preserve exact user wording when available. Otherwise label the record as a user-confirmed summary or reconstructed summary; never invent a quote.
3. A trigger becoming true does not authorize implementation. It means the item should be surfaced for planning or decision.
4. When implementation starts, create or identify the governing Backlog Ticket and link it here.
5. When an item is completed, rejected, or superseded, retain the row and update its state and evidence rather than deleting it.
6. During project planning and closeout, review this file together with `BACKLOG.md` so that deferred commitments are not dependent on assistant memory.
