import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent


def backlog_section(text, backlog_id):
    marker = f"## {backlog_id} "
    start = text.index(marker)
    next_section = text.find("\n## ", start + len(marker))
    return text[start:] if next_section == -1 else text[start:next_section]


class UiSpecDocumentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec_path = REPOSITORY_ROOT / "UI_SPEC.md"
        cls.spec = cls.spec_path.read_text(encoding="utf-8")
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.decisions = (REPOSITORY_ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.bl004 = backlog_section(cls.backlog, "BL-004")
        cls.bl005 = backlog_section(cls.backlog, "BL-005")
        cls.bl020 = backlog_section(cls.backlog, "BL-020")
        cls.bl022 = backlog_section(cls.backlog, "BL-022")

    def test_ui_spec_exists_with_version_metadata(self):
        self.assertTrue(self.spec_path.is_file())
        self.assertIn("# Monomi Digest UI Specification", self.spec)
        # BL-009 Phase A-1 (2026-08-14): UI_SPEC entered a Draft phase again, exactly as
        # it did for 1.6 and 1.7 -- the version bumps first and 状態 reads Draft until the
        # user's visual acceptance flips it to 承認済み. Same assertions, same order, only
        # the two phase-dependent literals move; the 1.7 acceptance date stays asserted.
        self.assertIn("- **バージョン:** 1.8", self.spec)
        self.assertIn("- **状態:** Draft（Version 1.7までは承認済み）", self.spec)
        self.assertIn("- **最終受入日:** 2026-08-04", self.spec)
        self.assertIn(
            "2026-07-26にユーザーがPC 1280px／390pxのトップページ・Archive一覧・日別Archive計6画面を目視受入し、"
            "Version 1.4として承認済みである",
            self.spec,
        )
        self.assertIn(
            "本書は、Version 1.0〜1.4の受入済み仕様、安定した意思決定、現在の`main`実装と回帰テストを一つにまとめる。",
            self.spec,
        )
        self.assertIn(
            "2026-07-26、ユーザーがトップページ・Archive一覧・日別ArchiveのPC 1280px／390px計6画面を目視確認し受入した。",
            self.spec,
        )
        self.assertIn(
            "[PR #57](https://github.com/matkei31/security-digest/pull/57)はmainへmergeされ、"
            "GitHub Pagesでの公開反映を確認済みである。",
            self.spec,
        )
        self.assertIn(
            "Version 1.5はBL-029の「本日の要点」子見出し・記事カード見出しの再設計を反映する。",
            self.spec,
        )
        self.assertIn(
            "「8枚とも確認した。BL-029の見出し、重要・優先事項の2段落表示、"
            "過去Archiveへの適用、0記事日の表示に問題なし。BL-029として受入。」と受入した",
            self.spec,
        )
        self.assertIn("c4ca053b176c93fba3588c1f0aaf4116ab3fbc33", self.spec)
        self.assertIn(
            "Version 1.5は、BL-029でユーザーと確定した仕様に基づき、"
            "「本日の要点」の子見出しを概況／重要・優先事項／確認事項へ、"
            "記事カードの見出しを概要／金融機関との関連／確認すべきことへ統一する。",
            self.spec,
        )
        self.assertIn(
            "2026-07-27、ユーザーがトップページ・日別Archive（記事あり2日・0記事1日）の"
            "PC 1280px／390px計8画面を目視確認し受入した。",
            self.spec,
        )
        self.assertIn(
            "Version 1.6はBL-028のダイジェストナビゲーション配置再設計"
            "（A案「左寄せ二段・ラベルなし」）を反映する。",
            self.spec,
        )
        self.assertIn(
            "「10枚とも確認した。BL-028の左寄せ二段配置、前→次／過去→最新の順序、"
            "上部・下部ナビゲーション、単一方向ケース、PC 1280px／390pxの表示に問題なし。"
            "BL-028として受入。」と受入した",
            self.spec,
        )
        self.assertIn("77b4106618c29b9220012fd10e9ff616d773fa56", self.spec)
        self.assertIn(
            "Version 1.6は、BL-028でユーザーと確定したA案「左寄せ二段・ラベルなし」に基づき、"
            "ダイジェストナビゲーションをPC／390px共通の左寄せ縦二段構造"
            "（1段目が方向移動、2段目が全体導線）へ再設計する。",
            self.spec,
        )
        self.assertIn(
            "日別Archiveの全体導線は`過去のダイジェスト`→`最新のダイジェスト`の順へ変更する。",
            self.spec,
        )

    def test_all_required_chapters_exist_in_order(self):
        chapters = (
            "文書の目的と対象読者",
            "正本と優先順位",
            "UI設計原則",
            "ページ全体の情報構造と表示順",
            "用語",
            "ページヘッダー",
            "本日の要点",
            "優先確認",
            "本日のダッシュボード",
            "記事一覧と記事カード",
            "タイトル・日本語訳・原題の扱い",
            "取得元・重要度・確認目安・カテゴリ・関連タグ",
            "CVE・CVSS・CISA KEV",
            "Archive一覧・日別ページ・前後移動",
            "PCと390pxモバイル",
            "空状態・欠損状態・例外状態",
            "リンク・focus・anchor・アクセシビリティ",
            "受入例・チェックリスト",
            "未決事項",
            "変更管理",
        )
        positions = []
        for index, title in enumerate(chapters, start=1):
            heading = f"## {index}. {title}"
            self.assertEqual(self.spec.count(heading), 1, heading)
            positions.append(self.spec.index(heading))
        self.assertEqual(positions, sorted(positions))

    def test_confirmed_axis_and_related_tag_contracts_are_explicit(self):
        self.assertIn(
            "「重要度」と「確認目安」を独立した軸として扱う", self.spec
        )
        self.assertIn("「確認優先度」ではなく「重要度」", self.spec)
        self.assertIn(
            "関連タグはvariant Bで残す確定仕様であり、全面削除しない", self.spec
        )
        self.assertIn("カード最下部の低コントラストな補助情報", self.spec)
        self.assertIn("キーボードfocus対象にしない", self.spec)

    def test_all_seven_choices_are_confirmed_and_no_active_unresolved_items_remain(self):
        self.assertIn("**現時点の未決事項: なし。**", self.spec)
        self.assertNotIn("#### 未決", self.spec)
        self.assertIn("現行UIへAI利用を明示する専用注記は追加しない", self.spec)
        self.assertIn("記事カード単位・分析区分単位の注記も採用しない", self.spec)
        self.assertIn("600px以下でも現在のstickyとpaddingを維持し、圧縮案は採用しない", self.spec)
        self.assertIn("`🔐`を維持する。BL-006のMonomi Digestへのブランド移行後も置換していない", self.spec)
        self.assertIn("英語原題に行数制限やclampを設けず、原題の一部を省略しない", self.spec)
        self.assertIn("現行の`.kev-badge`はアンバー系の小さいpillとして維持", self.spec)
        self.assertIn("各セクション別の空状態を確定仕様として維持", self.spec)
        self.assertIn("ページ全体を一つの専用空状態へ置き換えない", self.spec)
        self.assertIn("ブラウザ既定のfocus表示を維持", self.spec)
        self.assertIn("outlineやfocus表示を消してはならない", self.spec)
        self.assertIn("専用の`:focus-visible`意匠は追加しない", self.spec)

    def test_bl022_previous_digest_link_is_an_approved_responsive_contract(self):
        self.assertIn("### 6.3 直前の公開ダイジェスト", self.spec)
        self.assertIn("現在の`digest_date`より前で最も新しい日", self.spec)
        self.assertIn("表示文言は「← 前のダイジェスト」", self.spec)
        self.assertIn("日付を含めない", self.spec)
        self.assertIn("「過去のダイジェスト」は維持", self.spec)
        # BL-028 (Version 1.6 Draft): PC/390px share a left-aligned two-row
        # layout instead of the old PC left/right split.
        self.assertIn("PC／390pxともに方向移動グループを1段目、全体導線グループを2段目とする左寄せの縦二段構造", self.spec)
        self.assertIn("### 6.4 ナビゲーション配置(BL-028, Version 1.6)", self.spec)
        self.assertIn("「次のダイジェスト →」", self.spec)
        self.assertIn("「過去のダイジェスト」「最新のダイジェスト」", self.spec)
        self.assertIn("| 1.1 | 承認済み | BL-022", self.spec)
        self.assertIn("| 1.2 | 承認済み | ナビゲーションの4用語を統一", self.spec)
        self.assertIn("| 1.3 | 承認済み | 収集元フッターの取得元別カラーとpill表現を廃止", self.spec)
        self.assertIn("- **状態:** 完了", self.bl022)
        self.assertIn("[PR #38](https://github.com/matkei31/security-digest/pull/38)", self.bl022)

        self.assertIn(
            "## SD-020 — Link the top page to the latest validated earlier digest",
            self.decisions,
        )
        self.assertIn(
            "## SD-021 — Unify digest navigation labels and separate direction from global navigation",
            self.decisions,
        )
        self.assertIn(
            "SD-020's validated earlier-date selection",
            " ".join(self.decisions.split()),
        )
        self.assertIn("only for navigation labels, date display, placement", self.decisions)

    def test_bl020_source_footer_is_plain_user_accepted_and_complete(self):
        self.assertIn("取得元別カラー、背景、border、pill状の角丸", self.spec)
        self.assertIn("無彩色・低強調のプレーンテキスト一覧", self.spec)
        self.assertIn("件数、表示集合、定義順は`build_footer_sources()`", self.spec)
        self.assertIn("CISA KEVも他の取得元と同じ通常表示", self.spec)
        self.assertIn("トップページと日別Archive", self.spec)
        self.assertIn("PCで3列、600px以下で1列", self.spec)
        self.assertIn("browser既定のfocus表示を維持", self.spec)
        self.assertIn(
            "## SD-023 — Remove source-specific colors and pill styling from the source footer",
            self.decisions,
        )
        self.assertIn("- **状態:** 完了", self.bl020)
        self.assertIn("「この表示でOK、進めて」", self.bl020)
        self.assertIn("ユーザーが確認したのはmerge前の生成screenshots", self.bl020)
        self.assertIn("公開PagesはWorkが客観確認", self.bl020)
        self.assertIn("ユーザーが公開サイトを目視したとは記録しない", self.bl020)
        self.assertIn("- **残作業:** なし。", self.bl020)

    def test_sd016_and_user_adjudication_are_recorded_verbatim(self):
        self.assertIn(
            "## SD-016 — Resolve the remaining BL-004 UI choices without changing the accepted layout",
            self.decisions,
        )
        self.assertIn("- **Status:** Accepted / Active", self.decisions)
        quote = "「7点ともこの方針でOK」"
        self.assertIn(quote, self.decisions)
        self.assertIn(quote, self.bl004)
        self.assertIn(quote, self.spec)

    def test_bl004_is_complete_with_original_evidence_unchanged(self):
        self.assertIn("- **状態:** 完了", self.bl004)
        self.assertIn(
            "- **ユーザー原文:** 「設計書は作成済みの理解で合ってる？」",
            self.bl004,
        )
        expected_acceptance = (
            "- **ユーザー受入証跡:** Dashboardスコープ: 2026-07-17に受入。記事カードスコープ: "
            "ユーザーは2026-07-17のプロジェクト会話で通常記事カードのvariant（B）を明示的に選択し、"
            "別途2026-07-17にPC/390px実装を目視で受入（verbatim: 「見られたけど、いいと思うよ」；"
            "[BL-002](#bl-002--記事カードの楕円バッジ多用を見直す)/"
            "[BL-003](#bl-003--aiで機械処理された印象を弱める)参照）。これはdashboardと記事カードの"
            "*決定事項*自体に関するBL-004の完了条件を満たすが、依然として不足している専用の仕様書の"
            "代替にはならない（残作業を参照）。"
        )
        self.assertIn(expected_acceptance, self.bl004)
        self.assertIn("「7点ともこの方針でOK」", self.bl004)
        self.assertIn(
            "- **残作業:** なし。",
            self.bl004,
        )
        self.assertIn("[UI_SPEC.md](UI_SPEC.md)をVersion 1.0／承認済みへ更新", self.bl004)
        self.assertIn(
            "[SD-016](DECISIONS.md#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)",
            self.bl004,
        )
        self.assertIn("[PR #30](https://github.com/matkei31/security-digest/pull/30)", self.bl004)
        self.assertIn("198b5a6dc723870b691575ba89c2aaae89e35b8c", self.bl004)
        self.assertIn("[Pull Request CI run 29647361707]", self.bl004)
        self.assertIn("[Pages deployment run 29648894119]", self.bl004)

    def test_status_completes_bl004_bl021_and_bl022(self):
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1].split(
            "## 6. Known issues and limitations", 1
        )[0]
        known_issues = self.status.split("## 6. Known issues and limitations", 1)[1].split(
            "## 7. Next candidates", 1
        )[0]
        next_candidates = self.status.split("## 7. Next candidates", 1)[1].split(
            "## 8. Sources of truth", 1
        )[0]
        self.assertIn("BL-004", recently_completed)
        self.assertIn("[UI_SPEC.md](UI_SPEC.md) Version 1.0／承認済み", recently_completed)
        self.assertIn("[SD-016]", recently_completed)
        self.assertIn("[PR #30](https://github.com/matkei31/security-digest/pull/30)", recently_completed)
        self.assertIn("198b5a6dc723870b691575ba89c2aaae89e35b8c", recently_completed)
        self.assertIn("ユーザー裁定済み", recently_completed)
        self.assertIn("merge後検証済み", recently_completed)
        self.assertNotIn("BL-004", known_issues)
        self.assertNotRegex(next_candidates, r"(?m)^\d+\. \[BL-004\]")
        self.assertNotIn("[BL-022]", next_candidates)
        self.assertNotRegex(next_candidates, r"(?m)^1\. \[BL-026\]")
        self.assertIn("[BL-026]", next_candidates)
        self.assertIn("are all complete", next_candidates)
        self.assertIn("so none is named as the ranked next candidate purely by priority number", next_candidates)
        self.assertIn("[BL-027]", next_candidates)
        self.assertNotIn("[BL-025]", next_candidates)
        self.assertIn("BL-021 deterministic-extractive Today's Brief", recently_completed)
        self.assertIn("completed and user-accepted", recently_completed)
        self.assertNotIn("[BL-021]", known_issues)
        self.assertIn("BL-022 digest navigation wording and layout", recently_completed)
        self.assertIn("[PR #38](https://github.com/matkei31/security-digest/pull/38)", recently_completed)
        self.assertNotIn("[BL-022]", known_issues)
        self.assertIn("[BL-023]", known_issues)
        self.assertIn("prompt-only改善はNo-Go", known_issues)
        self.assertNotIn("/Users/", next_candidates)
        self.assertIn("- **状態:** 実装試行済み（v4/v5/v6）／No-Go／main未反映", self.bl005)
        self.assertIn("- **実装証跡:** 目的:", self.bl005)
        self.assertIn("v4は構造ガードが成立したが編集品質Gate未達だった", self.bl005)
        self.assertNotIn("実装済み", self.bl005)
        self.assertNotIn("- **状態:** 完了", self.bl005)


class Bl036ArticleAttributionUiSpecTest(unittest.TestCase):
    """BL-036 (Fable 5 review R-01, final acceptance via PR #76, 2026-08-04):
    UI_SPEC.md Version 1.7 is Approved, distinguishing the maintained
    generic-AI-note-ban policy from the source-policy-required attribution
    exception that SD-033 now formally confirms, records the
    `.article-attribution` current values, and records BL-036's completion.
    """

    @classmethod
    def setUpClass(cls):
        cls.spec = (REPOSITORY_ROOT / "UI_SPEC.md").read_text(encoding="utf-8")
        cls.backlog = (REPOSITORY_ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (REPOSITORY_ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        cls.bl036 = backlog_section(cls.backlog, "BL-036")
        cls.sd033 = backlog_section(cls.decisions, "SD-033")
        cls.sd016 = backlog_section(cls.decisions, "SD-016")

    def test_version_is_17_approved_with_acceptance_date(self):
        # BL-009 Phase A-1 (2026-08-14): BL-036's durable fact is that Version 1.7 was
        # approved on 2026-08-04, which the version-history table still records. The
        # header now carries the 1.8 Draft, so this pair tracks the document's current
        # phase; BL-036's own durable fact -- that 1.7 was approved on 2026-08-04 -- is
        # the acceptance date asserted below and the 1.7 row in the version history.
        # Same three assertions in the same order, and they stay a duplicate pair with
        # UiSpecDocumentTest.test_ui_spec_exists_with_version_metadata (Category A).
        # The method name is kept for identity continuity.
        self.assertIn("- **バージョン:** 1.8", self.spec)
        self.assertIn("- **状態:** Draft（Version 1.7までは承認済み）", self.spec)
        self.assertIn("- **最終受入日:** 2026-08-04", self.spec)

    def test_original_ai_note_ban_sentences_are_preserved_not_deleted(self):
        self.assertIn("現行UIへAI利用を明示する専用注記は追加しない", self.spec)
        self.assertIn("記事カード単位・分析区分単位の注記も採用しない", self.spec)

    def test_maintained_policy_bans_generic_ai_badge_and_uniform_note(self):
        self.assertIn("維持する方針", self.spec)
        self.assertIn("genericな「AIを利用しています」badgeやalertを追加しない", self.spec)
        self.assertIn("一律AI noteを追加しない", self.spec)
        self.assertIn("generic AI disclosure禁止", self.spec)

    def test_source_policy_required_attribution_is_recorded_as_a_confirmed_limited_exception(self):
        # Final acceptance: the heading no longer describes a pending proposal
        # ("提案する") -- SD-033 confirmed the exception on 2026-08-04.
        self.assertIn("限定例外として認められた現行実装", self.spec)
        self.assertNotIn("例外として明示する現行契約", self.spec)
        self.assertNotIn("限定例外として提案する現行実装", self.spec)
        self.assertIn("`.article-attribution`", self.spec)
        self.assertIn("BACKLOG.md#bl-031--全取得元の公式規約監査とセキュリティ文書整合化", self.spec)
        self.assertIn("BACKLOG.md#bl-032--取得元別content-usage-policy-enforcement", self.spec)
        self.assertIn("一律のgeneric AI badgeとは目的・表示条件・文言が異なる", self.spec)
        self.assertIn("SOURCE_USAGE_POLICY.md", self.spec)
        self.assertIn("`render_source_attribution_html()`", self.spec)

    def test_runtime_attribution_is_already_implemented_and_bl036_only_added_css(self):
        self.assertIn("BL-032で既に実装・受入・merge済み", self.spec)
        self.assertIn("BL-036が新たに追加したruntime要素はCSSだけ", self.spec)

    def test_css_current_values_are_recorded_for_pc_and_390px_both(self):
        self.assertIn("| `.article-attribution` |", self.spec)
        self.assertIn("font-size `10px`", self.spec)
        self.assertIn("color `#768496`", self.spec)
        self.assertIn("line-height `1.6`", self.spec)
        self.assertIn("background／border／border-radius／pillなし", self.spec)
        self.assertIn("PC／390px共通", self.spec)

    def test_no_contradictory_no_change_claim_near_the_limited_exception(self):
        # Round 1 (Fable 5 review): "この区別自体は上記の確定方針を変更しない"
        # directly contradicted the later statement that SD-033 will supersede
        # part of SD-016. That exact contradictory phrase must not remain.
        self.assertNotIn("この区別自体は上記の確定方針を変更しない", self.spec)
        self.assertNotIn("決定自体は変更していない", self.spec)

    def test_no_pending_or_draft_current_state_wording_remains_for_the_exception(self):
        # Final acceptance: the exception is confirmed, not "pending until
        # acceptance/SD-033" -- that framing described the Draft/round-1 state
        # and must not remain as a claim about the current state.
        self.assertNotIn("確定するまで", self.spec)
        self.assertNotIn("受入待ちのDraft", self.spec)
        self.assertNotIn("Version 1.7 Draft", self.spec)

    def test_screenshot_filenames_and_evidence_are_recorded(self):
        for filename in (
            "bl036-attribution-page-1280px.png",
            "bl036-attribution-page-390px.png",
            "bl036-attribution-card-1280px.png",
            "bl036-attribution-card-390px.png",
            "bl036-attribution-card2-link-1280px.png",
            "bl036-attribution-card2-link-390px.png",
        ):
            with self.subTest(filename=filename):
                self.assertIn(filename, self.spec)
        self.assertIn("12a6f502973c78e21dbe0b209073f824731a3e5d", self.spec)
        self.assertIn("[PR #76](https://github.com/matkei31/security-digest/pull/76)", self.spec)

    def test_user_original_text_and_interpretation_are_recorded_separately(self):
        self.assertIn("「おk」", self.spec)
        self.assertIn("原文の解釈", self.spec)
        self.assertIn(
            "ユーザーが「10px」等の具体的CSS値を明示発言したものとしては扱わない", self.spec,
        )

    def test_sd033_exists_accepted_and_supersedes_only_the_ai_note_clause(self):
        self.assertIn(
            "## SD-033 — Allow source-policy-required article attribution as a "
            "limited exception to the generic AI-note ban",
            self.decisions,
        )
        self.assertIn("- **Date:** 2026-08-04", self.sd033)
        self.assertIn("- **Status:** Accepted / Active", self.sd033)
        self.assertIn(
            "[SD-016](#sd-016--resolve-the-remaining-bl-004-ui-choices-without-changing-the-accepted-layout)",
            self.sd033,
        )
        self.assertIn("other six resolved choices are not superseded and remain Active", self.sd033)
        self.assertIn("generic sitewide", self.sd033)
        self.assertIn("[UI_SPEC.md](UI_SPEC.md)", self.sd033)
        self.assertIn("[SOURCE_USAGE_POLICY.md](SOURCE_USAGE_POLICY.md)", self.sd033)
        self.assertIn("`source_definitions.json`", self.sd033)
        self.assertIn("`render_source_attribution_html()`", self.sd033)
        self.assertIn("[PR #76]", self.sd033)
        self.assertIn("12a6f502973c78e21dbe0b209073f824731a3e5d", self.sd033)

    def test_sd016_historical_body_is_preserved_and_notes_partial_supersession(self):
        self.assertIn(
            "## SD-016 — Resolve the remaining BL-004 UI choices without changing the accepted layout",
            self.decisions,
        )
        self.assertIn("- **Status:** Accepted / Active", self.decisions)
        quote = "「7点ともこの方針でOK」"
        self.assertIn(quote, self.sd016)
        self.assertIn(
            "(1) do not add an AI-use note to the current UI, including "
            "per-article-card or per-analysis-section notes",
            self.sd016,
        )
        self.assertIn("- **Partially superseded by:**", self.sd016)
        self.assertIn("SD-033", self.sd016)
        self.assertIn("generic sitewide AI-disclosure ban", self.sd016)
        self.assertIn("other six choices remain unchanged and Active", self.sd016)

    def test_bl036_is_recorded_as_complete_without_r04_r13_bl009_contamination(self):
        self.assertIn("- **状態:** 完了", self.bl036)
        self.assertNotIn("- **状態:** 実装中／ユーザー目視受入待ち", self.bl036)
        self.assertIn("PC 1280px／390px", self.bl036)
        self.assertIn("残作業:** なし", self.bl036)
        self.assertIn("R-04", self.bl036)
        self.assertIn("R-13", self.bl036)
        self.assertIn("BL-009", self.bl036)

    def test_status_active_work_excludes_and_recently_completed_includes_bl036(self):
        active = self.status.split("## Active work", 1)[1].split(
            "\n## 5. Recently completed work", 1
        )[0]
        self.assertFalse(
            any(line.startswith("- BL-036 ") for line in active.splitlines()),
            "BL-036 must not remain in Active work after final acceptance",
        )
        recently_completed = self.status.split("## 5. Recently completed work", 1)[1]
        bl036_line = next(
            line for line in recently_completed.splitlines() if line.startswith("- BL-036 ")
        )
        self.assertIn("SD-033", bl036_line)
        self.assertIn("承認済み", bl036_line)
        self.assertIn("12a6f502973c78e21dbe0b209073f824731a3e5d", bl036_line)


if __name__ == "__main__":
    unittest.main()
