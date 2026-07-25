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

    def test_ui_spec_exists_with_approved_version_metadata(self):
        self.assertTrue(self.spec_path.is_file())
        self.assertIn("# Security Digest UI Specification", self.spec)
        self.assertIn("- **バージョン:** 1.3", self.spec)
        self.assertIn("- **状態:** 承認済み", self.spec)
        self.assertIn("将来のMonomi Digestへの名称変更はBL-006の範囲", self.spec)

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
        self.assertIn("現行Security Digestでは`🔐`を維持", self.spec)
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
        self.assertIn("方向移動グループを左、全体導線グループを右", self.spec)
        self.assertIn("グループのDOM順と区別を保ったまま`flex-wrap`", self.spec)
        self.assertIn("「次のダイジェスト →」", self.spec)
        self.assertIn("「最新のダイジェスト」「過去のダイジェスト」", self.spec)
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
        self.assertIn("SD-020's validated earlier-date selection", self.decisions)
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
        self.assertIn("is complete", next_candidates)
        self.assertIn("no new ranked next candidate is named here", next_candidates)
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


if __name__ == "__main__":
    unittest.main()
