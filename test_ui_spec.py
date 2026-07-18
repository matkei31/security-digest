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
        cls.status = (REPOSITORY_ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.bl004 = backlog_section(cls.backlog, "BL-004")

    def test_ui_spec_exists_with_draft_metadata(self):
        self.assertTrue(self.spec_path.is_file())
        self.assertIn("# Security Digest UI Specification", self.spec)
        self.assertIn("- **バージョン:** Draft 0.1", self.spec)
        self.assertIn("- **状態:** ユーザーレビュー待ち", self.spec)
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

    def test_unresolved_proposals_are_separate_from_confirmed_spec(self):
        self.assertIn("未決事項を確定仕様として扱ってはならず", self.spec)
        self.assertIn("#### 採用・実装済み", self.spec)
        self.assertIn("#### 後のユーザー判断で置換・不採用", self.spec)
        self.assertIn("#### 未決", self.spec)
        self.assertIn("AI利用を明示する注記", self.spec)
        self.assertIn("モバイルsticky headerの圧縮", self.spec)
        self.assertIn("ヘッダー絵文字の削除", self.spec)

    def test_bl004_remains_in_progress_with_original_evidence_unchanged(self):
        self.assertIn("- **状態:** 仕様化済み / 進行中", self.bl004)
        self.assertNotIn("- **状態:** 完了", self.bl004)
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
        self.assertIn(
            "- **残作業:** 未決事項のユーザー裁定、UI_SPEC.mdの承認、完了記録",
            self.bl004,
        )

    def test_status_keeps_bl004_as_the_next_candidate(self):
        next_candidates = self.status.split("## 7. Next candidates", 1)[1].split(
            "## 8. Sources of truth", 1
        )[0]
        self.assertIn("UI_SPEC.md Draft 0.1", self.status)
        self.assertIn("ユーザーレビュー待ち", self.status)
        self.assertRegex(next_candidates, r"(?m)^1\. \[BL-004\]")
        self.assertNotIn("BL-004", self.status.split("## 5. Recently completed work", 1)[1].split("## 6.", 1)[0])


if __name__ == "__main__":
    unittest.main()
