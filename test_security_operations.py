import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def github_anchor(heading):
    lowered = heading.strip().lower()
    kept = [ch for ch in lowered if ch.isalnum() or ch in (" ", "-", "_")]
    return "".join(kept).replace(" ", "-")


def compact_whitespace(text):
    return re.sub(r"\s+", " ", text)


class SecurityOperationsContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.operations_path = ROOT / "SECURITY_OPERATIONS.md"
        cls.operations = cls.operations_path.read_text(encoding="utf-8")
        cls.backlog = (ROOT / "BACKLOG.md").read_text(encoding="utf-8")
        cls.status = (ROOT / "STATUS.md").read_text(encoding="utf-8")
        cls.decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")

    def test_draft_identity_scope_and_pending_approval(self):
        self.assertTrue(self.operations_path.exists())
        self.assertIn("# Security Digest Security Operations", self.operations)
        self.assertIn("**Version:** Draft 0.1", self.operations)
        self.assertIn("**Status:** User and external review pending", self.operations)
        self.assertIn("personally managed static site", self.operations)
        self.assertIn("Runtime implementation", self.operations)
        self.assertIn("production execution are out of scope", self.operations)

    def test_requirements_and_decision_references(self):
        for reference in (
            "SR-043",
            "GAP-006",
            "GAP-008",
            "GAP-013",
            "GAP-014",
            "GAP-010",
            "SD-014",
            "SD-024",
            "AGENTS.md",
        ):
            with self.subTest(reference=reference):
                self.assertIn(reference, self.operations)

    def test_history_and_published_output_contract(self):
        self.assertRegex(
            self.operations,
            r"(?s)do not force-push or rewrite history.*daily JSON.*HTML",
        )
        for asset in (
            "`data/YYYY-MM-DD.json`",
            "`data/index.json`",
            "`docs/index.html`",
            "`docs/archive/YYYY-MM-DD.html`",
            "`docs/archive/index.html`",
            "Git repository history",
        ):
            with self.subTest(asset=asset):
                self.assertIn(asset, self.operations)
        self.assertIn("deterministic offline regeneration", self.operations)
        self.assertIn("do not rerun Gemini or external HTTP", self.operations)
        self.assertIn("Do not run the production workflow", self.operations)

    def test_rotation_steps_and_github_token_distinction(self):
        rotation = self.operations.split("## 5. Secret and credential rotation", 1)[1].split(
            "## 6.", 1
        )[0]
        for contract in (
            "revoke or disable",
            "replacement credential",
            "update the corresponding GitHub Actions repository secret",
            "old credential can no longer be used",
            "without recording the value",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, rotation)
        self.assertIn("job-scoped `GITHUB_TOKEN`", rotation)
        self.assertIn("not a long-lived", rotation)

    def test_artifact_retention_and_sensitive_data_boundaries(self):
        artifact = self.operations.split(
            "## 8. Repository-external artifact handling", 1
        )[1].split("## 9.", 1)[0]
        compact_artifact = compact_whitespace(artifact)
        self.assertIn("90 days after the evaluation is completed", artifact)
        self.assertIn("Evaluation summaries", artifact)
        self.assertIn("manifest or hash lists", artifact)
        self.assertIn("approved BL or SD evidence", artifact)
        for prohibited in (
            "secret",
            "credential",
            "authorization header",
            "cookie",
            "private key",
            "unnecessary local absolute path",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertIn(prohibited, compact_artifact)
        self.assertIn("Existing artifacts are not deleted", compact_artifact)
        self.assertIn(
            "not this repository-external artifact policy",
            compact_artifact,
        )

    def test_emergency_and_withdrawal_remain_pending(self):
        self.assertIn(
            "direct production rewrite that bypasses a pull request is not approved",
            self.operations,
        )
        self.assertIn(
            "Draft 0.1 does not unconditionally select or authorize one",
            compact_whitespace(self.operations),
        )
        open_questions = self.operations.split("## 11. Open review questions", 1)[1]
        self.assertIn("Emergency hotfix", open_questions)
        self.assertIn("Withdrawal display", open_questions)
        self.assertIn("These recommendations are not approved decisions", open_questions)

    def test_bl024_and_status_are_active_and_not_complete(self):
        section = self.backlog.split("## BL-024", 1)[1].split("## BL-025", 1)[0]
        self.assertIn(
            "進行中 / SECURITY_OPERATIONS Draft 0.1 / ユーザー・外部レビュー待ち",
            section,
        )
        self.assertIn("Version 1.0前は未完了", section)
        self.assertIn("Draft 0.1のユーザー受入および外部レビューは未実施", section)
        self.assertIn("BL-024", self.status.split("## Active work", 1)[1])
        self.assertNotIn("## SD-025", self.decisions)

    def test_no_local_absolute_path_or_credential_value_pattern(self):
        reviewed = "\n".join((self.operations, self.backlog, self.status))
        self.assertNotRegex(reviewed, r"/Users/[A-Za-z0-9._-]+/")
        self.assertNotRegex(reviewed, r"AKIA[0-9A-Z]{16}")
        self.assertNotRegex(reviewed, r"gh[opusr]_[A-Za-z0-9]{20,}")
        self.assertNotRegex(reviewed, r"AIza[0-9A-Za-z_-]{30,}")
        self.assertNotIn("-----BEGIN PRIVATE KEY-----", reviewed)

    def test_internal_markdown_links_resolve(self):
        files = {
            name: (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "SECURITY_OPERATIONS.md",
                "SECURITY_REQUIREMENTS.md",
                "BACKLOG.md",
                "STATUS.md",
                "DECISIONS.md",
                "AGENTS.md",
            )
        }
        headings = {
            name: {
                github_anchor(match.group(1))
                for match in re.finditer(r"(?m)^#{1,6}\s+(.+?)\s*$", text)
            }
            for name, text in files.items()
        }
        link_pattern = re.compile(r"\]\((?!https?://)([^)#\s]+)(?:#([^)\s]+))?\)")
        for source_name in ("SECURITY_OPERATIONS.md", "BACKLOG.md", "STATUS.md"):
            for target_name, anchor in link_pattern.findall(files[source_name]):
                target_path = ROOT / target_name
                with self.subTest(source=source_name, target=target_name, anchor=anchor):
                    self.assertTrue(target_path.exists(), f"Missing link target: {target_name}")
                    if anchor:
                        self.assertIn(anchor, headings[target_name])


if __name__ == "__main__":
    unittest.main()
