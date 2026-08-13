import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FETCH_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "fetch.yml"
PR_CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "pr-ci.yml"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
CHECKOUT_VERSION_COMMENT = "# v7.0.1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
SETUP_PYTHON_VERSION_COMMENT = "# v7.0.0"


class WorkflowActionPinningTest(unittest.TestCase):
    """BL-026/BL-027: both workflows must pin actions/checkout and
    actions/setup-python to a verified full commit SHA, not a mutable
    major-version tag. BL-027 moved the pinned versions to v7.0.1/v7.0.0."""

    @classmethod
    def setUpClass(cls):
        cls.workflows = {
            "fetch.yml": FETCH_WORKFLOW_PATH.read_text(encoding="utf-8"),
            "pr-ci.yml": PR_CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        }

    def test_workflow_files_exist(self):
        self.assertTrue(FETCH_WORKFLOW_PATH.is_file())
        self.assertTrue(PR_CI_WORKFLOW_PATH.is_file())

    def test_checkout_uses_are_pinned_to_forty_char_sha(self):
        for name, text in self.workflows.items():
            with self.subTest(workflow=name):
                shas = re.findall(r"uses:\s*actions/checkout@([0-9a-f]+)\s", text)
                self.assertTrue(shas, f"No actions/checkout uses found in {name}")
                for sha in shas:
                    self.assertEqual(len(sha), 40, f"{sha!r} in {name} is not 40 chars")
                    self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_setup_python_uses_are_pinned_to_forty_char_sha(self):
        for name, text in self.workflows.items():
            with self.subTest(workflow=name):
                shas = re.findall(r"uses:\s*actions/setup-python@([0-9a-f]+)\s", text)
                self.assertTrue(shas, f"No actions/setup-python uses found in {name}")
                for sha in shas:
                    self.assertEqual(len(sha), 40, f"{sha!r} in {name} is not 40 chars")
                    self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_checkout_sha_matches_approved_v7_0_1(self):
        for name, text in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertIn(
                    f"uses: actions/checkout@{CHECKOUT_SHA} {CHECKOUT_VERSION_COMMENT}",
                    text,
                )

    def test_setup_python_sha_matches_approved_v7_0_0(self):
        for name, text in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertIn(
                    f"uses: actions/setup-python@{SETUP_PYTHON_SHA} "
                    f"{SETUP_PYTHON_VERSION_COMMENT}",
                    text,
                )

    def test_no_mutable_major_version_tag_remains(self):
        for name, text in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertNotIn("actions/checkout@v4", text)
                self.assertNotIn("actions/setup-python@v5", text)
                self.assertNotRegex(text, r"actions/checkout@(?!" + CHECKOUT_SHA + r")\S+")
                self.assertNotRegex(
                    text, r"actions/setup-python@(?!" + SETUP_PYTHON_SHA + r")\S+"
                )

    def test_no_arbitrary_branch_or_tag_reference_is_allowed(self):
        for name, text in self.workflows.items():
            with self.subTest(workflow=name):
                for match in re.finditer(r"uses:\s*(actions/[^\s@]+)@(\S+)", text):
                    action, ref = match.group(1), match.group(2)
                    with self.subTest(action=action, ref=ref):
                        self.assertRegex(
                            ref,
                            r"^[0-9a-f]{40}$",
                            f"{action}@{ref} in {name} is not a full commit SHA",
                        )


class DependabotConfigurationTest(unittest.TestCase):
    """BL-026: weekly github-actions-only Dependabot configuration."""

    DEPENDABOT_PATH = ROOT / ".github" / "dependabot.yml"

    @classmethod
    def setUpClass(cls):
        cls.text = cls.DEPENDABOT_PATH.read_text(encoding="utf-8")

    def test_dependabot_file_exists(self):
        self.assertTrue(self.DEPENDABOT_PATH.is_file())

    def test_declares_version_2(self):
        self.assertRegex(self.text, r"(?m)^version:\s*2$")

    def test_has_exactly_one_update_entry(self):
        entries = re.findall(r"(?m)^\s*-\s*package-ecosystem:", self.text)
        self.assertEqual(len(entries), 1)

    def test_ecosystem_is_github_actions_only(self):
        self.assertRegex(
            self.text,
            r'(?m)^[ \t]*-[ \t]*package-ecosystem:[ \t]*'
            r'(?:"github-actions"|\'github-actions\'|github-actions)'
            r'(?:[ \t]+#.*)?[ \t]*$',
        )
        for other in ("pip", "npm", "docker", "npm-workspaces"):
            with self.subTest(ecosystem=other):
                self.assertNotIn(f'"{other}"', self.text)

    def test_directory_is_repository_root(self):
        self.assertRegex(
            self.text,
            r'(?m)^[ \t]*directory:[ \t]*(?:"/"|\'/\'|/)(?:[ \t]+#.*)?[ \t]*$')

    def test_schedule_is_weekly(self):
        self.assertRegex(
            self.text,
            r'(?m)^[ \t]*interval:[ \t]*(?:"weekly"|\'weekly\'|weekly)'
            r'(?:[ \t]+#.*)?[ \t]*$')

    def test_does_not_include_optional_policy_fields(self):
        for marker in (
            "reviewers",
            "assignees",
            "labels",
            "target-branch",
            "open-pull-requests-limit",
            "registries",
            "groups",
            "ignore",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.text)


if __name__ == "__main__":
    unittest.main()
