import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "pr-ci.yml"


class PullRequestCIWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    def test_workflow_file_exists(self):
        self.assertTrue(WORKFLOW_PATH.is_file())

    def test_uses_safe_pull_request_trigger(self):
        self.assertRegex(
            self.workflow,
            r"(?m)^on:\n  pull_request:\n    branches:\n      - main$",
        )
        self.assertNotIn("pull_request_target", self.workflow)
        self.assertNotRegex(self.workflow, r"(?m)^\s*(?:schedule|workflow_dispatch):")

    def test_has_read_only_repository_permissions(self):
        self.assertRegex(self.workflow, r"(?m)^permissions:\n  contents: read$")
        self.assertNotIn("contents: write", self.workflow)

    def test_checkout_and_python_are_pinned_safely(self):
        self.assertIn(
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
            self.workflow,
        )
        self.assertRegex(self.workflow, r"(?m)^\s+fetch-depth: 0$")
        self.assertRegex(self.workflow, r"(?m)^\s+persist-credentials: false$")
        self.assertIn(
            "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
            self.workflow,
        )
        self.assertRegex(self.workflow, r'(?m)^\s+python-version: "3\.12"$')
        self.assertNotIn("actions/checkout@v4", self.workflow)
        self.assertNotIn("actions/setup-python@v5", self.workflow)

    def test_limits_runtime_and_cancels_superseded_runs(self):
        self.assertRegex(self.workflow, r"(?m)^\s+timeout-minutes: 15$")
        self.assertRegex(self.workflow, r"(?m)^\s+cancel-in-progress: true$")
        self.assertIn("github.event.pull_request.number", self.workflow)

    def test_does_not_use_secrets_or_production_commands(self):
        self.assertNotIn("secrets.", self.workflow.lower())
        self.assertNotIn("GEMINI_API_KEY", self.workflow)
        self.assertNotIn("NVD_API_KEY", self.workflow)
        self.assertNotRegex(self.workflow, r"\bfetch\.py\b")
        self.assertNotRegex(self.workflow, r"\bgit\s+(?:add|commit|push)\b")
        self.assertNotIn("docs/", self.workflow)
        self.assertNotIn("data/", self.workflow)

    def test_runs_full_suite_and_checks_actual_pull_request_diff(self):
        self.assertIn(
            'python3 -m unittest discover -p "test_*.py"',
            self.workflow,
        )
        self.assertIn(
            "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
            self.workflow,
        )
        self.assertIn(
            "HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
            self.workflow,
        )
        self.assertIn('git diff --check "$BASE_SHA...$HEAD_SHA"', self.workflow)


if __name__ == "__main__":
    unittest.main()
