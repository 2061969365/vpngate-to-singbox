"""Workflow contract tests: deploy-railway job must exist with the right guards."""
from __future__ import annotations

import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "test-converter.yml"


class DeployJobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_deploy_railway_job_exists(self) -> None:
        self.assertIn("deploy-railway:", self.text)

    def test_deploy_needs_railway_build(self) -> None:
        self.assertIn("needs: railway-build", self.text)

    def test_deploy_uses_railway_up(self) -> None:
        self.assertIn("railway up", self.text)

    def test_deploy_requires_token_and_service_secrets(self) -> None:
        self.assertIn("RAILWAY_TOKEN", self.text)
        self.assertIn("RAILWAY_SERVICE_ID", self.text)

    def test_deploy_guarded_to_main_push_or_dispatch(self) -> None:
        self.assertIn("refs/heads/main", self.text)
        self.assertIn("workflow_dispatch", self.text)


if __name__ == "__main__":
    unittest.main()
