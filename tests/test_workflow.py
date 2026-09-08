"""Workflow contract tests: trial-run job must exist; no Railway deploy job."""
from __future__ import annotations

import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "test-converter.yml"


class TrialRunJobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_trial_run_job_exists(self) -> None:
        self.assertIn("trial-run:", self.text)

    def test_trial_run_needs_railway_build(self) -> None:
        self.assertIn("needs: railway-build", self.text)

    def test_trial_run_does_real_dial(self) -> None:
        self.assertIn("REAL_TOPK=2", self.text)

    def test_trial_run_checks_exit_ip_via_proxy(self) -> None:
        self.assertIn("socks5h", self.text)
        self.assertIn("api.ipify.org", self.text)

    def test_trial_run_exercises_full_probe(self) -> None:
        self.assertIn("full_probe", self.text)

    def test_no_railway_deploy_job(self) -> None:
        self.assertNotIn("deploy-railway:", self.text)


if __name__ == "__main__":
    unittest.main()
