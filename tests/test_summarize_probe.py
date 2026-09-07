"""Tests for scripts/summarize_probe.py (stability report + pass/fail gate)."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "summarize_probe.py"


def load_module():
    spec = importlib.util.spec_from_file_location("summarize_probe", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def latency(endpoint, ok=True, seconds=1.2):
    return {"endpoint": endpoint, "kind": "latency", "ok": ok, "seconds": seconds}


def speed(endpoint, ok=True, seconds=8.0, mbps=5.0):
    return {"endpoint": endpoint, "kind": "speed", "ok": ok, "seconds": seconds, "mbps": mbps if ok else 0.0}


class SummarizeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_stable_endpoint_passes(self) -> None:
        samples = [latency("vpngate-0", seconds=1.0 + i * 0.1) for i in range(6)]
        samples.append(speed("vpngate-0"))

        code, markdown = self.mod.run(samples)

        self.assertEqual(0, code)
        self.assertIn("vpngate-0", markdown)
        self.assertIn("6/6", markdown)
        self.assertIn("PASS", markdown)

    def test_flaky_endpoint_fails_gate(self) -> None:
        samples = [latency("vpngate-0", ok=(i >= 4)) for i in range(6)]

        code, markdown = self.mod.run(samples)

        self.assertEqual(1, code)
        self.assertIn("2/6", markdown)
        self.assertIn("FAIL", markdown)

    def test_one_stable_endpoint_saves_the_run(self) -> None:
        samples = [latency("vpngate-0", ok=False) for _ in range(6)]
        samples += [latency("vpngate-1") for _ in range(6)]

        code, _ = self.mod.run(samples)

        self.assertEqual(0, code)

    def test_empty_samples_is_usage_error(self) -> None:
        code, markdown = self.mod.run([])

        self.assertEqual(2, code)
        self.assertIn("no samples", markdown)

    def test_avg_latency_is_reported(self) -> None:
        samples = [latency("vpngate-0", seconds=2.0) for _ in range(4)]

        _, markdown = self.mod.run(samples, min_samples=3)

        self.assertIn("2.00s", markdown)

    def test_too_few_samples_does_not_qualify(self) -> None:
        samples = [latency("vpngate-0")]

        code, _ = self.mod.run(samples, min_samples=3)

        self.assertEqual(1, code)

    def test_p50_p95_reported(self) -> None:
        samples = [latency("vpngate-0", seconds=float(s)) for s in (1, 2, 3, 4, 5, 6)]

        _, markdown = self.mod.run(samples)

        self.assertIn("p50 3.50s", markdown)
        self.assertIn("p95 5.75s", markdown)

    def test_worst_ok_speed_reported(self) -> None:
        samples = [latency("vpngate-0") for _ in range(4)]
        samples.append(speed("vpngate-0", mbps=47.0))
        samples.append(speed("vpngate-1", mbps=19.0))

        _, markdown = self.mod.run(samples, min_samples=3)

        self.assertIn("worst ok speed: 19.0 Mbps", markdown)

    def test_dial_vs_http_failures_distinguished(self) -> None:
        samples = [latency("vpngate-0") for _ in range(4)]
        failing = dict(latency("vpngate-0", ok=False, seconds=0.0))
        failing["reason"] = "dial"
        samples.append(failing)
        failing = dict(latency("vpngate-0", ok=False, seconds=0.5))
        failing["reason"] = "http_500"
        samples.append(failing)

        _, markdown = self.mod.run(samples, min_samples=3)

        self.assertIn("dial failures: 1", markdown)
        self.assertIn("http failures: 1", markdown)


if __name__ == "__main__":
    unittest.main()
