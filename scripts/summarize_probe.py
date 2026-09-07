"""Summarize stability probe samples (JSONL) into a markdown report + exit gate.

Sample schema (one JSON object per line):
  {"endpoint": "vpngate-0", "kind": "latency", "ok": true, "seconds": 1.23}
  {"endpoint": "vpngate-0", "kind": "speed", "ok": true, "seconds": 8.1, "mbps": 4.9}

Exit codes: 0 = at least one endpoint passes the gate, 1 = gate failed,
2 = usage error (no samples).
"""
from __future__ import annotations

import argparse
import json
import sys


def summarize(samples: list[dict]) -> dict[str, dict]:
    report: dict[str, dict] = {}
    for sample in samples:
        tag = str(sample.get("endpoint", "?"))
        entry = report.setdefault(tag, {"latency_ok": 0, "latency_total": 0,
                                        "latency_sum": 0.0, "speed_mbps": 0.0})
        if sample.get("kind") == "speed":
            if sample.get("ok"):
                entry["speed_mbps"] = max(entry["speed_mbps"], float(sample.get("mbps", 0.0)))
        else:
            entry["latency_total"] += 1
            if sample.get("ok"):
                entry["latency_ok"] += 1
                entry["latency_sum"] += float(sample.get("seconds", 0.0))
    for entry in report.values():
        ok = entry["latency_ok"]
        entry["latency_avg"] = (entry["latency_sum"] / ok) if ok else 0.0
        entry["success_rate"] = (ok / entry["latency_total"]) if entry["latency_total"] else 0.0
    return report


def qualifies(entry: dict, min_success_rate: float, min_samples: int) -> bool:
    return (entry["latency_total"] >= min_samples
            and entry["success_rate"] >= min_success_rate)


def render_markdown(report: dict[str, dict], min_success_rate: float, min_samples: int) -> str:
    lines = ["| endpoint | latency ok/total | avg latency | speed | verdict |",
             "|---|---|---|---|---|"]
    for tag in sorted(report):
        entry = report[tag]
        verdict = "PASS" if qualifies(entry, min_success_rate, min_samples) else "FAIL"
        lines.append(
            f"| {tag} | {entry['latency_ok']}/{entry['latency_total']} "
            f"| {entry['latency_avg']:.2f}s | {entry['speed_mbps']:.1f} Mbps | {verdict} |"
        )
    return "\n".join(lines) + "\n"


def run(samples: list[dict], min_success_rate: float = 0.8, min_samples: int = 3) -> tuple[int, str]:
    if not samples:
        return 2, "no samples to summarize\n"
    report = summarize(samples)
    markdown = render_markdown(report, min_success_rate, min_samples)
    if any(qualifies(entry, min_success_rate, min_samples) for entry in report.values()):
        return 0, markdown
    return 1, markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize stability probe JSONL")
    parser.add_argument("--input", default="-", help="JSONL file or - for stdin")
    parser.add_argument("--min-success-rate", type=float, default=0.8)
    parser.add_argument("--min-samples", type=int, default=3)
    parser.add_argument("--summary-file", default=None,
                        help="append markdown report here (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(argv)

    text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    samples = [json.loads(line) for line in text.splitlines() if line.strip()]
    code, markdown = run(samples, args.min_success_rate, args.min_samples)
    sys.stdout.write(markdown)
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as handle:
            handle.write("## Stability probe\n\n" + markdown + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
