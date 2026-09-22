"""Generate a fictional, offline matched-scan review without credentials."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dspy_security_bench.scan.compare import compare_scan_evidence
from dspy_security_bench.scan.compare_html import render_scan_comparison_html
from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.evidence import build_scan_evidence, evidence_policy


def build_demo_artifacts() -> dict[str, str]:
    """Return deterministic teaching artifacts, never measured model results."""
    scope = {
        "scope_version": 1, "benchmark_version": "v1",
        "agentdojo_distribution_version": "fictional-demo-not-executed",
        "measurement_protocol": "complete-binary-observations-v2",
        "agent_name": "fictional-agent-not-a-model",
        "defenses": ["fictional-defense"],
        "suites": [{"suite": "fictional-teaching-cases", "user_task_ids": [f"case-{i}" for i in range(6)],
                    "attacks": [{"attack": "fictional-input", "is_dos_attack": False,
                                 "injection_task_ids": ["fictional-injection"]}]}],
    }

    def evidence(security, utility):
        rows = [{"suite": "fictional-teaching-cases", "agent": scope["agent_name"],
                 "defense": "fictional-defense", "attack": "fictional-input",
                 "user_task_id": f"case-{i}", "injection_task_id": "fictional-injection",
                 "security": s, "injection_succeeded": 1 - s, "utility": u}
                for i, (s, u) in enumerate(zip(security, utility, strict=True))]
        return build_scan_evidence(scope, evidence_policy(GateSpec(), "error"), rows)

    before = evidence([1, 0, 1, 1, 0, 1], [1, 1, 1, 1, 0, 1])
    after = evidence([0, 1, 1, 1, 0, 1], [1, 0, 1, 1, 1, 1])
    comparison = compare_scan_evidence(before, after)
    artifacts = {name: json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
                 for name, value in (("before.json", before), ("after.json", after),
                                     ("comparison.json", comparison))}
    artifacts["review.html"] = render_scan_comparison_html(comparison).replace(
        '<main id="main">', '<main id="main"><p class="notice"><strong>Fictional teaching demo.</strong> '
        'No model was executed. These invented outcomes are not benchmark results.</p>', 1)
    artifacts["README.md"] = """# Fictional scan review — no model was executed

These six invented cases teach evidence replay and matched comparison. They are
not AgentDojo benchmark results, a model ranking, or deployment evidence.

Open review.html in a browser; it needs no server or internet connection.
From this directory, run:

```sh
dspy-security-bench scan verify before.json
dspy-security-bench scan verify after.json --fail-on-shortfalls
dspy-security-bench scan compare before.json after.json --verify comparison.json
dspy-security-bench scan compare before.json after.json --fail-on-regression
```

Expected exit codes: 0, 1, 0, 1 respectively. Valid evidence is not the same as
meeting requirements. Both security (4/6) and utility (5/6) totals stay unchanged,
but each axis has one newly failing case. Improvements elsewhere do not cancel it.

All identifiers and outcomes are fictional. Digests demonstrate reproducibility,
not execution authenticity. Do not submit these files as measured public results.
"""
    return artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench scan demo", description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new directory beneath an existing parent")
    args = parser.parse_args(argv)
    try:
        artifacts = build_demo_artifacts()
        # A new directory avoids replacing unrelated review artifacts or following
        # an existing output symlink. Partial output on unexpected I/O errors is
        # deliberately retained for inspection, never recursively removed.
        args.out.mkdir(parents=False, exist_ok=False)
        for name, content in artifacts.items():
            with (args.out / name).open("x", encoding="utf-8") as stream:
                stream.write(content)
    except (OSError, TypeError, ValueError) as exc:
        print(f"scan demo: {exc}", file=sys.stderr)
        return 2
    print(f"Fictional offline demo written to {args.out}. Open review.html; no model was executed.")
    return 0
