"""Deterministic fictional repeated-study files, with visible missing/error trials."""

from __future__ import annotations

import json

from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.study import build_scan_study, build_study_plan
from dspy_security_bench.scan.study_html import render_scan_study_html


def build_study_demo_artifacts() -> dict[str, str]:
    scan_demo = build_demo_artifacts()
    before, after = (json.loads(scan_demo[name]) for name in ("before.json", "after.json"))
    plan = build_study_plan(before, "fictional-study-no-model-executed", 5)
    evidence = {"trial-001": before, "trial-002": after, "trial-003": before}
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": source["evidence_sha256"]}
              for name, source in evidence.items()]
    trials += [{"trial_id": "trial-004", "status": "execution_error"},
               {"trial_id": "trial-005", "status": "missing"}]
    declarations = [dict(trial, evidence="after.json" if trial["trial_id"] == "trial-002" else "before.json")
                    if trial["status"] == "complete" else trial for trial in trials]
    manifest = {"schema_version": 1, "plan": plan, "trials": declarations}
    report = build_scan_study(plan, trials, evidence)
    artifacts = {"before.json": scan_demo["before.json"], "after.json": scan_demo["after.json"]}
    for name, value in (("manifest.json", manifest), ("study.json", report)):
        artifacts[name] = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    artifacts["review.html"] = render_scan_study_html(report).replace(
        '<main id="main">', '<main id="main"><p class="notice"><strong>Fictional teaching demo.</strong> '
        'No model was executed. Outcomes and missing/error statuses are invented. '
        'The first source is deliberately reused in trial 3 to illustrate repeated digests.</p>', 1)
    artifacts["README.md"] = """# Fictional repeated study — no model was executed

Open review.html directly; no server, network, provider, or credentials are needed.
Three complete fictional trials, one invented execution error, and one missing
trial demonstrate why conditional success rates need a coverage audit. Trial 3
deliberately reuses trial 1's source; these are not independent measurements.

From this directory:

```sh
dspy-security-bench scan study review manifest.json --verify study.json
dspy-security-bench scan study review manifest.json --verify study.json --fail-on-shortfalls
```

Expected exit codes: 0 (valid recomputation), then 1 (incomplete/unmet requirements).
Do not present these invented outcomes as model results or use them as an
operational baseline. Retain the manifest and both sources for native replay.
"""
    return artifacts
