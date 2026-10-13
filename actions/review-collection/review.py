"""GitHub runner adapter: inputs are data, reports are private until explicitly shared.

Run with Python isolated mode so the evidence checkout cannot shadow imports.
The runner and its environment files must be trusted and exclusively controlled;
this is not a sandbox against other processes on a shared runner.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

from dspy_security_bench.outputio import check_directory
from dspy_security_bench.proofrun_reports import export_collection_reports


def run(environment) -> tuple[int, dict[str, str]]:
    outputs = {"exit-code": "2", "report-set-complete": "false"}
    try:
        pin = environment.get("PROOFRUN_REVIEW_PIN", "")
        plan = environment.get("PROOFRUN_REVIEW_PLAN", "")
        temporary = environment.get("RUNNER_TEMP", "")
        if (environment.get("RUNNER_OS") != "Linux" or not isinstance(pin, str)
                or re.fullmatch(r"[0-9a-f]{64}", pin) is None
                or not isinstance(plan, str) or not plan.strip()
                or not isinstance(temporary, str) or not Path(temporary).is_absolute()
                or any(ord(c) < 32 or ord(c) == 127 for c in plan + temporary)
                or any(c in temporary for c in "*?[]!")):
            return 2, outputs
        parent = Path(temporary)
        check_directory(parent)
        # Never derive output paths from supplier labels or caller-selected paths.
        container = Path(tempfile.mkdtemp(prefix="proofrun-review-", dir=parent))
        destination = container / "reports"
        receipt = export_collection_reports(Path(plan), destination, expected_plan_file_sha256=pin)
        code = receipt["exit_code"]
        if (type(code) is not int or code not in (0, 1, 2)
                or not receipt["report_set_complete"]):
            return 2, outputs
        outputs.update({"exit-code": str(code), "report-set-complete": "true",
                        "report-directory": str(destination),
                        "manifest-file-sha256": receipt["manifest_file_sha256"]})
        return code, outputs
    except Exception:
        # No paths, source diagnostics, caller values, or exceptions in CI logs.
        return 2, outputs


def main() -> int:
    code, outputs = run(os.environ)
    try:
        # GITHUB_OUTPUT is supplied by the trusted runner, never by the evidence.
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in outputs.items()))
    except (OSError, ValueError, KeyError):
        print("ProofRun review could not record runner outputs.", file=sys.stderr)
        return 2
    print(f"ProofRun collection review: exit={code}; report-set-complete={outputs['report-set-complete']}.")
    print("Selected checks only; no deployment approval, evidence upload, or execution attestation.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
