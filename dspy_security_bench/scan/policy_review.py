"""Offline policy-only sensitivity review of retained scan observations."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.evidence import MAX_BYTES, build_scan_evidence, verify_scan_evidence

REVIEW_TYPE = "dspy-security-bench-scan-policy-review"
CLAIM_BOUNDARY = (
    "Post-hoc policy-only decision analysis on unchanged retained observations. No model was "
    "executed and no new security, utility, or joint outcomes were measured. A more permissive "
    "policy can change a verdict without improving an agent. This does not replace the original "
    "evidence, establish pre-registration, validate post-selection inference, authorize deployment, "
    "or authenticate execution. Review identifiers before sharing; sources and proposed policy "
    "are retained so the analysis can be recomputed."
)


def review_scan_policy(source: dict, proposed_policy: dict, expected_source_sha256: str | None = None) -> dict:
    """Recompute the original and proposed verdicts, never overwrite the source."""
    original = verify_scan_evidence(source, expected_source_sha256)
    if not isinstance(proposed_policy, dict):
        raise ValueError("proposed policy must be an object")
    baseline = source["baseline"] if proposed_policy.get("mode") == "regression" else None
    if proposed_policy.get("mode") == "regression" and baseline is None:
        raise ValueError("regression review requires a baseline already retained in the source")
    reviewed = build_scan_evidence(source["scope"], proposed_policy, source["observations"], baseline)["report"]
    summary = {
        "observations_reused": len(source["observations"]), "model_calls_performed": 0,
        "policy_changed": canonical_sha256(source["policy"]) != canonical_sha256(proposed_policy),
        "original_requirements_met": original["requirements_met"],
        "reviewed_requirements_met": reviewed["requirements_met"],
        "original_enforcement_status": original["enforcement_status"],
        "reviewed_enforcement_status": reviewed["enforcement_status"],
        "original_shortfall_findings": sum(not finding["passed"] for finding in original["findings"]),
        "reviewed_shortfall_findings": sum(not finding["passed"] for finding in reviewed["findings"]),
    }
    result = {
        "schema_version": 1, "proof_type": REVIEW_TYPE, "protocol_version": "scan-policy-review-v1",
        "source_evidence": source, "source_evidence_sha256": source["evidence_sha256"],
        "proposed_policy": proposed_policy, "reviewed_report": reviewed,
        "summary": summary, "claim_boundary": CLAIM_BOUNDARY,
    }
    result["review_sha256"] = canonical_sha256(result)
    return json.loads(json.dumps(result, allow_nan=False))


def verify_policy_review(review: dict, expected_source_sha256: str | None = None,
                         expected_review_sha256: str | None = None) -> dict:
    fields = {"schema_version", "proof_type", "protocol_version", "source_evidence", "source_evidence_sha256",
              "proposed_policy", "reviewed_report", "summary", "claim_boundary", "review_sha256"}
    if not isinstance(review, dict) or set(review) != fields:
        raise ValueError("invalid scan policy review structure")
    if expected_review_sha256 is not None:
        from dspy_security_bench.scan.study import _digest

        if not _digest(expected_review_sha256) or expected_review_sha256 != review["review_sha256"]:
            raise ValueError("policy review differs from the independently retained pin")
    expected = review_scan_policy(review["source_evidence"], review["proposed_policy"], expected_source_sha256)
    if canonical_sha256(review) != canonical_sha256(expected):
        raise ValueError("policy review does not exactly recompute")
    return expected["summary"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench scan policy", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="copy a verified source's original policy for explicit owner editing")
    init.add_argument("source", type=Path)
    init.add_argument("--out", type=Path, required=True)
    init.add_argument("--expected-source-sha256")
    review = commands.add_parser("review", help="apply a proposed policy without running an agent")
    review.add_argument("source", type=Path)
    review.add_argument("--policy", type=Path, required=True)
    review.add_argument("--out", type=Path, required=True, help="new portable policy-review JSON, not scan evidence")
    review.add_argument("--expected-source-sha256")
    review.add_argument("--fail-on-shortfalls", action="store_true")
    review.add_argument("--html", type=Path, help="new script-free review page")
    verify = commands.add_parser("verify", help="recompute both verdicts from a retained policy review")
    verify.add_argument("path", type=Path)
    verify.add_argument("--expected-source-sha256")
    verify.add_argument("--expected-review-sha256")
    verify.add_argument("--fail-on-shortfalls", action="store_true")
    verify.add_argument("--html", type=Path, help="new page rendered only after native verification")
    args = parser.parse_args(argv)
    try:
        destinations = [args.out] if args.command in ("init", "review") else []
        if args.command != "init" and args.html:
            destinations.append(args.html)
        if len({path.resolve() for path in destinations}) != len(destinations):
            raise ValueError("policy outputs must be distinct")
        if any(path.exists() or path.is_symlink() or not path.parent.is_dir() for path in destinations):
            raise ValueError("policy outputs must be new files beneath existing directories")
        artifacts = {}
        if args.command in ("init", "review"):
            source = read_json_object(args.source, MAX_BYTES)
            if args.command == "init":
                verify_scan_evidence(source, args.expected_source_sha256)
                output = source["policy"]
            else:
                proposed = read_json_object(args.policy, 1_000_000)
                output = review_scan_policy(source, proposed, args.expected_source_sha256)
                summary = output["summary"]
            raw = (json.dumps(output, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            artifacts[args.out] = raw
        else:
            output = read_json_object(args.path, MAX_BYTES)
            summary = verify_policy_review(output, args.expected_source_sha256, args.expected_review_sha256)
        if args.command != "init" and args.html:
            from dspy_security_bench.scan.policy_html import render_policy_review_html

            artifacts[args.html] = render_policy_review_html(output).encode("utf-8")
        if any(len(raw) > MAX_BYTES for raw in artifacts.values()):
            raise ValueError("policy review output exceeds 50 MB")
        for path, raw in artifacts.items():
            with path.open("xb") as stream:
                stream.write(raw)
    except (OSError, ValueError, TypeError) as exc:
        print(f"[scan policy] invalid input or output ({type(exc).__name__}); no successful review", file=sys.stderr)
        return 2
    if args.command == "init":
        print("[scan policy] copied the original policy for explicit review; no model was executed")
        return 0
    print(f"[scan policy] POST-HOC POLICY-ONLY REVIEW; original requirements={summary['original_requirements_met']}; "
          f"proposed requirements={summary['reviewed_requirements_met']}; "
          f"unchanged observations={summary['observations_reused']}; model calls=0")
    print("[scan policy] a changed verdict does not measure an improved agent; original evidence retained")
    return 1 if args.fail_on_shortfalls and not summary["reviewed_requirements_met"] else 0
