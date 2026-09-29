"""Portable study evidence: retained inputs, not authenticated execution claims."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.study import (
    MAX_BYTES,
    MAX_TRIALS,
    _digest,
    build_scan_study,
    load_study_manifest,
    validate_study_plan,
)

BUNDLE_TYPE = "dspy-security-bench-scan-study-bundle"
CLAIM_BOUNDARY = (
    "This portable bundle retains native scan sources and a recomputable fixed-scope study. "
    "Source-file paths are excluded, but identifiers and outcomes remain; review before sharing. "
    "Deduplication preserves all trial declarations and does not establish independent execution. "
    "Digests provide content identity, not authenticity, trusted time, signatures, completeness "
    "outside the plan, production reliability, certification, or approval."
)


def build_study_bundle(plan: dict, trials: list, evidence_by_trial: dict,
                       expected_plan_sha256: str | None = None) -> dict:
    study = build_scan_study(plan, trials, evidence_by_trial, expected_plan_sha256)
    sources = {item["evidence_sha256"]: item for item in evidence_by_trial.values()}
    bundle = {"schema_version": 1, "proof_type": BUNDLE_TYPE,
              "protocol_version": "scan-study-bundle-v1", "study": study,
              "sources": sources, "claim_boundary": CLAIM_BOUNDARY}
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    # Detach from callers' mutable sources and plan without altering JSON types.
    return json.loads(json.dumps(bundle, allow_nan=False))


def verify_study_bundle(bundle: dict, expected_plan_sha256: str | None = None,
                        expected_bundle_sha256: str | None = None) -> dict:
    fields = {"schema_version", "proof_type", "protocol_version", "study", "sources",
              "claim_boundary", "bundle_sha256"}
    if (not isinstance(bundle, dict) or set(bundle) != fields
            or type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1
            or bundle["proof_type"] != BUNDLE_TYPE or bundle["protocol_version"] != "scan-study-bundle-v1"
            or bundle["claim_boundary"] != CLAIM_BOUNDARY or not _digest(bundle["bundle_sha256"])):
        raise ValueError("invalid study bundle structure")
    if expected_bundle_sha256 is not None and (
            not _digest(expected_bundle_sha256) or expected_bundle_sha256 != bundle["bundle_sha256"]):
        raise ValueError("study bundle differs from the independently retained pin")
    if canonical_sha256({k: v for k, v in bundle.items() if k != "bundle_sha256"}) != bundle["bundle_sha256"]:
        raise ValueError("study bundle digest does not recompute")
    study, sources = bundle["study"], bundle["sources"]
    if (not isinstance(study, dict) or not isinstance(sources, dict) or len(sources) > MAX_TRIALS
            or not all(_digest(key) for key in sources)):
        raise ValueError("invalid study bundle report or source index")
    plan = study.get("plan")
    validate_study_plan(plan, expected_plan_sha256)
    declared = study.get("trials")
    if not isinstance(declared, list) or len(declared) != len(plan["trial_ids"]):
        raise ValueError("study bundle must retain the full trial roster")
    trials, used, evidence = [], set(), {}
    for item in declared:
        if not isinstance(item, dict):
            raise ValueError("invalid bundled trial")
        trial = dict(item)
        if trial.get("status") == "complete":
            trial.pop("requirements_met", None)  # recomputed below, not trusted
            digest = trial.get("evidence_sha256")
            trial_id = trial.get("trial_id")
            if not _digest(digest) or digest not in sources or not isinstance(trial_id, str):
                raise ValueError("complete bundled trial lacks its exact retained source")
            used.add(digest)
            evidence[trial_id] = sources[digest]
        trials.append(trial)
    if used != set(sources):
        raise ValueError("bundle sources must exactly cover complete trials with no extras")
    expected = build_scan_study(plan, trials, evidence, expected_plan_sha256)
    if canonical_sha256(study) != canonical_sha256(expected):
        raise ValueError("bundled study does not exactly recompute from retained sources")
    return expected["summary"]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench scan study " + argv[0])
    parser.add_argument("path", type=Path, help="manifest to bundle, or retained bundle to verify")
    parser.add_argument("--expected-plan-sha256")
    if argv[0] == "bundle":
        parser.add_argument("--out", type=Path, required=True, help="new self-contained JSON file")
    else:
        parser.add_argument("--expected-bundle-sha256")
        parser.add_argument("--html", type=Path, help="new script-free page rendered only after native verification")
    parser.add_argument("--fail-on-shortfalls", action="store_true")
    args = parser.parse_args(argv[1:])
    try:
        if argv[0] == "bundle":
            if args.out.exists() or args.out.is_symlink() or not args.out.parent.is_dir():
                raise ValueError("bundle output must be a new file beneath an existing directory")
            inputs = load_study_manifest(args.path, args.expected_plan_sha256)
            bundle = build_study_bundle(*inputs, args.expected_plan_sha256)
            raw = (json.dumps(bundle, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            if len(raw) > MAX_BYTES:
                raise ValueError("study bundle exceeds 50 MB")
            summary = verify_study_bundle(bundle, args.expected_plan_sha256)
            with args.out.open("xb") as stream:
                stream.write(raw)
        else:
            if args.html and (args.html.exists() or args.html.is_symlink() or not args.html.parent.is_dir()):
                raise ValueError("bundle HTML output must be a new file beneath an existing directory")
            bundle = read_json_object(args.path, MAX_BYTES)
            summary = verify_study_bundle(bundle, args.expected_plan_sha256, args.expected_bundle_sha256)
            if args.html:
                from dspy_security_bench.scan.study_html import render_scan_study_html

                raw = render_scan_study_html(bundle["study"]).encode("utf-8")
                if len(raw) > MAX_BYTES:
                    raise ValueError("bundle HTML exceeds 50 MB")
                with args.html.open("xb") as stream:
                    stream.write(raw)
    except (OSError, TypeError, ValueError) as exc:
        print(f"[scan study bundle] invalid input or output ({type(exc).__name__}); no verified bundle", file=sys.stderr)
        return 2
    print(f"[scan study bundle] verified {bundle['bundle_sha256']}; "
          f"complete={summary['complete_trials']}/{summary['planned_trials']}; "
          f"requirements_met={summary['study_requirements_met']}; execution authenticity not established")
    return 1 if args.fail_on_shortfalls and not summary["study_requirements_met"] else 0
