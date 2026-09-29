"""Offline, fixed-scope repeated-trial accounting from retained scan evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from dspy_security_bench.jsonio import decode_json_object, read_json_object
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.evidence import (
    IDENTITY_FIELDS,
    MAX_BYTES,
    MAX_ROWS,
    expected_observation_keys,
    verify_scan_evidence,
)

MAX_TRIALS = 100
AXES = ("security", "utility", "secure_and_useful")
CLAIM_BOUNDARY = (
    "Descriptive repeated observations on a declared fixed matrix, not independent trials, "
    "a population estimate, confidence interval, pass-at-k estimate, causal effect, or approval. "
    "Rates condition on complete trials; missing runs and execution errors are not successes "
    "or measured failures. Every planned trial remains visible. Identical evidence digests "
    "can reflect identical outcomes or replay; neither independence nor distinct execution "
    "is established. Plan pins establish identity, not when a plan was made or execution "
    "authenticity. Truth, completeness outside the plan, and unreported attempts cannot be "
    "verified. Review identifiers before sharing; retain source evidence and provenance."
)


def _identifier(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) is not None


def _digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_study_plan(plan: dict, expected_sha256: str | None = None) -> set[tuple[str, ...]]:
    fields = {"schema_version", "protocol_version", "study_id", "scope", "policy_sha256",
              "baseline_sha256", "trial_ids", "plan_sha256"}
    if (not isinstance(plan, dict) or set(plan) != fields
            or type(plan["schema_version"]) is not int or plan["schema_version"] != 1
            or plan["protocol_version"] != "scan-study-plan-v1" or not _identifier(plan["study_id"])):
        raise ValueError("invalid scan study plan")
    trials = plan["trial_ids"]
    if (not isinstance(trials, list) or not 2 <= len(trials) <= MAX_TRIALS
            or not all(_identifier(item) for item in trials) or len(set(trials)) != len(trials)):
        raise ValueError("study requires 2 to 100 unique bounded trial IDs")
    if not all(_digest(plan[key]) for key in ("policy_sha256", "baseline_sha256", "plan_sha256")):
        raise ValueError("study plan digests must be lowercase SHA-256")
    if canonical_sha256({k: v for k, v in plan.items() if k != "plan_sha256"}) != plan["plan_sha256"]:
        raise ValueError("study plan digest does not recompute")
    if expected_sha256 is not None and (not _digest(expected_sha256) or expected_sha256 != plan["plan_sha256"]):
        raise ValueError("study plan differs from the independently retained pin")
    keys = expected_observation_keys(plan["scope"])
    if len(keys) * len(trials) > MAX_ROWS:
        raise ValueError("study exceeds 100000 planned case-trial observations")
    return keys


def build_study_plan(evidence: dict, study_id: str, trial_count: int) -> dict:
    verify_scan_evidence(evidence)
    if type(trial_count) is not int or not 2 <= trial_count <= MAX_TRIALS:
        raise ValueError("study requires 2 to 100 trials")
    plan = {"schema_version": 1, "protocol_version": "scan-study-plan-v1", "study_id": study_id,
            "scope": json.loads(json.dumps(evidence["scope"])),
            "policy_sha256": canonical_sha256(evidence["policy"]),
            "baseline_sha256": canonical_sha256(evidence["baseline"]),
            "trial_ids": [f"trial-{i:03d}" for i in range(1, trial_count + 1)]}
    plan["plan_sha256"] = canonical_sha256(plan)
    validate_study_plan(plan)
    return plan


def _trial_index(plan: dict, trials: list) -> dict:
    if not isinstance(trials, list) or len(trials) != len(plan["trial_ids"]):
        raise ValueError("every planned trial must be declared, including missing runs")
    indexed = {}
    for trial in trials:
        if not isinstance(trial, dict):
            raise ValueError("invalid trial declaration")
        status = trial.get("status")
        fields = {"trial_id", "status"} | ({"evidence_sha256"} if status == "complete" else set())
        trial_id = trial.get("trial_id")
        if (set(trial) != fields or status not in ("complete", "missing", "execution_error")
                or not _identifier(trial_id) or trial_id not in plan["trial_ids"] or trial_id in indexed
                or (status == "complete" and not _digest(trial["evidence_sha256"]))):
            raise ValueError("invalid, unknown, or repeated trial declaration")
        indexed[trial_id] = trial
    return indexed


def build_scan_study(plan: dict, trials: list, evidence_by_trial: dict,
                     expected_plan_sha256: str | None = None) -> dict:
    """Reverify every complete source; incomplete attempts stay in the denominator audit."""
    keys = validate_study_plan(plan, expected_plan_sha256)
    indexed = _trial_index(plan, trials)
    complete_ids = {key for key, value in indexed.items() if value["status"] == "complete"}
    if not isinstance(evidence_by_trial, dict) or set(evidence_by_trial) != complete_ids:
        raise ValueError("source evidence must exactly match complete trial declarations")
    counts = {key: dict.fromkeys(AXES, 0) for key in keys}
    sources, digest_groups = [], defaultdict(list)
    for trial_id in plan["trial_ids"]:
        trial = indexed[trial_id]
        source = dict(trial)
        if trial["status"] == "complete":
            evidence = evidence_by_trial[trial_id]
            verified = verify_scan_evidence(evidence, trial["evidence_sha256"])
            if (canonical_sha256(evidence["scope"]) != canonical_sha256(plan["scope"])
                    or canonical_sha256(evidence["policy"]) != plan["policy_sha256"]
                    or canonical_sha256(evidence["baseline"]) != plan["baseline_sha256"]):
                raise ValueError("trial scope, policy, or baseline differs from the study plan")
            source["requirements_met"] = verified["requirements_met"]
            digest_groups[evidence["evidence_sha256"]].append(trial_id)
            for row in evidence["observations"]:
                count = counts[tuple(row[field] for field in IDENTITY_FIELDS)]
                count["security"] += row["security"]
                count["utility"] += row["utility"]
                count["secure_and_useful"] += row["security"] * row["utility"]
        sources.append(source)
    completed = len(complete_ids)
    cases = []
    for key, count in sorted(counts.items()):
        case = dict(zip(IDENTITY_FIELDS, key, strict=True))
        for axis in AXES:
            successes = count[axis]
            case[axis] = {"successes": successes, "failures": completed - successes,
                          "observed_trials": completed,
                          "observed_rate": successes / completed if completed else None,
                          "varied": 0 < successes < completed}
        cases.append(case)
    observations = completed * len(keys)
    summary = {
        "planned_trials": len(trials), "complete_trials": completed,
        "missing_trials": sum(t["status"] == "missing" for t in trials),
        "execution_error_trials": sum(t["status"] == "execution_error" for t in trials),
        "cases_per_trial": len(keys), "planned_observations": len(keys) * len(trials),
        "observed_observations": observations,
        "all_trials_complete": completed == len(trials),
        "completed_trials_meeting_requirements": sum(t.get("requirements_met", False) for t in sources),
        "study_requirements_met": completed == len(trials) and all(t["requirements_met"] for t in sources),
    }
    for axis in AXES:
        successes = sum(count[axis] for count in counts.values())
        summary[axis] = {
            "successes": successes, "failures": observations - successes,
            "observed_rate": successes / observations if observations else None,
            "cases_with_observed_failure": sum(completed > count[axis] for count in counts.values()),
            "cases_with_varied_outcomes": sum(0 < count[axis] < completed for count in counts.values()),
            "cases_successful_in_all_observed_trials": sum(completed > 0 and count[axis] == completed
                                                          for count in counts.values()),
        }
    report = {
        "schema_version": 1, "protocol_version": "scan-study-v1",
        "report_type": "DSPy Security Bench fixed-scope scan study", "plan": plan,
        "trials": sources, "summary": summary, "cases": cases,
        "repeated_evidence_groups": [{"evidence_sha256": digest, "trial_ids": ids}
                                     for digest, ids in sorted(digest_groups.items()) if len(ids) > 1],
        "claim_boundary": CLAIM_BOUNDARY,
    }
    report["study_sha256"] = canonical_sha256(report)
    return report


def verify_scan_study(report: dict, plan: dict, trials: list, evidence_by_trial: dict,
                      expected_plan_sha256: str | None = None) -> None:
    expected = build_scan_study(plan, trials, evidence_by_trial, expected_plan_sha256)
    if canonical_sha256(report) != canonical_sha256(expected):
        raise ValueError("scan study does not exactly recompute from retained inputs")


def _local_source(parent: Path, name: str) -> Path:
    if (not isinstance(name, str) or not name or len(name) > 1024 or "\\" in name
            or ":" in name or any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("study source paths must be relative files beneath the manifest directory")
    path = parent
    for part in name.split("/"):
        path = path / part
        if path.is_symlink():
            raise ValueError("study source paths must not traverse symbolic links")
    if not path.is_file():
        raise ValueError("a complete trial must reference a retained regular source file")
    return path


def load_study_manifest(path: Path, expected_plan_sha256: str | None = None) -> tuple[dict, list, dict]:
    manifest = read_json_object(path, MAX_BYTES)
    if (set(manifest) != {"schema_version", "plan", "trials"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1):
        raise ValueError("invalid study manifest")
    plan = manifest["plan"]
    validate_study_plan(plan, expected_plan_sha256)
    declared = manifest["trials"]
    if not isinstance(declared, list) or len(declared) > MAX_TRIALS:
        raise ValueError("invalid study manifest trials")
    trials, paths = [], {}
    for item in declared:
        if not isinstance(item, dict):
            raise ValueError("invalid study manifest trial")
        trial = dict(item)
        if trial.get("status") == "complete":
            if "evidence" not in trial:
                raise ValueError("complete trial is missing its source reference")
            paths[trial.get("trial_id")] = _local_source(path.resolve().parent, trial.pop("evidence"))
        trials.append(trial)
    _trial_index(plan, trials)
    remaining, evidence = MAX_BYTES, {}
    for trial_id, source in paths.items():
        with source.open("rb") as stream:
            raw = stream.read(remaining + 1)
        if len(raw) > remaining:
            raise ValueError("study sources exceed the combined 50 MB limit")
        evidence[trial_id] = decode_json_object(raw, remaining)
        remaining -= len(raw)
    return plan, trials, evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench scan study", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="derive an unexecuted fixed-scope plan from verified pilot evidence")
    init.add_argument("evidence", type=Path)
    init.add_argument("--study-id", required=True)
    init.add_argument("--trials", type=int, default=3)
    init.add_argument("--out", type=Path, required=True, help="new manifest file; all trials initially missing")
    review = commands.add_parser("review", help="recompute a repeated study without model calls")
    review.add_argument("manifest", type=Path)
    review.add_argument("--expected-plan-sha256")
    output = review.add_mutually_exclusive_group()
    output.add_argument("--json", type=Path, help="new report file")
    output.add_argument("--verify", type=Path, help="retained report to recompute")
    review.add_argument("--fail-on-shortfalls", action="store_true")
    args = parser.parse_args(argv)
    try:
        destination = args.out if args.command == "init" else args.json
        if destination and (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()):
            raise ValueError("study output requires a new file in an existing directory")
        if args.command == "init":
            plan = build_study_plan(read_json_object(args.evidence, MAX_BYTES), args.study_id, args.trials)
            report = {"schema_version": 1, "plan": plan,
                      "trials": [{"trial_id": name, "status": "missing"} for name in plan["trial_ids"]]}
        else:
            plan, trials, evidence = load_study_manifest(args.manifest, args.expected_plan_sha256)
            report = build_scan_study(plan, trials, evidence, args.expected_plan_sha256)
            if args.verify:
                if canonical_sha256(read_json_object(args.verify, MAX_BYTES)) != canonical_sha256(report):
                    raise ValueError("saved study differs from the retained inputs and plan")
        if destination:
            raw = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            if len(raw) > MAX_BYTES:
                raise ValueError("study output exceeds 50 MB")
            with destination.open("xb") as stream:
                stream.write(raw)
    except (OSError, ValueError, TypeError) as exc:
        print(f"[scan study] invalid input or output ({type(exc).__name__}); no successful review", file=sys.stderr)
        return 2
    if args.command == "init":
        print(f"[scan study] unexecuted plan {plan['plan_sha256']}; retain independently before collecting trials")
        return 0
    summary = report["summary"]
    print(f"[scan study] {summary['complete_trials']}/{summary['planned_trials']} complete; "
          f"missing={summary['missing_trials']}; execution_errors={summary['execution_error_trials']}; "
          f"requirements_met={summary['study_requirements_met']}")
    print("[scan study] descriptive complete-trial outcomes only; no execution authenticity or independence established")
    return 1 if args.fail_on_shortfalls and not summary["study_requirements_met"] else 0
