"""Minimal, bounded scan evidence and model-free recomputation.

Self-consistency is not authenticated execution provenance. Retain and pin the
evidence digest separately; identifiers still need an owner's sharing review.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from itertools import product
from pathlib import Path
from typing import Any

import pandas as pd

from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.gate import evaluate_scan_summaries

MAX_ROWS = 100_000
MAX_BYTES = 50_000_000
IDENTITY_FIELDS = ("suite", "agent", "defense", "attack", "user_task_id", "injection_task_id")
OUTCOME_FIELDS = ("utility", "security", "injection_succeeded")
ROW_FIELDS = (*IDENTITY_FIELDS, *OUTCOME_FIELDS)
POLICY_FIELDS = set(GateSpec.__dataclass_fields__) - {"baseline", "min_utility"} | {"fail_on"}
CLAIM_BOUNDARY = (
    "This artifact retains declared task identities and binary case outcomes, not prompts, "
    "responses, credentials, or tool logs. Verification checks the declared matrix, counts, "
    "policy, baseline, and derived verdict. It does not authenticate execution, validate the "
    "truth of observations, establish benchmark-source identity, or certify safety. Digests "
    "only establish identity when pinned independently. Labels may be sensitive; review "
    "before sharing. Upstream errors already encoded as binary outcomes are not distinguished."
)


def _label(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 512 and value.isprintable() and "|" not in value


def _labels(values: Any, maximum: int = 1000) -> bool:
    return (isinstance(values, list) and 0 < len(values) <= maximum
            and all(_label(value) for value in values) and len(set(values)) == len(values))


def expected_observation_keys(scope: dict) -> set[tuple[str, ...]]:
    """Validate the declared frozen scope and bound the matrix before expansion."""
    if not isinstance(scope, dict) or set(scope) != {
        "scope_version", "benchmark_version", "agentdojo_distribution_version",
        "measurement_protocol", "agent_name", "defenses", "suites",
    }:
        raise ValueError("unsupported evidence scope fields")
    if (type(scope["scope_version"]) is not int or scope["scope_version"] != 1
            or scope["benchmark_version"] != "v1"
            or scope["measurement_protocol"] not in {"complete-binary-observations-v1", "complete-binary-observations-v2"}
            or not _label(scope["agentdojo_distribution_version"])
            or not _label(scope["agent_name"]) or not _labels(scope["defenses"], 50)):
        raise ValueError("unsupported evidence scope")
    suites = scope["suites"]
    if not isinstance(suites, list) or not 1 <= len(suites) <= 20:
        raise ValueError("scope must contain 1 to 20 suites")
    names, expected = set(), set()
    for suite in suites:
        if not isinstance(suite, dict) or set(suite) != {"suite", "user_task_ids", "attacks"}:
            raise ValueError("invalid suite scope")
        name = suite["suite"]
        if not _label(name) or name in names or not _labels(suite["user_task_ids"]):
            raise ValueError("suite and task identities must be unique bounded labels")
        names.add(name)
        attacks = suite["attacks"]
        if not isinstance(attacks, list) or not 1 <= len(attacks) <= 50:
            raise ValueError("scope must contain 1 to 50 attacks per suite")
        attack_names = set()
        for attack in attacks:
            if not isinstance(attack, dict) or set(attack) != {"attack", "is_dos_attack", "injection_task_ids"}:
                raise ValueError("invalid attack scope")
            if (not _label(attack["attack"]) or attack["attack"] in attack_names
                    or type(attack["is_dos_attack"]) is not bool
                    or not _labels(attack["injection_task_ids"])
                    or (attack["is_dos_attack"] and len(attack["injection_task_ids"]) != 1)):
                raise ValueError("invalid attack identities or DoS scope")
            attack_names.add(attack["attack"])
            count = len(scope["defenses"]) * len(suite["user_task_ids"]) * len(attack["injection_task_ids"])
            if len(expected) + count > MAX_ROWS:
                raise ValueError("scan evidence exceeds 100000 declared observations")
            expected.update(product([name], [scope["agent_name"]], scope["defenses"],
                                    [attack["attack"]], suite["user_task_ids"], attack["injection_task_ids"]))
    return expected


def evidence_policy(gate: GateSpec, fail_on: str) -> dict:
    policy = asdict(gate)
    policy.pop("baseline")  # Local/private source paths are not export fields.
    if policy["min_utility"] is None:
        policy.pop("min_utility")
    policy["fail_on"] = fail_on
    return policy


def _gate(policy: dict, baseline: dict | None) -> GateSpec:
    if not isinstance(policy, dict) or set(policy) not in (POLICY_FIELDS, POLICY_FIELDS | {"min_utility"}):
        raise ValueError("evidence policy has missing or unknown fields")
    if "min_utility" in policy and policy["min_utility"] is None:
        raise ValueError("utility evidence policy requires a numeric floor")
    settings = {key: value for key, value in policy.items() if key != "fail_on"}
    gate = GateSpec(**settings, baseline="embedded" if baseline is not None else None)
    gate.validate()
    if policy["fail_on"] not in {"error", "warning", "never"}:
        raise ValueError("invalid enforcement policy")
    if (gate.mode == "regression") != (baseline is not None):
        raise ValueError("baseline presence must match the gate mode")
    return gate


def build_scan_evidence(scope: dict, policy: dict, observations: list[dict], baseline: dict | None = None) -> dict:
    expected = expected_observation_keys(scope)
    gate = _gate(policy, baseline)
    if not isinstance(observations, list) or len(observations) != len(expected):
        raise ValueError("observations must cover the declared scope exactly")
    seen = set()
    for row in observations:
        if not isinstance(row, dict) or set(row) != set(ROW_FIELDS):
            raise ValueError("observations must contain only declared identities and binary outcomes")
        if not all(_label(row[key]) for key in IDENTITY_FIELDS):
            raise ValueError("observation identities must be bounded printable labels")
        key = tuple(row[field] for field in IDENTITY_FIELDS)
        if key not in expected or key in seen:
            raise ValueError("observation matrix contains substitutions or duplicates")
        seen.add(key)
        if any(type(row[field]) is not int or row[field] not in {0, 1} for field in OUTCOME_FIELDS):
            raise ValueError("outcomes must be integer zero or one")
        if row["security"] + row["injection_succeeded"] != 1:
            raise ValueError("security must complement injection success")
    # Aggregate the retained primitive outcomes; never trust saved rates.
    ordered = sorted(observations, key=lambda row: tuple(row[key] for key in IDENTITY_FIELDS))
    frame = pd.DataFrame(ordered)
    summaries = []
    for suite in scope["suites"]:
        cells = frame[frame["suite"] == suite["suite"]].groupby(["agent", "defense", "attack"]).agg(
            security_rate=("security", "mean"), injection_success_rate=("injection_succeeded", "mean"),
            utility_rate=("utility", "mean"), security_successes=("security", "sum"), n_runs=("security", "size"),
        ).reset_index()
        summaries.append((suite["suite"], cells))
    report = evaluate_scan_summaries(summaries, gate, scope, policy["fail_on"], baseline)
    evidence_version = 2 if "min_utility" in policy else 1
    payload = {
        "schema_version": evidence_version, "evidence_type": "dspy-security-bench-scan-evidence",
        "protocol_version": f"scan-evidence-v{evidence_version}", "scope": scope, "policy": policy,
        "baseline": baseline, "observations": ordered, "report": report.to_dict(),
        "claim_boundary": CLAIM_BOUNDARY,
    }
    payload["evidence_sha256"] = canonical_sha256(payload)
    return payload


def write_scan_evidence(path: Path, scope: dict, policy: dict, observations: list[dict], baseline: dict | None = None) -> dict:
    payload = build_scan_evidence(scope, policy, observations, baseline)
    raw = (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("scan evidence exceeds 50 MB")
    with path.open("xb") as stream:
        stream.write(raw)
    return payload


def verify_scan_evidence(payload: dict, expected_sha256: str | None = None) -> dict:
    fields = {"schema_version", "evidence_type", "protocol_version", "scope", "policy",
              "baseline", "observations", "report", "claim_boundary", "evidence_sha256"}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("evidence has missing or unknown fields")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not re.fullmatch("[0-9a-f]{64}", expected_sha256)):
        raise ValueError("expected evidence digest must be lowercase SHA-256")
    rebuilt = build_scan_evidence(payload["scope"], payload["policy"], payload["observations"], payload["baseline"])
    if canonical_sha256(payload) != canonical_sha256(rebuilt):
        raise ValueError("scan evidence does not exactly recompute")
    if expected_sha256 is not None and rebuilt["evidence_sha256"] != expected_sha256:
        raise ValueError("scan evidence differs from the independently retained digest")
    return rebuilt["report"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench scan verify", description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-sha256", help="independently retained canonical evidence digest")
    parser.add_argument("--fail-on-shortfalls", action="store_true", help="exit 1 for unmet requirements even when the recorded enforcement was non-blocking")
    args = parser.parse_args(argv)
    try:
        payload = read_json_object(args.evidence, MAX_BYTES)
        report = verify_scan_evidence(payload, args.expected_sha256)
    except (OSError, ValueError, TypeError) as exc:
        print(f"[scan verify] invalid evidence: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(f"[scan verify] recomputed {payload['evidence_sha256']}; requirements_met={report['requirements_met']}; enforcement={report['enforcement_status']}")
    print("[scan verify] execution authenticity is not established; " + ("digest matched retained pin" if args.expected_sha256 else "no independent digest pin supplied"))
    return 1 if args.fail_on_shortfalls and not report["requirements_met"] else 0
