"""Content-free, deterministic integrity evidence for AI-agent evaluations.

EvalIntegrityProof reviews an operator-supplied structural record. It never
loads a model, reveals a holdout, executes an evaluator, reads credentials,
contacts a network, or makes a deployment decision.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

SCENARIO_TYPE = "dspy-security-bench-evalintegrityproof-scenario"
REPORT_TYPE = "EvalIntegrityProof / Evaluation-process integrity evidence"
PROTOCOL_VERSION = "evalintegrityproof-v1"
ANALYZER = "deterministic-evaluation-integrity-analyzer-v1"
MAX_SCENARIO_BYTES = 2_000_000
MAX_SOURCES = 50
MAX_CASES = 10_000_000
MAX_CLOCK_SKEW_MS = 86_400_000
CLAIM_BOUNDARY = (
    "EvalIntegrityProof deterministically recomputes a bounded, content-free structural record "
    "about one AI-agent evaluation. It does not run or score an evaluation, establish that "
    "operator assertions are externally true, reveal holdouts, inspect prompts or outputs, "
    "prove model alignment, certify security or compliance, authorize deployment, or accept "
    "risk. Accountable owners retain every evaluation, incident, release, and deployment decision."
)
LIMITATIONS = (
    "Digest shape and recomputation do not establish who created the referenced artifacts.",
    "Source completeness, independence, and boundary observations remain operator assertions unless separately attested.",
    "A zero canary-hit count covers only the declared detector and does not prove the absence of all leakage.",
    "Case accounting establishes structural closure, not semantic correctness of scores or labels.",
    "The report applies only to the declared evaluation run and is not a prediction of future integrity.",
)

CONTROLS: dict[str, dict[str, Any]] = {
    "EI001": {
        "title": "Workload, evaluator, environment, case-set, and scoring artifacts are pinned",
        "category": "artifact-identity",
        "source_classes": ["artifact-registry", "evaluator"],
        "evidence_paths": ["/artifacts"],
    },
    "EI002": {
        "title": "Holdout case-set commitment predates evaluation start",
        "category": "holdout-integrity",
        "source_classes": ["orchestrator", "time"],
        "evidence_paths": ["/run/holdout_committed_at", "/run/started_at"],
    },
    "EI003": {
        "title": "Results are committed before labels are revealed",
        "category": "commit-reveal-ordering",
        "source_classes": ["evaluator", "time"],
        "evidence_paths": [
            "/run/started_at",
            "/run/result_committed_at",
            "/run/labels_revealed_at",
        ],
    },
    "EI004": {
        "title": "Workload and evaluator use separate failure domains",
        "category": "failure-domain-separation",
        "source_classes": ["orchestrator", "evaluator"],
        "evidence_paths": [
            "/boundaries/workload_failure_domain_id",
            "/boundaries/evaluator_failure_domain_id",
        ],
    },
    "EI005": {
        "title": "Workload cannot read evaluator state or unrevealed labels",
        "category": "evaluator-data-isolation",
        "source_classes": ["evaluator", "monitor"],
        "evidence_paths": [
            "/boundaries/evaluator_state_readable_by_workload",
            "/boundaries/label_store_readable_before_result_commit",
        ],
    },
    "EI006": {
        "title": "Workload and evaluator credential scopes are separate",
        "category": "credential-separation",
        "source_classes": ["identity", "evaluator"],
        "evidence_paths": [
            "/boundaries/workload_credential_scope_id",
            "/boundaries/evaluator_credential_scope_id",
        ],
    },
    "EI007": {
        "title": "Evaluation egress is denied or simulated without unauthorized egress",
        "category": "network-isolation",
        "source_classes": ["network", "monitor"],
        "evidence_paths": [
            "/boundaries/network_egress_policy",
            "/boundaries/unauthorized_egress_observed",
        ],
    },
    "EI008": {
        "title": "Every planned case is committed or safely stopped",
        "category": "case-accounting",
        "source_classes": ["orchestrator", "evaluator"],
        "evidence_paths": [
            "/run/case_count_planned",
            "/run/case_count_started",
            "/run/case_count_committed",
            "/run/case_count_safe_stopped",
        ],
    },
    "EI009": {
        "title": "Active leakage-canary monitoring reports no hits",
        "category": "holdout-leakage",
        "source_classes": ["monitor", "evaluator"],
        "evidence_paths": [
            "/monitoring/canary_detector_enabled",
            "/monitoring/leakage_canary_hits",
        ],
    },
    "EI010": {
        "title": "An independent, complete monitor observes the evaluation",
        "category": "monitor-independence",
        "source_classes": ["monitor"],
        "evidence_paths": [
            "/monitoring/independent_control",
            "/monitoring/complete",
        ],
    },
    "EI011": {
        "title": "The evaluation provides a safe exit and records no forced unsafe continuation",
        "category": "safe-exit",
        "source_classes": ["orchestrator", "monitor"],
        "evidence_paths": [
            "/boundaries/safe_exit_available",
            "/boundaries/unsafe_continuation_count",
        ],
    },
    "EI012": {
        "title": "The integrity record contains no prompts, outputs, or credential values",
        "category": "content-minimization",
        "source_classes": ["orchestrator", "identity"],
        "evidence_paths": [
            "/execution/raw_prompts_embedded",
            "/execution/raw_outputs_embedded",
            "/execution/credential_values_embedded",
        ],
    },
    "EI013": {
        "title": "Observed clock skew stays within the declared ordering tolerance",
        "category": "clock-integrity",
        "source_classes": ["time", "monitor"],
        "evidence_paths": ["/monitoring/clock_skew_ms", "/policy/max_clock_skew_ms"],
    },
}

SOURCE_CLASSES = (
    "orchestrator",
    "artifact-registry",
    "evaluator",
    "network",
    "identity",
    "monitor",
    "time",
)
BUILT_IN_PROFILES = (
    "integrity-reference",
    "label-leakage",
    "monitor-gap",
    "incomplete-record",
)
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SCENARIO_FIELDS = {
    "schema_version",
    "scenario_type",
    "scenario_id",
    "title",
    "description",
    "execution",
    "policy",
    "artifacts",
    "run",
    "boundaries",
    "monitoring",
    "sources",
    "control_evidence",
    "claim_boundary",
    "scenario_sha256",
}
_EXECUTION_FIELDS = {
    "review_mode",
    "production_access",
    "network_actions_performed",
    "credential_values_embedded",
    "raw_prompts_embedded",
    "raw_outputs_embedded",
}
_POLICY_FIELDS = {"max_clock_skew_ms"}
_ARTIFACT_FIELDS = {
    "workload_sha256",
    "evaluator_sha256",
    "environment_sha256",
    "case_set_commitment_sha256",
    "scoring_policy_sha256",
}
_RUN_FIELDS = {
    "run_id",
    "holdout_committed_at",
    "started_at",
    "result_committed_at",
    "labels_revealed_at",
    "case_count_planned",
    "case_count_started",
    "case_count_committed",
    "case_count_safe_stopped",
}
_BOUNDARY_FIELDS = {
    "workload_failure_domain_id",
    "evaluator_failure_domain_id",
    "workload_credential_scope_id",
    "evaluator_credential_scope_id",
    "evaluator_state_readable_by_workload",
    "label_store_readable_before_result_commit",
    "network_egress_policy",
    "unauthorized_egress_observed",
    "safe_exit_available",
    "unsafe_continuation_count",
}
_MONITORING_FIELDS = {
    "independent_control",
    "complete",
    "clock_skew_ms",
    "canary_detector_enabled",
    "leakage_canary_hits",
}
_SOURCE_FIELDS = {"source_id", "source_class", "complete", "independent_control", "description"}
_EVIDENCE_FIELDS = {"control_id", "source_ids"}


def protocol_payload() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "control_definitions": deepcopy(CONTROLS),
        "outcomes": [
            "integrity_evidenced",
            "integrity_violated",
            "monitor_failed",
            "incomplete_evidence",
        ],
        "per_control_outcomes": [
            "evidenced",
            "violation_observed",
            "monitor_failed",
            "incomplete_evidence",
        ],
        "input": "operator-supplied, content-free structural observations about one evaluation run",
        "automatic_actions": 0,
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def seal_scenario(payload: Mapping[str, Any]) -> dict[str, Any]:
    scenario = _json_clone(payload)
    scenario.pop("scenario_sha256", None)
    scenario["scenario_sha256"] = canonical_sha256(scenario)
    return scenario


def built_in_scenario(profile: str = "integrity-reference") -> dict[str, Any]:
    if profile not in BUILT_IN_PROFILES:
        raise ValueError(f"unknown EvalIntegrityProof profile {profile!r}")
    sources = [
        {
            "source_id": f"{source_class}-source",
            "source_class": source_class,
            "complete": True,
            "independent_control": source_class
            in {"artifact-registry", "evaluator", "network", "identity", "monitor", "time"},
            "description": f"Fictional {source_class} evidence source for the reference lab.",
        }
        for source_class in SOURCE_CLASSES
    ]
    evidence = [
        {
            "control_id": control_id,
            "source_ids": [
                f"{source_class}-source" for source_class in definition["source_classes"]
            ],
        }
        for control_id, definition in CONTROLS.items()
    ]

    def digest(label: str) -> str:
        return canonical_sha256({"fictional_reference_artifact": label})

    scenario = {
        "schema_version": 1,
        "scenario_type": SCENARIO_TYPE,
        "scenario_id": profile,
        "title": f"Fictional {profile.replace('-', ' ')} evaluation record",
        "description": (
            "A content-free reference record containing only identifiers, digests, counts, "
            "timestamps, boundaries, and operator observations; it is not a product result."
        ),
        "execution": {
            "review_mode": "offline-record-review",
            "production_access": False,
            "network_actions_performed": False,
            "credential_values_embedded": False,
            "raw_prompts_embedded": False,
            "raw_outputs_embedded": False,
        },
        "policy": {"max_clock_skew_ms": 1_000},
        "artifacts": {
            "workload_sha256": digest("workload"),
            "evaluator_sha256": digest("evaluator"),
            "environment_sha256": digest("environment"),
            "case_set_commitment_sha256": digest("case-set"),
            "scoring_policy_sha256": digest("scoring-policy"),
        },
        "run": {
            "run_id": "fictional-evaluation-run",
            "holdout_committed_at": "2026-08-30T18:00:00Z",
            "started_at": "2026-08-30T18:05:00Z",
            "result_committed_at": "2026-08-30T18:20:00Z",
            "labels_revealed_at": "2026-08-30T18:21:00Z",
            "case_count_planned": 100,
            "case_count_started": 100,
            "case_count_committed": 98,
            "case_count_safe_stopped": 2,
        },
        "boundaries": {
            "workload_failure_domain_id": "workload-zone",
            "evaluator_failure_domain_id": "evaluator-zone",
            "workload_credential_scope_id": "workload-scope",
            "evaluator_credential_scope_id": "evaluator-scope",
            "evaluator_state_readable_by_workload": False,
            "label_store_readable_before_result_commit": False,
            "network_egress_policy": "denied",
            "unauthorized_egress_observed": False,
            "safe_exit_available": True,
            "unsafe_continuation_count": 0,
        },
        "monitoring": {
            "independent_control": True,
            "complete": True,
            "clock_skew_ms": 50,
            "canary_detector_enabled": True,
            "leakage_canary_hits": 0,
        },
        "sources": sources,
        "control_evidence": evidence,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    if profile == "label-leakage":
        scenario["boundaries"]["label_store_readable_before_result_commit"] = True
        scenario["monitoring"]["leakage_canary_hits"] = 2
    elif profile == "monitor-gap":
        scenario["monitoring"]["complete"] = False
        scenario["monitoring"]["canary_detector_enabled"] = False
    elif profile == "incomplete-record":
        source = next(item for item in sources if item["source_id"] == "artifact-registry-source")
        source["complete"] = False
    return seal_scenario(scenario)


def validate_scenario(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ("scenario must be an object",)
    _exact(payload, _SCENARIO_FIELDS, "scenario", errors)
    if payload.get("schema_version") != 1 or payload.get("scenario_type") != SCENARIO_TYPE:
        errors.append("scenario metadata does not match EvalIntegrityProof v1")
    _identifier(payload.get("scenario_id"), "scenario_id", errors)
    _text(payload.get("title"), "title", 300, errors)
    _text(payload.get("description"), "description", 1_500, errors)

    execution = _mapping(payload.get("execution"), "execution", errors)
    if execution is not None:
        _exact(execution, _EXECUTION_FIELDS, "execution", errors)
        if execution.get("review_mode") != "offline-record-review":
            errors.append("execution.review_mode must be offline-record-review")
        if execution.get("production_access") is not False:
            errors.append("execution.production_access must be false")
        if execution.get("network_actions_performed") is not False:
            errors.append("execution.network_actions_performed must be false")
        for field in ("credential_values_embedded", "raw_prompts_embedded", "raw_outputs_embedded"):
            if not isinstance(execution.get(field), bool):
                errors.append(f"execution.{field} must be boolean")

    policy = _mapping(payload.get("policy"), "policy", errors)
    if policy is not None:
        _exact(policy, _POLICY_FIELDS, "policy", errors)
        _integer(
            policy.get("max_clock_skew_ms"),
            "policy.max_clock_skew_ms",
            0,
            MAX_CLOCK_SKEW_MS,
            errors,
        )

    artifacts = _mapping(payload.get("artifacts"), "artifacts", errors)
    if artifacts is not None:
        _exact(artifacts, _ARTIFACT_FIELDS, "artifacts", errors)
        for field in _ARTIFACT_FIELDS:
            if not isinstance(artifacts.get(field), str):
                errors.append(f"artifacts.{field} must be a string")

    run = _mapping(payload.get("run"), "run", errors)
    if run is not None:
        _exact(run, _RUN_FIELDS, "run", errors)
        _identifier(run.get("run_id"), "run.run_id", errors)
        for field in (
            "holdout_committed_at",
            "started_at",
            "result_committed_at",
            "labels_revealed_at",
        ):
            _timestamp(run.get(field), f"run.{field}", errors)
        for field in (
            "case_count_planned",
            "case_count_started",
            "case_count_committed",
            "case_count_safe_stopped",
        ):
            _integer(run.get(field), f"run.{field}", 0, MAX_CASES, errors)

    boundaries = _mapping(payload.get("boundaries"), "boundaries", errors)
    if boundaries is not None:
        _exact(boundaries, _BOUNDARY_FIELDS, "boundaries", errors)
        for field in (
            "workload_failure_domain_id",
            "evaluator_failure_domain_id",
            "workload_credential_scope_id",
            "evaluator_credential_scope_id",
        ):
            _identifier(boundaries.get(field), f"boundaries.{field}", errors)
        for field in (
            "evaluator_state_readable_by_workload",
            "label_store_readable_before_result_commit",
            "unauthorized_egress_observed",
            "safe_exit_available",
        ):
            if not isinstance(boundaries.get(field), bool):
                errors.append(f"boundaries.{field} must be boolean")
        if boundaries.get("network_egress_policy") not in {"denied", "simulated", "allowed"}:
            errors.append("boundaries.network_egress_policy is unsupported")
        _integer(
            boundaries.get("unsafe_continuation_count"),
            "boundaries.unsafe_continuation_count",
            0,
            MAX_CASES,
            errors,
        )

    monitoring = _mapping(payload.get("monitoring"), "monitoring", errors)
    if monitoring is not None:
        _exact(monitoring, _MONITORING_FIELDS, "monitoring", errors)
        for field in ("independent_control", "complete", "canary_detector_enabled"):
            if not isinstance(monitoring.get(field), bool):
                errors.append(f"monitoring.{field} must be boolean")
        _integer(
            monitoring.get("clock_skew_ms"),
            "monitoring.clock_skew_ms",
            0,
            MAX_CLOCK_SKEW_MS,
            errors,
        )
        _integer(
            monitoring.get("leakage_canary_hits"),
            "monitoring.leakage_canary_hits",
            0,
            MAX_CASES,
            errors,
        )

    source_ids: set[str] = set()
    source_classes: dict[str, str] = {}
    sources = payload.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        errors.append(f"sources must contain 1 to {MAX_SOURCES} objects")
        sources = []
    for index, source in enumerate(sources):
        label = f"sources[{index}]"
        if not isinstance(source, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(source, _SOURCE_FIELDS, label, errors)
        source_id = source.get("source_id")
        _identifier(source_id, f"{label}.source_id", errors)
        if isinstance(source_id, str):
            if source_id in source_ids:
                errors.append(f"duplicate source_id {source_id!r}")
            source_ids.add(source_id)
            if source.get("source_class") in SOURCE_CLASSES:
                source_classes[source_id] = str(source["source_class"])
        if source.get("source_class") not in SOURCE_CLASSES:
            errors.append(f"{label}.source_class is unsupported")
        for field in ("complete", "independent_control"):
            if not isinstance(source.get(field), bool):
                errors.append(f"{label}.{field} must be boolean")
        _text(source.get("description"), f"{label}.description", 500, errors)

    evidence = payload.get("control_evidence")
    if not isinstance(evidence, list) or len(evidence) != len(CONTROLS):
        errors.append(f"control_evidence must contain exactly {len(CONTROLS)} records")
        evidence = []
    seen_controls: set[str] = set()
    for index, item in enumerate(evidence):
        label = f"control_evidence[{index}]"
        if not isinstance(item, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(item, _EVIDENCE_FIELDS, label, errors)
        control_id = item.get("control_id")
        if control_id not in CONTROLS:
            errors.append(f"{label}.control_id is unsupported")
        elif control_id in seen_controls:
            errors.append(f"duplicate control_id {control_id!r}")
        else:
            seen_controls.add(str(control_id))
        refs = item.get("source_ids")
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) for ref in refs):
            errors.append(f"{label}.source_ids must be a non-empty string list")
            continue
        if len(refs) != len(set(refs)):
            errors.append(f"{label}.source_ids must be unique")
        if unknown := sorted(set(refs) - source_ids):
            errors.append(f"{label}.source_ids reference unknown sources: {', '.join(unknown)}")
        if control_id in CONTROLS:
            present = {source_classes.get(ref) for ref in refs}
            required = set(CONTROLS[str(control_id)]["source_classes"])
            if missing := sorted(required - present):
                errors.append(f"{label} lacks required source classes: {', '.join(missing)}")
    if seen_controls != set(CONTROLS):
        errors.append("control_evidence does not cover the frozen EvalIntegrityProof controls")
    if payload.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match EvalIntegrityProof v1")
    claimed = payload.get("scenario_sha256")
    unsigned = dict(payload)
    unsigned.pop("scenario_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("scenario_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("scenario is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def analyze_scenario(payload: Mapping[str, Any]) -> dict[str, Any]:
    errors = validate_scenario(payload)
    if errors:
        raise ValueError("invalid EvalIntegrityProof scenario: " + "; ".join(errors))
    scenario = _json_clone(payload)
    sources = {item["source_id"]: item for item in scenario["sources"]}
    bindings = {item["control_id"]: item["source_ids"] for item in scenario["control_evidence"]}
    evaluations = _evaluate_controls(scenario)
    results = []
    for control_id, definition in CONTROLS.items():
        condition, failure_status, detail = evaluations[control_id]
        source_records = [sources[source_id] for source_id in bindings[control_id]]
        evidence_complete = all(source["complete"] for source in source_records)
        independent_source_present = any(source["independent_control"] for source in source_records)
        if not condition:
            status = failure_status
        elif not evidence_complete or not independent_source_present:
            status = "incomplete_evidence"
        else:
            status = "evidenced"
        results.append(
            {
                "control_id": control_id,
                "title": definition["title"],
                "category": definition["category"],
                "status": status,
                "condition_met": condition,
                "evidence_complete": evidence_complete,
                "independent_source_present": independent_source_present,
                "source_ids": list(bindings[control_id]),
                "evidence_paths": list(definition["evidence_paths"]),
                "finding": detail,
            }
        )
    statuses = ("evidenced", "violation_observed", "monitor_failed", "incomplete_evidence")
    counts = {status: sum(item["status"] == status for item in results) for status in statuses}
    if counts["violation_observed"]:
        overall = "integrity_violated"
    elif counts["monitor_failed"]:
        overall = "monitor_failed"
    elif counts["incomplete_evidence"]:
        overall = "incomplete_evidence"
    else:
        overall = "integrity_evidenced"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "analyzer": ANALYZER,
        "scenario_sha256": scenario["scenario_sha256"],
        "scenario": scenario,
        "summary": {
            "status": overall,
            "control_count": len(results),
            "control_status_counts": counts,
            "holdout_precommitted": evaluations["EI002"][0],
            "result_committed_before_label_reveal": evaluations["EI003"][0],
            "failure_domains_separate": evaluations["EI004"][0],
            "evaluator_data_isolated": evaluations["EI005"][0],
            "credential_scopes_separate": evaluations["EI006"][0],
            "network_boundary_observed": evaluations["EI007"][0],
            "all_cases_accounted_for": evaluations["EI008"][0],
            "leakage_canary_hits": scenario["monitoring"]["leakage_canary_hits"],
            "monitor_independent_and_complete": evaluations["EI010"][0],
            "safe_exit_observed": evaluations["EI011"][0],
            "content_free_record": evaluations["EI012"][0],
            "automatic_actions": 0,
        },
        "control_results": results,
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_report(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ("report must be an object",)
    if payload.get("report_type") != REPORT_TYPE:
        errors.append("unsupported EvalIntegrityProof report type")
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("unsupported EvalIntegrityProof protocol version")
    if payload.get("protocol_sha256") != protocol_sha256():
        errors.append("protocol_sha256 does not match EvalIntegrityProof v1")
    claimed = payload.get("report_sha256")
    unsigned = dict(payload)
    unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    scenario = payload.get("scenario")
    if not isinstance(scenario, Mapping):
        errors.append("report scenario must be an object")
        return tuple(dict.fromkeys(errors))
    try:
        expected = analyze_scenario(scenario)
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if payload != expected:
            errors.append("EvalIntegrityProof report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _evaluate_controls(scenario: Mapping[str, Any]) -> dict[str, tuple[bool, str, str]]:
    artifacts = scenario["artifacts"]
    run = scenario["run"]
    boundaries = scenario["boundaries"]
    monitoring = scenario["monitoring"]
    execution = scenario["execution"]
    policy = scenario["policy"]
    times = {
        field: _parse_timestamp(run[field])
        for field in (
            "holdout_committed_at",
            "started_at",
            "result_committed_at",
            "labels_revealed_at",
        )
    }
    all_digests = all(
        isinstance(value, str) and bool(_SHA256.fullmatch(value)) for value in artifacts.values()
    )
    holdout_first = times["holdout_committed_at"] <= times["started_at"]
    commit_reveal = (
        times["started_at"] <= times["result_committed_at"] < times["labels_revealed_at"]
    )
    failure_domains = (
        boundaries["workload_failure_domain_id"] != boundaries["evaluator_failure_domain_id"]
    )
    evaluator_isolated = (
        not boundaries["evaluator_state_readable_by_workload"]
        and not boundaries["label_store_readable_before_result_commit"]
    )
    credential_scopes = (
        boundaries["workload_credential_scope_id"] != boundaries["evaluator_credential_scope_id"]
    )
    network_boundary = (
        boundaries["network_egress_policy"] in {"denied", "simulated"}
        and not boundaries["unauthorized_egress_observed"]
    )
    accounting = (
        run["case_count_planned"] > 0
        and run["case_count_started"] == run["case_count_planned"]
        and run["case_count_committed"] + run["case_count_safe_stopped"]
        == run["case_count_planned"]
    )
    canary_enabled = monitoring["canary_detector_enabled"]
    canary_clean = monitoring["leakage_canary_hits"] == 0
    monitor_ok = monitoring["independent_control"] and monitoring["complete"]
    safe_exit = boundaries["safe_exit_available"] and boundaries["unsafe_continuation_count"] == 0
    content_free = (
        not execution["credential_values_embedded"]
        and not execution["raw_prompts_embedded"]
        and not execution["raw_outputs_embedded"]
    )
    clock_ok = monitoring["clock_skew_ms"] <= policy["max_clock_skew_ms"]
    return {
        "EI001": (
            all_digests,
            "violation_observed",
            "all five declared artifact identities use SHA-256 digests"
            if all_digests
            else "one or more artifact identities are not pinned with a SHA-256 digest",
        ),
        "EI002": (
            holdout_first,
            "violation_observed",
            "holdout commitment is no later than run start"
            if holdout_first
            else "holdout commitment occurs after run start",
        ),
        "EI003": (
            commit_reveal,
            "violation_observed",
            "result commit precedes label reveal"
            if commit_reveal
            else "commit/reveal timestamps are out of order",
        ),
        "EI004": (
            failure_domains,
            "violation_observed",
            "workload and evaluator failure-domain identifiers differ"
            if failure_domains
            else "workload and evaluator share a failure-domain identifier",
        ),
        "EI005": (
            evaluator_isolated,
            "violation_observed",
            "workload cannot read evaluator state or unrevealed labels"
            if evaluator_isolated
            else "workload-readable evaluator state or unrevealed labels were declared",
        ),
        "EI006": (
            credential_scopes,
            "violation_observed",
            "workload and evaluator credential-scope identifiers differ"
            if credential_scopes
            else "workload and evaluator share a credential-scope identifier",
        ),
        "EI007": (
            network_boundary,
            "violation_observed",
            "egress was denied or simulated and no unauthorized egress was observed"
            if network_boundary
            else "allowed policy or unauthorized egress was declared",
        ),
        "EI008": (
            accounting,
            "violation_observed",
            "every planned case is committed or safely stopped"
            if accounting
            else "case counts do not close over the planned case set",
        ),
        "EI009": (
            canary_enabled and canary_clean,
            "monitor_failed" if not canary_enabled else "violation_observed",
            "active leakage-canary detector reports zero hits"
            if canary_enabled and canary_clean
            else (
                "leakage-canary detector was not enabled"
                if not canary_enabled
                else "one or more leakage-canary hits were observed"
            ),
        ),
        "EI010": (
            monitor_ok,
            "monitor_failed",
            "monitor is declared independent and complete"
            if monitor_ok
            else "monitor is not both independent and complete",
        ),
        "EI011": (
            safe_exit,
            "violation_observed",
            "safe exit is available and no unsafe continuation was recorded"
            if safe_exit
            else "safe exit was unavailable or unsafe continuation was recorded",
        ),
        "EI012": (
            content_free,
            "violation_observed",
            "record declares no embedded prompts, outputs, or credential values"
            if content_free
            else "record declares embedded sensitive evaluation content",
        ),
        "EI013": (
            clock_ok,
            "monitor_failed",
            "clock skew is within policy tolerance"
            if clock_ok
            else "clock skew exceeds policy tolerance",
        ),
    }


def _mapping(value: Any, label: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return None
    return value


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _text(value: Any, label: str, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        errors.append(f"{label} must be a non-empty string of at most {maximum} characters")


def _integer(value: Any, label: str, minimum: int, maximum: int, errors: list[str]) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        errors.append(f"{label} must be between {minimum} and {maximum}")


def _timestamp(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{label} must be an RFC 3339 UTC timestamp")
        return
    try:
        _parse_timestamp(value)
    except ValueError:
        errors.append(f"{label} must be an RFC 3339 UTC timestamp")


def _parse_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z notation")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
