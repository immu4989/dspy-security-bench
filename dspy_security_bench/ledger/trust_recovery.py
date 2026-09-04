"""Content-minimized, non-authorizing trust-root recovery drill evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from dspy_security_bench.ledger.trust_root import evaluate_trust_root
from dspy_security_bench.mission.loader import canonical_sha256

POLICY_TYPE = "dspy-security-bench-assurance-trust-recovery-policy"
DRILL_TYPE = "dspy-security-bench-assurance-trust-recovery-drill"
REPORT_TYPE = "AssuranceLedger TrustRecoveryDrill / Root recovery readiness evidence"
PROTOCOL_VERSION = "assuranceledger-trust-recovery-drill-v1"
ANALYZER = "deterministic-root-recovery-drill-analyzer-v1"
ROLE_NAMES = (
    "auditor",
    "distributor",
    "incident-commander",
    "independent-approver",
    "key-custodian",
)
EVENT_ROLES = {
    "compromise-detected": "incident-commander",
    "incident-declared": "incident-commander",
    "affected-signatures-inventoried": "auditor",
    "damage-assessment-completed": "auditor",
    "replacement-root-prepared": "key-custodian",
    "independent-approval-recorded": "independent-approver",
    "out-of-band-distribution-rehearsed": "distributor",
    "replacement-verification-completed": "auditor",
    "lessons-retained": "incident-commander",
}
EVENT_EVIDENCE_CLASSES = {
    "compromise-detected": "alert-record",
    "incident-declared": "incident-declaration",
    "affected-signatures-inventoried": "signature-inventory",
    "damage-assessment-completed": "damage-assessment",
    "replacement-root-prepared": "replacement-root-manifest",
    "independent-approval-recorded": "approval-record",
    "out-of-band-distribution-rehearsed": "distribution-rehearsal",
    "replacement-verification-completed": "verification-record",
    "lessons-retained": "lessons-record",
}
TIME_LIMIT_NAMES = (
    "declaration_to_replacement_seconds",
    "detection_to_declaration_seconds",
    "distribution_to_verification_seconds",
    "maximum_drill_age_seconds",
    "replacement_to_distribution_seconds",
)
TRUSTED_STATUS = "recovery_readiness_evidenced"
MAX_ACTORS_PER_ROLE = 20
MAX_EVENTS = len(EVENT_ROLES)
MAX_TIME_LIMIT_SECONDS = 31_536_000
CLAIM_BOUNDARY = (
    "TrustRecoveryDrill evaluates a content-minimized tabletop record against an exact "
    "recovery policy authorized by a caller-anchored AssuranceTrustRoot. It checks required "
    "recovery stages, actor/organization assignments, separation of duties, event ordering, "
    "response windows, evidence digests, root binding, policy validity, and drill freshness. "
    "A passing report is readiness evidence for the supplied drill only. It never authorizes, "
    "creates, distributes, installs, revokes, or activates a replacement root."
)
LIMITATIONS = (
    "Drill events and actor/organization labels are owner-supplied assertions; evidence digests prove binding, not the truth or quality of the underlying records.",
    "A tabletop exercise cannot prove that people, communications, HSMs, backups, or distribution channels will remain available during a real compromise.",
    "The protocol does not bypass the normal old/new root thresholds or define an emergency replacement trust mechanism.",
    "Root compromise can invalidate signatures and require out-of-band recovery beyond what an offline analyzer can establish.",
    "The report is not legal identity proof, key-custody assurance, FIPS validation, incident notification, compliance certification, authorization to operate, or risk acceptance.",
    "The analyzer performs no network access, key operation, notification, deployment, revocation, rollback, or automatic remediation.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_FIELDS = {
    "schema_version",
    "policy_type",
    "protocol_version",
    "plan_id",
    "trust_domain",
    "root_version",
    "issued_at",
    "expires_at",
    "role_assignments",
    "separation_constraints",
    "required_event_types",
    "minimum_distinct_organizations",
    "time_limits",
    "policy_sha256",
}
_DRILL_FIELDS = {
    "schema_version",
    "drill_type",
    "protocol_version",
    "plan_id",
    "policy_sha256",
    "trust_domain",
    "root_sha256",
    "root_version",
    "drill_id",
    "simulation_only",
    "events",
    "drill_sha256",
}
_ACTOR_FIELDS = {"actor_id", "organization_id"}
_CONSTRAINT_FIELDS = {"left_role", "right_role"}
_EVENT_FIELDS = {
    "sequence",
    "event_type",
    "occurred_at",
    "actor_id",
    "organization_id",
    "evidence_class",
    "evidence_sha256",
}
_REQUIRED_SEPARATION = frozenset(("independent-approver", "key-custodian"))


def build_recovery_policy(
    *,
    plan_id: str,
    trust_domain: str,
    root_version: int,
    issued_at: int,
    expires_at: int,
    role_assignments: Mapping[str, Sequence[Mapping[str, Any]]],
    separation_constraints: Sequence[Mapping[str, Any]],
    minimum_distinct_organizations: int,
    time_limits: Mapping[str, int],
) -> dict[str, Any]:
    """Build a self-digested recovery policy for authorization by a trust root."""

    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "plan_id": plan_id,
        "trust_domain": trust_domain,
        "root_version": root_version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "role_assignments": {
            role: sorted(
                (deepcopy(dict(actor)) for actor in actors),
                key=lambda item: (item["actor_id"], item["organization_id"]),
            )
            for role, actors in sorted(role_assignments.items())
        },
        "separation_constraints": sorted(
            (deepcopy(dict(item)) for item in separation_constraints),
            key=lambda item: (item["left_role"], item["right_role"]),
        ),
        "required_event_types": sorted(EVENT_ROLES),
        "minimum_distinct_organizations": minimum_distinct_organizations,
        "time_limits": {name: time_limits[name] for name in sorted(time_limits)},
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    if errors := validate_recovery_policy(policy):
        raise ValueError("invalid TrustRecovery policy: " + "; ".join(errors))
    return policy


def recovery_event(
    sequence: int,
    event_type: str,
    occurred_at: int,
    *,
    actor_id: str,
    organization_id: str,
    evidence_sha256: str,
) -> dict[str, Any]:
    """Build one content-minimized recovery-drill event."""

    if event_type not in EVENT_EVIDENCE_CLASSES:
        raise ValueError("unsupported recovery event type")
    return {
        "sequence": sequence,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor_id": actor_id,
        "organization_id": organization_id,
        "evidence_class": EVENT_EVIDENCE_CLASSES[event_type],
        "evidence_sha256": evidence_sha256,
    }


def build_recovery_drill(
    policy: Mapping[str, Any],
    trust_root: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    *,
    drill_id: str,
) -> dict[str, Any]:
    """Build a simulation-only recovery drill bound to an exact root and policy."""

    if errors := validate_recovery_policy(policy):
        raise ValueError("invalid TrustRecovery policy: " + "; ".join(errors))
    drill: dict[str, Any] = {
        "schema_version": 1,
        "drill_type": DRILL_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "plan_id": policy["plan_id"],
        "policy_sha256": policy["policy_sha256"],
        "trust_domain": policy["trust_domain"],
        "root_sha256": trust_root.get("root_sha256"),
        "root_version": trust_root.get("version"),
        "drill_id": drill_id,
        "simulation_only": True,
        "events": sorted(
            (deepcopy(dict(item)) for item in events), key=lambda item: item["sequence"]
        ),
    }
    drill["drill_sha256"] = canonical_sha256(drill)
    if errors := validate_recovery_drill(drill):
        raise ValueError("invalid TrustRecovery drill: " + "; ".join(errors))
    return drill


def validate_recovery_policy(policy: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("recovery policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "recovery policy", errors)
    if (
        policy.get("schema_version") != 1
        or policy.get("policy_type") != POLICY_TYPE
        or policy.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("recovery policy does not match TrustRecoveryDrill v1")
    _identifier(policy.get("plan_id"), "plan_id", errors)
    domain = policy.get("trust_domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 300:
        errors.append("trust_domain must be a non-empty string of at most 300 characters")
    _positive_int(policy.get("root_version"), "root_version", errors)
    issued = _nonnegative_int(policy.get("issued_at"), "issued_at", errors)
    expires = _nonnegative_int(policy.get("expires_at"), "expires_at", errors)
    if issued is not None and expires is not None and issued >= expires:
        errors.append("recovery policy validity window must be non-empty")

    assignments = policy.get("role_assignments")
    if not isinstance(assignments, Mapping) or set(assignments) != set(ROLE_NAMES):
        errors.append("role_assignments must contain the exact recovery role set")
        assignments = {}
    for role in ROLE_NAMES:
        actors = assignments.get(role) if isinstance(assignments, Mapping) else None
        if not isinstance(actors, list) or not 1 <= len(actors) <= MAX_ACTORS_PER_ROLE:
            errors.append(f"role {role} must contain 1 to {MAX_ACTORS_PER_ROLE} actors")
            continue
        expected = sorted(
            actors,
            key=lambda item: (
                item.get("actor_id", "") if isinstance(item, Mapping) else "",
                item.get("organization_id", "") if isinstance(item, Mapping) else "",
            ),
        )
        if actors != expected:
            errors.append(f"role {role} actors must be sorted")
        seen: set[tuple[Any, Any]] = set()
        for index, actor in enumerate(actors):
            if not isinstance(actor, Mapping):
                errors.append(f"role {role} actor {index} must be an object")
                continue
            _exact(actor, _ACTOR_FIELDS, f"role {role} actor {index}", errors)
            _identifier(actor.get("actor_id"), f"role {role} actor_id", errors)
            _identifier(actor.get("organization_id"), f"role {role} organization_id", errors)
            identity = (actor.get("actor_id"), actor.get("organization_id"))
            if identity in seen:
                errors.append(f"role {role} contains a duplicate actor assignment")
            seen.add(identity)

    constraints = policy.get("separation_constraints")
    normalized_constraints: list[tuple[str, str]] = []
    if not isinstance(constraints, list) or not constraints:
        errors.append("separation_constraints must be a non-empty array")
        constraints = []
    for index, constraint in enumerate(constraints):
        if not isinstance(constraint, Mapping):
            errors.append(f"separation constraint {index} must be an object")
            continue
        _exact(constraint, _CONSTRAINT_FIELDS, f"separation constraint {index}", errors)
        left = constraint.get("left_role")
        right = constraint.get("right_role")
        if left not in ROLE_NAMES or right not in ROLE_NAMES or left == right:
            errors.append(f"separation constraint {index} must name two different roles")
            continue
        normalized_constraints.append((str(left), str(right)))
    if constraints != sorted(
        constraints,
        key=lambda item: (
            item.get("left_role", "") if isinstance(item, Mapping) else "",
            item.get("right_role", "") if isinstance(item, Mapping) else "",
        ),
    ):
        errors.append("separation_constraints must be sorted")
    if len(set(normalized_constraints)) != len(normalized_constraints):
        errors.append("separation_constraints must be unique")
    if not any(set(item) == _REQUIRED_SEPARATION for item in normalized_constraints):
        errors.append("key-custodian and independent-approver separation is required")

    if policy.get("required_event_types") != sorted(EVENT_ROLES):
        errors.append("required_event_types must contain the exact recovery event set")
    minimum_orgs = _positive_int(
        policy.get("minimum_distinct_organizations"),
        "minimum_distinct_organizations",
        errors,
    )
    declared_orgs = {
        actor.get("organization_id")
        for actors in assignments.values()
        if isinstance(actors, list)
        for actor in actors
        if isinstance(actor, Mapping)
    }
    if minimum_orgs is not None and minimum_orgs > len(declared_orgs):
        errors.append("minimum_distinct_organizations cannot be met")
    limits = policy.get("time_limits")
    if not isinstance(limits, Mapping) or set(limits) != set(TIME_LIMIT_NAMES):
        errors.append("time_limits must contain the exact recovery timing set")
    else:
        for name in TIME_LIMIT_NAMES:
            value = _positive_int(limits.get(name), f"time_limits.{name}", errors)
            if value is not None and value > MAX_TIME_LIMIT_SECONDS:
                errors.append(f"time_limits.{name} exceeds one year")
    if not _is_digest(policy.get("policy_sha256")):
        errors.append("policy_sha256 must be a lowercase SHA-256 digest")
    elif policy.get("policy_sha256") != _self_digest(policy, "policy_sha256"):
        errors.append("policy_sha256 does not recompute")
    return tuple(dict.fromkeys(errors))


def validate_recovery_drill(drill: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(drill, Mapping):
        return ("recovery drill must be an object",)
    _exact(drill, _DRILL_FIELDS, "recovery drill", errors)
    if (
        drill.get("schema_version") != 1
        or drill.get("drill_type") != DRILL_TYPE
        or drill.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("recovery drill does not match TrustRecoveryDrill v1")
    _identifier(drill.get("plan_id"), "plan_id", errors)
    _identifier(drill.get("drill_id"), "drill_id", errors)
    domain = drill.get("trust_domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 300:
        errors.append("trust_domain must be a non-empty string of at most 300 characters")
    for name in ("policy_sha256", "root_sha256"):
        if not _is_digest(drill.get(name)):
            errors.append(f"{name} must be a lowercase SHA-256 digest")
    _positive_int(drill.get("root_version"), "root_version", errors)
    if drill.get("simulation_only") is not True:
        errors.append("TrustRecoveryDrill v1 accepts simulation_only=true")
    events = drill.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        errors.append(f"events must contain 1 to {MAX_EVENTS} records")
        events = []
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            errors.append(f"events[{index}] must be an object")
            continue
        _exact(event, _EVENT_FIELDS, f"events[{index}]", errors)
        _nonnegative_int(event.get("sequence"), f"events[{index}].sequence", errors)
        _nonnegative_int(event.get("occurred_at"), f"events[{index}].occurred_at", errors)
        if event.get("event_type") not in EVENT_ROLES:
            errors.append(f"events[{index}].event_type is unsupported")
        if event.get("evidence_class") not in set(EVENT_EVIDENCE_CLASSES.values()):
            errors.append(f"events[{index}].evidence_class is unsupported")
        _identifier(event.get("actor_id"), f"events[{index}].actor_id", errors)
        _identifier(event.get("organization_id"), f"events[{index}].organization_id", errors)
        if not _is_digest(event.get("evidence_sha256")):
            errors.append(f"events[{index}].evidence_sha256 is invalid")
    if not _is_digest(drill.get("drill_sha256")):
        errors.append("drill_sha256 must be a lowercase SHA-256 digest")
    elif drill.get("drill_sha256") != _self_digest(drill, "drill_sha256"):
        errors.append("drill_sha256 does not recompute")
    return tuple(dict.fromkeys(errors))


def evaluate_recovery_drill(
    policy: Mapping[str, Any],
    drill: Mapping[str, Any],
    trust_root: Mapping[str, Any],
    *,
    evaluation_time: int,
    expected_root_sha256: str | None = None,
) -> dict[str, Any]:
    """Evaluate recovery readiness without authorizing or taking recovery action."""

    if isinstance(evaluation_time, bool) or not isinstance(evaluation_time, int):
        raise ValueError("evaluation_time must be an integer Unix timestamp")
    policy_input = deepcopy(dict(policy))
    drill_input = deepcopy(dict(drill))
    root_input = deepcopy(dict(trust_root))
    policy_errors = list(validate_recovery_policy(policy_input))
    drill_errors = list(validate_recovery_drill(drill_input))
    root_report = evaluate_trust_root(
        root_input,
        evaluation_time=evaluation_time,
        expected_root_sha256=expected_root_sha256,
        expected_trust_domain=policy_input.get("trust_domain"),
        minimum_version=_plain_int(policy_input.get("root_version")),
        policies=[policy_input],
    )
    events = drill_input.get("events", [])
    if not isinstance(events, list):
        events = []
    event_map: dict[str, Mapping[str, Any]] = {}
    duplicate_types: set[str] = set()
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event_type = event.get("event_type")
        if not isinstance(event_type, str):
            continue
        if event_type in event_map:
            duplicate_types.add(event_type)
        else:
            event_map[event_type] = event

    required = set(EVENT_ROLES)
    observed = set(event_map)
    missing = sorted(required - observed)
    unexpected = sorted(observed - required)
    findings = [
        _finding(
            "TRD001",
            "Required recovery stages are present exactly once",
            not missing and not unexpected and not duplicate_types,
            (
                "all required recovery stages are present exactly once"
                if not missing and not unexpected and not duplicate_types
                else f"missing={missing}, unexpected={unexpected}, duplicates={sorted(duplicate_types)}"
            ),
            sorted(required),
        )
    ]

    sequences = [event.get("sequence") for event in events if isinstance(event, Mapping)]
    times = [event.get("occurred_at") for event in events if isinstance(event, Mapping)]
    ordering_ok = sequences == list(range(len(events))) and all(
        isinstance(value, int) and not isinstance(value, bool) for value in times
    )
    if ordering_ok:
        ordering_ok = all(left <= right for left, right in zip(times, times[1:], strict=False))
    findings.append(
        _finding(
            "TRD002",
            "Event sequence and timestamps are monotonic",
            ordering_ok,
            "sequences are contiguous and timestamps monotonic"
            if ordering_ok
            else "event order is not contiguous and monotonic",
            sorted(observed),
        )
    )

    assignments = policy_input.get("role_assignments", {})
    role_authorization_errors: list[str] = []
    observed_role_actors: dict[str, set[str]] = {role: set() for role in ROLE_NAMES}
    for event_type, event in event_map.items():
        role = EVENT_ROLES.get(event_type)
        if role is None:
            continue
        observed_role_actors[role].add(str(event.get("actor_id")))
        allowed = {
            (item.get("actor_id"), item.get("organization_id"))
            for item in assignments.get(role, [])
            if isinstance(item, Mapping)
        }
        identity = (event.get("actor_id"), event.get("organization_id"))
        if identity not in allowed:
            role_authorization_errors.append(f"{event_type} actor is not assigned to {role}")
    findings.append(
        _finding(
            "TRD003",
            "Every recovery stage uses an assigned role actor",
            not role_authorization_errors,
            "; ".join(role_authorization_errors) or "all observed actors match policy assignments",
            sorted(observed),
        )
    )

    separation_errors: list[str] = []
    constraints = policy_input.get("separation_constraints", [])
    if isinstance(constraints, list):
        for constraint in constraints:
            if not isinstance(constraint, Mapping):
                continue
            left = str(constraint.get("left_role"))
            right = str(constraint.get("right_role"))
            shared = sorted(
                observed_role_actors.get(left, set()) & observed_role_actors.get(right, set())
            )
            if shared:
                separation_errors.append(f"{left}/{right} share actors {shared}")
    findings.append(
        _finding(
            "TRD004",
            "Observed actors satisfy separation-of-duty constraints",
            not separation_errors,
            "; ".join(separation_errors) or "all configured role pairs are actor-disjoint",
            sorted(observed),
        )
    )

    organizations = {
        str(event.get("organization_id"))
        for event in event_map.values()
        if isinstance(event.get("organization_id"), str)
    }
    minimum_orgs = _plain_int(policy_input.get("minimum_distinct_organizations"))
    diversity_ok = minimum_orgs is not None and len(organizations) >= minimum_orgs
    findings.append(
        _finding(
            "TRD005",
            "Recovery drill meets the organization-diversity floor",
            diversity_ok,
            f"observed {len(organizations)} organizations; required {minimum_orgs}",
            sorted(observed),
        )
    )

    evidence_errors = [
        event_type
        for event_type, event in event_map.items()
        if event.get("evidence_class") != EVENT_EVIDENCE_CLASSES.get(event_type)
    ]
    findings.append(
        _finding(
            "TRD006",
            "Every stage binds the expected evidence class",
            not evidence_errors,
            (
                "all recovery stages bind the expected content-free evidence class"
                if not evidence_errors
                else f"evidence-class mismatch for {sorted(evidence_errors)}"
            ),
            sorted(observed),
        )
    )

    root_binding_ok = (
        drill_input.get("root_sha256") == root_input.get("root_sha256")
        and drill_input.get("root_version") == root_input.get("version")
        and drill_input.get("policy_sha256") == policy_input.get("policy_sha256")
        and drill_input.get("plan_id") == policy_input.get("plan_id")
        and drill_input.get("trust_domain") == policy_input.get("trust_domain")
    )
    findings.append(
        _finding(
            "TRD007",
            "Drill binds the exact root and recovery policy",
            root_binding_ok,
            "drill root/policy bindings match"
            if root_binding_ok
            else "drill root or policy binding differs",
            [],
        )
    )

    future_events = sorted(
        event_type
        for event_type, event in event_map.items()
        if isinstance(event.get("occurred_at"), int)
        and not isinstance(event.get("occurred_at"), bool)
        and event["occurred_at"] > evaluation_time
    )
    findings.append(
        _finding(
            "TRD008",
            "No recovery event is future-dated",
            not future_events,
            "all events occurred by evaluation time"
            if not future_events
            else f"future events={future_events}",
            future_events,
        )
    )

    limits = policy_input.get("time_limits", {})
    timing_specs = (
        (
            "TRD009",
            "Detection-to-declaration window",
            "compromise-detected",
            "incident-declared",
            "detection_to_declaration_seconds",
        ),
        (
            "TRD010",
            "Declaration-to-replacement window",
            "incident-declared",
            "replacement-root-prepared",
            "declaration_to_replacement_seconds",
        ),
        (
            "TRD011",
            "Replacement-to-distribution window",
            "replacement-root-prepared",
            "out-of-band-distribution-rehearsed",
            "replacement_to_distribution_seconds",
        ),
        (
            "TRD012",
            "Distribution-to-verification window",
            "out-of-band-distribution-rehearsed",
            "replacement-verification-completed",
            "distribution_to_verification_seconds",
        ),
    )
    for rule_id, title, start, end, limit_name in timing_specs:
        elapsed = _elapsed(event_map.get(start), event_map.get(end))
        limit = limits.get(limit_name) if isinstance(limits, Mapping) else None
        passed = (
            elapsed is not None
            and isinstance(limit, int)
            and not isinstance(limit, bool)
            and 0 <= elapsed <= limit
        )
        findings.append(
            _finding(
                rule_id,
                title,
                passed,
                f"observed {elapsed} seconds; limit {limit}",
                [start, end],
            )
        )

    latest_time = max(
        (
            int(event["occurred_at"])
            for event in event_map.values()
            if isinstance(event.get("occurred_at"), int)
            and not isinstance(event.get("occurred_at"), bool)
        ),
        default=None,
    )
    maximum_age = limits.get("maximum_drill_age_seconds") if isinstance(limits, Mapping) else None
    drill_age = evaluation_time - latest_time if latest_time is not None else None
    stale = not (
        drill_age is not None
        and isinstance(maximum_age, int)
        and not isinstance(maximum_age, bool)
        and 0 <= drill_age <= maximum_age
    )
    findings.append(
        _finding(
            "TRD013",
            "Recovery drill remains within the policy freshness window",
            not stale,
            f"observed age {drill_age} seconds; maximum {maximum_age}",
            ["lessons-retained"],
        )
    )

    failed = sum(item["status"] == "failed" for item in findings)
    policy_issued = _plain_int(policy_input.get("issued_at"))
    policy_expires = _plain_int(policy_input.get("expires_at"))
    root_status = root_report["summary"]["status"]
    if policy_errors or drill_errors:
        status = "invalid_recovery_evidence"
    elif root_status == "policy_not_authorized":
        status = "recovery_policy_not_authorized"
    elif root_status != "trusted_bootstrap":
        status = "untrusted_root"
    elif (
        policy_issued is None
        or policy_expires is None
        or not (policy_issued <= evaluation_time < policy_expires)
    ):
        status = "inactive_recovery_policy"
    elif stale:
        status = "stale_recovery_drill"
    elif failed:
        status = "recovery_readiness_not_evidenced"
    else:
        status = TRUSTED_STATUS

    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "evaluation_time": evaluation_time,
        "anchor": {"expected_root_sha256": expected_root_sha256},
        "policy_input": policy_input,
        "drill_input": drill_input,
        "trust_root_input": root_input,
        "root_trust_report": root_report,
        "source_errors": {
            "policy": policy_errors,
            "drill": drill_errors,
        },
        "findings": findings,
        "summary": {
            "status": status,
            "checks_total": len(findings),
            "checks_passed": len(findings) - failed,
            "checks_failed": failed,
            "events_observed": len(events),
            "required_events": len(EVENT_ROLES),
            "distinct_organizations_observed": len(organizations),
            "drill_age_seconds": drill_age,
            "content_fields_processed": 0,
            "replacement_roots_activated": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_recovery_drill_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Recompute a saved recovery-drill report from embedded inputs."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported TrustRecoveryDrill report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    anchor = report.get("anchor")
    if not isinstance(anchor, Mapping):
        errors.append("report anchor must be an object")
        return tuple(dict.fromkeys(errors))
    try:
        expected = evaluate_recovery_drill(
            report.get("policy_input", {}),
            report.get("drill_input", {}),
            report.get("trust_root_input", {}),
            evaluation_time=report.get("evaluation_time"),
            expected_root_sha256=anchor.get("expected_root_sha256"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"TrustRecoveryDrill report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("TrustRecoveryDrill report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _finding(
    rule_id: str,
    title: str,
    passed: bool,
    detail: str,
    event_types: Sequence[str],
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "status": "passed" if passed else "failed",
        "detail": detail,
        "event_types": list(event_types),
    }


def _elapsed(start: Mapping[str, Any] | None, end: Mapping[str, Any] | None) -> int | None:
    if start is None or end is None:
        return None
    left = start.get("occurred_at")
    right = end.get("occurred_at")
    if (
        isinstance(left, bool)
        or not isinstance(left, int)
        or isinstance(right, bool)
        or not isinstance(right, int)
    ):
        return None
    return right - left


def _self_digest(payload: Mapping[str, Any], field: str) -> str:
    value = dict(payload)
    value.pop(field, None)
    try:
        return canonical_sha256(value)
    except (TypeError, ValueError):
        return "unavailable"


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _positive_int(value: Any, label: str, errors: list[str]) -> int | None:
    result = _nonnegative_int(value, label, errors)
    if result is not None and result < 1:
        errors.append(f"{label} must be positive")
        return None
    return result


def _nonnegative_int(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{label} must be a non-negative integer")
        return None
    return value


def _plain_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


__all__ = [
    "DRILL_TYPE",
    "EVENT_EVIDENCE_CLASSES",
    "EVENT_ROLES",
    "POLICY_TYPE",
    "PROTOCOL_VERSION",
    "REPORT_TYPE",
    "ROLE_NAMES",
    "TRUSTED_STATUS",
    "build_recovery_drill",
    "build_recovery_policy",
    "evaluate_recovery_drill",
    "recovery_event",
    "validate_recovery_drill",
    "validate_recovery_policy",
    "verify_recovery_drill_report",
]
