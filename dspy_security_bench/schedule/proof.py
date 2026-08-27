"""Bounded, deterministic exploration of agent-authorization event schedules.

ScheduleProof deliberately models only an operator-declared partial order.  It
does not execute tools, infer a production topology, or turn a bounded result
into a safety or compliance claim.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from copy import deepcopy
from functools import cache
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

SCENARIO_TYPE = "dspy-security-bench-scheduleproof-scenario"
REPORT_TYPE = "ScheduleProof / Bounded agent authorization interleaving assurance"
PROTOCOL_VERSION = "scheduleproof-v1"
ANALYZER = "reference-exhaustive-topological-explorer"
MAX_EVENTS = 12
MAX_SCHEDULES = 100_000
MAX_HAPPENS_BEFORE_EDGES = 66
MAX_SCENARIO_BYTES = 1_048_576
DISCLAIMER = (
    "ScheduleProof exhaustively checks only the declared bounded event graph when exploration "
    "is complete. An unsafe-schedule fraction is not a runtime probability. Results do not "
    "prove trace completeness, production safety, distributed-system correctness, compliance, "
    "risk acceptance, certification, or authorization to operate."
)

INVARIANTS: dict[str, str] = {
    "active_authority_at_use": "Token exchange and effects require an active declared authority.",
    "approval_before_effect": "Every effect must consume a matching prior approval.",
    "single_use_approval": "Approval use cannot exceed its declared maximum.",
    "token_before_effect": "Every effect must use a previously exchanged token.",
    "scope_attenuation": "Token and effect scopes cannot exceed their authority or approval.",
    "audience_binding": "Authority, approval, token, and effect audiences must match.",
    "identity_binding": "Subject and resource bindings must survive every transition.",
    "unique_effect_and_receipt": "Effect and receipt identifiers cannot be replayed.",
}
DEFAULT_INVARIANTS = tuple(INVARIANTS)
EVENT_KINDS = ("grant", "revoke", "approval", "token_exchange", "effect")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,79}$")
_COMMON_EVENT_FIELDS = {"id", "kind", "actor"}
_EVENT_FIELDS = {
    "grant": _COMMON_EVENT_FIELDS | {"authority_id", "subject", "resource", "scopes", "audience"},
    "revoke": _COMMON_EVENT_FIELDS | {"authority_id"},
    "approval": _COMMON_EVENT_FIELDS
    | {"decision_id", "subject", "resource", "scopes", "audience", "max_uses"},
    "token_exchange": _COMMON_EVENT_FIELDS
    | {"token_id", "authority_id", "subject", "resource", "scopes", "audience"},
    "effect": _COMMON_EVENT_FIELDS
    | {
        "effect_id",
        "subject",
        "resource",
        "scope",
        "audience",
        "authority_id",
        "decision_id",
        "token_id",
        "receipt_id",
    },
}
_VIOLATIONS = {
    "SP001": (
        "Authority not active at use",
        "Revalidate the named authority atomically at token exchange and effect commit.",
    ),
    "SP002": (
        "Approval unavailable before effect",
        "Make approval issuance happen-before effect commit and bind both to one decision ID.",
    ),
    "SP003": (
        "Approval replayed",
        "Consume the approval with an atomic compare-and-set at the effect boundary.",
    ),
    "SP004": (
        "Token unavailable before effect",
        "Make resource-bound token exchange happen-before effect commit.",
    ),
    "SP005": (
        "Scope amplification",
        "Attenuate scope at every hop and reject excess scope at the effect boundary.",
    ),
    "SP006": (
        "Audience mismatch",
        "Bind and validate the canonical target audience at exchange and effect commit.",
    ),
    "SP007": (
        "Subject or resource binding changed",
        "Carry verified subject and resource bindings through every delegated transition.",
    ),
    "SP008": (
        "Effect identifier replayed",
        "Enforce atomic idempotency for effect identifiers at the system of record.",
    ),
    "SP009": (
        "Receipt identifier replayed",
        "Issue a unique, request-bound receipt only after one committed effect.",
    ),
}


def protocol_payload() -> dict[str, Any]:
    """Return the frozen ScheduleProof v1 measurement contract."""

    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "algorithm": "lexicographic exhaustive topological-order exploration",
        "event_kinds": list(EVENT_KINDS),
        "invariants": dict(INVARIANTS),
        "bounds": {
            "max_events": MAX_EVENTS,
            "max_happens_before_edges": MAX_HAPPENS_BEFORE_EDGES,
            "max_schedules": MAX_SCHEDULES,
            "max_scenario_bytes": MAX_SCENARIO_BYTES,
        },
        "outcomes": ["bounded_safe", "unsafe", "incomplete_review"],
        "claim_boundary": DISCLAIMER,
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def validate_scenario(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the strict, data-only ScheduleProof scenario contract."""

    errors: list[str] = []
    fields = {
        "schema_version",
        "scenario_type",
        "scenario_id",
        "title",
        "description",
        "events",
        "happens_before",
        "invariants",
        "exploration",
    }
    if set(payload) != fields:
        errors.append("scenario fields are incomplete or unsupported")
    if payload.get("schema_version") != 1 or payload.get("scenario_type") != SCENARIO_TYPE:
        errors.append("scenario metadata does not match ScheduleProof v1")
    for field, limit in (("scenario_id", 80), ("title", 160), ("description", 1000)):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            errors.append(f"{field} must be a non-empty string of at most {limit} characters")
    if isinstance(payload.get("scenario_id"), str) and not _SAFE_ID.fullmatch(
        payload["scenario_id"]
    ):
        errors.append("scenario_id must use lowercase safe identifier characters")

    events = payload.get("events")
    event_ids: list[str] = []
    if not isinstance(events, list) or not 2 <= len(events) <= MAX_EVENTS:
        errors.append(f"events must contain between 2 and {MAX_EVENTS} objects")
    else:
        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                errors.append(f"event {index} must be an object")
                continue
            kind = event.get("kind")
            if kind not in _EVENT_FIELDS:
                errors.append(f"event {index} has unsupported kind")
                continue
            if set(event) != _EVENT_FIELDS[kind]:
                errors.append(f"event {index} fields do not match {kind}")
            event_id = event.get("id")
            if not isinstance(event_id, str) or not _SAFE_ID.fullmatch(event_id):
                errors.append(f"event {index} id must use safe identifier characters")
            else:
                event_ids.append(event_id)
            _validate_event(event, index, errors)
        if len(event_ids) != len(set(event_ids)):
            errors.append("event ids must be unique")

    invariants = payload.get("invariants")
    if (
        not isinstance(invariants, list)
        or not invariants
        or not all(isinstance(item, str) and item in INVARIANTS for item in invariants)
    ):
        errors.append("invariants must be a non-empty list of supported invariant ids")
    elif len(invariants) != len(set(invariants)):
        errors.append("invariants must not contain duplicates")

    exploration = payload.get("exploration")
    if not isinstance(exploration, Mapping) or set(exploration) != {"max_schedules"}:
        errors.append("exploration must contain only max_schedules")
    else:
        limit = exploration.get("max_schedules")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SCHEDULES:
            errors.append(f"max_schedules must be an integer from 1 through {MAX_SCHEDULES}")

    edges = payload.get("happens_before")
    normalized_edges: list[tuple[str, str]] = []
    if not isinstance(edges, list):
        errors.append("happens_before must be a list")
    else:
        if len(edges) > MAX_HAPPENS_BEFORE_EDGES:
            errors.append(
                f"happens_before cannot contain more than {MAX_HAPPENS_BEFORE_EDGES} edges"
            )
        known = set(event_ids)
        for index, edge in enumerate(edges):
            if (
                not isinstance(edge, list)
                or len(edge) != 2
                or not all(isinstance(item, str) for item in edge)
            ):
                errors.append(f"happens_before edge {index} must contain two event ids")
                continue
            before, after = edge
            normalized_edges.append((before, after))
            if before not in known or after not in known:
                errors.append(f"happens_before edge {index} references an unknown event")
            if before == after:
                errors.append(f"happens_before edge {index} cannot be a self edge")
        if len(normalized_edges) != len(set(normalized_edges)):
            errors.append("happens_before edges must be unique")
        if event_ids and not _acyclic(event_ids, normalized_edges):
            errors.append("happens_before must be acyclic")
    try:
        canonical_sha256(payload)
    except (TypeError, ValueError):
        errors.append("scenario must contain canonical JSON data")
    return tuple(dict.fromkeys(errors))


def analyze_scenario(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Explore valid schedules and return content-addressed, recomputable evidence."""

    errors = validate_scenario(payload)
    if errors:
        raise ValueError("invalid ScheduleProof scenario: " + "; ".join(errors))
    scenario = deepcopy(dict(payload))
    events = sorted(scenario["events"], key=lambda event: event["id"])
    ids = [event["id"] for event in events]
    prereqs = _prerequisite_masks(ids, scenario["happens_before"])
    total = _count_schedules(prereqs)
    cap = scenario["exploration"]["max_schedules"]
    explored = safe = unsafe = 0
    examples: dict[str, dict[str, Any]] = {}
    minimal: dict[str, Any] | None = None
    event_by_id = {event["id"]: event for event in events}
    ancestors = _ancestor_map(ids, scenario["happens_before"])
    for order in _topological_orders(prereqs, cap):
        explored += 1
        violation = _evaluate_order(order, events, set(scenario["invariants"]))
        if violation is None:
            safe += 1
            continue
        unsafe += 1
        counterexample = _counterexample(
            violation, event_by_id, ancestors, scenario["happens_before"]
        )
        code = counterexample["violation_id"]
        incumbent = examples.get(code)
        if incumbent is None or _counterexample_key(counterexample) < _counterexample_key(
            incumbent
        ):
            examples[code] = counterexample
        if minimal is None or _counterexample_key(counterexample) < _counterexample_key(minimal):
            minimal = counterexample
    complete = explored == total
    status = "unsafe" if unsafe else ("bounded_safe" if complete else "incomplete_review")
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "analyzer": ANALYZER,
        "scenario_sha256": canonical_sha256(scenario),
        "scenario": scenario,
        "summary": {
            "status": status,
            "event_count": len(events),
            "dependency_count": len(scenario["happens_before"]),
            "invariant_count": len(scenario["invariants"]),
            "reachable_schedule_count": total,
            "schedules_explored": explored,
            "complete_exploration": complete,
            "safe_schedules": safe,
            "unsafe_schedules": unsafe,
            "unsafe_schedule_fraction": unsafe / explored,
            "unsafe_schedule_fraction_is_probability": False,
            "counterexample_class_count": len(examples),
        },
        "minimal_counterexample": minimal,
        "counterexamples": [examples[key] for key in sorted(examples)],
        "disclaimer": DISCLAIMER,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_schedule_report(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Recompute every derived ScheduleProof field without network access."""

    errors: list[str] = []
    fields = {
        "schema_version",
        "report_type",
        "protocol_version",
        "protocol_sha256",
        "analyzer",
        "scenario_sha256",
        "scenario",
        "summary",
        "minimal_counterexample",
        "counterexamples",
        "disclaimer",
        "report_sha256",
    }
    if set(payload) != fields:
        errors.append("ScheduleProof report fields are incomplete or unsupported")
    metadata = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "analyzer": ANALYZER,
        "disclaimer": DISCLAIMER,
    }
    for field, expected in metadata.items():
        if payload.get(field) != expected:
            errors.append(f"{field} does not match ScheduleProof v1")
    claimed = payload.get("report_sha256")
    unsigned = dict(payload)
    unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not match canonical report content")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    scenario = payload.get("scenario")
    if not isinstance(scenario, Mapping):
        errors.append("scenario must be an object")
        return tuple(dict.fromkeys(errors))
    scenario_errors = validate_scenario(scenario)
    errors.extend(f"scenario: {item}" for item in scenario_errors)
    if scenario_errors:
        return tuple(dict.fromkeys(errors))
    try:
        expected = analyze_scenario(scenario)
    except ValueError as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        for field in sorted(fields - {"report_sha256"}):
            if payload.get(field) != expected.get(field):
                errors.append(f"{field} does not recompute")
    return tuple(dict.fromkeys(errors))


def built_in_scenario(profile: str) -> dict[str, Any]:
    """Return a copy of a public, synthetic ScheduleProof starter scenario."""

    if profile not in BUILT_IN_PROFILES:
        raise ValueError(f"unknown ScheduleProof profile {profile!r}")
    return deepcopy(BUILT_IN_PROFILES[profile])


def _scenario(
    scenario_id: str,
    title: str,
    description: str,
    events: list[dict[str, Any]],
    edges: list[list[str]],
    *,
    max_schedules: int = 10_000,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "scenario_type": SCENARIO_TYPE,
        "scenario_id": scenario_id,
        "title": title,
        "description": description,
        "events": events,
        "happens_before": edges,
        "invariants": list(DEFAULT_INVARIANTS),
        "exploration": {"max_schedules": max_schedules},
    }


def _payment_events(*, two_effects: bool = False) -> list[dict[str, Any]]:
    events = [
        {
            "id": "grant",
            "kind": "grant",
            "actor": "identity-service",
            "authority_id": "authority-1",
            "subject": "procurement-agent",
            "resource": "invoice-1042",
            "scopes": ["payments:create"],
            "audience": "payments-mcp",
        },
        {
            "id": "approve",
            "kind": "approval",
            "actor": "approver",
            "decision_id": "decision-1",
            "subject": "procurement-agent",
            "resource": "invoice-1042",
            "scopes": ["payments:create"],
            "audience": "payments-mcp",
            "max_uses": 1,
        },
        {
            "id": "exchange",
            "kind": "token_exchange",
            "actor": "token-service",
            "token_id": "token-1",
            "authority_id": "authority-1",
            "subject": "procurement-agent",
            "resource": "invoice-1042",
            "scopes": ["payments:create"],
            "audience": "payments-mcp",
        },
        {
            "id": "commit-a",
            "kind": "effect",
            "actor": "payments-mcp",
            "effect_id": "payment-1042",
            "subject": "procurement-agent",
            "resource": "invoice-1042",
            "scope": "payments:create",
            "audience": "payments-mcp",
            "authority_id": "authority-1",
            "decision_id": "decision-1",
            "token_id": "token-1",
            "receipt_id": "receipt-1042-a",
        },
    ]
    if two_effects:
        replay = deepcopy(events[-1])
        replay.update(
            {"id": "commit-b", "effect_id": "payment-1042-replay", "receipt_id": "receipt-1042-b"}
        )
        events.append(replay)
    events.append(
        {
            "id": "revoke",
            "kind": "revoke",
            "actor": "identity-service",
            "authority_id": "authority-1",
        }
    )
    return events


BUILT_IN_PROFILES: dict[str, dict[str, Any]] = {
    "hardened-payment": _scenario(
        "hardened-payment",
        "Commit-time authorized payment",
        "A synthetic payment effect with resource-bound token exchange, one-use approval, and revocation ordered after commit.",
        _payment_events(),
        [
            ["grant", "exchange"],
            ["approve", "commit-a"],
            ["exchange", "commit-a"],
            ["commit-a", "revoke"],
        ],
    ),
    "revocation-race": _scenario(
        "revocation-race",
        "Revocation versus effect commit",
        "Grant revocation and effect commit are unordered, exposing stale-authority schedules.",
        _payment_events(),
        [
            ["grant", "exchange"],
            ["exchange", "revoke"],
            ["approve", "commit-a"],
            ["exchange", "commit-a"],
        ],
    ),
    "token-race": _scenario(
        "token-race",
        "Token exchange versus effect commit",
        "The effect is not ordered after token exchange, exposing token-use-before-issuance schedules.",
        _payment_events(),
        [
            ["grant", "exchange"],
            ["grant", "commit-a"],
            ["approve", "commit-a"],
            ["commit-a", "revoke"],
        ],
    ),
    "approval-replay": _scenario(
        "approval-replay",
        "Single-use approval across parallel effects",
        "Two parallel effects consume a decision whose declared maximum is one use.",
        _payment_events(two_effects=True),
        [
            ["grant", "exchange"],
            ["approve", "commit-a"],
            ["approve", "commit-b"],
            ["exchange", "commit-a"],
            ["exchange", "commit-b"],
            ["commit-a", "revoke"],
            ["commit-b", "revoke"],
        ],
    ),
}


def _validate_event(event: Mapping[str, Any], index: int, errors: list[str]) -> None:
    for field in _EVENT_FIELDS.get(str(event.get("kind")), set()) - {"max_uses", "scopes"}:
        value = event.get(field)
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            errors.append(f"event {index} {field} must use safe identifier characters")
    if "scopes" in event:
        scopes = event.get("scopes")
        if (
            not isinstance(scopes, list)
            or not scopes
            or len(scopes) > 16
            or not all(isinstance(item, str) and _SAFE_ID.fullmatch(item) for item in scopes)
            or len(scopes) != len(set(scopes))
        ):
            errors.append(f"event {index} scopes must contain unique safe identifiers")
    if event.get("kind") == "approval":
        uses = event.get("max_uses")
        if isinstance(uses, bool) or not isinstance(uses, int) or not 1 <= uses <= 16:
            errors.append(f"event {index} max_uses must be an integer from 1 through 16")


def _acyclic(ids: Sequence[str], edges: Sequence[tuple[str, str]]) -> bool:
    incoming = {item: 0 for item in ids}
    outgoing = {item: [] for item in ids}
    for before, after in edges:
        if before in outgoing and after in incoming and before != after:
            outgoing[before].append(after)
            incoming[after] += 1
    queue = sorted(item for item, count in incoming.items() if count == 0)
    visited = 0
    while queue:
        current = queue.pop(0)
        visited += 1
        for target in outgoing[current]:
            incoming[target] -= 1
            if incoming[target] == 0:
                queue.append(target)
                queue.sort()
    return visited == len(ids)


def _prerequisite_masks(ids: Sequence[str], edges: Sequence[Sequence[str]]) -> tuple[int, ...]:
    position = {event_id: index for index, event_id in enumerate(ids)}
    masks = [0] * len(ids)
    for before, after in edges:
        masks[position[after]] |= 1 << position[before]
    return tuple(masks)


def _count_schedules(prereqs: tuple[int, ...]) -> int:
    full = (1 << len(prereqs)) - 1

    @cache
    def visit(mask: int) -> int:
        if mask == full:
            return 1
        return sum(
            visit(mask | (1 << index))
            for index, required in enumerate(prereqs)
            if not mask & (1 << index) and required & ~mask == 0
        )

    return visit(0)


def _topological_orders(prereqs: tuple[int, ...], limit: int) -> Iterator[tuple[int, ...]]:
    full = (1 << len(prereqs)) - 1
    yielded = 0

    def visit(mask: int, order: tuple[int, ...]) -> Iterator[tuple[int, ...]]:
        nonlocal yielded
        if yielded >= limit:
            return
        if mask == full:
            yielded += 1
            yield order
            return
        for index, required in enumerate(prereqs):
            if yielded >= limit:
                return
            if not mask & (1 << index) and required & ~mask == 0:
                yield from visit(mask | (1 << index), (*order, index))

    yield from visit(0, ())


def _evaluate_order(
    order: Sequence[int], events: Sequence[Mapping[str, Any]], invariants: set[str]
) -> dict[str, Any] | None:
    authorities: dict[str, Mapping[str, Any]] = {}
    revoked: set[str] = set()
    approvals: dict[str, Mapping[str, Any]] = {}
    approval_uses: dict[str, int] = {}
    tokens: dict[str, Mapping[str, Any]] = {}
    effect_ids: set[str] = set()
    receipt_ids: set[str] = set()
    prefix: list[str] = []
    for position in order:
        event = events[position]
        prefix.append(str(event["id"]))
        kind = event["kind"]
        violation: tuple[str, list[str]] | None = None
        if kind == "grant":
            authorities[str(event["authority_id"])] = event
        elif kind == "revoke":
            revoked.add(str(event["authority_id"]))
        elif kind == "approval":
            approvals[str(event["decision_id"])] = event
            approval_uses[str(event["decision_id"])] = 0
        elif kind == "token_exchange":
            authority = authorities.get(str(event["authority_id"]))
            if "active_authority_at_use" in invariants and (
                authority is None or event["authority_id"] in revoked
            ):
                violation = ("SP001", [str(event["authority_id"])])
            elif authority is not None:
                violation = _binding_violation(event, authority, invariants)
            if violation is None:
                tokens[str(event["token_id"])] = event
        elif kind == "effect":
            authority = authorities.get(str(event["authority_id"]))
            approval = approvals.get(str(event["decision_id"]))
            token = tokens.get(str(event["token_id"]))
            if "active_authority_at_use" in invariants and (
                authority is None or event["authority_id"] in revoked
            ):
                violation = ("SP001", [str(event["authority_id"])])
            elif "approval_before_effect" in invariants and approval is None:
                violation = ("SP002", [str(event["decision_id"])])
            elif (
                "single_use_approval" in invariants
                and approval is not None
                and approval_uses[str(event["decision_id"])] >= int(approval["max_uses"])
            ):
                violation = ("SP003", [str(event["decision_id"])])
            elif "token_before_effect" in invariants and token is None:
                violation = ("SP004", [str(event["token_id"])])
            else:
                for binding in (authority, approval, token):
                    if binding is not None:
                        violation = _binding_violation(event, binding, invariants)
                        if violation:
                            break
            if violation is None and "unique_effect_and_receipt" in invariants:
                if event["effect_id"] in effect_ids:
                    violation = ("SP008", [str(event["effect_id"])])
                elif event["receipt_id"] in receipt_ids:
                    violation = ("SP009", [str(event["receipt_id"])])
            if violation is None:
                if approval is not None:
                    approval_uses[str(event["decision_id"])] = (
                        approval_uses.get(str(event["decision_id"]), 0) + 1
                    )
                effect_ids.add(str(event["effect_id"]))
                receipt_ids.add(str(event["receipt_id"]))
        if violation:
            code, references = violation
            title, hint = _VIOLATIONS[code]
            return {
                "violation_id": code,
                "title": title,
                "event_id": event["id"],
                "schedule_prefix": prefix,
                "reference_ids": references,
                "repair_hint": hint,
            }
    return None


def _binding_violation(
    event: Mapping[str, Any], binding: Mapping[str, Any], invariants: set[str]
) -> tuple[str, list[str]] | None:
    if "identity_binding" in invariants and any(
        event.get(field) != binding.get(field) for field in ("subject", "resource")
    ):
        return "SP007", [str(binding["id"])]
    if "audience_binding" in invariants and event.get("audience") != binding.get("audience"):
        return "SP006", [str(binding["id"])]
    if "scope_attenuation" in invariants:
        requested = set(event.get("scopes", [event.get("scope")]))
        allowed = set(binding.get("scopes", []))
        if not requested <= allowed:
            return "SP005", [str(binding["id"])]
    return None


def _ancestor_map(ids: Sequence[str], edges: Sequence[Sequence[str]]) -> dict[str, set[str]]:
    parents = {item: set() for item in ids}
    for before, after in edges:
        parents[after].add(before)
    changed = True
    while changed:
        changed = False
        for event_id in ids:
            expanded = (
                set().union(*(parents[item] for item in parents[event_id]))
                if parents[event_id]
                else set()
            )
            if not expanded <= parents[event_id]:
                parents[event_id].update(expanded)
                changed = True
    return parents


def _counterexample(
    violation: Mapping[str, Any],
    event_by_id: Mapping[str, Mapping[str, Any]],
    ancestors: Mapping[str, set[str]],
    edges: Sequence[Sequence[str]],
) -> dict[str, Any]:
    prefix = list(violation["schedule_prefix"])
    event_id = str(violation["event_id"])
    refs = set(str(item) for item in violation["reference_ids"])
    related = {
        item["id"]
        for item in event_by_id.values()
        if refs
        & {
            str(item.get(key, ""))
            for key in ("authority_id", "decision_id", "token_id", "effect_id", "receipt_id")
        }
    }
    causal = [
        item
        for item in prefix
        if item == event_id or item in ancestors[event_id] or item in related
    ]
    missing: list[list[str]] = []
    code = violation["violation_id"]
    target_kind = {"SP002": "approval", "SP004": "token_exchange"}.get(code)
    if target_kind:
        candidates = [
            item["id"]
            for item in event_by_id.values()
            if item["kind"] == target_kind
            and item["id"] not in prefix
            and refs & {str(item.get(key, "")) for key in ("decision_id", "token_id")}
        ]
        if candidates and [candidates[0], event_id] not in edges:
            missing.append([candidates[0], event_id])
    if code == "SP001":
        candidates = [
            item["id"]
            for item in event_by_id.values()
            if item["kind"] == "grant"
            and item["id"] not in prefix
            and str(item.get("authority_id", "")) in refs
        ]
        if candidates and [candidates[0], event_id] not in edges:
            missing.append([candidates[0], event_id])
    return {
        "violation_id": code,
        "title": violation["title"],
        "event_id": event_id,
        "schedule_prefix": prefix,
        "causal_event_ids": causal,
        "missing_happens_before": missing,
        "repair_hint": violation["repair_hint"],
    }


def _counterexample_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    prefix = tuple(item["schedule_prefix"])
    return (len(prefix), prefix, item["violation_id"])
