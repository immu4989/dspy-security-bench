"""Content-free causal reconstruction for ScheduleProof.

CausalProof reads only structural OTLP fields: trace/span identifiers, parent
identifiers, span links, timestamps, and dropped-record counters. Names,
attributes, events, prompts, arguments, results, and credentials are ignored.
Operator-owned bindings supply the data-only ScheduleProof event semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.schedule.proof import validate_scenario

MANIFEST_TYPE = "dspy-security-bench-causalproof-manifest"
REPORT_TYPE = "CausalProof / Runtime-to-ScheduleProof evidence"
PROTOCOL_VERSION = "causalproof-v1"
MAX_TRACE_BYTES = 50 * 1024 * 1024
MAX_MANIFEST_BYTES = 1_048_576
MAX_SPANS = 10_000
MAX_BINDINGS = 12
DISCLAIMER = (
    "CausalProof establishes only how structural fields in the supplied OTLP bytes and "
    "operator assertions were converted. Generic span links remain undirected and wall-clock "
    "order remains non-proving. It does not prove trace completeness, clock synchronization, "
    "production safety, compliance, non-repudiation, risk acceptance, or authorization to operate."
)
_ID = re.compile(r"^[A-Za-z0-9_+/=-]{1,128}$")
_SAFE_EVENT_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,79}$")
_MANIFEST_FIELDS = {
    "schema_version",
    "manifest_type",
    "scenario_id",
    "title",
    "description",
    "bindings",
    "asserted_edges",
    "invariants",
    "exploration",
}


def protocol_payload() -> dict[str, Any]:
    """Return the frozen CausalProof v1 conversion contract."""

    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "structural_fields_read": [
            "traceId",
            "spanId",
            "parentSpanId",
            "links[].traceId",
            "links[].spanId",
            "startTimeUnixNano",
            "endTimeUnixNano",
            "droppedAttributesCount",
            "droppedEventsCount",
            "droppedLinksCount",
        ],
        "ignored_fields": ["name", "attributes", "events", "status", "resource", "scope"],
        "provenance_classes": {
            "observed_parent": "directional and eligible for ScheduleProof",
            "asserted": "operator-declared, directional, and eligible for ScheduleProof",
            "observed_link": "causally related but undirected; never schedule-eligible",
            "timing_candidate": "wall-clock review hint; never schedule-eligible",
        },
        "bounds": {
            "max_trace_bytes": MAX_TRACE_BYTES,
            "max_manifest_bytes": MAX_MANIFEST_BYTES,
            "max_spans": MAX_SPANS,
            "max_bindings": MAX_BINDINGS,
        },
        "claim_boundary": DISCLAIMER,
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def validate_manifest(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the operator-owned span-to-event binding manifest."""

    errors: list[str] = []
    if set(payload) != _MANIFEST_FIELDS:
        errors.append("manifest fields are incomplete or unsupported")
    if payload.get("schema_version") != 1 or payload.get("manifest_type") != MANIFEST_TYPE:
        errors.append("manifest metadata does not match CausalProof v1")
    for field, limit in (("scenario_id", 80), ("title", 160), ("description", 1000)):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            errors.append(f"{field} must be a non-empty string of at most {limit} characters")
    if isinstance(payload.get("scenario_id"), str) and not _SAFE_EVENT_ID.fullmatch(
        payload["scenario_id"]
    ):
        errors.append("scenario_id must use lowercase safe identifier characters")

    bindings = payload.get("bindings")
    event_ids: list[str] = []
    span_keys: list[tuple[str, str]] = []
    events: list[dict[str, Any]] = []
    if not isinstance(bindings, list) or not 2 <= len(bindings) <= MAX_BINDINGS:
        errors.append(f"bindings must contain between 2 and {MAX_BINDINGS} objects")
    else:
        for index, binding in enumerate(bindings):
            if not isinstance(binding, Mapping) or set(binding) != {"trace_id", "span_id", "event"}:
                errors.append(f"binding {index} fields are invalid")
                continue
            trace_id, span_id, event = (
                binding.get("trace_id"),
                binding.get("span_id"),
                binding.get("event"),
            )
            if not _valid_otel_id(trace_id):
                errors.append(f"binding {index} trace_id is invalid")
            if not _valid_otel_id(span_id):
                errors.append(f"binding {index} span_id is invalid")
            if isinstance(trace_id, str) and isinstance(span_id, str):
                span_keys.append((trace_id, span_id))
            if not isinstance(event, Mapping):
                errors.append(f"binding {index} event must be an object")
                continue
            event_copy = dict(event)
            events.append(event_copy)
            if isinstance(event.get("id"), str):
                event_ids.append(event["id"])
        if len(span_keys) != len(set(span_keys)):
            errors.append("binding trace_id/span_id pairs must be unique")
        if len(event_ids) != len(set(event_ids)):
            errors.append("bound event ids must be unique")

    asserted = payload.get("asserted_edges")
    asserted_pairs: list[tuple[str, str]] = []
    if not isinstance(asserted, list) or len(asserted) > 66:
        errors.append("asserted_edges must be a list with at most 66 entries")
    else:
        known = set(event_ids)
        for index, edge in enumerate(asserted):
            if not isinstance(edge, Mapping) or set(edge) != {"before", "after", "rationale"}:
                errors.append(f"asserted edge {index} fields are invalid")
                continue
            before, after, rationale = edge.get("before"), edge.get("after"), edge.get("rationale")
            if before not in known or after not in known:
                errors.append(f"asserted edge {index} references an unknown event")
            if before == after:
                errors.append(f"asserted edge {index} cannot be a self edge")
            if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 240:
                errors.append(f"asserted edge {index} rationale must contain 1 to 240 characters")
            if isinstance(before, str) and isinstance(after, str):
                asserted_pairs.append((before, after))
        if len(asserted_pairs) != len(set(asserted_pairs)):
            errors.append("asserted edges must be unique")

    if events:
        scenario = {
            "schema_version": 1,
            "scenario_type": "dspy-security-bench-scheduleproof-scenario",
            "scenario_id": payload.get("scenario_id"),
            "title": payload.get("title"),
            "description": payload.get("description"),
            "events": events,
            "happens_before": [list(pair) for pair in asserted_pairs],
            "invariants": payload.get("invariants"),
            "exploration": payload.get("exploration"),
        }
        errors.extend(f"bound ScheduleProof events: {item}" for item in validate_scenario(scenario))
    try:
        canonical_sha256(payload)
    except (TypeError, ValueError):
        errors.append("manifest must contain canonical JSON data")
    return tuple(dict.fromkeys(errors))


def analyze_causality(
    trace: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    source_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a provenance-separated causal ledger and ScheduleProof draft."""

    manifest_errors = validate_manifest(manifest)
    if manifest_errors:
        raise ValueError("invalid CausalProof manifest: " + "; ".join(manifest_errors))
    source_digest = source_sha256 or canonical_sha256(trace)
    if not re.fullmatch(r"[0-9a-f]{64}", source_digest):
        raise ValueError("source_sha256 must be a lowercase SHA-256 digest")

    spans = list(_iter_structural_spans(trace))
    if not spans:
        raise ValueError("trace input contains no OTLP spans")
    if len(spans) > MAX_SPANS:
        raise ValueError(f"trace input exceeds the {MAX_SPANS}-span boundary")
    diagnostics: list[dict[str, str]] = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for span in spans:
        key = (span["trace_id"], span["span_id"])
        if key in by_key:
            _diagnostic(
                diagnostics,
                "CP001",
                "error",
                "duplicate-span-identity",
                "The OTLP input repeats one trace/span identity; causal reconstruction is ambiguous.",
            )
        else:
            by_key[key] = span

    bindings = list(manifest["bindings"])
    event_to_key = {
        binding["event"]["id"]: (binding["trace_id"], binding["span_id"])
        for binding in bindings
    }
    key_to_event = {key: event_id for event_id, key in event_to_key.items()}
    observations: list[dict[str, Any]] = []
    found_events: set[str] = set()
    for event_id, key in sorted(event_to_key.items()):
        span = by_key.get(key)
        if span is None:
            _diagnostic(
                diagnostics,
                "CP002",
                "error",
                "bound-span-missing",
                f"Bound event {event_id!r} has no matching structural OTLP span.",
            )
            continue
        found_events.add(event_id)
        observations.append(
            {
                "event_id": event_id,
                "span_fingerprint": _span_fingerprint(*key),
                "has_parent": span["parent_span_id"] is not None,
                "link_count": len(span["links"]),
            }
        )

    relations: list[dict[str, Any]] = []
    trusted: set[tuple[str, str]] = set()
    observed_parent_count = observed_link_count = 0
    for event_id in sorted(found_events):
        key = event_to_key[event_id]
        span = by_key[key]
        parent_id = span["parent_span_id"]
        if parent_id:
            parent_key = (span["trace_id"], parent_id)
            parent_event = key_to_event.get(parent_key)
            if parent_event:
                pair = (parent_event, event_id)
                trusted.add(pair)
                observed_parent_count += 1
                relations.append(
                    _relation(
                        parent_event,
                        event_id,
                        "observed_parent",
                        "before",
                        True,
                        "OTLP parentSpanId within the same trace",
                    )
                )
            elif parent_key not in by_key:
                _diagnostic(
                    diagnostics,
                    "CP003",
                    "warning",
                    "parent-span-missing",
                    f"Event {event_id!r} references a parent span absent from the supplied OTLP bytes.",
                )
            else:
                _diagnostic(
                    diagnostics,
                    "CP004",
                    "warning",
                    "parent-span-unbound",
                    f"Event {event_id!r} has an observed parent that is not bound to a proof event.",
                )
        for linked_key in span["links"]:
            linked_event = key_to_event.get(linked_key)
            if linked_event:
                observed_link_count += 1
                relations.append(
                    _relation(
                        linked_event,
                        event_id,
                        "observed_link",
                        "related",
                        False,
                        "OTLP span link is causal but does not establish direction",
                    )
                )
            elif linked_key not in by_key:
                _diagnostic(
                    diagnostics,
                    "CP007",
                    "warning",
                    "linked-span-missing",
                    f"Event {event_id!r} links to a span absent from the supplied OTLP bytes.",
                )
            else:
                _diagnostic(
                    diagnostics,
                    "CP008",
                    "warning",
                    "linked-span-unbound",
                    f"Event {event_id!r} links to a span that is not bound to a proof event.",
                )

    asserted_count = 0
    for edge in sorted(manifest["asserted_edges"], key=lambda item: (item["before"], item["after"])):
        pair = (edge["before"], edge["after"])
        trusted.add(pair)
        asserted_count += 1
        relations.append(
            _relation(
                edge["before"],
                edge["after"],
                "asserted",
                "before",
                True,
                edge["rationale"],
            )
        )

    dropped = sum(span["dropped_records"] for span in spans)
    if dropped:
        _diagnostic(
            diagnostics,
            "CP005",
            "warning",
            "otel-records-dropped",
            f"The supplied OTLP spans report {dropped} dropped attributes, events, or links.",
        )

    timing_candidates = _timing_candidates(found_events, event_to_key, by_key, trusted)
    relations.extend(timing_candidates)
    scenario = {
        "schema_version": 1,
        "scenario_type": "dspy-security-bench-scheduleproof-scenario",
        "scenario_id": manifest["scenario_id"],
        "title": manifest["title"],
        "description": manifest["description"],
        "events": sorted(
            [deepcopy(binding["event"]) for binding in bindings], key=lambda item: item["id"]
        ),
        "happens_before": [list(pair) for pair in sorted(trusted)],
        "invariants": list(manifest["invariants"]),
        "exploration": deepcopy(manifest["exploration"]),
    }
    scenario_errors = validate_scenario(scenario)
    if scenario_errors:
        _diagnostic(
            diagnostics,
            "CP006",
            "error",
            "combined-causal-graph-invalid",
            "Observed and asserted directional edges do not form a valid ScheduleProof graph: "
            + "; ".join(scenario_errors),
        )
        schedule_scenario: dict[str, Any] | None = None
    else:
        schedule_scenario = scenario

    status = "review_required" if diagnostics else "ready"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "source_sha256": source_digest,
        "manifest_sha256": canonical_sha256(manifest),
        "summary": {
            "status": status,
            "span_records": len(spans),
            "bound_events": len(bindings),
            "matched_events": len(found_events),
            "trusted_edges": len(trusted),
            "observed_parent_edges": observed_parent_count,
            "asserted_edges": asserted_count,
            "observed_links": observed_link_count,
            "timing_candidates": len(timing_candidates),
            "diagnostic_count": len(diagnostics),
        },
        "observations": observations,
        "relations": sorted(
            relations,
            key=lambda item: (
                item["provenance"],
                item["from_event"],
                item["to_event"],
            ),
        ),
        "diagnostics": diagnostics,
        "schedule_scenario": schedule_scenario,
        "claim_boundary": DISCLAIMER,
    }
    report["report_sha256"] = _report_digest(report)
    return report


def verify_causal_report(
    report: Mapping[str, Any],
    trace: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    source_sha256: str | None = None,
) -> tuple[str, ...]:
    """Recompute a CausalProof report from its original structural inputs."""

    errors: list[str] = []
    if report.get("report_sha256") != _report_digest(report):
        errors.append("report_sha256 does not match canonical report content")
    try:
        expected = analyze_causality(trace, manifest, source_sha256=source_sha256)
    except (TypeError, ValueError) as exc:
        return tuple([*errors, str(exc)])
    if dict(report) != expected:
        errors.append("CausalProof report does not recompute from the supplied trace and manifest")
    return tuple(dict.fromkeys(errors))


def read_trace_file(path: Path) -> tuple[dict[str, Any], str]:
    """Read bounded OTLP JSON or JSON Lines and return its exact byte digest."""

    size = path.stat().st_size
    if size > MAX_TRACE_BYTES:
        raise ValueError(f"trace input exceeds the {MAX_TRACE_BYTES}-byte boundary")
    encoded = path.read_bytes()
    try:
        payload = json.loads(encoded)
    except json.JSONDecodeError:
        documents: list[dict[str, Any]] = []
        for number, line in enumerate(encoded.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid OTLP JSON Lines document at line {number}") from exc
            if not isinstance(item, dict):
                raise ValueError(
                    f"OTLP JSON Lines document {number} must be an object"
                ) from None
            documents.append(item)
        resources: list[Any] = []
        flat: list[Any] = []
        for item in documents:
            grouped = item.get("resourceSpans", item.get("resource_spans"))
            if isinstance(grouped, list):
                resources.extend(grouped)
            elif isinstance(item.get("spans"), list):
                flat.extend(item["spans"])
            else:
                raise ValueError(
                    "each OTLP JSON Lines document must contain resourceSpans or spans"
                ) from None
        if resources and flat:
            raise ValueError(
                "OTLP JSON Lines cannot mix grouped and flat span documents"
            ) from None
        payload = {"resourceSpans": resources} if resources else {"spans": flat}
    if not isinstance(payload, dict):
        raise ValueError("trace input root must be an object")
    return payload, hashlib.sha256(encoded).hexdigest()


def structural_trace(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Return a content-free, portable trace containing only fields CausalProof reads."""

    spans = list(_iter_structural_spans(trace))
    if not spans:
        raise ValueError("trace input contains no OTLP spans")
    if len(spans) > MAX_SPANS:
        raise ValueError(f"trace input exceeds the {MAX_SPANS}-span boundary")
    exported: list[dict[str, Any]] = []
    for span in spans:
        item: dict[str, Any] = {
            "traceId": span["trace_id"],
            "spanId": span["span_id"],
            "startTimeUnixNano": str(span["start"]),
            "endTimeUnixNano": str(span["end"]),
        }
        if span["parent_span_id"]:
            item["parentSpanId"] = span["parent_span_id"]
        if span["links"]:
            item["links"] = [
                {"traceId": trace_id, "spanId": span_id}
                for trace_id, span_id in span["links"]
            ]
        if span["dropped_records"]:
            item["droppedAttributesCount"] = span["dropped_records"]
        exported.append(item)
    exported.sort(key=lambda item: (item["traceId"], item["spanId"]))
    return {"spans": exported}


def build_demo_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a fictional trace and manifest with one undirected link and one assertion."""

    trace_id = "c" * 32
    ids = {name: f"{index:016x}" for index, name in enumerate(
        ("grant", "approve", "exchange", "commit", "revoke"), start=1
    )}
    spans = [
        _demo_span(trace_id, ids["grant"], 10, 20),
        _demo_span(trace_id, ids["approve"], 12, 22, links=[(trace_id, ids["grant"])]),
        _demo_span(trace_id, ids["exchange"], 30, 40, parent=ids["grant"]),
        _demo_span(trace_id, ids["commit"], 50, 60, parent=ids["exchange"]),
        _demo_span(trace_id, ids["revoke"], 45, 48, parent=ids["grant"]),
    ]
    trace = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    common = {
        "subject": "benefits-agent",
        "resource": "benefits-record-1042",
        "audience": "benefits-mcp",
    }
    events = {
        "grant": {
            "id": "grant",
            "kind": "grant",
            "actor": "identity-service",
            "authority_id": "authority-1042",
            **common,
            "scopes": ["record:update"],
        },
        "approve": {
            "id": "approve",
            "kind": "approval",
            "actor": "case-worker",
            "decision_id": "decision-1042",
            **common,
            "scopes": ["record:update"],
            "max_uses": 1,
        },
        "exchange": {
            "id": "exchange",
            "kind": "token_exchange",
            "actor": "token-service",
            "token_id": "token-1042",
            "authority_id": "authority-1042",
            **common,
            "scopes": ["record:update"],
        },
        "commit": {
            "id": "commit",
            "kind": "effect",
            "actor": "benefits-agent",
            "effect_id": "record-change-1042",
            **common,
            "scope": "record:update",
            "authority_id": "authority-1042",
            "decision_id": "decision-1042",
            "token_id": "token-1042",
            "receipt_id": "receipt-1042",
        },
        "revoke": {
            "id": "revoke",
            "kind": "revoke",
            "actor": "identity-service",
            "authority_id": "authority-1042",
        },
    }
    manifest = {
        "schema_version": 1,
        "manifest_type": MANIFEST_TYPE,
        "scenario_id": "fictional-benefits-revocation",
        "title": "Fictional benefits record revocation race",
        "description": "Synthetic metadata-only fixture; no claimant, agency, or production data.",
        "bindings": [
            {"trace_id": trace_id, "span_id": ids[name], "event": events[name]}
            for name in ("grant", "approve", "exchange", "commit", "revoke")
        ],
        "asserted_edges": [
            {
                "before": "approve",
                "after": "commit",
                "rationale": "The operator asserts atomic approval persistence before commit.",
            }
        ],
        "invariants": [
            "active_authority_at_use",
            "approval_before_effect",
            "single_use_approval",
            "token_before_effect",
            "scope_attenuation",
            "audience_binding",
            "identity_binding",
            "unique_effect_and_receipt",
        ],
        "exploration": {"max_schedules": 100000},
    }
    return trace, manifest


def _iter_structural_spans(trace: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    resource_spans = trace.get("resourceSpans", trace.get("resource_spans"))
    if isinstance(resource_spans, list):
        for resource_group in resource_spans:
            if not isinstance(resource_group, Mapping):
                continue
            groups = resource_group.get("scopeSpans", resource_group.get("scope_spans", []))
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, Mapping) or not isinstance(group.get("spans"), list):
                    continue
                for span in group["spans"]:
                    if isinstance(span, Mapping):
                        yield _structural_span(span)
        return
    spans = trace.get("spans")
    if isinstance(spans, list):
        for span in spans:
            if isinstance(span, Mapping):
                yield _structural_span(span)


def _structural_span(span: Mapping[str, Any]) -> dict[str, Any]:
    trace_id = _first(span, "traceId", "trace_id")
    span_id = _first(span, "spanId", "span_id")
    parent_id = _first(span, "parentSpanId", "parent_span_id")
    if not _valid_otel_id(trace_id) or not _valid_otel_id(span_id):
        raise ValueError("every structural OTLP span requires valid traceId and spanId values")
    if parent_id not in (None, "") and not _valid_otel_id(parent_id):
        raise ValueError("OTLP parentSpanId is invalid")
    links: list[tuple[str, str]] = []
    raw_links = span.get("links", [])
    if isinstance(raw_links, list):
        for link in raw_links:
            if not isinstance(link, Mapping):
                continue
            link_trace = _first(link, "traceId", "trace_id")
            link_span = _first(link, "spanId", "span_id")
            if _valid_otel_id(link_trace) and _valid_otel_id(link_span):
                links.append((link_trace, link_span))
    dropped = sum(
        _nonnegative_int(_first(span, camel, snake))
        for camel, snake in (
            ("droppedAttributesCount", "dropped_attributes_count"),
            ("droppedEventsCount", "dropped_events_count"),
            ("droppedLinksCount", "dropped_links_count"),
        )
    )
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_id or None,
        "links": links,
        "start": _nonnegative_int(_first(span, "startTimeUnixNano", "start_time_unix_nano")),
        "end": _nonnegative_int(_first(span, "endTimeUnixNano", "end_time_unix_nano")),
        "dropped_records": dropped,
    }


def _timing_candidates(
    found: set[str],
    event_to_key: Mapping[str, tuple[str, str]],
    spans: Mapping[tuple[str, str], Mapping[str, Any]],
    trusted: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    causally_ordered = _transitive_pairs(trusted)
    ordered = sorted(found)
    for before in ordered:
        left = spans[event_to_key[before]]
        if not left["end"]:
            continue
        for after in ordered:
            if (
                before == after
                or (before, after) in causally_ordered
                or (after, before) in causally_ordered
            ):
                continue
            right = spans[event_to_key[after]]
            if right["start"] and left["end"] <= right["start"]:
                candidates.append(
                    _relation(
                        before,
                        after,
                        "timing_candidate",
                        "candidate_before",
                        False,
                        "Local timestamps do not establish distributed happens-before order",
                    )
                )
    return candidates


def _transitive_pairs(edges: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Return the strict reachability relation without treating it as new evidence."""

    reachable = set(edges)
    while True:
        inferred = {
            (left, right)
            for left, middle in reachable
            for candidate, right in reachable
            if middle == candidate and left != right
        }
        expanded = reachable | inferred
        if expanded == reachable:
            return reachable
        reachable = expanded


def _relation(
    from_event: str,
    to_event: str,
    provenance: str,
    direction: str,
    eligible: bool,
    rationale: str,
) -> dict[str, Any]:
    return {
        "from_event": from_event,
        "to_event": to_event,
        "provenance": provenance,
        "direction": direction,
        "schedule_eligible": eligible,
        "rationale": rationale,
    }


def _diagnostic(
    target: list[dict[str, str]], code: str, severity: str, name: str, message: str
) -> None:
    item = {"code": code, "severity": severity, "name": name, "message": message}
    if item not in target:
        target.append(item)


def _span_fingerprint(trace_id: str, span_id: str) -> str:
    return hashlib.sha256(f"causalproof-v1\0{trace_id}\0{span_id}".encode()).hexdigest()


def _report_digest(report: Mapping[str, Any]) -> str:
    return canonical_sha256({key: value for key, value in report.items() if key != "report_sha256"})


def _valid_otel_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID.fullmatch(value)) and bool(value.strip("0="))


def _first(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _nonnegative_int(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def _demo_span(
    trace_id: str,
    span_id: str,
    start: int,
    end: int,
    *,
    parent: str | None = None,
    links: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    span: dict[str, Any] = {
        "traceId": trace_id,
        "spanId": span_id,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "name": "ignored-by-causalproof",
        "attributes": [{"key": "ignored.content", "value": {"stringValue": "never-read"}}],
    }
    if parent:
        span["parentSpanId"] = parent
    if links:
        span["links"] = [{"traceId": item[0], "spanId": item[1]} for item in links]
    return span
