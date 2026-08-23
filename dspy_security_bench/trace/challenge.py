"""Deterministic synthetic corpus that regression-tests TraceProof redaction."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.trace.proof import build_trace_evidence

CHALLENGE_TYPE = "TraceProof / Synthetic redaction challenge"
CHALLENGE_VERSION = "traceproof-redaction-challenge-v1"
DISCLAIMER = (
    "This deterministic corpus tests documented sanitizer surfaces with fictional canaries. "
    "Passing does not prove that arbitrary production telemetry is anonymous, secret-free, "
    "complete, compliant, or safe to publish. Operators must review their own data boundary."
)

_SURFACES: tuple[tuple[str, str, str, str], ...] = (
    ("prompt", "span", "gen_ai.prompt", "content_fields_removed"),
    ("completion", "span", "gen_ai.completion", "content_fields_removed"),
    ("tool-arguments", "span", "tool.call.arguments", "content_fields_removed"),
    ("request-body", "span", "http.request.body", "content_fields_removed"),
    ("response-body", "span", "http.response.body", "content_fields_removed"),
    ("message-array", "span", "gen_ai.input.messages", "content_fields_removed"),
    ("authorization-header", "span", "http.request.header.authorization", "secret_fields_removed"),
    ("api-key", "span", "provider.api_key", "secret_fields_removed"),
    ("access-token", "span", "oauth.access_token", "secret_fields_removed"),
    ("password", "span", "database.password", "secret_fields_removed"),
    ("cookie", "span", "http.cookie", "secret_fields_removed"),
    ("private-key", "span", "tls.private_key", "secret_fields_removed"),
    ("unknown-attribute", "span", "customer.raw_record", "unapproved_attributes_removed"),
    ("unknown-dsb-attribute", "span", "dsb.auth.debug_payload", "unapproved_attributes_removed"),
    ("user-identity", "span", "user.id", "identity_values_hashed"),
    ("tenant-identity", "resource", "tenant", "identity_values_hashed"),
    ("agent-identity", "span", "dsb.auth.agent_id", "identity_values_hashed"),
    ("event-content", "event", "event.message", "content_fields_removed"),
    ("allowed-key-bearer-value", "span", "dsb.auth.resource", "secret_fields_removed"),
    ("allowed-key-provider-secret", "span", "gen_ai.agent.name", "secret_fields_removed"),
)


def run_redaction_challenge() -> dict[str, Any]:
    cases = []
    for index, (surface, location, key, counter) in enumerate(_SURFACES, start=1):
        canary = _canary(index, surface)
        value = _surface_value(surface, canary)
        evidence = build_trace_evidence(_payload(index, location, key, value))
        encoded = json.dumps(evidence, sort_keys=True)
        escaped = canary in encoded
        observed = int(evidence["redaction_summary"][counter])
        cases.append(
            {
                "case_id": f"RC{index:03d}",
                "surface": surface,
                "location": location,
                "attribute_key": key,
                "expected_counter": counter,
                "counter_observed": observed,
                "canary_sha256": hashlib.sha256(canary.encode()).hexdigest(),
                "sanitized_evidence_sha256": evidence["evidence_sha256"],
                "escaped": escaped,
                "passed": not escaped and observed >= 1,
            }
        )
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": CHALLENGE_TYPE,
        "challenge_version": CHALLENGE_VERSION,
        "case_count": len(cases),
        "passed_count": sum(item["passed"] for item in cases),
        "escaped_count": sum(item["escaped"] for item in cases),
        "cases": cases,
        "status": "pass" if all(item["passed"] for item in cases) else "fail",
        "disclaimer": DISCLAIMER,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_redaction_challenge(report: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        expected = run_redaction_challenge()
    except (TypeError, ValueError) as exc:  # pragma: no cover - internal regression path
        return (f"challenge could not recompute: {exc}",)
    if report != expected:
        errors.append("redaction challenge does not recompute from the frozen synthetic corpus")
    if report.get("status") != "pass" or report.get("escaped_count") != 0:
        errors.append("one or more synthetic redaction canaries escaped")
    return tuple(errors)


def _payload(index: int, location: str, key: str, value: Any) -> dict[str, Any]:
    base_attributes = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "synthetic.redaction_probe",
    }
    resource_attributes = {"service.name": "traceproof-redaction-challenge"}
    events = []
    if location == "span":
        base_attributes[key] = value
    elif location == "resource":
        resource_attributes[key] = value
    else:
        events = [
            {
                "name": "gen_ai.redaction_probe",
                "timeUnixNano": str(2_000_000_000 + index),
                "attributes": _otlp_attributes({key: value}),
            }
        ]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": _otlp_attributes(resource_attributes)},
                "scopeSpans": [
                    {
                        "scope": {"name": "traceproof.challenge"},
                        "spans": [
                            {
                                "traceId": f"{index:032x}",
                                "spanId": f"{index:016x}",
                                "name": "synthetic-redaction-probe",
                                "kind": 3,
                                "startTimeUnixNano": str(1_000_000_000 + index),
                                "endTimeUnixNano": str(1_001_000_000 + index),
                                "status": {"code": 1},
                                "attributes": _otlp_attributes(base_attributes),
                                "events": events,
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _surface_value(surface: str, canary: str) -> Any:
    if surface == "message-array":
        return [canary, "synthetic second message"]
    if surface == "allowed-key-bearer-value":
        return f"Bearer {canary}ABCDEFGH"
    if surface == "allowed-key-provider-secret":
        return f"sk-{canary}ABCDEFGH"
    if surface == "private-key":
        return f"-----BEGIN PRIVATE KEY-----\n{canary}\n-----END PRIVATE KEY-----"
    return canary


def _canary(index: int, surface: str) -> str:
    return f"TRACEPROOF_CANARY_{index:03d}_{surface.upper().replace('-', '_')}"


def _otlp_attributes(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key, value in values.items():
        if isinstance(value, list):
            wrapped = {"arrayValue": {"values": [{"stringValue": item} for item in value]}}
        else:
            wrapped = {"stringValue": str(value)}
        result.append({"key": key, "value": wrapped})
    return result
