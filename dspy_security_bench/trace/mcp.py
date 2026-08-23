"""Evidence probes for the stable MCP 2025-11-25 authorization specification."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.trace.proof import verify_trace_evidence

REPORT_TYPE = "TraceProof / MCP authorization evidence probes"
SPECIFICATION_REVISION = "2025-11-25"
SPECIFICATION_URL = "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization"
DISCLAIMER = (
    "This report evaluates declared, sanitized telemetry against selected MCP authorization "
    "requirements. It is not protocol certification, proof of telemetry completeness, identity "
    "validation, penetration testing, compliance, government endorsement, or authorization to operate."
)

_OBSERVATION_FIELDS = (
    "transport",
    "resource",
    "token_audience",
    "resource_indicator_authorization",
    "resource_indicator_token",
    "token_validated",
    "token_passthrough",
    "protected_resource_metadata",
    "authorization_server_issuer",
    "token_transport",
    "authorization_error",
    "response_status",
    "step_up_required",
    "step_up_completed",
    "retry_count",
    "decision",
)
_PSEUDONYM = re.compile(r"^sha256:[0-9a-f]{64}$")


def mcp_requirement_catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": "MCP-AUTH-001",
            "title": "Resource indicator in authorization and token requests",
            "requirement": "MUST",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-002",
            "title": "Canonical resource URI",
            "requirement": "MUST",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-003",
            "title": "Access token audience validation",
            "requirement": "MUST",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-004",
            "title": "No upstream token passthrough",
            "requirement": "MUST NOT",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-005",
            "title": "Protected Resource Metadata discovery",
            "requirement": "MUST",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-006",
            "title": "Authorization server issuer recorded",
            "requirement": "MUST",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-007",
            "title": "Bearer token in Authorization header, never query string",
            "requirement": "MUST / MUST NOT",
            "required_for_http": True,
        },
        {
            "id": "MCP-AUTH-008",
            "title": "Bounded step-up retries",
            "requirement": "SHOULD",
            "required_for_http": False,
        },
        {
            "id": "MCP-AUTH-009",
            "title": "Authorization error status semantics",
            "requirement": "MUST / SHOULD",
            "required_for_http": False,
        },
    ]


def analyze_mcp_authorization(evidence: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_trace_evidence(evidence)
    if errors:
        raise ValueError("invalid TraceProof evidence: " + "; ".join(errors))
    observations = []
    for span in evidence["spans"]:
        attrs = span["attributes"]
        if not _is_mcp_span(attrs):
            continue
        observation = {
            "trace_id": span["trace_id"],
            "span_id": span["span_id"],
            **{
                field: _observation_value(attrs.get(_attribute_name(field)))
                for field in _OBSERVATION_FIELDS
            },
        }
        observations.append(observation)
    observations.sort(key=lambda item: (item["trace_id"], item["span_id"]))
    checks = _evaluate_checks(observations)
    summary = _summary(observations, checks)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "specification_revision": SPECIFICATION_REVISION,
        "specification_url": SPECIFICATION_URL,
        "source_evidence_sha256": evidence["evidence_sha256"],
        "observations": observations,
        "requirements": mcp_requirement_catalog(),
        "checks": checks,
        "summary": summary,
        "disclaimer": DISCLAIMER,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_mcp_authorization_report(
    report: Mapping[str, Any], evidence: Mapping[str, Any] | None = None
) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "report_type",
        "specification_revision",
        "specification_url",
        "source_evidence_sha256",
        "observations",
        "requirements",
        "checks",
        "summary",
        "disclaimer",
        "report_sha256",
    }
    if set(report) != fields:
        errors.append("MCP probe report fields are incomplete or unsupported")
    if (
        report.get("schema_version") != 1
        or report.get("report_type") != REPORT_TYPE
        or report.get("specification_revision") != SPECIFICATION_REVISION
        or report.get("specification_url") != SPECIFICATION_URL
        or report.get("requirements") != mcp_requirement_catalog()
        or report.get("disclaimer") != DISCLAIMER
    ):
        errors.append("MCP probe metadata does not match the frozen protocol")
    observations = report.get("observations")
    if not isinstance(observations, list) or not all(
        _valid_observation(item) for item in observations
    ):
        errors.append("MCP probe observations are invalid")
        observations = []
    else:
        if observations != sorted(
            observations, key=lambda item: (item["trace_id"], item["span_id"])
        ):
            errors.append("MCP probe observations are not canonically sorted")
        expected_checks = _evaluate_checks(observations)
        if report.get("checks") != expected_checks:
            errors.append("MCP authorization checks do not recompute")
        if report.get("summary") != _summary(observations, expected_checks):
            errors.append("MCP authorization summary does not recompute")
    if evidence is not None:
        evidence_errors = verify_trace_evidence(evidence)
        errors.extend(f"source evidence: {item}" for item in evidence_errors)
        if not evidence_errors:
            expected = analyze_mcp_authorization(evidence)
            if report != expected:
                errors.append("MCP probe report does not recompute from source evidence")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError):
        actual = None
    if claimed != actual:
        errors.append("MCP probe report_sha256 does not match canonical content")
    return tuple(dict.fromkeys(errors))


def _evaluate_checks(observations: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    http = [item for item in observations if item.get("transport") == "streamable_http"]
    if not observations:
        return [_check(item, "not_observed", 0, 0) for item in mcp_requirement_catalog()]
    if not http:
        return [_check(item, "not_applicable", 0, 0) for item in mcp_requirement_catalog()]
    checks = []
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[0],
            http,
            lambda item: (
                bool(item.get("resource_indicator_authorization"))
                and bool(item.get("resource_indicator_token"))
                and item.get("resource_indicator_authorization")
                == item.get("resource_indicator_token")
                == item.get("resource")
            ),
            ("resource_indicator_authorization", "resource_indicator_token", "resource"),
        )
    )
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[1],
            http,
            lambda item: _canonical_resource(item.get("resource")),
            ("resource",),
        )
    )
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[2],
            http,
            lambda item: (
                item.get("token_validated") is True
                and bool(item.get("token_audience"))
                and item.get("token_audience") == item.get("resource")
            ),
            ("token_validated", "token_audience", "resource"),
        )
    )
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[3],
            http,
            lambda item: item.get("token_passthrough") is False,
            ("token_passthrough",),
        )
    )
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[4],
            http,
            lambda item: item.get("protected_resource_metadata") is True,
            ("protected_resource_metadata",),
        )
    )
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[5],
            http,
            lambda item: _https_uri(item.get("authorization_server_issuer")),
            ("authorization_server_issuer",),
        )
    )
    checks.append(
        _aggregate(
            mcp_requirement_catalog()[6],
            http,
            lambda item: item.get("token_transport") == "authorization_header",
            ("token_transport",),
        )
    )
    step_up = [
        item
        for item in http
        if item.get("step_up_required") is not None or item.get("retry_count") is not None
    ]
    if not step_up:
        checks.append(_check(mcp_requirement_catalog()[7], "not_applicable", 0, 0))
    else:
        checks.append(
            _aggregate(
                mcp_requirement_catalog()[7],
                step_up,
                lambda item: _bounded_retry(item),
                (),
            )
        )
    auth_errors = [item for item in http if item.get("authorization_error")]
    if not auth_errors:
        checks.append(_check(mcp_requirement_catalog()[8], "not_applicable", 0, 0))
    else:
        checks.append(
            _aggregate(
                mcp_requirement_catalog()[8],
                auth_errors,
                lambda item: _valid_error_status(
                    item.get("authorization_error"), item.get("response_status")
                ),
                ("authorization_error", "response_status"),
            )
        )
    return checks


def _aggregate(
    requirement: Mapping[str, Any],
    observations: list[Mapping[str, Any]],
    predicate,
    required_fields: tuple[str, ...],
) -> dict[str, Any]:
    observed = [
        item
        for item in observations
        if all(item.get(field) is not None and item.get(field) != "" for field in required_fields)
    ]
    if not observed:
        return _check(requirement, "not_observed", 0, 0)
    failures = sum(not bool(predicate(item)) for item in observed)
    return _check(requirement, "fail" if failures else "pass", len(observed), failures)


def _check(
    requirement: Mapping[str, Any], status: str, observed: int, failures: int
) -> dict[str, Any]:
    return {
        "id": requirement["id"],
        "title": requirement["title"],
        "requirement": requirement["requirement"],
        "status": status,
        "observed_spans": observed,
        "failed_spans": failures,
    }


def _summary(
    observations: list[Mapping[str, Any]], checks: list[Mapping[str, Any]]
) -> dict[str, Any]:
    counts = {
        status: sum(item["status"] == status for item in checks)
        for status in ("pass", "fail", "not_observed", "not_applicable")
    }
    required_ids = {item["id"] for item in mcp_requirement_catalog() if item["required_for_http"]}
    required_checks = [item for item in checks if item["id"] in required_ids]
    http_count = sum(item.get("transport") == "streamable_http" for item in observations)
    return {
        "observation_count": len(observations),
        "http_observation_count": http_count,
        **counts,
        "required_check_count": len(required_checks),
        "required_pass_count": sum(item["status"] == "pass" for item in required_checks),
        "conformance_ready": bool(http_count)
        and all(item["status"] == "pass" for item in required_checks)
        and counts["fail"] == 0,
        "review_required": counts["fail"] > 0 or counts["not_observed"] > 0,
    }


def _valid_observation(value: Any) -> bool:
    fields = {"trace_id", "span_id", *_OBSERVATION_FIELDS}
    if not isinstance(value, Mapping) or set(value) != fields:
        return False
    for field in ("trace_id", "span_id"):
        current = value.get(field)
        if not isinstance(current, str) or not _PSEUDONYM.fullmatch(current):
            return False
    try:
        canonical_sha256(value)
    except (TypeError, ValueError):
        return False
    return True


def _is_mcp_span(attrs: Mapping[str, Any]) -> bool:
    return any(key.startswith("dsb.mcp.") or key.startswith("mcp.") for key in attrs)


def _attribute_name(field: str) -> str:
    aliases = {
        "resource": "dsb.auth.resource",
        "token_audience": "dsb.auth.token_audience",
        "token_passthrough": "dsb.auth.token_passthrough",
        "step_up_required": "dsb.auth.step_up_required",
        "step_up_completed": "dsb.auth.step_up_completed",
        "retry_count": "dsb.auth.retry_count",
        "decision": "dsb.auth.decision",
    }
    return aliases.get(field, f"dsb.mcp.{field}")


def _observation_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, list):
        return value[:64]
    return None


def _canonical_resource(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc and not parsed.fragment)


def _https_uri(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.fragment


def _bounded_retry(item: Mapping[str, Any]) -> bool:
    retries = item.get("retry_count")
    if not isinstance(retries, (int, float)) or isinstance(retries, bool) or retries > 3:
        return False
    if item.get("step_up_required") is True:
        return item.get("step_up_completed") is True or item.get("decision") != "allow"
    return True


def _valid_error_status(error: Any, status: Any) -> bool:
    expected = {
        "invalid_token": 401,
        "missing_token": 401,
        "insufficient_scope": 403,
        "malformed_request": 400,
    }
    return expected.get(str(error)) == status
