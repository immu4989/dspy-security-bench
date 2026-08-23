"""Privacy-first OpenTelemetry/MCP trace normalization and deterministic analysis.

TraceProof intentionally accepts exported JSON rather than connecting to a live
collector.  Operators retain custody of production telemetry and choose the bytes
that enter this bounded, offline transformation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import yaml

from dspy_security_bench.mission.loader import canonical_sha256

EVIDENCE_TYPE = "traceproof-normalized-trace"
REPORT_TYPE = "TraceProof / Privacy-bounded agent trace analysis"
TWIN_TYPE = "traceproof-synthetic-agent-twin"
SCHEMA_VERSION = 1
OSCAL_VERSION = "1.2.2"
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_SPANS = 10_000
MAX_ATTRIBUTES = 256
MAX_VALUE_CHARS = 512
DISCLAIMER = (
    "TraceProof is privacy-bounded technical evidence, not complete production telemetry, "
    "incident response, formal verification, compliance, certification, risk acceptance, "
    "or an authorization to operate. Findings require accountable human review."
)

_CONTENT_TOKENS = {
    "prompt",
    "completion",
    "content",
    "message",
    "arguments",
    "response.body",
    "request.body",
    "tool.call.arguments",
}
_SECRET_TOKENS = {
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "cookie",
    "private_key",
}
_IDENTITY_TOKENS = {
    "user.id",
    "enduser.id",
    "principal.id",
    "principal_id",
    "agent.id",
    "agent_id",
    "session.id",
    "session_id",
    "tenant",
}
_SAFE_DEFAULTS = {
    "gen_ai.operation.name",
    "gen_ai.agent.name",
    "gen_ai.tool.name",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "mcp.method.name",
    "mcp.tool.name",
    "rpc.method",
    "server.address",
    "service.name",
    "error.type",
}
_DSB_PREFIXES = ("dsb.auth.", "dsb.approval.", "dsb.effect.", "dsb.delegation.")
_SAFE_EVENT_PREFIXES = ("gen_ai.", "mcp.", "tool.", "auth.", "approval.", "effect.")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def default_redaction_policy() -> dict[str, Any]:
    """Return the public, deny-by-default TraceProof policy."""

    return {
        "schema_version": 1,
        "policy_id": "traceproof-default-deny-v1",
        "allow_attributes": sorted(_SAFE_DEFAULTS),
        "hash_attributes": sorted(_IDENTITY_TOKENS),
        "drop_attributes": sorted(_CONTENT_TOKENS | _SECRET_TOKENS),
        "allow_dsb_security_attributes": True,
        "keep_span_names": False,
        "max_spans": MAX_SPANS,
        "max_attributes_per_span": MAX_ATTRIBUTES,
        "max_value_chars": MAX_VALUE_CHARS,
    }


def load_redaction_policy(path: str | Path | None) -> tuple[dict[str, Any], str]:
    """Load and validate a JSON/YAML policy; return the public policy and hash salt."""

    raw: Any = default_redaction_policy()
    if path is not None:
        source = Path(path)
        try:
            raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"could not read redaction policy: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ValueError("redaction policy must be an object")
    allowed = set(default_redaction_policy()) | {"hash_salt"}
    extra = sorted(set(raw) - allowed)
    if extra:
        raise ValueError("unsupported redaction policy fields: " + ", ".join(extra))
    merged = {**default_redaction_policy(), **dict(raw)}
    if merged.get("schema_version") != 1:
        raise ValueError("redaction policy schema_version must be 1")
    if not isinstance(merged.get("policy_id"), str) or not merged["policy_id"].strip():
        raise ValueError("redaction policy_id must be non-empty")
    for field in ("allow_attributes", "hash_attributes", "drop_attributes"):
        values = merged.get(field)
        if not isinstance(values, list) or not all(
            isinstance(item, str) and item.strip() for item in values
        ):
            raise ValueError(f"redaction policy {field} must be a string array")
        merged[field] = sorted(set(values))
    for field, maximum in (
        ("max_spans", MAX_SPANS),
        ("max_attributes_per_span", MAX_ATTRIBUTES),
        ("max_value_chars", MAX_VALUE_CHARS),
    ):
        value = merged.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            raise ValueError(f"redaction policy {field} must be between 1 and {maximum}")
    for field in ("allow_dsb_security_attributes", "keep_span_names"):
        if not isinstance(merged.get(field), bool):
            raise ValueError(f"redaction policy {field} must be boolean")
    salt = merged.pop("hash_salt", "traceproof-local-v1")
    if not isinstance(salt, str) or len(salt) < 8:
        raise ValueError("redaction policy hash_salt must contain at least 8 characters")
    return json.loads(json.dumps(merged)), salt


def build_trace_evidence(
    source: str | Path | Mapping[str, Any],
    *,
    policy_path: str | Path | None = None,
) -> dict[str, Any]:
    """Normalize OTLP JSON into a content-addressed, privacy-bounded evidence graph."""

    raw, source_sha256 = _read_source(source)
    policy, salt = load_redaction_policy(policy_path)
    spans = list(_iter_spans(raw))
    if not spans:
        raise ValueError("trace input contains no OTLP or flat JSON spans")
    if len(spans) > policy["max_spans"]:
        raise ValueError(f"trace input exceeds policy max_spans={policy['max_spans']}")
    counters: Counter[str] = Counter()
    normalized = [
        _normalize_span(span, resource, scope, policy, salt, counters)
        for span, resource, scope in spans
    ]
    normalized.sort(
        key=lambda item: (item["trace_id"], item["start_time_unix_nano"], item["span_id"])
    )
    trace_count = len({item["trace_id"] for item in normalized})
    public_policy = deepcopy(policy)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_type": EVIDENCE_TYPE,
        "source_format": "opentelemetry-json",
        "source_sha256": source_sha256,
        "policy": public_policy,
        "policy_sha256": canonical_sha256(public_policy),
        "salt_sha256": hashlib.sha256(salt.encode()).hexdigest(),
        "trace_count": trace_count,
        "span_count": len(normalized),
        "spans": normalized,
        "redaction_summary": {
            "content_fields_removed": counters["content"],
            "secret_fields_removed": counters["secret"],
            "unapproved_attributes_removed": counters["unapproved"],
            "identity_values_hashed": counters["hashed"],
            "truncated_values": counters["truncated"],
        },
        "disclaimer": DISCLAIMER,
    }
    payload["evidence_sha256"] = canonical_sha256(payload)
    return payload


def analyze_trace_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Apply deterministic authorization/effect rules to verified TraceProof evidence."""

    errors = verify_trace_evidence(evidence)
    if errors:
        raise ValueError("invalid TraceProof evidence: " + "; ".join(errors))
    findings: list[dict[str, Any]] = []
    by_span = {span["span_id"]: span for span in evidence["spans"]}
    for span in evidence["spans"]:
        attrs = span["attributes"]
        _apply_span_rules(span, attrs, findings)
        parent = span.get("parent_span_id")
        if parent and parent not in by_span:
            findings.append(
                _finding(
                    "TP010",
                    "medium",
                    span,
                    "Parent span is absent from the supplied evidence boundary",
                    {"parent_span_id": parent},
                    "Preserve the authorization path or document the intentional export boundary.",
                )
            )
    findings.sort(key=lambda item: (item["severity_rank"], item["rule_id"], item["span_id"]))
    for item in findings:
        item.pop("severity_rank")
    severities = Counter(item["severity"] for item in findings)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_type": REPORT_TYPE,
        "source_evidence_sha256": evidence["evidence_sha256"],
        "policy_sha256": evidence["policy_sha256"],
        "summary": {
            "trace_count": evidence["trace_count"],
            "span_count": evidence["span_count"],
            "finding_count": len(findings),
            "critical": severities["critical"],
            "high": severities["high"],
            "medium": severities["medium"],
            "low": severities["low"],
            "review_required": bool(findings),
        },
        "rules": rule_catalog(),
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def rule_catalog() -> list[dict[str, str]]:
    return [
        {"id": "TP001", "name": "missing-authorization-decision", "severity": "high"},
        {"id": "TP002", "name": "token-audience-mismatch", "severity": "critical"},
        {"id": "TP003", "name": "token-passthrough-observed", "severity": "critical"},
        {"id": "TP004", "name": "scope-exceeds-grant", "severity": "high"},
        {"id": "TP005", "name": "missing-sensitive-action-approval", "severity": "high"},
        {"id": "TP006", "name": "approval-action-mismatch", "severity": "critical"},
        {"id": "TP007", "name": "delegated-agent-identity-mismatch", "severity": "high"},
        {"id": "TP008", "name": "revoked-grant-allowed", "severity": "critical"},
        {"id": "TP009", "name": "incomplete-step-up-allowed", "severity": "high"},
        {"id": "TP010", "name": "trace-parent-missing", "severity": "medium"},
        {"id": "TP011", "name": "authorization-retry-loop", "severity": "medium"},
        {"id": "TP012", "name": "unreceipted-external-effect", "severity": "high"},
    ]


def verify_trace_artifact(payload: Mapping[str, Any]) -> tuple[str, ...]:
    artifact = (
        payload.get("evidence_type") or payload.get("report_type") or payload.get("pack_type")
    )
    if artifact == EVIDENCE_TYPE:
        return verify_trace_evidence(payload)
    if artifact == REPORT_TYPE:
        return verify_trace_report(payload)
    if artifact == TWIN_TYPE:
        return verify_trace_twin(payload)
    return ("unsupported TraceProof artifact type",)


def verify_trace_evidence(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "evidence_type",
        "source_format",
        "source_sha256",
        "policy",
        "policy_sha256",
        "salt_sha256",
        "trace_count",
        "span_count",
        "spans",
        "redaction_summary",
        "disclaimer",
        "evidence_sha256",
    }
    if set(payload) != fields:
        errors.append("evidence fields are incomplete or unsupported")
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("evidence_type") != EVIDENCE_TYPE
    ):
        errors.append("unsupported TraceProof evidence version or type")
    if (
        payload.get("source_format") != "opentelemetry-json"
        or payload.get("disclaimer") != DISCLAIMER
    ):
        errors.append("evidence metadata does not match TraceProof v1")
    for field in ("source_sha256", "policy_sha256", "salt_sha256", "evidence_sha256"):
        if not _is_digest(payload.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")
    policy = payload.get("policy")
    if not isinstance(policy, Mapping) or payload.get("policy_sha256") != _safe_hash(policy):
        errors.append("policy_sha256 does not match canonical policy")
    spans = payload.get("spans")
    if not isinstance(spans, list) or not spans or len(spans) > MAX_SPANS:
        errors.append("spans must contain 1 to 10000 normalized spans")
    elif not all(_valid_normalized_span(item) for item in spans):
        errors.append("one or more normalized spans are invalid or contain unsupported fields")
    else:
        if payload.get("span_count") != len(spans):
            errors.append("span_count does not match spans")
        if payload.get("trace_count") != len({item["trace_id"] for item in spans}):
            errors.append("trace_count does not match spans")
    summary = payload.get("redaction_summary")
    expected_summary = {
        "content_fields_removed",
        "secret_fields_removed",
        "unapproved_attributes_removed",
        "identity_values_hashed",
        "truncated_values",
    }
    if (
        not isinstance(summary, Mapping)
        or set(summary) != expected_summary
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in summary.values()
        )
    ):
        errors.append("redaction_summary is invalid")
    unsigned = dict(payload)
    claimed = unsigned.pop("evidence_sha256", None)
    if claimed != _safe_hash(unsigned):
        errors.append("evidence_sha256 does not match canonical evidence content")
    return tuple(dict.fromkeys(errors))


def verify_trace_report(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "report_type",
        "source_evidence_sha256",
        "policy_sha256",
        "summary",
        "rules",
        "findings",
        "disclaimer",
        "report_sha256",
    }
    if set(payload) != fields:
        errors.append("report fields are incomplete or unsupported")
    if payload.get("schema_version") != 1 or payload.get("report_type") != REPORT_TYPE:
        errors.append("unsupported TraceProof report version or type")
    if payload.get("disclaimer") != DISCLAIMER or payload.get("rules") != rule_catalog():
        errors.append("report metadata or rule catalog does not match TraceProof v1")
    for field in ("source_evidence_sha256", "policy_sha256", "report_sha256"):
        if not _is_digest(payload.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")
    findings = payload.get("findings")
    if not isinstance(findings, list) or not all(_valid_finding(item) for item in findings):
        errors.append("findings are invalid")
    elif payload.get("summary") != _report_summary(payload, findings):
        errors.append("summary does not recompute from findings")
    unsigned = dict(payload)
    claimed = unsigned.pop("report_sha256", None)
    if claimed != _safe_hash(unsigned):
        errors.append("report_sha256 does not match canonical report content")
    return tuple(dict.fromkeys(errors))


def synthesize_trace_twin(
    evidence: Mapping[str, Any], report: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Distill sanitized evidence into a deterministic, shareable graph replay."""

    errors = verify_trace_evidence(evidence)
    if errors:
        raise ValueError("invalid TraceProof evidence: " + "; ".join(errors))
    generated = analyze_trace_evidence(evidence) if report is None else dict(report)
    report_errors = verify_trace_report(generated)
    if report_errors or generated["source_evidence_sha256"] != evidence["evidence_sha256"]:
        raise ValueError("TraceProof report is invalid or belongs to different evidence")
    if generated != analyze_trace_evidence(evidence):
        raise ValueError("TraceProof report does not recompute from supplied evidence")
    spans = evidence["spans"]
    nodes = sorted(
        {
            value
            for span in spans
            for value in (
                span["attributes"].get("gen_ai.agent.name"),
                span["attributes"].get("gen_ai.tool.name"),
                span["attributes"].get("mcp.tool.name"),
            )
            if isinstance(value, str)
        }
    )
    edges = [
        {
            "edge_id": span["span_id"],
            "parent_edge_id": span["parent_span_id"],
            "operation": span["name"],
            "trace_id": span["trace_id"],
        }
        for span in spans
    ]
    scenarios = [
        {
            "scenario_id": f"traceproof-{index:03d}-{finding['rule_id'].lower()}",
            "rule_id": finding["rule_id"],
            "source_span_id": finding["span_id"],
            "mutation_surface": finding["evidence"],
            "expected_control_outcome": "contain_or_review",
        }
        for index, finding in enumerate(generated["findings"], start=1)
    ]
    twin: dict[str, Any] = {
        "schema_version": 1,
        "pack_type": TWIN_TYPE,
        "source_evidence_sha256": evidence["evidence_sha256"],
        "source_report_sha256": generated["report_sha256"],
        "privacy_boundary": "only normalized TraceProof fields; no source trace content",
        "nodes": nodes,
        "edges": edges,
        "scenarios": scenarios,
        "disclaimer": DISCLAIMER,
    }
    twin["pack_sha256"] = canonical_sha256(twin)
    return twin


def verify_trace_twin(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "pack_type",
        "source_evidence_sha256",
        "source_report_sha256",
        "privacy_boundary",
        "nodes",
        "edges",
        "scenarios",
        "disclaimer",
        "pack_sha256",
    }
    if set(payload) != fields:
        errors.append("synthetic twin fields are incomplete or unsupported")
    if payload.get("schema_version") != 1 or payload.get("pack_type") != TWIN_TYPE:
        errors.append("unsupported synthetic twin version or type")
    if payload.get("disclaimer") != DISCLAIMER:
        errors.append("synthetic twin disclaimer does not match TraceProof v1")
    if not isinstance(payload.get("nodes"), list) or not all(
        isinstance(item, str) for item in payload.get("nodes", [])
    ):
        errors.append("synthetic twin nodes must be strings")
    if not isinstance(payload.get("edges"), list) or not all(
        isinstance(item, Mapping)
        and set(item) == {"edge_id", "parent_edge_id", "operation", "trace_id"}
        for item in payload.get("edges", [])
    ):
        errors.append("synthetic twin edges are invalid")
    if not isinstance(payload.get("scenarios"), list) or not all(
        isinstance(item, Mapping)
        and set(item)
        == {
            "scenario_id",
            "rule_id",
            "source_span_id",
            "mutation_surface",
            "expected_control_outcome",
        }
        for item in payload.get("scenarios", [])
    ):
        errors.append("synthetic twin scenarios are invalid")
    for field in ("source_evidence_sha256", "source_report_sha256", "pack_sha256"):
        if not _is_digest(payload.get(field)):
            errors.append(f"{field} must be a SHA-256 digest")
    unsigned = dict(payload)
    claimed = unsigned.pop("pack_sha256", None)
    if claimed != _safe_hash(unsigned):
        errors.append("pack_sha256 does not match canonical twin content")
    return tuple(dict.fromkeys(errors))


def export_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_trace_report(report)
    if errors:
        raise ValueError("invalid TraceProof report: " + "; ".join(errors))
    by_id = {item["id"]: item for item in report["rules"]}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench TraceProof",
                        "informationUri": "https://immu4989.github.io/dspy-security-bench/",
                        "rules": [
                            {
                                "id": rule["id"],
                                "name": rule["name"],
                                "shortDescription": {"text": rule["name"].replace("-", " ")},
                                "properties": {"defaultSeverity": rule["severity"]},
                            }
                            for rule in report["rules"]
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding["rule_id"],
                        "level": _sarif_level(finding["severity"]),
                        "message": {"text": finding["title"]},
                        "locations": [
                            {
                                "logicalLocations": [
                                    {
                                        "name": finding["span_id"],
                                        "fullyQualifiedName": f"trace:{finding['trace_id']}/span:{finding['span_id']}",
                                        "kind": "trace-span",
                                    }
                                ]
                            }
                        ],
                        "properties": {
                            "severity": finding["severity"],
                            "remediation": finding["remediation"],
                            "ruleName": by_id[finding["rule_id"]]["name"],
                            "sourceReportSha256": report["report_sha256"],
                        },
                    }
                    for finding in report["findings"]
                ],
            }
        ],
    }


def export_oscal(report: Mapping[str, Any]) -> dict[str, Any]:
    errors = verify_trace_report(report)
    if errors:
        raise ValueError("invalid TraceProof report: " + "; ".join(errors))
    digest = report["report_sha256"]
    namespace = f"https://github.com/immu4989/dspy-security-bench/traceproof/{digest}"
    start = "1970-01-01T00:00:00Z"
    return {
        "assessment-results": {
            "uuid": str(uuid5(NAMESPACE_URL, namespace)),
            "metadata": {
                "title": "TraceProof privacy-bounded agent assessment observations",
                "last-modified": start,
                "version": digest[:12],
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "traceproof-report-sha256", "value": digest},
                    {"name": "traceproof-non-certifying", "value": "true"},
                ],
                "remarks": DISCLAIMER,
            },
            "import-ap": {"href": "urn:traceproof:owner-supplied-assessment-plan"},
            "results": [
                {
                    "uuid": str(uuid5(NAMESPACE_URL, namespace + "/result")),
                    "title": "TraceProof deterministic trace analysis",
                    "description": "Owner-reviewed observations from sanitized agent telemetry.",
                    "start": start,
                    "reviewed-controls": {"control-selections": []},
                    "observations": [
                        {
                            "uuid": str(uuid5(NAMESPACE_URL, namespace + "/" + item["finding_id"])),
                            "title": f"{item['rule_id']}: {item['title']}",
                            "description": item["remediation"],
                            "methods": ["TEST"],
                            "collected": start,
                            "props": [
                                {"name": "traceproof-rule-id", "value": item["rule_id"]},
                                {"name": "traceproof-severity", "value": item["severity"]},
                                {"name": "traceproof-span-id", "value": item["span_id"]},
                            ],
                        }
                        for item in report["findings"]
                    ],
                    "risks": [],
                }
            ],
        }
    }


def demo_otlp_payload() -> dict[str, Any]:
    """Small synthetic fixture with several deliberate, non-sensitive violations."""

    attrs = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.agent.name": "claims-assistant",
        "gen_ai.tool.name": "records.update",
        "dsb.auth.required": True,
        "dsb.auth.decision": "allow",
        "dsb.auth.token_audience": "mcp://records",
        "dsb.auth.resource": "mcp://payments",
        "dsb.auth.requested_scopes": ["records:read", "records:write"],
        "dsb.auth.granted_scopes": ["records:read"],
        "dsb.auth.token_passthrough": True,
        "dsb.approval.required": True,
        "dsb.approval.completed": False,
        "dsb.effect.external": True,
        "dsb.effect.receipt_id": "",
        "gen_ai.prompt": "Synthetic prompt that must not survive redaction",
        "http.request.header.authorization": "Bearer synthetic-do-not-preserve",
    }
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": _otlp_attributes({"service.name": "claims-demo"})},
                "scopeSpans": [
                    {
                        "scope": {"name": "traceproof-demo"},
                        "spans": [
                            {
                                "traceId": "0123456789abcdef0123456789abcdef",
                                "spanId": "0123456789abcdef",
                                "name": "unsafe sensitive production-like name user@example.test",
                                "kind": 3,
                                "startTimeUnixNano": "1000000000",
                                "endTimeUnixNano": "1010000000",
                                "status": {"code": 1},
                                "attributes": _otlp_attributes(attrs),
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _read_source(source: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    if isinstance(source, Mapping):
        raw = json.loads(json.dumps(source, ensure_ascii=False, allow_nan=False))
        return raw, canonical_sha256(raw)
    path = Path(source)
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ValueError(f"trace input exceeds {MAX_FILE_BYTES} byte limit")
        encoded = path.read_bytes()
        raw = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read trace input: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("trace input root must be an object")
    return raw, hashlib.sha256(encoded).hexdigest()


def _iter_spans(raw: Mapping[str, Any]) -> Iterable[tuple[Mapping[str, Any], Any, Any]]:
    resource_spans = raw.get("resourceSpans", raw.get("resource_spans"))
    if isinstance(resource_spans, list):
        for resource_group in resource_spans:
            if not isinstance(resource_group, Mapping):
                continue
            resource = resource_group.get("resource", {})
            scope_spans = resource_group.get("scopeSpans", resource_group.get("scope_spans", []))
            if not isinstance(scope_spans, list):
                continue
            for scope_group in scope_spans:
                if not isinstance(scope_group, Mapping):
                    continue
                scope = scope_group.get("scope", scope_group.get("instrumentationScope", {}))
                for span in scope_group.get("spans", []):
                    if isinstance(span, Mapping):
                        yield span, resource, scope
        return
    spans = raw.get("spans")
    if isinstance(spans, list):
        resource = raw.get("resource", {})
        scope = raw.get("scope", {})
        for span in spans:
            if isinstance(span, Mapping):
                yield span, resource, scope


def _normalize_span(
    span: Mapping[str, Any],
    resource: Any,
    scope: Any,
    policy: Mapping[str, Any],
    salt: str,
    counters: Counter[str],
) -> dict[str, Any]:
    attributes = _attributes(span.get("attributes", {}))
    resource_attrs = _attributes(
        resource.get("attributes", {}) if isinstance(resource, Mapping) else {}
    )
    safe_attrs = _redact_attributes(attributes, policy, salt, counters)
    safe_resource = _redact_attributes(resource_attrs, policy, salt, counters)
    trace_raw = _first(span, "traceId", "trace_id") or "missing-trace-id"
    span_raw = _first(span, "spanId", "span_id") or canonical_sha256(dict(span))[:16]
    parent_raw = _first(span, "parentSpanId", "parent_span_id")
    start = _integer(_first(span, "startTimeUnixNano", "start_time_unix_nano"))
    end = _integer(_first(span, "endTimeUnixNano", "end_time_unix_nano"))
    duration = max(0.0, (end - start) / 1_000_000) if end >= start else 0.0
    raw_name = str(span.get("name", "span"))
    operation = safe_attrs.get("gen_ai.operation.name") or safe_attrs.get("mcp.method.name")
    name = (
        _safe_value(raw_name, int(policy["max_value_chars"]), counters)
        if policy["keep_span_names"]
        else str(operation or "agent.operation")
    )
    events = []
    raw_events = span.get("events", [])
    if isinstance(raw_events, list):
        for event in raw_events[:64]:
            if not isinstance(event, Mapping):
                continue
            event_name = str(event.get("name", "event"))
            if not event_name.startswith(_SAFE_EVENT_PREFIXES):
                event_name = "event"
            events.append(
                {
                    "name": event_name[:128],
                    "attributes": _redact_attributes(
                        _attributes(event.get("attributes", {})), policy, salt, counters
                    ),
                }
            )
    status = span.get("status", {})
    code = status.get("code", "UNSET") if isinstance(status, Mapping) else "UNSET"
    return {
        "trace_id": _pseudonym("trace", trace_raw, salt),
        "span_id": _pseudonym("span", span_raw, salt),
        "parent_span_id": _pseudonym("span", parent_raw, salt) if parent_raw else None,
        "name": name,
        "kind": str(span.get("kind", "UNSPECIFIED")),
        "start_time_unix_nano": start,
        "duration_ms": round(duration, 6),
        "status": str(code),
        "scope": _safe_scope(scope),
        "resource": safe_resource,
        "attributes": safe_attrs,
        "events": events,
    }


def _redact_attributes(
    values: Mapping[str, Any],
    policy: Mapping[str, Any],
    salt: str,
    counters: Counter[str],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    allowed = set(policy["allow_attributes"])
    hashed = set(policy["hash_attributes"])
    dropped = set(policy["drop_attributes"])
    limit = int(policy["max_attributes_per_span"])
    for key, value in list(values.items())[:limit]:
        normalized_key = str(key).strip().lower()
        if _matches_token(normalized_key, _SECRET_TOKENS):
            counters["secret"] += 1
            continue
        if _matches_token(normalized_key, _CONTENT_TOKENS | dropped):
            counters["content"] += 1
            continue
        should_hash = _matches_token(normalized_key, _IDENTITY_TOKENS | hashed)
        is_allowed = normalized_key in allowed or (
            policy["allow_dsb_security_attributes"] and normalized_key.startswith(_DSB_PREFIXES)
        )
        if should_hash:
            result[str(key)] = _pseudonym("attribute", value, salt)
            counters["hashed"] += 1
        elif is_allowed:
            result[str(key)] = _safe_value(value, int(policy["max_value_chars"]), counters)
        else:
            counters["unapproved"] += 1
    if len(values) > limit:
        counters["unapproved"] += len(values) - limit
    return dict(sorted(result.items()))


def _apply_span_rules(
    span: Mapping[str, Any], attrs: Mapping[str, Any], findings: list[dict[str, Any]]
) -> None:
    decision = str(attrs.get("dsb.auth.decision", "")).lower()
    allowed = decision == "allow"
    if _truthy(attrs.get("dsb.auth.required")) and decision not in {"allow", "deny", "review"}:
        findings.append(
            _finding(
                "TP001",
                "high",
                span,
                "Authorization decision is missing",
                {},
                "Record a deny/allow/review decision before the tool boundary.",
            )
        )
    audience = attrs.get("dsb.auth.token_audience")
    resource = attrs.get("dsb.auth.resource")
    if allowed and audience and resource and audience != resource:
        findings.append(
            _finding(
                "TP002",
                "critical",
                span,
                "Allowed token audience does not match the target resource",
                {"token_audience": audience, "resource": resource},
                "Bind and validate the access token for the exact MCP resource.",
            )
        )
    if _truthy(attrs.get("dsb.auth.token_passthrough")):
        findings.append(
            _finding(
                "TP003",
                "critical",
                span,
                "Upstream token passthrough was observed",
                {},
                "Exchange for a resource-bound downstream token; never transit unrelated access tokens.",
            )
        )
    requested = _string_set(attrs.get("dsb.auth.requested_scopes"))
    granted = _string_set(attrs.get("dsb.auth.granted_scopes"))
    if allowed and requested and not requested.issubset(granted):
        findings.append(
            _finding(
                "TP004",
                "high",
                span,
                "Allowed scopes exceed the recorded grant",
                {"requested_scopes": sorted(requested), "granted_scopes": sorted(granted)},
                "Deny or perform an explicit, bounded step-up authorization.",
            )
        )
    approval_required = _truthy(attrs.get("dsb.approval.required"))
    approval_complete = _truthy(attrs.get("dsb.approval.completed"))
    if allowed and approval_required and not approval_complete:
        findings.append(
            _finding(
                "TP005",
                "high",
                span,
                "Sensitive action was allowed without completed approval",
                {},
                "Require approval before executing the external effect.",
            )
        )
    bound = attrs.get("dsb.approval.bound_action_sha256")
    action = attrs.get("dsb.effect.action_sha256")
    if allowed and bound and action and bound != action:
        findings.append(
            _finding(
                "TP006",
                "critical",
                span,
                "Approval is bound to a different action",
                {"approval_target": bound, "effect_target": action},
                "Bind approval to canonical action bytes and reject mismatches.",
            )
        )
    agent = attrs.get("dsb.auth.agent_id")
    grant_agent = attrs.get("dsb.delegation.agent_id")
    if allowed and agent and grant_agent and agent != grant_agent:
        findings.append(
            _finding(
                "TP007",
                "high",
                span,
                "Acting agent differs from the delegated agent",
                {"acting_agent": agent, "delegated_agent": grant_agent},
                "Preserve and validate agent identity across every delegation hop.",
            )
        )
    if allowed and _truthy(attrs.get("dsb.auth.grant_revoked")):
        findings.append(
            _finding(
                "TP008",
                "critical",
                span,
                "A revoked grant was allowed",
                {},
                "Propagate revocation and fail closed before executing the effect.",
            )
        )
    if (
        allowed
        and _truthy(attrs.get("dsb.auth.step_up_required"))
        and not _truthy(attrs.get("dsb.auth.step_up_completed"))
    ):
        findings.append(
            _finding(
                "TP009",
                "high",
                span,
                "An action was allowed before required step-up completed",
                {},
                "Complete bounded step-up authorization before retrying the operation.",
            )
        )
    retries = attrs.get("dsb.auth.retry_count")
    if isinstance(retries, (int, float)) and not isinstance(retries, bool) and retries > 3:
        findings.append(
            _finding(
                "TP011",
                "medium",
                span,
                "Authorization was retried more than three times",
                {"retry_count": retries},
                "Bound retries and treat repeated scope failures as permanent.",
            )
        )
    if _truthy(attrs.get("dsb.effect.external")) and not attrs.get("dsb.effect.receipt_id"):
        findings.append(
            _finding(
                "TP012",
                "high",
                span,
                "External effect has no recorded receipt",
                {},
                "Record a request-bound decision/effect receipt without storing secrets.",
            )
        )


def _finding(
    rule_id: str,
    severity: str,
    span: Mapping[str, Any],
    title: str,
    evidence: Mapping[str, Any],
    remediation: str,
) -> dict[str, Any]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}[severity]
    base = {
        "rule_id": rule_id,
        "severity": severity,
        "trace_id": span["trace_id"],
        "span_id": span["span_id"],
        "title": title,
        "evidence": dict(evidence),
        "remediation": remediation,
    }
    return {"finding_id": canonical_sha256(base)[:24], **base, "severity_rank": rank}


def _report_summary(
    payload: Mapping[str, Any], findings: list[Mapping[str, Any]]
) -> dict[str, Any]:
    current = payload.get("summary")
    trace_count = current.get("trace_count") if isinstance(current, Mapping) else None
    span_count = current.get("span_count") if isinstance(current, Mapping) else None
    severities = Counter(item.get("severity") for item in findings)
    return {
        "trace_count": trace_count,
        "span_count": span_count,
        "finding_count": len(findings),
        "critical": severities["critical"],
        "high": severities["high"],
        "medium": severities["medium"],
        "low": severities["low"],
        "review_required": bool(findings),
    }


def _valid_normalized_span(value: Any) -> bool:
    fields = {
        "trace_id",
        "span_id",
        "parent_span_id",
        "name",
        "kind",
        "start_time_unix_nano",
        "duration_ms",
        "status",
        "scope",
        "resource",
        "attributes",
        "events",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        return False
    if not _pseudonym_digest(value.get("trace_id")) or not _pseudonym_digest(value.get("span_id")):
        return False
    parent = value.get("parent_span_id")
    if parent is not None and not _pseudonym_digest(parent):
        return False
    if not isinstance(value.get("name"), str) or len(value["name"]) > MAX_VALUE_CHARS:
        return False
    if not isinstance(value.get("attributes"), Mapping) or not isinstance(
        value.get("resource"), Mapping
    ):
        return False
    return _json_bounded(value)


def _valid_finding(value: Any) -> bool:
    fields = {
        "finding_id",
        "rule_id",
        "severity",
        "trace_id",
        "span_id",
        "title",
        "evidence",
        "remediation",
    }
    valid = (
        isinstance(value, Mapping)
        and set(value) == fields
        and isinstance(value.get("finding_id"), str)
        and value.get("rule_id") in {item["id"] for item in rule_catalog()}
        and value.get("severity") in {"critical", "high", "medium", "low"}
        and _pseudonym_digest(value.get("trace_id"))
        and _pseudonym_digest(value.get("span_id"))
        and isinstance(value.get("evidence"), Mapping)
        and _json_bounded(value)
    )
    if not valid:
        return False
    unsigned = {key: value[key] for key in fields if key != "finding_id"}
    return value["finding_id"] == canonical_sha256(unsigned)[:24]


def _attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _unwrap_otlp(item) for key, item in value.items()}
    if not isinstance(value, list):
        return {}
    result = {}
    for item in value:
        if isinstance(item, Mapping) and isinstance(item.get("key"), str):
            result[item["key"]] = _unwrap_otlp(item.get("value"))
    return result


def _unwrap_otlp(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return value
    aliases = (
        "stringValue",
        "string_value",
        "boolValue",
        "bool_value",
        "intValue",
        "int_value",
        "doubleValue",
        "double_value",
        "bytesValue",
        "bytes_value",
    )
    for field in aliases:
        if field in value:
            candidate = value[field]
            if field in {"intValue", "int_value"}:
                return _integer(candidate)
            return candidate
    array = value.get("arrayValue", value.get("array_value"))
    if isinstance(array, Mapping):
        return [_unwrap_otlp(item) for item in array.get("values", [])][:64]
    return "[structured-value-removed]"


def _safe_value(value: Any, limit: int, counters: Counter[str]) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value if not isinstance(value, float) or value == value else "invalid-number"
    if isinstance(value, list):
        return [_safe_value(item, limit, counters) for item in value[:64]]
    text = str(value)
    if len(text) > limit:
        counters["truncated"] += 1
        text = text[:limit] + "…"
    return text


def _safe_scope(scope: Any) -> str:
    if not isinstance(scope, Mapping):
        return "unknown"
    name = scope.get("name", "unknown")
    text = str(name)
    return text[:128] if re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", text) else "redacted-scope"


def _matches_token(key: str, tokens: set[str]) -> bool:
    return any(token in key for token in tokens)


def _pseudonym(kind: str, value: Any, salt: str) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(f'{salt}:{kind}:{encoded}'.encode()).hexdigest()}"


def _pseudonym_digest(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _is_digest(value[7:])


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _first(value: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in value:
            return value[key]
    return None


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _string_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {item for item in re.split(r"[\s,]+", value) if item}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_sha256(value)
    except (TypeError, ValueError):
        return None


def _json_bounded(value: Any) -> bool:
    try:
        return len(json.dumps(value, allow_nan=False)) <= 2_000_000
    except (TypeError, ValueError):
        return False


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}[severity]


def _otlp_attributes(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key, value in values.items():
        if isinstance(value, bool):
            wrapped = {"boolValue": value}
        elif isinstance(value, list):
            wrapped = {"arrayValue": {"values": [{"stringValue": str(item)} for item in value]}}
        elif isinstance(value, (int, float)):
            wrapped = {"intValue": str(value)}
        else:
            wrapped = {"stringValue": str(value)}
        result.append({"key": key, "value": wrapped})
    return result
