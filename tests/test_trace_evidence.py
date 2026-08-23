import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.trace.evidence import (
    build_trace_submission_bundle,
    verify_trace_submission_bundle,
)
from dspy_security_bench.trace.mcp import analyze_mcp_authorization
from dspy_security_bench.trace.proof import analyze_trace_evidence, build_trace_evidence


def _attributes(values):
    result = []
    for key, value in values.items():
        if isinstance(value, bool):
            wrapped = {"boolValue": value}
        elif isinstance(value, int):
            wrapped = {"intValue": str(value)}
        else:
            wrapped = {"stringValue": value}
        result.append({"key": key, "value": wrapped})
    return result


def _mcp_payload():
    resource = "https://mcp.example.test/server"
    values = {
        "gen_ai.operation.name": "execute_tool",
        "mcp.method.name": "tools/call",
        "dsb.auth.required": True,
        "dsb.auth.decision": "allow",
        "dsb.auth.resource": resource,
        "dsb.auth.token_audience": resource,
        "dsb.auth.token_passthrough": False,
        "dsb.auth.retry_count": 1,
        "dsb.auth.step_up_required": False,
        "dsb.mcp.transport": "streamable_http",
        "dsb.mcp.resource_indicator_authorization": resource,
        "dsb.mcp.resource_indicator_token": resource,
        "dsb.mcp.token_validated": True,
        "dsb.mcp.protected_resource_metadata": True,
        "dsb.mcp.authorization_server_issuer": "https://identity.example.test",
        "dsb.mcp.token_transport": "authorization_header",
    }
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": _attributes({"service.name": "external-mcp"})},
                "scopeSpans": [
                    {
                        "scope": {"name": "runtime"},
                        "spans": [
                            {
                                "traceId": "a" * 32,
                                "spanId": "b" * 16,
                                "name": "tools/call",
                                "startTimeUnixNano": "1",
                                "endTimeUnixNano": "2",
                                "attributes": _attributes(values),
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_trace_community_bundle_recomputes_nested_evidence():
    evidence = build_trace_evidence(_mcp_payload())
    report = analyze_trace_evidence(evidence)
    mcp_report = analyze_mcp_authorization(evidence)
    bundle = build_trace_submission_bundle(
        evidence,
        report,
        mcp_report=mcp_report,
        submitter="@independent-team",
        runtime="external-mcp-runtime@1.0",
        source_repository_url="https://github.com/example/agent/tree/commit",
    )
    verification = verify_trace_submission_bundle(bundle)
    assert verification.community_eligible
    assert verification.errors == ()
    assert bundle["provenance"]["evidence_tier"] == "self_attested"
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/trace-submission.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(bundle)


def test_trace_community_bundle_rejects_nested_tampering():
    evidence = build_trace_evidence(_mcp_payload())
    report = analyze_trace_evidence(evidence)
    bundle = build_trace_submission_bundle(
        evidence,
        report,
        submitter="@team",
        runtime="runtime@1",
        source_repository_url="https://github.com/example/agent",
    )
    tampered = deepcopy(bundle)
    tampered["report"]["summary"]["finding_count"] = 99
    verification = verify_trace_submission_bundle(tampered)
    assert not verification.community_eligible
    assert verification.errors


def test_trace_community_bundle_requires_timezone_aware_created_at():
    evidence = build_trace_evidence(_mcp_payload())
    report = analyze_trace_evidence(evidence)
    bundle = build_trace_submission_bundle(
        evidence,
        report,
        submitter="@team",
        runtime="runtime@1",
        source_repository_url="https://github.com/example/agent",
    )
    bundle["submission"]["created_at"] = "2026-08-23T12:00:00"
    verification = verify_trace_submission_bundle(bundle)
    assert not verification.community_eligible
    assert any("created_at must include a timezone" in error for error in verification.errors)


def test_maintainer_demo_is_valid_but_not_registry_eligible():
    from dspy_security_bench.trace.proof import demo_otlp_payload

    evidence = build_trace_evidence(demo_otlp_payload())
    report = analyze_trace_evidence(evidence)
    bundle = build_trace_submission_bundle(
        evidence,
        report,
        submitter="@maintainer",
        runtime="synthetic-demo",
        source_repository_url="https://github.com/immu4989/dspy-security-bench",
    )
    verification = verify_trace_submission_bundle(bundle)
    assert not verification.community_eligible
    assert "not registry eligible" in verification.warnings[0]
