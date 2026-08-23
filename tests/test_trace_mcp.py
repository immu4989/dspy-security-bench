import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.trace.mcp import (
    analyze_mcp_authorization,
    verify_mcp_authorization_report,
)
from dspy_security_bench.trace.proof import build_trace_evidence


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


def _mcp_payload(**overrides):
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
        "dsb.auth.step_up_completed": False,
        "dsb.mcp.transport": "streamable_http",
        "dsb.mcp.resource_indicator_authorization": resource,
        "dsb.mcp.resource_indicator_token": resource,
        "dsb.mcp.token_validated": True,
        "dsb.mcp.protected_resource_metadata": True,
        "dsb.mcp.authorization_server_issuer": "https://identity.example.test",
        "dsb.mcp.token_transport": "authorization_header",
    }
    values.update(overrides)
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


def test_mcp_probe_passes_complete_declared_http_evidence():
    evidence = build_trace_evidence(_mcp_payload())
    report = analyze_mcp_authorization(evidence)
    assert report["specification_revision"] == "2025-11-25"
    assert report["summary"]["required_pass_count"] == 7
    assert report["summary"]["conformance_ready"] is True
    assert report["summary"]["review_required"] is False
    assert verify_mcp_authorization_report(report, evidence) == ()
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/trace-mcp-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_mcp_probe_separates_failure_from_missing_observation():
    evidence = build_trace_evidence(
        _mcp_payload(
            **{
                "dsb.auth.token_passthrough": True,
                "dsb.mcp.token_transport": "query_string",
                "dsb.mcp.authorization_server_issuer": "",
            }
        )
    )
    report = analyze_mcp_authorization(evidence)
    statuses = {item["id"]: item["status"] for item in report["checks"]}
    assert statuses["MCP-AUTH-004"] == "fail"
    assert statuses["MCP-AUTH-006"] == "not_observed"
    assert statuses["MCP-AUTH-007"] == "fail"
    assert report["summary"]["conformance_ready"] is False
    assert report["summary"]["review_required"] is True


def test_mcp_probe_verifier_rejects_tampering():
    evidence = build_trace_evidence(_mcp_payload())
    report = analyze_mcp_authorization(evidence)
    tampered = deepcopy(report)
    tampered["summary"]["conformance_ready"] = False
    errors = verify_mcp_authorization_report(tampered, evidence)
    assert "MCP authorization summary does not recompute" in errors
    assert "MCP probe report_sha256 does not match canonical content" in errors


def test_mcp_probe_verifier_rejects_malformed_pseudonym():
    evidence = build_trace_evidence(_mcp_payload())
    report = analyze_mcp_authorization(evidence)
    report["observations"][0]["trace_id"] = "sha256:short"
    assert "MCP probe observations are invalid" in verify_mcp_authorization_report(report)


def test_mcp_cli_analyzes_and_verifies(tmp_path):
    evidence = build_trace_evidence(_mcp_payload())
    evidence_path = tmp_path / "evidence.json"
    report_path = tmp_path / "mcp.json"
    evidence_path.write_text(json.dumps(evidence))
    assert (
        root_main(
            [
                "trace",
                "mcp",
                "analyze",
                str(evidence_path),
                "--out",
                str(report_path),
            ]
        )
        == 0
    )
    assert (
        root_main(
            [
                "trace",
                "mcp",
                "verify",
                str(report_path),
                "--evidence",
                str(evidence_path),
            ]
        )
        == 0
    )
