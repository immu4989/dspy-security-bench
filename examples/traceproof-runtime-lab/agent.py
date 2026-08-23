"""Fictional dependency-free agent boundary for the TraceProof reference lab."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

RESOURCE = "https://mcp.example.test/records"


def post_json(url: str, payload: dict, *, attempts: int = 20) -> dict:
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                body = response.read()
            return json.loads(body) if body else {}
        except (OSError, urllib.error.URLError):
            if attempt == attempts - 1:
                raise
            time.sleep(0.25)
    raise RuntimeError("bounded retry loop exhausted")


def otlp_attributes(values: dict) -> list[dict]:
    result = []
    for key, value in values.items():
        if isinstance(value, bool):
            wrapped = {"boolValue": value}
        elif isinstance(value, int):
            wrapped = {"intValue": str(value)}
        elif isinstance(value, list):
            wrapped = {"arrayValue": {"values": [{"stringValue": item} for item in value]}}
        else:
            wrapped = {"stringValue": value}
        result.append({"key": key, "value": wrapped})
    return result


def main() -> None:
    authority_request = {
        "principal": "synthetic-reviewer",
        "agent": "records-assistant",
        "resource": RESOURCE,
        "scopes": ["records:read"],
    }
    decision = post_json(os.environ["OPA_URL"], {"input": authority_request})["result"]
    now = time.time_ns()
    attributes = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.agent.name": "records-assistant",
        "gen_ai.tool.name": "records.lookup",
        "mcp.method.name": "tools/call",
        "dsb.auth.required": True,
        "dsb.auth.decision": "allow" if decision["allow"] else "deny",
        "dsb.auth.resource": RESOURCE,
        "dsb.auth.token_audience": RESOURCE,
        "dsb.auth.requested_scopes": ["records:read"],
        "dsb.auth.granted_scopes": ["records:read"],
        "dsb.auth.token_passthrough": False,
        "dsb.auth.retry_count": 0,
        "dsb.auth.step_up_required": False,
        "dsb.auth.step_up_completed": False,
        "dsb.effect.external": False,
        "dsb.mcp.transport": "streamable_http",
        "dsb.mcp.resource_indicator_authorization": RESOURCE,
        "dsb.mcp.resource_indicator_token": RESOURCE,
        "dsb.mcp.token_validated": True,
        "dsb.mcp.protected_resource_metadata": True,
        "dsb.mcp.authorization_server_issuer": "https://identity.example.test",
        "dsb.mcp.token_transport": "authorization_header",
    }
    payload = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": otlp_attributes(
                        {"service.name": "traceproof-reference-lab"}
                    )
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "traceproof.reference.lab", "version": "1"},
                        "spans": [
                            {
                                "traceId": "5a0f15d5a0f15d5a0f15d5a0f15d5a0f",
                                "spanId": "5a0f15d5a0f15d5a",
                                "name": "execute_tool",
                                "kind": 3,
                                "startTimeUnixNano": str(now),
                                "endTimeUnixNano": str(now + 1_000_000),
                                "status": {"code": 1 if decision["allow"] else 2},
                                "attributes": otlp_attributes(attributes),
                            }
                        ],
                    }
                ],
            }
        ]
    }
    post_json(os.environ["OTLP_HTTP_URL"], payload)
    time.sleep(2)
    print("synthetic OPA decision and content-free OTLP span emitted")


if __name__ == "__main__":
    main()
