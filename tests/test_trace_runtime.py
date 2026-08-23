import json

from dspy_security_bench.agents import AgentResult, BenchTool, ToolCall
from dspy_security_bench.cli import main as root_main
from dspy_security_bench.trace.proof import analyze_trace_evidence, build_trace_evidence
from dspy_security_bench.trace.runtime import (
    TraceRecorder,
    TraceRecordingAgent,
    runtime_doctor,
    runtime_scaffold,
)


class ToolUsingAgent:
    name = "runtime-test-agent"

    def run(self, query, tools, *, system_directive=""):
        result = tools[0](account_id="ACCOUNT-SECRET-42")
        return AgentResult(
            final_answer=f"handled {query}",
            tool_calls=[ToolCall("payment.lookup", {"account_id": "ACCOUNT-SECRET-42"}, result)],
        )


def _context(tool_name, arguments):
    assert arguments["account_id"] == "ACCOUNT-SECRET-42"
    return {
        "dsb.auth.required": True,
        "dsb.auth.decision": "allow",
        "dsb.auth.resource": "https://mcp.example.test/payments",
        "dsb.auth.token_audience": "https://mcp.example.test/payments",
        "dsb.auth.requested_scopes": ["payments:read"],
        "dsb.auth.granted_scopes": ["payments:read"],
        "dsb.auth.token_passthrough": False,
        "dsb.effect.external": False,
    }


def test_runtime_wrapper_records_boundary_metadata_without_content(tmp_path):
    destination = tmp_path / "runtime.json"
    agent = TraceRecordingAgent(
        ToolUsingAgent(), output_path=destination, security_context=_context
    )
    tool = BenchTool(
        name="payment.lookup",
        description="Synthetic lookup",
        parameters={"type": "object"},
        _call=lambda **kwargs: "RESULT-SECRET-99",
    )
    result = agent.run("QUERY-SECRET-11", [tool], system_directive="DIRECTIVE-SECRET-22")
    assert result.final_answer == "handled QUERY-SECRET-11"

    encoded = destination.read_text()
    for secret in (
        "QUERY-SECRET-11",
        "DIRECTIVE-SECRET-22",
        "ACCOUNT-SECRET-42",
        "RESULT-SECRET-99",
    ):
        assert secret not in encoded

    evidence = build_trace_evidence(destination)
    report = analyze_trace_evidence(evidence)
    assert evidence["span_count"] == 2
    assert report["summary"]["finding_count"] == 0


def test_trace_recorder_rejects_application_attributes():
    recorder = TraceRecorder()
    try:
        recorder.record(
            operation="execute_tool",
            agent_name="agent",
            security_attributes={"customer.record": "must-not-enter"},
        )
    except ValueError as exc:
        assert "outside the dsb namespace" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("unbounded runtime attribute was accepted")


def test_runtime_doctor_and_scaffold_never_import_target(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["langchain>=1.3"]\n')
    report = runtime_doctor(tmp_path, framework="langchain")
    assert report["ready"]
    assert report["detected_frameworks"] == ["langchain"]
    assert "no agent" in report["non_execution_claim"]

    source = runtime_scaffold("myapp.agent:build_agent")
    assert "TraceRecordingAgent" in source
    assert "dsb.auth.decision" in source
    assert "unknown" in source
    assert "myapp.agent import build_agent" in source


def test_runtime_cli_lists_doctors_and_scaffolds(tmp_path, capsys):
    assert root_main(["trace", "runtime", "list"]) == 0
    assert "openai-agents" in capsys.readouterr().out

    target = tmp_path / "traceproof_target.py"
    assert (
        root_main(
            [
                "trace",
                "runtime",
                "scaffold",
                "--agent",
                "myapp.agent:build_agent",
                "--out",
                str(target),
            ]
        )
        == 0
    )
    assert target.is_file()
    assert "build_traced_agent" in target.read_text()
    assert root_main(["trace", "runtime", "doctor", "--root", str(tmp_path)]) == 0


def test_runtime_otlp_is_regular_json():
    recorder = TraceRecorder(service_name="safe-service")
    recorder.record(operation="invoke_agent", agent_name="safe-agent")
    assert json.loads(json.dumps(recorder.to_otlp_json()))["resourceSpans"]
