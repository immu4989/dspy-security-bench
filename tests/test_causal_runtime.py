import json
from uuid import UUID

import pytest

from dspy_security_bench.causal.proof import analyze_causality
from dspy_security_bench.causal.runtime import (
    CausalRuntimeSession,
    LangGraphCausalCallback,
    OpenAIAgentsCausalProcessor,
    integration_catalog,
)
from dspy_security_bench.cli import main as root_main


def _grant(event_id="grant"):
    return {
        "id": event_id,
        "kind": "grant",
        "actor": "identity-service",
        "authority_id": "authority-1042",
        "subject": "benefits-agent",
        "resource": "benefits-record-1042",
        "scopes": ["record:update"],
        "audience": "benefits-mcp",
    }


def _exchange(event_id="exchange"):
    return {
        "id": event_id,
        "kind": "token_exchange",
        "actor": "token-service",
        "token_id": "token-1042",
        "authority_id": "authority-1042",
        "subject": "benefits-agent",
        "resource": "benefits-record-1042",
        "scopes": ["record:update"],
        "audience": "benefits-mcp",
    }


def _session(**kwargs):
    return CausalRuntimeSession(
        scenario_id="runtime-benefits-demo",
        title="Fictional runtime benefits authorization",
        description="Synthetic structural runtime fixture; no claimant or production data.",
        invariants=["scope_attenuation", "audience_binding", "identity_binding"],
        **kwargs,
    )


class _FakeOpenAISpan:
    def __init__(self, span_id, *, parent_id=None, started="2026-08-27T12:00:00Z"):
        self.trace_id = "trace_NATIVE_PRIVATE_CORRELATION_ID"
        self.span_id = span_id
        self.parent_id = parent_id
        self.started_at = started
        self.ended_at = "2026-08-27T12:00:01Z"

    @property
    def span_data(self):
        raise AssertionError("CausalProof must never access native span_data")

    @property
    def error(self):
        raise AssertionError("CausalProof must never access native errors")


def test_openai_agents_processor_reads_structure_only_and_builds_ready_graph():
    session = _session()
    processor = OpenAIAgentsCausalProcessor(session)
    grant = _FakeOpenAISpan("span_grant")
    exchange = _FakeOpenAISpan("span_exchange", parent_id="span_grant")
    processor.bind_span(grant, _grant())
    processor.bind_span(exchange, _exchange())
    processor.on_span_end(grant)
    processor.on_span_end(exchange)

    trace, manifest = session.build()
    encoded = json.dumps(trace)
    assert "NATIVE_PRIVATE_CORRELATION_ID" not in encoded
    assert "span_grant" not in encoded
    report = analyze_causality(trace, manifest)
    assert report["summary"]["status"] == "ready"
    assert report["summary"]["observed_parent_edges"] == 1
    assert report["schedule_scenario"]["happens_before"] == [["grant", "exchange"]]


def test_langgraph_callback_ignores_state_and_keeps_graph_guarantee_asserted():
    session = _session(
        asserted_edges=[
            {
                "before": "grant",
                "after": "exchange",
                "rationale": "The compiled graph declares authorize before exchange.",
            }
        ]
    )
    callback = LangGraphCausalCallback(
        session, node_events={"authorize": _grant(), "exchange": _exchange()}
    )
    root = UUID("00000000-0000-0000-0000-000000000001")
    grant = UUID("00000000-0000-0000-0000-000000000002")
    exchange = UUID("00000000-0000-0000-0000-000000000003")
    secret_state = {"messages": ["PRIVATE PROMPT"], "token": "SECRET"}
    callback.on_chain_start(None, secret_state, run_id=root, metadata={})
    callback.on_chain_start(
        None,
        secret_state,
        run_id=grant,
        parent_run_id=root,
        metadata={"langgraph_node": "authorize", "private": secret_state},
    )
    callback.on_chain_end(secret_state, run_id=grant, parent_run_id=root)
    callback.on_chain_start(
        None,
        secret_state,
        run_id=exchange,
        parent_run_id=root,
        metadata={"langgraph_node": "exchange", "private": secret_state},
    )
    callback.on_chain_end(secret_state, run_id=exchange, parent_run_id=root)

    trace, manifest = session.build()
    assert "PRIVATE PROMPT" not in json.dumps(trace)
    assert "SECRET" not in json.dumps(trace)
    report = analyze_causality(trace, manifest)
    assert report["summary"]["status"] == "ready"
    assert report["summary"]["asserted_edges"] == 1
    assert report["summary"]["observed_parent_edges"] == 0


def test_repeated_langgraph_node_requires_explicit_occurrence_factory():
    session = _session()
    callback = LangGraphCausalCallback(session, node_events={"authorize": _grant()})
    callback.on_chain_start(None, {}, run_id="root", metadata={})
    for run in ("one", "two"):
        callback.on_chain_start(
            None,
            {},
            run_id=run,
            parent_run_id="root",
            metadata={"langgraph_node": "authorize"},
        )
        callback.on_chain_end({}, run_id=run, parent_run_id="root")
    with pytest.raises(ValueError, match="occurrence event factory"):
        session.build()


def test_session_detects_conflicting_structure_and_atomic_writes(tmp_path):
    session = _session()
    session.capture_span(
        trace_id="trace", span_id="grant", parent_span_id=None, started_ns=1, ended_ns=2
    )
    session.capture_span(
        trace_id="trace", span_id="exchange", parent_span_id="grant", started_ns=3, ended_ns=4
    )
    session.bind_event(trace_id="trace", span_id="grant", event=_grant())
    session.bind_event(trace_id="trace", span_id="exchange", event=_exchange())
    trace_path, manifest_path = session.write(tmp_path / "trace.json", tmp_path / "manifest.json")
    assert json.loads(trace_path.read_text())["resourceSpans"]
    assert json.loads(manifest_path.read_text())["bindings"]
    with pytest.raises(ValueError, match="conflicting structure"):
        session.capture_span(
            trace_id="trace", span_id="grant", parent_span_id=None, started_ns=1, ended_ns=9
        )


def test_runtime_catalog_and_cli_scaffolds_are_safe_and_non_destructive(tmp_path, capsys):
    assert {item["key"] for item in integration_catalog()} == {"openai-agents", "langgraph"}
    assert root_main(["causal", "integrations"]) == 0
    assert "TracingProcessor" in capsys.readouterr().out
    destination = tmp_path / "causal_bridge.py"
    assert root_main(
        ["causal", "scaffold", "openai-agents", "--out", str(destination)]
    ) == 0
    content = destination.read_text()
    assert "OpenAIAgentsCausalProcessor" in content
    assert "span_data" not in content
    compile(content, str(destination), "exec")
    assert root_main(
        ["causal", "scaffold", "langgraph", "--out", str(destination)]
    ) == 2
    assert destination.read_text() == content
    langgraph = tmp_path / "langgraph_bridge.py"
    assert root_main(
        ["causal", "scaffold", "langgraph", "--out", str(langgraph)]
    ) == 0
    compile(langgraph.read_text(), str(langgraph), "exec")
