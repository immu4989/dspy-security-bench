import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.graph.v2 import (
    build_ambient_temporal_graph_adapter,
    build_bounded_temporal_graph_adapter,
    run_agent_graph_twin_v2,
    verify_agent_graph_twin_v2,
)


def test_agentgraphtwin_v2_distinguishes_bounded_and_ambient_authority():
    bounded = run_agent_graph_twin_v2(
        build_bounded_temporal_graph_adapter(), adapter_factory=build_bounded_temporal_graph_adapter
    )
    ambient = run_agent_graph_twin_v2(
        build_ambient_temporal_graph_adapter(), adapter_factory=build_ambient_temporal_graph_adapter
    )
    assert bounded["summary"]["attack_resistance"] == 1.0
    assert bounded["summary"]["clean_mission_utility"] == 1.0
    assert bounded["summary"]["total_unsafe_effects"] == 0
    assert ambient["summary"]["attack_resistance"] == 0.0
    assert ambient["summary"]["clean_mission_utility"] == 1.0
    assert ambient["summary"]["total_unsafe_effects"] == 6
    assert verify_agent_graph_twin_v2(bounded) == ()
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas/agent-graph-v2-report.schema.json")
        .read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(bounded)


def test_agentgraphtwin_v2_rejects_semantic_tampering():
    report = run_agent_graph_twin_v2(
        build_bounded_temporal_graph_adapter(), adapter_factory=build_bounded_temporal_graph_adapter
    )
    tampered = deepcopy(report)
    tampered["pairs"][0]["injected"]["unsafe_effects"] = 9
    errors = verify_agent_graph_twin_v2(tampered)
    assert "report_sha256 does not match canonical report content" in errors
    assert any("does not recompute" in error for error in errors)


def test_agentgraphtwin_v2_cli_round_trip(tmp_path):
    report = tmp_path / "graph-v2.json"
    assert root_main(["graph", "v2-run", "--reference", "bounded", "--json-out", str(report)]) == 0
    assert root_main(["graph", "v2-verify", str(report)]) == 0
