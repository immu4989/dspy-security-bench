import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.authority.adapter import (
    build_ambient_authority_adapter,
    build_bounded_authority_adapter,
)
from dspy_security_bench.cli import main as root_main
from dspy_security_bench.graph.benchmark import run_agent_graph_twin, verify_graph_report


def test_bounded_graph_resists_all_synthetic_attacks():
    report = run_agent_graph_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    )
    assert report["summary"] == {
        "pair_count": 6,
        "attack_resistance": 1.0,
        "clean_mission_utility": 1.0,
        "harm_containment": 1.0,
        "receipt_integrity": 1.0,
        "total_unsafe_effects": 0,
    }
    assert verify_graph_report(report) == ()
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/agent-graph-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_ambient_graph_exposes_first_unsafe_edge_and_blast_radius():
    report = run_agent_graph_twin(
        build_ambient_authority_adapter(), adapter_factory=build_ambient_authority_adapter
    )
    assert report["summary"]["total_unsafe_effects"] == 6
    assert all(pair["first_unsafe_edge"] for pair in report["pairs"])
    assert verify_graph_report(report) == ()


def test_graph_verifier_rejects_metric_tampering():
    report = run_agent_graph_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    )
    tampered = deepcopy(report)
    tampered["summary"]["attack_resistance"] = 0.0
    errors = verify_graph_report(tampered)
    assert "summary does not recompute from pairs" in errors
    assert "report_sha256 does not match canonical report content" in errors


def test_graph_verifier_rejects_rehashed_metadata_and_extra_claims():
    report = run_agent_graph_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    )
    report["pairs"][0]["title"] = "unfrozen title"
    report["unsupported_claim"] = "certified"
    report.pop("report_sha256")
    from dspy_security_bench.mission.loader import canonical_sha256

    report["report_sha256"] = canonical_sha256(report)
    errors = verify_graph_report(report)
    assert "report fields are incomplete or unsupported" in errors
    assert any("title does not match protocol" in error for error in errors)


def test_graph_cli_round_trip(tmp_path):
    path = tmp_path / "graph.json"
    assert root_main(["graph", "run", "--reference", "bounded", "--json-out", str(path)]) == 0
    assert root_main(["graph", "verify", str(path)]) == 0
    assert json.loads(path.read_text())["summary"]["pair_count"] == 6
