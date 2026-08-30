from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from dspy_security_bench.containment.cli import main as containment_main
from dspy_security_bench.containment.proof import (
    BUILT_IN_PROFILES,
    CLAIM_BOUNDARY,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    seal_scenario,
    validate_scenario,
    verify_report,
)
from dspy_security_bench.containment.sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


def test_hardened_reference_preserves_eight_separate_containment_controls():
    report = analyze_scenario(built_in_scenario("hardened-reference"))
    assert report["summary"]["status"] == "contained"
    assert report["summary"]["probe_count"] == 8
    assert report["summary"]["probe_status_counts"] == {
        "contained": 8,
        "violation_observed": 0,
        "monitor_failed": 0,
        "incomplete_evidence": 0,
    }
    assert report["summary"]["safe_stop_observed"] is True
    assert report["summary"]["human_pause_effective"] is True
    assert report["summary"]["restart_authorized"] is True
    assert report["summary"]["automatic_shutdown_actions"] == 0
    assert verify_report(report) == ()


def test_violation_monitor_failure_and_missing_evidence_are_not_blended():
    outcomes = {
        profile: analyze_scenario(built_in_scenario(profile))["summary"]["status"]
        for profile in BUILT_IN_PROFILES
    }
    assert outcomes == {
        "hardened-reference": "contained",
        "egress-violation": "containment_violated",
        "monitor-gap": "monitor_failed",
        "incomplete-record": "incomplete_evidence",
    }
    violation = analyze_scenario(built_in_scenario("egress-violation"))
    egress = next(
        item for item in violation["probe_results"] if item["probe_id"] == "network-egress"
    )
    assert egress["status"] == "violation_observed"
    assert egress["observed"]["canary_triggered"] is True


def test_scenario_rejects_live_access_extensions_and_tampering():
    scenario = built_in_scenario()
    scenario["environment"]["production_access"] = True
    scenario = seal_scenario(scenario)
    assert "environment.production_access must be false" in validate_scenario(scenario)

    extended = built_in_scenario()
    extended["exploit_payload"] = "not-allowed"
    extended = seal_scenario(extended)
    assert any("unsupported fields" in item for item in validate_scenario(extended))

    tampered = built_in_scenario()
    tampered["title"] = "changed after sealing"
    assert "scenario_sha256 does not recompute" in validate_scenario(tampered)


def test_report_semantic_recomputation_detects_rehashed_tampering():
    report = analyze_scenario(built_in_scenario())
    report["summary"]["status"] = "containment_violated"
    report.pop("report_sha256")
    report["report_sha256"] = canonical_sha256(report)
    assert "ContainmentProof report does not recompute exactly" in verify_report(report)


def test_schema_sarif_protocol_and_cli_demo(tmp_path):
    scenario = built_in_scenario()
    report = analyze_scenario(scenario)
    scenario_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/containmentproof-scenario.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/containmentproof-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(scenario_schema).validate(scenario)
    jsonschema.Draft202012Validator(report_schema).validate(report)
    assert report_to_sarif(report)["runs"][0]["results"] == []
    violated_sarif = report_to_sarif(analyze_scenario(built_in_scenario("egress-violation")))
    assert violated_sarif["runs"][0]["results"][0]["level"] == "error"
    protocol = protocol_payload()
    assert protocol["automatic_actions"] == 0
    assert protocol["claim_boundary"] == CLAIM_BOUNDARY

    demo = tmp_path / "containment"
    assert containment_main(["demo", "--out-dir", str(demo)]) == 0
    report_path = demo / "hardened-reference.report.json"
    assert report_path.is_file()
    assert containment_main(["verify", str(report_path)]) == 0
