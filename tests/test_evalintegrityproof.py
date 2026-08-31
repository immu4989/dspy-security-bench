from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.evalguard.cli import main as evalguard_main
from dspy_security_bench.evalguard.proof import (
    BUILT_IN_PROFILES,
    CLAIM_BOUNDARY,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    seal_scenario,
    validate_scenario,
    verify_report,
)
from dspy_security_bench.evalguard.sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


def test_reference_run_evidences_thirteen_independent_integrity_controls():
    report = analyze_scenario(built_in_scenario())
    assert report["summary"]["status"] == "integrity_evidenced"
    assert report["summary"]["control_count"] == 13
    assert report["summary"]["control_status_counts"] == {
        "evidenced": 13,
        "violation_observed": 0,
        "monitor_failed": 0,
        "incomplete_evidence": 0,
    }
    assert report["summary"]["result_committed_before_label_reveal"] is True
    assert report["summary"]["all_cases_accounted_for"] is True
    assert report["summary"]["automatic_actions"] == 0
    assert verify_report(report) == ()


def test_leakage_monitor_failure_and_incomplete_evidence_are_not_blended():
    outcomes = {
        profile: analyze_scenario(built_in_scenario(profile))["summary"]["status"]
        for profile in BUILT_IN_PROFILES
    }
    assert outcomes == {
        "integrity-reference": "integrity_evidenced",
        "label-leakage": "integrity_violated",
        "monitor-gap": "monitor_failed",
        "incomplete-record": "incomplete_evidence",
    }
    leakage = analyze_scenario(built_in_scenario("label-leakage"))
    result = next(item for item in leakage["control_results"] if item["control_id"] == "EI009")
    assert result["status"] == "violation_observed"
    assert leakage["summary"]["leakage_canary_hits"] == 2


def test_commit_reveal_case_accounting_and_content_minimization_are_enforced():
    scenario = built_in_scenario()
    scenario["run"]["labels_revealed_at"] = "2026-08-30T18:19:00Z"
    scenario["run"]["case_count_safe_stopped"] = 1
    scenario["execution"]["raw_outputs_embedded"] = True
    report = analyze_scenario(seal_scenario(scenario))
    by_id = {item["control_id"]: item for item in report["control_results"]}
    assert by_id["EI003"]["status"] == "violation_observed"
    assert by_id["EI008"]["status"] == "violation_observed"
    assert by_id["EI012"]["status"] == "violation_observed"


def test_scenario_rejects_active_access_extensions_and_tampering():
    scenario = built_in_scenario()
    scenario["execution"]["network_actions_performed"] = True
    scenario = seal_scenario(scenario)
    assert "execution.network_actions_performed must be false" in validate_scenario(scenario)

    extended = built_in_scenario()
    extended["raw_holdout"] = "not allowed"
    extended = seal_scenario(extended)
    assert any("unsupported fields" in item for item in validate_scenario(extended))

    tampered = built_in_scenario()
    tampered["title"] = "changed after sealing"
    assert "scenario_sha256 does not recompute" in validate_scenario(tampered)


def test_rehashed_report_tampering_fails_semantic_recomputation():
    report = analyze_scenario(built_in_scenario())
    report["summary"]["status"] = "integrity_violated"
    report.pop("report_sha256")
    report["report_sha256"] = canonical_sha256(report)
    assert "EvalIntegrityProof report does not recompute exactly" in verify_report(report)


def test_schema_sarif_protocol_and_cli_demo(tmp_path):
    scenario = built_in_scenario()
    report = analyze_scenario(scenario)
    scenario_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/evalintegrityproof-scenario.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/evalintegrityproof-report.schema.json").read_text()
    )
    registry = Registry().with_resource(
        scenario_schema["$id"], Resource.from_contents(scenario_schema)
    )
    jsonschema.Draft202012Validator(scenario_schema).validate(scenario)
    jsonschema.Draft202012Validator(report_schema, registry=registry).validate(report)
    assert report_to_sarif(report)["runs"][0]["results"] == []
    violated = report_to_sarif(analyze_scenario(built_in_scenario("label-leakage")))
    assert any(item["level"] == "error" for item in violated["runs"][0]["results"])
    protocol = protocol_payload()
    assert protocol["automatic_actions"] == 0
    assert protocol["claim_boundary"] == CLAIM_BOUNDARY

    demo = tmp_path / "evalguard"
    assert evalguard_main(["demo", "--out-dir", str(demo)]) == 0
    report_path = demo / "integrity-reference.report.json"
    assert report_path.is_file()
    assert evalguard_main(["verify", str(report_path)]) == 0


def test_umbrella_cli_exposes_evalguard(capsys):
    from dspy_security_bench.cli import main

    assert main(["evalguard", "describe"]) == 0
    assert "EvalIntegrityProof v1" in capsys.readouterr().out


def test_continuousproof_accepts_only_semantically_verified_eval_integrity():
    report = analyze_scenario(built_in_scenario())
    snapshot = build_evidence_snapshot(report, label="evaluation-integrity-baseline")
    assert snapshot["evidence_kind"] == "evaluation-integrity"
    assert snapshot["identity"]["protocol_sha256"] == report["protocol_sha256"]

    report["summary"]["leakage_canary_hits"] = 99
    try:
        build_evidence_snapshot(report, label="tampered")
    except ValueError as exc:
        assert "does not recompute" in str(exc)
    else:
        raise AssertionError("ContinuousProof accepted a tampered integrity report")
