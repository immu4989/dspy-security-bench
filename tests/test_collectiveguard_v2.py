from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.collective.bridge import (
    bridge_manifest_from_v2,
    build_v2_scenario,
)
from dspy_security_bench.collective.profiles import (
    assess_profile,
    built_in_profile,
    export_oscal,
)
from dspy_security_bench.collective.registry import (
    build_collective_submission_bundle,
    verify_collective_submission_bundle,
)
from dspy_security_bench.collective.v2 import (
    BUILT_IN_PROFILES,
    analyze_scenario_v2,
    built_in_scenario_v2,
    validate_scenario,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]


def test_v2_fixtures_cover_all_three_defensible_outcomes():
    statuses = {
        name: analyze_scenario_v2(scenario)["summary"]["status"]
        for name, scenario in BUILT_IN_PROFILES.items()
    }
    assert statuses == {
        "hardened-complete": "no_violation_observed",
        "hardened-partial": "insufficient_evidence",
        "emergent-complete": "violations_detected",
    }


def test_v2_scenarios_and_reports_validate_and_recompute():
    scenario_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/collectiveguard-v2-scenario.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/collectiveguard-v2-report.schema.json").read_text()
    )
    for scenario in BUILT_IN_PROFILES.values():
        assert validate_scenario(scenario) == ()
        jsonschema.validate(scenario, scenario_schema)
        report = analyze_scenario_v2(scenario)
        jsonschema.validate(report, report_schema)
        assert verify_report(report) == ()


def test_clean_claim_fails_closed_when_event_is_asserted_only():
    scenario = built_in_scenario_v2("hardened-complete")
    scenario["event_bindings"][0]["provenance"] = "asserted"
    report = analyze_scenario_v2(scenario)
    assert report["summary"]["status"] == "insufficient_evidence"
    assert "CGV204" in {item["rule_id"] for item in report["diagnostics"]}


def test_owner_can_require_attested_provenance_for_every_clean_event():
    scenario = built_in_scenario_v2("hardened-complete")
    scenario["evidence_policy"]["clean_result_minimum_provenance"] = "attested"
    report = analyze_scenario_v2(scenario)
    assert report["summary"]["all_events_directly_supported"] is True
    assert report["summary"]["all_events_meet_clean_policy"] is False
    assert report["summary"]["status"] == "insufficient_evidence"


def test_findings_survive_incomplete_provenance_without_becoming_clean():
    scenario = built_in_scenario_v2("emergent-complete")
    scenario["event_bindings"] = scenario["event_bindings"][1:]
    report = analyze_scenario_v2(scenario)
    assert report["summary"]["status"] == "violations_detected"
    assert report["summary"]["finding_count"] > 0
    assert "CGV203" in {item["rule_id"] for item in report["diagnostics"]}


def test_evidence_bridge_round_trips_without_content_fields():
    scenario = built_in_scenario_v2("hardened-complete")
    manifest = bridge_manifest_from_v2(scenario, adapter_profile="runtime-neutral-json")
    bridge_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/evidencebridge.schema.json").read_text()
    )
    jsonschema.validate(manifest, bridge_schema)
    assert build_v2_scenario(manifest) == scenario
    serialized = json.dumps(manifest).lower()
    for forbidden in ("chain_of_thought", "tool_arguments", "tool_results", "credentials"):
        assert forbidden not in serialized


def test_registry_bundle_recomputes_and_marks_partial_evidence_ineligible():
    complete = build_collective_submission_bundle(
        built_in_scenario_v2("hardened-complete"),
        submitter="test-owner",
        runtime="reference-runtime",
        source_repository="https://github.com/example/runtime",
        deployment_class="synthetic",
        created_at="2026-08-29",
    )
    assert verify_collective_submission_bundle(complete).community_eligible is True
    partial = build_collective_submission_bundle(
        built_in_scenario_v2("hardened-partial"),
        submitter="test-owner",
        runtime="reference-runtime",
        source_repository="https://github.com/example/runtime",
        deployment_class="synthetic",
        created_at="2026-08-29",
    )
    result = verify_collective_submission_bundle(partial)
    assert not result.errors
    assert result.warnings
    assert result.community_eligible is False


def test_profile_assessment_and_oscal_are_informative_not_certifying():
    report = analyze_scenario_v2(built_in_scenario_v2("hardened-complete"))
    enterprise = assess_profile(report, built_in_profile("enterprise"))
    assert enterprise["summary"]["status"] == "profile_objectives_observed"
    federal = assess_profile(report, built_in_profile("federal-high-impact"))
    assessment_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/collective-profile-assessment.schema.json").read_text()
    )
    jsonschema.validate(federal, assessment_schema)
    assert federal["summary"]["status"] == "review_required"
    oscal = export_oscal(federal)
    props = oscal["assessment-results"]["metadata"]["props"]
    assert {item["name"]: item["value"] for item in props}["non-certifying"] == "true"


def test_v2_report_tampering_is_detected():
    report = analyze_scenario_v2(built_in_scenario_v2("hardened-complete"))
    tampered = deepcopy(report)
    tampered["summary"]["status"] = "violations_detected"
    assert verify_report(tampered)


def test_v2_cli_demo_and_round_trip(tmp_path, capsys):
    scenario = tmp_path / "scenario.json"
    report = tmp_path / "report.json"
    assert (
        umbrella_main(
            [
                "collective",
                "plane",
                "init",
                "--profile",
                "hardened-complete",
                "--out",
                str(scenario),
            ]
        )
        == 0
    )
    assert (
        umbrella_main(["collective", "plane", "run", str(scenario), "--json-out", str(report)]) == 0
    )
    assert umbrella_main(["collective", "plane", "verify", str(report)]) == 0
    assert "no_violation_observed" in capsys.readouterr().out
