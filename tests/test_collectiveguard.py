from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.collective.cli import main
from dspy_security_bench.collective.proof import (
    BUILT_IN_PROFILES,
    analyze_scenario,
    built_in_scenario,
    protocol_payload,
    protocol_sha256,
    validate_scenario,
    verify_collective_report,
)
from dspy_security_bench.collective.sarif import collective_report_to_sarif
from dspy_security_bench.continuous.proof import build_evidence_snapshot, compare_evidence

ROOT = Path(__file__).resolve().parents[1]


def test_protocol_is_content_free_and_content_addressed():
    protocol = protocol_payload()
    assert protocol["protocol_version"] == "collectiveguard-v1"
    assert len(protocol["rules"]) == 13
    assert set(protocol["excluded_content"]) >= {
        "prompts",
        "chain_of_thought",
        "credentials",
        "exploit_payloads",
    }
    assert len(protocol_sha256()) == 64


def test_built_in_scenarios_validate_against_code_and_json_schema():
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/collectiveguard-scenario.schema.json").read_text()
    )
    for scenario in BUILT_IN_PROFILES.values():
        assert validate_scenario(scenario) == ()
        jsonschema.validate(scenario, schema)


def test_hardened_collective_has_no_observed_violation_and_recomputes():
    report = analyze_scenario(built_in_scenario("hardened-collective"))
    assert report["summary"]["status"] == "no_violation_observed"
    assert report["summary"]["finding_count"] == 0
    assert report["summary"]["content_fields_processed"] == 0
    assert report["communication_paths"][0]["communication_allowed"] is True
    assert report["earliest_intervention"] is None
    assert verify_collective_report(report) == ()


def test_emergent_collective_detects_cross_domain_failure_chain():
    report = analyze_scenario(built_in_scenario("emergent-collective"))
    assert report["summary"]["status"] == "violations_detected"
    assert report["summary"]["critical_findings"] == 7
    assert report["summary"]["high_findings"] == 4
    assert report["summary"]["containment_status"] == "late"
    assert {item["rule_id"] for item in report["findings"]} == {
        "CG001",
        "CG003",
        "CG004",
        "CG005",
        "CG006",
        "CG007",
        "CG008",
        "CG009",
        "CG010",
        "CG011",
    }
    assert report["summary"]["intervention_window_seconds"] == 40
    assert report["earliest_intervention"]["event_id"] == "side-read"


def test_rapid_containment_does_not_erase_the_boundary_violation():
    report = analyze_scenario(built_in_scenario("rapid-containment"))
    assert report["summary"]["finding_count"] == 1
    assert report["findings"][0]["rule_id"] == "CG001"
    assert report["summary"]["containment_status"] == "timely"
    assert report["response_windows"][0]["evidence_status"] == "timely"


def test_channel_access_policy_is_independent_from_shared_service_access():
    scenario = built_in_scenario("rapid-containment")
    scenario["runs"][1]["allowed_channel_ids"].remove("artifact-channel")
    report = analyze_scenario(scenario)
    assert {item["rule_id"] for item in report["findings"]} >= {"CG001", "CG002"}


def test_peer_message_never_confers_authority_without_approved_issuer():
    scenario = built_in_scenario("hardened-collective")
    decision = next(item for item in scenario["events"] if item["kind"] == "authority_decision")
    decision["issuer_id"] = "eval-a"
    report = analyze_scenario(scenario)
    assert "CG004" in {item["rule_id"] for item in report["findings"]}


def test_authority_issuer_must_match_the_decision_actor():
    scenario = built_in_scenario("hardened-collective")
    decision = next(item for item in scenario["events"] if item["kind"] == "authority_decision")
    decision["actor_id"] = "eval-a"
    report = analyze_scenario(scenario)
    assert "CG004" in {item["rule_id"] for item in report["findings"]}


def test_unapproved_response_actor_cannot_satisfy_containment_window():
    scenario = built_in_scenario("rapid-containment")
    pause = next(
        item
        for item in scenario["events"]
        if item["kind"] == "response_action" and item["action"] == "isolate_run"
    )
    pause["actor_id"] = "eval-a"
    report = analyze_scenario(scenario)
    assert report["summary"]["containment_status"] == "missing"
    assert "CG009" in {item["rule_id"] for item in report["findings"]}


def test_impossible_task_budget_is_enforced_structurally():
    scenario = built_in_scenario("hardened-collective")
    scenario["events"].insert(
        0,
        {
            "id": "impossible",
            "kind": "task_state",
            "offset_seconds": 0,
            "actor_id": "runtime",
            "run_id": "eval-a",
            "state": "impossible",
            "reason_code": "fixture-broken",
        },
    )
    report = analyze_scenario(scenario)
    finding = next(item for item in report["findings"] if item["rule_id"] == "CG007")
    assert finding["evidence_event_ids"] == ["impossible", "approved-note"]


def test_control_independence_and_runtime_collapse_are_separate_findings():
    scenario = built_in_scenario("hardened-collective")
    network_controls = [
        item for item in scenario["controls"] if item["objective"] == "network_egress"
    ]
    network_controls[1]["failure_domain"] = network_controls[0]["failure_domain"]
    for index, control in enumerate(network_controls):
        scenario["events"].append(
            {
                "id": f"failure-{index}",
                "kind": "control_failure",
                "offset_seconds": 30 + index,
                "actor_id": "monitor",
                "control_id": control["control_id"],
                "failure_mode": "unavailable",
            }
        )
    report = analyze_scenario(scenario)
    assert {item["rule_id"] for item in report["findings"]} >= {"CG012", "CG013"}
    coverage = next(
        item for item in report["control_coverage"] if item["objective"] == "network_egress"
    )
    assert coverage["coverage_status"] == "review_required"
    assert coverage["runtime_status"] == "collapsed"


def test_restart_requires_a_matching_prior_recovery_decision():
    scenario = built_in_scenario("rapid-containment")
    scenario["events"].extend(
        [
            {
                "id": "restart-approval",
                "kind": "response_action",
                "offset_seconds": 80,
                "actor_id": "operator",
                "action": "approve_restart",
                "target_id": "eval-b",
                "decision_id": "recovery-1",
                "authorized": True,
            },
            {
                "id": "restart",
                "kind": "response_action",
                "offset_seconds": 90,
                "actor_id": "runtime",
                "action": "restart",
                "target_id": "eval-b",
                "decision_id": "recovery-1",
                "authorized": True,
            },
        ]
    )
    report = analyze_scenario(scenario)
    assert "CG011" not in {item["rule_id"] for item in report["findings"]}


def test_scenario_rejects_content_and_unknown_references():
    scenario = built_in_scenario("hardened-collective")
    scenario["events"][0]["prompt"] = "must never enter the protocol"
    errors = validate_scenario(scenario)
    assert any("fields do not match" in item for item in errors)

    scenario = built_in_scenario("hardened-collective")
    effect = next(item for item in scenario["events"] if item["kind"] == "effect")
    effect["cause_event_id"] = "missing"
    assert any("unknown event" in item for item in validate_scenario(scenario))


def test_report_tampering_is_detected_and_schema_validates():
    report = analyze_scenario(built_in_scenario("rapid-containment"))
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/collectiveguard-report.schema.json").read_text()
    )
    jsonschema.validate(report, schema)
    tampered = deepcopy(report)
    tampered["summary"]["finding_count"] = 0
    errors = verify_collective_report(tampered)
    assert "report_sha256 does not match canonical report content" in errors
    assert "summary does not recompute" in errors


def test_sarif_preserves_structural_evidence_without_content():
    report = analyze_scenario(built_in_scenario("emergent-collective"))
    sarif = collective_report_to_sarif(report)
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"].endswith("CollectiveGuard")
    assert len(run["results"]) == report["summary"]["finding_count"]
    assert run["properties"]["contentFieldsProcessed"] == 0
    serialized = json.dumps(sarif)
    assert "chain_of_thought" not in serialized
    assert "tool_arguments" not in serialized


def test_continuousproof_tracks_collectiveguard_regression():
    baseline_report = analyze_scenario(built_in_scenario("hardened-collective"))
    candidate_report = analyze_scenario(built_in_scenario("rapid-containment"))
    baseline = build_evidence_snapshot(baseline_report, label="before")
    candidate = build_evidence_snapshot(candidate_report, label="after")
    drift = compare_evidence(baseline, candidate)
    assert baseline["evidence_kind"] == "collective"
    assert drift["status"] == "review"
    finding = next(
        item for item in drift["metric_changes"] if item["metric"] == "summary.critical_findings"
    )
    assert finding["threshold_exceeded"] is True


def test_cli_demo_run_verify_and_gates(tmp_path, capsys):
    assert umbrella_main(["collective", "demo"]) == 0
    assert "emergent-collective: violations_detected" in capsys.readouterr().out

    scenario_path = tmp_path / "scenario.json"
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif.json"
    scenario_path.write_text(json.dumps(built_in_scenario("rapid-containment")))
    assert (
        main(
            [
                "run",
                str(scenario_path),
                "--json-out",
                str(report_path),
                "--sarif-out",
                str(sarif_path),
            ]
        )
        == 0
    )
    assert main(["verify", str(report_path)]) == 0
    assert main(["run", str(scenario_path), "--fail-on-findings"]) == 1
    assert main(["run", str(scenario_path), "--require-timely-containment"]) == 0
    assert sarif_path.is_file()


def test_cli_init_is_non_destructive(tmp_path):
    path = tmp_path / "collective.json"
    assert main(["init", "--out", str(path)]) == 0
    original = path.read_text()
    assert main(["init", "--out", str(path)]) == 2
    assert path.read_text() == original
    assert main(["init", "--out", str(path), "--force"]) == 0
