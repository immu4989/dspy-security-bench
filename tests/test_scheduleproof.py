import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.schedule.proof import (
    analyze_scenario,
    built_in_scenario,
    validate_scenario,
    verify_schedule_report,
)
from dspy_security_bench.schedule.sarif import schedule_report_to_sarif


def test_hardened_profile_exhaustively_checks_every_reachable_schedule():
    report = analyze_scenario(built_in_scenario("hardened-payment"))
    assert report["summary"]["status"] == "bounded_safe"
    assert report["summary"]["complete_exploration"] is True
    assert report["summary"]["reachable_schedule_count"] > 1
    assert report["summary"]["unsafe_schedules"] == 0
    assert report["minimal_counterexample"] is None
    assert verify_schedule_report(report) == ()


def test_revocation_race_produces_minimal_causal_counterexample():
    report = analyze_scenario(built_in_scenario("revocation-race"))
    assert report["summary"]["status"] == "unsafe"
    assert 0 < report["summary"]["unsafe_schedules"] < report["summary"]["schedules_explored"]
    counterexample = report["minimal_counterexample"]
    assert counterexample["violation_id"] == "SP001"
    assert counterexample["event_id"] == "commit-a"
    assert "revoke" in counterexample["causal_event_ids"]
    assert counterexample["schedule_prefix"][-1] == "commit-a"


def test_token_and_parallel_approval_races_are_distinct_failure_classes():
    token = analyze_scenario(built_in_scenario("token-race"))
    replay = analyze_scenario(built_in_scenario("approval-replay"))
    assert {item["violation_id"] for item in token["counterexamples"]} == {"SP004"}
    assert {item["violation_id"] for item in replay["counterexamples"]} == {"SP003"}


def test_every_binding_and_replay_invariant_has_an_observable_failure_class():
    mutations = {}

    missing_approval = built_in_scenario("hardened-payment")
    missing_approval["happens_before"].remove(["approve", "commit-a"])
    mutations["SP002"] = missing_approval

    scope = built_in_scenario("hardened-payment")
    _event(scope, "commit-a")["scope"] = "payments:admin"
    mutations["SP005"] = scope

    audience = built_in_scenario("hardened-payment")
    _event(audience, "commit-a")["audience"] = "payroll-mcp"
    mutations["SP006"] = audience

    identity = built_in_scenario("hardened-payment")
    _event(identity, "commit-a")["subject"] = "other-agent"
    mutations["SP007"] = identity

    duplicate_effect = built_in_scenario("approval-replay")
    _event(duplicate_effect, "approve")["max_uses"] = 2
    _event(duplicate_effect, "commit-b")["effect_id"] = "payment-1042"
    mutations["SP008"] = duplicate_effect

    duplicate_receipt = built_in_scenario("approval-replay")
    _event(duplicate_receipt, "approve")["max_uses"] = 2
    _event(duplicate_receipt, "commit-b")["receipt_id"] = "receipt-1042-a"
    mutations["SP009"] = duplicate_receipt

    for expected, scenario in mutations.items():
        observed = {item["violation_id"] for item in analyze_scenario(scenario)["counterexamples"]}
        assert expected in observed


def test_truncated_safe_search_never_claims_bounded_safety():
    scenario = built_in_scenario("hardened-payment")
    scenario["exploration"]["max_schedules"] = 1
    report = analyze_scenario(scenario)
    assert report["summary"]["complete_exploration"] is False
    assert report["summary"]["status"] == "incomplete_review"


def test_scenario_and_report_match_packaged_json_schemas():
    scenario = built_in_scenario("revocation-race")
    report = analyze_scenario(scenario)
    root = files("dspy_security_bench").joinpath("schemas")
    scenario_schema = json.loads(root.joinpath("scheduleproof-scenario.schema.json").read_text())
    report_schema = json.loads(root.joinpath("scheduleproof-report.schema.json").read_text())
    jsonschema.Draft202012Validator(scenario_schema).validate(scenario)
    jsonschema.Draft202012Validator(report_schema).validate(report)


def test_cycle_and_unknown_fields_are_rejected():
    scenario = built_in_scenario("hardened-payment")
    scenario["unexpected"] = True
    scenario["happens_before"].append(["revoke", "grant"])
    errors = validate_scenario(scenario)
    assert "scenario fields are incomplete or unsupported" in errors
    assert "happens_before must be acyclic" in errors


def test_semantic_tampering_fails_offline_verification():
    report = analyze_scenario(built_in_scenario("revocation-race"))
    tampered = deepcopy(report)
    tampered["summary"]["unsafe_schedules"] = 0
    errors = verify_schedule_report(tampered)
    assert "report_sha256 does not match canonical report content" in errors
    assert "summary does not recompute" in errors


def test_sarif_and_continuousproof_accept_verified_schedule_evidence():
    report = analyze_scenario(built_in_scenario("revocation-race"))
    sarif = schedule_report_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"].startswith("SP")
    snapshot = build_evidence_snapshot(report, label="revocation-race-baseline")
    assert snapshot["evidence_kind"] == "schedule"
    assert snapshot["metrics"]["summary.unsafe_schedules"] > 0


def test_schedule_cli_init_run_gate_and_verify(tmp_path):
    scenario = tmp_path / "schedule.json"
    report = tmp_path / "report.json"
    sarif = tmp_path / "report.sarif"
    assert (
        root_main(["schedule", "init", "--profile", "revocation-race", "--out", str(scenario)]) == 0
    )
    assert (
        root_main(
            ["schedule", "run", str(scenario), "--json-out", str(report), "--sarif-out", str(sarif)]
        )
        == 0
    )
    assert root_main(["schedule", "run", str(scenario), "--fail-on-unsafe"]) == 1
    assert root_main(["schedule", "verify", str(report)]) == 0
    assert sarif.is_file()

    truncated = json.loads(scenario.read_text())
    truncated["exploration"]["max_schedules"] = 1
    scenario.write_text(json.dumps(truncated))
    assert root_main(["schedule", "run", str(scenario), "--require-complete"]) == 1


def _event(scenario, event_id):
    return next(item for item in scenario["events"] if item["id"] == event_id)
