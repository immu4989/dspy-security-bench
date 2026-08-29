from __future__ import annotations

import csv
import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.portfolio.proof import (
    CLAIM_BOUNDARY,
    MAX_ACTIONS,
    analyze_campaign,
    built_in_campaign,
    frontier_csv_rows,
    protocol_payload,
    seal_campaign,
    validate_campaign,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]


def _report():
    return analyze_campaign(built_in_campaign())


def test_built_in_campaign_is_exact_decision_ready_and_scenario_robust():
    campaign = built_in_campaign()
    assert validate_campaign(campaign) == ()
    report = analyze_campaign(campaign)

    assert report["summary"] == {
        "outcome": "decision_ready",
        "candidate_count": 6,
        "eligible_candidate_count": 5,
        "excluded_candidate_count": 1,
        "service_count": 6,
        "scenario_count": 3,
        "fully_robust_portfolio_exists": True,
        "reference_portfolio_id": "portfolio-815c144ed9a9bf40",
        "reference_is_recommendation": False,
        "content_fields_processed": 0,
        "live_system_actions": 0,
    }
    assert report["enumeration"] == {
        "eligible_action_count": 5,
        "total_subsets": 32,
        "feasible_portfolio_count": 13,
        "frontier_portfolio_count": 10,
        "complete": True,
        "action_limit": MAX_ACTIONS,
    }
    reference = report["reference_selection"]
    assert reference["robust_scenario_count"] == 3
    assert reference["selected_action_ids"] == [
        "government-bounded-fix",
        "open-source-bounded-fix",
        "small-business-bounded-fix",
        "water-bounded-fix",
    ]
    assert verify_report(report) == ()


def test_unsafe_defender_fix_is_excluded_before_enumeration():
    report = _report()
    excluded = [item for item in report["candidate_eligibility"] if not item["eligible"]]
    assert len(excluded) == 1
    assert excluded[0]["action_id"] == "hospital-disruptive-fix"
    assert excluded[0]["defender_outcome"] == "effective_with_regression"
    assert excluded[0]["planning_mapping_verified_by_defendertwin"] is False
    assert all(
        "hospital-disruptive-fix" not in item["selected_action_ids"] for item in report["frontier"]
    )


def test_frontier_contains_no_pair_that_dominates_another():
    frontier = _report()["frontier"]

    def dominates(left, right):
        maximize = (
            "robust_scenario_count",
            "worst_direct_service_weight",
            "worst_dependency_reach_weight",
            "worst_beneficiary_group_count",
        )
        minimize = ("budget_units", "workforce_units", "disruption_units")
        no_worse = (
            all(left[key] >= right[key] for key in maximize)
            and all(left["resources"][key] <= right["resources"][key] for key in minimize)
            and len(left["selected_action_ids"]) <= len(right["selected_action_ids"])
        )
        strict = (
            any(left[key] > right[key] for key in maximize)
            or any(left["resources"][key] < right["resources"][key] for key in minimize)
            or len(left["selected_action_ids"]) < len(right["selected_action_ids"])
        )
        return no_worse and strict

    assert not any(
        dominates(left, right) for left in frontier for right in frontier if left is not right
    )


def test_dependency_reach_is_separate_from_direct_service_protection():
    reference = _report()["reference_selection"]
    baseline = next(
        item for item in reference["scenario_results"] if item["scenario_id"] == "baseline"
    )
    assert "digital-communications" not in baseline["direct_service_ids"]
    assert "digital-communications" in baseline["dependency_reach_service_ids"]
    assert set(baseline["direct_service_ids"]).isdisjoint(baseline["dependency_reach_service_ids"])
    assert "not proof that a downstream service is secure" in CLAIM_BOUNDARY


def test_impossible_owner_floor_returns_no_feasible_portfolio_without_relaxing_it():
    campaign = deepcopy(built_in_campaign())
    campaign["constraints"]["required_service_ids"] = ["digital-communications"]
    campaign = seal_campaign(campaign)
    report = analyze_campaign(campaign)
    assert report["summary"]["outcome"] == "no_feasible_portfolio"
    assert report["enumeration"]["feasible_portfolio_count"] == 0
    assert report["frontier"] == []
    assert report["reference_selection"] is None
    assert verify_report(report) == ()


def test_campaign_rejects_cycles_unknown_references_and_asymmetric_exclusions():
    cycle = deepcopy(built_in_campaign())
    cycle["services"][0]["depends_on"] = ["clinical-care"]
    cycle = seal_campaign(cycle)
    assert "service dependency graph must be acyclic" in validate_campaign(cycle)

    unknown = deepcopy(built_in_campaign())
    unknown["scenarios"][0]["unavailable_action_ids"] = ["unknown-action"]
    unknown = seal_campaign(unknown)
    assert any("unknown action" in item for item in validate_campaign(unknown))

    asymmetric = deepcopy(built_in_campaign())
    asymmetric["actions"][0]["exclusive_with_action_ids"] = ["water-bounded-fix"]
    asymmetric = seal_campaign(asymmetric)
    assert any("must be symmetric" in item for item in validate_campaign(asymmetric))


def test_campaign_rejects_tampered_source_evidence_and_digest():
    campaign = deepcopy(built_in_campaign())
    campaign["actions"][0]["defender_report"]["summary"]["outcome"] = "ineffective"
    campaign = seal_campaign(campaign)
    assert any("invalid DefenderTwin report" in item for item in validate_campaign(campaign))

    digest = built_in_campaign()
    digest["name"] = "Changed after sealing"
    assert "campaign_sha256 does not recompute" in validate_campaign(digest)


def test_report_tampering_is_detected_even_after_rehashing():
    report = _report()
    report["summary"]["reference_is_recommendation"] = True
    report.pop("report_sha256")
    from dspy_security_bench.mission.loader import canonical_sha256

    report["report_sha256"] = canonical_sha256(report)
    assert "ResilienceGraph report does not recompute exactly" in verify_report(report)


def test_json_schemas_validate_and_reject_nested_extensions():
    campaign = built_in_campaign()
    report = analyze_campaign(campaign)
    campaign_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/resilience-campaign.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/resiliencegraph-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(campaign_schema).validate(campaign)
    jsonschema.Draft202012Validator(report_schema).validate(report)

    campaign["services"][0]["economic_multiplier"] = 100
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(campaign_schema).validate(campaign)
    report["frontier"][0]["predicted_savings"] = 1_000_000
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(report_schema).validate(report)


def test_protocol_excludes_false_precision_and_hidden_ranking():
    protocol = protocol_payload()
    serialized = json.dumps(protocol).lower()
    assert protocol["enumeration"] == "all subsets of eligible actions"
    assert protocol["tie_break"].endswith("explicitly not a recommendation")
    assert "probabilities inferred" in protocol["scenario_model"]
    assert "avoided losses" in serialized
    assert "vendor ranking" in serialized


def test_continuousproof_tracks_portfolio_evidence_without_reversing_resource_direction():
    snapshot = build_evidence_snapshot(_report(), label="approved planning baseline")
    assert snapshot["evidence_kind"] == "defense-portfolio"
    assert snapshot["identity"]["campaign_sha256"]
    assert snapshot["metrics"]["summary.fully_robust_portfolio"] == 1.0
    assert snapshot["metrics"]["summary.robust_scenarios"] == 3.0
    assert snapshot["metrics"]["summary.worst_direct_service_weight"] == 12.0


def test_csv_rows_are_flat_recomputable_views():
    report = _report()
    rows = frontier_csv_rows(report)
    assert len(rows) == report["enumeration"]["frontier_portfolio_count"]
    assert sum(row["reference_selection"] for row in rows) == 1
    assert all("selected_action_ids" in row for row in rows)


def test_umbrella_cli_init_run_verify_and_csv(tmp_path, capsys):
    campaign_path = tmp_path / "campaign.json"
    report_path = tmp_path / "report.json"
    csv_path = tmp_path / "frontier.csv"
    assert umbrella_main(["portfolio", "init", "--out", str(campaign_path)]) == 0
    assert (
        umbrella_main(
            [
                "portfolio",
                "run",
                str(campaign_path),
                "--json-out",
                str(report_path),
                "--csv-out",
                str(csv_path),
                "--require-fully-robust",
            ]
        )
        == 0
    )
    assert umbrella_main(["portfolio", "verify", str(report_path)]) == 0
    rows = list(csv.DictReader(csv_path.open()))
    assert rows and sum(row["reference_selection"] == "True" for row in rows) == 1
    assert "not a recommendation" in capsys.readouterr().out


def test_action_bound_prevents_silent_incomplete_enumeration():
    campaign = deepcopy(built_in_campaign())
    base = campaign["actions"][0]
    for index in range(len(campaign["actions"]), MAX_ACTIONS + 1):
        candidate = deepcopy(base)
        candidate["action_id"] = f"extra-action-{index}"
        campaign["actions"].append(candidate)
    campaign = seal_campaign(campaign)
    assert f"campaign actions must contain 1..{MAX_ACTIONS} entries" in validate_campaign(campaign)
