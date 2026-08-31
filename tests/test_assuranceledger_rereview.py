from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.rereview import plan_rereview, verify_rereview_report
from dspy_security_bench.ledger.rereview_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> tuple[dict, dict, dict, dict]:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    current = json.loads((tmp_path / "current-trust.report.json").read_text())
    retired = json.loads((tmp_path / "key-retirement.report.json").read_text())
    invalidated = json.loads((tmp_path / "compromise-invalidation.report.json").read_text())
    plan = json.loads((tmp_path / "rereview-plan.report.json").read_text())
    return current, retired, invalidated, plan


def test_one_compromised_reviewer_produces_one_minimal_eight_claim_request(tmp_path):
    _, _, _, plan = _demo(tmp_path)
    assert plan["summary"]["status"] == "rereview_required"
    assert plan["summary"]["claims_requiring_rereview"] == 8
    assert plan["summary"]["rereview_request_count"] == 1
    assert plan["summary"]["replacement_reviewers_selected"] == 0
    request = plan["rereview_requests"][0]
    assert request["role"] == "independent-reviewer"
    assert request["reason"] == "compromise-invalidated"
    assert len(request["claim_ids"]) == 8
    assert request["replacement_selected"] is False
    assert verify_rereview_report(plan, evidence_root=tmp_path / "quorum") == ()
    assert len(report_to_sarif(plan)["runs"][0]["results"]) == 8


def test_current_trust_produces_no_rereview_request(tmp_path):
    current, _, _, _ = _demo(tmp_path)
    plan = plan_rereview(current, evidence_root=tmp_path / "quorum")
    assert plan["summary"]["status"] == "no_rereview_indicated"
    assert plan["rereview_requests"] == []
    assert all(item["status"] == "review_current" for item in plan["claim_results"])


def test_owner_historical_policy_changes_renewal_timing_not_recorded_history(tmp_path):
    _, retired, _, _ = _demo(tmp_path)
    strict = plan_rereview(
        retired,
        evidence_root=tmp_path / "quorum",
        historical_policy="require-current-key",
    )
    until_expiry = plan_rereview(
        retired,
        evidence_root=tmp_path / "quorum",
        historical_policy="allow-until-review-expiry",
    )
    assert strict["summary"]["status"] == "rereview_required"
    assert strict["summary"]["claims_requiring_rereview"] == 8
    assert until_expiry["summary"]["status"] == "renewal_due"
    assert until_expiry["summary"]["claims_requiring_rereview"] == 0
    assert until_expiry["rereview_requests"] == []
    assert (
        strict["ledger_report"]["report_sha256"] == until_expiry["ledger_report"]["report_sha256"]
    )


def test_invalid_source_yields_no_actionable_rereview_requests(tmp_path):
    current, _, _, _ = _demo(tmp_path)
    current["checkpoint"]["operator_signature"]["signature_base64"] = "aW52YWxpZA=="
    current.pop("report_sha256")
    current["report_sha256"] = canonical_sha256(current)
    plan = plan_rereview(current, evidence_root=tmp_path / "quorum")
    assert plan["summary"]["status"] == "invalid_source_evidence"
    assert plan["rereview_requests"] == []
    assert plan["claim_results"] == []


def test_rehashed_plan_tampering_fails_semantic_recomputation(tmp_path):
    _, _, _, plan = _demo(tmp_path)
    tampered = deepcopy(plan)
    tampered["summary"]["replacement_reviewers_selected"] = 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AssuranceLedger ReReview report does not recompute exactly" in verify_rereview_report(
        tampered, evidence_root=tmp_path / "quorum"
    )


def test_plan_cli_emits_owner_policy_bound_report(tmp_path):
    _, retired, _, _ = _demo(tmp_path)
    source = tmp_path / "retired-copy.json"
    output = tmp_path / "renewal-plan.json"
    source.write_text(json.dumps(retired))
    assert (
        ledger_main(
            [
                "plan-rereview",
                str(source),
                "--evidence-root",
                str(tmp_path / "quorum"),
                "--historical-policy",
                "allow-until-review-expiry",
                "--out",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["summary"]["status"] == "renewal_due"


def test_rereview_schema_validates_reference_plan(tmp_path):
    _, _, _, plan = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assurancequorum-policy.schema.json",
        "assurancequorum-report.schema.json",
        "assuranceledger-policy.schema.json",
        "assuranceledger-report.schema.json",
        "assuranceledger-rereview-report.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(plan)
