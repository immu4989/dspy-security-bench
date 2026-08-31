from __future__ import annotations

import base64
import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.quorum.cli import main as quorum_main
from dspy_security_bench.quorum.proof import (
    analyze_quorum,
    validate_policy,
    verify_quorum_report,
)
from dspy_security_bench.quorum.sarif import report_to_sarif

ROOT = Path(__file__).resolve().parents[1]


def _demo(tmp_path: Path) -> tuple[dict, dict]:
    assert quorum_main(["demo", "--out-dir", str(tmp_path)]) == 0
    satisfied = json.loads((tmp_path / "quorum-satisfied.report.json").read_text())
    gap = json.loads((tmp_path / "review-gap.report.json").read_text())
    return satisfied, gap


def _role(envelope: dict) -> str:
    statement = json.loads(base64.b64decode(envelope["payload"]))
    return statement["predicate"]["reviewer"]["role"]


def test_six_role_dsse_reviews_satisfy_every_critical_infrastructure_claim(tmp_path):
    satisfied, _ = _demo(tmp_path)
    assert satisfied["summary"]["status"] == "quorum_satisfied"
    assert satisfied["summary"]["claim_count"] == 9
    assert satisfied["summary"]["claim_status_counts"] == {
        "quorum_satisfied": 9,
        "review_gap_recorded": 0,
        "quorum_incomplete": 0,
    }
    assert satisfied["summary"]["valid_reviews"] == 5
    assert satisfied["summary"]["distinct_valid_signers"] == 5
    assert satisfied["summary"]["automatic_deployment_actions"] == 0
    assert verify_quorum_report(satisfied, evidence_root=tmp_path) == ()
    assert report_to_sarif(satisfied)["runs"][0]["results"] == []


def test_authorized_evidence_gap_is_a_veto_not_a_vote(tmp_path):
    _, gap = _demo(tmp_path)
    assert gap["summary"]["status"] == "review_gap_recorded"
    assert gap["summary"]["evidence_gap_vetoes"] > 0
    assert gap["summary"]["valid_reviews"] == 5
    affected = [item for item in gap["claim_results"] if item["gap_reviewers"]]
    assert affected
    assert all(item["status"] == "review_gap_recorded" for item in affected)
    sarif = report_to_sarif(gap)
    assert any(item["ruleId"] == "AQ001" for item in sarif["runs"][0]["results"])


def test_missing_independent_review_stays_incomplete(tmp_path):
    satisfied, _ = _demo(tmp_path)
    reviews = [
        item for item in satisfied["review_envelopes"] if _role(item) != "independent-reviewer"
    ]
    report = analyze_quorum(
        satisfied["policy"],
        satisfied["assurance_report"],
        reviews,
        evidence_root=tmp_path,
        evaluation_time=satisfied["evaluation_time"],
    )
    assert report["summary"]["status"] == "quorum_incomplete"
    assert all(
        "independent-reviewer" in item["missing_roles"]
        for item in report["claim_results"]
        if "independent-reviewer" in item["required_roles"]
    )


def test_invalid_signature_and_duplicate_signer_fail_closed(tmp_path):
    satisfied, _ = _demo(tmp_path)
    tampered = deepcopy(satisfied["review_envelopes"])
    tampered[0]["signatures"][0]["sig"] = base64.b64encode(b"invalid").decode()
    invalid = analyze_quorum(
        satisfied["policy"],
        satisfied["assurance_report"],
        tampered,
        evidence_root=tmp_path,
        evaluation_time=satisfied["evaluation_time"],
    )
    assert invalid["summary"]["status"] == "invalid_review_evidence"
    assert invalid["summary"]["invalid_reviews"] == 1

    duplicated = analyze_quorum(
        satisfied["policy"],
        satisfied["assurance_report"],
        [*satisfied["review_envelopes"], satisfied["review_envelopes"][0]],
        evidence_root=tmp_path,
        evaluation_time=satisfied["evaluation_time"],
    )
    assert duplicated["summary"]["status"] == "invalid_review_evidence"
    assert duplicated["summary"]["duplicate_signers"]


def test_rehashed_quorum_report_tampering_fails_semantic_recomputation(tmp_path):
    satisfied, _ = _demo(tmp_path)
    satisfied["summary"]["status"] = "quorum_incomplete"
    satisfied.pop("report_sha256")
    satisfied["report_sha256"] = canonical_sha256(satisfied)
    assert "AssuranceQuorum report does not recompute exactly" in verify_quorum_report(
        satisfied, evidence_root=tmp_path
    )


def test_policy_rejects_an_organizational_quorum_that_cannot_be_met(tmp_path):
    satisfied, _ = _demo(tmp_path)
    policy = deepcopy(satisfied["policy"])
    for reviewer in policy["reviewers"]:
        reviewer["organization_id"] = "fictional-single-organization"
    policy.pop("policy_sha256")
    policy["policy_sha256"] = canonical_sha256(policy)

    errors = validate_policy(policy, satisfied["assurance_report"])
    assert any("cannot meet minimum_distinct_organizations" in error for error in errors)


def test_policy_and_report_schemas_validate_demo(tmp_path):
    satisfied, _ = _demo(tmp_path)
    policy_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/assurancequorum-policy.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/assurancequorum-report.schema.json").read_text()
    )
    registry = Registry().with_resource(policy_schema["$id"], Resource.from_contents(policy_schema))
    jsonschema.Draft202012Validator(policy_schema).validate(satisfied["policy"])
    jsonschema.Draft202012Validator(report_schema, registry=registry).validate(satisfied)


def test_umbrella_cli_exposes_quorum(capsys):
    from dspy_security_bench.cli import main

    assert main(["quorum"]) == 0
    assert "role-separated" in capsys.readouterr().out
