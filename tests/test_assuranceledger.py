from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.proof import (
    analyze_ledger,
    merkle_root,
    validate_policy,
    verify_ledger_report,
)
from dspy_security_bench.ledger.sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> tuple[dict, dict]:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    current = json.loads((tmp_path / "current-trust.report.json").read_text())
    invalidated = json.loads((tmp_path / "compromise-invalidation.report.json").read_text())
    return current, invalidated


def test_witnessed_current_reviewer_trust_is_recomputed_offline(tmp_path):
    current, _ = _demo(tmp_path)
    assert current["summary"]["status"] == "reviewer_trust_current"
    assert current["summary"]["review_count"] == 5
    assert current["summary"]["current_reviews"] == 5
    assert current["summary"]["witness_count"] == 2
    assert current["summary"]["distinct_witness_organizations"] == 2
    assert current["summary"]["automatic_deployment_actions"] == 0
    assert verify_ledger_report(current, evidence_root=tmp_path / "quorum") == ()
    assert report_to_sarif(current)["runs"][0]["results"] == []


def test_logged_compromise_invalidates_historical_review_without_automatic_action(tmp_path):
    _, invalidated = _demo(tmp_path)
    assert invalidated["summary"]["status"] == "reviewer_trust_invalidated"
    assert invalidated["summary"]["invalidated_reviews"] == 1
    affected = [
        item
        for item in invalidated["review_results"]
        if item["status"] == "reviewer_trust_invalidated"
    ]
    assert affected[0]["revocation_event_sha256s"]
    assert report_to_sarif(invalidated)["runs"][0]["results"][0]["ruleId"] == "AL001"


def test_removing_a_review_log_entry_breaks_checkpoint_and_trust(tmp_path):
    current, _ = _demo(tmp_path)
    entries = deepcopy(current["entries"])
    entries.pop()
    report = analyze_ledger(
        current["policy"],
        current["quorum_report"],
        entries,
        current["checkpoint"],
        previous_checkpoint=None,
        evidence_root=tmp_path / "quorum",
        evaluation_time=current["evaluation_time"],
    )
    assert report["summary"]["status"] == "invalid_ledger_evidence"
    assert any(
        "tree_size" in error or "root_sha256" in error for error in report["checkpoint_errors"]
    )


def test_witness_signature_tampering_fails_closed(tmp_path):
    current, _ = _demo(tmp_path)
    checkpoint = deepcopy(current["checkpoint"])
    checkpoint["witness_signatures"][0]["signature_base64"] = "aW52YWxpZA=="
    report = analyze_ledger(
        current["policy"],
        current["quorum_report"],
        current["entries"],
        checkpoint,
        previous_checkpoint=None,
        evidence_root=tmp_path / "quorum",
        evaluation_time=current["evaluation_time"],
    )
    assert report["summary"]["status"] == "invalid_ledger_evidence"
    assert any("signature is invalid" in error for error in report["checkpoint_errors"])


def test_extended_tree_preserves_the_previous_checkpoint_prefix(tmp_path):
    _, invalidated = _demo(tmp_path)
    previous = invalidated["previous_checkpoint"]["checkpoint"]
    assert invalidated["checkpoint"]["checkpoint"]["previous_tree_size"] == previous["tree_size"]
    assert (
        invalidated["checkpoint"]["checkpoint"]["previous_root_sha256"] == previous["root_sha256"]
    )
    assert merkle_root(invalidated["entries"][: previous["tree_size"]]) == previous["root_sha256"]


def test_policy_rejects_an_impossible_witness_organization_threshold(tmp_path):
    current, _ = _demo(tmp_path)
    policy = deepcopy(current["policy"])
    for witness in policy["witnesses"]:
        witness["organization_id"] = "fictional-one-organization"
    policy.pop("policy_sha256")
    policy["policy_sha256"] = canonical_sha256(policy)
    assert "minimum_distinct_witness_organizations cannot be met" in validate_policy(policy)


def test_policy_and_report_schemas_validate_demo(tmp_path):
    current, _ = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-policy.schema.json",
        "assurancequorum-policy.schema.json",
        "assurancequorum-report.schema.json",
        "assuranceledger-report.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[0], registry=registry).validate(current["policy"])
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(current)


def test_umbrella_cli_exposes_ledger(capsys):
    from dspy_security_bench.cli import main

    assert main(["ledger"]) == 0
    assert "append-only" in capsys.readouterr().out
