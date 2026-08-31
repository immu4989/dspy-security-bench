from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.misbehavior import export_fork_proof, verify_fork_proof
from dspy_security_bench.ledger.misbehavior_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> tuple[dict, dict]:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    comparison = json.loads((tmp_path / "view-comparison.report.json").read_text())
    proof = json.loads((tmp_path / "fork-proof.report.json").read_text())
    return comparison, proof


def _rehash(report: dict) -> None:
    report.pop("report_sha256", None)
    report["report_sha256"] = canonical_sha256(report)


def test_compact_proof_verifies_without_source_ledgers(tmp_path):
    _, proof = _demo(tmp_path)
    assert verify_fork_proof(proof) == ()
    assert proof["finding"]["status"] == "operator_equivocation_proved"
    assert proof["finding"]["valid_operator_signatures"] == 2
    assert proof["finding"]["valid_witness_quorums"] == 2


def test_compact_proof_contains_no_review_or_log_content(tmp_path):
    _, proof = _demo(tmp_path)
    serialized = json.dumps(proof, sort_keys=True)
    assert '"entries"' not in serialized
    assert '"quorum_report"' not in serialized
    assert '"review_envelopes"' not in serialized
    assert proof["privacy"] == {
        "automatic_actions": 0,
        "log_entries_embedded": 0,
        "quorum_reports_embedded": 0,
        "review_envelopes_embedded": 0,
        "reviewer_key_registrations_embedded": 0,
        "source_report_digests_disclosed": 2,
    }


def test_rehashed_root_tampering_fails_operator_signature(tmp_path):
    _, proof = _demo(tmp_path)
    tampered = deepcopy(proof)
    tampered["checkpoints"][1]["signed_checkpoint"]["checkpoint"]["root_sha256"] = "a" * 64
    tampered["finding"]["right_root_sha256"] = "a" * 64
    _rehash(tampered)
    assert any(
        "operator signature Ed25519 signature is invalid" in item
        for item in verify_fork_proof(tampered)
    )


def test_rehashed_finding_tampering_fails_semantic_recomputation(tmp_path):
    _, proof = _demo(tmp_path)
    tampered = deepcopy(proof)
    tampered["finding"]["tree_size"] += 1
    _rehash(tampered)
    assert "finding does not match the verified checkpoint conflict" in verify_fork_proof(tampered)


def test_consistent_views_cannot_export_a_fork_proof(tmp_path):
    _, _ = _demo(tmp_path)
    current = json.loads((tmp_path / "current-trust.report.json").read_text())
    extended = json.loads((tmp_path / "compromise-invalidation.report.json").read_text())
    current_path = tmp_path / "current-copy.json"
    extended_path = tmp_path / "extended-copy.json"
    comparison_path = tmp_path / "consistent.json"
    current_path.write_text(json.dumps(current))
    extended_path.write_text(json.dumps(extended))
    assert (
        ledger_main(
            [
                "compare",
                str(current_path),
                str(extended_path),
                "--evidence-root",
                str(tmp_path / "quorum"),
                "--out",
                str(comparison_path),
            ]
        )
        == 0
    )
    comparison = json.loads(comparison_path.read_text())
    with pytest.raises(ValueError, match="no compactly provable same-size fork"):
        export_fork_proof(comparison, evidence_root=tmp_path / "quorum")


def test_cli_exports_and_offline_verifies_compact_proof(tmp_path):
    comparison, _ = _demo(tmp_path)
    comparison_path = tmp_path / "comparison-copy.json"
    output = tmp_path / "portable-fork-proof.json"
    sarif = tmp_path / "portable-fork-proof.sarif"
    comparison_path.write_text(json.dumps(comparison))
    assert (
        ledger_main(
            [
                "export-fork-proof",
                str(comparison_path),
                "--evidence-root",
                str(tmp_path / "quorum"),
                "--out",
                str(output),
                "--sarif-out",
                str(sarif),
            ]
        )
        == 0
    )
    assert ledger_main(["verify-fork-proof", str(output)]) == 0
    assert json.loads(sarif.read_text())["runs"][0]["results"][0]["ruleId"] == "ALF001"


def test_fork_proof_schema_validates_reference_artifact(tmp_path):
    _, proof = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-policy.schema.json",
        "assuranceledger-report.schema.json",
        "assuranceledger-fork-proof.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(proof)


def test_sarif_has_one_high_severity_evidence_finding(tmp_path):
    _, proof = _demo(tmp_path)
    sarif = report_to_sarif(proof)
    result = sarif["runs"][0]["results"]
    assert len(result) == 1
    assert result[0]["ruleId"] == "ALF001"
    assert result[0]["properties"]["automaticActions"] == 0
