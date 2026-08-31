from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.consistency import (
    merkle_consistency_path,
    verify_consistency_proof,
    verify_merkle_consistency,
)
from dspy_security_bench.ledger.consistency_sarif import report_to_sarif
from dspy_security_bench.ledger.proof import merkle_root
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> tuple[dict, dict, dict]:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    current = json.loads((tmp_path / "current-trust.report.json").read_text())
    newer = json.loads((tmp_path / "compromise-invalidation.report.json").read_text())
    proof = json.loads((tmp_path / "consistency-proof.report.json").read_text())
    return current, newer, proof


def _rehash(report: dict) -> None:
    report.pop("report_sha256", None)
    report["report_sha256"] = canonical_sha256(report)


def test_rfc6962_style_paths_verify_for_non_power_of_two_sizes():
    for newer_size in range(2, 66):
        entries = [
            {"sequence": index, "payload": f"fixture-{index}"} for index in range(newer_size)
        ]
        for older_size in range(1, newer_size):
            path = merkle_consistency_path(entries, older_size)
            assert (
                verify_merkle_consistency(
                    older_tree_size=older_size,
                    newer_tree_size=newer_size,
                    older_root_sha256=merkle_root(entries[:older_size]),
                    newer_root_sha256=merkle_root(entries),
                    path_sha256=path,
                )
                == ()
            )


def test_portable_consistency_proof_verifies_without_source_ledgers(tmp_path):
    _, _, proof = _demo(tmp_path)
    assert verify_consistency_proof(proof) == ()
    assert proof["finding"]["status"] == "append_only_extension_proved"
    assert proof["finding"]["valid_operator_signatures"] == 2
    assert proof["finding"]["valid_witness_quorums"] == 2


def test_consistency_proof_contains_no_review_or_log_content(tmp_path):
    _, _, proof = _demo(tmp_path)
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
    }


def test_rehashed_path_tampering_fails_merkle_verification(tmp_path):
    _, _, proof = _demo(tmp_path)
    tampered = deepcopy(proof)
    tampered["consistency"]["path_sha256"][0] = "a" * 64
    _rehash(tampered)
    errors = verify_consistency_proof(tampered)
    assert any("does not reconstruct" in item for item in errors)


def test_rehashed_checkpoint_tampering_fails_signature_and_consistency(tmp_path):
    _, _, proof = _demo(tmp_path)
    tampered = deepcopy(proof)
    tampered["newer_checkpoint"]["checkpoint"]["root_sha256"] = "b" * 64
    tampered["finding"]["newer_root_sha256"] = "b" * 64
    _rehash(tampered)
    errors = verify_consistency_proof(tampered)
    assert any("operator signature Ed25519 signature is invalid" in item for item in errors)
    assert "consistency path does not reconstruct the newer root" in errors


def test_cli_exports_and_offline_verifies_consistency_proof(tmp_path):
    current, newer, _ = _demo(tmp_path)
    older_path = tmp_path / "older-copy.json"
    newer_path = tmp_path / "newer-copy.json"
    output = tmp_path / "portable-consistency.json"
    sarif = tmp_path / "portable-consistency.sarif"
    older_path.write_text(json.dumps(current))
    newer_path.write_text(json.dumps(newer))
    assert (
        ledger_main(
            [
                "export-consistency-proof",
                str(older_path),
                str(newer_path),
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
    assert ledger_main(["verify-consistency-proof", str(output)]) == 0
    assert json.loads(sarif.read_text())["runs"][0]["results"][0]["ruleId"] == "ALC001"


def test_consistency_schema_validates_reference_artifact(tmp_path):
    _, _, proof = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-policy.schema.json",
        "assuranceledger-report.schema.json",
        "assuranceledger-consistency-proof.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(proof)


def test_sarif_records_verified_extension_without_action(tmp_path):
    _, _, proof = _demo(tmp_path)
    result = report_to_sarif(proof)["runs"][0]["results"][0]
    assert result["ruleId"] == "ALC001"
    assert result["level"] == "note"
    assert result["properties"]["automaticActions"] == 0
