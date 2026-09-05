from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.conformance import (
    MAX_ARTIFACT_BYTES,
    load_conformance_artifacts,
    run_conformance,
    verify_conformance_report,
)
from dspy_security_bench.ledger.conformance_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> dict:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    return json.loads((tmp_path / "verifier-conformance.report.json").read_text())


def test_all_sixteen_rehashed_adversarial_vectors_are_rejected(tmp_path):
    report = _demo(tmp_path)
    assert report["summary"] == {
        "automatic_actions": 0,
        "case_count": 16,
        "expected_rejections_observed": 16,
        "status": "conformance_passed",
        "unexpected_acceptances": 0,
    }
    assert {item["artifact_kind"] for item in report["cases"]} == {
        "ledger",
        "gossip",
        "rereview",
        "fork_proof",
        "consistency_proof",
        "observer",
        "witness_conflict",
        "trust_root",
        "trust_chain",
        "trust_recovery",
        "trust_recovery_attestation",
        "time_quorum",
        "trust_root_time",
        "root_view",
        "capability_manifest",
        "integration_lock_check",
    }
    assert all(item["status"] == "expected_rejection_observed" for item in report["cases"])


def test_conformance_report_recomputes_from_exact_source_artifacts(tmp_path):
    report = _demo(tmp_path)
    artifacts = load_conformance_artifacts(tmp_path)
    assert verify_conformance_report(report, artifacts, evidence_root=tmp_path / "quorum") == ()


def test_rehashed_case_result_tampering_fails_recomputation(tmp_path):
    report = _demo(tmp_path)
    tampered = deepcopy(report)
    tampered["cases"][0]["status"] = "unexpected_acceptance"
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    artifacts = load_conformance_artifacts(tmp_path)
    assert "VerifierConformance report does not recompute exactly" in verify_conformance_report(
        tampered, artifacts, evidence_root=tmp_path / "quorum"
    )


def test_invalid_clean_source_is_rejected_before_mutation_matrix(tmp_path):
    _demo(tmp_path)
    artifacts = load_conformance_artifacts(tmp_path)
    invalid = deepcopy(artifacts)
    invalid["gossip"]["summary"]["status"] = "views_consistent"
    invalid["gossip"].pop("report_sha256")
    invalid["gossip"]["report_sha256"] = canonical_sha256(invalid["gossip"])
    try:
        run_conformance(invalid, evidence_root=tmp_path / "quorum")
    except ValueError as exc:
        assert "source artifact gossip is not valid" in str(exc)
    else:
        raise AssertionError("invalid clean source entered the mutation matrix")


def test_oversized_conformance_source_is_rejected_before_json_read(tmp_path):
    target = tmp_path / "current-trust.report.json"
    with target.open("wb") as stream:
        stream.truncate(MAX_ARTIFACT_BYTES + 1)
    try:
        load_conformance_artifacts(tmp_path)
    except ValueError as exc:
        assert f"exceeds {MAX_ARTIFACT_BYTES} bytes" in str(exc)
    else:
        raise AssertionError("oversized conformance source was accepted")


def test_conformance_cli_runs_and_verifies_saved_matrix(tmp_path):
    _demo(tmp_path)
    output = tmp_path / "conformance-copy.json"
    sarif_output = tmp_path / "conformance-copy.sarif"
    assert (
        ledger_main(
            [
                "conformance",
                str(tmp_path),
                "--evidence-root",
                str(tmp_path / "quorum"),
                "--out",
                str(output),
                "--sarif-out",
                str(sarif_output),
                "--fail-on-miss",
            ]
        )
        == 0
    )
    sarif = json.loads(sarif_output.read_text())
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "ALC001"
    assert (
        ledger_main(
            [
                "verify-conformance",
                str(output),
                "--artifact-dir",
                str(tmp_path),
                "--evidence-root",
                str(tmp_path / "quorum"),
            ]
        )
        == 0
    )


def test_conformance_schema_validates_reference_report(tmp_path):
    report = _demo(tmp_path)
    path = (
        Path(__file__).resolve().parents[1]
        / "dspy_security_bench"
        / "schemas"
        / "assuranceledger-conformance-report.schema.json"
    )
    jsonschema.Draft202012Validator(json.loads(path.read_text())).validate(report)


def test_sarif_surfaces_an_unexpected_acceptance_without_action(tmp_path):
    report = _demo(tmp_path)
    failed = deepcopy(report)
    failed["cases"][0]["status"] = "unexpected_acceptance"
    failed["summary"]["status"] = "conformance_failed"
    failed["summary"]["expected_rejections_observed"] = 11
    failed["summary"]["unexpected_acceptances"] = 1
    failed.pop("report_sha256")
    failed["report_sha256"] = canonical_sha256(failed)
    results = report_to_sarif(failed)["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "ALC001"
    assert results[0]["properties"]["automaticActions"] == 0
