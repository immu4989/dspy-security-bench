from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.witness_conflict import verify_witness_conflict_report
from dspy_security_bench.ledger.witness_conflict_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> dict:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    return json.loads((tmp_path / "witness-conflict.report.json").read_text())


def test_reference_fork_attributes_both_shared_witness_keys(tmp_path):
    report = _demo(tmp_path)
    assert report["summary"]["status"] == "operator_and_witness_conflict_evidenced"
    assert report["summary"]["shared_witness_keys"] == 2
    assert report["summary"]["shared_witness_organizations"] == 2
    assert all(
        item["status"] == "signed_both_conflicting_checkpoints"
        for item in report["witness_results"]
    )
    assert verify_witness_conflict_report(report) == ()


def test_attribution_tampering_fails_semantic_recomputation(tmp_path):
    report = _demo(tmp_path)
    tampered = deepcopy(report)
    tampered["summary"]["shared_witness_keys"] = 0
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "WitnessConflict report does not recompute exactly" in verify_witness_conflict_report(
        tampered
    )


def test_cli_and_sarif_expose_key_level_findings_without_action(tmp_path):
    report = _demo(tmp_path)
    assert (
        ledger_main(["verify-witness-conflict", str(tmp_path / "witness-conflict.report.json")])
        == 0
    )
    results = report_to_sarif(report)["runs"][0]["results"]
    assert len(results) == 2
    assert all(item["ruleId"] == "ALW001" for item in results)
    assert all(item["properties"]["automaticActions"] == 0 for item in results)


def test_witness_conflict_schema_validates_reference_artifact(tmp_path):
    report = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-policy.schema.json",
        "assuranceledger-report.schema.json",
        "assuranceledger-fork-proof.schema.json",
        "assuranceledger-witness-conflict.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(report)
