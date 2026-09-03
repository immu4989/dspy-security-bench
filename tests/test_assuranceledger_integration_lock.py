from __future__ import annotations

import json
import shutil
from copy import deepcopy

import jsonschema

from dspy_security_bench.ledger.capabilities import (
    build_capability_manifest,
    default_schema_root,
)
from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.integration_lock import (
    build_integration_lock,
    check_integration_lock,
    verify_integration_lock_check,
)
from dspy_security_bench.ledger.integration_lock_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def test_owner_lock_pins_every_schema_and_protocol():
    manifest = build_capability_manifest()
    lock = build_integration_lock(manifest)
    assert lock["summary"] == {
        "automatic_actions": 0,
        "required_protocol_count": 10,
        "required_schema_count": 15,
    }
    assert set(lock["required_schemas"]) == {
        item["filename"] for item in manifest["schema_catalog"]
    }
    assert all(item["artifact_schema_sha256"] for item in lock["required_protocols"])


def test_unchanged_verified_candidate_satisfies_owner_lock():
    manifest = build_capability_manifest()
    lock = build_integration_lock(manifest)
    report = check_integration_lock(lock, manifest)
    assert report["summary"]["status"] == "requirements_satisfied"
    assert report["findings"] == []
    assert verify_integration_lock_check(report, lock, manifest) == ()


def test_one_byte_schema_drift_is_reported_against_previous_lock(tmp_path):
    baseline = build_capability_manifest()
    lock = build_integration_lock(baseline)
    schema_root = tmp_path / "schemas"
    shutil.copytree(default_schema_root(), schema_root)
    target = schema_root / "assuranceledger-report.schema.json"
    target.write_text(target.read_text() + "\n")
    candidate = build_capability_manifest(schema_root)
    report = check_integration_lock(lock, candidate, schema_root)
    assert report["summary"]["status"] == "capability_drift"
    assert any(
        item["rule_id"] == "schema-drift"
        and item["subject"] == "assuranceledger-report.schema.json"
        for item in report["findings"]
    )
    assert any(item["rule_id"] == "protocol-contract-drift" for item in report["findings"])
    sarif = report_to_sarif(report)
    assert {item["ruleId"] for item in sarif["runs"][0]["results"]} == {
        "AIL003",
        "AIL005",
    }
    assert all(item["properties"]["automaticActions"] == 0 for item in sarif["runs"][0]["results"])


def test_rehashed_check_tampering_fails_exact_recomputation():
    manifest = build_capability_manifest()
    lock = build_integration_lock(manifest)
    report = check_integration_lock(lock, manifest)
    tampered = deepcopy(report)
    tampered["summary"]["status"] = "capability_drift"
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "IntegrationLockCheck does not recompute exactly" in verify_integration_lock_check(
        tampered, lock, manifest
    )


def test_rehashed_structurally_invalid_lock_yields_reviewable_report():
    manifest = build_capability_manifest()
    lock = build_integration_lock(manifest)
    malformed = deepcopy(lock)
    malformed["required_protocols"] = [malformed["required_protocols"][0]] * 2
    malformed["summary"]["required_protocol_count"] = 2
    malformed.pop("lock_sha256")
    malformed["lock_sha256"] = canonical_sha256(malformed)
    report = check_integration_lock(malformed, manifest)
    assert report["summary"]["status"] == "capability_drift"
    assert any(
        item["rule_id"] == "invalid-lock" and "duplicated" in item["detail"]
        for item in report["findings"]
    )
    schema = json.loads(
        (default_schema_root() / "assuranceledger-integration-lock-check.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_rehashed_unknown_lock_field_is_rejected_without_crash():
    manifest = build_capability_manifest()
    lock = build_integration_lock(manifest)
    malformed = deepcopy(lock)
    malformed["unreviewed_override"] = True
    malformed.pop("lock_sha256")
    malformed["lock_sha256"] = canonical_sha256(malformed)
    report = check_integration_lock(malformed, manifest)
    assert any("fields are not exact" in item["detail"] for item in report["findings"])


def test_null_lock_containers_return_schema_valid_invalid_lock_evidence():
    manifest = build_capability_manifest()
    malformed = build_integration_lock(manifest)
    malformed["required_schemas"] = None
    malformed["required_protocols"] = None
    malformed.pop("lock_sha256")
    malformed["lock_sha256"] = canonical_sha256(malformed)
    report = check_integration_lock(malformed, manifest)
    assert report["summary"]["status"] == "capability_drift"
    assert report["summary"]["required_schema_count"] == 0
    assert report["summary"]["required_protocol_count"] == 0
    schema = json.loads(
        (default_schema_root() / "assuranceledger-integration-lock-check.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_lock_and_check_strict_schemas_validate():
    manifest = build_capability_manifest()
    lock = build_integration_lock(manifest)
    report = check_integration_lock(lock, manifest)
    for filename, artifact in (
        ("assuranceledger-integration-lock.schema.json", lock),
        ("assuranceledger-integration-lock-check.schema.json", report),
    ):
        schema = json.loads((default_schema_root() / filename).read_text())
        jsonschema.Draft202012Validator(schema).validate(artifact)


def test_integration_lock_cli_round_trip(tmp_path):
    manifest_path = tmp_path / "capabilities.json"
    lock_path = tmp_path / "integration-lock.json"
    report_path = tmp_path / "integration-lock-check.json"
    sarif_path = tmp_path / "integration-lock-check.sarif"
    assert ledger_main(["capabilities", "--out", str(manifest_path)]) == 0
    assert ledger_main(["lock-capabilities", str(manifest_path), "--out", str(lock_path)]) == 0
    assert (
        ledger_main(
            [
                "check-capability-lock",
                str(lock_path),
                str(manifest_path),
                "--out",
                str(report_path),
                "--sarif-out",
                str(sarif_path),
                "--fail-on-drift",
            ]
        )
        == 0
    )
    assert json.loads(sarif_path.read_text())["runs"][0]["results"] == []
    assert (
        ledger_main(
            [
                "verify-capability-lock",
                str(report_path),
                str(lock_path),
                str(manifest_path),
            ]
        )
        == 0
    )
