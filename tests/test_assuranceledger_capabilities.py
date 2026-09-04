from __future__ import annotations

import json
import shutil
from copy import deepcopy

import jsonschema

from dspy_security_bench.ledger.capabilities import (
    MAX_SCHEMA_BYTES,
    build_capability_manifest,
    default_schema_root,
    verify_capability_manifest,
)
from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.mission.loader import canonical_sha256


def test_manifest_covers_every_assuranceledger_protocol_and_schema():
    manifest = build_capability_manifest()
    assert manifest["summary"] == {
        "automatic_actions": 0,
        "offline_verifier_count": 15,
        "protocol_count": 15,
        "schema_count": 26,
        "standalone_verifier_count": 10,
    }
    assert len({item["protocol_id"] for item in manifest["protocols"]}) == 15
    assert all(not item["network_required"] for item in manifest["protocols"])
    catalog = {item["filename"] for item in manifest["schema_catalog"]}
    assert catalog == {
        path.name for path in default_schema_root().glob("assuranceledger-*.schema.json")
    }
    assert {
        schema for protocol in manifest["protocols"] for schema in protocol["artifact_schemas"]
    } <= catalog


def test_manifest_recomputes_from_shipped_schema_bytes():
    manifest = build_capability_manifest()
    assert verify_capability_manifest(manifest) == ()


def test_rehashed_capability_tampering_fails_exact_recomputation():
    manifest = build_capability_manifest()
    tampered = deepcopy(manifest)
    tampered["protocols"][0]["network_required"] = True
    tampered.pop("manifest_sha256")
    tampered["manifest_sha256"] = canonical_sha256(tampered)
    assert "CapabilityManifest does not match local schemas and capabilities" in (
        verify_capability_manifest(tampered)
    )


def test_schema_byte_drift_is_detected(tmp_path):
    schema_root = tmp_path / "schemas"
    shutil.copytree(default_schema_root(), schema_root)
    manifest = build_capability_manifest(schema_root)
    target = schema_root / "assuranceledger-report.schema.json"
    target.write_text(target.read_text() + "\n")
    assert "CapabilityManifest does not match local schemas and capabilities" in (
        verify_capability_manifest(manifest, schema_root)
    )


def test_oversized_vendor_schema_is_rejected_before_reading(tmp_path):
    schema_root = tmp_path / "schemas"
    shutil.copytree(default_schema_root(), schema_root)
    target = schema_root / "assuranceledger-report.schema.json"
    target.write_bytes(b" " * (MAX_SCHEMA_BYTES + 1))
    try:
        build_capability_manifest(schema_root)
    except ValueError as exc:
        assert f"exceeds {MAX_SCHEMA_BYTES} bytes" in str(exc)
    else:
        raise AssertionError("oversized schema was accepted")


def test_capability_manifest_schema_validates_reference_artifact():
    manifest = build_capability_manifest()
    schema = json.loads(
        (default_schema_root() / "assuranceledger-capability-manifest.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(manifest)


def test_every_cataloged_schema_is_valid_draft_2020_12():
    manifest = build_capability_manifest()
    for descriptor in manifest["schema_catalog"]:
        schema = json.loads((default_schema_root() / descriptor["filename"]).read_text())
        jsonschema.Draft202012Validator.check_schema(schema)


def test_capability_cli_emits_and_verifies_manifest(tmp_path):
    output = tmp_path / "assuranceledger-capabilities.json"
    assert ledger_main(["capabilities", "--out", str(output)]) == 0
    assert ledger_main(["verify-capabilities", str(output)]) == 0
    payload = json.loads(output.read_text())
    assert payload["summary"]["protocol_count"] == 15
