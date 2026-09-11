from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.proof import analyze_change, validate_inventory
from dspy_security_bench.supplychain.slsa import (
    CLAIM_BOUNDARY,
    build_slsa_import_report,
    import_slsa,
    verify_slsa_import_report,
)

ROOT = Path(__file__).resolve().parents[1]


def _statement(*, subject_digest: str = "a" * 64, parameter: str = "release") -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "private-agent-image.tar",
                "uri": "pkg:oci/private.example/agent@candidate",
                "digest": {"sha256": subject_digest},
                "annotations": {"tenant": "sensitive-tenant-name"},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://private.example/build-types/agent/v1",
                "externalParameters": {
                    "releaseChannel": parameter,
                    "secretShapedValue": "do-not-retain-this-value",
                },
                "internalParameters": {"workerPool": "private-pool"},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://private.example/source@refs/heads/main",
                        "name": "private-source-tree",
                        "digest": {"sha256": "b" * 64},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://private.example/builders/isolated",
                    "version": {"runner": "2026.09"},
                },
                "metadata": {
                    "invocationId": "private-run-123",
                    "startedOn": "2026-09-11T12:00:00Z",
                },
                "byproducts": [
                    {
                        "name": "private-build-log",
                        "digest": {"sha256": "c" * 64},
                    }
                ],
            },
            "example_extension": {"customer": "private-customer"},
        },
    }


def test_slsa_mapping_builds_incomplete_content_minimized_agentbom():
    statement = _statement()
    report = build_slsa_import_report(statement, inventory_id="slsa-agent")
    inventory = report["inventory"]
    assert validate_inventory(inventory) == ()
    assert inventory["complete"] is False
    assert inventory["claim_bindings"] == []
    assert report["summary"] == {
        "automatic_actions": 0,
        "claim_binding_count": 0,
        "component_count": 4,
        "inventory_complete": False,
        "network_requests": 0,
        "raw_names_retained": False,
        "raw_parameters_retained": False,
        "raw_uris_retained": False,
        "relationship_count": 3,
        "resolved_dependency_components": 1,
        "signatures_verified": False,
        "subject_components": 1,
    }
    serialized = json.dumps(report, sort_keys=True)
    for prohibited in (
        "private-agent-image.tar",
        "private.example",
        "sensitive-tenant-name",
        "do-not-retain-this-value",
        "private-pool",
        "private-run-123",
        "private-customer",
    ):
        assert prohibited not in serialized
    assert verify_slsa_import_report(report, statement) == ()


def test_subject_digest_changes_remain_one_stable_content_changed_component():
    baseline = import_slsa(_statement(), inventory_id="slsa-agent")
    candidate = import_slsa(_statement(subject_digest="d" * 64), inventory_id="slsa-agent")
    baseline_subject = next(
        item for item in baseline["components"] if item["name"] == "SLSA output subject"
    )
    candidate_subject = next(
        item for item in candidate["components"] if item["name"] == "SLSA output subject"
    )
    assert baseline_subject["component_id"] == candidate_subject["component_id"]
    impact = analyze_change(baseline, candidate, change_reason="new attested artifact")
    assert impact["changes"]["added_component_ids"] == []
    assert impact["changes"]["removed_component_ids"] == []
    assert impact["changes"]["content_changed_component_ids"] == [baseline_subject["component_id"]]


def test_external_parameter_changes_preserve_build_definition_identity():
    baseline = import_slsa(_statement(), inventory_id="slsa-agent")
    candidate = import_slsa(_statement(parameter="emergency"), inventory_id="slsa-agent")
    before = next(item for item in baseline["components"] if item["component_type"] == "policy")
    after = next(item for item in candidate["components"] if item["component_type"] == "policy")
    assert before["component_id"] == after["component_id"]
    assert before["digest"] != after["digest"]


def test_report_schema_is_strict_and_validates_reference_mapping():
    report = build_slsa_import_report(_statement(), inventory_id="slsa-agent")
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/agentbom-slsa-import-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)


def test_self_rehashed_mapping_tamper_fails_source_recomputation():
    statement = _statement()
    report = build_slsa_import_report(statement, inventory_id="slsa-agent")
    tampered = deepcopy(report)
    tampered["summary"]["signatures_verified"] = True
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "SLSAImport report does not recompute exactly" in verify_slsa_import_report(
        tampered, statement
    )


def test_mapping_rejects_missing_sha256_and_dsse_envelope():
    missing = _statement()
    missing["subject"][0]["digest"] = {"sha512": "a" * 128}
    with pytest.raises(ValueError, match="must declare a lowercase SHA-256"):
        import_slsa(missing, inventory_id="slsa-agent")
    with pytest.raises(ValueError, match="in-toto Statement v1"):
        import_slsa(
            {"payloadType": "application/vnd.in-toto+json", "payload": "..."},
            inventory_id="slsa-agent",
        )


def test_cli_writes_and_reverifies_inventory_and_mapping_report(tmp_path):
    source = tmp_path / "provenance.json"
    source.write_text(json.dumps(_statement(), indent=2) + "\n")
    inventory = tmp_path / "agentbom.json"
    report = tmp_path / "slsa-import.report.json"
    assert (
        bom_main(
            [
                "import-slsa",
                str(source),
                "--inventory-id",
                "slsa-agent",
                "--out",
                str(inventory),
                "--report-out",
                str(report),
            ]
        )
        == 0
    )
    assert json.loads(inventory.read_text())["complete"] is False
    assert bom_main(["verify-slsa-import", str(report), str(source)]) == 0


def test_committed_fictional_example_maps_without_live_identifiers():
    source = json.loads((ROOT / "examples/slsa-provenance-v1.json").read_text())
    report = build_slsa_import_report(source, inventory_id="fictional-slsa-agent")
    assert report["summary"]["component_count"] == 4
    assert report["summary"]["signatures_verified"] is False
    assert "fictional-builder.example" not in json.dumps(report)


def test_claim_boundary_refuses_signature_and_slsa_level_claims():
    assert "does not verify an attestation signature" in CLAIM_BOUNDARY
    assert "establish a SLSA Build level" in CLAIM_BOUNDARY
