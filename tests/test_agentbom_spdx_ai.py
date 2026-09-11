from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.proof import analyze_change, validate_inventory
from dspy_security_bench.supplychain.spdxai import (
    CLAIM_BOUNDARY,
    build_spdx_ai_import_report,
    import_spdx_ai,
    verify_spdx_ai_import_report,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/spdx-ai-3.0.1.json"


def _spdx_ai() -> dict:
    return json.loads(EXAMPLE.read_text())


def test_spdx_ai_mapping_preserves_semantics_without_raw_values():
    source = _spdx_ai()
    report = build_spdx_ai_import_report(source, inventory_id="fictional-spdx-ai")
    inventory = report["inventory"]
    assert validate_inventory(inventory) == ()
    assert inventory["complete"] is False
    assert {item["component_type"] for item in inventory["components"]} == {
        "model",
        "dataset",
    }
    assert inventory["relationships"][0]["relationship"] == "sourced-from"
    assert report["mapping"] == {
        "agentbom_relationship_count": 1,
        "ai_component_ids": report["mapping"]["ai_component_ids"],
        "dataset_component_ids": report["mapping"]["dataset_component_ids"],
        "depends_on_relationships": 0,
        "has_data_file_relationships": 0,
        "tested_on_relationships": 1,
        "trained_on_relationships": 1,
    }
    assert report["summary"] == {
        "ai_packages": 1,
        "automatic_actions": 0,
        "claim_binding_count": 0,
        "dataset_packages": 1,
        "disclosure_fields_expected": 28,
        "disclosure_fields_present": 22,
        "disclosure_gaps": 6,
        "full_spdx_validation_performed": False,
        "inventory_complete": False,
        "license_relationship_rule_failures": 0,
        "network_requests": 0,
        "raw_disclosure_values_retained": False,
        "review_status": "owner_review_required",
        "unresolved_ai_relationship_references": 0,
    }
    assert {item["status"] for item in report["license_relationship_checks"]} == {
        "exactly_one_each"
    }
    serialized = json.dumps(report, sort_keys=True)
    for prohibited in (
        "Fictional public-service routing model",
        "fictional request routing",
        "fictional-depth",
        "fictional-accuracy",
        "Fictional synthetic training dataset",
        "private/model.bin",
        "CC0-1.0",
        "Fictional Example Organization",
    ):
        assert prohibited not in serialized
    assert verify_spdx_ai_import_report(report, source) == ()


def test_spdx_ai_identity_is_stable_across_disclosure_change():
    baseline_source = _spdx_ai()
    candidate_source = deepcopy(baseline_source)
    model = next(item for item in candidate_source["@graph"] if item["type"] == "ai_AIPackage")
    model["ai_limitation"] = "changed private limitation"
    baseline = import_spdx_ai(baseline_source, inventory_id="fictional-spdx-ai")
    candidate = import_spdx_ai(candidate_source, inventory_id="fictional-spdx-ai")
    before = next(item for item in baseline["components"] if item["component_type"] == "model")
    after = next(item for item in candidate["components"] if item["component_type"] == "model")
    assert before["component_id"] == after["component_id"]
    assert before["digest"] != after["digest"]
    impact = analyze_change(baseline, candidate, change_reason="reviewed SPDX AI change")
    assert impact["changes"]["added_component_ids"] == []
    assert impact["changes"]["removed_component_ids"] == []
    assert impact["changes"]["content_changed_component_ids"] == [before["component_id"]]


def test_license_relationship_gap_is_visible_without_license_value():
    source = _spdx_ai()
    source["@graph"] = [
        item
        for item in source["@graph"]
        if item.get("spdxId") != "https://example.invalid/relations/model-declared-license"
    ]
    report = build_spdx_ai_import_report(source, inventory_id="fictional-spdx-ai")
    assert report["summary"]["license_relationship_rule_failures"] == 1
    model_check = next(
        item
        for item in report["license_relationship_checks"]
        if item["component_id"] in report["mapping"]["ai_component_ids"]
    )
    assert model_check["declared_license_relationships"] == 0
    assert model_check["status"] == "owner_review_required"


def test_spdx_ai_report_schema_is_strict_and_valid():
    report = build_spdx_ai_import_report(_spdx_ai(), inventory_id="fictional-spdx-ai")
    schema = json.loads(
        (
            ROOT / "dspy_security_bench/schemas/agentbom-spdx-ai-disclosure-report.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    invalid = deepcopy(report)
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)


def test_source_and_self_rehashed_report_mutations_are_rejected():
    source = _spdx_ai()
    report = build_spdx_ai_import_report(source, inventory_id="fictional-spdx-ai")
    changed = deepcopy(source)
    changed["@graph"][1]["name"] = "changed private organization"
    assert "SPDXAIDisclosure report does not recompute exactly" in verify_spdx_ai_import_report(
        report, changed
    )
    tampered = deepcopy(report)
    tampered["summary"]["full_spdx_validation_performed"] = True
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "SPDXAIDisclosure report does not recompute exactly" in verify_spdx_ai_import_report(
        tampered, source
    )


def test_context_missing_model_duplicate_id_and_unresolved_relation_are_bounded():
    wrong_context = _spdx_ai()
    wrong_context["@context"] = "https://example.invalid/context"
    with pytest.raises(ValueError, match="SPDX 3.0.1 global JSON-LD context"):
        import_spdx_ai(wrong_context, inventory_id="fictional-spdx-ai")
    no_model = _spdx_ai()
    no_model["@graph"] = [item for item in no_model["@graph"] if item["type"] != "ai_AIPackage"]
    with pytest.raises(ValueError, match="ai_AIPackage"):
        import_spdx_ai(no_model, inventory_id="fictional-spdx-ai")
    duplicate = _spdx_ai()
    duplicate["@graph"].append(deepcopy(duplicate["@graph"][1]))
    with pytest.raises(ValueError, match="duplicate SPDX spdxId"):
        import_spdx_ai(duplicate, inventory_id="fictional-spdx-ai")

    unresolved = _spdx_ai()
    trained = next(
        item for item in unresolved["@graph"] if item.get("relationshipType") == "trainedOn"
    )
    trained["to"].append("https://example.invalid/private-missing-dataset")
    report = build_spdx_ai_import_report(unresolved, inventory_id="fictional-spdx-ai")
    assert report["summary"]["unresolved_ai_relationship_references"] == 1
    assert "private-missing-dataset" not in json.dumps(report, sort_keys=True)


def test_committed_spdx_ai_example_cli_imports_and_reverifies(tmp_path):
    inventory = tmp_path / "spdx-ai.agentbom.json"
    report = tmp_path / "spdx-ai-disclosure.report.json"
    assert (
        bom_main(
            [
                "import-spdx-ai",
                str(EXAMPLE),
                "--inventory-id",
                "fictional-spdx-ai",
                "--out",
                str(inventory),
                "--report-out",
                str(report),
            ]
        )
        == 0
    )
    assert bom_main(["verify-spdx-ai-import", str(report), str(EXAMPLE)]) == 0
    assert json.loads(report.read_text())["claim_boundary"] == CLAIM_BOUNDARY
