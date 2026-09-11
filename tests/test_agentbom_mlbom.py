from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.mlbom import (
    CLAIM_BOUNDARY,
    build_mlbom_import_report,
    import_mlbom,
    verify_mlbom_import_report,
)
from dspy_security_bench.supplychain.proof import analyze_change, validate_inventory

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/cyclonedx-mlbom-1.7.json"


def _mlbom() -> dict:
    return json.loads(EXAMPLE.read_text())


def test_mlbom_mapping_is_privacy_minimized_and_reports_disclosure_gaps():
    source = _mlbom()
    report = build_mlbom_import_report(source, inventory_id="fictional-ml-system")
    inventory = report["inventory"]
    assert validate_inventory(inventory) == ()
    assert inventory["complete"] is False
    assert inventory["claim_bindings"] == []
    assert {item["component_type"] for item in inventory["components"]} == {
        "model",
        "dataset",
    }
    assert {item["relationship"] for item in inventory["relationships"]} == {
        "depends-on",
        "sourced-from",
    }
    assert report["summary"] == {
        "automatic_actions": 0,
        "claim_binding_count": 0,
        "data_components": 1,
        "disclosure_fields_expected": 22,
        "disclosure_fields_present": 17,
        "disclosure_gaps": 5,
        "inventory_complete": False,
        "model_components": 1,
        "network_requests": 0,
        "raw_disclosure_values_retained": False,
        "review_status": "owner_review_required",
        "source_signature_verified": False,
        "unresolved_dataset_references": 0,
    }
    model = report["model_disclosure_coverage"][0]
    assert model["present_count"] == 13
    assert model["missing_fields"] == [
        "quantitativeAnalysis.graphics",
        "considerations.performanceTradeoffs",
        "considerations.environmentalConsiderations",
    ]
    assert report["data_disclosure_coverage"][0]["present_count"] == 4
    serialized = json.dumps(report, sort_keys=True)
    for prohibited in (
        "Fictional public-service routing model",
        "fictional request classification",
        "fictional-small-v1",
        "fictional trained reviewer",
        "fictional automation bias",
        "Fictional synthetic training rows",
        "Fictional Example Organization",
    ):
        assert prohibited not in serialized
    assert verify_mlbom_import_report(report, source) == ()


def test_model_identity_is_stable_when_model_card_content_changes():
    baseline_source = _mlbom()
    candidate_source = deepcopy(baseline_source)
    candidate_source["metadata"]["component"]["modelCard"]["modelParameters"]["task"] = (
        "changed fictional task"
    )
    baseline = import_mlbom(baseline_source, inventory_id="fictional-ml-system")
    candidate = import_mlbom(candidate_source, inventory_id="fictional-ml-system")
    before = next(item for item in baseline["components"] if item["component_type"] == "model")
    after = next(item for item in candidate["components"] if item["component_type"] == "model")
    assert before["component_id"] == after["component_id"]
    assert before["digest"] != after["digest"]
    impact = analyze_change(baseline, candidate, change_reason="reviewed model-card change")
    assert impact["changes"]["added_component_ids"] == []
    assert impact["changes"]["removed_component_ids"] == []
    assert impact["changes"]["content_changed_component_ids"] == [before["component_id"]]


def test_mlbom_report_schema_is_strict_and_valid():
    report = build_mlbom_import_report(_mlbom(), inventory_id="fictional-ml-system")
    schema = json.loads(
        (
            ROOT / "dspy_security_bench/schemas/agentbom-mlbom-disclosure-report.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    invalid = deepcopy(report)
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)


def test_source_and_self_rehashed_report_mutations_are_rejected():
    source = _mlbom()
    report = build_mlbom_import_report(source, inventory_id="fictional-ml-system")
    changed_source = deepcopy(source)
    changed_source["metadata"]["component"]["name"] = "different private name"
    assert "MLBOMDisclosure report does not recompute exactly" in verify_mlbom_import_report(
        report, changed_source
    )
    tampered = deepcopy(report)
    tampered["summary"]["raw_disclosure_values_retained"] = True
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "MLBOMDisclosure report does not recompute exactly" in verify_mlbom_import_report(
        tampered, source
    )


def test_mlbom_rejects_wrong_version_missing_model_and_duplicate_identity():
    wrong_version = _mlbom()
    wrong_version["specVersion"] = "1.6"
    with pytest.raises(ValueError, match="specVersion 1.7"):
        import_mlbom(wrong_version, inventory_id="fictional-ml-system")
    missing_model = _mlbom()
    missing_model["metadata"].pop("component")
    with pytest.raises(ValueError, match="machine-learning-model"):
        import_mlbom(missing_model, inventory_id="fictional-ml-system")
    duplicate = _mlbom()
    duplicate["components"].append(deepcopy(duplicate["metadata"]["component"]))
    with pytest.raises(ValueError, match="duplicate ML component bom-ref"):
        import_mlbom(duplicate, inventory_id="fictional-ml-system")


def test_unresolved_dataset_reference_is_visible_but_not_promoted_to_component():
    source = _mlbom()
    source["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"].append(
        {"ref": "urn:example:private-unresolved-dataset"}
    )
    report = build_mlbom_import_report(source, inventory_id="fictional-ml-system")
    assert report["summary"]["unresolved_dataset_references"] == 1
    assert len(report["inventory"]["components"]) == 2
    assert "private-unresolved-dataset" not in json.dumps(report, sort_keys=True)


def test_inline_dataset_becomes_privacy_minimized_sourced_from_component():
    source = _mlbom()
    source["components"] = []
    source["dependencies"] = []
    source["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"] = [
        {
            "type": "dataset",
            "name": "private inline dataset",
            "classification": "restricted",
            "description": "private inline description",
        }
    ]
    report = build_mlbom_import_report(source, inventory_id="fictional-ml-system")
    assert report["summary"]["data_components"] == 1
    assert report["summary"]["unresolved_dataset_references"] == 0
    assert report["mapping"]["dataset_relationship_count"] == 1
    assert report["data_disclosure_coverage"][0]["present_fields"] == [
        "classification",
        "description",
    ]
    serialized = json.dumps(report, sort_keys=True)
    assert "private inline dataset" not in serialized
    assert "private inline description" not in serialized


def test_multiple_component_data_entries_merge_presence_without_values():
    source = _mlbom()
    data = source["components"][0]["data"]
    data[0].pop("classification")
    data.append(
        {
            "type": "dataset",
            "classification": "private-secondary-classification",
            "contents": {"url": "https://private.example/dataset"},
        }
    )
    report = build_mlbom_import_report(source, inventory_id="fictional-ml-system")
    coverage = report["data_disclosure_coverage"][0]
    assert coverage["present_fields"] == [
        "contents",
        "classification",
        "sensitiveData",
        "description",
        "governance",
    ]
    serialized = json.dumps(report, sort_keys=True)
    assert "private-secondary-classification" not in serialized
    assert "private.example" not in serialized


def test_committed_example_cli_imports_and_reverifies(tmp_path):
    inventory = tmp_path / "mlbom.agentbom.json"
    report = tmp_path / "mlbom-disclosure.report.json"
    assert (
        bom_main(
            [
                "import-mlbom",
                str(EXAMPLE),
                "--inventory-id",
                "fictional-ml-system",
                "--out",
                str(inventory),
                "--report-out",
                str(report),
            ]
        )
        == 0
    )
    assert bom_main(["verify-mlbom-import", str(report), str(EXAMPLE)]) == 0
    assert json.loads(report.read_text())["claim_boundary"] == CLAIM_BOUNDARY
