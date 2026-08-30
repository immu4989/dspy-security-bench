from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.proof import (
    CLAIM_BOUNDARY,
    analyze_change,
    built_in_inventory,
    import_cyclonedx,
    import_spdx,
    protocol_payload,
    report_to_sarif,
    seal_inventory,
    validate_inventory,
    verify_report,
)

ROOT = Path(__file__).resolve().parents[1]


def test_equivalent_inventory_supports_current_dependency_boundary():
    baseline = built_in_inventory("baseline")
    equivalent = built_in_inventory("equivalent")
    report = analyze_change(baseline, equivalent, change_reason="routine comparison")
    assert report["summary"]["status"] == "no_material_change"
    assert report["summary"]["affected_components"] == 0
    assert report["summary"]["impacted_claims"] == 0
    assert report["summary"]["automatic_deployment_actions"] == 0
    assert verify_report(report) == ()


def test_changed_mcp_server_propagates_to_transitively_bound_claims():
    report = analyze_change(
        built_in_inventory("baseline"),
        built_in_inventory("candidate"),
        change_reason="fictional MCP server revision",
    )
    assert report["summary"]["status"] == "reevaluation_required"
    assert report["changes"]["content_changed_component_ids"] == ["payments-mcp"]
    assert "mission-agent" in report["affected_component_ids"]
    assert report["summary"]["impacted_claims"] == 5
    impacted = {item["claim_id"] for item in report["claim_impacts"]}
    assert "bounded-authority" in impacted
    assert "runtime-containment" in impacted
    assert "verified-remediation" not in impacted
    assert len(report["minimal_reevaluation_plan"]) == 5


def test_relationship_and_binding_changes_are_material_even_without_version_change():
    baseline = built_in_inventory("baseline")
    candidate = deepcopy(baseline)
    candidate["relationships"].pop()
    candidate = seal_inventory(candidate)
    report = analyze_change(baseline, candidate, change_reason="container edge removed")
    assert report["summary"]["changed_relationships"] == 1
    assert report["summary"]["status"] == "reevaluation_required"


def test_inventory_rejects_unknown_fields_references_and_tampering():
    inventory = built_in_inventory()
    inventory["remote_lookup_url"] = "https://example.invalid"
    inventory = seal_inventory(inventory)
    assert any("unsupported fields" in item for item in validate_inventory(inventory))

    invalid = built_in_inventory()
    invalid["relationships"][0]["to_component_id"] = "missing-component"
    invalid = seal_inventory(invalid)
    assert any("unknown component" in item for item in validate_inventory(invalid))

    tampered = built_in_inventory()
    tampered["owner"] = "changed after sealing"
    assert "inventory_sha256 does not recompute" in validate_inventory(tampered)


def test_rehashed_report_tampering_does_not_survive_semantic_verification():
    report = analyze_change(
        built_in_inventory("baseline"),
        built_in_inventory("candidate"),
        change_reason="test",
    )
    report["summary"]["status"] = "no_material_change"
    report.pop("report_sha256")
    report["report_sha256"] = canonical_sha256(report)
    assert "AgentBOM report does not recompute exactly" in verify_report(report)


def test_cyclonedx_and_spdx_imports_are_local_incomplete_starters():
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "bom-ref": "pkg:pypi/example@1",
                "name": "example",
                "version": "1",
                "purl": "pkg:pypi/example@1",
            }
        ],
        "dependencies": [{"ref": "pkg:pypi/example@1", "dependsOn": []}],
    }
    imported_cdx = import_cyclonedx(cyclonedx, inventory_id="imported-cyclonedx")
    assert imported_cdx["complete"] is False
    assert imported_cdx["claim_bindings"] == []
    assert validate_inventory(imported_cdx) == ()

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "packages": [{"SPDXID": "SPDXRef-example", "name": "example", "versionInfo": "1"}],
        "relationships": [],
    }
    imported_spdx = import_spdx(spdx, inventory_id="imported-spdx")
    assert imported_spdx["components"][0]["component_type"] == "dependency"
    assert validate_inventory(imported_spdx) == ()


def test_schemas_sarif_protocol_and_cli_demo(tmp_path):
    inventory = built_in_inventory()
    report = analyze_change(inventory, built_in_inventory("candidate"), change_reason="demo")
    inventory_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/agentbom-inventory.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/agentbom-claimimpact-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(inventory_schema).validate(inventory)
    jsonschema.Draft202012Validator(report_schema).validate(report)
    sarif = report_to_sarif(report)
    assert len(sarif["runs"][0]["results"]) == 5
    assert protocol_payload()["network_access"] is False
    assert protocol_payload()["claim_boundary"] == CLAIM_BOUNDARY

    demo = tmp_path / "agentbom"
    assert bom_main(["demo", "--out-dir", str(demo)]) == 0
    report_path = demo / "changed.claim-impact.json"
    assert report_path.is_file()
    assert bom_main(["verify", str(report_path)]) == 0
