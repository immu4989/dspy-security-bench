from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_policy import (
    CLAIM_BOUNDARY,
    ai_disclosure_policy_report_to_sarif,
    build_ai_disclosure_policy_report,
    verify_ai_disclosure_policy_report,
)
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.mlbom import build_mlbom_import_report
from dspy_security_bench.supplychain.spdxai import build_spdx_ai_import_report

ROOT = Path(__file__).resolve().parents[1]
CDX_SOURCE = ROOT / "examples/cyclonedx-mlbom-1.7.json"
SPDX_SOURCE = ROOT / "examples/spdx-ai-3.0.1.json"
POLICY = ROOT / "examples/ai-bom-disclosure-policy.json"


def _inputs() -> tuple[dict, dict, dict, dict, dict]:
    policy = json.loads(POLICY.read_text())
    cdx_source = json.loads(CDX_SOURCE.read_text())
    spdx_source = json.loads(SPDX_SOURCE.read_text())
    cdx_report = build_mlbom_import_report(cdx_source, inventory_id="fictional-ml-system")
    spdx_report = build_spdx_ai_import_report(spdx_source, inventory_id="fictional-spdx-ai")
    return policy, cdx_report, cdx_source, spdx_report, spdx_source


def test_owner_policy_routes_four_missing_disclosures_without_raw_values():
    inputs = _inputs()
    report = build_ai_disclosure_policy_report(*inputs)
    assert report["summary"] == {
        "status": "owner_review_required",
        "component_checks": 4,
        "requirements_met_components": 0,
        "components_requiring_review": 4,
        "finding_count": 4,
        "missing_required_fields": 4,
        "unresolved_reference_findings": 0,
        "license_relationship_findings": 0,
        "raw_disclosure_values_processed": False,
        "automatic_waivers": 0,
        "automatic_actions": 0,
    }
    assert [item["field"] for item in report["findings"]] == [
        "contents",
        "considerations.environmentalConsiderations",
        "dataset_sensor",
        "ai_energyConsumption",
    ]
    serialized = json.dumps(report, sort_keys=True)
    for prohibited in (
        "Fictional public-service routing model",
        "fictional request classification",
        "Fictional synthetic training dataset",
        "CC0-1.0",
        "private/model.bin",
    ):
        assert prohibited not in serialized
    assert report["claim_boundary"] == CLAIM_BOUNDARY
    assert verify_ai_disclosure_policy_report(report, *inputs) == ()


def test_satisfied_owner_policy_does_not_overclaim():
    inputs = list(_inputs())
    policy = deepcopy(inputs[0])
    policy["cyclonedx"]["required_model_fields"].remove(
        "considerations.environmentalConsiderations"
    )
    policy["cyclonedx"]["required_dataset_fields"].remove("contents")
    policy["spdx"]["required_ai_fields"].remove("ai_energyConsumption")
    policy["spdx"]["required_dataset_fields"].remove("dataset_sensor")
    inputs[0] = policy
    report = build_ai_disclosure_policy_report(*inputs)
    assert report["summary"]["status"] == "requirements_met"
    assert report["summary"]["finding_count"] == 0
    assert report["summary"]["raw_disclosure_values_processed"] is False
    assert "does not validate field truth or adequacy" in report["claim_boundary"]


def test_relationship_and_license_gaps_are_separate_review_findings():
    policy, _, cdx_source, _, spdx_source = _inputs()
    changed_cdx = deepcopy(cdx_source)
    changed_cdx["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"][0]["ref"] = (
        "urn:example:missing-dataset"
    )
    changed_spdx = deepcopy(spdx_source)
    for item in changed_spdx["@graph"]:
        if item.get("relationshipType") == "trainedOn":
            item["to"] = ["https://example.invalid/missing-dataset"]
    changed_spdx["@graph"] = [
        item
        for item in changed_spdx["@graph"]
        if item.get("spdxId") != "https://example.invalid/relations/model-declared-license"
    ]
    cdx_report = build_mlbom_import_report(changed_cdx, inventory_id="fictional-ml-system")
    spdx_report = build_spdx_ai_import_report(changed_spdx, inventory_id="fictional-spdx-ai")
    report = build_ai_disclosure_policy_report(
        policy, cdx_report, changed_cdx, spdx_report, changed_spdx
    )
    types = [item["finding_type"] for item in report["findings"]]
    assert "unresolved_dataset_reference" in types
    assert "unresolved_relationship_reference" in types
    assert "license_relationship_rule" in types
    assert report["summary"]["unresolved_reference_findings"] == 2
    assert report["summary"]["license_relationship_findings"] == 1


@pytest.mark.parametrize("mutation", ["unknown", "duplicate", "empty"])
def test_policy_is_strict_owner_input(mutation):
    inputs = list(_inputs())
    policy = deepcopy(inputs[0])
    if mutation == "unknown":
        policy["cyclonedx"]["required_model_fields"].append("not.a.standard.field")
    elif mutation == "duplicate":
        policy["spdx"]["required_ai_fields"].append("ai_metric")
    else:
        policy["cyclonedx"]["required_model_fields"] = []
        policy["cyclonedx"]["required_dataset_fields"] = []
        policy["spdx"]["required_ai_fields"] = []
        policy["spdx"]["required_dataset_fields"] = []
    inputs[0] = policy
    with pytest.raises(ValueError, match="duplicate or unsupported|at least one"):
        build_ai_disclosure_policy_report(*inputs)


def test_policy_and_report_schemas_are_strict_and_validate():
    inputs = _inputs()
    report = build_ai_disclosure_policy_report(*inputs)
    policy_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/agentbom-ai-disclosure-policy.schema.json").read_text()
    )
    report_schema = json.loads(
        (
            ROOT / "dspy_security_bench/schemas/agentbom-ai-disclosure-policy-report.schema.json"
        ).read_text()
    )
    for schema, payload in ((policy_schema, inputs[0]), (report_schema, report)):
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(payload)
        invalid = deepcopy(payload)
        invalid["unexpected"] = True
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(invalid)


def test_report_rejects_source_drift_and_self_rehashed_edits():
    inputs = _inputs()
    report = build_ai_disclosure_policy_report(*inputs)
    changed = list(inputs)
    changed[2] = deepcopy(inputs[2])
    changed[2]["metadata"]["component"]["name"] = "changed private name"
    assert any(
        "invalid CycloneDX ML-BOM import report" in item
        for item in verify_ai_disclosure_policy_report(report, *changed)
    )
    tampered = deepcopy(report)
    tampered["summary"]["automatic_waivers"] = 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AIDisclosurePolicy report does not recompute exactly" in (
        verify_ai_disclosure_policy_report(tampered, *inputs)
    )


def test_sarif_routes_findings_as_review_warnings_not_vulnerabilities():
    report = build_ai_disclosure_policy_report(*_inputs())
    sarif = ai_disclosure_policy_report_to_sarif(report)
    run = sarif["runs"][0]
    assert len(run["results"]) == 4
    assert {item["level"] for item in run["results"]} == {"warning"}
    assert run["properties"] == {
        "reportSha256": report["report_sha256"],
        "automaticActions": 0,
        "findingsAreVulnerabilities": False,
    }


def test_policy_cli_builds_sarif_fails_closed_and_exactly_reverifies(tmp_path):
    _, cdx_report, _, spdx_report, _ = _inputs()
    cdx_report_path = tmp_path / "cdx.report.json"
    spdx_report_path = tmp_path / "spdx.report.json"
    cdx_report_path.write_text(json.dumps(cdx_report))
    spdx_report_path.write_text(json.dumps(spdx_report))
    out = tmp_path / "policy.report.json"
    sarif = tmp_path / "policy.sarif"
    common = [
        "--policy",
        str(POLICY),
        "--cyclonedx-report",
        str(cdx_report_path),
        "--cyclonedx-source",
        str(CDX_SOURCE),
        "--spdx-report",
        str(spdx_report_path),
        "--spdx-source",
        str(SPDX_SOURCE),
    ]
    assert (
        bom_main(
            [
                "evaluate-ai-disclosure",
                *common,
                "--out",
                str(out),
                "--sarif-out",
                str(sarif),
                "--fail-on-findings",
            ]
        )
        == 1
    )
    assert json.loads(out.read_text())["summary"]["finding_count"] == 4
    assert len(json.loads(sarif.read_text())["runs"][0]["results"]) == 4
    assert bom_main(["verify-ai-disclosure", str(out), *common]) == 0
