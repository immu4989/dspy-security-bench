from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_drift import (
    CLAIM_BOUNDARY,
    ai_disclosure_drift_report_to_sarif,
    build_ai_disclosure_drift_report,
    verify_ai_disclosure_drift_report,
)
from dspy_security_bench.supplychain.aibom_policy import build_ai_disclosure_policy_report
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.mlbom import build_mlbom_import_report
from dspy_security_bench.supplychain.spdxai import build_spdx_ai_import_report

ROOT = Path(__file__).resolve().parents[1]
CDX_SOURCE = ROOT / "examples/cyclonedx-mlbom-1.7.json"
SPDX_SOURCE = ROOT / "examples/spdx-ai-3.0.1.json"
POLICY_PATH = ROOT / "examples/ai-bom-disclosure-policy.json"


def _policy() -> dict:
    return json.loads(POLICY_PATH.read_text())


def _snapshot(cdx_source: dict | None = None, spdx_source: dict | None = None) -> dict:
    cdx_source = cdx_source or json.loads(CDX_SOURCE.read_text())
    spdx_source = spdx_source or json.loads(SPDX_SOURCE.read_text())
    cdx_report = build_mlbom_import_report(cdx_source, inventory_id="fictional-ml-system")
    spdx_report = build_spdx_ai_import_report(spdx_source, inventory_id="fictional-spdx-ai")
    evaluation = build_ai_disclosure_policy_report(
        _policy(), cdx_report, cdx_source, spdx_report, spdx_source
    )
    return {
        "evaluation": evaluation,
        "cyclonedx_report": cdx_report,
        "cyclonedx_source": cdx_source,
        "spdx_report": spdx_report,
        "spdx_source": spdx_source,
    }


def _inputs(baseline: dict, candidate: dict) -> dict:
    return {
        **{f"baseline_{key}": value for key, value in baseline.items()},
        **{f"candidate_{key}": value for key, value in candidate.items()},
    }


def _resolved_sources() -> tuple[dict, dict]:
    cdx = json.loads(CDX_SOURCE.read_text())
    cdx["metadata"]["component"]["modelCard"]["considerations"]["environmentalConsiderations"] = [
        "fictional value; presence only"
    ]
    cdx["components"][0]["data"][0]["contents"] = {
        "attachment": {"content": "fictional value; never retained"}
    }
    spdx = json.loads(SPDX_SOURCE.read_text())
    for item in spdx["@graph"]:
        if item.get("type") == "ai_AIPackage":
            item["ai_energyConsumption"] = {"energyQuantity": "fictional value"}
        if item.get("type") == "dataset_DatasetPackage":
            item["dataset_sensor"] = ["fictional value; never retained"]
    return cdx, spdx


def test_identical_snapshots_preserve_gaps_without_inventing_regression():
    baseline = _snapshot()
    report = build_ai_disclosure_drift_report(_policy(), **_inputs(baseline, deepcopy(baseline)))
    assert report["summary"] == {
        "status": "no_new_disclosure_regression",
        "baseline_finding_count": 4,
        "candidate_finding_count": 4,
        "candidate_requirements_status": "owner_review_required",
        "retained_components": 4,
        "added_components": 0,
        "removed_components": 0,
        "component_set_changed": False,
        "regression_findings": 0,
        "introduced_findings": 0,
        "worsened_findings": 0,
        "persistent_findings": 4,
        "improved_findings": 0,
        "resolved_findings": 0,
        "added_component_gaps": 0,
        "removed_component_prior_gaps": 0,
        "raw_disclosure_values_compared": False,
        "automatic_waivers": 0,
        "automatic_actions": 0,
    }
    assert ai_disclosure_drift_report_to_sarif(report)["runs"][0]["results"] == []
    assert report["claim_boundary"] == CLAIM_BOUNDARY


def test_resolved_fields_are_visible_but_not_automatically_approved():
    baseline = _snapshot()
    cdx, spdx = _resolved_sources()
    candidate = _snapshot(cdx, spdx)
    inputs = _inputs(baseline, candidate)
    report = build_ai_disclosure_drift_report(_policy(), **inputs)
    assert report["summary"]["status"] == "no_new_disclosure_regression"
    assert report["summary"]["resolved_findings"] == 4
    assert report["summary"]["candidate_requirements_status"] == "requirements_met"
    assert report["summary"]["automatic_actions"] == 0
    assert verify_ai_disclosure_drift_report(report, _policy(), **inputs) == ()


def test_new_missing_field_is_a_regression_and_sarif_warning():
    baseline = _snapshot()
    candidate_cdx = deepcopy(baseline["cyclonedx_source"])
    del candidate_cdx["metadata"]["component"]["modelCard"]["modelParameters"]["task"]
    candidate = _snapshot(candidate_cdx, deepcopy(baseline["spdx_source"]))
    report = build_ai_disclosure_drift_report(_policy(), **_inputs(baseline, candidate))
    assert report["summary"]["status"] == "disclosure_regression"
    assert report["summary"]["regression_findings"] == 1
    assert report["summary"]["introduced_findings"] == 1
    assert report["summary"]["persistent_findings"] == 4
    sarif = ai_disclosure_drift_report_to_sarif(report)
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["properties"]["resultsAreVulnerabilities"] is False


def test_fully_disclosed_added_component_still_requires_topology_review():
    baseline = _snapshot()
    candidate_cdx = deepcopy(baseline["cyclonedx_source"])
    candidate_cdx["components"].append(
        {
            "type": "data",
            "bom-ref": "urn:example:fictional-added-data:1",
            "name": "Fictional added data",
            "data": [
                {
                    "type": "dataset",
                    "contents": {"attachment": {"content": "fictional"}},
                    "classification": "fictional",
                    "sensitiveData": ["fictional"],
                    "governance": {"owners": [{"contact": {"name": "fictional"}}]},
                }
            ],
        }
    )
    candidate = _snapshot(candidate_cdx, deepcopy(baseline["spdx_source"]))
    report = build_ai_disclosure_drift_report(_policy(), **_inputs(baseline, candidate))
    assert report["summary"]["status"] == "component_set_changed"
    assert report["summary"]["added_components"] == 1
    assert report["summary"]["added_component_gaps"] == 0
    assert len(ai_disclosure_drift_report_to_sarif(report)["runs"][0]["results"]) == 1


def test_removed_component_prior_gap_is_not_mislabeled_resolved():
    baseline = _snapshot()
    candidate_cdx = deepcopy(baseline["cyclonedx_source"])
    candidate_cdx["components"] = []
    candidate_cdx["metadata"]["component"]["modelCard"]["modelParameters"]["datasets"] = []
    candidate = _snapshot(candidate_cdx, deepcopy(baseline["spdx_source"]))
    report = build_ai_disclosure_drift_report(_policy(), **_inputs(baseline, candidate))
    assert report["summary"]["removed_components"] == 1
    assert report["summary"]["removed_component_prior_gaps"] == 1
    assert report["summary"]["resolved_findings"] == 0


def test_drift_schema_is_strict_and_report_contains_no_raw_values():
    baseline = _snapshot()
    cdx, spdx = _resolved_sources()
    report = build_ai_disclosure_drift_report(_policy(), **_inputs(baseline, _snapshot(cdx, spdx)))
    schema = json.loads(
        (
            ROOT / "dspy_security_bench/schemas/agentbom-ai-disclosure-drift-report.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    invalid = deepcopy(report)
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)
    serialized = json.dumps(report, sort_keys=True)
    for prohibited in (
        "Fictional public-service routing model",
        "fictional request classification",
        "Fictional synthetic training dataset",
        "private/model.bin",
        "fictional value; never retained",
    ):
        assert prohibited not in serialized


def test_drift_rejects_source_drift_and_self_rehashed_edits():
    baseline = _snapshot()
    inputs = _inputs(baseline, deepcopy(baseline))
    report = build_ai_disclosure_drift_report(_policy(), **inputs)
    changed = deepcopy(inputs)
    changed["candidate_cyclonedx_source"]["metadata"]["component"]["name"] = "changed"
    assert any(
        "invalid candidate AI disclosure policy report" in item
        for item in verify_ai_disclosure_drift_report(report, _policy(), **changed)
    )
    tampered = deepcopy(report)
    tampered["summary"]["automatic_waivers"] = 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AIDisclosureDrift report does not recompute exactly" in (
        verify_ai_disclosure_drift_report(tampered, _policy(), **inputs)
    )


def test_drift_cli_fails_on_regression_and_exactly_reverifies(tmp_path):
    baseline = _snapshot()
    candidate_cdx = deepcopy(baseline["cyclonedx_source"])
    del candidate_cdx["metadata"]["component"]["modelCard"]["modelParameters"]["task"]
    candidate = _snapshot(candidate_cdx, deepcopy(baseline["spdx_source"]))
    common = ["--policy", str(POLICY_PATH)]
    for prefix, snapshot in (("baseline", baseline), ("candidate", candidate)):
        for key, payload in snapshot.items():
            path = tmp_path / f"{prefix}-{key}.json"
            path.write_text(json.dumps(payload))
            common.extend([f"--{prefix}-{key.replace('_', '-')}", str(path)])
    out = tmp_path / "drift.report.json"
    sarif = tmp_path / "drift.sarif"
    assert (
        bom_main(
            [
                "compare-ai-disclosure",
                *common,
                "--out",
                str(out),
                "--sarif-out",
                str(sarif),
                "--fail-on-regression",
            ]
        )
        == 1
    )
    assert json.loads(out.read_text())["summary"]["regression_findings"] == 1
    assert bom_main(["verify-ai-disclosure-drift", str(out), *common]) == 0
