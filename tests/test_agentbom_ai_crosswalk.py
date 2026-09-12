from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_crosswalk import (
    CLAIM_BOUNDARY,
    build_ai_bom_crosswalk,
    verify_ai_bom_crosswalk,
)
from dspy_security_bench.supplychain.cli import main as bom_main
from dspy_security_bench.supplychain.mlbom import build_mlbom_import_report
from dspy_security_bench.supplychain.spdxai import build_spdx_ai_import_report

ROOT = Path(__file__).resolve().parents[1]
CDX_SOURCE = ROOT / "examples/cyclonedx-mlbom-1.7.json"
SPDX_SOURCE = ROOT / "examples/spdx-ai-3.0.1.json"
PAIR_POLICY = ROOT / "examples/ai-bom-crosswalk-pairs.json"


def _inputs() -> tuple[dict, dict, dict, dict, dict]:
    cdx_source = json.loads(CDX_SOURCE.read_text())
    spdx_source = json.loads(SPDX_SOURCE.read_text())
    cdx_report = build_mlbom_import_report(cdx_source, inventory_id="fictional-ml-system")
    spdx_report = build_spdx_ai_import_report(spdx_source, inventory_id="fictional-spdx-ai")
    pairs = json.loads(PAIR_POLICY.read_text())
    return cdx_report, cdx_source, spdx_report, spdx_source, pairs


def test_crosswalk_routes_asymmetries_without_comparing_values():
    inputs = _inputs()
    report = build_ai_bom_crosswalk(*inputs)
    assert report["summary"] == {
        "automatic_actions": 0,
        "both_missing": 1,
        "both_present": 8,
        "pair_count": 2,
        "presence_asymmetries": 2,
        "raw_values_compared": False,
        "review_status": "owner_review_required",
        "semantic_equivalence_established": False,
        "standard_shape_differences": 5,
        "topic_count": 16,
    }
    pairs = {item["pair_id"]: item for item in report["pair_results"]}
    model_topics = {item["topic_id"]: item for item in pairs["fictional-routing-model"]["topics"]}
    assert model_topics["purpose-and-domain"]["state"] == "both_present"
    assert model_topics["environmental-impact"]["state"] == "both_missing"
    assert model_topics["model-interfaces"]["state"] == "spdx_not_represented"
    assert model_topics["explainability"]["state"] == "cyclonedx_not_represented"
    dataset_topics = {
        item["topic_id"]: item for item in pairs["fictional-training-dataset"]["topics"]
    }
    assert dataset_topics["availability"]["state"] == "spdx_only"
    assert dataset_topics["governance"]["state"] == "spdx_not_represented"
    serialized = json.dumps(report, sort_keys=True)
    for prohibited in (
        "Fictional public-service routing model",
        "fictional request routing",
        "Fictional synthetic training dataset",
        "fictional-accuracy",
        "CC0-1.0",
        "private/model.bin",
    ):
        assert prohibited not in serialized
    assert verify_ai_bom_crosswalk(report, *inputs) == ()


def test_crosswalk_schema_is_strict_and_valid():
    report = build_ai_bom_crosswalk(*_inputs())
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/agentbom-ai-crosswalk-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    invalid = deepcopy(report)
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)


def test_crosswalk_rejects_changed_source_and_self_rehashed_edit():
    inputs = _inputs()
    report = build_ai_bom_crosswalk(*inputs)
    changed_inputs = list(inputs)
    changed_inputs[1] = deepcopy(inputs[1])
    changed_inputs[1]["metadata"]["component"]["name"] = "changed private name"
    assert any(
        "invalid CycloneDX ML-BOM import report" in item
        for item in verify_ai_bom_crosswalk(report, *changed_inputs)
    )
    tampered = deepcopy(report)
    tampered["summary"]["semantic_equivalence_established"] = True
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AIBOMCrosswalk report does not recompute exactly" in verify_ai_bom_crosswalk(
        tampered, *inputs
    )


def test_pair_policy_is_strict_owner_input_and_requires_matching_types():
    inputs = list(_inputs())
    reused = deepcopy(inputs[-1])
    reused["pairs"][1]["cyclonedx_component_id"] = reused["pairs"][0]["cyclonedx_component_id"]
    inputs[-1] = reused
    with pytest.raises(ValueError, match="reuses a CycloneDX component"):
        build_ai_bom_crosswalk(*inputs)

    inputs = list(_inputs())
    wrong_type = deepcopy(inputs[-1])
    wrong_type["pairs"][0]["component_type"] = "dataset"
    inputs[-1] = wrong_type
    with pytest.raises(ValueError, match="unknown CycloneDX component"):
        build_ai_bom_crosswalk(*inputs)

    inputs = list(_inputs())
    extra = deepcopy(inputs[-1])
    extra["unexpected"] = True
    inputs[-1] = extra
    with pytest.raises(ValueError, match="must contain only"):
        build_ai_bom_crosswalk(*inputs)


def test_crosswalk_cli_builds_and_exactly_reverifies(tmp_path):
    cdx_report, cdx_source, spdx_report, spdx_source, _pairs = _inputs()
    cdx_report_path = tmp_path / "cdx.report.json"
    spdx_report_path = tmp_path / "spdx.report.json"
    cdx_report_path.write_text(json.dumps(cdx_report))
    spdx_report_path.write_text(json.dumps(spdx_report))
    out = tmp_path / "crosswalk.json"
    common = [
        "--cyclonedx-report",
        str(cdx_report_path),
        "--cyclonedx-source",
        str(CDX_SOURCE),
        "--spdx-report",
        str(spdx_report_path),
        "--spdx-source",
        str(SPDX_SOURCE),
        "--pairs",
        str(PAIR_POLICY),
    ]
    assert bom_main(["crosswalk-ai", *common, "--out", str(out)]) == 0
    assert bom_main(["verify-ai-crosswalk", str(out), *common]) == 0
    assert json.loads(out.read_text())["claim_boundary"] == CLAIM_BOUNDARY
