import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.aibom_policy import (
    compare_ai_disclosure_policies,
    verify_ai_policy_change_report,
)
from dspy_security_bench.supplychain.cli import main

POLICY_PATH = Path(__file__).resolve().parents[1] / "examples/ai-bom-disclosure-policy.json"


def policy():
    return json.loads(POLICY_PATH.read_text())


def test_policy_relaxation_cannot_be_hidden_by_added_requirements():
    baseline = policy()
    candidate = deepcopy(baseline)
    candidate["cyclonedx"]["required_model_fields"].remove("modelParameters.task")
    candidate["cyclonedx"]["required_model_fields"].append("modelParameters.inputs")
    candidate["spdx"]["require_resolved_ai_relationships"] = False
    report = compare_ai_disclosure_policies(baseline, candidate)
    assert report["summary"]["relaxations"] == 2
    assert report["summary"]["strengthenings"] == 1
    assert report["summary"]["status"] == "review_required"
    assert verify_ai_policy_change_report(report, baseline, candidate) == ()
    report["summary"]["relaxations"] = 0
    report.pop("report_sha256")
    report["report_sha256"] = canonical_sha256(report)
    assert verify_ai_policy_change_report(report, baseline, candidate)


def test_reordering_is_semantically_unchanged_but_source_bound():
    baseline = policy()
    candidate = deepcopy(baseline)
    candidate["spdx"]["required_ai_fields"].reverse()
    report = compare_ai_disclosure_policies(baseline, candidate)
    assert report["summary"]["status"] == "requirements_unchanged"
    assert report["baseline_policy_sha256"] != report["candidate_policy_sha256"]


def test_policy_change_schema_rejects_unknown_fields():
    report = compare_ai_disclosure_policies(policy(), policy())
    schema = json.loads(
        (
            POLICY_PATH.parents[1]
            / "dspy_security_bench/schemas/agentbom-ai-policy-change.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(report, schema)
    report["automatic_approval"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report, schema)


def test_owner_changes_require_review_without_disclosing_owner_value():
    baseline = policy()
    candidate = deepcopy(baseline)
    candidate["owner"] = "private-owner-contact"
    report = compare_ai_disclosure_policies(baseline, candidate)
    assert report["summary"]["policy_identity_changed"] is True
    assert report["summary"]["status"] == "review_required"
    assert "private-owner-contact" not in json.dumps(report)


def test_policy_schema_version_rejects_boolean():
    malformed = policy()
    malformed["schema_version"] = True
    with pytest.raises(ValueError):
        compare_ai_disclosure_policies(policy(), malformed)


def test_cli_emits_review_artifact_before_failing_gate(tmp_path):
    candidate = policy()
    candidate["spdx"]["require_exactly_one_license_relationship_each"] = False
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text(json.dumps(candidate))
    output = tmp_path / "changes.json"
    common = ["--baseline", str(POLICY_PATH), "--candidate", str(candidate_path)]
    assert main(["compare-ai-policy", *common, "--out", str(output), "--fail-on-relaxation"]) == 1
    assert main(["verify-ai-policy-change", str(output), *common]) == 0
