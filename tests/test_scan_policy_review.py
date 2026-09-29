"""A changed gate verdict must not masquerade as an improved measured system."""
import json
import socket
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest
from referencing import Registry, Resource

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import (
    build_scan_evidence,
    evidence_policy,
    verify_scan_evidence,
)
from dspy_security_bench.scan.policy_review import review_scan_policy, verify_policy_review


def source():
    return json.loads(build_demo_artifacts()["before.json"])


def review():
    evidence = source()
    proposed = {**evidence["policy"], "min_security": 0.5}
    return review_scan_policy(evidence, proposed)


def rehash(value):
    value["review_sha256"] = canonical_sha256({k: v for k, v in value.items() if k != "review_sha256"})
    return value


def test_policy_relaxation_changes_verdict_not_original_evidence():
    evidence = source()
    original = deepcopy(evidence)
    proposed = {**evidence["policy"], "min_security": 0.5}
    result = review_scan_policy(evidence, proposed, evidence["evidence_sha256"])
    assert evidence == original
    assert result["source_evidence"] == original
    assert not result["summary"]["original_requirements_met"]
    assert result["summary"]["reviewed_requirements_met"]
    assert result["summary"]["model_calls_performed"] == 0
    assert result["summary"]["policy_changed"]
    assert result["summary"]["observations_reused"] == 6
    assert "Post-hoc" in result["claim_boundary"]
    assert verify_policy_review(result, evidence["evidence_sha256"], result["review_sha256"]) == result["summary"]
    with pytest.raises(ValueError):
        verify_scan_evidence(result)
    evidence["report"]["requirements_met"] = True
    proposed["min_security"] = 0
    assert result["source_evidence"] == original
    assert result["proposed_policy"]["min_security"] == 0.5


def test_noop_policy_review_is_labeled_unchanged():
    evidence = source()
    result = review_scan_policy(evidence, evidence["policy"])
    assert not result["summary"]["policy_changed"]
    assert result["reviewed_report"] == result["source_evidence"]["report"]


def test_joint_and_sample_requirements_can_be_rehearsed_from_existing_rows():
    proposed = evidence_policy(GateSpec(min_security=0, min_utility=0, min_joint_success=1, min_runs=10), "never")
    result = review_scan_policy(source(), proposed)
    assert not result["summary"]["reviewed_requirements_met"]
    assert result["summary"]["reviewed_enforcement_status"] == "non_blocking_shortfalls"
    assert {f["finding_type"] for f in result["reviewed_report"]["findings"] if not f["passed"]} == {
        "sample_coverage", "joint_success_threshold"}
    assert verify_policy_review(result)


def test_policy_review_schema_registers_native_source_schema_offline():
    root = files("dspy_security_bench.schemas")
    evidence = json.loads(root.joinpath("scan-evidence.schema.json").read_text())
    schema = json.loads(root.joinpath("scan-policy-review.schema.json").read_text())
    registry = Registry().with_resource("scan-evidence.schema.json", Resource.from_contents(evidence))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, registry=registry).validate(review())


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema_version=True),
    lambda r: r.update(proof_type="scan-evidence"),
    lambda r: r.update(protocol_version="other"),
    lambda r: r.update(extra="private-value"),
    lambda r: r.update(claim_boundary="improved agent and approved"),
    lambda r: r.update(source_evidence_sha256="0" * 64),
    lambda r: r["summary"].update(model_calls_performed=1),
    lambda r: r["summary"].update(policy_changed=False),
    lambda r: r["summary"].update(original_requirements_met=True),
    lambda r: r["summary"].update(reviewed_shortfall_findings=9),
    lambda r: r["reviewed_report"]["findings"].pop(),
    lambda r: r["proposed_policy"].update(min_security=1),
])
def test_rehashed_review_tampering_is_rejected(mutation):
    result = review()
    mutation(result)
    with pytest.raises(ValueError):
        verify_policy_review(rehash(result))


def test_native_source_tampering_cannot_be_repaired_by_rehashing_outer_review():
    result = review()
    evidence = result["source_evidence"]
    evidence["report"]["requirements_met"] = True
    evidence["evidence_sha256"] = canonical_sha256({k: v for k, v in evidence.items() if k != "evidence_sha256"})
    result["source_evidence_sha256"] = evidence["evidence_sha256"]
    with pytest.raises(ValueError):
        verify_policy_review(rehash(result))


@pytest.mark.parametrize("changes", [{"min_security": True}, {"min_security": float("nan")},
    {"min_joint_success": None}, {"unknown_setting": "private-value"}, {"baseline": "private-path"}])
def test_invalid_policy_fields_fail_instead_of_defaulting(changes):
    evidence = source()
    with pytest.raises(ValueError):
        review_scan_policy(evidence, {**evidence["policy"], **changes})


def test_cannot_invent_a_regression_baseline_for_an_absolute_source():
    evidence = source()
    with pytest.raises(ValueError, match="already retained"):
        review_scan_policy(evidence, {**evidence["policy"], "mode": "regression"})


def test_regression_review_reuses_exact_retained_baseline_and_can_explicitly_switch_to_absolute():
    evidence = source()
    row = evidence["observations"][0]
    key = "|".join(row[field] for field in ("suite", "agent", "defense", "attack"))
    baseline = {"security_by_cell": {key: 1}}
    policy = evidence_policy(GateSpec(mode="regression", baseline="retained", max_regression=0), "error")
    evidence = build_scan_evidence(evidence["scope"], policy, evidence["observations"], baseline)
    relaxed = review_scan_policy(evidence, {**policy, "max_regression": 1})
    assert relaxed["summary"]["reviewed_requirements_met"]
    absolute = review_scan_policy(evidence, {**policy, "mode": "absolute", "min_security": 0})
    assert absolute["summary"]["reviewed_requirements_met"]
    assert absolute["source_evidence"]["baseline"] == baseline
    assert absolute["reviewed_report"]["meta"]["baseline_scope_verified"] is None


def test_pins_reject_source_or_review_substitution():
    result = review()
    with pytest.raises(ValueError):
        verify_policy_review(result, expected_source_sha256="0" * 64)
    with pytest.raises(ValueError):
        verify_policy_review(result, expected_review_sha256="0" * 64)


def test_cli_workflow_is_offline_source_preserving_and_nonblocking_explicit(tmp_path, monkeypatch, capsys):
    def offline(*args, **kwargs):
        pytest.fail("policy review must not access providers")

    monkeypatch.setattr(socket.socket, "connect", offline)
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", offline)
    evidence, proposed, result = (tmp_path / name for name in ("source.json", "policy.json", "review.json"))
    evidence.write_text(json.dumps(source()))
    original = evidence.read_bytes()
    assert main(["policy", "init", str(evidence), "--out", str(proposed)]) == 0
    policy = json.loads(proposed.read_text())
    policy["fail_on"] = "never"
    proposed.write_text(json.dumps(policy))
    assert main(["policy", "review", str(evidence), "--policy", str(proposed), "--out", str(result),
                 "--fail-on-shortfalls"]) == 1
    assert evidence.read_bytes() == original
    assert main(["policy", "verify", str(result)]) == 0
    assert main(["policy", "verify", str(result), "--fail-on-shortfalls"]) == 1
    assert "POST-HOC POLICY-ONLY REVIEW" in capsys.readouterr().out
    assert main(["policy", "init", str(evidence), "--out", str(proposed)]) == 2


def test_invalid_inputs_do_not_write_outputs_or_echo_private_values(tmp_path, capsys):
    evidence, policy, result = (tmp_path / name for name in ("source.json", "policy.json", "review.json"))
    evidence.write_text(json.dumps(source()))
    policy.write_text('{"private-value": 1, "private-value": 2}')
    assert main(["policy", "review", str(evidence), "--policy", str(policy), "--out", str(result)]) == 2
    assert not result.exists()
    assert "private-value" not in capsys.readouterr().err


def test_output_size_bound_is_enforced_before_creation(tmp_path, monkeypatch):
    evidence, policy, result = (tmp_path / name for name in ("source.json", "policy.json", "review.json"))
    evidence.write_text(json.dumps(source()))
    policy.write_text(json.dumps(source()["policy"]))
    monkeypatch.setattr("dspy_security_bench.scan.policy_review.MAX_BYTES", evidence.stat().st_size)
    assert main(["policy", "review", str(evidence), "--policy", str(policy), "--out", str(result)]) == 2
    assert not result.exists()
