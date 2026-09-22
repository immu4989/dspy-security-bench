"""Matched-case regressions must not disappear into unchanged aggregate rates."""

import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.compare import compare_scan_evidence, verify_scan_comparison
from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.evidence import build_scan_evidence, evidence_policy


def evidence(security, utility=None, *, policy=None, label="stable-agent"):
    utility = [1] * len(security) if utility is None else utility
    scope = {"scope_version": 1, "benchmark_version": "v1", "agentdojo_distribution_version": "fixture",
             "measurement_protocol": "complete-binary-observations-v1", "agent_name": label,
             "defenses": ["none"], "suites": [{"suite": "fixture", "user_task_ids": [f"u{i}" for i in range(len(security))],
                 "attacks": [{"attack": "direct", "is_dos_attack": False, "injection_task_ids": ["i"]}]}]}
    rows = [{"suite": "fixture", "agent": label, "defense": "none", "attack": "direct",
             "user_task_id": f"u{i}", "injection_task_id": "i", "security": s,
             "injection_succeeded": 1 - s, "utility": u}
            for i, (s, u) in enumerate(zip(security, utility, strict=True))]
    return build_scan_evidence(scope, policy or evidence_policy(GateSpec(), "error"), rows)


def test_new_failures_are_not_canceled_by_new_successes():
    before, after = evidence([1, 0, 1, 0]), evidence([0, 1, 1, 0])
    report = compare_scan_evidence(before, after)
    counts = report["summary"]["security"]
    assert counts == {"cases": 4, "before_successes": 2, "after_successes": 2,
                      "new_failures": 1, "new_successes": 1, "stable_successes": 1, "stable_failures": 1}
    assert not report["summary"]["comparison_requirements_met"]
    assert report["summary"]["changed_cases"] == 2
    assert len(report["changed_cases"]) == 2
    verify_scan_comparison(report, before, after)
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-comparison.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(report, schema)


def test_security_improvement_does_not_hide_lost_task_utility():
    report = compare_scan_evidence(evidence([0, 0], [1, 1]), evidence([1, 1], [0, 0]))
    assert report["summary"]["security"]["new_successes"] == 2
    assert report["summary"]["utility"]["new_failures"] == 2
    assert not report["summary"]["comparison_requirements_met"]


def test_unchanged_bad_runs_do_not_become_acceptable_scans():
    report = compare_scan_evidence(evidence([0]), evidence([0]))
    assert report["summary"]["comparison_requirements_met"]
    assert not report["source_review"]["after_requirements_met"]
    assert report["summary"]["security"]["stable_failures"] == 1


def test_changed_source_policy_is_flagged_not_used_to_reclassify_outcomes():
    relaxed = evidence_policy(GateSpec(min_security=0), "never")
    report = compare_scan_evidence(evidence([1, 0]), evidence([0, 1], policy=relaxed))
    assert report["source_review"]["gate_policy_changed"]
    assert not report["summary"]["comparison_requirements_met"]


@pytest.mark.parametrize("after", [evidence([1, 1]), evidence([1], label="other-agent")])
def test_scope_or_agent_label_mismatch_is_not_silently_paired(after):
    with pytest.raises(ValueError, match="matched scopes"):
        compare_scan_evidence(evidence([1]), after)


@pytest.mark.parametrize("limit", [-1, True, 0.5, 100001, "1"])
def test_invalid_allowance_is_rejected(limit):
    with pytest.raises(ValueError, match="limits"):
        compare_scan_evidence(evidence([1]), evidence([0]), max_new_security_failures=limit)


def test_independent_source_pins_are_checked():
    before, after = evidence([1]), evidence([0])
    assert compare_scan_evidence(before, after, expected_before_sha256=before["evidence_sha256"], expected_after_sha256=after["evidence_sha256"])
    with pytest.raises(ValueError, match="retained digest"):
        compare_scan_evidence(before, after, expected_after_sha256="0" * 64)


@pytest.mark.parametrize("mutation", ["counts", "remove-case", "swap-sources", "claim", "coerce"])
def test_self_rehashed_comparison_tampering_fails(mutation):
    before, after = evidence([1, 0]), evidence([0, 1])
    report = compare_scan_evidence(before, after)
    if mutation == "counts":
        report["summary"]["security"]["new_failures"] = 0
    elif mutation == "remove-case":
        report["changed_cases"].pop()
    elif mutation == "swap-sources":
        report["before_evidence_sha256"] = after["evidence_sha256"]
    elif mutation == "claim":
        report["claim_boundary"] = "approved"
    else:
        report["summary"]["comparison_requirements_met"] = 0
    report["comparison_sha256"] = canonical_sha256({k: v for k, v in report.items() if k != "comparison_sha256"})
    with pytest.raises(ValueError, match="recompute"):
        verify_scan_comparison(report, before, after)


def test_source_rehashing_cannot_hide_invalid_primitive_outcomes():
    before, after = evidence([1]), evidence([0])
    after = deepcopy(after)
    after["observations"][0]["security"] = 1
    after["evidence_sha256"] = canonical_sha256({k: v for k, v in after.items() if k != "evidence_sha256"})
    with pytest.raises(ValueError):
        compare_scan_evidence(before, after)


def test_cli_preserves_failed_comparison_and_enforces_caller_thresholds(tmp_path):
    before, after, output = (tmp_path / name for name in ("before.json", "after.json", "comparison.json"))
    before.write_text(json.dumps(evidence([1])))
    after.write_text(json.dumps(evidence([0])))
    args = ["compare", str(before), str(after)]
    assert main([*args, "--json", str(output), "--fail-on-regression"]) == 1
    assert output.is_file()
    assert main([*args, "--verify", str(output)]) == 0
    assert main([*args, "--verify", str(output), "--max-new-security-failures", "1"]) == 2
    retained = output.read_bytes()
    assert main([*args, "--json", str(output)]) == 2
    assert output.read_bytes() == retained
