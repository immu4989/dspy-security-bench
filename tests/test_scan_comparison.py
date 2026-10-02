"""Matched-case regressions must not disappear into unchanged aggregate rates."""

import json
from copy import deepcopy
from html.parser import HTMLParser
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.compare import compare_scan_evidence, verify_scan_comparison
from dspy_security_bench.scan.compare_html import render_scan_comparison_html
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


def test_joint_allowance_catches_lost_joint_success_despite_per_axis_allowances():
    before, after = evidence([1, 1, 0, 1], [1, 0, 1, 1]), evidence([1, 1, 1, 0], [0, 1, 1, 1])
    original = deepcopy((before, after))
    kwargs = {"max_new_security_failures": 1, "max_new_utility_failures": 1}
    legacy = compare_scan_evidence(before, after, **kwargs)
    assert legacy["summary"]["comparison_requirements_met"]
    report = compare_scan_evidence(before, after, max_new_joint_failures=1, **kwargs)
    assert report["protocol_version"] == "scan-comparison-v2"
    assert not report["summary"]["comparison_requirements_met"]
    assert report["summary"]["secure_and_useful"] == {
        "cases": 4, "before_successes": 2, "after_successes": 2,
        "new_failures": 2, "new_successes": 2, "stable_successes": 0, "stable_failures": 0}
    assert report["cells"][0]["secure_and_useful"] == report["summary"]["secure_and_useful"]
    assert (before, after) == original
    verify_scan_comparison(report, before, after)
    html = render_scan_comparison_html(report)
    assert "Secure and useful together" in html and "Allowed new secure-and-useful failures" in html
    assert "not the product of aggregate rates" in html
    assert compare_scan_evidence(before, after, max_new_joint_failures=2, **kwargs)["summary"]["comparison_requirements_met"]
    # Increasing the joint allowance cannot disable either marginal gate.
    assert not compare_scan_evidence(before, after, max_new_joint_failures=4)["summary"]["comparison_requirements_met"]


def test_joint_comparison_exhausts_all_binary_transition_combinations():
    from itertools import product

    states = list(product((0, 1), repeat=4))
    before = evidence([s for s, u, t, v in states], [u for s, u, t, v in states])
    after = evidence([t for s, u, t, v in states], [v for s, u, t, v in states])
    result = compare_scan_evidence(before, after, max_new_joint_failures=0)
    assert result["summary"]["secure_and_useful"] == {
        "cases": 16, "before_successes": 4, "after_successes": 4,
        "new_failures": 3, "new_successes": 3, "stable_successes": 1, "stable_failures": 9}


@pytest.mark.parametrize("limit", [-1, True, False, 0.5, 100001, "1", float("nan")])
def test_joint_allowance_rejects_invalid_types_and_values(limit):
    with pytest.raises(ValueError, match="limits"):
        compare_scan_evidence(evidence([1]), evidence([0]), max_new_joint_failures=limit)


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema_version=1),
    lambda r: r.update(protocol_version="scan-comparison-v1"),
    lambda r: r["comparison_policy"].pop("max_new_joint_failures"),
    lambda r: r["summary"].pop("secure_and_useful"),
    lambda r: r["cells"][0].pop("secure_and_useful"),
    lambda r: r["comparison_policy"].update(max_new_joint_failures=None),
])
def test_joint_comparison_schema_and_replay_reject_mixed_versions(mutation):
    before, after = evidence([1]), evidence([0])
    result = compare_scan_evidence(before, after, max_new_joint_failures=0)
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-comparison.schema.json").read_text())
    jsonschema.validate(result, schema)
    mutation(result)
    result["comparison_sha256"] = canonical_sha256({k: v for k, v in result.items() if k != "comparison_sha256"})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(result, schema)
    with pytest.raises(ValueError):
        verify_scan_comparison(result, before, after)


def test_joint_replay_rejects_self_rehashed_false_summary():
    before, after = evidence([1]), evidence([0])
    result = compare_scan_evidence(before, after, max_new_joint_failures=0)
    result["summary"]["secure_and_useful"]["new_failures"] = 0
    result["comparison_sha256"] = canonical_sha256({k: v for k, v in result.items() if k != "comparison_sha256"})
    with pytest.raises(ValueError, match="recompute"):
        verify_scan_comparison(result, before, after)


def test_joint_cli_replay_requires_independent_allowance_and_preserves_v1(tmp_path):
    before, after = evidence([1, 0]), evidence([0, 1])
    for name, value in (("before", before), ("after", after)):
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    command = ["compare", str(tmp_path / "before.json"), str(tmp_path / "after.json")]
    output, html = tmp_path / "joint.json", tmp_path / "joint.html"
    assert main([*command, "--max-new-joint-failures", "0", "--json", str(output),
                 "--html", str(html), "--fail-on-regression"]) == 1
    assert main([*command, "--max-new-joint-failures", "0", "--verify", str(output)]) == 0
    assert main([*command, "--verify", str(output)]) == 2
    assert main([*command, "--max-new-joint-failures", "1", "--verify", str(output)]) == 2
    assert "Secure and useful together" in html.read_text()
    assert compare_scan_evidence(before, after) == compare_scan_evidence(before, after, max_new_joint_failures=None)
    assert compare_scan_evidence(before, after)["protocol_version"] == "scan-comparison-v1"


def test_historical_v1_demo_digest_is_unchanged():
    from dspy_security_bench.scan.demo import build_demo_artifacts

    artifacts = build_demo_artifacts()
    before, after = (json.loads(artifacts[name]) for name in ("before.json", "after.json"))
    assert compare_scan_evidence(before, after)["comparison_sha256"] == (
        "2a444ef864cfe77d899737d7f8c89b5710e6fae32ea95669dd382bb5d06971e5")


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


class ReviewParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_html_has_offline_accessible_structure_without_executable_content():
    report = compare_scan_evidence(evidence([1, 0], [1, 1]), evidence([0, 1], [1, 0]))
    html = render_scan_comparison_html(report)
    parser = ReviewParser()
    parser.feed(html)
    assert not {"script", "img", "iframe", "link", "form"} & {tag for tag, _ in parser.tags}
    assert ("html", {"lang": "en"}) in parser.tags
    assert any(tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy" for tag, attrs in parser.tags)
    assert any(tag == "div" and attrs.get("role") == "region" and attrs.get("tabindex") == "0" for tag, attrs in parser.tags)
    assert "New failure" in html and "New success" in html
    assert "New-failure allowances exceeded" in html
    assert "@media print" in html
    assert "statistical significance" in html


def test_html_escapes_labels_and_defensively_escapes_unverified_numeric_fields():
    report = compare_scan_evidence(evidence([1]), evidence([0]))
    attack = '<img src=x onerror="alert(1)">'
    report["changed_cases"][0]["user_task_id"] = attack
    report["summary"]["security"]["new_failures"] = attack
    report["comparison_policy"]["max_new_utility_failures"] = attack
    html = render_scan_comparison_html(report)
    parser = ReviewParser()
    parser.feed(html)
    assert "img" not in {tag for tag, _ in parser.tags}
    assert "&lt;img" in html


def test_html_preview_is_bounded_and_labels_omissions():
    report = compare_scan_evidence(evidence([1] * 52), evidence([0] * 52))
    html = render_scan_comparison_html(report)
    parser = ReviewParser()
    parser.feed(html)
    assert sum(tag == "tr" for tag, _ in parser.tags) == 51  # header plus 50 cases
    assert "50 of 52 changed cases" in html
    assert len(report["changed_cases"]) == 52


def test_html_unchanged_failures_stay_visible():
    html = render_scan_comparison_html(compare_scan_evidence(evidence([0]), evidence([0])))
    assert "No case outcomes changed" in html
    assert "Unchanged failures still matter" in html
    assert "original scan requirements met</dt><dd>No" in html


def test_cli_html_and_json_outputs_are_preflighted_together(tmp_path):
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps(evidence([1])))
    after.write_text(json.dumps(evidence([0])))
    output, page = tmp_path / "result.json", tmp_path / "review.html"
    args = ["compare", str(before), str(after)]
    assert main([*args, "--json", str(output), "--html", str(output)]) == 2
    assert not output.exists()
    assert main([*args, "--json", str(output), "--html", str(page), "--fail-on-regression"]) == 1
    assert "New-failure allowances exceeded" in page.read_text()
    retained = page.read_bytes()
    other = tmp_path / "another.json"
    assert main([*args, "--json", str(other), "--html", str(page)]) == 2
    assert not other.exists() and page.read_bytes() == retained
