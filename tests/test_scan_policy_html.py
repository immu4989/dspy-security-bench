"""Policy-only report presentation and verified output boundaries."""
import json
from copy import deepcopy

from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.policy_html import MAX_FINDING_PREVIEW, render_policy_review_html
from dspy_security_bench.scan.policy_review import review_scan_policy


def inputs():
    source = json.loads(build_demo_artifacts()["before.json"])
    return source, {**source["policy"], "min_security": 0.5}


def test_html_keeps_policy_only_boundary_ahead_of_changed_verdicts():
    review = review_scan_policy(*inputs())
    html = render_policy_review_html(review)
    assert html.index("not a new benchmark run") < html.index("Requirements met")
    assert "0 new model calls" in html and "6 observations reused unchanged" in html
    assert "Requirements unmet" in html and "Requirements met" in html
    assert "Recorded policy" in html and "Proposed policy" in html
    assert "90.00%" in html and "50.00%" in html
    assert "No finding emitted” is not a measured success" in html
    assert "<script" not in html and "<link" not in html
    assert "default-src 'none'" in html
    assert 'role="region" tabindex="0"' in html
    assert "@media print" in html


def test_noop_heading_does_not_claim_a_policy_change():
    source, _ = inputs()
    html = render_policy_review_html(review_scan_policy(source, source["policy"]))
    assert "Unchanged requirements" in html
    assert "Policy settings are unchanged" in html


def test_untrusted_labels_and_unknown_presentation_values_are_escaped():
    review = review_scan_policy(*inputs())
    label = '<img src="https://private.invalid" onerror="alert(1)">'
    review["reviewed_report"]["findings"][0]["suite"] = label
    review["proposed_policy"]["mode"] = label
    review["claim_boundary"] = label
    html = render_policy_review_html(review)
    assert "<img" not in html and "&lt;img" in html
    assert "onerror=&quot;alert(1)&quot;" in html


def test_bounded_preview_shows_changed_findings_first_and_labels_omissions():
    review = review_scan_policy(*inputs())
    old, new = review["source_evidence"]["report"]["findings"][0], review["reviewed_report"]["findings"][0]
    review["source_evidence"]["report"]["findings"] = []
    review["reviewed_report"]["findings"] = []
    for index in range(MAX_FINDING_PREVIEW + 5):
        first, second = deepcopy(old), deepcopy(new)
        first["suite"] = second["suite"] = f"fixture-{index:03d}"
        second["passed"] = False if index < MAX_FINDING_PREVIEW + 4 else True
        second["severity"] = "error" if not second["passed"] else "none"
        review["source_evidence"]["report"]["findings"].append(first)
        review["reviewed_report"]["findings"].append(second)
    html = render_policy_review_html(review)
    assert f"Showing {MAX_FINDING_PREVIEW} of 55 cell-requirement rows; 5 omitted" in html
    assert html.index("fixture-054") < html.index("fixture-000")
    assert "fixture-053" not in html


def test_cli_native_replay_produces_deterministic_html_and_refuses_overwrites(tmp_path):
    source, policy = inputs()
    evidence, proposal, output, page = (tmp_path / name for name in ("source.json", "policy.json", "review.json", "review.html"))
    evidence.write_text(json.dumps(source))
    proposal.write_text(json.dumps(policy))
    args = ["policy", "review", str(evidence), "--policy", str(proposal), "--out", str(output)]
    assert main([*args, "--html", str(page)]) == 0
    replayed = tmp_path / "replayed.html"
    assert main(["policy", "verify", str(output), "--html", str(replayed)]) == 0
    assert replayed.read_bytes() == page.read_bytes()
    assert main(["policy", "verify", str(output), "--html", str(page)]) == 2


def test_cli_preflights_all_destinations_before_writing_any(tmp_path):
    source, policy = inputs()
    evidence, proposal, output = (tmp_path / name for name in ("source.json", "policy.json", "review.json"))
    evidence.write_text(json.dumps(source))
    proposal.write_text(json.dumps(policy))
    args = ["policy", "review", str(evidence), "--policy", str(proposal), "--out", str(output)]
    assert main([*args, "--html", str(evidence)]) == 2
    assert not output.exists()
    assert main([*args, "--html", str(output)]) == 2
    assert not output.exists()


def test_false_review_cannot_get_a_verified_presentation(tmp_path):
    review = review_scan_policy(*inputs())
    review["summary"]["original_requirements_met"] = True
    path, page = tmp_path / "false.json", tmp_path / "false.html"
    path.write_text(json.dumps(review))
    assert main(["policy", "verify", str(path), "--html", str(page)]) == 2
    assert not page.exists()
