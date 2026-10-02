"""Public review surfaces must preserve uncertainty and withhold source diagnostics."""

import json
from copy import deepcopy
from xml.etree import ElementTree

import pytest

from dspy_security_bench.procurement.agents import (
    build_bounded_reference,
    build_vulnerable_reference,
)
from dspy_security_bench.procurement.cli import main
from dspy_security_bench.procurement.control_registry import (
    _metric_svg,
    render_control_evidence_card_svg,
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.repeat import (
    canonical_sha256,
    create_submission_bundle,
    run_repeat_twin,
)
from dspy_security_bench.procurement.repeat_control import run_repeat_control_twin
from tests.test_control_registry import _bundle, _rehash
from tests.test_control_twin import _procurement_policy
from tests.test_control_twin import _rehash as _rehash_report


@pytest.fixture(scope="module")
def bundle():
    return _bundle(run_repeat_control_twin(
        build_vulnerable_reference, _procurement_policy(), trials=2,
    ).to_dict())


@pytest.mark.parametrize("confidence,label", [(0.8, "80%"), (0.9, "90%"), (0.95, "95%"), (0.995, "99.5%")])
def test_card_uses_retained_confidence_and_conditional_sample_counts(confidence, label):
    report = run_repeat_control_twin(
        build_vulnerable_reference, _procurement_policy(), trials=2, confidence_level=confidence,
    ).to_dict()
    card = render_control_evidence_card_svg(_bundle(report))
    ElementTree.fromstring(card)
    assert card.count(label + " Wilson") == 3
    if confidence != 0.95:
        assert "95% Wilson" not in card
    for key, denominator in [
        ("harm_containment_efficacy", "among baseline-harmful pair-trials"),
        ("safe_mission_recovery", "among baseline-failed pair-trials"),
        ("clean_utility_preservation", "among baseline clean successes"),
    ]:
        estimate = report["summary"][key]
        assert f"{estimate['successes']}/{estimate['observations']} {denominator}" in card


@pytest.mark.parametrize("confidence,label", [(0.000001, "&lt;0.01%"), (0.999999, "&gt;99.99%")])
def test_extreme_confidence_never_rounds_to_zero_or_one(confidence, label):
    card = _metric_svg(0, 0, "TEST", {
        "rate": 1, "lower": 0.5, "upper": 1, "confidence_level": confidence,
        "successes": 10, "observations": 10,
    }, "synthetic trials")
    ElementTree.fromstring(card)
    assert label + " Wilson" in card


def test_empty_conditional_sample_is_not_displayed_as_zero_percent():
    report = run_repeat_control_twin(
        build_bounded_reference, _procurement_policy(), trials=2,
    ).to_dict()
    card = render_control_evidence_card_svg(_bundle(report))
    assert "N/A" in card
    assert "no eligible observations" in card


@pytest.mark.parametrize("section", [None, "submission", "producer", "local", "github_actions", "nested_rule"])
def test_invalid_bundle_diagnostics_do_not_echo_source_keys_or_values(bundle, section, tmp_path, capsys):
    changed = deepcopy(bundle)
    sentinel = "PRIVATE-SOURCE-DIAGNOSTIC"
    if section in (None, "submission", "producer"):
        target = changed if section is None else changed[section]
        target[sentinel] = sentinel
    elif section in ("local", "github_actions"):
        changed["bundle_schema_version"] = 2
        changed["provenance"] = {"provider": section, sentinel: sentinel}
    else:
        control = changed["report"]["trials"][0]["control"]
        control["pairs"][0]["policy_events"][0]["rule_id"] = sentinel
        _rehash_report(control)
        _rehash_report(changed["report"])
        changed["report_sha256"] = canonical_sha256(changed["report"])
    _rehash(changed)
    result = verify_control_submission_bundle(changed)
    assert not result.valid
    assert sentinel not in " ".join(result.errors + result.warnings)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(changed))
    assert main(["control-submission-verify", str(path)]) == 1
    captured = capsys.readouterr()
    assert sentinel not in captured.out + captured.err
    assert "[INVALID]" in captured.out
    assert "[NOT ELIGIBLE]" not in captured.out


def test_valid_but_ineligible_control_bundle_has_distinct_marker(bundle, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    assert main(["control-submission-verify", str(path)]) == 1
    assert "[NOT ELIGIBLE]" in capsys.readouterr().out


def test_repeat_bundle_invalid_and_ineligible_markers_differ(tmp_path, capsys):
    report = run_repeat_twin(build_bounded_reference(), trials=2).to_dict()
    bundle = create_submission_bundle(report, submitter="test", agent_source_url="https://example.com/test")
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    assert main(["verify", str(path)]) == 1
    assert "[NOT ELIGIBLE]" in capsys.readouterr().out
    bundle["bundle_sha256"] = "0" * 64
    path.write_text(json.dumps(bundle))
    assert main(["verify", str(path)]) == 1
    assert "[INVALID]" in capsys.readouterr().out
