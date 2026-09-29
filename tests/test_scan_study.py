"""Fixed-scope trials preserve failures, incompleteness, and source boundaries."""

import json
import socket
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import build_scan_evidence
from dspy_security_bench.scan.study import (
    build_scan_study,
    build_study_plan,
    load_study_manifest,
    validate_study_plan,
    verify_scan_study,
)


def test_study_and_manifest_match_structural_schema(tmp_path):
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-study.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    plan, trials, evidence = inputs()
    report = build_scan_study(plan, trials, evidence)
    jsonschema.validate(report, schema)
    path = manifest(tmp_path, plan, trials, evidence)
    jsonschema.validate(json.loads(path.read_text()), {"$ref": "#/$defs/manifest", "$defs": schema["$defs"]})
    report["schema_version"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report, schema)


def inputs(count=3):
    demo = build_demo_artifacts()
    before, after = (json.loads(demo[name]) for name in ("before.json", "after.json"))
    plan = build_study_plan(before, "fictional-study", count)
    evidence = {name: before if i % 2 == 0 else after for i, name in enumerate(plan["trial_ids"])}
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": item["evidence_sha256"]}
              for name, item in evidence.items()]
    return plan, trials, evidence


def rehash(value, field):
    value[field] = canonical_sha256({key: item for key, item in value.items() if key != field})


def manifest(tmp_path, plan, trials, evidence):
    declarations = deepcopy(trials)
    for trial in declarations:
        if trial["status"] == "complete":
            name = trial["trial_id"]
            trial["evidence"] = name + ".json"
            (tmp_path / trial["evidence"]).write_text(json.dumps(evidence[name]), encoding="utf-8")
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "plan": plan, "trials": declarations}), encoding="utf-8")
    return path


def test_repeated_study_keeps_case_variability_and_joint_outcomes():
    plan, trials, evidence = inputs()
    report = build_scan_study(plan, trials, evidence, plan["plan_sha256"])
    summary = report["summary"]
    assert summary["complete_trials"] == 3 and summary["observed_observations"] == 18
    assert summary["security"]["successes"] == 12
    assert summary["security"]["cases_with_varied_outcomes"] == 2
    assert summary["utility"]["successes"] == 15
    assert summary["utility"]["cases_with_varied_outcomes"] == 2
    assert summary["secure_and_useful"]["successes"] == 11
    assert summary["security"]["cases_successful_in_all_observed_trials"] == 3
    assert summary["all_trials_complete"] and not summary["study_requirements_met"]
    assert report["repeated_evidence_groups"][0]["trial_ids"] == ["trial-001", "trial-003"]
    verify_scan_study(report, plan, trials, evidence)
    assert build_scan_study(plan, list(reversed(trials)), evidence) == report


def test_incomplete_runs_are_visible_and_never_counted_as_binary_outcomes():
    plan, trials, evidence = inputs()
    for i, status in ((0, "missing"), (1, "execution_error")):
        name = trials[i]["trial_id"]
        trials[i] = {"trial_id": name, "status": status}
        evidence.pop(name)
    report = build_scan_study(plan, trials, evidence)
    summary = report["summary"]
    assert summary["missing_trials"] == summary["execution_error_trials"] == 1
    assert summary["observed_observations"] == 6 and summary["planned_observations"] == 18
    assert summary["security"]["observed_rate"] == 4 / 6
    assert not summary["all_trials_complete"] and not summary["study_requirements_met"]
    assert report["cases"][0]["security"]["observed_trials"] == 1


def test_no_complete_trials_have_null_rates_and_no_claimed_successes():
    plan, trials, _ = inputs()
    trials = [{"trial_id": t["trial_id"], "status": "missing"} for t in trials]
    report = build_scan_study(plan, trials, {})
    assert report["summary"]["security"]["observed_rate"] is None
    assert report["summary"]["security"]["cases_successful_in_all_observed_trials"] == 0
    assert report["cases"][0]["utility"]["observed_rate"] is None
    assert not report["summary"]["study_requirements_met"]


def test_study_requirement_needs_all_complete_sources_to_meet_original_requirements():
    plan, trials, evidence = inputs(2)
    for trial in trials:
        original = evidence[trial["trial_id"]]
        rows = deepcopy(original["observations"])
        for row in rows:
            row.update(security=1, utility=1, injection_succeeded=0)
        good = build_scan_evidence(original["scope"], original["policy"], rows)
        evidence[trial["trial_id"]] = good
        trial["evidence_sha256"] = good["evidence_sha256"]
    assert build_scan_study(plan, trials, evidence)["summary"]["study_requirements_met"]


@pytest.mark.parametrize("field", ["scope", "policy", "baseline"])
def test_plan_rejects_changed_source_context(field):
    plan, trials, evidence = inputs(2)
    key = field + "_sha256"
    if field == "scope":
        plan[field]["agent_name"] = "another-agent"
    else:
        plan[key] = "0" * 64
    rehash(plan, "plan_sha256")
    with pytest.raises(ValueError, match="differs from the study plan"):
        build_scan_study(plan, trials, evidence)


@pytest.mark.parametrize("count", [True, 0, 1, 101, 2.0])
def test_trial_count_is_strict_and_bounded(count):
    _, _, evidence = inputs(2)
    with pytest.raises(ValueError):
        build_study_plan(next(iter(evidence.values())), "fixture", count)


def test_planned_observation_budget_is_checked_before_trial_aggregation():
    plan, _, _ = inputs(100)
    plan["scope"]["suites"][0]["user_task_ids"] = [f"case-{i}" for i in range(1000)]
    plan["scope"]["defenses"] = ["one", "two"]
    rehash(plan, "plan_sha256")
    with pytest.raises(ValueError, match="planned case-trial"):
        validate_study_plan(plan)


@pytest.mark.parametrize("mutation", ["omit", "duplicate", "unknown", "extra", "wrong-pin", "missing-source"])
def test_declared_trial_coverage_cannot_be_silently_reduced(mutation):
    plan, trials, evidence = inputs()
    if mutation == "omit":
        trials.pop()
    elif mutation == "duplicate":
        trials[-1] = trials[0]
    elif mutation == "unknown":
        trials[0]["trial_id"] = "unplanned"
    elif mutation == "extra":
        trials[0]["private-prompt"] = "must-not-be-accepted"
    elif mutation == "wrong-pin":
        trials[0]["evidence_sha256"] = "0" * 64
    else:
        evidence.pop(trials[0]["trial_id"])
    with pytest.raises(ValueError):
        build_scan_study(plan, trials, evidence)


@pytest.mark.parametrize("mutation", ["schema-bool", "rate", "error-count", "verdict", "repeated-groups", "unknown"])
def test_rehashed_report_mutations_do_not_recompute(mutation):
    plan, trials, evidence = inputs()
    report = build_scan_study(plan, trials, evidence)
    if mutation == "schema-bool":
        report["schema_version"] = True
    elif mutation == "rate":
        report["cases"][0]["security"]["observed_rate"] = 1
    elif mutation == "error-count":
        report["summary"]["execution_error_trials"] = 1
    elif mutation == "verdict":
        report["summary"]["study_requirements_met"] = True
    elif mutation == "repeated-groups":
        report["repeated_evidence_groups"] = []
    else:
        report["approval"] = True
    rehash(report, "study_sha256")
    with pytest.raises(ValueError, match="recompute"):
        verify_scan_study(report, plan, trials, evidence)


def test_cli_is_offline_and_preserves_valid_nonpassing_report(tmp_path, monkeypatch):
    plan, trials, evidence = inputs()
    path = manifest(tmp_path, plan, trials, evidence)

    def forbidden(*args, **kwargs):
        raise AssertionError("study must not contact a provider")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    output = tmp_path / "study.json"
    assert main(["study", "review", str(path), "--json", str(output), "--fail-on-shortfalls"]) == 1
    assert main(["study", "review", str(path), "--verify", str(output)]) == 0
    assert main(["study", "review", str(path), "--verify", str(output), "--expected-plan-sha256", "0" * 64]) == 2
    assert "trial-001.json" not in output.read_text()
    assert main(["study", "review", str(path), "--json", str(output)]) == 2


def test_init_does_not_count_pilot_as_a_completed_trial(tmp_path):
    plan, trials, evidence = inputs()
    path = manifest(tmp_path, plan, trials, evidence)
    output = tmp_path / "new-manifest.json"
    assert main(["study", "init", str(path.parent / "trial-001.json"), "--study-id", "fresh", "--out", str(output)]) == 0
    declared = json.loads(output.read_text())
    assert all(t["status"] == "missing" for t in declared["trials"])
    assert main(["study", "review", str(output), "--fail-on-shortfalls"]) == 1
    assert main(["study", "init", str(path.parent / "trial-001.json"), "--study-id", "fresh", "--out", str(output)]) == 2


@pytest.mark.parametrize("name", ["../private.json", "/private.json", "file://private", "a/../private", "a\\private", "./trial-001.json"])
def test_manifest_cannot_read_outside_its_own_directory(tmp_path, name):
    path = manifest(tmp_path, *inputs())
    value = json.loads(path.read_text())
    value["trials"][0]["evidence"] = name
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_study_manifest(path)


def test_manifest_rejects_symlink_and_source_payloads_are_not_in_diagnostics(tmp_path, capsys):
    path = manifest(tmp_path, *inputs())
    link = tmp_path / "link.json"
    link.symlink_to(tmp_path / "trial-001.json")
    value = json.loads(path.read_text())
    value["trials"][0]["evidence"] = "link.json"
    path.write_text(json.dumps(value))
    assert main(["study", "review", str(path)]) == 2
    assert "link.json" not in capsys.readouterr().err


def test_combined_source_budget_and_early_plan_pin(tmp_path, monkeypatch):
    import dspy_security_bench.scan.study as study

    path = manifest(tmp_path, *inputs())
    total = sum((tmp_path / f"trial-{i:03d}.json").stat().st_size for i in range(1, 4))
    monkeypatch.setattr(study, "MAX_BYTES", total - 1)
    with pytest.raises(ValueError, match="combined"):
        load_study_manifest(path)

    def forbidden(*args):
        raise AssertionError("wrong plan pin must reject before reading sources")

    monkeypatch.setattr(study, "_local_source", forbidden)
    with pytest.raises(ValueError, match="retained pin"):
        load_study_manifest(path, "0" * 64)
