"""Safe trial bookkeeping preserves plan identity and unfavorable attempts."""
import json
import socket
from copy import deepcopy

import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.study import (
    build_scan_study,
    build_study_plan,
    load_study_manifest,
    record_study_trial,
)


@pytest.fixture
def pending(tmp_path):
    artifacts = build_demo_artifacts()
    source = json.loads(artifacts["before.json"])
    (tmp_path / "source.json").write_text(artifacts["before.json"])
    plan = build_study_plan(source, "fictional-record-test", 3)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "plan": plan,
        "trials": [{"trial_id": name, "status": "missing"} for name in plan["trial_ids"]]}))
    return path, plan


def command(path, *args):
    return ["study", "record", str(path), "--trial", "trial-001", "--status", "complete",
            "--evidence", "source.json", "--out", str(path.with_name("next.json")), *args]


def test_complete_trial_replays_source_and_preserves_original_plan(pending, monkeypatch):
    path, plan = pending
    original = path.read_bytes()

    def offline(*args, **kwargs):
        pytest.fail("record must not access the network")

    monkeypatch.setattr(socket, "create_connection", offline)
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", offline)
    assert main(command(path, "--expected-plan-sha256", plan["plan_sha256"])) == 0
    assert path.read_bytes() == original
    output = path.with_name("next.json")
    new = json.loads(output.read_text())
    assert new["plan"] == plan
    assert new["trials"][1:] == json.loads(original)["trials"][1:]
    assert new["trials"][0]["evidence"] == "source.json"
    report = build_scan_study(*load_study_manifest(output))
    assert report["summary"]["complete_trials"] == 1
    assert report["summary"]["missing_trials"] == 2
    assert not report["summary"]["study_requirements_met"]


def test_error_trial_never_fabricates_binary_measurements(pending):
    path, plan = pending
    result = record_study_trial(path, "trial-002", "execution_error", expected_plan_sha256=plan["plan_sha256"])
    assert result["trials"][1] == {"trial_id": "trial-002", "status": "execution_error"}
    assert result["plan"] == plan
    assert json.loads(path.read_text())["trials"][1]["status"] == "missing"


@pytest.mark.parametrize("status,evidence", [
    ("complete", None), ("execution_error", "source.json"), ("missing", None), ("complete", ""),
])
def test_status_requires_exact_source_shape(pending, status, evidence):
    path, _ = pending
    with pytest.raises(ValueError):
        record_study_trial(path, "trial-001", status, evidence)


@pytest.mark.parametrize("trial", ["unknown", "trial-004", "", "private\nvalue", True, []])
def test_only_planned_identifiers_can_be_recorded(pending, trial):
    path, _ = pending
    with pytest.raises(ValueError):
        record_study_trial(path, trial, "execution_error")


@pytest.mark.parametrize("status", ["complete", "execution_error"])
def test_existing_attempt_cannot_be_replaced_even_with_same_source(pending, status):
    path, _ = pending
    first = record_study_trial(path, "trial-001", status, "source.json" if status == "complete" else None)
    path.write_text(json.dumps(first))
    with pytest.raises(ValueError, match="cannot be replaced"):
        record_study_trial(path, "trial-001", "complete", "source.json")


def test_invalid_pin_stops_before_opening_sources(pending, monkeypatch):
    path, _ = pending

    def forbidden(*args, **kwargs):
        pytest.fail("invalid plan pin reached a source")

    monkeypatch.setattr("dspy_security_bench.scan.study._local_source", forbidden)
    assert main(command(path, "--expected-plan-sha256", "0" * 64)) == 2
    assert not path.with_name("next.json").exists()


@pytest.mark.parametrize("source", ["../source.json", "/source.json", "dir/../source.json", "C:/source.json", "dir\\source.json", "absent.json"])
def test_source_paths_are_confined(pending, source):
    path, _ = pending
    with pytest.raises(ValueError):
        record_study_trial(path, "trial-001", "complete", source)


def test_existing_and_relocated_outputs_are_refused(pending, tmp_path):
    path, _ = pending
    output = path.with_name("next.json")
    output.write_text("keep")
    assert main(command(path)) == 2
    assert output.read_text() == "keep"
    subdir = tmp_path / "other"
    subdir.mkdir()
    args = command(path)
    args[args.index("--out") + 1] = str(subdir / "next.json")
    assert main(args) == 2
    assert not (subdir / "next.json").exists()


@pytest.mark.parametrize("field", ["scope", "policy", "baseline"])
def test_source_must_match_unchanged_study_context(pending, field):
    path, _ = pending
    data = json.loads(path.read_text())
    plan = data["plan"]
    if field == "scope":
        plan["scope"]["agent_name"] = "other-agent"
    else:
        plan[field + "_sha256"] = "0" * 64
    plan["plan_sha256"] = canonical_sha256({k: v for k, v in plan.items() if k != "plan_sha256"})
    path.write_text(json.dumps(data))
    assert main(command(path)) == 2
    assert not path.with_name("next.json").exists()


def test_existing_invalid_trial_cannot_be_hidden_by_recording_another(pending):
    path, _ = pending
    revision = record_study_trial(path, "trial-002", "complete", "source.json")
    revision["trials"][1]["evidence_sha256"] = "0" * 64
    path.write_text(json.dumps(revision))
    assert main(command(path)) == 2


def test_combined_source_byte_budget_applies_to_new_revision(pending, monkeypatch):
    path, _ = pending
    revision = record_study_trial(path, "trial-002", "complete", "source.json")
    path.write_text(json.dumps(revision))
    size = path.with_name("source.json").stat().st_size
    assert path.stat().st_size < size
    monkeypatch.setattr("dspy_security_bench.scan.study.MAX_BYTES", 2 * size - 1)
    assert main(command(path)) == 2
    assert not path.with_name("next.json").exists()


def test_source_symlink_is_refused(pending):
    path, _ = pending
    link = path.with_name("link.json")
    try:
        link.symlink_to("source.json")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="symbolic"):
        record_study_trial(path, "trial-001", "complete", "link.json")


def test_source_change_between_validation_and_retention_is_rejected(pending, monkeypatch):
    path, _ = pending
    import dspy_security_bench.scan.study as study
    original = study.verify_scan_evidence

    def changing(source, *args):
        result = original(source, *args)
        changed = deepcopy(source)
        changed["evidence_sha256"] = "0" * 64
        path.with_name("source.json").write_text(json.dumps(changed))
        return result

    monkeypatch.setattr(study, "verify_scan_evidence", changing)
    assert main(command(path)) == 2
    assert not path.with_name("next.json").exists()
