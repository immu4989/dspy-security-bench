"""Independently retained plan pins stop drift before agent construction."""

import json

import pytest

from dspy_security_bench.scan.cli import main


def plan(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("review or mismatched pin must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    config = tmp_path / "scan.yaml"
    config.write_text("agent: {model: fixture, name: stable}\nscan: {attacks: [direct]}\n")
    output = tmp_path / "plan.json"
    assert main(["--config", str(config), "--plan-json", str(output)]) == 0
    return config, json.loads(output.read_text())


@pytest.mark.parametrize("override", [
    ["--agent-model", "other-model"], ["--user-tasks", "2"],
    ["--min-security", "0.5"], ["--fail-on", "never"],
    ["--defenses", "security_prompt"], ["--attacks", "dos"],
    ["--min-runs", "2"], ["--confidence", "0.9"],
])
def test_changed_selection_or_policy_rejects_before_agent(tmp_path, monkeypatch, override):
    config, payload = plan(tmp_path, monkeypatch)
    assert payload["protocol_version"] == "scan-plan-v2"
    assert main(["--config", str(config), "--expected-plan-sha256", payload["report_sha256"], *override]) == 2


def test_same_plan_allows_review_with_different_output_location(tmp_path, monkeypatch):
    config, payload = plan(tmp_path, monkeypatch)
    output = tmp_path / "second.json"
    assert main(["--config", str(config), "--expected-plan-sha256", payload["report_sha256"],
                 "--plan-json", str(output)]) == 0
    assert json.loads(output.read_text()) == payload


def test_same_plan_reaches_agent_construction(tmp_path, monkeypatch):
    config, payload = plan(tmp_path, monkeypatch)
    calls = []

    def stop_at_agent(spec):
        calls.append(spec.model)
        raise RuntimeError("test stops before execution")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", stop_at_agent)
    assert main(["--config", str(config), "--expected-plan-sha256", payload["report_sha256"]]) == 2
    assert calls == ["fixture"]


def test_changed_baseline_snapshot_rejects_before_agent(tmp_path, monkeypatch):
    config, _ = plan(tmp_path, monkeypatch)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"security_by_cell": {"workspace|stable|none|direct": 1.0}}))
    reviewed = tmp_path / "regression-plan.json"
    args = ["--config", str(config), "--baseline", str(baseline)]
    assert main([*args, "--plan-json", str(reviewed)]) == 0
    digest = json.loads(reviewed.read_text())["report_sha256"]
    baseline.write_text(json.dumps({"security_by_cell": {"workspace|stable|none|direct": 0.5}}))
    assert main([*args, "--expected-plan-sha256", digest]) == 2


@pytest.mark.parametrize("digest", ["", "0" * 63, "A" * 64, "not-a-digest"])
def test_bad_pin_fails_before_planning(tmp_path, monkeypatch, digest):
    def forbidden(*args, **kwargs):
        pytest.fail("malformed pin must fail before planning")

    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_plan", forbidden)
    assert main(["--agent-model", "fixture", "--expected-plan-sha256", digest]) == 2
