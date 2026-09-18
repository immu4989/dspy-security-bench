import json
from copy import deepcopy

import pandas as pd
import pytest

from dspy_security_bench.scan.cli import build_scan_plan, build_scan_scope, main
from dspy_security_bench.scan.config import GateSpec, ScanConfig
from dspy_security_bench.scan.gate import (
    bind_baseline_scope,
    evaluate_gate,
    load_baseline_document,
    verify_baseline_scope,
)


def config():
    return ScanConfig.from_dict(
        {
            "agent": {"model": "fixture", "name": "stable-agent"},
            "scan": {"user_tasks": 2, "injection_tasks": 1},
        }
    )


def scope():
    cfg = config()
    return build_scan_scope(cfg, build_scan_plan(cfg))


def test_scope_binds_task_identity_but_allows_owner_named_model_upgrade():
    cfg = config()
    before = build_scan_scope(cfg, build_scan_plan(cfg))
    cfg.agent.model = "different-provider/model-revision"
    after = build_scan_scope(cfg, build_scan_plan(cfg))
    assert before == after
    assert "model" not in before
    assert before["suites"][0]["user_task_ids"] == ["user_task_0", "user_task_1"]


def test_all_tasks_are_expanded_in_scope_not_left_as_wildcards():
    cfg = config()
    cfg.scan.user_tasks = cfg.scan.injection_tasks = "all"
    result = build_scan_scope(cfg, build_scan_plan(cfg))
    assert result["suites"][0]["user_task_ids"]
    assert result["suites"][0]["attacks"][0]["injection_task_ids"]
    assert None not in result["suites"][0]["user_task_ids"]


@pytest.mark.parametrize("change", ["user", "injection", "attack", "defense", "order", "agent"])
def test_scope_changes_are_rejected_even_with_same_cell_rate(change):
    original = scope()
    candidate = deepcopy(original)
    if change == "user":
        candidate["suites"][0]["user_task_ids"][0] = "user_task_3"
    elif change == "injection":
        candidate["suites"][0]["attacks"][0]["injection_task_ids"] = ["injection_task_1"]
    elif change == "attack":
        candidate["suites"][0]["attacks"][0]["attack"] = "dos"
    elif change == "defense":
        candidate["defenses"] = ["security_prompt"]
    elif change == "order":
        candidate["suites"][0]["user_task_ids"].reverse()
    else:
        candidate["agent_name"] = "another-agent"
    document = bind_baseline_scope({"workspace|stable-agent|none|direct": 1.0}, original)
    with pytest.raises(ValueError, match="scope differs"):
        verify_baseline_scope(document, candidate)


def test_scope_bound_gate_requires_caller_scope_and_reports_successful_match(tmp_path):
    original = scope()
    document = bind_baseline_scope({"workspace|stable-agent|none|direct": 1.0}, original)
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(document))
    frame = pd.DataFrame(
        [
            {
                "agent": "stable-agent",
                "defense": "none",
                "attack": "direct",
                "security_rate": 1.0,
                "injection_success_rate": 0.0,
                "n_runs": 2,
            }
        ]
    )
    gate = GateSpec(mode="regression", baseline=str(path))
    with pytest.raises(ValueError, match="scope differs"):
        evaluate_gate(frame, gate, "workspace")
    result = evaluate_gate(frame, gate, "workspace", scan_scope=original)
    assert result.passed
    assert result.meta["baseline_scope_verified"] is True
    document["scope"]["agent_name"] = "modified"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="digest"):
        load_baseline_document(path)


def test_legacy_baseline_does_not_claim_verified_scope():
    assert verify_baseline_scope({"security_by_cell": {}}, scope()) is False


def test_changed_scope_cli_stops_before_agent_calls(tmp_path, monkeypatch):
    cfg = config()
    original = build_scan_scope(cfg, build_scan_plan(cfg))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(bind_baseline_scope({}, original)))
    yaml = tmp_path / "config.yaml"
    yaml.write_text(
        f"agent:\n  model: fixture\n  name: stable-agent\nscan:\n  user_tasks: 3\ngate:\n  mode: regression\n  baseline: {baseline}\n"
    )

    def forbidden(*args, **kwargs):
        pytest.fail("scope mismatch must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--config", str(yaml)]) == 2
