"""Execute the collection action's actual isolated review and final gate scripts."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from dspy_security_bench.proofrun_demo import create_collection_demo

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "actions/review-collection"
ACTION = yaml.safe_load((DIRECTORY / "action.yml").read_text())
STEP = next(step for step in ACTION["runs"]["steps"] if step.get("id") == "review")
GATE = ACTION["runs"]["steps"][-1]
SPEC = importlib.util.spec_from_file_location("collection_action", DIRECTORY / "review.py")
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


@pytest.fixture
def fixture(tmp_path):
    result = create_collection_demo(tmp_path / "demo")
    assert result["exit_code"] == 0
    return tmp_path / "demo", result


def environment(tmp_path, plan, pin):
    return {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
            "GITHUB_ACTION_PATH": str(DIRECTORY), "GITHUB_OUTPUT": str(tmp_path / "outputs"),
            "RUNNER_OS": "Linux", "RUNNER_TEMP": str(tmp_path),
            "PROOFRUN_REVIEW_PLAN": str(plan), "PROOFRUN_REVIEW_PIN": pin}


def shell(script, env, cwd):
    return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                          env=env, cwd=cwd, capture_output=True, text=True, timeout=30)


@pytest.mark.skipif(sys.platform == "win32", reason="action explicitly supports Linux bash runners")
@pytest.mark.parametrize("case", [0, 1, 2])
def test_actual_action_retains_failed_reports_and_native_gate(fixture, tmp_path, case):
    source, receipt = fixture
    chosen = receipt["cases"][case]
    env = environment(tmp_path, source / chosen["plan"], chosen["plan_file_sha256"])
    # An intake checkout must not shadow imports, including the standard library.
    (tmp_path / "dspy_security_bench.py").write_text("raise RuntimeError('PRIVATE shadow package executed')")
    (tmp_path / "json.py").write_text("raise RuntimeError('PRIVATE shadow module executed')")
    result = shell(STEP["run"], env, tmp_path)
    assert result.returncode == case, result.stderr
    assert "PRIVATE" not in result.stdout + result.stderr
    outputs = dict(line.split("=", 1) for line in (tmp_path / "outputs").read_text().splitlines())
    assert outputs["report-set-complete"] == "true" and outputs["exit-code"] == str(case)
    report = Path(outputs["report-directory"])
    assert report.parent.parent == tmp_path
    assert set(p.name for p in report.iterdir()) == {"review.json", "review.html", "review.xml", "manifest.json"}
    assert json.loads((report / "review.json").read_bytes())["exit_code"] == case
    assert hashlib.sha256((report / "manifest.json").read_bytes()).hexdigest() == outputs["manifest-file-sha256"]
    gate = shell(GATE["run"], {**env, "PROOFRUN_REVIEW_EXIT": str(case), "PROOFRUN_REVIEW_COMPLETE": "true",
                              "PROOFRUN_REVIEW_OUTCOME": "failure" if case else "success"}, tmp_path)
    assert gate.returncode == case


@pytest.mark.parametrize("key,value", [
    ("PROOFRUN_REVIEW_PIN", ""), ("PROOFRUN_REVIEW_PIN", "A" * 64),
    ("PROOFRUN_REVIEW_PIN", "0" * 64 + "\nforged=true"),
    ("PROOFRUN_REVIEW_PLAN", ""), ("PROOFRUN_REVIEW_PLAN", "private\ninput"),
    ("RUNNER_TEMP", ""), ("RUNNER_TEMP", "relative"), ("RUNNER_TEMP", "/tmp/*"),
    ("RUNNER_TEMP", "/tmp/!excluded"), ("RUNNER_OS", "Windows"),
])
def test_bad_environment_rejected_before_review_or_output_creation(tmp_path, monkeypatch, key, value):
    env = environment(tmp_path, "missing.json", "0" * 64)
    env[key] = value
    monkeypatch.setattr(ADAPTER, "export_collection_reports", lambda *a, **k: pytest.fail("unexpected native review"))
    code, result = ADAPTER.run(env)
    assert code == 2 and result == {"exit-code": "2", "report-set-complete": "false"}
    assert not list(tmp_path.iterdir())


def test_wrong_pin_keeps_complete_invalid_plan_report(fixture, tmp_path):
    source, _ = fixture
    code, outputs = ADAPTER.run(environment(tmp_path, source / "recipient/collection-plan.json", "0" * 64))
    assert code == 2 and outputs["report-set-complete"] == "true"
    reviewed = json.loads((Path(outputs["report-directory"]) / "review.json").read_bytes())
    assert reviewed["entries"] == []


@pytest.mark.parametrize("failure", ["partial", "exception"])
def test_partial_exports_or_runtime_errors_never_expose_upload_paths(tmp_path, monkeypatch, failure):
    def broken(*a, **k):
        if failure == "exception":
            raise RuntimeError("PRIVATE diagnostics")
        return {"exit_code": 2, "report_set_complete": False}
    monkeypatch.setattr(ADAPTER, "export_collection_reports", broken)
    code, outputs = ADAPTER.run(environment(tmp_path, "missing.json", "0" * 64))
    assert code == 2 and outputs == {"exit-code": "2", "report-set-complete": "false"}


@pytest.mark.skipif(sys.platform == "win32", reason="action explicitly supports Linux bash runners")
@pytest.mark.parametrize("code,complete,outcome", [("", "", "skipped"), ("0", "true", "failure"),
                                                   ("0", "false", "success"), ("17", "true", "success"),
                                                   ("$(touch INJECTED)", "true", "success")])
def test_actual_final_gate_fails_closed(tmp_path, code, complete, outcome):
    env = {**os.environ, "PROOFRUN_REVIEW_EXIT": code, "PROOFRUN_REVIEW_COMPLETE": complete,
           "PROOFRUN_REVIEW_OUTCOME": outcome}
    assert shell(GATE["run"], env, tmp_path).returncode == 2
    assert not (tmp_path / "INJECTED").exists()


def test_action_has_no_caller_install_upload_or_approval_permissions():
    steps = ACTION["runs"]["steps"]
    assert set(ACTION["inputs"]) == {"plan", "expected-plan-file-sha256"}
    assert STEP["continue-on-error"] is True
    assert GATE["if"] == "${{ !cancelled() }}"
    assert all("${{" not in step.get("run", "") for step in steps)
    text = (DIRECTORY / "action.yml").read_text()
    assert "upload-artifact" not in text and "attestations: write" not in text
    assert 'python -I -m pip install "$GITHUB_ACTION_PATH/../.."' in text
    assert "pip install -e" not in text


@pytest.mark.skipif(sys.platform == "win32", reason="action explicitly supports Linux bash runners")
def test_plan_shell_metacharacters_are_literal_data(fixture, tmp_path):
    source, result = fixture
    name = "$(touch INJECTED);'plan.json"
    plan = source / "recipient" / name
    plan.write_bytes((source / "recipient/collection-plan.json").read_bytes())
    env = environment(tmp_path, plan, result["cases"][0]["plan_file_sha256"])
    env["PYTHONPATH"] = str(tmp_path)  # -I must also ignore this import path.
    (tmp_path / "json.py").write_text("raise RuntimeError('PRIVATE shadow module')")
    reviewed = shell(STEP["run"], env, tmp_path)
    assert reviewed.returncode == 0, reviewed.stderr
    assert not (tmp_path / "INJECTED").exists()
    assert name not in reviewed.stdout + reviewed.stderr


def test_hosted_smoke_covers_all_outcomes_without_secrets_or_write_permissions():
    workflow = yaml.safe_load((ROOT / ".github/workflows/collection-review-smoke.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["review"]
    assert job["strategy"]["matrix"]["case"] == [0, 1, 2]
    assert job["timeout-minutes"] == 10
    action = next(step for step in job["steps"] if step.get("id") == "review")
    assert action["uses"] == "./actions/review-collection"
    assert "expected-plan-file-sha256" in action["with"]
    assert "continue-on-error" not in job["steps"][-1]
    assert job["steps"][-1]["if"] == "${{ !cancelled() }}"
    for step in job["steps"]:
        assert "${{" not in step.get("run", "")
