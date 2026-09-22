from pathlib import Path

import pytest
import yaml

from dspy_security_bench.cli import main
from dspy_security_bench.scaffold import initialize_project


def test_init_creates_ready_to_run_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--model", "anthropic/claude-sonnet-4-5"]) == 0

    config = (tmp_path / ".dspy-security-bench.yaml").read_text()
    workflow = (tmp_path / ".github/workflows/injection-scan.yml").read_text()
    assert yaml.safe_load(config)["agent"]["model"] == "anthropic/claude-sonnet-4-5"
    assert "ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}" in workflow
    assert "--plan" in workflow
    assert "upload-sarif" in workflow


def test_init_preserves_existing_files_unless_forced(tmp_path):
    config = tmp_path / ".dspy-security-bench.yaml"
    config.write_text("user-owned\n")
    result = initialize_project(tmp_path, include_workflow=False)
    assert result.created == ()
    assert result.skipped == (Path(config),)
    assert config.read_text() == "user-owned\n"

    result = initialize_project(tmp_path, include_workflow=False, force=True)
    assert result.created == (Path(config),)
    assert "agent:" in config.read_text()


def test_init_supports_custom_agent_factory(tmp_path):
    initialize_project(tmp_path, agent_import="my_agent:build")
    assert yaml.safe_load((tmp_path / ".dspy-security-bench.yaml").read_text())["agent"]["import"] == "my_agent:build"
    workflow = (tmp_path / ".github/workflows/injection-scan.yml").read_text()
    assert "pip install -e ." in workflow
    assert "secrets.OPENAI_API_KEY" not in workflow


@pytest.mark.parametrize("model", ["null", "yes", "123", "provider/model # comment", 'provider/"model"'])
def test_init_preserves_model_as_literal_yaml_string(tmp_path, model):
    initialize_project(tmp_path, model=model, include_workflow=False)
    assert yaml.safe_load((tmp_path / ".dspy-security-bench.yaml").read_text())["agent"]["model"] == model


@pytest.mark.parametrize("settings", [
    {"model": ""}, {"model": "x\nfail_on: never"}, {"model": "x\x00"},
    {"model": "a" * 513}, {"agent_import": "pkg:fn\nother: value"},
    {"agent_import": "pkg:fn:extra"}, {"agent_import": "../pkg:fn"},
])
def test_init_rejects_invalid_values_before_writing(tmp_path, settings):
    with pytest.raises(ValueError):
        initialize_project(tmp_path, **settings)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("target", ["file-link", "parent-link", "parent-file", "output-directory"])
def test_init_preflights_all_targets_without_following_links(tmp_path, force, target):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original = outside / "original"
    original.write_text("retained")
    if target == "file-link":
        (root / ".dspy-security-bench.yaml").symlink_to(original)
    elif target == "parent-link":
        (root / ".github").symlink_to(outside, target_is_directory=True)
    elif target == "parent-file":
        (root / ".github").write_text("retained")
    else:
        (root / ".dspy-security-bench.yaml").mkdir()
    with pytest.raises(ValueError):
        initialize_project(root, force=force)
    assert original.read_text() == "retained"
    assert not (outside / "workflows").exists()
    if target in {"parent-link", "parent-file"}:
        assert not (root / ".dspy-security-bench.yaml").exists()


def test_init_force_does_not_change_other_hardlink(tmp_path):
    original = tmp_path / "retained"
    original.write_text("retained")
    (tmp_path / ".dspy-security-bench.yaml").hardlink_to(original)
    with pytest.raises(ValueError, match="multiply linked"):
        initialize_project(tmp_path, force=True)
    assert original.read_text() == "retained"


@pytest.mark.parametrize("automatic", [False, True])
def test_init_pr_trigger_requires_explicit_opt_in(tmp_path, automatic):
    initialize_project(tmp_path, on_pull_request=automatic)
    workflow = (tmp_path / ".github/workflows/injection-scan.yml").read_text()
    assert ("  pull_request:" in workflow) is automatic
    assert "  workflow_dispatch:" in workflow


def test_init_cli_handles_bad_input_with_no_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--agent", "bad import"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_umbrella_cli_dispatches_policy_profiles(capsys):
    assert main(["policy", "profiles"]) == 0
    assert "customer-support" in capsys.readouterr().out


def test_umbrella_cli_dispatches_impact_describe(capsys):
    assert main(["impact", "describe"]) == 0
    assert "ImpactTwin / ProcureBench" in capsys.readouterr().out
