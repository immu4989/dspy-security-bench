from pathlib import Path

from dspy_security_bench.cli import main
from dspy_security_bench.scaffold import initialize_project


def test_init_creates_ready_to_run_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--model", "anthropic/claude-sonnet-4-5"]) == 0

    config = (tmp_path / ".dspy-security-bench.yaml").read_text()
    workflow = (tmp_path / ".github/workflows/injection-scan.yml").read_text()
    assert "model: anthropic/claude-sonnet-4-5" in config
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
    assert "import: my_agent:build" in (tmp_path / ".dspy-security-bench.yaml").read_text()
    workflow = (tmp_path / ".github/workflows/injection-scan.yml").read_text()
    assert "pip install -e ." in workflow


def test_umbrella_cli_dispatches_policy_profiles(capsys):
    assert main(["policy", "profiles"]) == 0
    assert "customer-support" in capsys.readouterr().out


def test_umbrella_cli_dispatches_impact_describe(capsys):
    assert main(["impact", "describe"]) == 0
    assert "ImpactTwin / ProcureBench" in capsys.readouterr().out
