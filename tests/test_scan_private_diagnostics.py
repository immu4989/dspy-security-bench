"""Scan-owned execution diagnostics do not expose provider exception payloads."""

import pytest

from dspy_security_bench.scan.cli import main


@pytest.mark.parametrize("phase", ["construction", "execution"])
def test_private_exception_text_is_not_printed_or_exported(tmp_path, monkeypatch, capsys, phase):
    sensitive = "fictional-private-prompt tenant=private-example token=not-a-real-key"

    def fail(*args, **kwargs):
        raise RuntimeError(sensitive)

    if phase == "construction":
        monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", fail)
    else:
        monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda *args: object())
        monkeypatch.setattr("dspy_security_bench.runner.evaluate_agents", fail)
    report = tmp_path / "report.json"
    evidence = tmp_path / "evidence.json"
    assert main(["--agent-model", "fixture", "--json", str(report), "--evidence-json", str(evidence)]) == 2
    captured = capsys.readouterr()
    assert sensitive not in captured.out + captured.err
    assert "RuntimeError" in captured.err
    assert "withheld" in captured.err
    assert not report.exists() and not evidence.exists()
