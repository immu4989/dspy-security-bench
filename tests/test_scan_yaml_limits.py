"""Hostile scan configuration must fail before agent construction."""
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

from dspy_security_bench.scan import yaml_config
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import ScanConfig


@pytest.mark.parametrize("payload", [
    "gate: {<<: {min_security: 0.9}}",
    "scan: {attacks: &items [direct], defenses: *items}",
    "scan: &recursive {attacks: *recursive}",
    "gate: {min_security: *unknown}",
    "gate: {min_security: .nan}",
    "gate: {min_security: -.inf}",
    "gate: {min_security: 1.0e+999}",
    "agent: {name: 2026-09-28}",
    "agent: {name: !!binary c2VjcmV0}",
    "agent: {name: !!set {secret: null}}",
    "agent: {name: !!python/object:private-value {}}",
    'agent: {name: "\\uD800"}',
    "gate: {min_security: !!float private-value}",
    "gate: {min_security: !!int private-value}",
    "gate: {min_security: !!bool private-value}",
    "gate: {min_security: " + "9" * 129 + "}",
    "gate: {min_security: " + "[" * 51 + "0" + "]" * 51 + "}",
    "scan: {attacks: [" + "direct," * 10_001 + "]}",
    "? [private-value]\n: secret",
], ids=[
    "merge-key", "container-alias", "recursive-alias", "unknown-alias", "nan", "negative-infinity",
    "overflow-float", "implicit-date", "binary", "set", "python-object", "unpaired-surrogate",
    "invalid-float", "invalid-int", "invalid-bool", "oversized-number", "excessive-depth",
    "excessive-nodes", "non-scalar-key",
])
def test_hostile_yaml_is_rejected_before_planning(tmp_path, monkeypatch, capsys, payload):
    path = tmp_path / "config.yaml"
    path.write_text(payload)

    def forbidden(*args, **kwargs):
        pytest.fail("invalid configuration reached planning")

    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_plan", forbidden)
    assert main(["--config", str(path), "--plan", "--fail-on", "never"]) == 2
    assert "private-value" not in capsys.readouterr().err


@pytest.mark.parametrize("literal", ["!!int private-value", "!!float private-value", "!!bool private-value", "["])
def test_loader_traceback_does_not_expose_yaml_source(tmp_path, literal):
    path = tmp_path / "config.yaml"
    path.write_text("gate: {min_security: " + literal + "}")
    with pytest.raises(ValueError) as caught:
        ScanConfig.load(path)
    assert "private-value" not in "".join(traceback.format_exception(caught.value))


def test_depth_limit_is_inclusive(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("agent: {model: fixture}")
    monkeypatch.setattr(yaml_config, "MAX_DEPTH", 3)
    assert ScanConfig.load(path).agent.model == "fixture"
    monkeypatch.setattr(yaml_config, "MAX_DEPTH", 2)
    with pytest.raises(ValueError, match="nesting"):
        ScanConfig.load(path)


def test_node_limit_counts_alias_references(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("agent: {model: &model fixture, name: *model}")
    monkeypatch.setattr(yaml_config, "MAX_NODES", 7)
    assert ScanConfig.load(path).agent.name == "fixture"
    monkeypatch.setattr(yaml_config, "MAX_NODES", 6)
    with pytest.raises(ValueError, match="node limit"):
        ScanConfig.load(path)


def test_byte_limit_is_inclusive(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    payload = b"agent: {model: fixture}"
    path.write_bytes(payload)
    monkeypatch.setattr(yaml_config, "MAX_BYTES", len(payload))
    assert ScanConfig.load(path).agent.model == "fixture"
    path.write_bytes(payload + b" ")
    with pytest.raises(ValueError, match="exceeds"):
        ScanConfig.load(path)


def test_quoted_date_and_scalar_alias_are_supported(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('agent: {model: fixture, name: "2026-09-28"}\ngate: {min_security: &rate 0.9, max_regression: *rate}')
    config = ScanConfig.load(path)
    config.validate()
    assert config.gate.min_security == config.gate.max_regression == 0.9


def test_loader_registration_does_not_mutate_global_safe_loader():
    import yaml
    assert yaml.safe_load("x: [1, 2]\ny: 2026-09-28")["y"].year == 2026


def test_hostile_payloads_do_not_become_oversized_pytest_environment_variables():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/test_scan_yaml_limits.py"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    node_ids = [line for line in result.stdout.splitlines() if line.startswith("tests/")]
    assert node_ids
    # Pytest stores node IDs in PYTEST_CURRENT_TEST at setup/call/teardown.
    # Windows rejects values over 32,767 characters; keep generous headroom.
    assert max(map(len, node_ids)) < 256
    assert any("excessive-nodes" in node for node in node_ids)
