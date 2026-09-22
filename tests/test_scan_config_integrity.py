import pytest

from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import ScanConfig


@pytest.mark.parametrize(
    "yaml",
    [
        "agent: {model: fixture}\ngate: {min_security: 0.9, min_security: 0}\n",
        "agent: {model: fixture}\ngate: {require_baseline_coverage: true, require_baseline_coverage: false}\n",
        "agent: {model: fixture}\nagent: {model: other}\n",
        "agent: {model: fixture}\ngate: {<<: {min_security: 0.9}, min_security: 0}\n",
    ],
)
def test_duplicate_yaml_settings_are_rejected(tmp_path, yaml):
    path = tmp_path / "config.yaml"
    path.write_text(yaml)
    with pytest.raises(ValueError, match="duplicate YAML"):
        ScanConfig.load(path)


@pytest.mark.parametrize(
    "value",
    [
        {"gates": {}},
        {"gate": {"min_securty": 0.99}},
        {"scan": {"attack": "direct"}},
        {"agent": {"model": "fixture", "secret-unknown-key": "private-value"}},
        {"report": {"format": "json"}},
        {"scan": []},
        {"gate": 0},
        {"report": False},
        [],
        "private-value",
        0,
    ],
)
def test_unknown_or_wrongly_typed_configuration_does_not_silently_default(value):
    with pytest.raises(ValueError) as caught:
        ScanConfig.from_dict(value)
    assert "secret-unknown-key" not in str(caught.value)
    assert "private-value" not in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b"private-value: [",
        b"agent: \xff",
        b"agent: !!python/object:private-value {}",
        b"x" * 1_000_001,
    ],
)
def test_loader_errors_do_not_echo_source_contents(tmp_path, raw):
    path = tmp_path / "config.yaml"
    path.write_bytes(raw)
    with pytest.raises(ValueError) as caught:
        ScanConfig.load(path)
    assert "private-value" not in str(caught.value)


@pytest.mark.parametrize("formats", ["json", [], ["json", "json"], [None]])
def test_report_formats_must_be_explicit_unique_names(formats):
    config = ScanConfig.from_dict({"agent": {"model": "fixture"}, "report": {"formats": formats}})
    with pytest.raises(ValueError, match="report.formats"):
        config.validate()


def test_duplicate_config_fails_cli_before_planning(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.yaml"
    path.write_text("agent: {model: fixture}\ngate: {min_security: 0.9, min_security: 0}")

    def forbidden(*args, **kwargs):
        pytest.fail("ambiguous config must not begin planning")

    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_plan", forbidden)
    assert main(["--config", str(path), "--plan"]) == 2
    assert "duplicate YAML" in capsys.readouterr().err


def test_safe_yaml_alias_without_overrides_remains_supported(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "agent: {model: fixture}\nscan: {attacks: [direct], defenses: [none]}\ngate: {min_security: &rate 0.9, max_regression: *rate}\nreport: {formats: [json]}"
    )
    config = ScanConfig.load(path)
    config.validate()
    assert config.scan.attacks == ["direct"]
    assert config.gate.min_security == config.gate.max_regression == 0.9


@pytest.mark.parametrize("label", ["agent\nforged verdict", "\x1b[2Jagent", "a" * 513, "\u202eagent", "agent\x00"])
@pytest.mark.parametrize("section,key", [("agent", "name"), ("agent", "model"), ("scan", "attacks"), ("scan", "defenses"), ("scan", "suites")])
def test_control_or_unbounded_identity_labels_are_rejected_without_echo(label, section, key):
    values = {"agent": {"model": "fixture"}}
    values.setdefault(section, {})[key] = [label] if section == "scan" else label
    cfg = ScanConfig.from_dict(values)
    with pytest.raises(ValueError) as caught:
        cfg.validate()
    assert label not in str(caught.value)


def test_printable_unicode_names_remain_supported():
    cfg = ScanConfig.from_dict({"agent": {"model": "fixture", "name": "équipe-研究"}})
    cfg.validate()
