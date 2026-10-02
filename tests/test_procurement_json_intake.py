"""Retained procurement evidence must have one unambiguous bounded JSON meaning."""

import importlib
import io
import json
from types import SimpleNamespace

import pytest

from dspy_security_bench.procurement import cli
from dspy_security_bench.procurement.repeat import create_submission_bundle, run_repeat_twin
from tests.test_repeat_twin import build_community_agent

COMMANDS = [
    ("control-verify", "control_twin.verify_control_report", 2),
    ("control-repeat-verify", "repeat_control.verify_repeat_control_report", 2),
    ("control-submit", "control_registry.create_control_submission_bundle", 2),
    ("control-submission-verify", "control_registry.verify_control_submission_bundle", 1),
    ("control-card", "control_registry.render_control_evidence_card_svg", 2),
    ("explain", "evidence.render_evidence_payload", 2),
    ("submit-result", "repeat.create_submission_bundle", 2),
    ("verify", "repeat.verify_submission_bundle", 1),
]


def arguments(command, source, output):
    args = [command, str(source)]
    if command in {"control-card", "control-submit", "submit-result"}:
        args += ["--out", str(output)]
    if command in {"control-submit", "submit-result"}:
        args += ["--submitter", "fixture", "--agent-source", "https://example.com/fixture"]
    if command == "control-submit":
        args += ["--policy-source", "https://example.com/policy"]
    return args


@pytest.mark.parametrize("command,native,exit_code", COMMANDS)
@pytest.mark.parametrize("raw", [
    b'{"private-value":1,"private-value":2}',
    b'{"outer":{"private-value":1,"private-value":2}}',
    b'{"private-value":NaN}',
    b'{"private-value":1e999}',
    b'{"private-value":"\\ud800"}',
    b'{"private-value":"\xff"}',
    b'[]',
    b'{"private-value":' + b'[' * 110 + b'0' + b']' * 110 + b'}',
    b'{"private-value":' + b'9' * 129 + b'}',
])
def test_every_retained_evidence_command_rejects_ambiguity_before_native_work(
    tmp_path, monkeypatch, capsys, command, native, exit_code, raw,
):
    source, output = tmp_path / "input.json", tmp_path / "output"
    source.write_bytes(raw)
    module, name = native.split(".")

    def unexpected(*args, **kwargs):
        pytest.fail("invalid JSON reached native verification or rendering")

    monkeypatch.setattr(importlib.import_module(f"dspy_security_bench.procurement.{module}"), name, unexpected)
    assert cli.main(arguments(command, source, output)) == exit_code
    assert not output.exists()
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err


@pytest.mark.parametrize("command,native,exit_code", COMMANDS)
def test_each_command_enforces_the_shared_byte_limit(tmp_path, monkeypatch, command, native, exit_code):
    monkeypatch.setattr(cli, "MAX_EVIDENCE_BYTES", 8)
    source, output = tmp_path / "input.json", tmp_path / "output"
    source.write_text('{"value":"too long"}')
    assert cli.main(arguments(command, source, output)) == exit_code
    assert not output.exists()


def test_reader_requests_only_one_byte_beyond_its_limit(monkeypatch):
    reads = []

    class TrackingStream(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    path = SimpleNamespace(open=lambda mode: TrackingStream(b'{"ok":true}'))
    monkeypatch.setattr(cli, "MAX_EVIDENCE_BYTES", 20)
    assert cli._read_evidence(path) == {"ok": True}
    assert reads == [21]


@pytest.mark.parametrize("command,native,exit_code", COMMANDS)
def test_caught_native_exceptions_do_not_echo_source_content(
    tmp_path, monkeypatch, capsys, command, native, exit_code,
):
    source, output = tmp_path / "input.json", tmp_path / "output"
    source.write_text('{}')
    module, name = native.split(".")

    def invalid(*args, **kwargs):
        raise ValueError("private-content-must-not-be-printed")

    monkeypatch.setattr(importlib.import_module(f"dspy_security_bench.procurement.{module}"), name, invalid)
    assert cli.main(arguments(command, source, output)) == exit_code
    captured = capsys.readouterr()
    assert "private-content-must-not-be-printed" not in captured.out + captured.err
    assert "ValueError" in captured.err


def test_valid_submission_workflow_and_multi_file_failure_accounting(tmp_path):
    report = run_repeat_twin(build_community_agent(), trials=2, agent_factory=build_community_agent).to_dict()
    source, output = tmp_path / "report.json", tmp_path / "bundle.json"
    source.write_text(json.dumps(report))
    assert cli.main(arguments("submit-result", source, output)) == 0
    assert cli.main(["verify", str(output), "--minimum-trials", "2"]) == 0
    bad = tmp_path / "invalid.json"
    bad.write_text('{"x":1,"x":2}')
    assert cli.main(["verify", str(bad), str(output), "--minimum-trials", "2"]) == 1


def test_duplicate_last_member_cannot_be_blessed_by_hash_of_parsed_object(tmp_path):
    report = run_repeat_twin(build_community_agent(), trials=2).to_dict()
    bundle = create_submission_bundle(report, submitter="fixture", agent_source_url="https://example.com/fixture")
    raw = json.dumps(bundle)
    # Ordinary json.loads would silently retain the second, legitimate member
    # and its digest. The input still has two incompatible interpretations.
    ambiguous = '{"bundle_schema_version":999,' + raw[1:]
    assert json.loads(ambiguous) == bundle
    path = tmp_path / "ambiguous.json"
    path.write_text(ambiguous)
    assert cli.main(["verify", str(path), "--minimum-trials", "2"]) == 1
