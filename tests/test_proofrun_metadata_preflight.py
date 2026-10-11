"""Bad declarations must not spend evaluation calls or produce invalid bundles."""

from copy import deepcopy

import pytest

import dspy_security_bench.proofrun_cli as cli
from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.policy import ToolPolicy
from dspy_security_bench.procurement.agents import build_bounded_reference
from dspy_security_bench.procurement.control_registry import (
    create_control_submission_bundle,
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.repeat import (
    create_submission_bundle,
    verify_submission_bundle,
)
from dspy_security_bench.procurement.submission_metadata import prepare_submission_metadata
from dspy_security_bench.proofrun import capture_provenance
from tests.test_control_twin import _procurement_policy
from tests.test_proofrun import GITHUB_ENV
from tests.test_proofrun_output_preflight import arguments


@pytest.mark.parametrize("family", ["run", "control", "incident", "source", "authority"])
@pytest.mark.parametrize("change", [
    {"submitter": None}, {"submitter": True}, {"submitter": "  "},
    {"notes": []}, {"notes": "PRIVATE\ud800"},
    {"agent_source_url": "https://user:PRIVATE@example.com/repo"},
    {"agent_source_url": "https://example.com:PRIVATE/repo"},
    {"agent_source_url": "https://"}, {"agent_source_url": []},
    {"provenance": []}, {"provenance": {}},
    {"provenance": {"provider": "PRIVATE"}},
    {"provenance": {"provider": "local", "builder_kind": "PRIVATE", "runner_environment": "local"}},
    {"provenance": {"provider": "local", "builder_kind": "local_process", "runner_environment": []}},
    {"provenance": {**capture_provenance(GITHUB_ENV), "commit_sha": "PRIVATE"}},
    {"provenance": {**capture_provenance(GITHUB_ENV), "workflow_sha": "PRIVATE"}},
    {"provenance": {**capture_provenance(GITHUB_ENV), "PRIVATE": "PRIVATE"}},
])
def test_creators_reject_metadata_before_report_replay(family, change, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid metadata reached report replay")

    import dspy_security_bench.procurement.control_registry as registry
    import dspy_security_bench.procurement.repeat as repeat
    from dspy_security_bench.authority import repeat as authority
    from dspy_security_bench.incident import repeat as incident
    from dspy_security_bench.mission import repeat as source

    monkeypatch.setattr(repeat, "validate_repeat_payload", forbidden)
    monkeypatch.setattr(registry, "verify_repeat_control_report", forbidden)
    monkeypatch.setattr(incident, "verify_repeat_incident_report", forbidden)
    monkeypatch.setattr(source, "verify_repeat_source_report", forbidden)
    monkeypatch.setattr(authority, "verify_repeat_authority_report", forbidden)
    kwargs = {"submitter": "synthetic", "agent_source_url": "https://example.com/agent", **deepcopy(change)}
    create = create_submission_bundle
    if family == "control":
        kwargs["policy_source_url"] = "https://example.com/policy"
        create = create_control_submission_bundle
    elif family == "incident":
        create = incident.create_incident_submission_bundle
    elif family == "source":
        create = source.create_source_submission_bundle
    elif family == "authority":
        kwargs["adapter_source_url"] = kwargs.pop("agent_source_url")
        create = authority.create_authority_submission_bundle
    with pytest.raises(ValueError) as error:
        create({}, **kwargs)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("command", ["run", "control", "incident", "source", "authority"])
@pytest.mark.parametrize("bad", ["submitter", "agent-source", "notes", "github", "local"])
def test_cli_rejects_before_agent_policy_or_callback_loading(command, bad, tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid metadata reached user code or policy loading")

    monkeypatch.setattr(cli, "_agent_factory", forbidden)
    monkeypatch.setattr(cli, "_authority_adapter_factory", forbidden)
    monkeypatch.setattr(cli, "_resolve_callable", forbidden)
    monkeypatch.setattr("dspy_security_bench.mission.loader.load_mission_pack", forbidden)
    monkeypatch.setattr(ToolPolicy, "load", forbidden)
    provenance = capture_provenance({})
    args = arguments(command, tmp_path / "bundle.json", tmp_path / "report.json")
    if bad == "github":
        provenance = capture_provenance({"GITHUB_ACTIONS": "true", "GITHUB_SHA": "PRIVATE"})
    elif bad == "local":
        provenance["runner_environment"] = "PRIVATE"
    elif bad == "notes":
        args += ["--notes", "PRIVATE\ud800"]
    else:
        if bad == "agent-source" and command == "authority":
            bad = "adapter-source"
        args[args.index("--" + bad) + 1] = " " if bad == "submitter" else "https://user:PRIVATE@example.com/agent"
    monkeypatch.setattr(cli, "capture_provenance", lambda: provenance)
    assert cli.main(args) == 2
    assert not list(tmp_path.iterdir())
    output = capsys.readouterr()
    assert "PRIVATE" not in output.out + output.err
    assert "metadata" in output.err


def test_control_policy_source_preflight(tmp_path, monkeypatch, capsys):
    def forbidden(*args):
        pytest.fail("invalid policy source reached execution")

    monkeypatch.setattr(cli, "_agent_factory", forbidden)
    monkeypatch.setattr(cli, "capture_provenance", lambda: capture_provenance({}))
    args = arguments("control", tmp_path / "bundle.json")
    args[args.index("--policy-source") + 1] = "https://user:PRIVATE@example.com/policy"
    assert cli.main(args) == 2
    assert not list(tmp_path.iterdir())
    assert "PRIVATE" not in capsys.readouterr().err


@pytest.mark.parametrize("command", ["run", "control", "incident", "source", "authority"])
@pytest.mark.parametrize("github", [False, True])
def test_real_execution_keeps_preflight_provenance_snapshot(command, github, tmp_path, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        pytest.fail("synthetic run attempted network access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    expected = capture_provenance(GITHUB_ENV if github else {})
    live = deepcopy(expected)
    captures = []

    def capture():
        captures.append(True)
        return live

    def load_agent(args):
        live.clear()  # Simulate user code altering the environment after capture.
        live.update(provider="PRIVATE")
        if command == "incident":
            from tests.test_incident_twin import build_community_incident_agent
            return build_community_incident_agent
        if command == "source":
            from tests.test_missionforge import build_community_source_agent
            return build_community_source_agent
        if command == "authority":
            from tests.test_authoritytwin import build_community_authority_adapter
            return build_community_authority_adapter
        return build_bounded_reference

    monkeypatch.setattr(cli, "capture_provenance", capture)
    monkeypatch.setattr(cli, "_agent_factory", load_agent)
    monkeypatch.setattr(cli, "_authority_adapter_factory", load_agent)
    monkeypatch.setattr(ToolPolicy, "load", lambda *args: _procurement_policy())
    output = tmp_path / "bundle.json"
    assert cli.main(arguments(command, output)) in (0, 1)
    assert len(captures) == 1
    bundle = read_json_object(output, 50_000_000)
    assert bundle["provenance"] == expected
    verify = verify_control_submission_bundle if command == "control" else verify_submission_bundle
    if command == "incident":
        from dspy_security_bench.incident.repeat import verify_incident_submission_bundle
        verify = verify_incident_submission_bundle
    elif command == "source":
        from dspy_security_bench.mission.repeat import verify_source_submission_bundle
        verify = verify_source_submission_bundle
    elif command == "authority":
        from dspy_security_bench.authority.repeat import verify_authority_submission_bundle
        verify = verify_authority_submission_bundle
    result = verify(bundle)
    assert result.valid, result.errors
    assert result.evidence_tier == ("github_attestation_unverified" if github else "self_attested")


@pytest.mark.parametrize("provenance", [None, capture_provenance({}), capture_provenance(GITHUB_ENV)])
def test_preparation_is_only_metadata_and_does_not_modify_input(provenance):
    original = deepcopy(provenance)
    metadata = prepare_submission_metadata(
        submitter=" synthetic ", agent_source_url="https://example.com/agent",
        notes=" note ", provenance=provenance,
    )
    assert provenance == original
    assert not {"report", "report_sha256", "bundle_sha256", "bundle_type"} & metadata.keys()
    assert metadata["submission"]["submitter"] == "synthetic"
    assert metadata["submission"]["notes"] == "note"
    assert metadata["bundle_schema_version"] == (1 if provenance is None else 2)
