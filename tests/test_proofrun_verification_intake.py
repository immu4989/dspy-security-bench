"""A review verdict must refer to one bounded, unambiguous input snapshot."""

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

import dspy_security_bench.proofrun as proof
import dspy_security_bench.proofrun_cli as cli
import dspy_security_bench.proofrun_review as reviews
from dspy_security_bench.authority.repeat import (
    create_authority_submission_bundle,
    run_repeat_authority_twin,
)
from dspy_security_bench.incident.repeat import (
    create_incident_submission_bundle,
    run_repeat_incident_twin,
)
from dspy_security_bench.jsonio import read_json_snapshot
from dspy_security_bench.mission.loader import load_mission_pack
from dspy_security_bench.mission.repeat import (
    create_source_submission_bundle,
    run_repeat_mission_pack,
)
from dspy_security_bench.procurement.control_registry import create_control_submission_bundle
from dspy_security_bench.procurement.repeat import create_submission_bundle, run_repeat_twin
from dspy_security_bench.procurement.repeat_control import run_repeat_control_twin
from tests.test_authoritytwin import build_community_authority_adapter
from tests.test_control_registry import _policy, build_community_control_agent
from tests.test_incident_twin import build_community_incident_agent
from tests.test_missionforge import build_community_source_agent
from tests.test_proofrun import GITHUB_ENV, _proof_bundle
from tests.test_repeat_twin import build_community_agent


@pytest.fixture(scope="module", params=["repeat", "control", "incident", "source", "authority"])
def family(request):
    metadata = {"submitter": "synthetic", "agent_source_url": "https://example.com/agent"}
    if request.param == "repeat":
        report = run_repeat_twin(build_community_agent(), trials=2, agent_factory=build_community_agent)
        return create_submission_bundle(report.to_dict(), **metadata)
    if request.param == "control":
        report = run_repeat_control_twin(build_community_control_agent, _policy(), trials=2)
        return create_control_submission_bundle(report.to_dict(), **metadata, policy_source_url="https://example.com/policy")
    if request.param == "incident":
        report = run_repeat_incident_twin(build_community_incident_agent, trials=2)
        return create_incident_submission_bundle(report.to_dict(), **metadata)
    if request.param == "source":
        report = run_repeat_mission_pack(build_community_source_agent, load_mission_pack("source-twin"), trials=2)
        return create_source_submission_bundle(report.to_dict(), **metadata)
    report = run_repeat_authority_twin(build_community_authority_adapter, trials=2)
    return create_authority_submission_bundle(
        report.to_dict(), submitter="synthetic", adapter_source_url="https://example.com/adapter",
    )


@pytest.mark.parametrize("raw", [
    b"[]", b"null", b"true", b"1", b'"PRIVATE"', b'{"PRIVATE":', b'{"PRIVATE":"\xff"}',
    b'{"PRIVATE":1,"PRIVATE":2}', b'{"PRIVATE":{"x":1,"x":2}}',
    b'{"PRIVATE":NaN}', b'{"PRIVATE":Infinity}', b'{"PRIVATE":1e999}',
    b'{"PRIVATE":"\\ud800"}', b'{"PRIVATE":' + b"9" * 129 + b"}",
    b'{"PRIVATE":' + b"[" * 105 + b"0" + b"]" * 105 + b"}",
])
def test_invalid_intake_never_reaches_online_verification(raw, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("invalid input reached gh"))
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    assert cli.main(["verify", str(path)]) == 2
    output = capsys.readouterr()
    assert "PRIVATE" not in output.out + output.err
    assert path.read_bytes() == raw


def test_snapshot_reader_retains_exact_noncanonical_bytes(tmp_path):
    raw = b' { "label" : "caf\xc3\xa9", "flag":false }\n'
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    assert read_json_snapshot(path, len(raw)) == (raw, {"label": "café", "flag": False})
    with pytest.raises(ValueError):
        read_json_snapshot(path, len(raw) - 1)


def test_size_limit_before_native_or_online_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(reviews, "MAX_BUNDLE_BYTES", 16)
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("oversized input reached gh"))
    path = tmp_path / "input.json"
    path.write_bytes(b'{"padding":"' + b"x" * 20 + b'"}')
    assert cli.main(["verify", str(path)]) == 2


def test_all_families_preserve_valid_eligible_and_ineligible_verdicts(family, tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(family), encoding="utf-8")
    assert cli.main(["verify", str(path), "--offline", "--minimum-trials", "2"]) == 0
    assert cli.main(["verify", str(path), "--offline"]) == 1


@pytest.mark.parametrize("mutation", ["extra", "report", "version", "attestation"])
def test_all_families_fail_closed_without_private_diagnostics(family, mutation, tmp_path, capsys):
    changed = deepcopy(family)
    if mutation == "extra":
        changed["PRIVATE-FIELD"] = "PRIVATE"
    elif mutation == "report":
        changed["report"] = {"trials": [{"PRIVATE": "PRIVATE"}]}
    elif mutation == "version":
        changed["bundle_schema_version"] = ["PRIVATE"]
    else:
        changed["submission"]["attestation"] = ["PRIVATE"]
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(changed), encoding="utf-8")
    assert cli.main(["verify", str(path), "--offline", "--minimum-trials", "2"]) == 2
    output = capsys.readouterr()
    assert "PRIVATE" not in output.out + output.err


def test_file_pin_covers_formatting_not_only_canonical_content(family, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    raw = json.dumps(family, indent=2).encode()
    path.write_bytes(raw)
    pin = hashlib.sha256(raw).hexdigest()
    args = ["verify", str(path), "--offline", "--minimum-trials", "2", "--expected-file-sha256", pin]
    assert cli.main(args) == 0
    assert pin in capsys.readouterr().out
    path.write_bytes(raw + b"\n")
    assert cli.main(args) == 2
    assert "independent pin" in capsys.readouterr().err


@pytest.fixture
def attested(tmp_path, monkeypatch):
    bundle = _proof_bundle()
    raw = json.dumps(bundle, indent=2).encode()
    path = tmp_path / "bundle.json"
    path.write_bytes(raw)
    certificate = {
        "sourceRepositoryURI": "https://github.com/example/agent",
        "sourceRepositoryDigest": GITHUB_ENV["GITHUB_SHA"],
        "sourceRepositoryRef": GITHUB_ENV["GITHUB_REF"],
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": bundle["provenance"]["run_url"],
    }
    result = {"verificationResult": {"signature": {"certificate": certificate}}}
    monkeypatch.setattr(proof.shutil, "which", lambda *args: "/synthetic/gh")
    return path, raw, bundle, result


def test_native_and_online_verdicts_use_same_snapshot_when_source_changes(attested, monkeypatch):
    import dspy_security_bench.procurement.repeat as repeat

    path, raw, _, result = attested
    native = repeat.verify_submission_bundle
    snapshots = []

    def verify_then_replace(bundle, **kwargs):
        verdict = native(bundle, **kwargs)
        path.write_bytes(b'{"replaced":true}')
        return verdict

    def execute(command, **kwargs):
        snapshot = Path(command[3])
        snapshots.append(snapshot)
        assert snapshot != path
        assert snapshot.read_bytes() == raw
        assert kwargs["timeout"] == 60
        assert kwargs["maximum_stdout"] == proof.MAX_ATTESTATION_RESPONSE_BYTES
        assert "--deny-self-hosted-runners" in command
        return SimpleNamespace(returncode=0, stdout=json.dumps([result]).encode("utf-8"), stderr="")

    monkeypatch.setattr(repeat, "verify_submission_bundle", verify_then_replace)
    monkeypatch.setattr(proof, "run_bounded", execute)
    assert cli.main(["verify", str(path), "--expected-file-sha256", hashlib.sha256(raw).hexdigest()]) == 0
    assert snapshots and not snapshots[0].exists()
    assert path.read_bytes() == b'{"replaced":true}'


@pytest.mark.parametrize("difference", ["notes", "bool_alias", "float_alias"])
def test_attestation_api_rejects_claims_different_from_file(attested, difference, monkeypatch):
    path, _, bundle, _ = attested
    changed = deepcopy(bundle)
    if difference == "notes":
        changed["submission"]["notes"] = "PRIVATE"
    elif difference == "bool_alias":
        # Exact JSON comparison must not use Python's True == 1 shortcut.
        bundle["type_probe"] = 1
        path.write_text(json.dumps(bundle))
        changed["type_probe"] = True
    else:
        changed["bundle_schema_version"] = 2.0
    monkeypatch.setattr(proof, "run_bounded", lambda *a, **k: pytest.fail("mismatched snapshot reached gh"))
    result = proof.verify_github_attestation(path, changed)
    assert not result.verified
    assert "PRIVATE" not in " ".join(result.errors)


@pytest.mark.parametrize("payload", [
    "null", "{}", "[]", "[null]", "[true]", '["PRIVATE"]',
    '[{"verificationResult":[]}]', '[{"verificationResult":{"signature":null}}]',
    '[{"verificationResult":{"signature":{"certificate":[]}}}]',
    '[{"PRIVATE":1,"PRIVATE":2}]', '[{"PRIVATE":NaN}]', '[{"PRIVATE":"\\ud800"}]',
])
def test_malformed_gh_response_is_unverified_not_exception(attested, payload, monkeypatch):
    path, _, bundle, _ = attested
    monkeypatch.setattr(proof, "run_bounded", lambda *a, **k: SimpleNamespace(returncode=0, stdout=payload.encode("utf-8"), stderr=""))
    result = proof.verify_github_attestation(path, bundle)
    assert not result.verified
    assert "PRIVATE" not in " ".join(result.errors)


@pytest.mark.parametrize("failure", ["exit", "timeout", "oserror", "encoding", "boundary", "loop"])
def test_failed_gh_process_cleans_snapshot_and_redacts_output(attested, failure, monkeypatch):
    path, raw, bundle, _ = attested
    snapshots = []

    def execute(command, **kwargs):
        snapshots.append(Path(command[3]))
        assert snapshots[-1].read_bytes() == raw
        if failure == "timeout":
            raise subprocess.TimeoutExpired("PRIVATE", 60, output="PRIVATE")
        if failure == "oserror":
            raise OSError("PRIVATE")
        if failure == "encoding":
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "PRIVATE")
        if failure == "boundary":
            raise proof.BoundedProcessError("PRIVATE")
        if failure == "loop":
            raise RuntimeError("PRIVATE")
        return SimpleNamespace(returncode=1, stdout="PRIVATE", stderr="PRIVATE")

    monkeypatch.setattr(proof, "run_bounded", execute)
    result = proof.verify_github_attestation(path, bundle)
    assert not result.verified
    assert "PRIVATE" not in " ".join(result.errors)
    assert snapshots and not snapshots[0].exists()


@pytest.mark.parametrize("mode", ["valid", "bad_encoding", "overflow", "timeout", "nonzero"])
def test_real_process_intake_remains_fail_closed_and_removes_snapshot(attested, monkeypatch, mode):
    path, raw, bundle, certificate = attested
    payload = json.dumps([certificate]).encode("utf-8")
    if mode == "bad_encoding":
        payload = b'["\xff"]'
    elif mode == "overflow":
        payload = b"PRIVATE" * 1000
    code = f"import os, time; os.write(2, b'PRIVATE'); os.write(1, {payload!r}); "
    code += "time.sleep(30)" if mode == "timeout" else f"raise SystemExit({7 if mode == 'nonzero' else 0})"
    snapshots = []
    bounded = proof.run_bounded

    def local_verifier(command, **kwargs):
        snapshots.append(Path(command[3]))
        assert snapshots[-1].read_bytes() == raw
        return bounded([sys.executable, "-c", code], maximum_stdout=1000, timeout=0.5)

    monkeypatch.setattr(proof, "run_bounded", local_verifier)
    result = proof.verify_github_attestation(path, bundle)
    assert result.verified == (mode == "valid")
    assert "PRIVATE" not in " ".join(result.errors)
    assert snapshots and not snapshots[0].exists()


def test_matching_certificate_can_follow_other_verified_attestations(attested, monkeypatch):
    path, _, bundle, matching = attested
    mismatch = deepcopy(matching)
    mismatch["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = "c" * 40
    payload = [None, mismatch, matching]
    monkeypatch.setattr(proof, "run_bounded", lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode("utf-8"), stderr=""))
    assert proof.verify_github_attestation(path, bundle).verified


@pytest.mark.parametrize("options", [
    ["--minimum-trials", "1"], ["--expected-file-sha256", "PRIVATE"],
    ["--expected-file-sha256", "A" * 64],
])
def test_invalid_review_policy_is_rejected_before_input_read(options, monkeypatch, capsys):
    monkeypatch.setattr(reviews, "read_json_snapshot", lambda *a: pytest.fail("invalid policy reached file read"))
    assert cli.main(["verify", "not-read.json", *options]) == 2
    assert "PRIVATE" not in capsys.readouterr().err


def test_response_size_limit_is_enforced(attested, monkeypatch):
    path, _, bundle, result = attested
    monkeypatch.setattr(proof, "MAX_ATTESTATION_RESPONSE_BYTES", 20)
    monkeypatch.setattr(proof, "run_bounded", lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps([result]).encode("utf-8"), stderr=""))
    assert not proof.verify_github_attestation(path, bundle).verified
