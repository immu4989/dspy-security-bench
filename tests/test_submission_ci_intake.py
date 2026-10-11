"""Untrusted pull-request evidence must not abort or upgrade registry admission."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from dspy_security_bench.procurement.repeat import create_submission_bundle
from scripts import validate_impact_submissions as intake
from tests.test_proofrun import _proof_bundle


@pytest.fixture(scope="module")
def github_bundle():
    return _proof_bundle()


@pytest.fixture(scope="module")
def local_bundle(github_bundle):
    return create_submission_bundle(
        github_bundle["report"], submitter="synthetic", agent_source_url="https://example.com/agent",
    )


@pytest.fixture
def checkout(tmp_path):
    submissions = tmp_path / "submissions"
    (submissions / "impact").mkdir(parents=True)
    for name in ("attestations", "reproductions"):
        (submissions / f"{name}.json").write_text(json.dumps({"schema_version": 1, name: {}}))
    return tmp_path


def write(root, bundle, name="agent", family="impact"):
    path = root / "submissions" / family / f"{name}.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def registry(root, kind, records):
    (root / "submissions" / f"{kind}.json").write_text(json.dumps({"schema_version": 1, kind: records}))


def attestation_record(bundle):
    return {
        "evidence_tier": "trusted_builder", "verified_by": "synthetic-reviewer",
        "verified_at": "2026-10-10T12:00:00Z", "run_url": bundle["provenance"]["run_url"],
        "source_commit": bundle["provenance"]["commit_sha"],
        "signer_workflow": intake.TRUSTED_BUILDER_WORKFLOW,
    }


@pytest.mark.parametrize("raw", [
    b"[]", b"null", b"true", b'{"PRIVATE":', b'{"PRIVATE":1,"PRIVATE":2}',
    b'{"PRIVATE":NaN}', b'{"PRIVATE":"\xff"}', b'{"PRIVATE":"\\ud800"}',
    b'{"PRIVATE":' + b"9" * 129 + b"}",
    b'{"PRIVATE":' + b"[" * 105 + b"0" + b"]" * 105 + b"}",
])
def test_bad_input_does_not_abort_later_submission(checkout, local_bundle, raw, monkeypatch, capsys):
    (checkout / "submissions/impact/a-bad.json").write_bytes(raw)
    write(checkout, local_bundle, "z-good")
    monkeypatch.setattr(intake, "verify_github_attestation", lambda *a, **k: pytest.fail("invalid/local evidence reached gh"))
    assert intake.main(checkout) == 1
    output = capsys.readouterr().out
    assert "PRIVATE" not in output
    assert "[NATIVE VALID AND ELIGIBLE] submissions/impact/z-good.json" in output


@pytest.mark.parametrize("family", list(intake.FAMILY_TYPES))
def test_each_family_dispatches_only_its_native_verifier(checkout, family, monkeypatch):
    functions = {
        "impact": "verify_submission_bundle", "control": "verify_control_submission_bundle",
        "incident": "verify_incident_submission_bundle", "source": "verify_source_submission_bundle",
        "authority": "verify_authority_submission_bundle", "trace": "verify_trace_submission_bundle",
        "causal": "verify_causal_submission_bundle", "collective": "verify_collective_submission_bundle",
        "defense": "verify_evidence_bundle",
    }
    calls = []
    bundle = {"bundle_type": intake.FAMILY_TYPES[family], "bundle_sha256": "a" * 64}
    write(checkout, bundle, family=family)
    for name in functions.values():
        monkeypatch.setattr(intake, name, lambda *a: pytest.fail("wrong family verifier"))

    def verify(source):
        calls.append(source)
        # Four structural registries intentionally have no `valid` attribute.
        return SimpleNamespace(errors=(), warnings=(), community_eligible=True, registry_eligible=True)

    monkeypatch.setattr(intake, functions[family], verify)
    assert intake.main(checkout) == 0
    assert calls == [bundle]


def test_wrong_directory_cannot_fall_through_to_another_family(checkout, local_bundle, monkeypatch):
    write(checkout, local_bundle, family="control")
    monkeypatch.setattr(intake, "verify_control_submission_bundle", lambda *a: pytest.fail("misfiled evidence reached native replay"))
    monkeypatch.setattr(intake, "verify_submission_bundle", lambda *a: pytest.fail("misfiled evidence used fallback"))
    assert intake.main(checkout) == 1


@pytest.mark.parametrize("failure", ["invalid", "ineligible", "exception"])
def test_invalid_or_ineligible_evidence_never_requests_attestation(checkout, github_bundle, failure, monkeypatch, capsys):
    write(checkout, github_bundle)

    def verify(*args):
        if failure == "exception":
            raise AttributeError("PRIVATE")
        return SimpleNamespace(valid=failure != "invalid", community_eligible=False,
                               errors=("PRIVATE",) if failure == "invalid" else (), warnings=("PRIVATE",))

    monkeypatch.setattr(intake, "verify_submission_bundle", verify)
    monkeypatch.setattr(intake, "verify_github_attestation", lambda *a, **k: pytest.fail("unadmitted evidence reached gh"))
    assert intake.main(checkout) == 1
    assert "PRIVATE" not in capsys.readouterr().out


def test_local_acceptance_cannot_authorize_a_forged_attestation_registry(checkout, local_bundle, monkeypatch, capsys):
    write(checkout, local_bundle)
    # Previously str(None) passed the string check, and absent provenance values
    # could match these nulls in the general accepted-bundles map.
    registry(checkout, "attestations", {local_bundle["bundle_sha256"]: {
        "evidence_tier": "github_attested", "verified_by": "PRIVATE", "verified_at": "PRIVATE",
        "run_url": None, "source_commit": None, "signer_workflow": "PRIVATE",
    }})
    monkeypatch.setattr(intake, "verify_github_attestation", lambda *a, **k: pytest.fail("local bundle requested gh"))
    assert intake.main(checkout) == 1
    output = capsys.readouterr().out
    assert "no cryptographically accepted bundle" in output
    assert "PRIVATE" not in output


@pytest.mark.parametrize("verified", [True, False])
def test_attestation_registry_requires_success_and_exact_snapshot(checkout, github_bundle, verified, monkeypatch, capsys):
    path = write(checkout, github_bundle)
    raw = path.read_bytes()
    registry(checkout, "attestations", {github_bundle["bundle_sha256"]: attestation_record(github_bundle)})

    def authenticate(source, bundle, **kwargs):
        assert source == path and bundle == github_bundle
        assert kwargs["bundle_bytes"] == raw
        path.write_text('{"replaced":true}')
        return SimpleNamespace(verified=verified, errors=("PRIVATE",), warnings=("PRIVATE",))

    monkeypatch.setattr(intake, "verify_github_attestation", authenticate)
    assert intake.main(checkout) == (0 if verified else 1)
    assert "PRIVATE" not in capsys.readouterr().out


@pytest.mark.parametrize("kind", ["attestations", "reproductions"])
@pytest.mark.parametrize("raw", [
    "[]", '{"schema_version":true,"KEY":{}}', '{"schema_version":1.0,"KEY":{}}',
    '{"schema_version":1,"KEY":[],"PRIVATE":true}',
    '{"schema_version":1,"KEY":{"PRIVATE":{}}}',
    '{"schema_version":1,"KEY":{},"KEY":{}}',
])
def test_registry_roots_and_keys_fail_closed(checkout, kind, raw, capsys):
    (checkout / "submissions" / f"{kind}.json").write_text(raw.replace("KEY", kind))
    assert intake.main(checkout) == 1
    assert "PRIVATE" not in capsys.readouterr().out


@pytest.mark.parametrize("kind", ["attestations", "reproductions"])
@pytest.mark.parametrize("mutation", ["null", "boolean", "container", "time", "credentials", "port", "unknown"])
def test_registry_record_metadata_is_typed_and_source_redacted(checkout, github_bundle, kind, mutation, capsys):
    digest = github_bundle["bundle_sha256"]
    record = attestation_record(github_bundle) if kind == "attestations" else {
        "reproduced_by": "synthetic", "created_at": "2026-10-10T12:00:00Z", "run_url": "https://example.com/run",
    }
    person = "verified_by" if kind == "attestations" else "reproduced_by"
    timestamp = "verified_at" if kind == "attestations" else "created_at"
    if mutation in ("null", "boolean", "container"):
        record[person] = {"null": None, "boolean": True, "container": ["PRIVATE"]}[mutation]
    elif mutation == "time":
        record[timestamp] = "PRIVATE"
    elif mutation == "credentials":
        record["run_url"] = "https://user:PRIVATE@example.com/run"
    elif mutation == "port":
        record["run_url"] = "https://example.com:PRIVATE/run"
    else:
        record["PRIVATE"] = "PRIVATE"
    registry(checkout, kind, {digest: record})
    failed = intake._validate_attestations(checkout, {digest: github_bundle}) if kind == "attestations" else intake._validate_reproductions(checkout, {digest})
    assert failed
    assert "PRIVATE" not in capsys.readouterr().out


def test_valid_reproduction_record_remains_an_owner_reviewed_declaration(checkout, local_bundle):
    write(checkout, local_bundle)
    registry(checkout, "reproductions", {local_bundle["bundle_sha256"]: {
        "reproduced_by": "synthetic-reviewer", "created_at": "2026-10-10T12:00:00Z",
        "run_url": "https://example.com/run",
    }})
    assert intake.main(checkout) == 0


@pytest.mark.parametrize("link", ["file", "category", "registry", "root"])
def test_symlinks_are_refused_before_input_content_reads(checkout, local_bundle, link, monkeypatch):
    source = write(checkout, local_bundle)
    if link == "file":
        (source.parent / "linked.json").symlink_to(source)
    elif link == "category":
        (checkout / "submissions/source").symlink_to(source.parent, target_is_directory=True)
    elif link == "registry":
        target = checkout / "submissions/attestations.json"
        target.unlink()
        target.symlink_to(source)
    else:
        other = checkout / "linked-checkout"
        other.mkdir()
        (other / "submissions").symlink_to(checkout / "submissions", target_is_directory=True)
        checkout = other
    reader = intake.read_json_snapshot

    def read(path, maximum):
        assert not any(item.is_symlink() for item in (path, *path.parents))
        return reader(path, maximum)

    monkeypatch.setattr(intake, "read_json_snapshot", read)
    assert intake.main(checkout) == 1


@pytest.mark.parametrize("budget", ["count", "total", "bundle", "registry"])
def test_input_budgets_are_enforced(checkout, local_bundle, budget, monkeypatch):
    write(checkout, local_bundle)
    field = {"count": "MAX_SUBMISSIONS", "total": "MAX_TOTAL_BYTES", "bundle": "MAX_BUNDLE_BYTES", "registry": "MAX_REGISTRY_BYTES"}[budget]
    monkeypatch.setattr(intake, field, 0 if budget == "count" else 16)
    assert intake.main(checkout) == 1


def test_committed_collective_fixture_passes_real_native_admission(checkout, monkeypatch):
    monkeypatch.setattr(intake, "verify_github_attestation", lambda *a, **k: pytest.fail("unexpected online fixture"))
    fixture = Path(__file__).resolve().parents[1] / "submissions/collective/reference-runtime.json"
    write(checkout, json.loads(fixture.read_text()), family="collective")
    assert intake.main(checkout) == 0


def test_malformed_filename_is_not_copied_to_logs(checkout, local_bundle, capsys):
    write(checkout, local_bundle, name="PRIVATE\x1b[31m")
    assert intake.main(checkout) == 1
    assert "PRIVATE" not in capsys.readouterr().out
