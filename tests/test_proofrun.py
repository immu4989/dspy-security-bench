import json
from importlib.resources import files
from types import SimpleNamespace

import pytest

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.procurement.repeat import (
    canonical_sha256,
    create_submission_bundle,
    run_repeat_twin,
    verify_submission_bundle,
)
from dspy_security_bench.proofrun import (
    TRUSTED_BUILDER_WORKFLOW,
    capture_provenance,
    verify_github_attestation,
)
from tests.test_repeat_twin import build_community_agent

GITHUB_ENV = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_REPOSITORY": "example/agent",
    "GITHUB_REPOSITORY_ID": "123",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_REF": "example/agent/.github/workflows/security.yml@refs/heads/main",
    "GITHUB_WORKFLOW_SHA": "b" * 40,
    "GITHUB_RUN_ID": "456",
    "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_SERVER_URL": "https://github.com",
    "PROOFRUN_BUILDER_KIND": "dspy_security_bench_reusable_workflow",
    "PROOFRUN_RUNNER_ENVIRONMENT": "github-hosted",
    "PROOFRUN_ACTION_REF": "v0.7.0",
}


def _proof_bundle():
    report = run_repeat_twin(
        build_community_agent(), trials=5, agent_factory=build_community_agent
    ).to_dict()
    return create_submission_bundle(
        report,
        submitter="@researcher",
        agent_source_url="https://github.com/example/agent/tree/" + "a" * 40,
        provenance=capture_provenance(GITHUB_ENV),
    )


def test_capture_provenance_is_bounded_and_records_reproducible_github_identity():
    provenance = capture_provenance({**GITHUB_ENV, "OPENAI_API_KEY": "must-not-leak"})
    assert provenance == {
        "provider": "github_actions",
        "builder_kind": "dspy_security_bench_reusable_workflow",
        "repository": "example/agent",
        "repository_id": "123",
        "commit_sha": "a" * 40,
        "ref": "refs/heads/main",
        "workflow_ref": "example/agent/.github/workflows/security.yml@refs/heads/main",
        "workflow_sha": "b" * 40,
        "run_id": "456",
        "run_attempt": "2",
        "run_url": "https://github.com/example/agent/actions/runs/456/attempts/2",
        "runner_environment": "github-hosted",
        "action_ref": "v0.7.0",
    }
    assert "OPENAI_API_KEY" not in provenance


def test_capture_provenance_labels_local_execution_without_inventing_identity():
    assert capture_provenance({}) == {
        "provider": "local",
        "builder_kind": "local_process",
        "runner_environment": "local",
    }


def test_proof_bundle_is_schema_v2_and_requires_external_signature_verification():
    bundle = _proof_bundle()
    assert bundle["bundle_schema_version"] == 2
    assert bundle["submission"]["attestation"] == "github_actions_provenance_requested"
    integrity = verify_submission_bundle(bundle)
    assert integrity.valid is True
    assert integrity.community_eligible is True
    assert integrity.evidence_tier == "github_attestation_unverified"
    assert any("not cryptographically verified" in warning for warning in integrity.warnings)

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("submission-bundle.schema.json")
        .read_text()
    )
    jsonschema.validate(bundle, schema, format_checker=jsonschema.FormatChecker())


def test_provenance_is_covered_by_the_canonical_bundle_digest():
    bundle = _proof_bundle()
    bundle["provenance"]["commit_sha"] = "c" * 40
    result = verify_submission_bundle(bundle)
    assert result.valid is False
    assert any("bundle_sha256" in error for error in result.errors)


def test_github_provenance_cannot_be_relabelled_as_self_attested():
    bundle = _proof_bundle()
    bundle["submission"]["attestation"] = "self_attested_content_addressed"
    bundle["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )
    result = verify_submission_bundle(bundle)
    assert result.valid is False
    assert "GitHub provenance requires the GitHub attestation label" in result.errors


def test_github_attestation_verifier_enforces_trusted_builder_and_certificate_claims(
    tmp_path, monkeypatch
):
    bundle = _proof_bundle()
    path = tmp_path / "proofrun.json"
    path.write_text(json.dumps(bundle))
    certificate = {
        "sourceRepositoryURI": "https://github.com/example/agent",
        "sourceRepositoryDigest": "a" * 40,
        "sourceRepositoryRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": "https://github.com/example/agent/actions/runs/456/attempts/2",
    }
    payload = [
        {
            "verificationResult": {
                "signature": {"certificate": certificate},
                "statement": {"subject": [{"name": "proofrun.json"}]},
            }
        }
    ]
    calls = []

    monkeypatch.setattr("dspy_security_bench.proofrun.shutil.which", lambda _: "/usr/bin/gh")

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("dspy_security_bench.proofrun.subprocess.run", fake_run)
    result = verify_github_attestation(path, bundle, require_trusted_builder=True)
    assert result.verified is True
    assert result.evidence_tier == "trusted_builder"
    assert ["--signer-workflow", TRUSTED_BUILDER_WORKFLOW] == calls[0][
        calls[0].index("--signer-workflow") : calls[0].index("--signer-workflow") + 2
    ]
    assert "--deny-self-hosted-runners" in calls[0]
    assert calls[0][calls[0].index("--source-digest") + 1] == "a" * 40


def test_github_attestation_verifier_rejects_claim_mismatch(tmp_path, monkeypatch):
    bundle = _proof_bundle()
    path = tmp_path / "proofrun.json"
    path.write_text(json.dumps(bundle))
    payload = [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "sourceRepositoryURI": "https://github.com/example/other",
                        "sourceRepositoryDigest": "a" * 40,
                        "sourceRepositoryRef": "refs/heads/main",
                        "runnerEnvironment": "github-hosted",
                        "runInvocationURI": bundle["provenance"]["run_url"],
                    }
                }
            }
        }
    ]
    monkeypatch.setattr("dspy_security_bench.proofrun.shutil.which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(
        "dspy_security_bench.proofrun.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    result = verify_github_attestation(path, bundle)
    assert result.verified is False
    assert any("sourceRepositoryURI" in error for error in result.errors)


def test_proofrun_cli_runs_writes_v2_bundle_and_verifies_offline(tmp_path, monkeypatch, capsys):
    bundle_path = tmp_path / "proofrun.json"
    for key, value in GITHUB_ENV.items():
        monkeypatch.setenv(key, value)
    assert root_main(
        [
            "proofrun",
            "run",
            "--agent",
            "tests.test_repeat_twin:build_community_agent",
            "--trials",
            "5",
            "--submitter",
            "@tester",
            "--agent-source",
            "https://github.com/example/agent",
            "--out",
            str(bundle_path),
        ]
    ) == 0
    assert json.loads(bundle_path.read_text())["bundle_schema_version"] == 2
    assert root_main(["proofrun", "verify", str(bundle_path), "--offline"]) == 0
    output = capsys.readouterr().out
    assert "Leaderboard eligibility: yes" in output
    assert "github_attestation_unverified" in output


def test_proofrun_cli_preserves_bundle_before_a_failed_confidence_gate(
    tmp_path, monkeypatch
):
    bundle_path = tmp_path / "failed-gate.json"
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    result = root_main(
        [
            "proofrun",
            "run",
            "--agent",
            "tests.test_repeat_twin:build_community_agent",
            "--trials",
            "2",
            "--min-lower-bound",
            "1.0",
            "--submitter",
            "@tester",
            "--agent-source",
            "https://github.com/example/agent",
            "--out",
            str(bundle_path),
        ]
    )
    assert result == 1
    assert bundle_path.is_file()
    assert verify_submission_bundle(json.loads(bundle_path.read_text())).valid is True
