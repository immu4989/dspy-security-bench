"""ProofRun execution envelopes and GitHub artifact-attestation verification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TRUSTED_BUILDER_WORKFLOW = (
    "immu4989/dspy-security-bench/.github/workflows/proofrun.yml"
)
EVIDENCE_TIERS = (
    "self_attested",
    "github_attested",
    "trusted_builder",
    "maintainer_reproduced",
)


@dataclass(frozen=True)
class AttestationResult:
    """Outcome of verifying an exact bundle against GitHub/Sigstore provenance."""

    verified: bool
    evidence_tier: str
    repository: str | None
    signer_workflow: str | None
    source_commit: str | None
    run_url: str | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def capture_provenance(environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Capture bounded runner metadata without reading credentials or arbitrary environment state."""
    env = os.environ if environment is None else environment
    if env.get("GITHUB_ACTIONS") != "true":
        return {
            "provider": "local",
            "builder_kind": "local_process",
            "runner_environment": "local",
        }

    repository = env.get("GITHUB_REPOSITORY", "")
    server = env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    return {
        "provider": "github_actions",
        "builder_kind": env.get("PROOFRUN_BUILDER_KIND", "caller_workflow"),
        "repository": repository,
        "repository_id": env.get("GITHUB_REPOSITORY_ID", ""),
        "commit_sha": env.get("GITHUB_SHA", ""),
        "ref": env.get("GITHUB_REF", ""),
        "workflow_ref": env.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_sha": env.get("GITHUB_WORKFLOW_SHA", ""),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": f"{server}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}",
        "runner_environment": env.get("PROOFRUN_RUNNER_ENVIRONMENT", "github-hosted"),
        "action_ref": env.get("PROOFRUN_ACTION_REF", ""),
    }


def verify_github_attestation(
    bundle_path: Path,
    bundle: Mapping[str, Any],
    *,
    repository: str | None = None,
    require_trusted_builder: bool = False,
    deny_self_hosted: bool = True,
) -> AttestationResult:
    """Verify an exact bundle with ``gh attestation verify`` and enforce runner claims."""
    provenance = bundle.get("provenance")
    if not isinstance(provenance, Mapping) or provenance.get("provider") != "github_actions":
        return AttestationResult(
            verified=False,
            evidence_tier="self_attested",
            repository=None,
            signer_workflow=None,
            source_commit=None,
            run_url=None,
            errors=("bundle does not declare GitHub Actions provenance",),
            warnings=(),
        )

    claimed_repository = str(provenance.get("repository", ""))
    expected_repository = repository or claimed_repository
    if not expected_repository:
        return _failed("provenance.repository is required for attestation lookup")
    if repository and claimed_repository and repository.lower() != claimed_repository.lower():
        return _failed("requested repository does not match provenance.repository")
    if shutil.which("gh") is None:
        return _failed("GitHub CLI is required for online attestation verification")

    builder_kind = provenance.get("builder_kind")
    trusted_builder = builder_kind == "dspy_security_bench_reusable_workflow"
    signer_workflow = TRUSTED_BUILDER_WORKFLOW if trusted_builder else None
    if require_trusted_builder and not trusted_builder:
        return _failed("bundle was not produced by the DSPy Security Bench reusable workflow")

    command = [
        "gh",
        "attestation",
        "verify",
        str(bundle_path),
        "--repo",
        expected_repository,
        "--format",
        "json",
    ]
    if deny_self_hosted:
        command.append("--deny-self-hosted-runners")
    if signer_workflow:
        command.extend(["--signer-workflow", signer_workflow])
    commit_sha = str(provenance.get("commit_sha", ""))
    source_ref = str(provenance.get("ref", ""))
    if commit_sha:
        command.extend(["--source-digest", commit_sha])
    if source_ref:
        command.extend(["--source-ref", source_ref])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _failed(f"could not execute GitHub attestation verification: {exc}")
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        return _failed(f"GitHub attestation verification failed: {detail}")
    try:
        results = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return _failed(f"GitHub CLI returned invalid verification JSON: {exc}")
    if not isinstance(results, list) or not results:
        return _failed("GitHub CLI returned no verified attestations")

    certificate = results[0].get("verificationResult", {}).get("signature", {}).get("certificate", {})
    if not isinstance(certificate, Mapping):
        return _failed("verified attestation did not include certificate claims")
    expected_source = f"https://github.com/{expected_repository}"
    errors = []
    comparisons = {
        "sourceRepositoryURI": expected_source,
        "sourceRepositoryDigest": commit_sha,
        "sourceRepositoryRef": source_ref,
        "runnerEnvironment": provenance.get("runner_environment"),
    }
    for field, expected in comparisons.items():
        if expected and certificate.get(field) != expected:
            errors.append(f"certificate {field} does not match the bundle claim")
    expected_run = str(provenance.get("run_url", ""))
    actual_run = str(certificate.get("runInvocationURI", ""))
    if expected_run and actual_run.rstrip("/") != expected_run.rstrip("/"):
        errors.append("certificate runInvocationURI does not match provenance.run_url")
    if errors:
        return AttestationResult(
            verified=False,
            evidence_tier="github_attestation_unverified",
            repository=expected_repository,
            signer_workflow=signer_workflow,
            source_commit=commit_sha or None,
            run_url=expected_run or None,
            errors=tuple(errors),
            warnings=(),
        )

    return AttestationResult(
        verified=True,
        evidence_tier="trusted_builder" if trusted_builder else "github_attested",
        repository=expected_repository,
        signer_workflow=signer_workflow,
        source_commit=commit_sha or None,
        run_url=expected_run or actual_run or None,
        errors=(),
        warnings=(
            "provenance authenticates the workflow and exact bytes; it does not make model-provider outputs independently observable",
        ),
    )


def _failed(message: str) -> AttestationResult:
    return AttestationResult(
        verified=False,
        evidence_tier="github_attestation_unverified",
        repository=None,
        signer_workflow=None,
        source_commit=None,
        run_url=None,
        errors=(message,),
        warnings=(),
    )
