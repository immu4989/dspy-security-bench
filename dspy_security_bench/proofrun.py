"""ProofRun execution envelopes and GitHub artifact-attestation verification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dspy_security_bench.jsonio import decode_json_object, read_json_snapshot
from dspy_security_bench.processio import BoundedProcessError, run_bounded

MAX_BUNDLE_BYTES = 50_000_000
MAX_ATTESTATION_RESPONSE_BYTES = 5_000_000

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
    bundle_bytes: bytes | None = None,
) -> AttestationResult:
    """Verify a private exact-byte snapshot with gh and enforce certificate claims.

    ``bundle_bytes`` lets a caller bind native replay to the same input read.
    Without it, read the file once and require its decoded content to match
    ``bundle``. This function authenticates provenance, not report semantics.
    """
    if not isinstance(bundle, Mapping):
        return _failed("bundle must be an object")
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

    identity_fields = ("repository", "commit_sha", "ref", "run_url", "builder_kind", "runner_environment")
    if any(not isinstance(provenance.get(field), str) or not provenance[field].strip() for field in identity_fields):
        return _failed("GitHub provenance requires non-empty string identity claims")
    if provenance["builder_kind"] not in ("caller_workflow", "dspy_security_bench_reusable_workflow"):
        return _failed("unsupported provenance.builder_kind")
    if provenance["runner_environment"] not in ("github-hosted", "self-hosted"):
        return _failed("unsupported provenance.runner_environment")
    try:
        if bundle_bytes is None:
            raw, decoded = read_json_snapshot(bundle_path, MAX_BUNDLE_BYTES)
        else:
            raw = bundle_bytes
            decoded = decode_json_object(raw, MAX_BUNDLE_BYTES)
        # Python equality aliases bool/int and int/float. Compare typed JSON.
        options = {"sort_keys": True, "separators": (",", ":"), "allow_nan": False}
        if json.dumps(decoded, **options) != json.dumps(bundle, **options):
            return _failed("bundle claims do not match the input snapshot")
    except (OSError, TypeError, ValueError, RecursionError):
        return _failed("could not read a matching strict JSON snapshot; source details withheld")

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
        "",  # Replaced by the private snapshot path immediately before execution.
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
        with tempfile.TemporaryDirectory(prefix="proofrun-verify-") as temporary:
            snapshot = Path(temporary) / "bundle.json"
            snapshot.write_bytes(raw)
            command[3] = str(snapshot)
            completed = run_bounded(
                command, maximum_stdout=MAX_ATTESTATION_RESPONSE_BYTES, timeout=60,
            )
    except BoundedProcessError:
        return _failed("GitHub attestation verifier exceeded a process collection boundary; output withheld")
    except (OSError, subprocess.TimeoutExpired, UnicodeError, RuntimeError):
        return _failed("could not execute GitHub attestation verification; process details withheld")
    if completed.returncode:
        return _failed("GitHub attestation verification failed; process output withheld")
    try:
        response = b'{"results":' + completed.stdout + b'}'
        results = decode_json_object(response, MAX_ATTESTATION_RESPONSE_BYTES)["results"]
    except (TypeError, ValueError, AttributeError):
        return _failed("GitHub CLI returned invalid verification JSON; source details withheld")
    if not isinstance(results, list) or not results:
        return _failed("GitHub CLI returned no verified attestations")

    expected_source = f"https://github.com/{expected_repository}"
    errors = []
    comparisons = {
        "sourceRepositoryURI": expected_source,
        "sourceRepositoryDigest": commit_sha,
        "sourceRepositoryRef": source_ref,
        "runnerEnvironment": provenance.get("runner_environment"),
    }
    expected_run = str(provenance.get("run_url", ""))
    for result in results:
        certificate = result
        for key in ("verificationResult", "signature", "certificate"):
            certificate = certificate.get(key) if isinstance(certificate, Mapping) else None
        if not isinstance(certificate, Mapping):
            errors.append("verified attestation did not include certificate claims")
            continue
        mismatches = [f"certificate {field} does not match the bundle claim"
                      for field, expected in comparisons.items() if certificate.get(field) != expected]
        actual_run = certificate.get("runInvocationURI")
        if not isinstance(actual_run, str) or actual_run.rstrip("/") != expected_run.rstrip("/"):
            mismatches.append("certificate runInvocationURI does not match provenance.run_url")
        if mismatches:
            errors.extend(mismatches)
            continue
        return AttestationResult(
            verified=True,
            evidence_tier="trusted_builder" if trusted_builder else "github_attested",
            repository=expected_repository,
            signer_workflow=signer_workflow,
            source_commit=commit_sha,
            run_url=expected_run,
            errors=(),
            warnings=(
                "provenance authenticates the workflow and exact bytes; it does not make model-provider outputs independently observable",
            ),
        )
    return AttestationResult(
        verified=False,
        evidence_tier="github_attestation_unverified",
        repository=expected_repository,
        signer_workflow=signer_workflow,
        source_commit=commit_sha,
        run_url=expected_run,
        errors=tuple(dict.fromkeys(errors)),
        warnings=(),
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
