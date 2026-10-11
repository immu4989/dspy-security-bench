"""Typed, source-redacted admission checks shared by ProofRun bundle families.

Metadata remains a declaration, not authenticated provenance. These checks run
before native replay so malformed containers cannot reach lookups or coercions.
"""

import json
import platform
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlsplit


def _https_reference(value) -> bool:
    if not isinstance(value, str) or any(character.isspace() for character in value):
        return False
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None
                and parsed.password is None and (parsed.port is None or 1 <= parsed.port <= 65535))
    except ValueError:
        return False


def validate_submission_metadata(bundle, *, control: bool, source_field: str = "agent_source_url") -> tuple[str, ...]:
    _check_source_field(source_field, control)
    errors = []
    if not isinstance(bundle, Mapping):
        return ("submission bundle must be an object",)
    version = bundle.get("bundle_schema_version")
    if type(version) is not int or version not in (1, 2):
        errors.append("unsupported bundle_schema_version; expected integer 1 or 2")
    fields = {"bundle_schema_version", "bundle_type", "submission", "producer", "report_sha256", "report", "bundle_sha256"}
    if type(version) is int and version == 2:
        fields.add("provenance")

    def shape(value, required, label):
        if not isinstance(value, Mapping):
            errors.append(f"{label} metadata must be an object")
            return False
        if set(value) - required:
            errors.append(f"unsupported {label} fields; source field names withheld")
        if required - set(value):
            errors.append(f"{label} required fields are missing")
        return True

    shape(bundle, fields, "bundle")
    for field in ("report_sha256", "bundle_sha256"):
        if not isinstance(bundle.get(field), str) or re.fullmatch(r"[a-f0-9]{64}", bundle[field]) is None:
            errors.append(f"{field} must be lowercase SHA-256")
    errors.extend(_validate_envelope(bundle, control=control, source_field=source_field))
    return tuple(errors)


def _check_source_field(source_field, control):
    if source_field not in ("agent_source_url", "adapter_source_url") or (control and source_field != "agent_source_url"):
        raise ValueError("unsupported submission source field")


def _validate_envelope(bundle, *, control: bool, source_field: str = "agent_source_url") -> tuple[str, ...]:
    """Check declarations without a report or placeholder content hashes."""
    errors = []
    version = bundle.get("bundle_schema_version")

    def shape(value, required, label):
        if not isinstance(value, Mapping):
            errors.append(f"{label} metadata must be an object")
            return False
        if set(value) - required:
            errors.append(f"unsupported {label} fields; source field names withheld")
        if required - set(value):
            errors.append(f"{label} required fields are missing")
        return True

    submission = bundle.get("submission")
    required = {"submitter", source_field, "notes", "created_at", "attestation"}
    if control:
        required.add("policy_source_url")
    if shape(submission, required, "submission"):
        for field in sorted(required):
            value = submission.get(field)
            if not isinstance(value, str) or (field != "notes" and not value.strip()):
                errors.append(f"submission.{field} must be a string" + ("" if field == "notes" else " and non-empty"))
        for field in (source_field, "policy_source_url") if control else (source_field,):
            if not _https_reference(submission.get(field)):
                errors.append(f"submission.{field} must be an https URL without credentials")
        stamp = submission.get("created_at")
        try:
            valid_time = isinstance(stamp, str) and stamp.endswith("Z") and datetime.fromisoformat(
                stamp[:-1] + "+00:00"
            ).utcoffset() == timezone.utc.utcoffset(None)
        except ValueError:
            valid_time = False
        if not valid_time:
            errors.append("submission.created_at must be an ISO-8601 UTC timestamp")
    producer = bundle.get("producer")
    producer_fields = {"package", "package_version", "python_version", "platform"}
    if shape(producer, producer_fields, "producer"):
        for field in sorted(producer_fields):
            if not isinstance(producer.get(field), str) or not producer[field].strip():
                errors.append(f"producer.{field} must be a non-empty string")
        if producer.get("package") != "dspy-security-bench":
            errors.append("producer.package must be dspy-security-bench")
    if type(version) is int and version == 2:
        provenance = bundle.get("provenance")
        if not isinstance(provenance, Mapping):
            errors.append("schema-v2 bundles require provenance metadata")
        else:
            provider = provenance.get("provider")
            common = {"provider", "builder_kind", "runner_environment"}
            if provider == "local":
                shape(provenance, common, "local provenance")
                if provenance.get("builder_kind") != "local_process":
                    errors.append("local provenance requires builder_kind=local_process")
                if provenance.get("runner_environment") != "local":
                    errors.append("local provenance requires runner_environment=local")
            elif provider == "github_actions":
                required = common | {"repository", "repository_id", "commit_sha", "ref", "workflow_ref",
                                     "workflow_sha", "run_id", "run_attempt", "run_url", "action_ref"}
                shape(provenance, required, "GitHub provenance")
                for field in sorted(required):
                    value = provenance.get(field)
                    if not isinstance(value, str) or (field != "action_ref" and not value.strip()):
                        errors.append(f"provenance.{field} must be a string")
                for field in ("repository_id", "run_id", "run_attempt"):
                    value = provenance.get(field)
                    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
                        errors.append(f"provenance.{field} must contain only ASCII digits")
                repository = provenance.get("repository")
                if not isinstance(repository, str) or re.fullmatch(r"[^/\s]+/[^/\s]+", repository) is None:
                    errors.append("provenance.repository must be owner/repository")
                if provenance.get("builder_kind") not in ("caller_workflow", "dspy_security_bench_reusable_workflow"):
                    errors.append("unsupported provenance.builder_kind")
                if provenance.get("runner_environment") not in ("github-hosted", "self-hosted"):
                    errors.append("unsupported provenance.runner_environment")
                ref = provenance.get("ref")
                if not isinstance(ref, str) or not ref.startswith("refs/"):
                    errors.append("provenance.ref must start with refs/")
                url = provenance.get("run_url")
                if not _https_reference(url):
                    errors.append("provenance.run_url must be an https URL")
                for field in ("commit_sha", "workflow_sha"):
                    value = provenance.get(field)
                    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None:
                        errors.append(f"provenance.{field} must be a full Git commit SHA")
            else:
                errors.append("unsupported provenance provider")
    if isinstance(submission, Mapping):
        provenance = bundle.get("provenance")
        if version == 1:
            if submission.get("attestation") != "self_attested_content_addressed":
                errors.append("schema-v1 bundles must remain self-attested")
        elif isinstance(provenance, Mapping):
            if provenance.get("provider") == "github_actions":
                if submission.get("attestation") != "github_actions_provenance_requested":
                    errors.append("GitHub provenance requires the GitHub attestation label")
            elif provenance.get("provider") == "local":
                if submission.get("attestation") != "self_attested_content_addressed":
                    errors.append("local provenance must remain self-attested")
    if errors:
        return tuple(errors)
    try:
        declarations = {key: bundle[key] for key in ("submission", "producer", "provenance") if key in bundle}
        json.dumps(declarations, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        errors.append("submission metadata must be portable UTF-8 JSON; source details withheld")
    return tuple(errors)


def prepare_submission_metadata(
    *, submitter, agent_source_url, notes="", provenance=None,
    control: bool = False, policy_source_url=None, source_field: str = "agent_source_url",
) -> dict:
    """Build validated declarations before evaluation; no execution is attested.

    The returned envelope contains no report or digests and is not a bundle.
    Provenance is copied, so later mutations to the input cannot change it.
    Validation errors name only fixed contract fields, never supplied values.
    """
    _check_source_field(source_field, control)
    if provenance is not None and not isinstance(provenance, Mapping):
        raise ValueError("provenance metadata must be an object")
    provenance_copy = dict(provenance) if provenance is not None else None
    attestation = (
        "github_actions_provenance_requested"
        if provenance_copy is not None and provenance_copy.get("provider") == "github_actions"
        else "self_attested_content_addressed"
    )
    try:
        package_version = version("dspy-security-bench")
    except PackageNotFoundError:
        package_version = "unknown"
    submission = {
        "submitter": submitter.strip() if isinstance(submitter, str) else submitter,
        source_field: agent_source_url,
        "notes": notes.strip() if isinstance(notes, str) else notes,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "attestation": attestation,
    }
    if control:
        submission["policy_source_url"] = policy_source_url
    envelope = {
        "bundle_schema_version": 2 if provenance_copy is not None else 1,
        "submission": submission,
        "producer": {
            "package": "dspy-security-bench", "package_version": package_version,
            "python_version": platform.python_version(), "platform": platform.platform(),
        },
    }
    if provenance_copy is not None:
        envelope["provenance"] = provenance_copy
    errors = _validate_envelope(envelope, control=control, source_field=source_field)
    if errors:
        raise ValueError("invalid submission metadata: " + "; ".join(errors))
    return envelope
