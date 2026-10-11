"""Typed, source-redacted admission checks shared by procurement bundle families.

Metadata remains a declaration, not authenticated provenance. These checks run
before native replay so malformed containers cannot reach lookups or coercions.
"""

import re
from collections.abc import Mapping
from datetime import datetime, timezone
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


def validate_submission_metadata(bundle, *, control: bool) -> tuple[str, ...]:
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
    submission = bundle.get("submission")
    required = {"submitter", "agent_source_url", "notes", "created_at", "attestation"}
    if control:
        required.add("policy_source_url")
    if shape(submission, required, "submission"):
        for field in sorted(required):
            value = submission.get(field)
            if not isinstance(value, str) or (field != "notes" and not value.strip()):
                errors.append(f"submission.{field} must be a string" + ("" if field == "notes" else " and non-empty"))
        for field in ("agent_source_url", "policy_source_url") if control else ("agent_source_url",):
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
            else:
                errors.append("unsupported provenance provider")
    return tuple(errors)
