"""Source-redacted, machine-readable ProofRun review decisions.

These local decisions are not signed attestations or independent reproductions.
Native replay and optional signature verification consume one input snapshot.
"""

from __future__ import annotations

import hashlib
import importlib
import re
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from dspy_security_bench.jsonio import read_json_snapshot
from dspy_security_bench.proofrun import MAX_BUNDLE_BYTES, verify_github_attestation

FAMILIES = {
    "dspy-security-bench-community-submission": (
        "dspy_security_bench.procurement.repeat", "verify_submission_bundle",
        "community_eligible", "Leaderboard eligibility",
    ),
    "dspy-security-bench-control-evidence-submission": (
        "dspy_security_bench.procurement.control_registry", "verify_control_submission_bundle",
        "registry_eligible", "Control registry eligibility",
    ),
    "dspy-security-bench-incident-evidence-submission": (
        "dspy_security_bench.incident.repeat", "verify_incident_submission_bundle",
        "community_eligible", "Incident registry eligibility",
    ),
    "dspy-security-bench-source-evidence-submission": (
        "dspy_security_bench.mission.repeat", "verify_source_submission_bundle",
        "community_eligible", "Source registry eligibility",
    ),
    "dspy-security-bench-authority-evidence-submission": (
        "dspy_security_bench.authority.repeat", "verify_authority_submission_bundle",
        "community_eligible", "Authority registry eligibility",
    ),
}

REASONS = {
    "offline_verified": "Native evidence is valid and eligible; provenance was not authenticated.",
    "online_verified": "Native evidence is valid and eligible; GitHub provenance was verified.",
    "not_eligible": "Valid evidence does not satisfy registry eligibility under this trial policy.",
    "attestation_unverified": "GitHub provenance was not verified under the requested identity policy.",
    "invalid_policy": "Invalid review policy; check minimum trials, file pin, repository, and offline/trusted-builder options.",
    "invalid_input": "Input must be readable bounded strict UTF-8 JSON; source details withheld.",
    "pin_mismatch": "Input file SHA-256 does not match the independent pin.",
    "unsupported_bundle_type": "Unsupported bundle type; source details withheld.",
    "invalid_evidence": "Bundle failed native verification; source-derived details withheld.",
    "verification_error": "Native verification could not complete; source-derived details withheld.",
}


@dataclass(frozen=True)
class ReviewPolicy:
    """Caller-selected verification requirements; never inferred from a report."""

    minimum_trials: int = 5
    offline: bool = False
    expected_file_sha256: str | None = None
    attestation_repository: str | None = None
    require_trusted_builder: bool = False
    allow_self_hosted_runner: bool = False

    def public_fields(self) -> dict:
        """Validate policy and return a projection without private repository names."""
        if type(self.minimum_trials) is not int or self.minimum_trials < 2:
            raise ValueError("invalid minimum trials")
        if any(type(flag) is not bool for flag in (
            self.offline, self.require_trusted_builder, self.allow_self_hosted_runner,
        )):
            raise ValueError("policy flags must be booleans")
        pin = self.expected_file_sha256
        if pin is not None and (not isinstance(pin, str) or re.fullmatch(r"[a-f0-9]{64}", pin) is None):
            raise ValueError("invalid file pin")
        repo = self.attestation_repository
        if repo is not None:
            if (not isinstance(repo, str) or re.fullmatch(r"[^/\s]+/[^/\s]+", repo) is None
                    or any(ord(char) < 32 or ord(char) == 127 for char in repo)):
                raise ValueError("invalid repository constraint")
            repo.encode("utf-8")
        if self.offline and self.require_trusted_builder:
            raise ValueError("offline mode cannot require authenticated builder identity")
        return {
            "minimum_trials": self.minimum_trials,
            "mode": "offline" if self.offline else "online",
            "expected_file_sha256": pin,
            "expected_repository_sha256": hashlib.sha256(repo.encode("utf-8")).hexdigest() if repo is not None else None,
            "require_trusted_builder": self.require_trusted_builder,
            "deny_self_hosted_runner": not self.allow_self_hosted_runner,
        }


def review_bundle(path: Path, *, policy: ReviewPolicy | None = None) -> dict:
    """Return a schema-v1 decision without printing or copying source strings.

    Exit 0: passes the selected review. Exit 1: valid but ineligible or provenance
    unverified. Exit 2: invalid policy/input/evidence. Offline decisions are
    deterministic for the same bytes, policy, and installed verifier. Online checks
    can change with external availability and trust state; rerun them when needed.
    """
    try:
        package_version = version("dspy-security-bench")
    except PackageNotFoundError:
        package_version = "unknown"
    result = {
        "schema_version": 1, "review_type": "ProofRun verification",
        "verifier_version": package_version,
        "input_file_sha256": None, "bundle_type": None, "bundle_sha256": None,
        "integrity": "not_checked", "eligibility": "not_checked",
        "provenance": "not_checked", "evidence_tier": "not_established",
        "policy": None, "review_is_attestation": False, "execution_reproduced": False,
    }

    def finish(exit_code, verdict, reason):
        return {**result, "exit_code": exit_code, "verdict": verdict, "reason_code": reason}

    policy = ReviewPolicy() if policy is None else policy
    try:
        if not isinstance(policy, ReviewPolicy):
            raise ValueError("policy must be a ReviewPolicy")
        result["policy"] = policy.public_fields()
    except (ValueError, TypeError):
        return finish(2, "invalid", "invalid_policy")
    try:
        path = Path(path)
        raw, bundle = read_json_snapshot(path, MAX_BUNDLE_BYTES)
    except (OSError, ValueError, TypeError):
        return finish(2, "invalid", "invalid_input")
    result["input_file_sha256"] = hashlib.sha256(raw).hexdigest()
    if policy.expected_file_sha256 is not None and policy.expected_file_sha256 != result["input_file_sha256"]:
        return finish(2, "invalid", "pin_mismatch")
    bundle_type = bundle.get("bundle_type")
    if not isinstance(bundle_type, str) or bundle_type not in FAMILIES:
        return finish(2, "invalid", "unsupported_bundle_type")
    result["bundle_type"] = bundle_type
    module_name, function_name, eligibility_field, _ = FAMILIES[bundle_type]
    try:
        verify = getattr(importlib.import_module(module_name), function_name)
        integrity = verify(bundle, minimum_trials=policy.minimum_trials)
        eligible = getattr(integrity, eligibility_field)
    except (OSError, TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        result["integrity"] = "invalid"
        return finish(2, "invalid", "verification_error")
    if not integrity.valid:
        result["integrity"] = "invalid"
        return finish(2, "invalid", "invalid_evidence")
    result.update(
        integrity="valid", eligibility="eligible" if eligible else "ineligible",
        bundle_sha256=integrity.bundle_sha256, evidence_tier=integrity.evidence_tier,
    )
    if not eligible:
        return finish(1, "not_eligible", "not_eligible")
    if policy.offline:
        return finish(0, "pass", "offline_verified")
    try:
        attestation = verify_github_attestation(
            path, bundle, repository=policy.attestation_repository,
            require_trusted_builder=policy.require_trusted_builder,
            deny_self_hosted=not policy.allow_self_hosted_runner, bundle_bytes=raw,
        )
    except (OSError, TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        result["provenance"] = "unverified"
        return finish(1, "attestation_unverified", "attestation_unverified")
    if not attestation.verified:
        result["provenance"] = "unverified"
        return finish(1, "attestation_unverified", "attestation_unverified")
    result.update(provenance="verified", evidence_tier=attestation.evidence_tier)
    return finish(0, "pass", "online_verified")


def render_review(review: dict) -> str:
    """Human-readable view of the same decision used by JSON consumers."""
    lines = []
    if review["input_file_sha256"] is not None:
        lines.append(f"Input snapshot sha256: {review['input_file_sha256']}")
    lines.append(f"Integrity: {review['integrity']}")
    bundle_type = review["bundle_type"]
    if bundle_type in FAMILIES:
        label = FAMILIES[bundle_type][3]
        eligible = {"eligible": "yes", "ineligible": "no", "not_checked": "not checked"}[review["eligibility"]]
        lines.append(f"{label}: {eligible}")
    tier_label = "Cryptographic" if review["provenance"] == "verified" else "Offline"
    lines.append(f"{tier_label} evidence tier: {review['evidence_tier']}")
    marker = "INVALID" if review["exit_code"] == 2 else review["verdict"].upper()
    lines.append(f"[{marker}] {REASONS[review['reason_code']]}")
    lines.append("This local review is not a signed attestation or independent execution reproduction.")
    return "\n".join(lines)
