"""Offline trust-root continuity for the AssuranceLedger protocol family.

The design borrows the security property of TUF root rotation—each successor is
authorized by thresholds from both the previously trusted and candidate roots—
without claiming wire-format or implementation compatibility with TUF.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

ROOT_TYPE = "dspy-security-bench-assurance-trust-root"
REPORT_TYPE = "AssuranceLedger TrustRoot / Threshold trust-anchor continuity evidence"
PROTOCOL_VERSION = "assuranceledger-trust-root-v1"
ANALYZER = "deterministic-threshold-trust-root-analyzer-v1"
SIGNATURE_SCHEMES = (
    "ecdsa-sha2-nistp256",
    "ed25519",
    "rsassa-pss-sha256",
)
ROLE_NAMES = (
    "ledger-observer",
    "ledger-operator",
    "ledger-witness",
    "quorum-reviewer",
    "root",
)
AUTHORIZED_POLICY_TYPES = (
    "dspy-security-bench-assurance-ledger-observer-policy",
    "dspy-security-bench-assurance-ledger-policy",
    "dspy-security-bench-assurance-quorum-policy",
    "dspy-security-bench-assurance-trust-recovery-policy",
)
TRUSTED_STATUSES = ("trusted_bootstrap", "trusted_rotation")
MAX_KEYS = 100
MAX_POLICIES = 100
MAX_SIGNATURES = 100
CLAIM_BOUNDARY = (
    "AssuranceTrustRoot verifies a pinned bootstrap or one-step, dual-threshold trust-root "
    "rotation; exact version and predecessor continuity; expiration; distinct-organization "
    "thresholds; supported signature schemes; and authorization of exact AssuranceLedger, "
    "ObserverReceipt, and AssuranceQuorum policy digests. A trusted result establishes only "
    "continuity from the caller-selected trust anchor. It does not prove legal identity, "
    "organizational independence, private-key custody, policy quality, artifact truth, global "
    "consistency, compliance, authorization to operate, procurement approval, deployment "
    "authority, or risk acceptance."
)
LIMITATIONS = (
    "This is an AssuranceLedger-specific format inspired by threshold root rotation; it is not a TUF, SCITT, PKI, or trust-store implementation.",
    "A first root is trusted only when its exact root_sha256 is supplied through an independent bootstrap channel.",
    "Expiration exposes a possible freeze or neglected rotation; an offline verifier cannot distinguish those causes.",
    "The supported algorithms provide migration choices but are not post-quantum algorithms or proof of deployment-level crypto agility.",
    "Identifiers and organization assignments are signed owner assertions, not externally proofed identities or independence guarantees.",
    "The verifier performs no network access, key generation, revocation, deployment, notification, authorization, or risk acceptance.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ROOT_FIELDS = {
    "schema_version",
    "root_type",
    "protocol_version",
    "trust_domain",
    "version",
    "issued_at",
    "expires_at",
    "previous_root_sha256",
    "keys",
    "roles",
    "authorized_policies",
    "signatures",
    "previous_root_signatures",
    "root_sha256",
}
_SIGNED_FIELDS = {
    "schema_version",
    "root_type",
    "protocol_version",
    "trust_domain",
    "version",
    "issued_at",
    "expires_at",
    "previous_root_sha256",
    "keys",
    "roles",
    "authorized_policies",
}
_KEY_FIELDS = {
    "keyid",
    "entity_id",
    "organization_id",
    "signature_scheme",
    "public_key_spki_base64",
}
_ROLE_FIELDS = {"keyids", "signature_threshold", "minimum_distinct_organizations"}
_POLICY_FIELDS = {"policy_type", "policy_sha256"}
_SIGNATURE_FIELDS = {"keyid", "signer_id", "signature_scheme", "signature_base64"}


def trust_key_descriptor(
    public_key_path: str | Path, *, entity_id: str, organization_id: str
) -> dict[str, str]:
    """Describe a supported public key with an algorithm-explicit stable identifier."""

    serialization, *_ = _crypto()
    try:
        public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load trust-root public key: {exc}") from exc
    scheme = _scheme_for_public_key(public)
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    descriptor = {
        "keyid": hashlib.sha256(der).hexdigest(),
        "entity_id": entity_id,
        "organization_id": organization_id,
        "signature_scheme": scheme,
        "public_key_spki_base64": base64.b64encode(der).decode(),
    }
    errors: list[str] = []
    _validate_key(descriptor, "key", errors)
    if errors:
        raise ValueError("invalid trust-root key descriptor: " + "; ".join(errors))
    return descriptor


def embedded_trust_key_descriptor(
    descriptor: Mapping[str, Any], *, entity_field: str = "entity_id"
) -> dict[str, str]:
    """Convert an existing Ed25519 assurance-policy key into a trust-root key."""

    try:
        entity_id = descriptor[entity_field]
        organization_id = descriptor["organization_id"]
        keyid = descriptor["public_key_sha256"]
        encoded = descriptor["public_key_spki_base64"]
    except KeyError as exc:
        raise ValueError(f"assurance key is missing {exc.args[0]}") from exc
    value = {
        "keyid": keyid,
        "entity_id": entity_id,
        "organization_id": organization_id,
        "signature_scheme": "ed25519",
        "public_key_spki_base64": encoded,
    }
    errors: list[str] = []
    _validate_key(value, "key", errors)
    if errors:
        raise ValueError("invalid embedded assurance key: " + "; ".join(errors))
    return value


def policy_descriptor(policy: Mapping[str, Any]) -> dict[str, str]:
    """Bind one exact, self-digested assurance policy into a root."""

    if not isinstance(policy, Mapping):
        raise ValueError("policy must be an object")
    policy_type = policy.get("policy_type")
    if policy_type not in AUTHORIZED_POLICY_TYPES:
        raise ValueError("policy_type is not supported by AssuranceTrustRoot v1")
    claimed = policy.get("policy_sha256")
    unsigned = dict(policy)
    unsigned.pop("policy_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError) as exc:
        raise ValueError("policy is not canonical JSON data") from exc
    if claimed != actual:
        raise ValueError("policy_sha256 does not recompute")
    return {"policy_type": str(policy_type), "policy_sha256": str(claimed)}


def build_trust_root(
    keys: Sequence[Mapping[str, Any]],
    roles: Mapping[str, Mapping[str, Any]],
    authorized_policies: Sequence[Mapping[str, Any]],
    *,
    trust_domain: str,
    version: int,
    issued_at: int,
    expires_at: int,
    previous_root_sha256: str | None = None,
) -> dict[str, Any]:
    """Build an unsigned trust root ready for current and predecessor signatures."""

    root: dict[str, Any] = {
        "schema_version": 1,
        "root_type": ROOT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "trust_domain": trust_domain,
        "version": version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "previous_root_sha256": previous_root_sha256,
        "keys": sorted((deepcopy(dict(item)) for item in keys), key=lambda item: item["keyid"]),
        "roles": {
            name: {
                "keyids": sorted(set(value["keyids"])),
                "signature_threshold": value["signature_threshold"],
                "minimum_distinct_organizations": value["minimum_distinct_organizations"],
            }
            for name, value in sorted(roles.items())
        },
        "authorized_policies": sorted(
            (deepcopy(dict(item)) for item in authorized_policies),
            key=lambda item: (item["policy_type"], item["policy_sha256"]),
        ),
        "signatures": [],
        "previous_root_signatures": [],
    }
    root["root_sha256"] = canonical_sha256(root)
    errors = _validate_payload(root)
    if errors:
        raise ValueError("invalid AssuranceTrustRoot payload: " + "; ".join(errors))
    return root


def sign_trust_root(
    root: Mapping[str, Any],
    private_key_path: str | Path,
    *,
    signing_root: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Add one current-root or predecessor-root threshold signature."""

    result = deepcopy(dict(root))
    if errors := _validate_payload(result):
        raise ValueError("invalid AssuranceTrustRoot payload: " + "; ".join(errors))
    if _root_sha256(result) != result.get("root_sha256"):
        raise ValueError("root_sha256 does not recompute before signing")
    authority = result if signing_root is None else signing_root
    if signing_root is not None:
        if errors := validate_trust_root(signing_root):
            raise ValueError("previous trust root is invalid: " + "; ".join(errors))
        if result.get("previous_root_sha256") != signing_root.get("root_sha256"):
            raise ValueError("candidate previous_root_sha256 does not match signing root")
    private, public_der, scheme = _load_private_key(private_key_path)
    keyid = hashlib.sha256(public_der).hexdigest()
    keys = {item["keyid"]: item for item in authority["keys"]}
    root_role = authority["roles"]["root"]
    descriptor = keys.get(keyid)
    if descriptor is None or keyid not in root_role["keyids"]:
        raise ValueError("private key is not authorized for the selected root role")
    if descriptor["signature_scheme"] != scheme:
        raise ValueError("private key algorithm does not match the root descriptor")
    signature = _sign(private, scheme, _canonical_bytes(_signed_payload(result)))
    entry = {
        "keyid": keyid,
        "signer_id": descriptor["entity_id"],
        "signature_scheme": scheme,
        "signature_base64": base64.b64encode(signature).decode(),
    }
    field = "signatures" if signing_root is None else "previous_root_signatures"
    if any(item.get("keyid") == keyid for item in result[field]):
        raise ValueError(f"{field} already contains this key")
    result[field].append(entry)
    result[field].sort(key=lambda item: item["keyid"])
    result.pop("root_sha256", None)
    result["root_sha256"] = canonical_sha256(result)
    return result


def validate_trust_root(root: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate structure, digest, and the candidate root's own threshold."""

    errors = list(_validate_payload(root))
    if not isinstance(root, Mapping):
        return tuple(errors)
    if root.get("root_sha256") != _root_sha256(root):
        errors.append("root_sha256 does not recompute")
    version = root.get("version")
    previous = root.get("previous_root_sha256")
    previous_signatures = root.get("previous_root_signatures")
    if version == 1:
        if previous is not None:
            errors.append("version 1 must not declare previous_root_sha256")
        if previous_signatures != []:
            errors.append("version 1 must not contain previous-root signatures")
    elif isinstance(version, int) and not isinstance(version, bool) and version > 1:
        if not _is_digest(previous):
            errors.append("successor roots require previous_root_sha256")
        if not isinstance(previous_signatures, list) or not previous_signatures:
            errors.append("successor roots require previous-root signatures")
    if not errors:
        threshold_errors, _, _ = _verify_role_signatures(
            root,
            root.get("signatures", []),
            root,
            label="current root",
        )
        errors.extend(threshold_errors)
    return tuple(dict.fromkeys(errors))


def evaluate_trust_root(
    candidate_root: Mapping[str, Any],
    *,
    evaluation_time: int,
    trusted_root: Mapping[str, Any] | None = None,
    expected_root_sha256: str | None = None,
    expected_trust_domain: str | None = None,
    minimum_version: int | None = None,
    policies: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Evaluate a pinned bootstrap or exactly one trust-root rotation."""

    if trusted_root is not None and expected_root_sha256 is not None:
        raise ValueError("select either a trusted root or a pinned root digest, not both")
    if isinstance(evaluation_time, bool) or not isinstance(evaluation_time, int):
        raise ValueError("evaluation_time must be an integer Unix timestamp")
    if minimum_version is not None and (
        isinstance(minimum_version, bool)
        or not isinstance(minimum_version, int)
        or minimum_version < 1
    ):
        raise ValueError("minimum_version must be a positive integer")
    if expected_root_sha256 is not None and not _is_digest(expected_root_sha256):
        raise ValueError("expected_root_sha256 must be a lowercase SHA-256 digest")
    if len(policies) > MAX_POLICIES:
        raise ValueError(f"policies exceeds {MAX_POLICIES} entries")

    source_errors = list(validate_trust_root(candidate_root))
    trust_errors: list[str] = []
    continuity = "bootstrap"
    status_hint: str | None = None
    previous_version: int | None = None
    previous_schemes: list[str] = []
    old_valid_signatures = 0
    old_distinct_organizations = 0
    candidate_mapping = candidate_root if isinstance(candidate_root, Mapping) else {}

    if expected_trust_domain is not None:
        if not isinstance(expected_trust_domain, str) or not expected_trust_domain.strip():
            raise ValueError("expected_trust_domain must be a non-empty string")
        if candidate_mapping.get("trust_domain") != expected_trust_domain:
            trust_errors.append("candidate trust_domain does not match the expected domain")

    if trusted_root is not None:
        continuity = "rotation"
        trusted_errors = list(validate_trust_root(trusted_root))
        if trusted_errors:
            trust_errors.extend(f"trusted root: {item}" for item in trusted_errors)
        trusted_mapping = trusted_root if isinstance(trusted_root, Mapping) else {}
        previous_version = _plain_int(trusted_mapping.get("version"))
        previous_schemes = _schemes(trusted_mapping)
        candidate_version = _plain_int(candidate_mapping.get("version"))
        if candidate_mapping.get("trust_domain") != trusted_mapping.get("trust_domain"):
            trust_errors.append("candidate and trusted roots use different trust domains")
        if candidate_version is not None and previous_version is not None:
            if candidate_version <= previous_version:
                status_hint = "rollback_detected"
                trust_errors.append("candidate version does not advance the trusted root")
            elif candidate_version != previous_version + 1:
                status_hint = "version_gap_detected"
                trust_errors.append("candidate version is not the exact next root version")
        if candidate_mapping.get("previous_root_sha256") != trusted_mapping.get("root_sha256"):
            trust_errors.append("candidate previous_root_sha256 breaks root continuity")
        if not trusted_errors and not source_errors:
            old_errors, old_valid_signatures, old_distinct_organizations = _verify_role_signatures(
                candidate_mapping,
                candidate_mapping.get("previous_root_signatures", []),
                trusted_mapping,
                label="previous root",
            )
            trust_errors.extend(old_errors)
    elif expected_root_sha256 is not None:
        if candidate_mapping.get("root_sha256") != expected_root_sha256:
            trust_errors.append("candidate root does not match the pinned bootstrap digest")
    else:
        status_hint = "untrusted_bootstrap"
        trust_errors.append("no trusted root or independently pinned bootstrap digest was supplied")

    candidate_version = _plain_int(candidate_mapping.get("version"))
    if minimum_version is not None and (
        candidate_version is None or candidate_version < minimum_version
    ):
        status_hint = "rollback_detected"
        trust_errors.append("candidate version is below the caller's minimum trusted version")

    expired = False
    not_yet_valid = False
    issued_at = _plain_int(candidate_mapping.get("issued_at"))
    if issued_at is not None and evaluation_time < issued_at:
        not_yet_valid = True
        trust_errors.append("candidate trust root is not yet valid at the evaluation time")
    expires_at = _plain_int(candidate_mapping.get("expires_at"))
    if expires_at is not None and evaluation_time >= expires_at:
        expired = True
        trust_errors.append("candidate trust root is expired at the evaluation time")

    policy_results = _evaluate_policies(candidate_mapping, policies)
    unauthorized = sum(item["status"] != "authorized" for item in policy_results)
    current_valid, current_orgs = _signature_counts(candidate_mapping)
    if source_errors:
        status = "invalid_trust_evidence"
    elif status_hint in {"rollback_detected", "version_gap_detected"}:
        status = status_hint
    elif not_yet_valid:
        status = "not_yet_valid_trust_root"
    elif expired:
        status = "expired_trust_root"
    elif trust_errors:
        status = status_hint or "trust_discontinuity"
    elif unauthorized:
        status = "policy_not_authorized"
    elif trusted_root is not None:
        status = "trusted_rotation"
    else:
        status = "trusted_bootstrap"

    current_schemes = _schemes(candidate_mapping)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "evaluation_time": evaluation_time,
        "anchor": {
            "mode": (
                "trusted-root"
                if trusted_root is not None
                else "pinned-root-digest"
                if expected_root_sha256 is not None
                else "none"
            ),
            "expected_root_sha256": expected_root_sha256,
            "expected_trust_domain": expected_trust_domain,
            "minimum_version": minimum_version,
        },
        "candidate_root": deepcopy(dict(candidate_mapping)),
        "trusted_root": deepcopy(dict(trusted_root)) if trusted_root is not None else None,
        "policy_inputs": [deepcopy(dict(item)) for item in policies],
        "source_errors": source_errors,
        "trust_errors": trust_errors,
        "policy_results": policy_results,
        "algorithm_transition": {
            "previous_schemes": previous_schemes,
            "candidate_schemes": current_schemes,
            "added_schemes": sorted(set(current_schemes) - set(previous_schemes)),
            "removed_schemes": sorted(set(previous_schemes) - set(current_schemes)),
        },
        "summary": {
            "status": status,
            "continuity_mode": continuity,
            "candidate_version": candidate_version,
            "previous_version": previous_version,
            "current_valid_root_signatures": current_valid,
            "current_distinct_root_organizations": current_orgs,
            "previous_valid_root_signatures": old_valid_signatures,
            "previous_distinct_root_organizations": old_distinct_organizations,
            "authorized_policies": len(policy_results) - unauthorized,
            "unauthorized_policies": unauthorized,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_trust_root_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Recompute a saved trust-root report from its fully embedded inputs."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceTrustRoot report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    anchor = report.get("anchor")
    if not isinstance(anchor, Mapping):
        errors.append("report anchor must be an object")
        return tuple(dict.fromkeys(errors))
    try:
        expected = evaluate_trust_root(
            report.get("candidate_root", {}),
            evaluation_time=report.get("evaluation_time"),
            trusted_root=report.get("trusted_root"),
            expected_root_sha256=anchor.get("expected_root_sha256"),
            expected_trust_domain=anchor.get("expected_trust_domain"),
            minimum_version=anchor.get("minimum_version"),
            policies=report.get("policy_inputs", []),
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"TrustRoot report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AssuranceTrustRoot report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _evaluate_policies(
    root: Mapping[str, Any], policies: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    allowed = {
        (item.get("policy_type"), item.get("policy_sha256"))
        for item in root.get("authorized_policies", [])
        if isinstance(item, Mapping)
    }
    results = []
    for index, policy in enumerate(policies):
        errors: list[str] = []
        descriptor: dict[str, str] | None = None
        try:
            descriptor = policy_descriptor(policy)
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
        if errors:
            status = "invalid_policy"
        elif (descriptor["policy_type"], descriptor["policy_sha256"]) not in allowed:
            status = "unauthorized_policy"
            errors.append("exact policy digest is not authorized by the candidate root")
        else:
            status = "authorized"
        results.append(
            {
                "policy_index": index,
                "policy_type": descriptor["policy_type"]
                if descriptor
                else policy.get("policy_type"),
                "policy_sha256": (
                    descriptor["policy_sha256"] if descriptor else policy.get("policy_sha256")
                ),
                "status": status,
                "errors": errors,
            }
        )
    return results


def _validate_payload(root: Any) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(root, Mapping):
        return ("trust root must be an object",)
    _exact(root, _ROOT_FIELDS, "trust root", errors)
    if (
        root.get("schema_version") != 1
        or root.get("root_type") != ROOT_TYPE
        or root.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("trust-root metadata does not match AssuranceTrustRoot v1")
    domain = root.get("trust_domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 300:
        errors.append("trust_domain must be a non-empty string of at most 300 characters")
    version = _positive_int(root.get("version"), "version", errors)
    issued = _nonnegative_int(root.get("issued_at"), "issued_at", errors)
    expires = _nonnegative_int(root.get("expires_at"), "expires_at", errors)
    if issued is not None and expires is not None and issued >= expires:
        errors.append("trust-root validity window must be non-empty")
    previous = root.get("previous_root_sha256")
    if previous is not None and not _is_digest(previous):
        errors.append("previous_root_sha256 must be null or a lowercase SHA-256 digest")
    if version == 1 and previous is not None:
        errors.append("version 1 cannot declare previous_root_sha256")

    keys = root.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        errors.append(f"keys must contain 1 to {MAX_KEYS} entries")
        keys = []
    if isinstance(keys, list) and keys != sorted(
        keys, key=lambda item: item.get("keyid", "") if isinstance(item, Mapping) else ""
    ):
        errors.append("keys must be sorted by keyid")
    keyids: set[str] = set()
    entity_ids: set[str] = set()
    valid_keys: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(keys):
        before = len(errors)
        _validate_key(item, f"keys[{index}]", errors)
        if not isinstance(item, Mapping):
            continue
        keyid = item.get("keyid")
        entity_id = item.get("entity_id")
        if keyid in keyids:
            errors.append(f"duplicate keyid {keyid!r}")
        if entity_id in entity_ids:
            errors.append(f"duplicate key entity_id {entity_id!r}")
        keyids.add(str(keyid))
        entity_ids.add(str(entity_id))
        if len(errors) == before and isinstance(keyid, str):
            valid_keys[keyid] = item

    roles = root.get("roles")
    if not isinstance(roles, Mapping) or set(roles) != set(ROLE_NAMES):
        errors.append("roles must contain the exact AssuranceTrustRoot v1 role set")
        roles = {}
    for name in ROLE_NAMES:
        role = roles.get(name) if isinstance(roles, Mapping) else None
        if not isinstance(role, Mapping):
            errors.append(f"role {name} must be an object")
            continue
        _exact(role, _ROLE_FIELDS, f"role {name}", errors)
        role_keyids = role.get("keyids")
        if (
            not isinstance(role_keyids, list)
            or not role_keyids
            or role_keyids != sorted(set(role_keyids))
            or any(not _is_digest(item) for item in role_keyids)
        ):
            errors.append(f"role {name} keyids must be a sorted non-empty unique digest list")
            role_keyids = []
        unknown = sorted(set(role_keyids) - set(valid_keys))
        if unknown:
            errors.append(f"role {name} references unknown keys: {', '.join(unknown)}")
        threshold = _positive_int(
            role.get("signature_threshold"), f"role {name} signature_threshold", errors
        )
        organizations = {
            valid_keys[item]["organization_id"] for item in role_keyids if item in valid_keys
        }
        minimum_orgs = _positive_int(
            role.get("minimum_distinct_organizations"),
            f"role {name} minimum_distinct_organizations",
            errors,
        )
        if threshold is not None and threshold > len(role_keyids):
            errors.append(f"role {name} signature threshold cannot be met")
        if minimum_orgs is not None and minimum_orgs > len(organizations):
            errors.append(f"role {name} organization threshold cannot be met")

    policies = root.get("authorized_policies")
    if not isinstance(policies, list) or not 1 <= len(policies) <= MAX_POLICIES:
        errors.append(f"authorized_policies must contain 1 to {MAX_POLICIES} entries")
        policies = []

    def policy_sort(item: Any) -> tuple[str, str]:
        if not isinstance(item, Mapping):
            return "", ""
        return str(item.get("policy_type", "")), str(item.get("policy_sha256", ""))

    if isinstance(policies, list) and policies != sorted(policies, key=policy_sort):
        errors.append("authorized_policies must be sorted")
    seen_policies: set[tuple[Any, Any]] = set()
    for index, item in enumerate(policies):
        if not isinstance(item, Mapping):
            errors.append(f"authorized_policies[{index}] must be an object")
            continue
        _exact(item, _POLICY_FIELDS, f"authorized_policies[{index}]", errors)
        if item.get("policy_type") not in AUTHORIZED_POLICY_TYPES:
            errors.append(f"authorized_policies[{index}] has an unsupported policy_type")
        if not _is_digest(item.get("policy_sha256")):
            errors.append(f"authorized_policies[{index}].policy_sha256 is invalid")
        identity = (item.get("policy_type"), item.get("policy_sha256"))
        if identity in seen_policies:
            errors.append(f"authorized_policies[{index}] is duplicated")
        seen_policies.add(identity)

    for field in ("signatures", "previous_root_signatures"):
        signatures = root.get(field)
        if not isinstance(signatures, list) or len(signatures) > MAX_SIGNATURES:
            errors.append(f"{field} must be an array of at most {MAX_SIGNATURES} entries")
            continue
        if signatures != sorted(
            signatures,
            key=lambda item: item.get("keyid", "") if isinstance(item, Mapping) else "",
        ):
            errors.append(f"{field} must be sorted by keyid")
        seen: set[str] = set()
        for index, signature in enumerate(signatures):
            _validate_signature_shape(signature, f"{field}[{index}]", errors)
            if isinstance(signature, Mapping):
                keyid = str(signature.get("keyid"))
                if keyid in seen:
                    errors.append(f"{field} contains duplicate keyid {keyid!r}")
                seen.add(keyid)
    if not _is_digest(root.get("root_sha256")):
        errors.append("root_sha256 must be a lowercase SHA-256 digest")
    return tuple(dict.fromkeys(errors))


def _validate_key(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return
    _exact(value, _KEY_FIELDS, label, errors)
    _identifier(value.get("entity_id"), f"{label}.entity_id", errors)
    _identifier(value.get("organization_id"), f"{label}.organization_id", errors)
    keyid = value.get("keyid")
    if not _is_digest(keyid):
        errors.append(f"{label}.keyid must be a lowercase SHA-256 digest")
    scheme = value.get("signature_scheme")
    if scheme not in SIGNATURE_SCHEMES:
        errors.append(f"{label}.signature_scheme is unsupported")
    try:
        der = base64.b64decode(str(value.get("public_key_spki_base64", "")), validate=True)
        serialization, *_ = _crypto()
        public = serialization.load_der_public_key(der)
        actual_scheme = _scheme_for_public_key(public)
        if scheme != actual_scheme:
            errors.append(f"{label}.signature_scheme does not match the embedded key")
        if hashlib.sha256(der).hexdigest() != keyid:
            errors.append(f"{label}.keyid does not match the embedded key")
    except (TypeError, ValueError):
        errors.append(f"{label} embedded public key is invalid or unsupported")


def _validate_signature_shape(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return
    _exact(value, _SIGNATURE_FIELDS, label, errors)
    if not _is_digest(value.get("keyid")):
        errors.append(f"{label}.keyid must be a lowercase SHA-256 digest")
    _identifier(value.get("signer_id"), f"{label}.signer_id", errors)
    if value.get("signature_scheme") not in SIGNATURE_SCHEMES:
        errors.append(f"{label}.signature_scheme is unsupported")
    try:
        signature = base64.b64decode(str(value.get("signature_base64", "")), validate=True)
        if not signature:
            raise ValueError("empty")
    except (TypeError, ValueError):
        errors.append(f"{label}.signature_base64 is invalid")


def _verify_role_signatures(
    payload_root: Mapping[str, Any],
    signatures: Any,
    authority_root: Mapping[str, Any],
    *,
    label: str,
) -> tuple[list[str], int, int]:
    errors: list[str] = []
    if not isinstance(signatures, list):
        return ([f"{label} signatures must be an array"], 0, 0)
    keys = {
        item["keyid"]: item
        for item in authority_root.get("keys", [])
        if isinstance(item, Mapping) and isinstance(item.get("keyid"), str)
    }
    role = authority_root.get("roles", {}).get("root", {})
    allowed = set(role.get("keyids", [])) if isinstance(role, Mapping) else set()
    valid: set[str] = set()
    organizations: set[str] = set()
    signed_bytes = _canonical_bytes(_signed_payload(payload_root))
    for index, signature in enumerate(signatures):
        if not isinstance(signature, Mapping):
            continue
        keyid = signature.get("keyid")
        descriptor = keys.get(keyid)
        if descriptor is None or keyid not in allowed:
            continue
        signature_errors = _verify_signature(
            signed_bytes, signature, descriptor, f"{label} signatures[{index}]"
        )
        if signature_errors:
            errors.extend(signature_errors)
            continue
        valid.add(str(keyid))
        organizations.add(str(descriptor["organization_id"]))
    threshold = role.get("signature_threshold") if isinstance(role, Mapping) else None
    minimum_orgs = role.get("minimum_distinct_organizations") if isinstance(role, Mapping) else None
    if isinstance(threshold, int) and len(valid) < threshold:
        errors.append(
            f"{label} signature threshold unmet: observed {len(valid)}, required {threshold}"
        )
    if isinstance(minimum_orgs, int) and len(organizations) < minimum_orgs:
        errors.append(
            f"{label} organization threshold unmet: observed {len(organizations)}, required {minimum_orgs}"
        )
    return errors, len(valid), len(organizations)


def _verify_signature(
    signed_bytes: bytes,
    signature: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    label: str,
) -> tuple[str, ...]:
    errors: list[str] = []
    if signature.get("signer_id") != descriptor.get("entity_id"):
        errors.append(f"{label} signer_id does not match the authorized key")
    if signature.get("signature_scheme") != descriptor.get("signature_scheme"):
        errors.append(f"{label} signature scheme does not match the authorized key")
    try:
        raw = base64.b64decode(str(signature.get("signature_base64", "")), validate=True)
        der = base64.b64decode(str(descriptor.get("public_key_spki_base64", "")), validate=True)
        serialization, _, _, _, _, _, InvalidSignature = _crypto()
        public = serialization.load_der_public_key(der)
        _verify(public, str(descriptor.get("signature_scheme")), raw, signed_bytes)
    except InvalidSignature:
        errors.append(f"{label} cryptographic signature is invalid")
    except (TypeError, ValueError):
        errors.append(f"{label} signature or public key is invalid")
    return tuple(errors)


def _signature_counts(root: Mapping[str, Any]) -> tuple[int, int]:
    if _validate_payload(root):
        return 0, 0
    _, valid, organizations = _verify_role_signatures(
        root, root.get("signatures", []), root, label="current root"
    )
    return valid, organizations


def _signed_payload(root: Mapping[str, Any]) -> dict[str, Any]:
    return {field: deepcopy(root[field]) for field in sorted(_SIGNED_FIELDS) if field in root}


def _root_sha256(root: Mapping[str, Any]) -> str:
    unsigned = dict(root)
    unsigned.pop("root_sha256", None)
    try:
        return canonical_sha256(unsigned)
    except (TypeError, ValueError):
        return "unavailable"


def _schemes(root: Mapping[str, Any]) -> list[str]:
    return sorted(
        {
            str(item.get("signature_scheme"))
            for item in root.get("keys", [])
            if isinstance(item, Mapping) and item.get("signature_scheme") in SIGNATURE_SCHEMES
        }
    )


def _load_private_key(path: str | Path) -> tuple[Any, bytes, str]:
    serialization, *_ = _crypto()
    try:
        private = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load trust-root private key: {exc}") from exc
    public = private.public_key()
    scheme = _scheme_for_public_key(public)
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, der, scheme


def _scheme_for_public_key(public: Any) -> str:
    _, Ed25519PublicKey, ec, rsa, *_ = _crypto()
    if isinstance(public, Ed25519PublicKey):
        return "ed25519"
    if isinstance(public, ec.EllipticCurvePublicKey):
        if not isinstance(public.curve, ec.SECP256R1):
            raise ValueError("only the NIST P-256 curve is supported")
        return "ecdsa-sha2-nistp256"
    if isinstance(public, rsa.RSAPublicKey):
        if public.key_size < 2048:
            raise ValueError("RSA trust-root keys must be at least 2048 bits")
        return "rsassa-pss-sha256"
    raise ValueError("unsupported trust-root public-key algorithm")


def _sign(private: Any, scheme: str, payload: bytes) -> bytes:
    _, _, ec, _, padding, hashes, _ = _crypto()
    if scheme == "ed25519":
        return private.sign(payload)
    if scheme == "ecdsa-sha2-nistp256":
        return private.sign(payload, ec.ECDSA(hashes.SHA256()))
    if scheme == "rsassa-pss-sha256":
        return private.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size),
            hashes.SHA256(),
        )
    raise ValueError("unsupported signature scheme")


def _verify(public: Any, scheme: str, signature: bytes, payload: bytes) -> None:
    _, _, ec, _, padding, hashes, _ = _crypto()
    if scheme == "ed25519":
        public.verify(signature, payload)
        return
    if scheme == "ecdsa-sha2-nistp256":
        public.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        return
    if scheme == "rsassa-pss-sha256":
        public.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size),
            hashes.SHA256(),
        )
        return
    raise ValueError("unsupported signature scheme")


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "AssuranceTrustRoot signing requires the 'signing' extra: "
            "pip install 'dspy-security-bench[signing]'"
        ) from exc
    return serialization, Ed25519PublicKey, ec, rsa, padding, hashes, InvalidSignature


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _positive_int(value: Any, label: str, errors: list[str]) -> int | None:
    result = _nonnegative_int(value, label, errors)
    if result is not None and result < 1:
        errors.append(f"{label} must be positive")
        return None
    return result


def _nonnegative_int(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{label} must be a non-negative integer")
        return None
    return value


def _plain_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))
