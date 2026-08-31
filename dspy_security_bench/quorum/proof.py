"""Role-separated, DSSE-signed review evidence for AssuranceGraph cases."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.assurance.case import verify_report as verify_assurance_report
from dspy_security_bench.mission.loader import canonical_sha256

POLICY_TYPE = "dspy-security-bench-assurance-quorum-policy"
REPORT_TYPE = "AssuranceQuorum / Role-separated assurance review evidence"
PROTOCOL_VERSION = "assurancequorum-v1"
ANALYZER = "deterministic-role-separated-review-analyzer-v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://immu4989.github.io/dspy-security-bench/predicates/assurance-review/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MAX_REVIEWERS = 50
MAX_CLAIMS = 100
MAX_ENVELOPES = 200
ROLES = (
    "system-owner",
    "evaluation-owner",
    "security-reviewer",
    "privacy-reviewer",
    "mission-owner",
    "independent-reviewer",
    "procurement-reviewer",
)
DECISIONS = ("evidence-sufficient", "evidence-gap", "abstain")
REASON_CODES = (
    "native-verification-reviewed",
    "claim-predicates-reviewed",
    "freshness-reviewed",
    "boundary-reviewed",
    "missing-evidence",
    "stale-evidence",
    "contradictory-evidence",
    "insufficient-source-independence",
    "scope-mismatch",
    "other-reviewed-gap",
)
_GAP_REASON_CODES = frozenset(
    {
        "missing-evidence",
        "stale-evidence",
        "contradictory-evidence",
        "insufficient-source-independence",
        "scope-mismatch",
        "other-reviewed-gap",
    }
)
PRESETS = ("independent-two-party", "federal-separation")
CLAIM_BOUNDARY = (
    "AssuranceQuorum verifies authorized Ed25519 signatures over role-scoped in-toto statements "
    "bound to one natively recomputed AssuranceGraph report and evaluates an owner-selected, "
    "content-addressed separation-of-duty policy. Quorum satisfaction means only that the "
    "required authorized reviewers signed evidence-sufficient statements for the assigned "
    "claims. It does not prove reviewer identity beyond governed key mappings, establish the "
    "truth or completeness of external observations, certify safety or compliance, approve a "
    "system, authorize deployment or operation, make a procurement decision, or accept risk."
)
LIMITATIONS = (
    "Embedded organization and role identifiers are policy assertions, not independently proofed identities.",
    "A cryptographically valid statement establishes key possession and exact signed content, not reviewer competence or independence.",
    "Reviewers assess the referenced evidence case; signatures do not make omitted hazards visible.",
    "An evidence-gap statement is preserved as a veto, but absence of a gap statement is not proof of safety.",
    "Key rotation, revocation, identity proofing, and organizational authorization are external governance responsibilities.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_FIELDS = {
    "schema_version",
    "policy_type",
    "policy_id",
    "title",
    "subject",
    "review_window",
    "reviewers",
    "claim_requirements",
    "constraints",
    "claim_boundary",
    "policy_sha256",
}
_SUBJECT_FIELDS = {"report_sha256", "case_sha256", "case_id", "profile_id"}
_WINDOW_FIELDS = {"not_before", "not_after"}
_REVIEWER_FIELDS = {
    "signer_id",
    "role",
    "organization_id",
    "public_key_spki_base64",
    "public_key_sha256",
}
_REQUIREMENT_FIELDS = {
    "claim_id",
    "required_roles",
    "minimum_supports",
    "minimum_distinct_organizations",
}
_CONSTRAINT_FIELDS = {
    "signature_algorithm",
    "statement_type",
    "predicate_type",
    "evidence_gap_veto",
    "unique_key_per_signer",
}
_PREDICATE_FIELDS = {
    "protocol_version",
    "policy_sha256",
    "case_id",
    "profile_id",
    "reviewer",
    "decision",
    "claim_ids",
    "reason_codes",
    "issued_at",
    "expires_at",
    "claim_boundary",
}


def build_policy(
    assurance_report: Mapping[str, Any],
    reviewers: Sequence[Mapping[str, Any]],
    *,
    policy_id: str,
    title: str,
    not_before: int,
    not_after: int,
    preset: str = "independent-two-party",
    evidence_root: str | Path,
) -> dict[str, Any]:
    _verified_assurance_report(assurance_report, evidence_root)
    if preset not in PRESETS:
        raise ValueError(f"unknown AssuranceQuorum preset {preset!r}")
    claims = assurance_report.get("claim_results", [])
    requirements = []
    for claim in claims:
        claim_id = str(claim["claim_id"])
        category = str(claim.get("category", ""))
        roles = _roles_for_claim(claim_id, category, preset)
        requirements.append(
            {
                "claim_id": claim_id,
                "required_roles": roles,
                "minimum_supports": len(roles),
                "minimum_distinct_organizations": 2,
            }
        )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "policy_id": policy_id,
        "title": title,
        "subject": {
            "report_sha256": assurance_report["report_sha256"],
            "case_sha256": assurance_report["case_sha256"],
            "case_id": assurance_report["case"]["case_id"],
            "profile_id": assurance_report["profile"]["profile_id"],
        },
        "review_window": {"not_before": not_before, "not_after": not_after},
        "reviewers": sorted(
            (_normalize_reviewer(item) for item in reviewers), key=lambda item: item["signer_id"]
        ),
        "claim_requirements": sorted(requirements, key=lambda item: item["claim_id"]),
        "constraints": {
            "signature_algorithm": "Ed25519",
            "statement_type": STATEMENT_TYPE,
            "predicate_type": PREDICATE_TYPE,
            "evidence_gap_veto": True,
            "unique_key_per_signer": True,
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    payload["policy_sha256"] = canonical_sha256(payload)
    errors = validate_policy(payload, assurance_report)
    if errors:
        raise ValueError("invalid AssuranceQuorum policy: " + "; ".join(errors))
    return payload


def reviewer_from_public_key(
    public_key_path: str | Path,
    *,
    signer_id: str,
    role: str,
    organization_id: str,
) -> dict[str, Any]:
    _, Ed25519PublicKey, serialization, _ = _crypto()
    try:
        public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load Ed25519 public key: {exc}") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("AssuranceQuorum requires an Ed25519 public key")
    public_der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "signer_id": signer_id,
        "role": role,
        "organization_id": organization_id,
        "public_key_spki_base64": base64.b64encode(public_der).decode(),
        "public_key_sha256": hashlib.sha256(public_der).hexdigest(),
    }


def validate_policy(
    policy: Mapping[str, Any], assurance_report: Mapping[str, Any] | None = None
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "policy", errors)
    if policy.get("schema_version") != 1 or policy.get("policy_type") != POLICY_TYPE:
        errors.append("policy metadata does not match AssuranceQuorum v1")
    _identifier(policy.get("policy_id"), "policy_id", errors)
    _text(policy.get("title"), "title", 300, errors)
    subject = _mapping(policy.get("subject"), "subject", errors)
    if subject is not None:
        _exact(subject, _SUBJECT_FIELDS, "subject", errors)
        for field in ("report_sha256", "case_sha256"):
            _digest(subject.get(field), f"subject.{field}", errors)
        _identifier(subject.get("case_id"), "subject.case_id", errors)
        _identifier(subject.get("profile_id"), "subject.profile_id", errors)
    window = _mapping(policy.get("review_window"), "review_window", errors)
    if window is not None:
        _exact(window, _WINDOW_FIELDS, "review_window", errors)
        not_before = _integer(window.get("not_before"), "review_window.not_before", errors)
        not_after = _integer(window.get("not_after"), "review_window.not_after", errors)
        if not_before is not None and not_after is not None and not_before >= not_after:
            errors.append("review_window.not_before must precede not_after")
    reviewers = policy.get("reviewers")
    signer_ids: set[str] = set()
    key_ids: set[str] = set()
    reviewer_roles: set[str] = set()
    if not isinstance(reviewers, list) or not 2 <= len(reviewers) <= MAX_REVIEWERS:
        errors.append(f"reviewers must contain 2 to {MAX_REVIEWERS} entries")
        reviewers = []
    for index, reviewer in enumerate(reviewers):
        label = f"reviewers[{index}]"
        if not isinstance(reviewer, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(reviewer, _REVIEWER_FIELDS, label, errors)
        _identifier(reviewer.get("signer_id"), f"{label}.signer_id", errors)
        _identifier(reviewer.get("organization_id"), f"{label}.organization_id", errors)
        if reviewer.get("role") not in ROLES:
            errors.append(f"{label}.role is unsupported")
        else:
            reviewer_roles.add(str(reviewer["role"]))
        signer_id = reviewer.get("signer_id")
        key_id = reviewer.get("public_key_sha256")
        if isinstance(signer_id, str):
            if signer_id in signer_ids:
                errors.append(f"duplicate signer_id {signer_id!r}")
            signer_ids.add(signer_id)
        _digest(key_id, f"{label}.public_key_sha256", errors)
        if isinstance(key_id, str):
            if key_id in key_ids:
                errors.append(f"duplicate reviewer key {key_id!r}")
            key_ids.add(key_id)
        try:
            public_der = base64.b64decode(
                str(reviewer.get("public_key_spki_base64", "")), validate=True
            )
        except (TypeError, ValueError):
            errors.append(f"{label}.public_key_spki_base64 is invalid")
        else:
            if key_id != hashlib.sha256(public_der).hexdigest():
                errors.append(f"{label}.public_key_sha256 does not match the embedded key")
            try:
                _, Ed25519PublicKey, serialization, _ = _crypto()
                public = serialization.load_der_public_key(public_der)
                if not isinstance(public, Ed25519PublicKey):
                    errors.append(f"{label} key is not Ed25519")
            except (TypeError, ValueError):
                errors.append(f"{label} embedded public key is invalid")
    requirements = policy.get("claim_requirements")
    claim_ids: set[str] = set()
    if not isinstance(requirements, list) or not 1 <= len(requirements) <= MAX_CLAIMS:
        errors.append(f"claim_requirements must contain 1 to {MAX_CLAIMS} entries")
        requirements = []
    for index, requirement in enumerate(requirements):
        label = f"claim_requirements[{index}]"
        if not isinstance(requirement, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(requirement, _REQUIREMENT_FIELDS, label, errors)
        claim_id = requirement.get("claim_id")
        _identifier(claim_id, f"{label}.claim_id", errors)
        if isinstance(claim_id, str):
            if claim_id in claim_ids:
                errors.append(f"duplicate claim requirement {claim_id!r}")
            claim_ids.add(claim_id)
        roles = requirement.get("required_roles")
        if (
            not isinstance(roles, list)
            or not roles
            or len(roles) != len(set(roles))
            or not all(role in ROLES for role in roles)
        ):
            errors.append(f"{label}.required_roles must be a unique non-empty role list")
            roles = []
        if missing_roles := sorted(set(roles) - reviewer_roles):
            errors.append(
                f"{label} has no authorized reviewer for roles: {', '.join(missing_roles)}"
            )
        supports = _integer(
            requirement.get("minimum_supports"), f"{label}.minimum_supports", errors
        )
        organizations = _integer(
            requirement.get("minimum_distinct_organizations"),
            f"{label}.minimum_distinct_organizations",
            errors,
        )
        if supports is not None and not 1 <= supports <= len(roles):
            errors.append(f"{label}.minimum_supports must be between 1 and the required role count")
        if organizations is not None and not 1 <= organizations <= len(reviewers):
            errors.append(f"{label}.minimum_distinct_organizations is outside the reviewer bound")
        eligible_reviewers = [
            reviewer
            for reviewer in reviewers
            if isinstance(reviewer, Mapping) and reviewer.get("role") in roles
        ]
        if supports is not None and supports > len(eligible_reviewers):
            errors.append(f"{label} cannot meet minimum_supports with its authorized reviewers")
        eligible_organizations = {
            reviewer.get("organization_id") for reviewer in eligible_reviewers
        }
        if organizations is not None and organizations > len(eligible_organizations):
            errors.append(
                f"{label} cannot meet minimum_distinct_organizations with its authorized reviewers"
            )
    constraints = _mapping(policy.get("constraints"), "constraints", errors)
    expected_constraints = {
        "signature_algorithm": "Ed25519",
        "statement_type": STATEMENT_TYPE,
        "predicate_type": PREDICATE_TYPE,
        "evidence_gap_veto": True,
        "unique_key_per_signer": True,
    }
    if constraints is not None:
        _exact(constraints, _CONSTRAINT_FIELDS, "constraints", errors)
        if dict(constraints) != expected_constraints:
            errors.append("constraints do not match AssuranceQuorum v1")
    if policy.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match AssuranceQuorum v1")
    claimed = policy.get("policy_sha256")
    unsigned = dict(policy)
    unsigned.pop("policy_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("policy_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("policy is not canonical JSON data")
    if assurance_report is not None and subject is not None:
        expected_subject = {
            "report_sha256": assurance_report.get("report_sha256"),
            "case_sha256": assurance_report.get("case_sha256"),
            "case_id": assurance_report.get("case", {}).get("case_id"),
            "profile_id": assurance_report.get("profile", {}).get("profile_id"),
        }
        if dict(subject) != expected_subject:
            errors.append("policy subject does not match the AssuranceGraph report")
        report_claims = {
            item.get("claim_id")
            for item in assurance_report.get("claim_results", [])
            if isinstance(item, Mapping)
        }
        if claim_ids != report_claims:
            errors.append("claim_requirements must exactly cover the AssuranceGraph claims")
    return tuple(dict.fromkeys(errors))


def sign_review(
    policy: Mapping[str, Any],
    assurance_report: Mapping[str, Any],
    private_key_path: str | Path,
    *,
    signer_id: str,
    decision: str,
    claim_ids: Sequence[str],
    reason_codes: Sequence[str],
    issued_at: int,
    expires_at: int,
    evidence_root: str | Path,
) -> dict[str, Any]:
    _verified_assurance_report(assurance_report, evidence_root)
    policy_errors = validate_policy(policy, assurance_report)
    if policy_errors:
        raise ValueError("invalid AssuranceQuorum policy: " + "; ".join(policy_errors))
    reviewers = {item["signer_id"]: item for item in policy["reviewers"]}
    if signer_id not in reviewers:
        raise ValueError("signer_id is not authorized by the policy")
    reviewer = reviewers[signer_id]
    if decision not in DECISIONS:
        raise ValueError("decision is unsupported")
    if not claim_ids or len(claim_ids) != len(set(claim_ids)):
        raise ValueError("claim_ids must be a unique non-empty list")
    valid_claims = {item["claim_id"] for item in policy["claim_requirements"]}
    if unknown := sorted(set(claim_ids) - valid_claims):
        raise ValueError("review references unknown claims: " + ", ".join(unknown))
    requirements = {item["claim_id"]: item for item in policy["claim_requirements"]}
    if unauthorized := sorted(
        claim_id
        for claim_id in claim_ids
        if reviewer["role"] not in requirements[claim_id]["required_roles"]
    ):
        raise ValueError("reviewer role is not assigned to claims: " + ", ".join(unauthorized))
    if not reason_codes or not all(item in REASON_CODES for item in reason_codes):
        raise ValueError("reason_codes must use the frozen AssuranceQuorum vocabulary")
    gap_reasons = _GAP_REASON_CODES.intersection(reason_codes)
    if decision == "evidence-gap" and not gap_reasons:
        raise ValueError("evidence-gap requires at least one frozen gap reason code")
    if decision == "evidence-sufficient" and gap_reasons:
        raise ValueError("evidence-sufficient cannot use a frozen gap reason code")
    window = policy["review_window"]
    if not window["not_before"] <= issued_at < expires_at <= window["not_after"]:
        raise ValueError("review timestamps must fit inside the policy review window")
    Ed25519PrivateKey, _, serialization, _ = _crypto()
    try:
        private = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=None
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load Ed25519 private key: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("AssuranceQuorum requires an Ed25519 private key")
    public_der = private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if hashlib.sha256(public_der).hexdigest() != reviewer["public_key_sha256"]:
        raise ValueError("private key does not match the policy-authorized reviewer key")
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "assurance-report.json",
                "digest": {"sha256": assurance_report["report_sha256"]},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "protocol_version": PROTOCOL_VERSION,
            "policy_sha256": policy["policy_sha256"],
            "case_id": policy["subject"]["case_id"],
            "profile_id": policy["subject"]["profile_id"],
            "reviewer": {
                "signer_id": reviewer["signer_id"],
                "role": reviewer["role"],
                "organization_id": reviewer["organization_id"],
                "key_sha256": reviewer["public_key_sha256"],
            },
            "decision": decision,
            "claim_ids": sorted(claim_ids),
            "reason_codes": sorted(set(reason_codes)),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "claim_boundary": CLAIM_BOUNDARY,
        },
    }
    payload = _canonical_bytes(statement)
    signature = private.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": reviewer["public_key_sha256"],
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }


def verify_review_envelope(
    envelope: Mapping[str, Any],
    policy: Mapping[str, Any],
    assurance_report: Mapping[str, Any],
    *,
    evaluation_time: int,
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    errors: list[str] = []
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        return None, ("DSSE envelope fields are incomplete or unsupported",)
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        errors.append("DSSE payloadType is unsupported")
    signatures = envelope.get("signatures")
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], Mapping)
        or set(signatures[0]) != {"keyid", "sig"}
    ):
        errors.append("DSSE envelope must contain exactly one keyid/sig signature")
        signatures = []
    try:
        payload_bytes = base64.b64decode(str(envelope.get("payload", "")), validate=True)
        statement = json.loads(payload_bytes)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, tuple(dict.fromkeys([*errors, "DSSE payload is not valid base64 JSON"]))
    if _canonical_bytes(statement) != payload_bytes:
        errors.append("DSSE statement payload is not canonical JSON")
    if not isinstance(statement, Mapping) or set(statement) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        return None, tuple(dict.fromkeys([*errors, "in-toto statement fields are invalid"]))
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        errors.append("in-toto statement or predicate type is unsupported")
    subject = statement.get("subject")
    expected_subject = [
        {
            "name": "assurance-report.json",
            "digest": {"sha256": assurance_report.get("report_sha256")},
        }
    ]
    if subject != expected_subject:
        errors.append("in-toto subject does not match the AssuranceGraph report")
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        return None, tuple(dict.fromkeys([*errors, "review predicate must be an object"]))
    _exact(predicate, _PREDICATE_FIELDS, "predicate", errors)
    if predicate.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("review protocol_version is unsupported")
    if predicate.get("policy_sha256") != policy.get("policy_sha256"):
        errors.append("review policy_sha256 does not match")
    for field in ("case_id", "profile_id"):
        if predicate.get(field) != policy.get("subject", {}).get(field):
            errors.append(f"review {field} does not match policy")
    reviewer = predicate.get("reviewer")
    if not isinstance(reviewer, Mapping) or set(reviewer) != {
        "signer_id",
        "role",
        "organization_id",
        "key_sha256",
    }:
        errors.append("reviewer fields are invalid")
        reviewer = {}
    authorized = {
        item["signer_id"]: item for item in policy.get("reviewers", []) if isinstance(item, Mapping)
    }
    signer_id = reviewer.get("signer_id")
    expected_reviewer = authorized.get(signer_id)
    if expected_reviewer is None:
        errors.append("review signer is not policy-authorized")
    else:
        expected_identity = {
            "signer_id": expected_reviewer["signer_id"],
            "role": expected_reviewer["role"],
            "organization_id": expected_reviewer["organization_id"],
            "key_sha256": expected_reviewer["public_key_sha256"],
        }
        if dict(reviewer) != expected_identity:
            errors.append("signed reviewer identity does not match policy")
    if predicate.get("decision") not in DECISIONS:
        errors.append("review decision is unsupported")
    claims = predicate.get("claim_ids")
    valid_claims = {
        item["claim_id"]
        for item in policy.get("claim_requirements", [])
        if isinstance(item, Mapping)
    }
    if (
        not isinstance(claims, list)
        or not claims
        or claims != sorted(set(claims))
        or not all(isinstance(item, str) for item in claims)
    ):
        errors.append("review claim_ids must be a sorted unique non-empty string list")
        claims = []
    elif unknown := sorted(set(claims) - valid_claims):
        errors.append("review references unknown claims: " + ", ".join(unknown))
    elif expected_reviewer is not None:
        requirements = {
            item["claim_id"]: item
            for item in policy.get("claim_requirements", [])
            if isinstance(item, Mapping)
        }
        if unauthorized := sorted(
            claim_id
            for claim_id in claims
            if expected_reviewer["role"] not in requirements[claim_id]["required_roles"]
        ):
            errors.append("reviewer role is not assigned to claims: " + ", ".join(unauthorized))
    reasons = predicate.get("reason_codes")
    if (
        not isinstance(reasons, list)
        or not reasons
        or reasons != sorted(set(reasons))
        or not all(item in REASON_CODES for item in reasons)
    ):
        errors.append("review reason_codes are invalid")
    else:
        gap_reasons = _GAP_REASON_CODES.intersection(reasons)
        if predicate.get("decision") == "evidence-gap" and not gap_reasons:
            errors.append("evidence-gap lacks a frozen gap reason code")
        if predicate.get("decision") == "evidence-sufficient" and gap_reasons:
            errors.append("evidence-sufficient uses a frozen gap reason code")
    issued_at = predicate.get("issued_at")
    expires_at = predicate.get("expires_at")
    if any(
        isinstance(value, bool) or not isinstance(value, int) for value in (issued_at, expires_at)
    ):
        errors.append("review timestamps must be integers")
    else:
        window = policy.get("review_window", {})
        if not window.get("not_before", 0) <= issued_at < expires_at <= window.get("not_after", 0):
            errors.append("review timestamps are outside the policy window")
        if not issued_at <= evaluation_time < expires_at:
            errors.append("review is not current at the evaluation time")
    if predicate.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("review claim_boundary does not match AssuranceQuorum v1")
    if signatures and expected_reviewer is not None:
        signature_record = signatures[0]
        if signature_record.get("keyid") != expected_reviewer["public_key_sha256"]:
            errors.append("DSSE signature keyid does not match the authorized reviewer key")
        try:
            signature = base64.b64decode(str(signature_record.get("sig", "")), validate=True)
            public_der = base64.b64decode(
                expected_reviewer["public_key_spki_base64"], validate=True
            )
            _, Ed25519PublicKey, serialization, InvalidSignature = _crypto()
            public = serialization.load_der_public_key(public_der)
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("authorized key is not Ed25519")
            public.verify(signature, _pae(PAYLOAD_TYPE, payload_bytes))
        except InvalidSignature:
            errors.append("DSSE Ed25519 signature is invalid")
        except (TypeError, ValueError):
            errors.append("DSSE signature or authorized public key is invalid")
    return deepcopy(dict(statement)), tuple(dict.fromkeys(errors))


def analyze_quorum(
    policy: Mapping[str, Any],
    assurance_report: Mapping[str, Any],
    envelopes: Sequence[Mapping[str, Any]],
    *,
    evidence_root: str | Path,
    evaluation_time: int,
) -> dict[str, Any]:
    if (
        isinstance(evaluation_time, bool)
        or not isinstance(evaluation_time, int)
        or evaluation_time < 0
    ):
        raise ValueError("evaluation_time must be a non-negative integer")
    _verified_assurance_report(assurance_report, evidence_root)
    policy_errors = validate_policy(policy, assurance_report)
    if policy_errors:
        raise ValueError("invalid AssuranceQuorum policy: " + "; ".join(policy_errors))
    if not 1 <= len(envelopes) <= MAX_ENVELOPES:
        raise ValueError(f"review envelopes must contain 1 to {MAX_ENVELOPES} items")
    review_results = []
    valid_statements: list[Mapping[str, Any]] = []
    valid_signers: list[str] = []
    for index, envelope in enumerate(envelopes):
        statement, errors = verify_review_envelope(
            envelope, policy, assurance_report, evaluation_time=evaluation_time
        )
        predicate = statement.get("predicate", {}) if isinstance(statement, Mapping) else {}
        signer_id = (
            predicate.get("reviewer", {}).get("signer_id")
            if isinstance(predicate, Mapping)
            else None
        )
        review_results.append(
            {
                "review_index": index,
                "envelope_sha256": _safe_digest(envelope),
                "status": "valid" if not errors else "invalid",
                "signer_id": signer_id,
                "role": predicate.get("reviewer", {}).get("role")
                if isinstance(predicate, Mapping)
                else None,
                "organization_id": predicate.get("reviewer", {}).get("organization_id")
                if isinstance(predicate, Mapping)
                else None,
                "decision": predicate.get("decision") if isinstance(predicate, Mapping) else None,
                "claim_ids": list(predicate.get("claim_ids", []))
                if isinstance(predicate, Mapping)
                else [],
                "errors": list(errors),
            }
        )
        if not errors and statement is not None:
            valid_statements.append(statement)
            valid_signers.append(str(signer_id))
    duplicate_signers = sorted(
        {signer for signer in valid_signers if valid_signers.count(signer) > 1}
    )
    claim_results = []
    for requirement in policy["claim_requirements"]:
        claim_id = requirement["claim_id"]
        statements = [
            item["predicate"]
            for item in valid_statements
            if claim_id in item["predicate"]["claim_ids"]
        ]
        gap_reviewers = sorted(
            item["reviewer"]["signer_id"]
            for item in statements
            if item["decision"] == "evidence-gap"
        )
        supports = [item for item in statements if item["decision"] == "evidence-sufficient"]
        support_roles = sorted({item["reviewer"]["role"] for item in supports})
        support_signers = sorted({item["reviewer"]["signer_id"] for item in supports})
        organizations = sorted({item["reviewer"]["organization_id"] for item in supports})
        missing_roles = sorted(set(requirement["required_roles"]) - set(support_roles))
        if gap_reviewers:
            status = "review_gap_recorded"
        elif (
            missing_roles
            or len(support_signers) < requirement["minimum_supports"]
            or len(organizations) < requirement["minimum_distinct_organizations"]
        ):
            status = "quorum_incomplete"
        else:
            status = "quorum_satisfied"
        claim_results.append(
            {
                "claim_id": claim_id,
                "status": status,
                "required_roles": list(requirement["required_roles"]),
                "supporting_roles": support_roles,
                "supporting_signers": support_signers,
                "distinct_organizations": organizations,
                "gap_reviewers": gap_reviewers,
                "missing_roles": missing_roles,
                "minimum_supports": requirement["minimum_supports"],
                "minimum_distinct_organizations": requirement["minimum_distinct_organizations"],
            }
        )
    invalid_count = sum(item["status"] == "invalid" for item in review_results)
    counts = {
        status: sum(item["status"] == status for item in claim_results)
        for status in ("quorum_satisfied", "review_gap_recorded", "quorum_incomplete")
    }
    if invalid_count or duplicate_signers:
        overall = "invalid_review_evidence"
    elif counts["review_gap_recorded"]:
        overall = "review_gap_recorded"
    elif counts["quorum_incomplete"]:
        overall = "quorum_incomplete"
    else:
        overall = "quorum_satisfied"
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "evaluation_time": evaluation_time,
        "policy": deepcopy(dict(policy)),
        "assurance_report": deepcopy(dict(assurance_report)),
        "review_envelopes": deepcopy(list(envelopes)),
        "review_results": review_results,
        "claim_results": claim_results,
        "summary": {
            "status": overall,
            "claim_count": len(claim_results),
            "claim_status_counts": counts,
            "submitted_reviews": len(envelopes),
            "valid_reviews": len(valid_statements),
            "invalid_reviews": invalid_count,
            "duplicate_signers": duplicate_signers,
            "evidence_gap_vetoes": sum(len(item["gap_reviewers"]) for item in claim_results),
            "distinct_valid_signers": len(set(valid_signers)),
            "automatic_deployment_actions": 0,
            "automatic_risk_acceptances": 0,
            "automatic_authorizations_to_operate": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_quorum_report(
    payload: Mapping[str, Any], *, evidence_root: str | Path
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ("report must be an object",)
    if (
        payload.get("report_type") != REPORT_TYPE
        or payload.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceQuorum report type or protocol version")
    claimed = payload.get("report_sha256")
    unsigned = dict(payload)
    unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = analyze_quorum(
            payload.get("policy", {}),
            payload.get("assurance_report", {}),
            payload.get("review_envelopes", []),
            evidence_root=evidence_root,
            evaluation_time=payload.get("evaluation_time"),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if payload != expected:
            errors.append("AssuranceQuorum report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _roles_for_claim(claim_id: str, category: str, preset: str) -> list[str]:
    if preset == "independent-two-party":
        return ["system-owner", "independent-reviewer"]
    if claim_id == "evaluation-process-integrity":
        return ["evaluation-owner", "independent-reviewer"]
    if category == "logging-and-observability":
        return ["privacy-reviewer", "security-reviewer"]
    if category in {"verified-cyber-defense", "mission-resilience"}:
        return ["mission-owner", "independent-reviewer"]
    return ["security-reviewer", "independent-reviewer"]


def _normalize_reviewer(reviewer: Mapping[str, Any]) -> dict[str, Any]:
    return {field: reviewer[field] for field in sorted(_REVIEWER_FIELDS)}


def _verified_assurance_report(report: Mapping[str, Any], evidence_root: str | Path) -> None:
    errors = verify_assurance_report(report, evidence_root)
    if errors:
        raise ValueError("AssuranceGraph report failed native verification: " + "; ".join(errors))


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode()
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode()
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def _safe_digest(payload: Any) -> str:
    try:
        return canonical_sha256(payload)
    except (TypeError, ValueError):
        return "unavailable"


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _mapping(value: Any, label: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return None
    return value


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _text(value: Any, label: str, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        errors.append(f"{label} must be a non-empty string of at most {maximum} characters")


def _digest(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        errors.append(f"{label} must be a SHA-256 digest")


def _integer(value: Any, label: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{label} must be a non-negative integer")
        return None
    return value


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "AssuranceQuorum signing requires: pip install 'dspy-security-bench[signing]'"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature
