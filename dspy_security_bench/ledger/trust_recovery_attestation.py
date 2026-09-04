"""DSSE-authenticated, replay-resistant handoffs for TrustRecoveryDrill."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.trust_recovery import (
    EVENT_ROLES,
    ROLE_NAMES,
    evaluate_recovery_drill,
    validate_recovery_drill,
    validate_recovery_policy,
)
from dspy_security_bench.ledger.trust_recovery import (
    TRUSTED_STATUS as RECOVERY_READY_STATUS,
)
from dspy_security_bench.ledger.trust_root import evaluate_trust_root
from dspy_security_bench.mission.loader import canonical_sha256

POLICY_TYPE = "dspy-security-bench-assurance-trust-recovery-attestation-policy"
REPORT_TYPE = "AssuranceLedger TrustRecoveryAttestation / Authenticated recovery handoffs"
PROTOCOL_VERSION = "assuranceledger-trust-recovery-attestation-v1"
ANALYZER = "deterministic-recovery-handoff-attestation-analyzer-v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://immu4989.github.io/dspy-security-bench/predicates/trust-recovery-event/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
GENESIS_ATTESTATION_SHA256 = "0" * 64
TRUSTED_STATUS = "authenticated_recovery_handoffs"
MAX_SIGNERS = 100
MAX_ENVELOPES = len(EVENT_ROLES)
CLAIM_BOUNDARY = (
    "TrustRecoveryAttestation verifies canonical in-toto Statements in DSSE envelopes for "
    "every content-minimized TrustRecoveryDrill event. It checks exact event subjects, "
    "root-authorized signer policy, recovery-role assignment, Ed25519 key possession, policy "
    "and drill bindings, timestamp order, unique replay nonces, and a digest-linked handoff "
    "chain. A passing report authenticates the recorded handoffs for the supplied simulation "
    "only. It never authorizes, creates, distributes, installs, revokes, or activates a root."
)
LIMITATIONS = (
    "A valid signature proves possession of a policy-authorized private key, not legal identity, competence, physical presence, or uncompromised key custody.",
    "Event attestations bind content-free evidence digests; they do not reveal or prove the truth, quality, completeness, or safe handling of the underlying records.",
    "Digest chaining detects deletion, insertion, reordering, and replay only when the verifier receives the expected complete drill and independently pinned root.",
    "This profile uses canonical JSON inside DSSE for deterministic fixtures; DSSE authenticates the exact payload bytes and payload type.",
    "The protocol is an AssuranceLedger application profile, not an in-toto predicate standard, TUF recovery mechanism, PKI, FIPS validation, compliance certification, authorization to operate, or risk acceptance.",
    "The analyzer performs no network access, key generation, notification, deployment, revocation, rollback, recovery action, or automatic remediation.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_FIELDS = {
    "schema_version",
    "policy_type",
    "protocol_version",
    "attestation_policy_id",
    "recovery_policy_sha256",
    "plan_id",
    "trust_domain",
    "root_version",
    "issued_at",
    "expires_at",
    "signers",
    "required_event_types",
    "policy_sha256",
}
_SIGNER_FIELDS = {
    "signer_id",
    "recovery_role",
    "organization_id",
    "public_key_spki_base64",
    "public_key_sha256",
}
_PREDICATE_FIELDS = {
    "protocol_version",
    "attestation_policy_sha256",
    "recovery_policy_sha256",
    "plan_id",
    "drill_id",
    "trust_domain",
    "root_sha256",
    "root_version",
    "sequence",
    "event_type",
    "actor",
    "evidence_sha256",
    "occurred_at",
    "issued_at",
    "nonce",
    "previous_attestation_sha256",
    "simulation_only",
    "claim_boundary",
}
_ACTOR_FIELDS = {"signer_id", "recovery_role", "organization_id", "key_sha256"}
_CHECKS = (
    ("TRA001", "Every recovery event has exactly one ordered attestation"),
    ("TRA002", "Every envelope and in-toto Statement is structurally valid"),
    ("TRA003", "Every statement subject binds the exact recovery event"),
    ("TRA004", "Every statement binds the exact root, policies, and drill"),
    ("TRA005", "Every signer matches the event actor and assigned recovery role"),
    ("TRA006", "Every DSSE Ed25519 signature verifies"),
    ("TRA007", "Every attestation timestamp is ordered, current, and policy-bounded"),
    ("TRA008", "Every attestation carries a unique replay nonce"),
    ("TRA009", "Attestations form one exact digest-linked handoff chain"),
    ("TRA010", "The anchored trust root authorizes both exact recovery policies"),
)


def attester_descriptor(
    public_key_path: str | Path,
    *,
    signer_id: str,
    recovery_role: str,
    organization_id: str,
) -> dict[str, str]:
    """Describe one Ed25519 recovery attester for an authorized policy."""

    Ed25519PublicKey, serialization, _ = _crypto()
    try:
        public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load recovery-attester public key: {exc}") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("TrustRecoveryAttestation requires an Ed25519 public key")
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    descriptor = {
        "signer_id": signer_id,
        "recovery_role": recovery_role,
        "organization_id": organization_id,
        "public_key_spki_base64": base64.b64encode(der).decode(),
        "public_key_sha256": hashlib.sha256(der).hexdigest(),
    }
    errors: list[str] = []
    _validate_signer(descriptor, "signer", errors)
    if errors:
        raise ValueError("invalid recovery-attester descriptor: " + "; ".join(errors))
    return descriptor


def build_attestation_policy(
    recovery_policy: Mapping[str, Any],
    signers: Sequence[Mapping[str, Any]],
    *,
    attestation_policy_id: str,
    issued_at: int,
    expires_at: int,
) -> dict[str, Any]:
    """Build a self-digested signer policy for root authorization."""

    if errors := validate_recovery_policy(recovery_policy):
        raise ValueError("invalid TrustRecovery policy: " + "; ".join(errors))
    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "attestation_policy_id": attestation_policy_id,
        "recovery_policy_sha256": recovery_policy["policy_sha256"],
        "plan_id": recovery_policy["plan_id"],
        "trust_domain": recovery_policy["trust_domain"],
        "root_version": recovery_policy["root_version"],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "signers": sorted(
            (deepcopy(dict(item)) for item in signers),
            key=lambda item: item["signer_id"],
        ),
        "required_event_types": sorted(EVENT_ROLES),
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    if errors := validate_attestation_policy(policy, recovery_policy):
        raise ValueError("invalid recovery-attestation policy: " + "; ".join(errors))
    return policy


def validate_attestation_policy(
    policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Validate structure and, when supplied, exact recovery-policy bindings."""

    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("recovery-attestation policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "recovery-attestation policy", errors)
    if (
        policy.get("schema_version") != 1
        or policy.get("policy_type") != POLICY_TYPE
        or policy.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("policy does not match TrustRecoveryAttestation v1")
    _identifier(policy.get("attestation_policy_id"), "attestation_policy_id", errors)
    _identifier(policy.get("plan_id"), "plan_id", errors)
    domain = policy.get("trust_domain")
    if not isinstance(domain, str) or not domain.strip() or len(domain) > 300:
        errors.append("trust_domain must be a non-empty string of at most 300 characters")
    _positive_int(policy.get("root_version"), "root_version", errors)
    issued = _nonnegative_int(policy.get("issued_at"), "issued_at", errors)
    expires = _nonnegative_int(policy.get("expires_at"), "expires_at", errors)
    if issued is not None and expires is not None and issued >= expires:
        errors.append("attestation policy validity window must be non-empty")
    if not _is_digest(policy.get("recovery_policy_sha256")):
        errors.append("recovery_policy_sha256 must be a lowercase SHA-256 digest")
    if policy.get("required_event_types") != sorted(EVENT_ROLES):
        errors.append("required_event_types must contain the exact recovery event set")

    signers = policy.get("signers")
    if not isinstance(signers, list) or not 1 <= len(signers) <= MAX_SIGNERS:
        errors.append(f"signers must contain 1 to {MAX_SIGNERS} records")
        signers = []
    if signers != sorted(
        signers,
        key=lambda item: item.get("signer_id", "") if isinstance(item, Mapping) else "",
    ):
        errors.append("signers must be sorted by signer_id")
    signer_ids: list[Any] = []
    key_ids: list[Any] = []
    covered_roles: set[Any] = set()
    for index, signer in enumerate(signers):
        if not isinstance(signer, Mapping):
            errors.append(f"signers[{index}] must be an object")
            continue
        _exact(signer, _SIGNER_FIELDS, f"signers[{index}]", errors)
        _validate_signer(signer, f"signers[{index}]", errors)
        signer_ids.append(signer.get("signer_id"))
        key_ids.append(signer.get("public_key_sha256"))
        covered_roles.add(signer.get("recovery_role"))
    if len(set(signer_ids)) != len(signer_ids):
        errors.append("signer_id values must be unique")
    if len(set(key_ids)) != len(key_ids):
        errors.append("public keys must be unique per signer")
    if covered_roles != set(ROLE_NAMES):
        errors.append("signers must cover the exact recovery role set")

    if recovery_policy is not None:
        recovery_errors = validate_recovery_policy(recovery_policy)
        errors.extend(f"recovery policy: {item}" for item in recovery_errors)
        expected_bindings = {
            "recovery_policy_sha256": recovery_policy.get("policy_sha256"),
            "plan_id": recovery_policy.get("plan_id"),
            "trust_domain": recovery_policy.get("trust_domain"),
            "root_version": recovery_policy.get("root_version"),
        }
        for field, expected in expected_bindings.items():
            if policy.get(field) != expected:
                errors.append(f"{field} does not match the recovery policy")
        recovery_issued = _plain_int(recovery_policy.get("issued_at"))
        recovery_expires = _plain_int(recovery_policy.get("expires_at"))
        if (
            issued is not None
            and expires is not None
            and recovery_issued is not None
            and recovery_expires is not None
            and not (recovery_issued <= issued < expires <= recovery_expires)
        ):
            errors.append("attestation policy window must fit inside the recovery policy window")
        assignments = recovery_policy.get("role_assignments", {})
        for signer in signers:
            if not isinstance(signer, Mapping):
                continue
            role = signer.get("recovery_role")
            allowed = {
                (item.get("actor_id"), item.get("organization_id"))
                for item in assignments.get(role, [])
                if isinstance(item, Mapping)
            }
            if (signer.get("signer_id"), signer.get("organization_id")) not in allowed:
                errors.append(
                    f"signer {signer.get('signer_id')} is not assigned to recovery role {role}"
                )

    if not _is_digest(policy.get("policy_sha256")):
        errors.append("policy_sha256 must be a lowercase SHA-256 digest")
    elif policy.get("policy_sha256") != _self_digest(policy, "policy_sha256"):
        errors.append("policy_sha256 does not recompute")
    return tuple(dict.fromkeys(errors))


def sign_recovery_event(
    attestation_policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    drill: Mapping[str, Any],
    private_key_path: str | Path,
    *,
    event_index: int,
    issued_at: int,
    nonce: str,
    previous_attestation_sha256: str,
) -> dict[str, Any]:
    """Sign one exact recovery event as a canonical in-toto/DSSE envelope."""

    if errors := validate_attestation_policy(attestation_policy, recovery_policy):
        raise ValueError("invalid recovery-attestation policy: " + "; ".join(errors))
    if errors := validate_recovery_drill(drill):
        raise ValueError("invalid TrustRecovery drill: " + "; ".join(errors))
    _validate_policy_drill_bindings(attestation_policy, recovery_policy, drill)
    if isinstance(event_index, bool) or not isinstance(event_index, int):
        raise ValueError("event_index must be an integer")
    events = drill["events"]
    if not 0 <= event_index < len(events):
        raise ValueError("event_index is outside the recovery drill")
    event = events[event_index]
    role = EVENT_ROLES[event["event_type"]]
    candidates = [
        signer
        for signer in attestation_policy["signers"]
        if signer["signer_id"] == event["actor_id"]
        and signer["organization_id"] == event["organization_id"]
        and signer["recovery_role"] == role
    ]
    if len(candidates) != 1:
        raise ValueError("event actor does not resolve to exactly one policy-authorized signer")
    signer = candidates[0]
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or not event["occurred_at"] <= issued_at < attestation_policy["expires_at"]
        or issued_at < attestation_policy["issued_at"]
    ):
        raise ValueError("issued_at must follow the event within the attestation policy window")
    _identifier_value(nonce, "nonce")
    if not _is_digest(previous_attestation_sha256):
        raise ValueError("previous_attestation_sha256 must be a lowercase SHA-256 digest")

    Ed25519PublicKey, serialization, _ = _crypto()
    try:
        private = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=None
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load recovery-attester private key: {exc}") from exc
    public = private.public_key()
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("TrustRecoveryAttestation requires an Ed25519 private key")
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if hashlib.sha256(der).hexdigest() != signer["public_key_sha256"]:
        raise ValueError("private key does not match the policy-authorized event actor")

    statement = _statement(
        attestation_policy,
        recovery_policy,
        drill,
        event,
        signer,
        issued_at=issued_at,
        nonce=nonce,
        previous_attestation_sha256=previous_attestation_sha256,
    )
    payload = _canonical_bytes(statement)
    signature = private.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": signer["public_key_sha256"],
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }


def verify_recovery_event_attestation(
    envelope: Mapping[str, Any],
    attestation_policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    drill: Mapping[str, Any],
    *,
    event_index: int,
    evaluation_time: int,
    expected_previous_sha256: str,
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    """Verify one policy-authorized recovery-event DSSE envelope."""

    events = drill.get("events", []) if isinstance(drill, Mapping) else []
    if (
        isinstance(event_index, bool)
        or not isinstance(event_index, int)
        or not isinstance(events, list)
        or not 0 <= event_index < len(events)
    ):
        return None, ("event_index is outside the recovery drill",)
    statement, categorized = _inspect_envelope(
        envelope,
        attestation_policy,
        recovery_policy,
        drill,
        events[event_index],
        evaluation_time=evaluation_time,
        expected_previous_sha256=expected_previous_sha256,
    )
    return statement, tuple(
        dict.fromkeys(message for messages in categorized.values() for message in messages)
    )


def evaluate_recovery_attestations(
    attestation_policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    drill: Mapping[str, Any],
    trust_root: Mapping[str, Any],
    envelopes: Sequence[Mapping[str, Any]],
    *,
    evaluation_time: int,
    expected_root_sha256: str | None = None,
) -> dict[str, Any]:
    """Evaluate a complete authenticated recovery-handoff chain offline."""

    if (
        isinstance(evaluation_time, bool)
        or not isinstance(evaluation_time, int)
        or evaluation_time < 0
    ):
        raise ValueError("evaluation_time must be a non-negative integer")
    if not isinstance(envelopes, Sequence) or isinstance(envelopes, (str, bytes)):
        raise ValueError("envelopes must be a sequence")
    if len(envelopes) > MAX_ENVELOPES:
        raise ValueError(f"envelopes exceeds {MAX_ENVELOPES} records")
    attestation_input = deepcopy(dict(attestation_policy))
    recovery_input = deepcopy(dict(recovery_policy))
    drill_input = deepcopy(dict(drill))
    root_input = deepcopy(dict(trust_root))
    envelope_inputs = [deepcopy(dict(item)) for item in envelopes]
    source_errors = {
        "attestation_policy": list(validate_attestation_policy(attestation_input, recovery_input)),
        "recovery_policy": list(validate_recovery_policy(recovery_input)),
        "drill": list(validate_recovery_drill(drill_input)),
    }
    recovery_report = evaluate_recovery_drill(
        recovery_input,
        drill_input,
        root_input,
        evaluation_time=evaluation_time,
        expected_root_sha256=expected_root_sha256,
    )
    root_report = evaluate_trust_root(
        root_input,
        evaluation_time=evaluation_time,
        expected_root_sha256=expected_root_sha256,
        expected_trust_domain=recovery_input.get("trust_domain"),
        minimum_version=_plain_int(recovery_input.get("root_version")),
        policies=[recovery_input, attestation_input],
    )
    events = drill_input.get("events", [])
    if not isinstance(events, list):
        events = []

    results: list[dict[str, Any]] = []
    statements: list[dict[str, Any] | None] = []
    all_errors: dict[str, list[str]] = {rule_id: [] for rule_id, _ in _CHECKS}
    previous_digest = GENESIS_ATTESTATION_SHA256
    for index, envelope in enumerate(envelope_inputs[: len(events)]):
        statement, categorized = _inspect_envelope(
            envelope,
            attestation_input,
            recovery_input,
            drill_input,
            events[index],
            evaluation_time=evaluation_time,
            expected_previous_sha256=previous_digest,
        )
        statements.append(statement)
        for rule_id, messages in categorized.items():
            all_errors[rule_id].extend(messages)
        predicate = statement.get("predicate", {}) if isinstance(statement, Mapping) else {}
        actor = predicate.get("actor", {}) if isinstance(predicate, Mapping) else {}
        flat_errors = list(
            dict.fromkeys(message for messages in categorized.values() for message in messages)
        )
        digest = _safe_digest(envelope)
        results.append(
            {
                "attestation_index": index,
                "attestation_sha256": digest,
                "sequence": predicate.get("sequence") if isinstance(predicate, Mapping) else None,
                "event_type": predicate.get("event_type")
                if isinstance(predicate, Mapping)
                else None,
                "signer_id": actor.get("signer_id") if isinstance(actor, Mapping) else None,
                "organization_id": actor.get("organization_id")
                if isinstance(actor, Mapping)
                else None,
                "status": "valid" if not flat_errors else "invalid",
                "errors": flat_errors,
            }
        )
        previous_digest = digest

    observed_sequences = [
        statement.get("predicate", {}).get("sequence")
        if isinstance(statement, Mapping) and isinstance(statement.get("predicate"), Mapping)
        else None
        for statement in statements
    ]
    coverage_ok = len(envelope_inputs) == len(events) == len(
        EVENT_ROLES
    ) and observed_sequences == list(range(len(EVENT_ROLES)))
    if not coverage_ok:
        all_errors["TRA001"].append(
            f"observed {len(envelope_inputs)} envelopes and sequences {observed_sequences}; "
            f"expected {len(EVENT_ROLES)} ordered envelopes"
        )
    nonces = [
        statement.get("predicate", {}).get("nonce")
        for statement in statements
        if isinstance(statement, Mapping) and isinstance(statement.get("predicate"), Mapping)
    ]
    nonce_ok = (
        coverage_ok
        and all(isinstance(item, str) and bool(_ID.fullmatch(item)) for item in nonces)
        and len(set(nonces)) == len(nonces)
    )
    if not nonce_ok:
        all_errors["TRA008"].append("attestation nonces are missing, invalid, or reused")
    root_status = root_report["summary"]["status"]
    root_authorized = root_status == "trusted_bootstrap"
    if not root_authorized:
        all_errors["TRA010"].append(
            f"anchored root evaluation returned {root_status} for the exact policies"
        )

    findings = []
    for rule_id, title in _CHECKS:
        errors = list(dict.fromkeys(all_errors[rule_id]))
        passed = coverage_ok and not errors if rule_id not in {"TRA001", "TRA010"} else not errors
        failure_detail = "; ".join(errors) or "complete ordered handoff coverage is required"
        findings.append(
            {
                "rule_id": rule_id,
                "title": title,
                "status": "passed" if passed else "failed",
                "detail": "verified for every recovery handoff" if passed else failure_detail,
                "attestation_indexes": list(range(len(envelope_inputs))),
            }
        )
    failed = sum(item["status"] == "failed" for item in findings)
    recovery_status = recovery_report["summary"]["status"]
    if any(source_errors.values()):
        status = "invalid_recovery_attestation_evidence"
    elif recovery_status != RECOVERY_READY_STATUS:
        status = "recovery_readiness_not_evidenced"
    elif root_status == "policy_not_authorized":
        status = "recovery_attestation_policy_not_authorized"
    elif root_status != "trusted_bootstrap":
        status = "untrusted_root"
    elif failed:
        status = "recovery_handoffs_not_authenticated"
    else:
        status = TRUSTED_STATUS

    valid_results = [item for item in results if item["status"] == "valid"]
    organizations = {
        item["organization_id"]
        for item in valid_results
        if isinstance(item["organization_id"], str)
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "evaluation_time": evaluation_time,
        "anchor": {"expected_root_sha256": expected_root_sha256},
        "attestation_policy_input": attestation_input,
        "recovery_policy_input": recovery_input,
        "drill_input": drill_input,
        "trust_root_input": root_input,
        "attestation_envelopes": envelope_inputs,
        "recovery_readiness_report": recovery_report,
        "root_trust_report": root_report,
        "source_errors": source_errors,
        "attestation_results": results,
        "findings": findings,
        "summary": {
            "status": status,
            "checks_total": len(findings),
            "checks_passed": len(findings) - failed,
            "checks_failed": failed,
            "events_expected": len(EVENT_ROLES),
            "attestations_observed": len(envelope_inputs),
            "valid_attestations": len(valid_results),
            "distinct_signer_organizations": len(organizations),
            "terminal_attestation_sha256": previous_digest
            if len(envelope_inputs) == len(events)
            else None,
            "content_fields_processed": 0,
            "replacement_roots_activated": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_recovery_attestation_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Recompute a saved recovery-attestation report from embedded inputs."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported TrustRecoveryAttestation report")
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
        expected = evaluate_recovery_attestations(
            report.get("attestation_policy_input", {}),
            report.get("recovery_policy_input", {}),
            report.get("drill_input", {}),
            report.get("trust_root_input", {}),
            report.get("attestation_envelopes", []),
            evaluation_time=report.get("evaluation_time"),
            expected_root_sha256=anchor.get("expected_root_sha256"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"TrustRecoveryAttestation report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("TrustRecoveryAttestation report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _inspect_envelope(
    envelope: Mapping[str, Any],
    attestation_policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    drill: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    evaluation_time: int,
    expected_previous_sha256: str,
) -> tuple[dict[str, Any] | None, dict[str, list[str]]]:
    errors: dict[str, list[str]] = {rule_id: [] for rule_id, _ in _CHECKS}
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        errors["TRA002"].append("DSSE envelope fields are incomplete or unsupported")
        return None, errors
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        errors["TRA002"].append("DSSE payloadType is unsupported")
    signatures = envelope.get("signatures")
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], Mapping)
        or set(signatures[0]) != {"keyid", "sig"}
    ):
        errors["TRA002"].append("DSSE envelope must contain exactly one keyid/sig signature")
        signatures = []
    try:
        payload = base64.b64decode(str(envelope.get("payload", "")), validate=True)
        statement = json.loads(payload)
    except (TypeError, ValueError, json.JSONDecodeError):
        errors["TRA002"].append("DSSE payload is not valid base64 JSON")
        return None, errors
    if not isinstance(statement, Mapping) or set(statement) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        errors["TRA002"].append("in-toto statement fields are invalid")
        return deepcopy(dict(statement)) if isinstance(statement, Mapping) else None, errors
    statement = deepcopy(dict(statement))
    if _canonical_bytes(statement) != payload:
        errors["TRA002"].append("DSSE statement payload is not canonical JSON")
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        errors["TRA002"].append("in-toto statement or predicate type is unsupported")
    expected_subject = [
        {
            "name": f"recovery-event/{event.get('sequence')}-{event.get('event_type')}.json",
            "digest": {"sha256": _safe_digest(event)},
        }
    ]
    if statement.get("subject") != expected_subject:
        errors["TRA003"].append("in-toto subject does not match the exact recovery event")
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        errors["TRA002"].append("recovery-event predicate must be an object")
        return statement, errors
    _exact(predicate, _PREDICATE_FIELDS, "recovery-event predicate", errors["TRA002"])
    if predicate.get("protocol_version") != PROTOCOL_VERSION:
        errors["TRA002"].append("predicate protocol_version is unsupported")
    expected_bindings = {
        "attestation_policy_sha256": attestation_policy.get("policy_sha256"),
        "recovery_policy_sha256": recovery_policy.get("policy_sha256"),
        "plan_id": recovery_policy.get("plan_id"),
        "drill_id": drill.get("drill_id"),
        "trust_domain": drill.get("trust_domain"),
        "root_sha256": drill.get("root_sha256"),
        "root_version": drill.get("root_version"),
        "simulation_only": True,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    for field, expected in expected_bindings.items():
        if predicate.get(field) != expected:
            errors["TRA004"].append(f"predicate {field} does not match")
    event_bindings = {
        "sequence": event.get("sequence"),
        "event_type": event.get("event_type"),
        "evidence_sha256": event.get("evidence_sha256"),
        "occurred_at": event.get("occurred_at"),
    }
    for field, expected in event_bindings.items():
        if predicate.get(field) != expected:
            errors["TRA003"].append(f"predicate {field} does not match the recovery event")

    actor = predicate.get("actor")
    if not isinstance(actor, Mapping) or set(actor) != _ACTOR_FIELDS:
        errors["TRA005"].append("signed actor fields are incomplete or unsupported")
        actor = {}
    role = EVENT_ROLES.get(event.get("event_type"))
    expected_actor = {
        "signer_id": event.get("actor_id"),
        "recovery_role": role,
        "organization_id": event.get("organization_id"),
    }
    for field, expected in expected_actor.items():
        if actor.get(field) != expected:
            errors["TRA005"].append(f"signed actor {field} does not match the recovery event")
    authorized = {
        item.get("signer_id"): item
        for item in attestation_policy.get("signers", [])
        if isinstance(item, Mapping)
    }
    signer = authorized.get(actor.get("signer_id"))
    if signer is None:
        errors["TRA005"].append("event signer is not attestation-policy authorized")
    else:
        expected_identity = {
            "signer_id": signer.get("signer_id"),
            "recovery_role": signer.get("recovery_role"),
            "organization_id": signer.get("organization_id"),
            "key_sha256": signer.get("public_key_sha256"),
        }
        if dict(actor) != expected_identity:
            errors["TRA005"].append("signed actor identity does not match the policy key record")

    issued_at = predicate.get("issued_at")
    occurred_at = predicate.get("occurred_at")
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (issued_at, occurred_at, evaluation_time)
    ):
        errors["TRA007"].append("attestation timestamps must be integers")
    elif not (
        occurred_at <= issued_at <= evaluation_time
        and attestation_policy.get("issued_at", 0)
        <= issued_at
        < attestation_policy.get("expires_at", 0)
    ):
        errors["TRA007"].append("attestation time is out of event, policy, or evaluation order")
    nonce = predicate.get("nonce")
    if not isinstance(nonce, str) or not _ID.fullmatch(nonce) or len(nonce) > 100:
        errors["TRA008"].append("attestation nonce is not a lowercase kebab-case identifier")
    if predicate.get("previous_attestation_sha256") != expected_previous_sha256:
        errors["TRA009"].append("previous_attestation_sha256 breaks the handoff chain")

    if signatures and signer is not None:
        signature_record = signatures[0]
        if signature_record.get("keyid") != signer.get("public_key_sha256"):
            errors["TRA006"].append("DSSE signature keyid does not match the authorized signer")
        try:
            signature = base64.b64decode(str(signature_record.get("sig", "")), validate=True)
            public_der = base64.b64decode(
                str(signer.get("public_key_spki_base64", "")), validate=True
            )
            Ed25519PublicKey, serialization, InvalidSignature = _crypto()
            public = serialization.load_der_public_key(public_der)
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("authorized key is not Ed25519")
            public.verify(signature, _pae(PAYLOAD_TYPE, payload))
        except InvalidSignature:
            errors["TRA006"].append("DSSE Ed25519 signature is invalid")
        except (TypeError, ValueError):
            errors["TRA006"].append("DSSE signature or authorized public key is invalid")
    elif not signatures:
        errors["TRA006"].append("DSSE signature is missing")
    return statement, errors


def _statement(
    attestation_policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    drill: Mapping[str, Any],
    event: Mapping[str, Any],
    signer: Mapping[str, Any],
    *,
    issued_at: int,
    nonce: str,
    previous_attestation_sha256: str,
) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"recovery-event/{event['sequence']}-{event['event_type']}.json",
                "digest": {"sha256": canonical_sha256(event)},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "protocol_version": PROTOCOL_VERSION,
            "attestation_policy_sha256": attestation_policy["policy_sha256"],
            "recovery_policy_sha256": recovery_policy["policy_sha256"],
            "plan_id": recovery_policy["plan_id"],
            "drill_id": drill["drill_id"],
            "trust_domain": drill["trust_domain"],
            "root_sha256": drill["root_sha256"],
            "root_version": drill["root_version"],
            "sequence": event["sequence"],
            "event_type": event["event_type"],
            "actor": {
                "signer_id": signer["signer_id"],
                "recovery_role": signer["recovery_role"],
                "organization_id": signer["organization_id"],
                "key_sha256": signer["public_key_sha256"],
            },
            "evidence_sha256": event["evidence_sha256"],
            "occurred_at": event["occurred_at"],
            "issued_at": issued_at,
            "nonce": nonce,
            "previous_attestation_sha256": previous_attestation_sha256,
            "simulation_only": True,
            "claim_boundary": CLAIM_BOUNDARY,
        },
    }


def _validate_policy_drill_bindings(
    attestation_policy: Mapping[str, Any],
    recovery_policy: Mapping[str, Any],
    drill: Mapping[str, Any],
) -> None:
    bindings = (
        attestation_policy.get("recovery_policy_sha256")
        == recovery_policy.get("policy_sha256")
        == drill.get("policy_sha256")
        and attestation_policy.get("plan_id")
        == recovery_policy.get("plan_id")
        == drill.get("plan_id")
        and attestation_policy.get("trust_domain")
        == recovery_policy.get("trust_domain")
        == drill.get("trust_domain")
        and attestation_policy.get("root_version")
        == recovery_policy.get("root_version")
        == drill.get("root_version")
    )
    if not bindings:
        raise ValueError("attestation policy, recovery policy, and drill bindings differ")


def _validate_signer(value: Mapping[str, Any], label: str, errors: list[str]) -> None:
    _identifier(value.get("signer_id"), f"{label}.signer_id", errors)
    _identifier(value.get("organization_id"), f"{label}.organization_id", errors)
    if value.get("recovery_role") not in ROLE_NAMES:
        errors.append(f"{label}.recovery_role is unsupported")
    encoded = value.get("public_key_spki_base64")
    claimed = value.get("public_key_sha256")
    if not isinstance(encoded, str) or not _is_digest(claimed):
        errors.append(f"{label} public key fields are invalid")
        return
    try:
        public_der = base64.b64decode(encoded, validate=True)
        Ed25519PublicKey, serialization, _ = _crypto()
        public = serialization.load_der_public_key(public_der)
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("not Ed25519")
    except (TypeError, ValueError):
        errors.append(f"{label} public key is not valid Ed25519 SPKI")
        return
    if hashlib.sha256(public_der).hexdigest() != claimed:
        errors.append(f"{label}.public_key_sha256 does not match the public key")


def _crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - package dependency
        raise RuntimeError("cryptography is required for TrustRecoveryAttestation") from exc
    return Ed25519PublicKey, serialization, InvalidSignature


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


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _safe_digest(payload: Any) -> str:
    try:
        return canonical_sha256(payload)
    except (TypeError, ValueError):
        return "unavailable"


def _self_digest(payload: Mapping[str, Any], field: str) -> str:
    value = dict(payload)
    value.pop(field, None)
    try:
        return canonical_sha256(value)
    except (TypeError, ValueError):
        return "unavailable"


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    if missing := sorted(expected - set(value)):
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra := sorted(set(value) - expected):
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _identifier_value(value: Any, label: str) -> None:
    errors: list[str] = []
    _identifier(value, label, errors)
    if errors:
        raise ValueError(errors[0])


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


__all__ = [
    "GENESIS_ATTESTATION_SHA256",
    "PAYLOAD_TYPE",
    "POLICY_TYPE",
    "PREDICATE_TYPE",
    "PROTOCOL_VERSION",
    "REPORT_TYPE",
    "STATEMENT_TYPE",
    "TRUSTED_STATUS",
    "attester_descriptor",
    "build_attestation_policy",
    "evaluate_recovery_attestations",
    "sign_recovery_event",
    "validate_attestation_policy",
    "verify_recovery_attestation_report",
    "verify_recovery_event_attestation",
]
