"""Witnessed append-only reviewer trust for AssuranceQuorum evidence."""

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
from dspy_security_bench.quorum.proof import verify_quorum_report

POLICY_TYPE = "dspy-security-bench-assurance-ledger-policy"
REPORT_TYPE = "AssuranceLedger / Witnessed reviewer trust evidence"
PROTOCOL_VERSION = "assuranceledger-v1"
ANALYZER = "deterministic-witnessed-reviewer-trust-analyzer-v1"
EVENT_TYPES = ("reviewer-key-registration", "review-envelope", "reviewer-key-revocation")
MAX_ENTRIES = 10_000
MAX_WITNESSES = 25
CLAIM_BOUNDARY = (
    "AssuranceLedger verifies an owner-selected Ed25519 log operator, witness signatures, "
    "the complete RFC 6962-style Merkle tree, append-only prefix continuity, and declared "
    "reviewer-key lifecycle events for one natively recomputed AssuranceQuorum report. It "
    "does not prove legal identity, organizational independence, event truth, uncompromised "
    "private-key custody, global log consistency, model safety, compliance, authorization to "
    "operate, procurement approval, deployment authority, or risk acceptance."
)
LIMITATIONS = (
    "This protocol uses RFC 6962 domain-separated Merkle hashing but is not a CT, Rekor, or C2SP wire-protocol implementation.",
    "Witness signatures evidence the exact checkpoint they observed; they do not prove a witness is independent or continuously available.",
    "A self-contained bundle recomputes append-only prefix continuity, but detecting a split view still requires exchanging checkpoints across trust domains.",
    "Registration and revocation events are declarations by the policy-authorized log operator, not external proof of identity or compromise time.",
    "A compromise_since value can invalidate historical reviews only when the accountable owner accepts that logged declaration.",
)

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_FIELDS = {
    "schema_version",
    "policy_type",
    "registry_id",
    "log_origin",
    "log_operator",
    "witnesses",
    "minimum_witnesses",
    "minimum_distinct_witness_organizations",
    "maximum_checkpoint_age_seconds",
    "claim_boundary",
    "policy_sha256",
}
_KEY_FIELDS = {
    "entity_id",
    "organization_id",
    "public_key_spki_base64",
    "public_key_sha256",
}
_EVENT_FIELDS = {"sequence", "event_type", "integrated_at", "body", "event_sha256"}
_REGISTRATION_FIELDS = {
    "signer_id",
    "role",
    "organization_id",
    "public_key_sha256",
    "valid_from",
    "valid_until",
}
_REVIEW_FIELDS = {
    "envelope_sha256",
    "policy_sha256",
    "signer_id",
    "public_key_sha256",
    "review_issued_at",
    "review_expires_at",
}
_REVOCATION_FIELDS = {
    "signer_id",
    "public_key_sha256",
    "effective_at",
    "compromise_since",
    "reason",
}
_CHECKPOINT_FIELDS = {
    "protocol_version",
    "log_origin",
    "policy_sha256",
    "tree_size",
    "root_sha256",
    "issued_at",
    "previous_tree_size",
    "previous_root_sha256",
}
_SIGNED_CHECKPOINT_FIELDS = {"checkpoint", "operator_signature", "witness_signatures"}
_SIGNATURE_FIELDS = {"keyid", "signer_id", "signature_base64"}


def key_descriptor(
    public_key_path: str | Path, *, entity_id: str, organization_id: str
) -> dict[str, Any]:
    _, Ed25519PublicKey, serialization, _ = _crypto()
    try:
        public = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load Ed25519 public key: {exc}") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("AssuranceLedger requires an Ed25519 public key")
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "entity_id": entity_id,
        "organization_id": organization_id,
        "public_key_spki_base64": base64.b64encode(der).decode(),
        "public_key_sha256": hashlib.sha256(der).hexdigest(),
    }


def build_policy(
    log_operator: Mapping[str, Any],
    witnesses: Sequence[Mapping[str, Any]],
    *,
    registry_id: str,
    log_origin: str,
    minimum_witnesses: int,
    minimum_distinct_witness_organizations: int,
    maximum_checkpoint_age_seconds: int,
) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_type": POLICY_TYPE,
        "registry_id": registry_id,
        "log_origin": log_origin,
        "log_operator": deepcopy(dict(log_operator)),
        "witnesses": sorted(
            (deepcopy(dict(item)) for item in witnesses), key=lambda item: item["entity_id"]
        ),
        "minimum_witnesses": minimum_witnesses,
        "minimum_distinct_witness_organizations": minimum_distinct_witness_organizations,
        "maximum_checkpoint_age_seconds": maximum_checkpoint_age_seconds,
        "claim_boundary": CLAIM_BOUNDARY,
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    if errors := validate_policy(policy):
        raise ValueError("invalid AssuranceLedger policy: " + "; ".join(errors))
    return policy


def validate_policy(policy: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(policy, Mapping):
        return ("policy must be an object",)
    _exact(policy, _POLICY_FIELDS, "policy", errors)
    if policy.get("schema_version") != 1 or policy.get("policy_type") != POLICY_TYPE:
        errors.append("policy metadata does not match AssuranceLedger v1")
    _identifier(policy.get("registry_id"), "registry_id", errors)
    origin = policy.get("log_origin")
    if not isinstance(origin, str) or not origin.strip() or len(origin) > 300:
        errors.append("log_origin must be a non-empty string of at most 300 characters")
    operator = _validate_key(policy.get("log_operator"), "log_operator", errors)
    witnesses = policy.get("witnesses")
    if not isinstance(witnesses, list) or not 1 <= len(witnesses) <= MAX_WITNESSES:
        errors.append(f"witnesses must contain 1 to {MAX_WITNESSES} entries")
        witnesses = []
    witness_ids: set[str] = set()
    key_ids = {operator.get("public_key_sha256")} if operator else set()
    organizations: set[str] = set()
    for index, witness in enumerate(witnesses):
        item = _validate_key(witness, f"witnesses[{index}]", errors)
        if item is None:
            continue
        entity_id = item.get("entity_id")
        key_id = item.get("public_key_sha256")
        if entity_id in witness_ids:
            errors.append(f"duplicate witness entity_id {entity_id!r}")
        witness_ids.add(str(entity_id))
        if key_id in key_ids:
            errors.append(f"duplicate operator or witness key {key_id!r}")
        key_ids.add(str(key_id))
        organizations.add(str(item.get("organization_id")))
    minimum = _integer(policy.get("minimum_witnesses"), "minimum_witnesses", errors)
    distinct = _integer(
        policy.get("minimum_distinct_witness_organizations"),
        "minimum_distinct_witness_organizations",
        errors,
    )
    maximum_age = _integer(
        policy.get("maximum_checkpoint_age_seconds"),
        "maximum_checkpoint_age_seconds",
        errors,
    )
    if minimum is not None and not 1 <= minimum <= len(witnesses):
        errors.append("minimum_witnesses is outside the witness bound")
    if distinct is not None and not 1 <= distinct <= len(organizations):
        errors.append("minimum_distinct_witness_organizations cannot be met")
    if maximum_age is not None and maximum_age < 1:
        errors.append("maximum_checkpoint_age_seconds must be positive")
    if policy.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match AssuranceLedger v1")
    claimed = policy.get("policy_sha256")
    unsigned = dict(policy)
    unsigned.pop("policy_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("policy_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("policy is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def make_registration_event(
    reviewer: Mapping[str, Any],
    *,
    sequence: int,
    integrated_at: int,
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    body = {
        "signer_id": reviewer["signer_id"],
        "role": reviewer["role"],
        "organization_id": reviewer["organization_id"],
        "public_key_sha256": reviewer["public_key_sha256"],
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    return _make_event("reviewer-key-registration", sequence, integrated_at, body)


def make_review_event(
    envelope: Mapping[str, Any], *, sequence: int, integrated_at: int
) -> dict[str, Any]:
    predicate = _review_predicate(envelope)
    reviewer = predicate["reviewer"]
    body = {
        "envelope_sha256": canonical_sha256(envelope),
        "policy_sha256": predicate["policy_sha256"],
        "signer_id": reviewer["signer_id"],
        "public_key_sha256": reviewer["key_sha256"],
        "review_issued_at": predicate["issued_at"],
        "review_expires_at": predicate["expires_at"],
    }
    return _make_event("review-envelope", sequence, integrated_at, body)


def make_revocation_event(
    *,
    signer_id: str,
    public_key_sha256: str,
    sequence: int,
    integrated_at: int,
    effective_at: int,
    compromise_since: int | None,
    reason: str,
) -> dict[str, Any]:
    body = {
        "signer_id": signer_id,
        "public_key_sha256": public_key_sha256,
        "effective_at": effective_at,
        "compromise_since": compromise_since,
        "reason": reason,
    }
    return _make_event("reviewer-key-revocation", sequence, integrated_at, body)


def _make_event(
    event_type: str, sequence: int, integrated_at: int, body: Mapping[str, Any]
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "sequence": sequence,
        "event_type": event_type,
        "integrated_at": integrated_at,
        "body": deepcopy(dict(body)),
    }
    event["event_sha256"] = canonical_sha256(event)
    if errors := validate_events([event], allow_nonzero_start=True):
        raise ValueError("invalid AssuranceLedger event: " + "; ".join(errors))
    return event


def validate_events(
    entries: Sequence[Mapping[str, Any]], *, allow_nonzero_start: bool = False
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        return (f"entries must contain 1 to {MAX_ENTRIES} events",)
    event_ids: set[str] = set()
    last_time = -1
    expected_start = entries[0].get("sequence") if allow_nonzero_start else 0
    for index, entry in enumerate(entries):
        label = f"entries[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(entry, _EVENT_FIELDS, label, errors)
        sequence = _integer(entry.get("sequence"), f"{label}.sequence", errors)
        if sequence is not None and sequence != expected_start + index:
            errors.append(f"{label}.sequence is not contiguous")
        integrated = _integer(entry.get("integrated_at"), f"{label}.integrated_at", errors)
        if integrated is not None:
            if integrated < last_time:
                errors.append(f"{label}.integrated_at is not monotonic")
            last_time = integrated
        event_type = entry.get("event_type")
        if event_type not in EVENT_TYPES:
            errors.append(f"{label}.event_type is unsupported")
        body = entry.get("body")
        if not isinstance(body, Mapping):
            errors.append(f"{label}.body must be an object")
        else:
            _validate_event_body(str(event_type), body, label, integrated, errors)
        claimed = entry.get("event_sha256")
        unsigned = dict(entry)
        unsigned.pop("event_sha256", None)
        try:
            if claimed != canonical_sha256(unsigned):
                errors.append(f"{label}.event_sha256 does not recompute")
        except (TypeError, ValueError):
            errors.append(f"{label} is not canonical JSON data")
        if isinstance(claimed, str):
            if claimed in event_ids:
                errors.append(f"{label}.event_sha256 is duplicated")
            event_ids.add(claimed)
    return tuple(dict.fromkeys(errors))


def create_checkpoint(
    policy: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    private_key_path: str | Path,
    *,
    issued_at: int,
    previous_checkpoint: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if errors := validate_policy(policy):
        raise ValueError("invalid AssuranceLedger policy: " + "; ".join(errors))
    if errors := validate_events(entries):
        raise ValueError("invalid AssuranceLedger entries: " + "; ".join(errors))
    previous_size = 0
    previous_root = _empty_root()
    if previous_checkpoint is not None:
        previous = previous_checkpoint.get("checkpoint", {})
        previous_size = previous.get("tree_size")
        previous_root = previous.get("root_sha256")
        if not isinstance(previous_size, int) or not 0 < previous_size <= len(entries):
            raise ValueError("previous checkpoint tree_size is outside the current tree")
        if previous_root != merkle_root(entries[:previous_size]):
            raise ValueError("current entries do not preserve the previous checkpoint prefix")
    checkpoint = {
        "protocol_version": PROTOCOL_VERSION,
        "log_origin": policy["log_origin"],
        "policy_sha256": policy["policy_sha256"],
        "tree_size": len(entries),
        "root_sha256": merkle_root(entries),
        "issued_at": issued_at,
        "previous_tree_size": previous_size,
        "previous_root_sha256": previous_root,
    }
    signature = _sign_payload(
        checkpoint,
        private_key_path,
        policy["log_operator"],
        signer_id=policy["log_operator"]["entity_id"],
    )
    return {
        "checkpoint": checkpoint,
        "operator_signature": signature,
        "witness_signatures": [],
    }


def cosign_checkpoint(
    policy: Mapping[str, Any],
    signed_checkpoint: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    private_key_path: str | Path,
    *,
    witness_id: str,
    previous_checkpoint: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    witness_map = {item["entity_id"]: item for item in policy["witnesses"]}
    if witness_id not in witness_map:
        raise ValueError("witness_id is not authorized by the policy")
    errors = verify_checkpoint(
        policy,
        signed_checkpoint,
        entries,
        previous_checkpoint=previous_checkpoint,
        require_witness_quorum=False,
        evaluation_time=signed_checkpoint.get("checkpoint", {}).get("issued_at", 0),
    )
    if errors:
        raise ValueError("witness refused checkpoint: " + "; ".join(errors))
    result = deepcopy(dict(signed_checkpoint))
    if any(item.get("signer_id") == witness_id for item in result["witness_signatures"]):
        raise ValueError("witness already signed this checkpoint")
    result["witness_signatures"].append(
        _sign_payload(
            result["checkpoint"],
            private_key_path,
            witness_map[witness_id],
            signer_id=witness_id,
        )
    )
    result["witness_signatures"].sort(key=lambda item: item["signer_id"])
    return result


def verify_checkpoint(
    policy: Mapping[str, Any],
    signed_checkpoint: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    *,
    previous_checkpoint: Mapping[str, Any] | None,
    require_witness_quorum: bool,
    evaluation_time: int,
    allow_unresolved_previous: bool = False,
) -> tuple[str, ...]:
    errors: list[str] = list(validate_policy(policy))
    errors.extend(validate_events(entries))
    if not isinstance(signed_checkpoint, Mapping):
        return tuple(dict.fromkeys([*errors, "signed checkpoint must be an object"]))
    _exact(signed_checkpoint, _SIGNED_CHECKPOINT_FIELDS, "signed checkpoint", errors)
    checkpoint = signed_checkpoint.get("checkpoint")
    if not isinstance(checkpoint, Mapping):
        return tuple(dict.fromkeys([*errors, "checkpoint must be an object"]))
    _exact(checkpoint, _CHECKPOINT_FIELDS, "checkpoint", errors)
    expected = {
        "protocol_version": PROTOCOL_VERSION,
        "log_origin": policy.get("log_origin"),
        "policy_sha256": policy.get("policy_sha256"),
        "tree_size": len(entries),
        "root_sha256": merkle_root(entries) if entries else _empty_root(),
    }
    for field, value in expected.items():
        if checkpoint.get(field) != value:
            errors.append(f"checkpoint.{field} does not match the verified log")
    issued_at = checkpoint.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 0:
        errors.append("checkpoint.issued_at must be a non-negative integer")
    else:
        maximum_age = policy.get("maximum_checkpoint_age_seconds")
        if issued_at > evaluation_time:
            errors.append("checkpoint is from the future")
        if isinstance(maximum_age, int) and evaluation_time - issued_at > maximum_age:
            errors.append("checkpoint is stale at the evaluation time")
        if entries and entries[-1].get("integrated_at", issued_at + 1) > issued_at:
            errors.append("checkpoint predates its latest integrated event")
    if previous_checkpoint is None and not allow_unresolved_previous:
        if checkpoint.get("previous_tree_size") != 0:
            errors.append("first checkpoint previous_tree_size must be zero")
        if checkpoint.get("previous_root_sha256") != _empty_root():
            errors.append("first checkpoint previous root must be the empty-tree root")
    elif previous_checkpoint is not None:
        previous = previous_checkpoint.get("checkpoint", {})
        previous_size = previous.get("tree_size")
        if checkpoint.get("previous_tree_size") != previous_size:
            errors.append("checkpoint does not link the supplied previous tree size")
        if checkpoint.get("previous_root_sha256") != previous.get("root_sha256"):
            errors.append("checkpoint does not link the supplied previous root")
        if not isinstance(previous_size, int) or not 0 < previous_size <= len(entries):
            errors.append("previous checkpoint tree_size is outside the current tree")
        elif previous.get("root_sha256") != merkle_root(entries[:previous_size]):
            errors.append("current log is not an append-only extension of the previous checkpoint")
        if isinstance(previous.get("issued_at"), int) and isinstance(issued_at, int):
            if previous["issued_at"] >= issued_at:
                errors.append("checkpoint time does not advance beyond the previous checkpoint")
        previous_errors = verify_checkpoint(
            policy,
            previous_checkpoint,
            entries[:previous_size] if isinstance(previous_size, int) and previous_size > 0 else [],
            previous_checkpoint=None,
            require_witness_quorum=True,
            evaluation_time=previous.get("issued_at", 0),
            allow_unresolved_previous=True,
        )
        errors.extend(f"previous checkpoint: {item}" for item in previous_errors)
    operator = policy.get("log_operator", {})
    errors.extend(
        _verify_signature(
            checkpoint,
            signed_checkpoint.get("operator_signature"),
            operator,
            expected_signer=operator.get("entity_id"),
            label="operator signature",
        )
    )
    witness_map = {
        item["entity_id"]: item
        for item in policy.get("witnesses", [])
        if isinstance(item, Mapping) and "entity_id" in item
    }
    signatures = signed_checkpoint.get("witness_signatures")
    if not isinstance(signatures, list) or len(signatures) > MAX_WITNESSES:
        errors.append("witness_signatures must be a bounded list")
        signatures = []
    valid_witnesses: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for index, signature in enumerate(signatures):
        signer = signature.get("signer_id") if isinstance(signature, Mapping) else None
        if signer in seen:
            errors.append(f"duplicate witness signature {signer!r}")
            continue
        seen.add(str(signer))
        witness = witness_map.get(signer)
        if witness is None:
            errors.append(f"witness signature {index} is not policy-authorized")
            continue
        signature_errors = _verify_signature(
            checkpoint,
            signature,
            witness,
            expected_signer=str(signer),
            label=f"witness signature {index}",
        )
        errors.extend(signature_errors)
        if not signature_errors:
            valid_witnesses.append(witness)
    if require_witness_quorum:
        if len(valid_witnesses) < policy.get("minimum_witnesses", MAX_WITNESSES + 1):
            errors.append("checkpoint lacks the required witness count")
        organizations = {item["organization_id"] for item in valid_witnesses}
        if len(organizations) < policy.get(
            "minimum_distinct_witness_organizations", MAX_WITNESSES + 1
        ):
            errors.append("checkpoint lacks the required distinct witness organizations")
    return tuple(dict.fromkeys(errors))


def verify_checkpoint_signature_bundle(
    policy: Mapping[str, Any],
    signed_checkpoint: Mapping[str, Any],
    *,
    require_witness_quorum: bool = True,
) -> tuple[str, ...]:
    """Verify a checkpoint's identity and signatures without requiring private log entries.

    This intentionally does not claim that the root commits to any particular event list. It is
    for compact disclosure artifacts where two valid operator signatures over different roots at
    the same size are themselves the evidence under review.
    """
    errors: list[str] = list(validate_policy(policy))
    if not isinstance(signed_checkpoint, Mapping):
        return tuple(dict.fromkeys([*errors, "signed checkpoint must be an object"]))
    _exact(signed_checkpoint, _SIGNED_CHECKPOINT_FIELDS, "signed checkpoint", errors)
    checkpoint = signed_checkpoint.get("checkpoint")
    if not isinstance(checkpoint, Mapping):
        return tuple(dict.fromkeys([*errors, "checkpoint must be an object"]))
    _exact(checkpoint, _CHECKPOINT_FIELDS, "checkpoint", errors)
    if checkpoint.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("checkpoint.protocol_version does not match AssuranceLedger v1")
    if checkpoint.get("log_origin") != policy.get("log_origin"):
        errors.append("checkpoint.log_origin does not match policy")
    if checkpoint.get("policy_sha256") != policy.get("policy_sha256"):
        errors.append("checkpoint.policy_sha256 does not match policy")
    tree_size = _integer(checkpoint.get("tree_size"), "checkpoint.tree_size", errors)
    if tree_size is not None and tree_size < 1:
        errors.append("checkpoint.tree_size must be positive")
    _digest(checkpoint.get("root_sha256"), "checkpoint.root_sha256", errors)
    _integer(checkpoint.get("issued_at"), "checkpoint.issued_at", errors)
    previous_size = _integer(
        checkpoint.get("previous_tree_size"), "checkpoint.previous_tree_size", errors
    )
    if previous_size is not None and tree_size is not None:
        if previous_size < 0 or previous_size > tree_size:
            errors.append("checkpoint.previous_tree_size is outside the tree")
    _digest(
        checkpoint.get("previous_root_sha256"),
        "checkpoint.previous_root_sha256",
        errors,
    )
    operator = policy.get("log_operator", {})
    errors.extend(
        _verify_signature(
            checkpoint,
            signed_checkpoint.get("operator_signature"),
            operator,
            expected_signer=operator.get("entity_id"),
            label="operator signature",
        )
    )
    witness_map = {
        item["entity_id"]: item
        for item in policy.get("witnesses", [])
        if isinstance(item, Mapping) and "entity_id" in item
    }
    signatures = signed_checkpoint.get("witness_signatures")
    if not isinstance(signatures, list) or len(signatures) > MAX_WITNESSES:
        errors.append("witness_signatures must be a bounded list")
        signatures = []
    valid_witnesses: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for index, signature in enumerate(signatures):
        signer = signature.get("signer_id") if isinstance(signature, Mapping) else None
        if signer in seen:
            errors.append(f"duplicate witness signature {signer!r}")
            continue
        seen.add(str(signer))
        witness = witness_map.get(signer)
        if witness is None:
            errors.append(f"witness signature {index} is not policy-authorized")
            continue
        signature_errors = _verify_signature(
            checkpoint,
            signature,
            witness,
            expected_signer=str(signer),
            label=f"witness signature {index}",
        )
        errors.extend(signature_errors)
        if not signature_errors:
            valid_witnesses.append(witness)
    if require_witness_quorum:
        if len(valid_witnesses) < policy.get("minimum_witnesses", MAX_WITNESSES + 1):
            errors.append("checkpoint lacks the required witness count")
        organizations = {item["organization_id"] for item in valid_witnesses}
        if len(organizations) < policy.get(
            "minimum_distinct_witness_organizations", MAX_WITNESSES + 1
        ):
            errors.append("checkpoint lacks the required distinct witness organizations")
    return tuple(dict.fromkeys(errors))


def analyze_ledger(
    policy: Mapping[str, Any],
    quorum_report: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    checkpoint: Mapping[str, Any],
    *,
    previous_checkpoint: Mapping[str, Any] | None,
    evidence_root: str | Path,
    evaluation_time: int,
) -> dict[str, Any]:
    if (
        isinstance(evaluation_time, bool)
        or not isinstance(evaluation_time, int)
        or evaluation_time < 0
    ):
        raise ValueError("evaluation_time must be a non-negative integer")
    source_errors = list(verify_quorum_report(quorum_report, evidence_root=evidence_root))
    checkpoint_errors = list(
        verify_checkpoint(
            policy,
            checkpoint,
            entries,
            previous_checkpoint=previous_checkpoint,
            require_witness_quorum=True,
            evaluation_time=evaluation_time,
        )
    )
    registration_events = [
        item for item in entries if item.get("event_type") == "reviewer-key-registration"
    ]
    review_events = [item for item in entries if item.get("event_type") == "review-envelope"]
    revocation_events = [
        item for item in entries if item.get("event_type") == "reviewer-key-revocation"
    ]
    review_results = []
    invalidated_count = 0
    retired_count = 0
    incomplete_count = 0
    source_reviews = quorum_report.get("review_envelopes", [])
    source_validity = {
        item.get("envelope_sha256"): item.get("status")
        for item in quorum_report.get("review_results", [])
        if isinstance(item, Mapping)
    }
    for envelope in source_reviews:
        envelope_sha256 = _safe_digest(envelope)
        predicate = _safe_review_predicate(envelope)
        reviewer = predicate.get("reviewer", {})
        signer_id = reviewer.get("signer_id")
        key_id = reviewer.get("key_sha256")
        issued_at = predicate.get("issued_at")
        matching_logs = [
            item
            for item in review_events
            if item.get("body", {}).get("envelope_sha256") == envelope_sha256
        ]
        matching_registrations = [
            item
            for item in registration_events
            if item.get("body", {}).get("signer_id") == signer_id
            and item.get("body", {}).get("public_key_sha256") == key_id
            and isinstance(issued_at, int)
            and item.get("body", {}).get("valid_from", issued_at + 1)
            <= issued_at
            < item.get("body", {}).get("valid_until", issued_at)
        ]
        errors: list[str] = []
        if source_validity.get(envelope_sha256) != "valid":
            errors.append("source AssuranceQuorum review is not valid")
        if len(matching_logs) != 1:
            errors.append("review envelope is not logged exactly once")
        elif matching_logs[0]["body"] != _expected_review_body(envelope, predicate):
            errors.append("logged review metadata does not match the signed envelope")
        if len(matching_registrations) != 1:
            errors.append("reviewer key has no unique valid registration at review issuance")
        elif (
            matching_logs and matching_registrations[0]["sequence"] >= matching_logs[0]["sequence"]
        ):
            errors.append("reviewer key registration was not logged before the review")
        relevant_revocations = [
            item
            for item in revocation_events
            if item.get("body", {}).get("signer_id") == signer_id
            and item.get("body", {}).get("public_key_sha256") == key_id
        ]
        invalidators = [
            item
            for item in relevant_revocations
            if isinstance(issued_at, int)
            and item.get("body", {}).get("compromise_since") is not None
            and item["body"]["compromise_since"] <= issued_at
        ]
        retired = [
            item
            for item in relevant_revocations
            if item.get("body", {}).get("effective_at", evaluation_time + 1) <= evaluation_time
        ]
        if errors:
            status = "trust_evidence_incomplete"
            incomplete_count += 1
        elif invalidators:
            status = "reviewer_trust_invalidated"
            invalidated_count += 1
        elif retired:
            status = "reviewer_trust_historical"
            retired_count += 1
        else:
            status = "reviewer_trust_current"
        proof = []
        if len(matching_logs) == 1:
            proof = inclusion_proof(entries, matching_logs[0]["sequence"])
        review_results.append(
            {
                "envelope_sha256": envelope_sha256,
                "signer_id": signer_id,
                "public_key_sha256": key_id,
                "status": status,
                "registration_event_sha256": matching_registrations[0]["event_sha256"]
                if len(matching_registrations) == 1
                else None,
                "review_event_sha256": matching_logs[0]["event_sha256"]
                if len(matching_logs) == 1
                else None,
                "revocation_event_sha256s": [item["event_sha256"] for item in relevant_revocations],
                "inclusion_proof_sha256": proof,
                "errors": errors,
            }
        )
    if source_errors or checkpoint_errors:
        overall = "invalid_ledger_evidence"
    elif invalidated_count:
        overall = "reviewer_trust_invalidated"
    elif incomplete_count:
        overall = "trust_evidence_incomplete"
    elif retired_count:
        overall = "reviewer_trust_historical"
    else:
        overall = "reviewer_trust_current"
    witness_ids = [
        item.get("signer_id")
        for item in checkpoint.get("witness_signatures", [])
        if isinstance(item, Mapping)
    ]
    witness_map = {item["entity_id"]: item for item in policy.get("witnesses", [])}
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "evaluation_time": evaluation_time,
        "policy": deepcopy(dict(policy)),
        "quorum_report": deepcopy(dict(quorum_report)),
        "entries": deepcopy(list(entries)),
        "checkpoint": deepcopy(dict(checkpoint)),
        "previous_checkpoint": deepcopy(dict(previous_checkpoint)) if previous_checkpoint else None,
        "source_errors": source_errors,
        "checkpoint_errors": checkpoint_errors,
        "review_results": review_results,
        "summary": {
            "status": overall,
            "tree_size": len(entries),
            "review_count": len(review_results),
            "current_reviews": sum(
                item["status"] == "reviewer_trust_current" for item in review_results
            ),
            "historical_reviews": retired_count,
            "invalidated_reviews": invalidated_count,
            "incomplete_reviews": incomplete_count,
            "witness_count": len(set(witness_ids)),
            "distinct_witness_organizations": len(
                {
                    witness_map[item]["organization_id"]
                    for item in witness_ids
                    if item in witness_map
                }
            ),
            "automatic_deployment_actions": 0,
            "automatic_risk_acceptances": 0,
            "automatic_authorizations_to_operate": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_ledger_report(
    report: Mapping[str, Any], *, evidence_root: str | Path
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger report type or protocol version")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = analyze_ledger(
            report.get("policy", {}),
            report.get("quorum_report", {}),
            report.get("entries", []),
            report.get("checkpoint", {}),
            previous_checkpoint=report.get("previous_checkpoint"),
            evidence_root=evidence_root,
            evaluation_time=report.get("evaluation_time"),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AssuranceLedger report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def merkle_root(entries: Sequence[Mapping[str, Any]]) -> str:
    leaves = [_canonical_bytes(item) for item in entries]
    return _merkle_tree_hash(leaves).hex()


def inclusion_proof(entries: Sequence[Mapping[str, Any]], index: int) -> list[str]:
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(entries):
        raise ValueError("inclusion proof index is outside the tree")
    leaves = [_canonical_bytes(item) for item in entries]
    return [item.hex() for item in _inclusion_path(leaves, index)]


def _merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = _largest_power_of_two_less_than(len(leaves))
    return hashlib.sha256(
        b"\x01" + _merkle_tree_hash(leaves[:split]) + _merkle_tree_hash(leaves[split:])
    ).digest()


def _inclusion_path(leaves: Sequence[bytes], index: int) -> list[bytes]:
    if len(leaves) == 1:
        return []
    split = _largest_power_of_two_less_than(len(leaves))
    if index < split:
        return [*_inclusion_path(leaves[:split], index), _merkle_tree_hash(leaves[split:])]
    return [*_inclusion_path(leaves[split:], index - split), _merkle_tree_hash(leaves[:split])]


def _largest_power_of_two_less_than(value: int) -> int:
    return 1 << ((value - 1).bit_length() - 1)


def _empty_root() -> str:
    return hashlib.sha256(b"").hexdigest()


def _validate_event_body(
    event_type: str,
    body: Mapping[str, Any],
    label: str,
    integrated_at: int | None,
    errors: list[str],
) -> None:
    expected = {
        "reviewer-key-registration": _REGISTRATION_FIELDS,
        "review-envelope": _REVIEW_FIELDS,
        "reviewer-key-revocation": _REVOCATION_FIELDS,
    }.get(event_type)
    if expected is None:
        return
    _exact(body, expected, f"{label}.body", errors)
    _identifier(body.get("signer_id"), f"{label}.body.signer_id", errors)
    _digest(body.get("public_key_sha256"), f"{label}.body.public_key_sha256", errors)
    if event_type == "reviewer-key-registration":
        _identifier(body.get("role"), f"{label}.body.role", errors)
        _identifier(body.get("organization_id"), f"{label}.body.organization_id", errors)
        start = _integer(body.get("valid_from"), f"{label}.body.valid_from", errors)
        end = _integer(body.get("valid_until"), f"{label}.body.valid_until", errors)
        if start is not None and end is not None and start >= end:
            errors.append(f"{label}.body registration validity is empty")
        if integrated_at is not None and start is not None and integrated_at > start:
            errors.append(f"{label}.body registration was integrated after its validity began")
    elif event_type == "review-envelope":
        _digest(body.get("envelope_sha256"), f"{label}.body.envelope_sha256", errors)
        _digest(body.get("policy_sha256"), f"{label}.body.policy_sha256", errors)
        issued = _integer(body.get("review_issued_at"), f"{label}.body.review_issued_at", errors)
        expires = _integer(body.get("review_expires_at"), f"{label}.body.review_expires_at", errors)
        if issued is not None and expires is not None and issued >= expires:
            errors.append(f"{label}.body review validity is empty")
        if integrated_at is not None and issued is not None and integrated_at < issued:
            errors.append(f"{label}.body review was logged before it was issued")
    else:
        effective = _integer(body.get("effective_at"), f"{label}.body.effective_at", errors)
        compromise = body.get("compromise_since")
        if compromise is not None:
            compromise = _integer(compromise, f"{label}.body.compromise_since", errors)
        if effective is not None and compromise is not None and compromise > effective:
            errors.append(f"{label}.body.compromise_since must not follow effective_at")
        if integrated_at is not None and effective is not None and integrated_at < effective:
            errors.append(f"{label}.body revocation cannot be logged before effective_at")
        reason = body.get("reason")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 300:
            errors.append(
                f"{label}.body.reason must be a non-empty string of at most 300 characters"
            )


def _validate_key(value: Any, label: str, errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return None
    _exact(value, _KEY_FIELDS, label, errors)
    _identifier(value.get("entity_id"), f"{label}.entity_id", errors)
    _identifier(value.get("organization_id"), f"{label}.organization_id", errors)
    key_id = value.get("public_key_sha256")
    _digest(key_id, f"{label}.public_key_sha256", errors)
    try:
        der = base64.b64decode(str(value.get("public_key_spki_base64", "")), validate=True)
        _, Ed25519PublicKey, serialization, _ = _crypto()
        public = serialization.load_der_public_key(der)
        if not isinstance(public, Ed25519PublicKey):
            errors.append(f"{label} key is not Ed25519")
        if hashlib.sha256(der).hexdigest() != key_id:
            errors.append(f"{label}.public_key_sha256 does not match the embedded key")
    except (TypeError, ValueError):
        errors.append(f"{label} embedded public key is invalid")
    return value


def _sign_payload(
    payload: Mapping[str, Any],
    private_key_path: str | Path,
    descriptor: Mapping[str, Any],
    *,
    signer_id: str,
) -> dict[str, Any]:
    Ed25519PrivateKey, _, serialization, _ = _crypto()
    try:
        private = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=None
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load Ed25519 private key: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("AssuranceLedger requires an Ed25519 private key")
    der = private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if hashlib.sha256(der).hexdigest() != descriptor["public_key_sha256"]:
        raise ValueError("private key does not match the policy-authorized key")
    signature = private.sign(_canonical_bytes(payload))
    return {
        "keyid": descriptor["public_key_sha256"],
        "signer_id": signer_id,
        "signature_base64": base64.b64encode(signature).decode(),
    }


def _verify_signature(
    payload: Mapping[str, Any],
    signature: Any,
    descriptor: Mapping[str, Any],
    *,
    expected_signer: str,
    label: str,
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(signature, Mapping):
        return (f"{label} must be an object",)
    _exact(signature, _SIGNATURE_FIELDS, label, errors)
    if signature.get("keyid") != descriptor.get("public_key_sha256"):
        errors.append(f"{label} keyid does not match policy")
    if signature.get("signer_id") != expected_signer:
        errors.append(f"{label} signer_id does not match policy")
    try:
        sig = base64.b64decode(str(signature.get("signature_base64", "")), validate=True)
        der = base64.b64decode(str(descriptor.get("public_key_spki_base64", "")), validate=True)
        _, Ed25519PublicKey, serialization, InvalidSignature = _crypto()
        public = serialization.load_der_public_key(der)
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("key is not Ed25519")
        public.verify(sig, _canonical_bytes(payload))
    except InvalidSignature:
        errors.append(f"{label} Ed25519 signature is invalid")
    except (TypeError, ValueError):
        errors.append(f"{label} signature or public key is invalid")
    return tuple(errors)


def _review_predicate(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        predicate = statement["predicate"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("review envelope does not contain a readable predicate") from exc
    if not isinstance(predicate, Mapping):
        raise ValueError("review predicate must be an object")
    return predicate


def _safe_review_predicate(envelope: Any) -> Mapping[str, Any]:
    try:
        return _review_predicate(envelope)
    except ValueError:
        return {}


def _expected_review_body(
    envelope: Mapping[str, Any], predicate: Mapping[str, Any]
) -> dict[str, Any]:
    reviewer = predicate.get("reviewer", {})
    return {
        "envelope_sha256": canonical_sha256(envelope),
        "policy_sha256": predicate.get("policy_sha256"),
        "signer_id": reviewer.get("signer_id"),
        "public_key_sha256": reviewer.get("key_sha256"),
        "review_issued_at": predicate.get("issued_at"),
        "review_expires_at": predicate.get("expires_at"),
    }


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _safe_digest(payload: Any) -> str:
    try:
        return canonical_sha256(payload)
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
            "AssuranceLedger requires: pip install 'dspy-security-bench[signing]'"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature
