"""Compact RFC 6962-style append-only consistency proofs for AssuranceLedger."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.proof import (
    validate_policy,
    verify_checkpoint_signature_bundle,
    verify_ledger_report,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger ConsistencyProof / Compact append-only evidence"
PROTOCOL_VERSION = "assuranceledger-consistency-proof-v1"
VERIFIER = "rfc6962-style-minimal-consistency-verifier-v1"
MAX_PATH_NODES = 65
CLAIM_BOUNDARY = (
    "AssuranceLedger ConsistencyProof verifies, without log entries, that one newer "
    "policy-authorized signed checkpoint is an RFC 6962-style append-only extension of one "
    "older signed checkpoint. It also verifies each disclosed operator signature and witness "
    "quorum. It does not prove log-entry truth or completeness, checkpoint dissemination, "
    "witness independence, legal identity, model safety, compliance, authorization to operate, "
    "deployment authority, or risk acceptance."
)
LIMITATIONS = (
    "The proof establishes append-only consistency only between the two disclosed checkpoints; it does not establish global consistency.",
    "The AssuranceLedger canonical JSON leaf format is not a CT or C2SP wire format, although the Merkle proof construction follows RFC 6962.",
    "Source report digests are references; standalone verification does not prove how either checkpoint was obtained.",
    "A failed or withheld consistency proof is not automatically classified as operator equivocation by this artifact.",
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {
    "schema_version",
    "report_type",
    "protocol_version",
    "verifier",
    "source",
    "policy",
    "older_checkpoint",
    "newer_checkpoint",
    "consistency",
    "finding",
    "privacy",
    "claim_boundary",
    "limitations",
    "report_sha256",
}
_SOURCE_FIELDS = {"older_ledger_report_sha256", "newer_ledger_report_sha256"}
_CONSISTENCY_FIELDS = {
    "hash_algorithm",
    "leaf_domain_prefix_hex",
    "node_domain_prefix_hex",
    "older_tree_size",
    "newer_tree_size",
    "path_sha256",
}
_FINDING_FIELDS = {
    "status",
    "log_origin",
    "older_root_sha256",
    "newer_root_sha256",
    "path_node_count",
    "valid_operator_signatures",
    "valid_witness_quorums",
}
_PRIVACY_FIELDS = {
    "log_entries_embedded",
    "quorum_reports_embedded",
    "review_envelopes_embedded",
    "reviewer_key_registrations_embedded",
    "automatic_actions",
}


def merkle_consistency_path(
    entries: Sequence[Mapping[str, Any]], older_tree_size: int
) -> list[str]:
    """Return the unique minimal RFC 6962 consistency path for a strict extension."""
    if (
        isinstance(older_tree_size, bool)
        or not isinstance(older_tree_size, int)
        or not 0 < older_tree_size < len(entries)
    ):
        raise ValueError("older_tree_size must be positive and smaller than the complete tree")
    leaves = [_canonical_bytes(item) for item in entries]
    return [item.hex() for item in _subproof(older_tree_size, leaves, known=True)]


def verify_merkle_consistency(
    *,
    older_tree_size: int,
    newer_tree_size: int,
    older_root_sha256: str,
    newer_root_sha256: str,
    path_sha256: Sequence[str],
) -> tuple[str, ...]:
    """Verify an RFC 9162 section 2.1.4.2 consistency path."""
    errors: list[str] = []
    if (
        isinstance(older_tree_size, bool)
        or not isinstance(older_tree_size, int)
        or older_tree_size < 1
    ):
        errors.append("older_tree_size must be a positive integer")
    if isinstance(newer_tree_size, bool) or not isinstance(newer_tree_size, int):
        errors.append("newer_tree_size must be an integer")
    elif isinstance(older_tree_size, int) and newer_tree_size <= older_tree_size:
        errors.append("newer_tree_size must be greater than older_tree_size")
    if not isinstance(older_root_sha256, str) or not _DIGEST.fullmatch(older_root_sha256):
        errors.append("older_root_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(newer_root_sha256, str) or not _DIGEST.fullmatch(newer_root_sha256):
        errors.append("newer_root_sha256 must be a lowercase SHA-256 digest")
    if (
        not isinstance(path_sha256, list)
        or not 1 <= len(path_sha256) <= MAX_PATH_NODES
        or any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in path_sha256)
    ):
        errors.append(f"path_sha256 must contain 1 to {MAX_PATH_NODES} SHA-256 nodes")
    if errors:
        return tuple(errors)
    path = [bytes.fromhex(item) for item in path_sha256]
    older_root = bytes.fromhex(older_root_sha256)
    newer_root = bytes.fromhex(newer_root_sha256)
    if older_tree_size & (older_tree_size - 1) == 0:
        path.insert(0, older_root)
    fn = older_tree_size - 1
    sn = newer_tree_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    first_root = path[0]
    second_root = path[0]
    for node in path[1:]:
        if sn == 0:
            errors.append("consistency path contains unused trailing nodes")
            break
        if fn & 1 or fn == sn:
            first_root = _node_hash(node, first_root)
            second_root = _node_hash(node, second_root)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            second_root = _node_hash(second_root, node)
        fn >>= 1
        sn >>= 1
    if first_root != older_root:
        errors.append("consistency path does not reconstruct the older root")
    if second_root != newer_root:
        errors.append("consistency path does not reconstruct the newer root")
    if sn != 0:
        errors.append("consistency path is incomplete for the newer tree")
    return tuple(dict.fromkeys(errors))


def export_consistency_proof(
    older_report: Mapping[str, Any],
    newer_report: Mapping[str, Any],
    *,
    evidence_root: str | Path,
) -> dict[str, Any]:
    """Minimize two fully verified ledger reports into portable extension evidence."""
    errors = list(verify_ledger_report(older_report, evidence_root=evidence_root))
    errors.extend(
        f"newer report: {item}"
        for item in verify_ledger_report(newer_report, evidence_root=evidence_root)
    )
    if errors:
        raise ValueError("invalid AssuranceLedger source report: " + "; ".join(errors))
    older = older_report["checkpoint"]["checkpoint"]
    newer = newer_report["checkpoint"]["checkpoint"]
    if older_report["policy"] != newer_report["policy"]:
        raise ValueError("source reports do not embed the same ledger policy")
    if older["tree_size"] >= newer["tree_size"]:
        raise ValueError("source reports are not in strict older-to-newer tree-size order")
    if older_report["entries"] != newer_report["entries"][: older["tree_size"]]:
        raise ValueError("older event history is not an exact prefix of the newer history")
    path = merkle_consistency_path(newer_report["entries"], older["tree_size"])
    proof: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "verifier": VERIFIER,
        "source": {
            "older_ledger_report_sha256": older_report["report_sha256"],
            "newer_ledger_report_sha256": newer_report["report_sha256"],
        },
        "policy": deepcopy(older_report["policy"]),
        "older_checkpoint": deepcopy(older_report["checkpoint"]),
        "newer_checkpoint": deepcopy(newer_report["checkpoint"]),
        "consistency": {
            "hash_algorithm": "sha256",
            "leaf_domain_prefix_hex": "00",
            "node_domain_prefix_hex": "01",
            "older_tree_size": older["tree_size"],
            "newer_tree_size": newer["tree_size"],
            "path_sha256": path,
        },
        "finding": {
            "status": "append_only_extension_proved",
            "log_origin": older["log_origin"],
            "older_root_sha256": older["root_sha256"],
            "newer_root_sha256": newer["root_sha256"],
            "path_node_count": len(path),
            "valid_operator_signatures": 2,
            "valid_witness_quorums": 2,
        },
        "privacy": {
            "log_entries_embedded": 0,
            "quorum_reports_embedded": 0,
            "review_envelopes_embedded": 0,
            "reviewer_key_registrations_embedded": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    proof["report_sha256"] = canonical_sha256(proof)
    if errors := verify_consistency_proof(proof):
        raise ValueError("generated consistency proof is invalid: " + "; ".join(errors))
    return proof


def verify_consistency_proof(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Verify a portable consistency proof without its source ledger reports."""
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    _exact(report, _TOP_FIELDS, "report", errors)
    if (
        report.get("schema_version") != 1
        or report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
        or report.get("verifier") != VERIFIER
    ):
        errors.append("report metadata does not match AssuranceLedger ConsistencyProof v1")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    source = report.get("source")
    if not isinstance(source, Mapping):
        errors.append("source must be an object")
    else:
        _exact(source, _SOURCE_FIELDS, "source", errors)
        for field in _SOURCE_FIELDS:
            _digest(source.get(field), f"source.{field}", errors)
        if source.get("older_ledger_report_sha256") == source.get("newer_ledger_report_sha256"):
            errors.append("source ledger report digests must be distinct")
    policy = report.get("policy")
    if not isinstance(policy, Mapping):
        errors.append("policy must be an object")
        policy = {}
    else:
        errors.extend(validate_policy(policy))
    signed = []
    for label in ("older_checkpoint", "newer_checkpoint"):
        value = report.get(label)
        if not isinstance(value, Mapping):
            errors.append(f"{label} must be an object")
            signed.append({})
        else:
            signed.append(value)
            errors.extend(
                f"{label}: {item}" for item in verify_checkpoint_signature_bundle(policy, value)
            )
    older = signed[0].get("checkpoint", {})
    newer = signed[1].get("checkpoint", {})
    consistency = report.get("consistency")
    if not isinstance(consistency, Mapping):
        errors.append("consistency must be an object")
        consistency = {}
    else:
        _exact(consistency, _CONSISTENCY_FIELDS, "consistency", errors)
        if (
            consistency.get("hash_algorithm") != "sha256"
            or consistency.get("leaf_domain_prefix_hex") != "00"
            or consistency.get("node_domain_prefix_hex") != "01"
        ):
            errors.append("consistency hash construction does not match AssuranceLedger v1")
    if consistency.get("older_tree_size") != older.get("tree_size"):
        errors.append("consistency older_tree_size does not match older checkpoint")
    if consistency.get("newer_tree_size") != newer.get("tree_size"):
        errors.append("consistency newer_tree_size does not match newer checkpoint")
    errors.extend(
        verify_merkle_consistency(
            older_tree_size=consistency.get("older_tree_size"),
            newer_tree_size=consistency.get("newer_tree_size"),
            older_root_sha256=older.get("root_sha256"),
            newer_root_sha256=newer.get("root_sha256"),
            path_sha256=consistency.get("path_sha256"),
        )
    )
    expected_finding = {
        "status": "append_only_extension_proved",
        "log_origin": older.get("log_origin"),
        "older_root_sha256": older.get("root_sha256"),
        "newer_root_sha256": newer.get("root_sha256"),
        "path_node_count": len(consistency.get("path_sha256", []))
        if isinstance(consistency.get("path_sha256"), list)
        else 0,
        "valid_operator_signatures": 2,
        "valid_witness_quorums": 2,
    }
    finding = report.get("finding")
    if not isinstance(finding, Mapping):
        errors.append("finding must be an object")
    else:
        _exact(finding, _FINDING_FIELDS, "finding", errors)
        if finding != expected_finding:
            errors.append("finding does not match the verified consistency proof")
    privacy = report.get("privacy")
    expected_privacy = {
        "log_entries_embedded": 0,
        "quorum_reports_embedded": 0,
        "review_envelopes_embedded": 0,
        "reviewer_key_registrations_embedded": 0,
        "automatic_actions": 0,
    }
    if not isinstance(privacy, Mapping):
        errors.append("privacy must be an object")
    else:
        _exact(privacy, _PRIVACY_FIELDS, "privacy", errors)
        if privacy != expected_privacy:
            errors.append("privacy declaration does not match ConsistencyProof v1")
    if report.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match ConsistencyProof v1")
    if report.get("limitations") != list(LIMITATIONS):
        errors.append("limitations do not match ConsistencyProof v1")
    return tuple(dict.fromkeys(errors))


def _subproof(size: int, leaves: Sequence[bytes], *, known: bool) -> list[bytes]:
    if size == len(leaves):
        return [] if known else [_tree_hash(leaves)]
    split = _largest_power_of_two_less_than(len(leaves))
    if size <= split:
        return [*_subproof(size, leaves[:split], known=known), _tree_hash(leaves[split:])]
    return [
        *_subproof(size - split, leaves[split:], known=False),
        _tree_hash(leaves[:split]),
    ]


def _tree_hash(leaves: Sequence[bytes]) -> bytes:
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = _largest_power_of_two_less_than(len(leaves))
    return _node_hash(_tree_hash(leaves[:split]), _tree_hash(leaves[split:]))


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(value: int) -> int:
    return 1 << ((value - 1).bit_length() - 1)


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    missing = expected - set(value)
    extra = set(value) - expected
    if missing:
        errors.append(f"{label} is missing fields: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{label} has unexpected fields: {', '.join(sorted(extra))}")


def _digest(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        errors.append(f"{label} must be a lowercase SHA-256 digest")
