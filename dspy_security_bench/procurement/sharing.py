"""Offline, content-free inventory for owner review before sharing evidence.

This is deliberately not a secret detector or a publication authorization gate.
Every JSON key and leaf is counted, including extensions unknown to the engine.
"""

from __future__ import annotations

import json
import re
from typing import Any

from dspy_security_bench.jsonio import decode_json_object
from dspy_security_bench.procurement.repeat import canonical_sha256

MAX_SHARING_BYTES = 50_000_000
_FIELDS = {
    "final_answer": "model_outputs",
    "error": "runtime_errors",
    "arguments": "tool_arguments",
    "submission": "submission_metadata",
    "provenance": "provenance_metadata",
}
_CATEGORIES = (*dict.fromkeys(_FIELDS.values()), "other_content")
_LIMITATIONS = [
    "Owner review required; this inventory never authorizes publication.",
    "Hashes bind content; they do not redact it or authenticate execution.",
    "Categories use field names, not secret detection; inspect other content and keys too.",
    "Counts include duplicated retained evidence and do not count unique disclosures.",
    "Numbers, booleans, metadata, keys, and the review itself may disclose information.",
    "Source evidence is unchanged; editing it can invalidate native verification.",
    "Native consistency verification is not registry eligibility or regulatory compliance.",
]


def _verify_source(source: dict[str, Any]) -> str:
    """Use native checks without propagating potentially sensitive diagnostics."""
    from dspy_security_bench.procurement.control_registry import (
        BUNDLE_TYPE,
        verify_control_submission_bundle,
    )
    from dspy_security_bench.procurement.control_twin import verify_control_report
    from dspy_security_bench.procurement.repeat import (
        validate_repeat_payload,
        verify_submission_bundle,
    )
    from dspy_security_bench.procurement.repeat_control import verify_repeat_control_report

    try:
        if source.get("bundle_type") == "dspy-security-bench-community-submission":
            if not verify_submission_bundle(source).valid:
                raise ValueError
            return "repeat_submission"
        if source.get("bundle_type") == BUNDLE_TYPE:
            if not verify_control_submission_bundle(source).valid:
                raise ValueError
            return "control_submission"
        if source.get("report_type") == "RepeatTwin / ProcureBench":
            if validate_repeat_payload(source):
                raise ValueError
            return "repeat_report"
        if source.get("report_type") == "RepeatControlTwin / Policy efficacy":
            verify_repeat_control_report(source)
            return "repeat_control_report"
        if source.get("specialty") == "ControlTwin / Policy efficacy":
            verify_control_report(source)
            return "control_report"
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
        raise ValueError("source failed native evidence verification") from None
    raise ValueError("unsupported source evidence type")


def create_sharing_review(
    source: dict[str, Any], *, source_sha256: str | None = None,
) -> dict[str, Any]:
    """Inventory a bounded verified JSON source; never retain values or field paths.

    The optional pin is the canonical hash of the WHOLE input, including its
    embedded digests. It is not the report's unsigned report_sha256 field.
    """
    try:
        encoded = json.dumps(source, ensure_ascii=False, allow_nan=False).encode("utf-8")
        source = decode_json_object(encoded, MAX_SHARING_BYTES)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ValueError("source must be bounded portable JSON") from None
    digest = canonical_sha256(source)
    if source_sha256 is not None and (
        not isinstance(source_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
        or source_sha256 != digest
    ):
        raise ValueError("source pin must match the whole canonical input")
    source_kind = _verify_source(source)
    inventory = {
        category: {
            "objects": 0, "arrays": 0, "object_keys": 0, "key_utf8_bytes": 0,
            "string_values": 0, "nonempty_strings": 0, "string_utf8_bytes": 0,
            "nonstring_values": 0,
        }
        for category in _CATEGORIES
    }
    pending = [(source, "other_content")]
    while pending:
        value, category = pending.pop()
        counts = inventory[category]
        if isinstance(value, dict):
            counts["objects"] += 1
            for key, child in value.items():
                # A recognized enclosing category owns its whole subtree.
                child_category = _FIELDS.get(key, category) if category == "other_content" else category
                child_counts = inventory[child_category]
                child_counts["object_keys"] += 1
                child_counts["key_utf8_bytes"] += len(key.encode("utf-8"))
                pending.append((child, child_category))
        elif isinstance(value, list):
            counts["arrays"] += 1
            pending.extend((child, category) for child in value)
        elif isinstance(value, str):
            counts["string_values"] += 1
            counts["nonempty_strings"] += int(bool(value))
            counts["string_utf8_bytes"] += len(value.encode("utf-8"))
        else:
            counts["nonstring_values"] += 1
    review = {
        "schema_version": 1,
        "review_type": "procurement-sharing-inventory-v1",
        "source_kind": source_kind,
        "source_sha256": digest,
        "source_digest_scope": "whole_canonical_json_including_embedded_digests",
        "native_consistency": "verified",
        "publication_status": "owner_review_required",
        "inventory": inventory,
        "limitations": list(_LIMITATIONS),
    }
    review["review_sha256"] = canonical_sha256(review)
    return review


def verify_sharing_review(
    review: dict[str, Any], source: dict[str, Any], *, source_sha256: str | None = None,
) -> None:
    """Replay the full review against retained source, not just a self-hash."""
    expected = create_sharing_review(source, source_sha256=source_sha256)
    try:
        matches = canonical_sha256(review) == canonical_sha256(expected)
    except (TypeError, ValueError, OverflowError, RecursionError):
        matches = False
    if not matches:
        raise ValueError("sharing review does not match retained source replay")
