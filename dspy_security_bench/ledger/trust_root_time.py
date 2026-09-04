"""Conservative AssuranceTrustRoot evaluation over signed bounded-time evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from dspy_security_bench.ledger.time_quorum import (
    TRUSTED_STATUS as TIME_TRUSTED_STATUS,
)
from dspy_security_bench.ledger.time_quorum import verify_time_quorum_report
from dspy_security_bench.ledger.trust_root import TRUSTED_STATUSES, evaluate_trust_root
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger TrustRootTimeGate / Conservatively time-bounded root trust"
PROTOCOL_VERSION = "assuranceledger-trust-root-time-gate-v1"
ANALYZER = "deterministic-conservative-root-time-gate-v1"
TRUSTED_STATUS = "temporally_trusted_root"
CLAIM_BOUNDARY = (
    "TrustRootTimeGate composes a caller-pinned AssuranceTimeQuorum report with an "
    "AssuranceTrustRoot evaluation. It binds signed time intervals to the exact candidate "
    "root and retained request nonce, then requires root continuity, policy authorization, "
    "issuance, and expiration checks to pass at both ends of the conservative interval. A "
    "passing report establishes root trust throughout that interval only."
)
LIMITATIONS = (
    "The gate inherits every AssuranceTimeQuorum limitation, including dependence on source clocks, policy distribution, declared organizations, key custody, and caller-retained nonce freshness.",
    "Checking both interval endpoints is sufficient for the root's monotonic issued-at and expires-at predicates; it does not generalize to arbitrary time-dependent policy logic.",
    "The report does not prove that the supplied root is the globally latest root or that a distributor did not withhold a newer version.",
    "A passing result is not RFC 3161 or Roughtime compatibility, UTC accuracy, a FIPS determination, compliance certification, authorization to operate, deployment approval, or risk acceptance.",
    "The gate performs no network access, clock adjustment, root installation, key operation, policy change, notification, deployment, or automatic remediation.",
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9._:-]{16,200}\Z")
_CHECKS = (
    ("ART001", "The AssuranceTimeQuorum report recomputes exactly"),
    ("ART002", "The time policy matches the caller-retained exact digest"),
    ("ART003", "The time request matches the caller-retained fresh nonce"),
    ("ART004", "The signed time subject is the exact candidate root"),
    ("ART005", "The independent bounded-time quorum is satisfied"),
    ("ART006", "A conservative ordered time interval is available"),
    ("ART007", "The root is trusted at the interval lower bound"),
    ("ART008", "The root remains trusted through the interval upper bound"),
)


def evaluate_trust_root_time(
    candidate_root: Mapping[str, Any],
    time_quorum_report: Mapping[str, Any],
    *,
    expected_time_policy_sha256: str,
    expected_request_nonce: str,
    trusted_root: Mapping[str, Any] | None = None,
    expected_root_sha256: str | None = None,
    expected_trust_domain: str | None = None,
    minimum_version: int | None = None,
    policies: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Require a candidate root to remain trusted across a signed time interval."""

    if not _is_digest(expected_time_policy_sha256):
        raise ValueError("expected_time_policy_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(expected_request_nonce, str) or not _NONCE.fullmatch(
        expected_request_nonce
    ):
        raise ValueError("expected_request_nonce must be 16 to 200 safe printable characters")
    candidate = dict(candidate_root) if isinstance(candidate_root, Mapping) else {}
    time_report = dict(time_quorum_report) if isinstance(time_quorum_report, Mapping) else {}
    root_subject = candidate.get("root_sha256")
    expectations = time_report.get("expectations", {})
    if not isinstance(expectations, Mapping):
        expectations = {}

    time_errors = list(verify_time_quorum_report(time_report))
    pin_matches = expectations.get("expected_policy_sha256") == expected_time_policy_sha256
    nonce_matches = expectations.get("expected_request_nonce") == expected_request_nonce
    subject_matches = _is_digest(root_subject) and (
        expectations.get("expected_subject_sha256") == root_subject
    )
    time_status = (
        time_report.get("summary", {}).get("status")
        if isinstance(time_report.get("summary"), Mapping)
        else None
    )
    interval = (
        time_report.get("conservative_interval", {})
        if isinstance(time_report.get("conservative_interval"), Mapping)
        else {}
    )
    lower = _plain_nonnegative_int(interval.get("lower_bound_unix"))
    upper = _plain_nonnegative_int(interval.get("upper_bound_unix"))
    interval_available = lower is not None and upper is not None and lower <= upper

    lower_report: dict[str, Any] | None = None
    upper_report: dict[str, Any] | None = None
    if (
        not time_errors
        and pin_matches
        and nonce_matches
        and subject_matches
        and time_status == TIME_TRUSTED_STATUS
        and interval_available
    ):
        common = {
            "trusted_root": trusted_root,
            "expected_root_sha256": expected_root_sha256,
            "expected_trust_domain": expected_trust_domain,
            "minimum_version": minimum_version,
            "policies": policies,
        }
        lower_report = evaluate_trust_root(candidate, evaluation_time=lower, **common)
        upper_report = evaluate_trust_root(candidate, evaluation_time=upper, **common)

    lower_status = lower_report["summary"]["status"] if lower_report else None
    upper_status = upper_report["summary"]["status"] if upper_report else None
    lower_trusted = lower_status in TRUSTED_STATUSES
    upper_trusted = upper_status in TRUSTED_STATUSES

    rule_errors = {rule_id: [] for rule_id, _ in _CHECKS}
    rule_errors["ART001"].extend(time_errors)
    if not pin_matches:
        rule_errors["ART002"].append("time policy does not match the retained digest")
    if not nonce_matches:
        rule_errors["ART003"].append("time request does not match the retained nonce")
    if not subject_matches:
        rule_errors["ART004"].append("time subject does not match candidate root_sha256")
    if time_status != TIME_TRUSTED_STATUS:
        rule_errors["ART005"].append(
            f"AssuranceTimeQuorum status is {time_status!r}, not {TIME_TRUSTED_STATUS}"
        )
    if not interval_available:
        rule_errors["ART006"].append("conservative time interval is absent or unordered")
    if lower_report is None:
        rule_errors["ART007"].append("lower-bound root evaluation was not eligible to run")
    elif not lower_trusted:
        rule_errors["ART007"].append(f"lower-bound root status is {lower_status}")
    if upper_report is None:
        rule_errors["ART008"].append("upper-bound root evaluation was not eligible to run")
    elif not upper_trusted:
        rule_errors["ART008"].append(f"upper-bound root status is {upper_status}")

    if time_errors:
        status = "invalid_time_quorum"
    elif not pin_matches:
        status = "time_policy_not_pinned"
    elif not nonce_matches:
        status = "time_request_mismatch"
    elif not subject_matches:
        status = "time_subject_mismatch"
    elif time_status != TIME_TRUSTED_STATUS:
        status = "time_quorum_not_satisfied"
    elif not interval_available:
        status = "time_interval_unavailable"
    elif lower_status == "not_yet_valid_trust_root":
        status = "root_not_yet_valid_for_interval"
    elif upper_status == "expired_trust_root":
        status = "root_expires_within_interval"
    elif not lower_trusted or not upper_trusted:
        status = "root_trust_failed"
    else:
        status = TRUSTED_STATUS

    findings = []
    for rule_id, title in _CHECKS:
        errors = list(dict.fromkeys(rule_errors[rule_id]))
        findings.append(
            {
                "rule_id": rule_id,
                "title": title,
                "status": "passed" if not errors else "failed",
                "detail": "verified" if not errors else "; ".join(errors),
            }
        )
    failed = sum(item["status"] == "failed" for item in findings)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "candidate_root": deepcopy(candidate),
        "trusted_root": deepcopy(dict(trusted_root)) if trusted_root is not None else None,
        "time_quorum_report": deepcopy(time_report),
        "anchor": {
            "expected_time_policy_sha256": expected_time_policy_sha256,
            "expected_request_nonce": expected_request_nonce,
            "expected_root_sha256": expected_root_sha256,
            "expected_trust_domain": expected_trust_domain,
            "minimum_version": minimum_version,
        },
        "policy_inputs": [deepcopy(dict(item)) for item in policies],
        "lower_bound_root_report": lower_report,
        "upper_bound_root_report": upper_report,
        "findings": findings,
        "summary": {
            "status": status,
            "lower_bound_unix": lower,
            "upper_bound_unix": upper,
            "interval_width_seconds": upper - lower if interval_available else None,
            "lower_bound_root_status": lower_status,
            "upper_bound_root_status": upper_status,
            "passed_checks": len(findings) - failed,
            "failed_checks": failed,
            "content_fields_processed": 0,
            "clock_adjustments": 0,
            "roots_installed": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_trust_root_time_report(
    report: Mapping[str, Any],
    *,
    expected_time_policy_sha256: str | None = None,
    expected_request_nonce: str | None = None,
) -> tuple[str, ...]:
    """Recompute a temporal gate and optionally enforce retained time expectations."""

    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported TrustRootTimeGate report")
    anchor = report.get("anchor")
    if not isinstance(anchor, Mapping):
        errors.append("report anchor must be an object")
        anchor = {}
    if (
        expected_time_policy_sha256 is not None
        and expected_time_policy_sha256 != anchor.get("expected_time_policy_sha256")
    ):
        errors.append("report time-policy pin does not match the caller-retained expectation")
    if (
        expected_request_nonce is not None
        and expected_request_nonce != anchor.get("expected_request_nonce")
    ):
        errors.append("report nonce does not match the caller-retained expectation")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = evaluate_trust_root_time(
            report.get("candidate_root", {}),
            report.get("time_quorum_report", {}),
            expected_time_policy_sha256=anchor.get("expected_time_policy_sha256", ""),
            expected_request_nonce=anchor.get("expected_request_nonce", ""),
            trusted_root=report.get("trusted_root"),
            expected_root_sha256=anchor.get("expected_root_sha256"),
            expected_trust_domain=anchor.get("expected_trust_domain"),
            minimum_version=anchor.get("minimum_version"),
            policies=report.get("policy_inputs", []),
        )
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("TrustRootTimeGate report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


def _plain_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
