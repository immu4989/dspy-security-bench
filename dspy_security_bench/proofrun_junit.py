"""JUnit presentation of freshly computed ProofRun review decisions.

This module is a renderer, not a verifier of saved decision documents. It uses
fingerprinted test identities, suite-level properties, and source-redacted projections.
No execution times, independent reproductions, or security approvals are implied.
"""

from __future__ import annotations

import hashlib
import json
from xml.etree import ElementTree as ET

from dspy_security_bench.proofrun_collection import REASONS as COLLECTION_REASONS
from dspy_security_bench.proofrun_review import REASONS as REVIEW_REASONS

_REVIEW_FIELDS = (
    "schema_version", "review_type", "verifier_version", "input_file_sha256", "bundle_type", "bundle_sha256",
    "integrity", "eligibility", "provenance", "evidence_tier", "review_is_attestation", "execution_reproduced",
    "exit_code", "verdict", "reason_code",
)
_POLICY_FIELDS = (
    "minimum_trials", "mode", "expected_file_sha256", "expected_repository_sha256",
    "require_trusted_builder", "deny_self_hosted_runner",
)
_COLLECTION_FIELDS = (
    "schema_version", "review_type", "verifier_version", "plan_file_sha256", "expected_plan_file_sha256",
    "review_is_attestation", "execution_reproduced", "requirements_completeness_established",
    "exit_code", "verdict", "reason_code",
)
_ENTRY_FIELDS = (
    "index", "entry_id_sha256", "expected_bundle_type", "expected_file_sha256", "input_file_sha256", "status",
)
_ENTRY_REASONS = {
    "invalid_input": "Required input could not be read as bounded strict JSON from an ordinary local file.",
    "pin_mismatch": "Required artifact bytes do not match the owner's exact file pin.",
    "bundle_type_mismatch": "The pinned artifact has a different bundle type than the required evidence slot.",
    "byte_budget_exceeded": "Required evidence was not reviewed within the input byte budget; it is an error, not a skipped requirement.",
}
_ADVICE = {
    "invalid_input": "Check the retained file and local path without publishing its contents.",
    "invalid_plan": "Correct the owner-controlled plan; keep every required evidence slot visible.",
    "invalid_policy": "Correct the explicitly selected policy before retrying.",
    "policy_not_applicable": "Select the appropriate structural or repeated-trial review policy.",
    "pin_mismatch": "Restore the expected artifact or obtain an independently approved pin change.",
    "plan_pin_mismatch": "Restore the expected plan or obtain an independently approved requirement change.",
    "bundle_type_mismatch": "Supply the artifact type required by the owner-controlled plan.",
    "not_eligible": "Review native limitations and eligibility rules; do not omit unfavorable evidence.",
    "attestation_unverified": "Establish the required provenance; offline consistency is not a substitute for authentication.",
    "byte_budget_exceeded": "Reduce artifact size within the protocol and rerun the complete plan; do not drop requirements.",
}
_BOUNDARY = "Review success is not deployment approval, proof of complete requirements, or independent execution reproduction."


def _project(source: dict, fields: tuple[str, ...]) -> dict:
    return {key: source[key] for key in fields if key in source}


def _review_projection(review: dict) -> dict:
    projected = _project(review, _REVIEW_FIELDS)
    policy = review.get("policy")
    projected["policy"] = _project(policy, _POLICY_FIELDS) if isinstance(policy, dict) else None
    return projected


def _json(value) -> str:
    # ASCII JSON escapes prevent source-independent version strings or future
    # metadata from creating XML 1.0 control characters or host-encoding failures.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def _render(name: str, properties: dict, cases: list[tuple[str, int, str, str, dict]], identity: dict) -> str:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", {
        "name": name, "tests": str(len(cases)), "failures": str(sum(case[1] == 1 for case in cases)),
        "errors": str(sum(case[1] == 2 for case in cases)), "skipped": "0",
    })
    props = ET.SubElement(suite, "properties")
    for key, value in properties.items():
        ET.SubElement(props, "property", {"name": key, "value": _json(value)})
    ET.SubElement(props, "property", {"name": "claim_boundary", "value": _json(_BOUNDARY)})
    # CI importers may silently discard duplicate classname/name pairs. Bind the
    # namespace to input, selected policy, and a hashed caller scope, not verdict.
    namespace = hashlib.sha256(_json(identity).encode("ascii")).hexdigest()
    for case_name, code, reason, message, projection in cases:
        case = ET.SubElement(suite, "testcase", {"classname": name, "name": case_name + "-" + namespace})
        if code:
            problem = ET.SubElement(case, "failure" if code == 1 else "error", {
                "type": "ProofRunRequirementNotMet" if code == 1 else "ProofRunInvalidReview",
                "message": message,
            })
            advice = _ADVICE.get(reason, "Regenerate evidence from retained original inputs and rerun native verification.")
            problem.text = message + "\n" + advice + "\n" + _BOUNDARY
        # Some CI UIs ignore suite properties, so repeat the boundary in each
        # visible testcase's output, including passing evidence reviews.
        ET.SubElement(case, "system-out").text = _json({**projection, "claim_boundary": _BOUNDARY})
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")


def render_review_junit(review: dict, *, scope: str | None = None) -> str:
    """One testcase; unmet requirements fail, invalid input errors. Scope is hashed."""
    reason = review["reason_code"]
    return _render("proofrun.review", {
        "verifier_version": review["verifier_version"], "review_is_attestation": False, "execution_reproduced": False,
    }, [("artifact", review["exit_code"], reason, REVIEW_REASONS[reason], _review_projection(review))],
        {"input_file_sha256": review["input_file_sha256"], "policy": _review_projection(review)["policy"], "scope": scope})


def render_collection_junit(review: dict, *, scope: str | None = None) -> str:
    """One testcase per required entry; invalid plan admission is one error case.

    Counts are derived from emitted outcomes, not copied from a summary. Budget
    exhaustion and missing files remain errors and are never marked skipped.
    """
    properties = _project(review, _COLLECTION_FIELDS)
    cases = []
    for row in review["entries"]:
        projection = _project(row, _ENTRY_FIELDS)
        native = row["review"]
        projection["review"] = _review_projection(native) if native is not None else None
        reason = native["reason_code"] if native is not None else row["status"]
        code = native["exit_code"] if native is not None else 2
        message = REVIEW_REASONS[reason] if native is not None else _ENTRY_REASONS[reason]
        cases.append((f"entry-{row['index'] + 1:04d}", code, reason, message, projection))
    if not cases:
        reason = review["reason_code"]
        cases.append(("plan-admission", 2, reason, COLLECTION_REASONS[reason], properties))
    return _render("proofrun.collection", properties, cases, {
        "plan_file_sha256": review["plan_file_sha256"], "expected_plan_file_sha256": review["expected_plan_file_sha256"],
        "scope": scope,
    })
