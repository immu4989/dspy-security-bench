"""Integrity-verifiable, non-certifying federal review inputs for AssuranceGraph."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.assurance.case import CLAIM_BOUNDARY, verify_report
from dspy_security_bench.assurance.exports import export_oscal
from dspy_security_bench.mission.loader import canonical_sha256

PACK_TYPE = "dspy-security-bench-assurance-review-pack"
PACK_VERSION = 1
PACK_FILES = (
    "README.md",
    "assessment-plan-input.json",
    "assessment-results.json",
    "assurance-report.json",
    "change-triggers.md",
    "evidence-index.json",
    "freshness-plan.json",
    "poam-input.json",
)
DISCLAIMER = (
    "This pack contains owner-reviewable technical assessment inputs. It is not an assessment "
    "plan, system security plan, control determination, compliance finding, legal opinion, "
    "procurement decision, risk acceptance, authorization to operate, or government endorsement."
)


def export_review_pack(
    report: Mapping[str, Any],
    evidence_root: str | Path,
    out_dir: str | Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Verify an AssuranceGraph report and write deterministic reviewer inputs."""

    errors = verify_report(report, evidence_root)
    if errors:
        raise ValueError("AssuranceGraph report does not verify: " + "; ".join(errors))
    root = Path(out_dir)
    if root.exists() and any(root.iterdir()) and not force:
        raise ValueError(f"output directory is not empty: {root} (use --force)")
    root.mkdir(parents=True, exist_ok=True)
    artifacts = _artifacts(report)
    for name, content in artifacts.items():
        (root / name).write_bytes(content)
    manifest = {
        "pack_schema_version": PACK_VERSION,
        "pack_type": PACK_TYPE,
        "case_id": report["case"]["case_id"],
        "report_sha256": report["report_sha256"],
        "profile_id": report["profile"]["profile_id"],
        "evaluation_time": report["case"]["evaluation_time"],
        "assurance_status": report["summary"]["status"],
        "oscal_version": "1.2.2",
        "files": {name: hashlib.sha256(artifacts[name]).hexdigest() for name in PACK_FILES},
        "automatic_control_determinations": 0,
        "automatic_risk_acceptances": 0,
        "automatic_authorizations_to_operate": 0,
        "disclaimer": DISCLAIMER,
    }
    manifest["pack_sha256"] = canonical_sha256(manifest)
    (root / "pack-manifest.json").write_bytes(_json_bytes(manifest))
    return manifest


def verify_review_pack(pack_dir: str | Path, evidence_root: str | Path) -> tuple[str, ...]:
    """Recompute every file, report, and manifest in a review pack offline."""

    root = Path(pack_dir)
    errors: list[str] = []
    try:
        manifest = _read_json(root / "pack-manifest.json", 1_000_000)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return (f"could not read pack-manifest.json: {exc}",)
    expected_manifest_fields = {
        "pack_schema_version",
        "pack_type",
        "case_id",
        "report_sha256",
        "profile_id",
        "evaluation_time",
        "assurance_status",
        "oscal_version",
        "files",
        "automatic_control_determinations",
        "automatic_risk_acceptances",
        "automatic_authorizations_to_operate",
        "disclaimer",
        "pack_sha256",
    }
    if set(manifest) != expected_manifest_fields:
        errors.append("manifest fields do not match the review-pack contract")
    if (
        manifest.get("pack_schema_version") != PACK_VERSION
        or manifest.get("pack_type") != PACK_TYPE
    ):
        errors.append("manifest metadata does not match the review-pack contract")
    if manifest.get("oscal_version") != "1.2.2":
        errors.append("manifest oscal_version must be 1.2.2")
    for field in (
        "automatic_control_determinations",
        "automatic_risk_acceptances",
        "automatic_authorizations_to_operate",
    ):
        if manifest.get(field) != 0:
            errors.append(f"manifest {field} must be zero")
    if manifest.get("disclaimer") != DISCLAIMER:
        errors.append("manifest disclaimer does not match the review-pack contract")
    unsigned = dict(manifest)
    unsigned.pop("pack_sha256", None)
    try:
        if manifest.get("pack_sha256") != canonical_sha256(unsigned):
            errors.append("manifest pack_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("manifest is not canonical JSON data")
    declared_files = manifest.get("files")
    if not isinstance(declared_files, Mapping) or set(declared_files) != set(PACK_FILES):
        errors.append("manifest files do not match the closed review-pack file set")
        declared_files = {}
    try:
        observed_names = {path.name for path in root.iterdir() if path.is_file()}
    except OSError as exc:
        errors.append(f"could not list pack directory: {exc}")
        observed_names = set()
    expected_names = {*PACK_FILES, "pack-manifest.json"}
    if observed_names != expected_names:
        missing = sorted(expected_names - observed_names)
        extra = sorted(observed_names - expected_names)
        if missing:
            errors.append("pack is missing files: " + ", ".join(missing))
        if extra:
            errors.append("pack contains undeclared files: " + ", ".join(extra))
    for name in PACK_FILES:
        path = root / name
        if not path.is_file():
            continue
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            errors.append(f"could not read {name}: {exc}")
        else:
            if declared_files.get(name) != actual:
                errors.append(f"file digest mismatch: {name}")
    try:
        report = _read_json(root / "assurance-report.json", 2_000_000)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        errors.append(f"could not read assurance-report.json: {exc}")
        return tuple(dict.fromkeys(errors))
    report_errors = verify_report(report, evidence_root)
    errors.extend(f"assurance report: {item}" for item in report_errors)
    if manifest.get("report_sha256") != report.get("report_sha256"):
        errors.append("manifest report_sha256 does not match assurance-report.json")
    if manifest.get("case_id") != report.get("case", {}).get("case_id"):
        errors.append("manifest case_id does not match assurance-report.json")
    if manifest.get("profile_id") != report.get("profile", {}).get("profile_id"):
        errors.append("manifest profile_id does not match assurance-report.json")
    if manifest.get("evaluation_time") != report.get("case", {}).get("evaluation_time"):
        errors.append("manifest evaluation_time does not match assurance-report.json")
    if manifest.get("assurance_status") != report.get("summary", {}).get("status"):
        errors.append("manifest assurance_status does not match assurance-report.json")
    if not report_errors:
        expected = _artifacts(report)
        for name, content in expected.items():
            path = root / name
            if path.is_file() and path.read_bytes() != content:
                errors.append(f"generated artifact does not recompute: {name}")
    return tuple(dict.fromkeys(errors))


def _artifacts(report: Mapping[str, Any]) -> dict[str, bytes]:
    return {
        "README.md": _readme().encode(),
        "assessment-plan-input.json": _json_bytes(_assessment_plan_input(report)),
        "assessment-results.json": _json_bytes(export_oscal(report)),
        "assurance-report.json": _json_bytes(report),
        "change-triggers.md": _change_triggers().encode(),
        "evidence-index.json": _json_bytes(_evidence_index(report)),
        "freshness-plan.json": _json_bytes(_freshness_plan(report)),
        "poam-input.json": _json_bytes(_poam_input(report)),
    }


def _assessment_plan_input(report: Mapping[str, Any]) -> dict[str, Any]:
    case = report["case"]
    return {
        "document_type": "owner-supplied-assessment-plan-input",
        "case_id": case["case_id"],
        "report_sha256": report["report_sha256"],
        "profile_id": report["profile"]["profile_id"],
        "evaluation_time": case["evaluation_time"],
        "system": case["system"],
        "decision_owner": case["decision_owner"],
        "objectives": [
            {
                "claim_id": item["claim_id"],
                "title": item["title"],
                "required_evidence_kind": item["required_evidence_kind"],
                "criticality": item["criticality"],
            }
            for item in report["claim_results"]
        ],
        "owner_actions_required": [
            "connect these inputs to an authorized assessment plan and actual system boundary",
            "select applicable controls and assessment procedures",
            "validate telemetry truth, evidence custody, privacy, and retention",
            "assign assessors, remediation owners, risk owners, and decision authority",
        ],
        "claim_boundary": CLAIM_BOUNDARY,
        "disclaimer": DISCLAIMER,
    }


def _evidence_index(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "document_type": "assurance-evidence-index",
        "report_sha256": report["report_sha256"],
        "payloads_embedded": False,
        "evidence": [
            {
                "evidence_id": item["evidence_id"],
                "evidence_kind": item["evidence_kind"],
                "path": item["path"],
                "owner": item["owner"],
                "observed_at": item["observed_at"],
                "max_age_seconds": item["max_age_seconds"],
                "age_seconds": item["age_seconds"],
                "verification_status": item["verification_status"],
                "expected_sha256": item["expected_sha256"],
                "actual_sha256": item["actual_sha256"],
            }
            for item in report["evidence_results"]
        ],
        "disclaimer": DISCLAIMER,
    }


def _freshness_plan(report: Mapping[str, Any]) -> dict[str, Any]:
    evaluation_time = report["case"]["evaluation_time"]
    return {
        "document_type": "owner-reviewable-evidence-freshness-plan",
        "evaluation_time": evaluation_time,
        "items": [
            {
                "evidence_id": item["evidence_id"],
                "owner": item["owner"],
                "observed_at": item["observed_at"],
                "max_age_seconds": item["max_age_seconds"],
                "expires_at": item["observed_at"] + item["max_age_seconds"],
                "status_at_evaluation": item["verification_status"],
            }
            for item in report["evidence_results"]
        ],
        "scheduling_actions_taken": 0,
        "disclaimer": DISCLAIMER,
    }


def _poam_input(report: Mapping[str, Any]) -> dict[str, Any]:
    items = []
    for claim in report["claim_results"]:
        if claim["status"] == "supported":
            continue
        items.append(
            {
                "claim_id": claim["claim_id"],
                "title": claim["title"],
                "local_status": claim["status"],
                "criticality": claim["criticality"],
                "violating_evidence_ids": claim["violating_evidence_ids"],
                "stale_evidence_ids": claim["stale_evidence_ids"],
                "unavailable_evidence_ids": claim["unavailable_evidence_ids"],
                "owner": "owner-assignment-required",
                "planned_completion": None,
                "risk_response": "owner-determination-required",
            }
        )
    return {
        "document_type": "owner-supplied-poam-input",
        "report_sha256": report["report_sha256"],
        "open_item_count": len(items),
        "items": items,
        "automatic_deadlines_invented": 0,
        "automatic_risk_decisions": 0,
        "disclaimer": DISCLAIMER,
    }


def _readme() -> str:
    return """# AssuranceGraph federal review inputs

This closed, content-addressed directory is designed for an accountable owner,
assessor, authorizing official, security engineer, and mission owner to review
together. Start with `assurance-report.json` and `evidence-index.json`; connect
`assessment-results.json` to an owner-approved OSCAL Assessment Plan; assign
owners and dates in `poam-input.json`; and review freshness and change triggers.

The pack intentionally embeds no source evidence payloads and takes no action.
It is not an assessment plan, system security plan, control determination,
compliance finding, legal opinion, procurement decision, risk acceptance,
authorization to operate, or government endorsement.
"""


def _change_triggers() -> str:
    return """# AssuranceGraph change triggers

Re-run native evidence, rebuild the case, and obtain accountable review when any
declared boundary element changes, including:

- model, weights, provider, serving configuration, or evaluator;
- prompt, policy, identity provider, delegated scope, approval rule, or trust root;
- framework, library, container, MCP server, tool, dataset, index, or infrastructure;
- network policy, credential boundary, workload isolation, monitor, alert, safe-stop, pause, or restart control;
- system mission, user population, data class, external effect, environment, owner, or evidence-retention rule;
- a ContainmentProof violation or monitor failure;
- an AgentBOM dependency-impact report requiring claim reevaluation; or
- an EvalIntegrityProof violation, monitor failure, or incomplete record; or
- stale, missing, contradictory, invalid, or superseded evidence.

No trigger in this file automatically stops, restarts, deploys, approves, rejects,
or accepts risk for a system. The accountable owner defines operational response.
"""


def _read_json(path: Path, maximum: int) -> dict[str, Any]:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds {maximum} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
