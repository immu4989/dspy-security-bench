"""Content-addressed AcquisitionProof export and verifier."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.acquisition.profile import AcquisitionProfile, validate_acquisition_profile
from dspy_security_bench.continuous.proof import (
    SNAPSHOT_TYPE,
    build_evidence_snapshot,
    verify_continuous_proof,
)
from dspy_security_bench.mission.loader import canonical_sha256

PACK_TYPE = "dspy-security-bench-acquisitionproof-pack"
DISCLAIMER = (
    "AcquisitionProof is a vendor-neutral technical evaluation input. It does not select, "
    "rank, recommend, award, accept, or reject a vendor; set a procurement requirement; "
    "determine compliance; accept risk; or imply government endorsement."
)


def export_acquisition_pack(
    evidence: Mapping[str, Any],
    profile: AcquisitionProfile,
    out_dir: str | Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    if evidence.get("proof_type") == SNAPSHOT_TYPE:
        errors = verify_continuous_proof(evidence)
        if errors:
            raise ValueError("invalid ContinuousProof snapshot: " + "; ".join(errors))
        snapshot = dict(evidence)
    else:
        snapshot = build_evidence_snapshot(evidence, label=profile.raw["acquisition_id"])
    destination = Path(out_dir)
    if destination.exists() and any(destination.iterdir()) and not force:
        raise ValueError(f"output directory is not empty: {destination} (use --force)")
    destination.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, str] = {
        "source-evidence.json": json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        "acquisition-profile.json": json.dumps(profile.raw, indent=2, sort_keys=True) + "\n",
        "qasp-objectives.json": json.dumps(_objectives(profile, snapshot), indent=2, sort_keys=True)
        + "\n",
        "vendor-neutral-test-plan.md": _test_plan(profile, snapshot),
        "portability-checklist.md": _portability(profile),
        "cost-observation.json": json.dumps(_cost_template(profile), indent=2, sort_keys=True)
        + "\n",
        "reevaluation-plan.md": _reevaluation(profile),
    }
    for name, content in outputs.items():
        (destination / name).write_text(content)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "pack_type": PACK_TYPE,
        "acquisition_id": profile.raw["acquisition_id"],
        "profile_sha256": profile.profile_sha256,
        "evidence_sha256": snapshot["evidence_sha256"],
        "files": {name: _file_sha256(destination / name) for name in sorted(outputs)},
        "decision_authority": "accountable acquisition and mission owners",
        "disclaimer": DISCLAIMER,
    }
    manifest["pack_sha256"] = canonical_sha256(manifest)
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def verify_acquisition_pack(path: str | Path) -> tuple[str, ...]:
    root = Path(path)
    errors: list[str] = []
    try:
        manifest = json.loads((root / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return (f"cannot read manifest: {exc}",)
    if not isinstance(manifest, Mapping):
        return ("manifest must be an object",)
    expected_manifest_fields = {
        "schema_version",
        "pack_type",
        "acquisition_id",
        "profile_sha256",
        "evidence_sha256",
        "files",
        "decision_authority",
        "disclaimer",
        "pack_sha256",
    }
    if set(manifest) != expected_manifest_fields:
        errors.append("manifest fields are incomplete or unsupported")
    claimed = manifest.get("pack_sha256")
    unsigned = dict(manifest)
    unsigned.pop("pack_sha256", None)
    if claimed != _safe_hash(unsigned):
        errors.append("pack_sha256 does not match canonical manifest content")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("pack_type") != PACK_TYPE
        or manifest.get("disclaimer") != DISCLAIMER
        or manifest.get("decision_authority") != "accountable acquisition and mission owners"
    ):
        errors.append("manifest metadata does not match AcquisitionProof v1")
    files = manifest.get("files")
    if not isinstance(files, Mapping):
        errors.append("manifest.files must be an object")
    else:
        required = {
            "source-evidence.json",
            "acquisition-profile.json",
            "qasp-objectives.json",
            "vendor-neutral-test-plan.md",
            "portability-checklist.md",
            "cost-observation.json",
            "reevaluation-plan.md",
        }
        if set(files) != required:
            errors.append("manifest file inventory is incomplete or unsupported")
        for name, digest in files.items():
            if not isinstance(name, str) or Path(name).name != name:
                errors.append("manifest contains an unsafe file name")
                continue
            target = root / name
            if not target.is_file() or digest != _file_sha256(target):
                errors.append(f"file digest mismatch: {name}")
    profile: AcquisitionProfile | None = None
    try:
        profile_payload = json.loads((root / "acquisition-profile.json").read_text())
        profile = validate_acquisition_profile(profile_payload)
        if profile.profile_sha256 != manifest.get("profile_sha256"):
            errors.append("profile_sha256 does not match acquisition-profile.json")
        if profile.raw["acquisition_id"] != manifest.get("acquisition_id"):
            errors.append("acquisition_id does not match acquisition-profile.json")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"invalid acquisition profile: {exc}")
    snapshot: dict[str, Any] | None = None
    try:
        snapshot = json.loads((root / "source-evidence.json").read_text())
        snapshot_errors = verify_continuous_proof(snapshot)
        errors.extend(f"source evidence: {item}" for item in snapshot_errors)
        if snapshot.get("evidence_sha256") != manifest.get("evidence_sha256"):
            errors.append("evidence_sha256 does not match source-evidence.json")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        errors.append(f"invalid source evidence: {exc}")
    if profile is not None and snapshot is not None:
        expected_content = {
            "qasp-objectives.json": json.dumps(
                _objectives(profile, snapshot), indent=2, sort_keys=True
            )
            + "\n",
            "vendor-neutral-test-plan.md": _test_plan(profile, snapshot),
            "portability-checklist.md": _portability(profile),
            "cost-observation.json": json.dumps(_cost_template(profile), indent=2, sort_keys=True)
            + "\n",
            "reevaluation-plan.md": _reevaluation(profile),
        }
        for name, expected in expected_content.items():
            try:
                actual = (root / name).read_text()
            except OSError:
                continue
            if actual != expected:
                errors.append(f"generated artifact does not recompute: {name}")
    return tuple(dict.fromkeys(errors))


def _objectives(profile: AcquisitionProfile, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    metrics = snapshot.get("metrics", {})
    objectives = []
    for item in profile.raw["outcomes"]:
        observed = metrics.get(item["metric"])
        met = None
        if isinstance(observed, (int, float)):
            met = (
                observed >= item["target"]
                if item["direction"] == "at_least"
                else observed <= item["target"]
            )
        objectives.append(
            {
                **item,
                "observed": observed,
                "status": "not_observed" if met is None else ("met" if met else "not_met"),
            }
        )
    return {
        "schema_version": 1,
        "type": "owner-defined-qasp-objective-inputs",
        "objectives": objectives,
        "decision": "human acquisition authority required",
    }


def _test_plan(profile: AcquisitionProfile, snapshot: Mapping[str, Any]) -> str:
    mission = profile.raw["mission"]
    return f"""# Vendor-neutral mission test plan\n\n## Mission\n\n**{mission["name"]}** — {mission["description"]}\n\nAccountable owner: {mission["owner"]}\n\n## Comparable evidence\n\n- Evidence kind: `{snapshot["evidence_kind"]}`\n- Frozen evidence SHA-256: `{snapshot["evidence_sha256"]}`\n- Run every candidate against the same versioned protocol, policy, tools, data bounds, and owner-approved objectives.\n- Record quality, mission utility, unsafe effects, latency, cost, and required human review.\n- Report missing observations as missing; do not convert them to passing results.\n\n## Decision boundary\n\nThis plan supplies comparable technical evidence. Accountable officials retain source selection, tradeoff, legal, security, privacy, accessibility, records, and risk decisions.\n\n{DISCLAIMER}\n"""


def _portability(profile: AcquisitionProfile) -> str:
    items = profile.raw["portability"]
    lines = ["# Portability and lock-in checklist", ""]
    labels = {
        "data_export_required": "Documented export of customer data and evaluation evidence",
        "open_interface_required": "Documented interoperable or open interface",
        "transition_plan_required": "Tested transition and exit plan",
    }
    lines.extend(f"- [ ] {labels[key]}" for key, required in items.items() if required)
    lines.extend(
        [
            "",
            "Unmet items are observations for owner review, not automatic source-selection decisions.",
            "",
        ]
    )
    return "\n".join(lines)


def _cost_template(profile: AcquisitionProfile) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "observation_unit": profile.raw["pricing"]["observation_unit"],
        "currency": "owner_must_define",
        "observations": {field: None for field in profile.raw["pricing"]["required_fields"]},
        "assumptions": [],
        "status": "unpopulated_owner_input",
    }


def _reevaluation(profile: AcquisitionProfile) -> str:
    lines = ["# Reevaluation plan", "", "Re-run the frozen evaluation when any trigger occurs:", ""]
    lines.extend(f"- {trigger}" for trigger in profile.raw["reevaluation_triggers"])
    lines.extend(
        ["", "The accountable owner sets cadence, thresholds, response, and risk disposition.", ""]
    )
    return "\n".join(lines)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_hash(payload: Any) -> str | None:
    try:
        return canonical_sha256(payload)
    except (TypeError, ValueError):
        return None
