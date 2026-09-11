"""Privacy-minimized CycloneDX 1.7 ML-BOM disclosure mapping evidence."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.proof import (
    CLAIM_BOUNDARY as AGENTBOM_CLAIM_BOUNDARY,
)
from dspy_security_bench.supplychain.proof import (
    INVENTORY_TYPE,
    MAX_COMPONENTS,
    seal_inventory,
    validate_inventory,
)

REPORT_TYPE = "AgentBOM MLBOMDisclosure / Privacy-minimized disclosure gap mapping"
PROTOCOL_VERSION = "agentbom-mlbom-disclosure-v1"
ANALYZER = "deterministic-privacy-minimized-cyclonedx-mlbom-mapper-v1"
CYCLONEDX_VERSION = "1.7"
MAX_TEXT = 2_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MODEL_DISCLOSURE_FIELDS = (
    "modelParameters.approach.type",
    "modelParameters.task",
    "modelParameters.architectureFamily",
    "modelParameters.modelArchitecture",
    "modelParameters.datasets",
    "modelParameters.inputs",
    "modelParameters.outputs",
    "quantitativeAnalysis.performanceMetrics",
    "quantitativeAnalysis.graphics",
    "considerations.users",
    "considerations.useCases",
    "considerations.technicalLimitations",
    "considerations.performanceTradeoffs",
    "considerations.ethicalConsiderations",
    "considerations.environmentalConsiderations",
    "considerations.fairnessAssessments",
)
DATA_DISCLOSURE_FIELDS = (
    "contents",
    "classification",
    "sensitiveData",
    "graphics",
    "description",
    "governance",
)
CLAIM_BOUNDARY = (
    "MLBOMDisclosure deterministically maps machine-learning-model and data components from one "
    "caller-supplied CycloneDX 1.7 JSON BOM into an incomplete AgentBOM and records only whether "
    "selected standard model-card and dataset disclosure fields are populated. Raw component "
    "names, versions, suppliers, package locators, URLs, model-card values, dataset descriptions, "
    "sensitive-data labels, governance identities, metrics, fairness content, and environmental "
    "content are not retained. Presence is not correctness, adequacy, safety, fairness, privacy, "
    "quality, provenance, compliance, certification, approval, or authorization to operate."
)
LIMITATIONS = (
    "Only CycloneDX JSON with specVersion 1.7 and at least one machine-learning-model component is accepted.",
    "The mapper checks a bounded field-presence profile; it does not perform full CycloneDX schema validation.",
    "A populated field may be inaccurate, misleading, stale, or inadequate and requires accountable human review.",
    "Source and identity hashes minimize copied data but do not provide confidentiality; low-entropy values may be guessable.",
    "The caller-supplied BOM and any embedded signature are not authenticated or trusted by this mapper.",
    "Unresolved, external, malformed, and undeclared dependencies remain owner-review gaps and are never silently treated as satisfied.",
    "The output is incomplete, contains no assurance claim bindings, and performs no network access or automatic action.",
)
EXCLUDED_INPUT_FIELDS = (
    "raw component names, versions, group, suppliers, authors, manufacturers, and publishers",
    "package URLs, CPEs, SWIDs, external references, licenses, copyright, and pedigree",
    "model task, architecture, input/output, dataset, performance-metric, and graphic values",
    "intended-user, use-case, limitation, tradeoff, ethical, environmental, and fairness values",
    "dataset names, descriptions, URLs, attachments, classifications, sensitive-data labels, and governance identities",
    "BOM metadata, annotations, vulnerabilities, formulation, declarations, citations, properties, and signatures",
)


def build_mlbom_import_report(payload: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    """Map ML-BOM identities and disclosure presence without retaining raw values."""

    parsed = _parse_mlbom(payload)
    inventory, mapping, model_coverage, data_coverage = _build_inventory(
        parsed, inventory_id=inventory_id
    )
    present = sum(item["present_count"] for item in [*model_coverage, *data_coverage])
    expected = sum(item["expected_count"] for item in [*model_coverage, *data_coverage])
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "source_bom": {
            "bom_format": "CycloneDX",
            "spec_version": CYCLONEDX_VERSION,
            "canonical_bom_sha256": canonical_sha256(payload),
            "source_component_count": parsed["source_component_count"],
            "model_component_count": len(model_coverage),
            "data_component_count": len(data_coverage),
        },
        "inventory": inventory,
        "mapping": mapping,
        "model_disclosure_coverage": model_coverage,
        "data_disclosure_coverage": data_coverage,
        "excluded_input_fields": list(EXCLUDED_INPUT_FIELDS),
        "summary": {
            "model_components": len(model_coverage),
            "data_components": len(data_coverage),
            "disclosure_fields_expected": expected,
            "disclosure_fields_present": present,
            "disclosure_gaps": expected - present,
            "unresolved_dataset_references": parsed["unresolved_dataset_references"],
            "inventory_complete": False,
            "claim_binding_count": 0,
            "raw_disclosure_values_retained": False,
            "source_signature_verified": False,
            "network_requests": 0,
            "automatic_actions": 0,
            "review_status": "owner_review_required",
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "agentbom_claim_boundary": AGENTBOM_CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def import_mlbom(payload: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    """Return only the incomplete privacy-minimized AgentBOM starter."""

    return build_mlbom_import_report(payload, inventory_id=inventory_id)["inventory"]


def verify_mlbom_import_report(
    report: Mapping[str, Any], payload: Mapping[str, Any]
) -> tuple[str, ...]:
    """Recompute a saved report from its separately retained CycloneDX source."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AgentBOM MLBOMDisclosure report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    inventory = report.get("inventory")
    if isinstance(inventory, Mapping):
        errors.extend(validate_inventory(inventory))
    else:
        errors.append("inventory must be an object")
    try:
        expected = build_mlbom_import_report(payload, inventory_id=inventory["inventory_id"])
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"MLBOMDisclosure report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("MLBOMDisclosure report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _parse_mlbom(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("ML-BOM input must be a JSON object")
    if payload.get("bomFormat") != "CycloneDX" or payload.get("specVersion") != CYCLONEDX_VERSION:
        raise ValueError("ML-BOM input must be CycloneDX JSON with specVersion 1.7")
    top_components = payload.get("components", [])
    if not isinstance(top_components, list):
        raise ValueError("CycloneDX components must be an array")
    roots: list[object] = list(top_components)
    metadata = payload.get("metadata")
    if metadata is not None and not isinstance(metadata, Mapping):
        raise ValueError("CycloneDX metadata must be an object, null, or absent")
    if isinstance(metadata, Mapping) and metadata.get("component") is not None:
        roots.insert(0, metadata["component"])
    flattened = _flatten_components(roots)
    relevant: list[dict[str, Any]] = []
    by_ref: dict[str, dict[str, Any]] = {}
    for index, component in enumerate(flattened):
        if component.get("type") not in {"machine-learning-model", "data"}:
            continue
        reference = _bounded_text(component.get("bom-ref"), f"ML component {index} bom-ref")
        if reference in by_ref:
            raise ValueError(f"duplicate ML component bom-ref: {reference}")
        cloned = deepcopy(dict(component))
        relevant.append(cloned)
        by_ref[reference] = cloned
    models = [item for item in relevant if item["type"] == "machine-learning-model"]
    if not models:
        raise ValueError("CycloneDX 1.7 ML-BOM requires a machine-learning-model component")
    inline_datasets: list[dict[str, Any]] = []
    dataset_edges: list[tuple[str, str]] = []
    unresolved = 0
    for model in models:
        model_ref = str(model["bom-ref"])
        card = model.get("modelCard")
        if card is None:
            continue
        if not isinstance(card, Mapping):
            raise ValueError(f"modelCard for {model_ref} must be an object")
        parameters = card.get("modelParameters")
        if parameters is None:
            continue
        if not isinstance(parameters, Mapping):
            raise ValueError(f"modelParameters for {model_ref} must be an object")
        datasets = parameters.get("datasets", [])
        if not isinstance(datasets, list):
            raise ValueError(f"modelParameters.datasets for {model_ref} must be an array")
        for index, dataset in enumerate(datasets):
            if not isinstance(dataset, Mapping):
                raise ValueError(f"dataset {index} for {model_ref} must be an object")
            if isinstance(dataset.get("ref"), str) and dataset["ref"]:
                dataset_ref = dataset["ref"]
                target = by_ref.get(dataset_ref)
                if target is not None and target.get("type") == "data":
                    dataset_edges.append((model_ref, dataset_ref))
                else:
                    unresolved += 1
                continue
            if dataset.get("type") != "dataset":
                unresolved += 1
                continue
            identity = dataset.get("bom-ref")
            if not isinstance(identity, str) or not identity:
                identity = f"inline-sha256:{canonical_sha256(dataset)}"
            if len(identity) > MAX_TEXT:
                raise ValueError(f"inline dataset identity exceeds {MAX_TEXT} characters")
            if identity in by_ref:
                unresolved += 1
                continue
            cloned = deepcopy(dict(dataset))
            cloned["bom-ref"] = identity
            cloned["type"] = "data"
            by_ref[identity] = cloned
            inline_datasets.append(cloned)
            dataset_edges.append((model_ref, identity))
    relevant.extend(inline_datasets)
    if len(relevant) > MAX_COMPONENTS:
        raise ValueError(f"ML-BOM mapping exceeds the AgentBOM {MAX_COMPONENTS}-component limit")
    dependency_edges = _dependency_edges(payload.get("dependencies", []), by_ref)
    try:
        canonical_sha256(payload)
        for component in relevant:
            canonical_sha256(component)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"ML-BOM input is not canonical JSON data: {exc}") from exc
    return {
        "components": relevant,
        "dataset_edges": sorted(set(dataset_edges)),
        "dependency_edges": dependency_edges,
        "unresolved_dataset_references": unresolved,
        "source_component_count": len(flattened),
    }


def _build_inventory(
    parsed: Mapping[str, Any], *, inventory_id: str
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    used: set[str] = set()
    ref_to_component: dict[str, dict[str, Any]] = {}
    source_by_ref = {str(item["bom-ref"]): item for item in parsed["components"]}
    for reference in sorted(source_by_ref):
        source = source_by_ref[reference]
        identity_sha256 = _text_sha256(reference)
        component_type = "model" if source["type"] == "machine-learning-model" else "dataset"
        digest = _component_digest(source)
        ref_to_component[reference] = {
            "component_id": _unique_component_id(f"mlbom-{component_type}", identity_sha256, used),
            "component_type": component_type,
            "name": f"CycloneDX ML-BOM {component_type}",
            "version": f"content-sha256:{digest[:12]}",
            "supplier": "undeclared-supplier",
            "digest": digest,
            "locator": f"cyclonedx-bom-ref:sha256:{identity_sha256}",
            "criticality": "moderate",
            "external": True,
        }
    relationships: set[tuple[str, str, str]] = set()
    for source_ref, target_ref in parsed["dependency_edges"]:
        relationships.add(
            (
                ref_to_component[source_ref]["component_id"],
                ref_to_component[target_ref]["component_id"],
                "depends-on",
            )
        )
    for model_ref, dataset_ref in parsed["dataset_edges"]:
        relationships.add(
            (
                ref_to_component[model_ref]["component_id"],
                ref_to_component[dataset_ref]["component_id"],
                "sourced-from",
            )
        )
    relationship_items = [
        {"from_component_id": source, "to_component_id": target, "relationship": kind}
        for source, target, kind in sorted(relationships)
    ]
    inventory = seal_inventory(
        {
            "schema_version": 1,
            "inventory_type": INVENTORY_TYPE,
            "inventory_id": inventory_id,
            "title": "Privacy-minimized CycloneDX 1.7 ML-BOM component inventory",
            "owner": "replace-with-accountable-inventory-owner",
            "boundary": (
                "Incomplete local ML-BOM import. Raw component and disclosure values are not "
                "retained; source authentication, owner review, claim binding, and completeness "
                "decisions remain deployment responsibilities."
            ),
            "complete": False,
            "components": sorted(ref_to_component.values(), key=lambda item: item["component_id"]),
            "relationships": relationship_items,
            "required_claim_ids": [],
            "claim_bindings": [],
            "claim_boundary": AGENTBOM_CLAIM_BOUNDARY,
        }
    )
    if errors := validate_inventory(inventory):
        raise ValueError("mapped AgentBOM is invalid: " + "; ".join(errors))
    model_coverage = []
    data_coverage = []
    for reference in sorted(source_by_ref):
        source = source_by_ref[reference]
        component_id = ref_to_component[reference]["component_id"]
        if source["type"] == "machine-learning-model":
            model_coverage.append(
                _coverage_record(component_id, source.get("modelCard"), MODEL_DISCLOSURE_FIELDS)
            )
        else:
            data_value = source.get("data", source)
            if isinstance(data_value, list):
                data_value = _merge_data_entries(data_value)
            data_coverage.append(_coverage_record(component_id, data_value, DATA_DISCLOSURE_FIELDS))
    mapping = {
        "model_component_ids": [item["component_id"] for item in model_coverage],
        "data_component_ids": [item["component_id"] for item in data_coverage],
        "dependency_relationship_count": sum(
            item["relationship"] == "depends-on" for item in relationship_items
        ),
        "dataset_relationship_count": sum(
            item["relationship"] == "sourced-from" for item in relationship_items
        ),
    }
    return inventory, mapping, model_coverage, data_coverage


def _coverage_record(component_id: str, value: object, fields: Sequence[str]) -> dict[str, Any]:
    root = value if isinstance(value, Mapping) else {}
    present = [field for field in fields if _path_populated(root, field)]
    missing = [field for field in fields if field not in present]
    return {
        "component_id": component_id,
        "present_fields": present,
        "missing_fields": missing,
        "present_count": len(present),
        "expected_count": len(fields),
        "review_status": "owner_review_required",
    }


def _merge_data_entries(entries: list[object]) -> dict[str, Any]:
    """Merge only field presence across componentData entries, never their values."""

    merged: dict[str, bool] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        for field in DATA_DISCLOSURE_FIELDS:
            if _path_populated(entry, field):
                merged[field] = True
    return merged


def _path_populated(root: Mapping[str, Any], path: str) -> bool:
    value: object = root
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return False
        value = value[part]
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return bool(value)
    if isinstance(value, list):
        return bool(value)
    return value is not None


def _flatten_components(roots: list[object]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    pending = list(reversed(roots))
    while pending:
        source = pending.pop()
        if not isinstance(source, Mapping):
            raise ValueError("every CycloneDX component must be an object")
        flattened.append(dict(source))
        children = source.get("components", [])
        if children is None:
            children = []
        if not isinstance(children, list):
            raise ValueError("nested CycloneDX components must be an array")
        pending.extend(reversed(children))
        if len(flattened) + len(pending) > MAX_COMPONENTS * 4:
            raise ValueError("CycloneDX component tree exceeds the bounded import limit")
    return flattened


def _dependency_edges(
    dependencies: object, by_ref: Mapping[str, Mapping[str, Any]]
) -> list[tuple[str, str]]:
    if dependencies is None:
        return []
    if not isinstance(dependencies, list):
        raise ValueError("CycloneDX dependencies must be an array")
    edges: set[tuple[str, str]] = set()
    for item in dependencies:
        if not isinstance(item, Mapping):
            raise ValueError("every CycloneDX dependency must be an object")
        source = item.get("ref")
        targets = item.get("dependsOn", [])
        if not isinstance(targets, list):
            raise ValueError("CycloneDX dependsOn must be an array")
        if source not in by_ref:
            continue
        for target in targets:
            if target in by_ref:
                edges.add((str(source), str(target)))
    return sorted(edges)


def _component_digest(source: Mapping[str, Any]) -> str:
    declared_sha256 = None
    hashes = source.get("hashes", [])
    if isinstance(hashes, list):
        for item in hashes:
            if not isinstance(item, Mapping):
                continue
            algorithm = str(item.get("alg", "")).upper().replace("-", "")
            content = str(item.get("content", "")).lower()
            if algorithm == "SHA256" and _DIGEST.fullmatch(content):
                declared_sha256 = content
                break
    return canonical_sha256(
        {
            "declared_artifact_sha256": declared_sha256,
            "source_component": source,
        }
    )


def _bounded_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be a non-empty string of at most {MAX_TEXT} characters")
    return value


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unique_component_id(prefix: str, digest: str, used: set[str]) -> str:
    base = f"{prefix}-{digest[:12]}"
    candidate, suffix = base, 2
    while candidate in used:
        candidate = f"{base}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate
