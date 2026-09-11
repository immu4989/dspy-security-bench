"""Privacy-minimized SPDX 3.0.1 AI/Dataset disclosure mapping evidence."""

from __future__ import annotations

import hashlib
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

REPORT_TYPE = "AgentBOM SPDXAIDisclosure / Privacy-minimized AI profile mapping"
PROTOCOL_VERSION = "agentbom-spdx-ai-disclosure-v1"
ANALYZER = "deterministic-privacy-minimized-spdx-3-ai-mapper-v1"
SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
MAX_ELEMENTS = 2_000
MAX_TEXT = 2_000
AI_TYPE = "ai_AIPackage"
DATASET_TYPE = "dataset_DatasetPackage"
AI_DISCLOSURE_FIELDS = (
    "ai_autonomyType",
    "ai_domain",
    "ai_energyConsumption",
    "ai_hyperparameter",
    "ai_informationAboutApplication",
    "ai_informationAboutTraining",
    "ai_limitation",
    "ai_metric",
    "ai_metricDecisionThreshold",
    "ai_modelDataPreprocessing",
    "ai_modelExplainability",
    "ai_safetyRiskAssessment",
    "ai_standardCompliance",
    "ai_typeOfModel",
    "ai_useSensitivePersonalInformation",
)
DATASET_DISCLOSURE_FIELDS = (
    "dataset_anonymizationMethodUsed",
    "dataset_confidentialityLevel",
    "dataset_dataCollectionProcess",
    "dataset_dataPreprocessing",
    "dataset_datasetAvailability",
    "dataset_datasetNoise",
    "dataset_datasetSize",
    "dataset_datasetType",
    "dataset_datasetUpdateMechanism",
    "dataset_hasSensitivePersonalInformation",
    "dataset_intendedUse",
    "dataset_knownBias",
    "dataset_sensor",
)
LICENSE_TYPES = {
    "simplelicensing_AnyLicenseInfo",
    "simplelicensing_LicenseExpression",
    "expandedlicensing_CustomLicense",
    "expandedlicensing_IndividualLicensingInfo",
    "expandedlicensing_ListedLicense",
}
CLAIM_BOUNDARY = (
    "SPDXAIDisclosure maps SPDX 3.0.1 JSON-LD AIPackage and DatasetPackage elements plus "
    "resolved dependsOn, trainedOn, and testedOn relationships into an incomplete AgentBOM. "
    "It records only disclosure-field presence and whether each AI/dataset package has exactly "
    "one resolved hasDeclaredLicense and hasConcludedLicense relationship. Raw names, locations, "
    "suppliers, AI metadata, dataset metadata, license expressions, relationship identifiers, and "
    "free-form values are not retained. The result is not full JSON-LD, JSON Schema, OWL, SHACL, "
    "or SPDX profile validation and establishes no truth, adequacy, safety, compliance, approval, "
    "certification, or authorization to operate."
)
LIMITATIONS = (
    "Only the SPDX 3.0.1 global JSON-LD context and compact ai_AIPackage/dataset_DatasetPackage type names are accepted.",
    "The bounded mapper is not a JSON-LD processor and does not perform SPDX JSON Schema, OWL, or SHACL validation.",
    "Disclosure presence does not establish that a value is accurate, current, sufficient, safe, fair, or privacy preserving.",
    "License-rule checks count only relationships resolved to recognized license element types; they are not legal advice or license analysis.",
    "Source and identity hashes minimize copied data but do not provide confidentiality; low-entropy values may be guessable.",
    "Unresolved relationships remain visible review gaps and are never treated as satisfied.",
    "The caller-supplied document is unauthenticated, the AgentBOM remains incomplete, and no network or automatic action is performed.",
)
EXCLUDED_INPUT_FIELDS = (
    "raw SPDX IDs, names, versions, suppliers, creators, origins, download locations, package URLs, and home pages",
    "AI application, training, limitation, preprocessing, explainability, model-type, domain, hyperparameter, metric, threshold, risk, and energy values",
    "dataset collection, preprocessing, availability, noise, size, type, update, intended-use, bias, sensor, anonymity, confidentiality, and sensitive-data values",
    "license expressions, custom license text, relationship SPDX IDs, comments, summaries, dates, lifecycle scope, and extensions",
    "creation information, agents, software packages, files, document metadata, external references, identifiers, and integrity methods",
)


def build_spdx_ai_import_report(payload: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    """Map SPDX AI/Dataset identity and disclosure presence without raw values."""

    parsed = _parse_spdx_ai(payload)
    inventory, mapping, ai_coverage, dataset_coverage, license_checks = _build_inventory(
        parsed, inventory_id=inventory_id
    )
    coverage = [*ai_coverage, *dataset_coverage]
    present = sum(item["present_count"] for item in coverage)
    expected = sum(item["expected_count"] for item in coverage)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "source_document": {
            "context": SPDX_CONTEXT,
            "canonical_document_sha256": canonical_sha256(payload),
            "graph_element_count": parsed["graph_element_count"],
            "ai_package_count": len(ai_coverage),
            "dataset_package_count": len(dataset_coverage),
        },
        "inventory": inventory,
        "mapping": mapping,
        "ai_disclosure_coverage": ai_coverage,
        "dataset_disclosure_coverage": dataset_coverage,
        "license_relationship_checks": license_checks,
        "excluded_input_fields": list(EXCLUDED_INPUT_FIELDS),
        "summary": {
            "ai_packages": len(ai_coverage),
            "dataset_packages": len(dataset_coverage),
            "disclosure_fields_expected": expected,
            "disclosure_fields_present": present,
            "disclosure_gaps": expected - present,
            "license_relationship_rule_failures": sum(
                item["status"] != "exactly_one_each" for item in license_checks
            ),
            "unresolved_ai_relationship_references": parsed["unresolved_references"],
            "inventory_complete": False,
            "claim_binding_count": 0,
            "raw_disclosure_values_retained": False,
            "full_spdx_validation_performed": False,
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


def import_spdx_ai(payload: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    """Return the incomplete privacy-minimized AgentBOM starter."""

    return build_spdx_ai_import_report(payload, inventory_id=inventory_id)["inventory"]


def verify_spdx_ai_import_report(
    report: Mapping[str, Any], payload: Mapping[str, Any]
) -> tuple[str, ...]:
    """Recompute an SPDX AI mapping from its separately retained source."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AgentBOM SPDXAIDisclosure report")
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
        expected = build_spdx_ai_import_report(payload, inventory_id=inventory["inventory_id"])
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"SPDXAIDisclosure report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("SPDXAIDisclosure report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _parse_spdx_ai(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("SPDX AI input must be a JSON object")
    if payload.get("@context") != SPDX_CONTEXT:
        raise ValueError("SPDX AI input must use the SPDX 3.0.1 global JSON-LD context")
    graph = payload.get("@graph")
    if not isinstance(graph, list) or not graph or len(graph) > MAX_ELEMENTS:
        raise ValueError(f"SPDX AI @graph must contain 1 to {MAX_ELEMENTS} elements")
    if not all(isinstance(item, Mapping) for item in graph):
        raise ValueError("every SPDX AI @graph element must be an object")
    all_by_id: dict[str, dict[str, Any]] = {}
    relevant: list[dict[str, Any]] = []
    relevant_by_id: dict[str, dict[str, Any]] = {}
    for index, element_value in enumerate(graph):
        element = deepcopy(dict(element_value))
        spdx_id = element.get("spdxId")
        if isinstance(spdx_id, str) and spdx_id:
            if len(spdx_id) > MAX_TEXT:
                raise ValueError(f"SPDX element {index} spdxId exceeds {MAX_TEXT} characters")
            if spdx_id in all_by_id:
                raise ValueError(f"duplicate SPDX spdxId: {spdx_id}")
            all_by_id[spdx_id] = element
        if element.get("type") not in {AI_TYPE, DATASET_TYPE}:
            continue
        reference = _bounded_text(spdx_id, f"SPDX AI element {index} spdxId")
        relevant.append(element)
        relevant_by_id[reference] = element
    if not any(item.get("type") == AI_TYPE for item in relevant):
        raise ValueError("SPDX 3.0.1 document requires an ai_AIPackage for AI mapping")
    if len(relevant) > MAX_COMPONENTS:
        raise ValueError(f"SPDX AI mapping exceeds the AgentBOM {MAX_COMPONENTS}-component limit")
    edges: set[tuple[str, str, str]] = set()
    license_counts = {
        reference: {"hasDeclaredLicense": 0, "hasConcludedLicense": 0}
        for reference in relevant_by_id
    }
    unresolved = 0
    for element in graph:
        if element.get("type") != "Relationship":
            continue
        relationship = element.get("relationshipType")
        source = element.get("from")
        targets = element.get("to")
        if isinstance(targets, str):
            targets = [targets]
        if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
            raise ValueError("SPDX Relationship.to must be a string or array of strings")
        if source in relevant_by_id and relationship in {
            "dependsOn",
            "trainedOn",
            "testedOn",
            "hasDataFile",
        }:
            for target in targets:
                if target in relevant_by_id:
                    edges.add((str(source), target, str(relationship)))
                else:
                    unresolved += 1
        if source in relevant_by_id and relationship in license_counts[str(source)]:
            if len(targets) == 1 and _is_license_target(targets[0], all_by_id):
                license_counts[str(source)][str(relationship)] += 1
    try:
        canonical_sha256(payload)
        for component in relevant:
            canonical_sha256(component)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"SPDX AI input is not canonical JSON data: {exc}") from exc
    return {
        "components": relevant,
        "edges": sorted(edges),
        "license_counts": license_counts,
        "unresolved_references": unresolved,
        "graph_element_count": len(graph),
    }


def _build_inventory(
    parsed: Mapping[str, Any], *, inventory_id: str
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    used: set[str] = set()
    source_by_id = {str(item["spdxId"]): item for item in parsed["components"]}
    mapped: dict[str, dict[str, Any]] = {}
    for spdx_id in sorted(source_by_id):
        source = source_by_id[spdx_id]
        identity_sha256 = _text_sha256(spdx_id)
        component_type = "model" if source["type"] == AI_TYPE else "dataset"
        digest = canonical_sha256(source)
        mapped[spdx_id] = {
            "component_id": _unique_component_id(f"spdx-{component_type}", identity_sha256, used),
            "component_type": component_type,
            "name": f"SPDX 3.0.1 {component_type} package",
            "version": f"content-sha256:{digest[:12]}",
            "supplier": "undeclared-supplier",
            "digest": digest,
            "locator": f"spdx-id:sha256:{identity_sha256}",
            "criticality": "moderate",
            "external": True,
        }
    relationships: set[tuple[str, str, str]] = set()
    relationship_counts = {"dependsOn": 0, "trainedOn": 0, "testedOn": 0, "hasDataFile": 0}
    for source, target, relation in parsed["edges"]:
        mapped_relation = "depends-on" if relation == "dependsOn" else "sourced-from"
        relationships.add(
            (mapped[source]["component_id"], mapped[target]["component_id"], mapped_relation)
        )
        relationship_counts[relation] += 1
    relationship_items = [
        {"from_component_id": source, "to_component_id": target, "relationship": relation}
        for source, target, relation in sorted(relationships)
    ]
    inventory = seal_inventory(
        {
            "schema_version": 1,
            "inventory_type": INVENTORY_TYPE,
            "inventory_id": inventory_id,
            "title": "Privacy-minimized SPDX 3.0.1 AI/Dataset component inventory",
            "owner": "replace-with-accountable-inventory-owner",
            "boundary": (
                "Incomplete local SPDX AI/Dataset import. Raw disclosure and license values are "
                "not retained; full SPDX validation, owner review, claim binding, and completeness "
                "decisions remain deployment responsibilities."
            ),
            "complete": False,
            "components": sorted(mapped.values(), key=lambda item: item["component_id"]),
            "relationships": relationship_items,
            "required_claim_ids": [],
            "claim_bindings": [],
            "claim_boundary": AGENTBOM_CLAIM_BOUNDARY,
        }
    )
    if errors := validate_inventory(inventory):
        raise ValueError("mapped AgentBOM is invalid: " + "; ".join(errors))
    ai_coverage: list[dict[str, Any]] = []
    dataset_coverage: list[dict[str, Any]] = []
    license_checks = []
    for spdx_id in sorted(source_by_id):
        source = source_by_id[spdx_id]
        component_id = mapped[spdx_id]["component_id"]
        if source["type"] == AI_TYPE:
            ai_coverage.append(_coverage_record(component_id, source, AI_DISCLOSURE_FIELDS))
        else:
            dataset_coverage.append(
                _coverage_record(component_id, source, DATASET_DISCLOSURE_FIELDS)
            )
        counts = parsed["license_counts"][spdx_id]
        license_checks.append(
            {
                "component_id": component_id,
                "declared_license_relationships": counts["hasDeclaredLicense"],
                "concluded_license_relationships": counts["hasConcludedLicense"],
                "status": (
                    "exactly_one_each"
                    if counts == {"hasDeclaredLicense": 1, "hasConcludedLicense": 1}
                    else "owner_review_required"
                ),
            }
        )
    mapping = {
        "ai_component_ids": [item["component_id"] for item in ai_coverage],
        "dataset_component_ids": [item["component_id"] for item in dataset_coverage],
        "depends_on_relationships": relationship_counts["dependsOn"],
        "trained_on_relationships": relationship_counts["trainedOn"],
        "tested_on_relationships": relationship_counts["testedOn"],
        "has_data_file_relationships": relationship_counts["hasDataFile"],
        "agentbom_relationship_count": len(relationship_items),
    }
    return inventory, mapping, ai_coverage, dataset_coverage, license_checks


def _coverage_record(
    component_id: str, source: Mapping[str, Any], fields: Sequence[str]
) -> dict[str, Any]:
    present = [field for field in fields if _populated(source.get(field))]
    missing = [field for field in fields if field not in present]
    return {
        "component_id": component_id,
        "present_fields": present,
        "missing_fields": missing,
        "present_count": len(present),
        "expected_count": len(fields),
        "review_status": "owner_review_required",
    }


def _populated(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, Mapping)):
        return bool(value)
    return value is not None


def _is_license_target(target: str, all_by_id: Mapping[str, Mapping[str, Any]]) -> bool:
    element = all_by_id.get(target)
    return element is not None and element.get("type") in LICENSE_TYPES


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
