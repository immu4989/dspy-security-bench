"""Privacy-preserving CycloneDX/SPDX AI disclosure crosswalk evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.supplychain.mlbom import (
    PROTOCOL_VERSION as MLBOM_PROTOCOL_VERSION,
)
from dspy_security_bench.supplychain.mlbom import verify_mlbom_import_report
from dspy_security_bench.supplychain.spdxai import (
    PROTOCOL_VERSION as SPDX_AI_PROTOCOL_VERSION,
)
from dspy_security_bench.supplychain.spdxai import verify_spdx_ai_import_report

REPORT_TYPE = "AgentBOM AIBOMCrosswalk / Cross-standard disclosure review"
PROTOCOL_VERSION = "agentbom-ai-crosswalk-v1"
PAIR_POLICY_VERSION = "agentbom-ai-crosswalk-pairs-v1"
ANALYZER = "deterministic-privacy-preserving-ai-bom-crosswalk-v1"
MAX_PAIRS = 500
_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MODEL_TOPICS = (
    (
        "purpose-and-domain",
        ("modelParameters.task", "considerations.users", "considerations.useCases"),
        ("ai_domain", "ai_informationAboutApplication"),
    ),
    (
        "training-context",
        ("modelParameters.approach.type", "modelParameters.datasets"),
        ("ai_informationAboutTraining", "ai_hyperparameter", "ai_modelDataPreprocessing"),
    ),
    (
        "architecture",
        ("modelParameters.architectureFamily", "modelParameters.modelArchitecture"),
        ("ai_typeOfModel",),
    ),
    (
        "performance",
        ("quantitativeAnalysis.performanceMetrics", "quantitativeAnalysis.graphics"),
        ("ai_metric", "ai_metricDecisionThreshold"),
    ),
    (
        "limitations",
        ("considerations.technicalLimitations", "considerations.performanceTradeoffs"),
        ("ai_limitation",),
    ),
    (
        "responsible-use",
        ("considerations.ethicalConsiderations", "considerations.fairnessAssessments"),
        ("ai_safetyRiskAssessment", "ai_useSensitivePersonalInformation"),
    ),
    (
        "environmental-impact",
        ("considerations.environmentalConsiderations",),
        ("ai_energyConsumption",),
    ),
    (
        "model-interfaces",
        ("modelParameters.inputs", "modelParameters.outputs"),
        (),
    ),
    ("explainability", (), ("ai_modelExplainability",)),
    ("standard-claims", (), ("ai_standardCompliance",)),
)
DATASET_TOPICS = (
    ("availability", ("contents",), ("dataset_datasetAvailability",)),
    (
        "classification-and-sensitivity",
        ("classification", "sensitiveData"),
        ("dataset_confidentialityLevel", "dataset_hasSensitivePersonalInformation"),
    ),
    (
        "preparation-and-provenance",
        ("description",),
        (
            "dataset_dataCollectionProcess",
            "dataset_dataPreprocessing",
            "dataset_anonymizationMethodUsed",
        ),
    ),
    (
        "dataset-technical-characteristics",
        ("graphics",),
        (
            "dataset_datasetSize",
            "dataset_datasetType",
            "dataset_datasetNoise",
            "dataset_sensor",
            "dataset_datasetUpdateMechanism",
        ),
    ),
    ("governance", ("governance",), ()),
    ("intended-use-and-bias", (), ("dataset_intendedUse", "dataset_knownBias")),
)
CLAIM_BOUNDARY = (
    "AIBOMCrosswalk compares only disclosure-field presence for owner-paired components in "
    "independently recomputable CycloneDX 1.7 ML-BOM and SPDX 3.0.1 AI/Dataset import reports. "
    "It exposes presence asymmetries, shared absence, and topics without a field mapping in one "
    "standard. It never compares raw values or establishes identity, semantic equivalence, "
    "correctness, adequacy, conformance, safety, fairness, privacy, legal compliance, supplier "
    "quality, certification, deployment approval, or authorization to operate."
)
LIMITATIONS = (
    "Component pairs are owner assertions and are not discovered or authenticated by the tool.",
    "Review topics group related disclosure fields for routing only; fields across standards are not declared semantically equivalent.",
    "Only field presence is compared; raw values remain in separately retained source documents and may materially disagree.",
    "Both source import reports are exactly recomputed before crosswalk generation, but their caller-supplied documents remain unauthenticated.",
    "Missing fields and asymmetries request review; they do not prove a defect, risk, noncompliance, or inferior standard.",
    "No network access, ranking, recommendation, procurement action, deployment action, or automatic decision is performed.",
)


def build_ai_bom_crosswalk(
    cyclonedx_report: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_report: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
    pair_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a source-verified, values-hidden cross-standard review matrix."""

    if errors := verify_mlbom_import_report(cyclonedx_report, cyclonedx_source):
        raise ValueError("invalid CycloneDX ML-BOM import report: " + "; ".join(errors))
    if errors := verify_spdx_ai_import_report(spdx_report, spdx_source):
        raise ValueError("invalid SPDX AI import report: " + "; ".join(errors))
    pairs = _parse_pair_policy(pair_policy)
    cdx_models = _coverage_index(cyclonedx_report["model_disclosure_coverage"])
    cdx_datasets = _coverage_index(cyclonedx_report["data_disclosure_coverage"])
    spdx_models = _coverage_index(spdx_report["ai_disclosure_coverage"])
    spdx_datasets = _coverage_index(spdx_report["dataset_disclosure_coverage"])
    results = []
    states: list[str] = []
    for pair in pairs:
        component_type = pair["component_type"]
        cdx_index = cdx_models if component_type == "model" else cdx_datasets
        spdx_index = spdx_models if component_type == "model" else spdx_datasets
        cdx_id = pair["cyclonedx_component_id"]
        spdx_id = pair["spdx_component_id"]
        if cdx_id not in cdx_index:
            raise ValueError(f"pair {pair['pair_id']} references unknown CycloneDX component")
        if spdx_id not in spdx_index:
            raise ValueError(f"pair {pair['pair_id']} references unknown SPDX component")
        topic_definitions = MODEL_TOPICS if component_type == "model" else DATASET_TOPICS
        topics = []
        for topic_id, cdx_fields, spdx_fields in topic_definitions:
            cdx_present = [field for field in cdx_fields if field in cdx_index[cdx_id]]
            spdx_present = [field for field in spdx_fields if field in spdx_index[spdx_id]]
            state = _topic_state(cdx_fields, spdx_fields, cdx_present, spdx_present)
            states.append(state)
            topics.append(
                {
                    "topic_id": topic_id,
                    "cyclonedx_fields_present": cdx_present,
                    "spdx_fields_present": spdx_present,
                    "state": state,
                    "owner_review_required": state != "both_present",
                }
            )
        results.append({**pair, "topics": topics})
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "source_reports": {
            "cyclonedx_protocol_version": MLBOM_PROTOCOL_VERSION,
            "cyclonedx_report_sha256": cyclonedx_report["report_sha256"],
            "cyclonedx_source_sha256": canonical_sha256(cyclonedx_source),
            "spdx_protocol_version": SPDX_AI_PROTOCOL_VERSION,
            "spdx_report_sha256": spdx_report["report_sha256"],
            "spdx_source_sha256": canonical_sha256(spdx_source),
        },
        "pair_policy": {
            "policy_version": PAIR_POLICY_VERSION,
            "canonical_policy_sha256": canonical_sha256(pair_policy),
            "pair_count": len(pairs),
        },
        "pair_results": results,
        "summary": {
            "pair_count": len(results),
            "topic_count": len(states),
            "both_present": states.count("both_present"),
            "both_missing": states.count("both_missing"),
            "presence_asymmetries": states.count("cyclonedx_only") + states.count("spdx_only"),
            "standard_shape_differences": states.count("cyclonedx_not_represented")
            + states.count("spdx_not_represented"),
            "raw_values_compared": False,
            "semantic_equivalence_established": False,
            "automatic_actions": 0,
            "review_status": "owner_review_required",
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_ai_bom_crosswalk(
    report: Mapping[str, Any],
    cyclonedx_report: Mapping[str, Any],
    cyclonedx_source: Mapping[str, Any],
    spdx_report: Mapping[str, Any],
    spdx_source: Mapping[str, Any],
    pair_policy: Mapping[str, Any],
) -> tuple[str, ...]:
    """Exactly recompute a crosswalk and both underlying import reports."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AgentBOM AIBOMCrosswalk report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
        expected = build_ai_bom_crosswalk(
            cyclonedx_report,
            cyclonedx_source,
            spdx_report,
            spdx_source,
            pair_policy,
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"AIBOMCrosswalk report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("AIBOMCrosswalk report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _parse_pair_policy(policy: Mapping[str, Any]) -> list[dict[str, str]]:
    if not isinstance(policy, Mapping) or set(policy) != {"policy_version", "pairs"}:
        raise ValueError("pair policy must contain only policy_version and pairs")
    if policy.get("policy_version") != PAIR_POLICY_VERSION:
        raise ValueError(f"pair policy must use {PAIR_POLICY_VERSION}")
    pairs = policy.get("pairs")
    if not isinstance(pairs, list) or not pairs or len(pairs) > MAX_PAIRS:
        raise ValueError(f"pair policy requires 1 to {MAX_PAIRS} pairs")
    parsed: list[dict[str, str]] = []
    pair_ids: set[str] = set()
    cdx_ids: set[str] = set()
    spdx_ids: set[str] = set()
    for index, value in enumerate(pairs):
        if not isinstance(value, Mapping) or set(value) != {
            "pair_id",
            "component_type",
            "cyclonedx_component_id",
            "spdx_component_id",
        }:
            raise ValueError(f"pair {index} has unsupported fields")
        pair = {key: str(value[key]) for key in value}
        if not _ID.fullmatch(pair["pair_id"]):
            raise ValueError(f"pair {index} has invalid pair_id")
        if pair["component_type"] not in {"model", "dataset"}:
            raise ValueError(f"pair {pair['pair_id']} has invalid component_type")
        for field in ("cyclonedx_component_id", "spdx_component_id"):
            if not _ID.fullmatch(pair[field]):
                raise ValueError(f"pair {pair['pair_id']} has invalid {field}")
        if pair["pair_id"] in pair_ids:
            raise ValueError("pair policy contains a duplicate pair_id")
        if pair["cyclonedx_component_id"] in cdx_ids:
            raise ValueError("pair policy reuses a CycloneDX component")
        if pair["spdx_component_id"] in spdx_ids:
            raise ValueError("pair policy reuses an SPDX component")
        pair_ids.add(pair["pair_id"])
        cdx_ids.add(pair["cyclonedx_component_id"])
        spdx_ids.add(pair["spdx_component_id"])
        parsed.append(pair)
    return sorted(parsed, key=lambda item: item["pair_id"])


def _coverage_index(records: Sequence[Mapping[str, Any]]) -> dict[str, set[str]]:
    return {str(item["component_id"]): set(item["present_fields"]) for item in records}


def _topic_state(
    cdx_fields: Sequence[str],
    spdx_fields: Sequence[str],
    cdx_present: Sequence[str],
    spdx_present: Sequence[str],
) -> str:
    if not cdx_fields:
        return "cyclonedx_not_represented"
    if not spdx_fields:
        return "spdx_not_represented"
    if cdx_present and spdx_present:
        return "both_present"
    if cdx_present:
        return "cyclonedx_only"
    if spdx_present:
        return "spdx_only"
    return "both_missing"
