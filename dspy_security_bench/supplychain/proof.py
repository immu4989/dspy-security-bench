"""AgentBOM inventory and dependency-to-assurance claim impact analysis."""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Mapping
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256

INVENTORY_TYPE = "dspy-security-bench-agentbom-inventory"
REPORT_TYPE = "AgentBOM / Dependency-to-assurance claim impact"
PROTOCOL_VERSION = "agentbom-claimimpact-v1"
ANALYZER = "deterministic-transitive-claim-impact-v1"
MAX_INVENTORY_BYTES = 10_000_000
MAX_COMPONENTS = 500
MAX_RELATIONSHIPS = 2_000
MAX_BINDINGS = 1_000
CLAIM_BOUNDARY = (
    "AgentBOM and ClaimImpact compare owner-supplied, content-addressed component inventories "
    "and compute which bound assurance claims may require reevaluation. The graph does not "
    "discover undeclared components, fetch vulnerabilities, establish supplier truth, predict "
    "exploitability or loss, approve a vendor, invalidate a deployment automatically, determine "
    "compliance, authorize operation, or accept risk. Accountable owners retain inventory, "
    "reevaluation, procurement, remediation, deployment, and risk decisions."
)
LIMITATIONS = (
    "Only declared components, relationships, and claim bindings are analyzed.",
    "A digest establishes canonical content identity, not supplier authenticity or runtime presence.",
    "Transitive impact means reevaluation may be required; it does not mean a vulnerability exists.",
    "Imported SPDX, CycloneDX, SLSA, and ML-BOM documents require owner enrichment and claim bindings.",
    "No network lookup, vulnerability scan, probability, financial loss, or vendor score is produced.",
)
COMPONENT_TYPES = (
    "model",
    "runtime",
    "framework",
    "library",
    "tool",
    "mcp-server",
    "policy",
    "dataset",
    "retrieval-index",
    "identity-provider",
    "trust-root",
    "container",
    "evaluator",
    "monitor",
    "infrastructure",
    "dependency",
)
RELATION_TYPES = (
    "depends-on",
    "uses",
    "authorized-by",
    "evaluated-by",
    "runs-on",
    "sourced-from",
    "monitored-by",
)
CRITICALITIES = ("critical", "high", "moderate", "low")
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_INVENTORY_FIELDS = {
    "schema_version",
    "inventory_type",
    "inventory_id",
    "title",
    "owner",
    "boundary",
    "complete",
    "components",
    "relationships",
    "required_claim_ids",
    "claim_bindings",
    "claim_boundary",
    "inventory_sha256",
}
_COMPONENT_FIELDS = {
    "component_id",
    "component_type",
    "name",
    "version",
    "supplier",
    "digest",
    "locator",
    "criticality",
    "external",
}
_RELATION_FIELDS = {"from_component_id", "to_component_id", "relationship"}
_BINDING_FIELDS = {"claim_id", "evidence_id", "component_ids"}


def protocol_payload() -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "component_types": list(COMPONENT_TYPES),
        "relationship_types": list(RELATION_TYPES),
        "change_classes": ["added", "removed", "content-changed", "relationship-changed"],
        "impact_algorithm": "changed components plus reverse transitive dependency closure",
        "outcomes": ["no_material_change", "reevaluation_required"],
        "import_formats": [
            "CycloneDX JSON",
            "SPDX JSON",
            "SLSA Provenance v1 (privacy-minimized unsigned mapping)",
            "CycloneDX 1.7 ML-BOM (privacy-minimized disclosure mapping)",
        ],
        "network_access": False,
        "automatic_actions": 0,
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }


def protocol_sha256() -> str:
    return canonical_sha256(protocol_payload())


def seal_inventory(payload: Mapping[str, Any]) -> dict[str, Any]:
    inventory = _json_clone(payload)
    inventory.pop("inventory_sha256", None)
    inventory["inventory_sha256"] = canonical_sha256(inventory)
    return inventory


def built_in_inventory(revision: str = "baseline") -> dict[str, Any]:
    if revision not in {"baseline", "candidate", "equivalent"}:
        raise ValueError(f"unknown AgentBOM revision {revision!r}")

    def component(
        component_id: str,
        component_type: str,
        version: str,
        criticality: str,
        external: bool,
    ) -> dict[str, Any]:
        identity = {
            "component_id": component_id,
            "component_type": component_type,
            "version": version,
        }
        return {
            "component_id": component_id,
            "component_type": component_type,
            "name": component_id.replace("-", " ").title(),
            "version": version,
            "supplier": "fictional-reference-supplier" if external else "fictional-system-owner",
            "digest": canonical_sha256(identity),
            "locator": f"pkg:generic/{component_id}@{version}",
            "criticality": criticality,
            "external": external,
        }

    mcp_version = "2.0.0" if revision == "candidate" else "1.0.0"
    components = [
        component("mission-agent", "runtime", "1.0.0", "critical", False),
        component("frontier-model", "model", "model-revision-a", "critical", True),
        component("agent-framework", "framework", "3.3.0", "high", True),
        component("payments-mcp", "mcp-server", mcp_version, "critical", True),
        component("authorization-policy", "policy", "policy-a", "critical", False),
        component("identity-provider", "identity-provider", "2026.08", "critical", True),
        component("retrieval-index", "retrieval-index", "index-a", "high", False),
        component("evaluation-harness", "evaluator", "1.0.0", "high", False),
        component("containment-monitor", "monitor", "1.0.0", "critical", False),
        component("agent-container", "container", "sha256-a", "critical", False),
    ]
    relationships = [
        {
            "from_component_id": "mission-agent",
            "to_component_id": "frontier-model",
            "relationship": "uses",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "agent-framework",
            "relationship": "depends-on",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "payments-mcp",
            "relationship": "uses",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "authorization-policy",
            "relationship": "authorized-by",
        },
        {
            "from_component_id": "authorization-policy",
            "to_component_id": "identity-provider",
            "relationship": "authorized-by",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "retrieval-index",
            "relationship": "sourced-from",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "evaluation-harness",
            "relationship": "evaluated-by",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "containment-monitor",
            "relationship": "monitored-by",
        },
        {
            "from_component_id": "mission-agent",
            "to_component_id": "agent-container",
            "relationship": "runs-on",
        },
    ]
    bindings = [
        {
            "claim_id": "bounded-authority",
            "evidence_id": "authority-evidence",
            "component_ids": [
                "mission-agent",
                "authorization-policy",
                "identity-provider",
                "payments-mcp",
            ],
        },
        {
            "claim_id": "observable-effects",
            "evidence_id": "trace-evidence",
            "component_ids": ["mission-agent", "containment-monitor", "payments-mcp"],
        },
        {
            "claim_id": "collective-containment",
            "evidence_id": "collective-v2-evidence",
            "component_ids": ["mission-agent", "agent-framework", "containment-monitor"],
        },
        {
            "claim_id": "bounded-schedule-safety",
            "evidence_id": "schedule-evidence",
            "component_ids": ["authorization-policy", "identity-provider", "payments-mcp"],
        },
        {
            "claim_id": "verified-remediation",
            "evidence_id": "verified-defense-evidence",
            "component_ids": ["evaluation-harness", "agent-container"],
        },
        {
            "claim_id": "runtime-containment",
            "evidence_id": "containment-evidence",
            "component_ids": [
                "mission-agent",
                "containment-monitor",
                "agent-container",
                "payments-mcp",
            ],
        },
        {
            "claim_id": "evaluation-process-integrity",
            "evidence_id": "evaluation-integrity-evidence",
            "component_ids": [
                "evaluation-harness",
                "containment-monitor",
                "agent-container",
            ],
        },
        {
            "claim_id": "resilience-decision-space",
            "evidence_id": "defense-portfolio-evidence",
            "component_ids": ["evaluation-harness", "agent-container"],
        },
    ]
    return seal_inventory(
        {
            "schema_version": 1,
            "inventory_type": INVENTORY_TYPE,
            "inventory_id": "fictional-mission-agent",
            "title": "Fictional mission agent dependency boundary",
            "owner": "fictional accountable system owner",
            "boundary": "Synthetic reference system with no production component assertion.",
            "complete": True,
            "components": components,
            "relationships": relationships,
            "required_claim_ids": [
                "bounded-authority",
                "observable-effects",
                "collective-containment",
                "bounded-schedule-safety",
                "verified-remediation",
                "runtime-containment",
                "evaluation-process-integrity",
                "resilience-decision-space",
            ],
            "claim_bindings": bindings,
            "claim_boundary": CLAIM_BOUNDARY,
        }
    )


def validate_inventory(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ("inventory must be an object",)
    _exact(payload, _INVENTORY_FIELDS, "inventory", errors)
    if payload.get("schema_version") != 1 or payload.get("inventory_type") != INVENTORY_TYPE:
        errors.append("inventory metadata does not match AgentBOM v1")
    _identifier(payload.get("inventory_id"), "inventory_id", errors)
    for field, maximum in (("title", 300), ("owner", 300), ("boundary", 1_500)):
        _text(payload.get(field), field, maximum, errors)
    if not isinstance(payload.get("complete"), bool):
        errors.append("complete must be boolean")
    components = payload.get("components")
    component_ids: set[str] = set()
    if not isinstance(components, list) or not 1 <= len(components) <= MAX_COMPONENTS:
        errors.append(f"components must contain 1 to {MAX_COMPONENTS} objects")
        components = []
    for index, component in enumerate(components):
        label = f"components[{index}]"
        if not isinstance(component, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(component, _COMPONENT_FIELDS, label, errors)
        component_id = component.get("component_id")
        _identifier(component_id, f"{label}.component_id", errors)
        if isinstance(component_id, str):
            if component_id in component_ids:
                errors.append(f"duplicate component_id {component_id!r}")
            component_ids.add(component_id)
        if component.get("component_type") not in COMPONENT_TYPES:
            errors.append(f"{label}.component_type is unsupported")
        for field in ("name", "version", "supplier", "locator"):
            _text(component.get(field), f"{label}.{field}", 500, errors)
        digest = component.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            errors.append(f"{label}.digest must be a SHA-256 digest")
        if component.get("criticality") not in CRITICALITIES:
            errors.append(f"{label}.criticality is unsupported")
        if not isinstance(component.get("external"), bool):
            errors.append(f"{label}.external must be boolean")
    relationships = payload.get("relationships")
    relationship_keys: set[tuple[str, str, str]] = set()
    if not isinstance(relationships, list) or len(relationships) > MAX_RELATIONSHIPS:
        errors.append(f"relationships must contain at most {MAX_RELATIONSHIPS} objects")
        relationships = []
    for index, relationship in enumerate(relationships):
        label = f"relationships[{index}]"
        if not isinstance(relationship, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(relationship, _RELATION_FIELDS, label, errors)
        source = relationship.get("from_component_id")
        target = relationship.get("to_component_id")
        if source not in component_ids or target not in component_ids:
            errors.append(f"{label} references an unknown component")
        if source == target:
            errors.append(f"{label} cannot be a self relationship")
        relation = relationship.get("relationship")
        if relation not in RELATION_TYPES:
            errors.append(f"{label}.relationship is unsupported")
        if all(isinstance(item, str) for item in (source, target, relation)):
            key = (source, target, relation)
            if key in relationship_keys:
                errors.append(f"duplicate relationship at {label}")
            relationship_keys.add(key)
    required_claim_ids = payload.get("required_claim_ids")
    if (
        not isinstance(required_claim_ids, list)
        or len(required_claim_ids) > MAX_BINDINGS
        or not all(isinstance(item, str) and _ID.fullmatch(item) for item in required_claim_ids)
    ):
        errors.append("required_claim_ids must be a list of lowercase kebab-case identifiers")
        required_claim_ids = []
    elif len(required_claim_ids) != len(set(required_claim_ids)):
        errors.append("required_claim_ids must be unique")
    bindings = payload.get("claim_bindings")
    binding_keys: set[tuple[str, str]] = set()
    if not isinstance(bindings, list) or len(bindings) > MAX_BINDINGS:
        errors.append(f"claim_bindings must contain at most {MAX_BINDINGS} objects")
        bindings = []
    for index, binding in enumerate(bindings):
        label = f"claim_bindings[{index}]"
        if not isinstance(binding, Mapping):
            errors.append(f"{label} must be an object")
            continue
        _exact(binding, _BINDING_FIELDS, label, errors)
        _identifier(binding.get("claim_id"), f"{label}.claim_id", errors)
        _identifier(binding.get("evidence_id"), f"{label}.evidence_id", errors)
        refs = binding.get("component_ids")
        if (
            not isinstance(refs, list)
            or not refs
            or not all(isinstance(item, str) for item in refs)
        ):
            errors.append(f"{label}.component_ids must be a non-empty string list")
        else:
            if len(refs) != len(set(refs)):
                errors.append(f"{label}.component_ids must be unique")
            if unknown := sorted(set(refs) - component_ids):
                errors.append(f"{label} references unknown components: {', '.join(unknown)}")
        claim_id, evidence_id = binding.get("claim_id"), binding.get("evidence_id")
        if isinstance(claim_id, str) and isinstance(evidence_id, str):
            key = (claim_id, evidence_id)
            if key in binding_keys:
                errors.append(f"duplicate claim/evidence binding at {label}")
            binding_keys.add(key)
    if payload.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("claim_boundary does not match AgentBOM v1")
    claimed = payload.get("inventory_sha256")
    unsigned = dict(payload)
    unsigned.pop("inventory_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("inventory_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("inventory is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def analyze_change(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    change_reason: str,
) -> dict[str, Any]:
    for label, inventory in (("baseline", baseline), ("candidate", candidate)):
        errors = validate_inventory(inventory)
        if errors:
            raise ValueError(f"invalid {label} AgentBOM: " + "; ".join(errors))
    if baseline["inventory_id"] != candidate["inventory_id"]:
        raise ValueError("baseline and candidate inventory_id must match")
    if (
        not isinstance(change_reason, str)
        or not change_reason.strip()
        or len(change_reason) > 1_000
    ):
        raise ValueError("change_reason must be a non-empty string of at most 1000 characters")
    before = {item["component_id"]: item for item in baseline["components"]}
    after = {item["component_id"]: item for item in candidate["components"]}
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(
        component_id
        for component_id in set(before) & set(after)
        if before[component_id] != after[component_id]
    )
    before_relations = {_relation_key(item) for item in baseline["relationships"]}
    after_relations = {_relation_key(item) for item in candidate["relationships"]}
    relationship_changes = sorted(before_relations ^ after_relations)
    seeds = set(added) | set(removed) | set(changed)
    for source, target, _relation in relationship_changes:
        seeds.update((source, target))
    affected = _reverse_dependency_closure(seeds, baseline, candidate)
    before_bindings = {_binding_key(item): item for item in baseline["claim_bindings"]}
    after_bindings = {_binding_key(item): item for item in candidate["claim_bindings"]}
    changed_bindings = sorted(
        key
        for key in set(before_bindings) | set(after_bindings)
        if before_bindings.get(key) != after_bindings.get(key)
    )
    impacted: dict[tuple[str, str], dict[str, Any]] = {}
    for binding in list(before_bindings.values()) + list(after_bindings.values()):
        key = _binding_key(binding)
        direct = sorted(set(binding["component_ids"]) & affected)
        binding_changed = key in changed_bindings
        if direct or binding_changed:
            impacted[key] = {
                "claim_id": binding["claim_id"],
                "evidence_id": binding["evidence_id"],
                "affected_component_ids": direct,
                "binding_changed": binding_changed,
                "status": "reevaluation_required",
            }
    candidate_claims = {item["claim_id"] for item in candidate["claim_bindings"]}
    unbound_claims = sorted(set(candidate["required_claim_ids"]) - candidate_claims)
    material = bool(seeds or relationship_changes or changed_bindings)
    inventory_complete = bool(baseline["complete"] and candidate["complete"])
    status = (
        "no_material_change"
        if not material and inventory_complete and not unbound_claims
        else "reevaluation_required"
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": protocol_sha256(),
        "analyzer": ANALYZER,
        "baseline_inventory_sha256": baseline["inventory_sha256"],
        "candidate_inventory_sha256": candidate["inventory_sha256"],
        "baseline": _json_clone(baseline),
        "candidate": _json_clone(candidate),
        "change_reason": change_reason.strip(),
        "summary": {
            "status": status,
            "inventory_complete": inventory_complete,
            "component_count_before": len(before),
            "component_count_after": len(after),
            "added_components": len(added),
            "removed_components": len(removed),
            "changed_components": len(changed),
            "changed_relationships": len(relationship_changes),
            "affected_components": len(affected),
            "impacted_claims": len({item["claim_id"] for item in impacted.values()}),
            "unbound_claims": len(unbound_claims),
            "automatic_deployment_actions": 0,
            "automatic_procurement_actions": 0,
        },
        "changes": {
            "added_component_ids": added,
            "removed_component_ids": removed,
            "content_changed_component_ids": changed,
            "relationship_changes": [
                {"from_component_id": item[0], "to_component_id": item[1], "relationship": item[2]}
                for item in relationship_changes
            ],
            "changed_claim_bindings": [
                {"claim_id": item[0], "evidence_id": item[1]} for item in changed_bindings
            ],
        },
        "affected_component_ids": sorted(affected),
        "claim_impacts": [impacted[key] for key in sorted(impacted)],
        "unbound_claim_ids": unbound_claims,
        "minimal_reevaluation_plan": [
            {
                "claim_id": item["claim_id"],
                "evidence_id": item["evidence_id"],
                "reason": "bound component or relationship changed",
            }
            for item in sorted(
                impacted.values(), key=lambda value: (value["claim_id"], value["evidence_id"])
            )
        ],
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_report(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return ("report must be an object",)
    if payload.get("report_type") != REPORT_TYPE:
        errors.append("unsupported AgentBOM report type")
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("unsupported AgentBOM protocol version")
    if payload.get("protocol_sha256") != protocol_sha256():
        errors.append("protocol_sha256 does not match AgentBOM v1")
    claimed = payload.get("report_sha256")
    unsigned = dict(payload)
    unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    baseline, candidate = payload.get("baseline"), payload.get("candidate")
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        errors.append("report baseline and candidate must be objects")
        return tuple(dict.fromkeys(errors))
    try:
        expected = analyze_change(baseline, candidate, change_reason=payload.get("change_reason"))
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if payload != expected:
            errors.append("AgentBOM report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def import_cyclonedx(payload: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    if payload.get("bomFormat") != "CycloneDX" or not isinstance(payload.get("components"), list):
        raise ValueError("input is not a supported CycloneDX JSON BOM")
    components, ref_to_id, used = [], {}, set()
    for index, source in enumerate(payload["components"]):
        if not isinstance(source, Mapping):
            raise ValueError(f"CycloneDX component {index} must be an object")
        reference = str(source.get("bom-ref") or f"component-{index + 1}")
        component_id = _unique_slug(reference, used)
        ref_to_id[reference] = component_id
        hashes = source.get("hashes") if isinstance(source.get("hashes"), list) else []
        digest = next(
            (
                str(item.get("content", "")).lower()
                for item in hashes
                if isinstance(item, Mapping)
                and str(item.get("alg", "")).upper().replace("-", "") == "SHA256"
                and _DIGEST.fullmatch(str(item.get("content", "")).lower())
            ),
            canonical_sha256(source),
        )
        properties = source.get("properties") if isinstance(source.get("properties"), list) else []
        declared_type = next(
            (
                str(item.get("value"))
                for item in properties
                if isinstance(item, Mapping) and item.get("name") == "dsb:component-type"
            ),
            "dependency",
        )
        components.append(
            {
                "component_id": component_id,
                "component_type": declared_type
                if declared_type in COMPONENT_TYPES
                else "dependency",
                "name": str(source.get("name") or component_id),
                "version": str(source.get("version") or "undeclared"),
                "supplier": _cyclonedx_supplier(source),
                "digest": digest,
                "locator": str(source.get("purl") or source.get("cpe") or f"cyclonedx:{reference}"),
                "criticality": "moderate",
                "external": True,
            }
        )
    relationships = []
    for dependency in payload.get("dependencies", []):
        if not isinstance(dependency, Mapping) or dependency.get("ref") not in ref_to_id:
            continue
        for target in dependency.get("dependsOn", []):
            if target in ref_to_id:
                relationships.append(
                    {
                        "from_component_id": ref_to_id[str(dependency["ref"])],
                        "to_component_id": ref_to_id[str(target)],
                        "relationship": "depends-on",
                    }
                )
    return seal_inventory(_imported_inventory(inventory_id, "CycloneDX", components, relationships))


def import_spdx(payload: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    if not str(payload.get("spdxVersion", "")).startswith("SPDX-") or not isinstance(
        payload.get("packages"), list
    ):
        raise ValueError("input is not a supported SPDX JSON document")
    components, ref_to_id, used = [], {}, set()
    for index, package in enumerate(payload["packages"]):
        if not isinstance(package, Mapping):
            raise ValueError(f"SPDX package {index} must be an object")
        reference = str(package.get("SPDXID") or f"SPDXRef-Package-{index + 1}")
        component_id = _unique_slug(reference.removeprefix("SPDXRef-"), used)
        ref_to_id[reference] = component_id
        checksums = package.get("checksums") if isinstance(package.get("checksums"), list) else []
        digest = next(
            (
                str(item.get("checksumValue", "")).lower()
                for item in checksums
                if isinstance(item, Mapping)
                and str(item.get("algorithm", "")).upper().replace("-", "") == "SHA256"
                and _DIGEST.fullmatch(str(item.get("checksumValue", "")).lower())
            ),
            canonical_sha256(package),
        )
        locator = next(
            (
                str(item.get("referenceLocator"))
                for item in package.get("externalRefs", [])
                if isinstance(item, Mapping) and item.get("referenceLocator")
            ),
            f"spdx:{reference}",
        )
        components.append(
            {
                "component_id": component_id,
                "component_type": "dependency",
                "name": str(package.get("name") or component_id),
                "version": str(package.get("versionInfo") or "undeclared"),
                "supplier": str(package.get("supplier") or "undeclared-supplier"),
                "digest": digest,
                "locator": locator,
                "criticality": "moderate",
                "external": True,
            }
        )
    relationships = []
    for relation in payload.get("relationships", []):
        if not isinstance(relation, Mapping) or relation.get("relationshipType") != "DEPENDS_ON":
            continue
        source, target = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
        if source in ref_to_id and target in ref_to_id:
            relationships.append(
                {
                    "from_component_id": ref_to_id[str(source)],
                    "to_component_id": ref_to_id[str(target)],
                    "relationship": "depends-on",
                }
            )
    return seal_inventory(_imported_inventory(inventory_id, "SPDX", components, relationships))


def report_to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AgentBOM report")
    results = [
        {
            "ruleId": "agentbom-claim-reevaluation",
            "level": "warning",
            "message": {"text": f"Reevaluate {item['claim_id']} using {item['evidence_id']}."},
            "properties": {
                "claimId": item["claim_id"],
                "evidenceId": item["evidence_id"],
                "affectedComponentIds": item["affected_component_ids"],
                "automaticActions": 0,
            },
        }
        for item in report["claim_impacts"]
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AgentBOM ClaimImpact",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": [
                            {
                                "id": "agentbom-claim-reevaluation",
                                "shortDescription": {
                                    "text": "Bound assurance evidence requires reevaluation"
                                },
                                "help": {"text": CLAIM_BOUNDARY},
                            }
                        ],
                    }
                },
                "results": results,
                "properties": {"reportSha256": report["report_sha256"]},
            }
        ],
    }


def _reverse_dependency_closure(
    seeds: set[str], baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> set[str]:
    reverse: dict[str, set[str]] = {}
    for inventory in (baseline, candidate):
        for relation in inventory["relationships"]:
            reverse.setdefault(relation["to_component_id"], set()).add(
                relation["from_component_id"]
            )
    affected = set(seeds)
    queue = deque(sorted(seeds))
    while queue:
        current = queue.popleft()
        for parent in sorted(reverse.get(current, set())):
            if parent not in affected:
                affected.add(parent)
                queue.append(parent)
    return affected


def _relation_key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    return (value["from_component_id"], value["to_component_id"], value["relationship"])


def _binding_key(value: Mapping[str, Any]) -> tuple[str, str]:
    return (value["claim_id"], value["evidence_id"])


def _imported_inventory(
    inventory_id: str,
    source_format: str,
    components: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
) -> dict[str, Any]:
    _require_identifier(inventory_id)
    if not components:
        raise ValueError(f"{source_format} document contains no components")
    return {
        "schema_version": 1,
        "inventory_type": INVENTORY_TYPE,
        "inventory_id": inventory_id,
        "title": f"Imported {source_format} component inventory",
        "owner": "replace-with-accountable-inventory-owner",
        "boundary": (
            f"Imported from {source_format}; enrich AI-specific types, criticality, ownership, "
            "relationships, completeness, and claim bindings before decision use."
        ),
        "complete": False,
        "components": components,
        "relationships": sorted(relationships, key=_relation_key),
        "required_claim_ids": [],
        "claim_bindings": [],
        "claim_boundary": CLAIM_BOUNDARY,
    }


def _cyclonedx_supplier(source: Mapping[str, Any]) -> str:
    supplier = source.get("supplier")
    if isinstance(supplier, Mapping) and supplier.get("name"):
        return str(supplier["name"])
    author = source.get("author")
    return str(author or "undeclared-supplier")


def _unique_slug(value: str, used: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80] or "component"
    candidate, suffix = base, 2
    while candidate in used:
        candidate = f"{base[:74]}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _require_identifier(value: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        raise ValueError("inventory_id must be a lowercase kebab-case identifier")


def _exact(value: Mapping[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    missing, extra = sorted(expected - set(value)), sorted(set(value) - expected)
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} has unsupported fields: {', '.join(extra)}")


def _identifier(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value) or len(value) > 100:
        errors.append(f"{label} must be a lowercase kebab-case identifier")


def _text(value: Any, label: str, maximum: int, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        errors.append(f"{label} must be a non-empty string of at most {maximum} characters")


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
