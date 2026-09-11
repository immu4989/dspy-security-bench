"""Privacy-minimized SLSA Provenance v1 to AgentBOM mapping evidence."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
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

REPORT_TYPE = "AgentBOM SLSAImport / Privacy-minimized provenance mapping"
PROTOCOL_VERSION = "agentbom-slsa-import-v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
ANALYZER = "deterministic-privacy-minimized-slsa-mapper-v1"
MAX_TEXT = 2_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
CLAIM_BOUNDARY = (
    "SLSAImport deterministically maps the SHA-256-identified outputs, resolved build "
    "dependencies, external build-definition identity, and builder identity from one supplied "
    "SLSA Provenance v1 Statement into an incomplete AgentBOM starter. Raw artifact names, "
    "URIs, builder IDs, build types, parameters, metadata, byproducts, annotations, and content "
    "are not retained. The mapping does not verify an attestation signature, establish a SLSA "
    "Build level, prove provenance completeness or truth, classify a supplier, certify a system, "
    "authorize deployment, or accept risk."
)
LIMITATIONS = (
    "Only in-toto Statement v1 with the SLSA Provenance v1 predicate and SHA-256 on every mapped resource is accepted.",
    "The source Statement is caller-supplied and unauthenticated; verify its envelope and signer-builder expectations separately before assigning trust.",
    "Deterministic digests minimize retained fields but are identifiers, not encryption or confidentiality controls; low-entropy values may be guessable.",
    "Builder and build-definition components are hashes of metadata, while subject and dependency components retain their declared artifact SHA-256 values.",
    "The output is deliberately incomplete and has no claim bindings until an accountable owner reviews and enriches it.",
    "The mapper performs no network access, artifact retrieval, vulnerability lookup, supplier scoring, procurement decision, deployment, or automatic action.",
)
EXCLUDED_INPUT_FIELDS = (
    "subject names, URIs, media types, download locations, annotations, and embedded content",
    "resolved-dependency names, URIs, media types, download locations, annotations, and embedded content",
    "raw builder ID, builder dependency descriptors, and builder version labels",
    "raw build type and external/internal parameter values",
    "run invocation ID, timestamps, byproducts, and extension fields",
    "attestation signatures or envelope material",
)


def build_slsa_import_report(statement: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    """Map one SLSA statement without retaining its raw identifying fields."""

    parsed = _parse_statement(statement)
    inventory, mapping = _build_inventory(parsed, inventory_id=inventory_id)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "analyzer": ANALYZER,
        "source_statement": {
            "statement_type": STATEMENT_TYPE,
            "predicate_type": PREDICATE_TYPE,
            "canonical_statement_sha256": canonical_sha256(statement),
            "subject_count": len(parsed["subjects"]),
            "resolved_dependency_count": len(parsed["dependencies"]),
            "builder_identity_sha256": _text_sha256(parsed["builder_id"]),
            "build_type_sha256": _text_sha256(parsed["build_type"]),
            "external_parameters_sha256": canonical_sha256(parsed["external_parameters"]),
        },
        "inventory": inventory,
        "mapping": mapping,
        "excluded_input_fields": list(EXCLUDED_INPUT_FIELDS),
        "summary": {
            "component_count": len(inventory["components"]),
            "relationship_count": len(inventory["relationships"]),
            "subject_components": len(mapping["subject_component_ids"]),
            "resolved_dependency_components": len(mapping["resolved_dependency_component_ids"]),
            "inventory_complete": False,
            "claim_binding_count": 0,
            "raw_names_retained": False,
            "raw_uris_retained": False,
            "raw_parameters_retained": False,
            "signatures_verified": False,
            "network_requests": 0,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "agentbom_claim_boundary": AGENTBOM_CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def import_slsa(statement: Mapping[str, Any], *, inventory_id: str) -> dict[str, Any]:
    """Return only the incomplete AgentBOM starter from a SLSA statement."""

    return build_slsa_import_report(statement, inventory_id=inventory_id)["inventory"]


def verify_slsa_import_report(
    report: Mapping[str, Any], statement: Mapping[str, Any]
) -> tuple[str, ...]:
    """Recompute a saved import report from the separately retained Statement."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AgentBOM SLSAImport report")
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
        inventory_id = inventory["inventory_id"]
        expected = build_slsa_import_report(statement, inventory_id=inventory_id)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"SLSAImport report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("SLSAImport report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _parse_statement(statement: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(statement, Mapping):
        raise ValueError("SLSA input must be a JSON object")
    if statement.get("_type") != STATEMENT_TYPE:
        raise ValueError("SLSA input must be an in-toto Statement v1")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError("SLSA input must use the SLSA Provenance v1 predicate")
    subjects = _resource_list(statement.get("subject"), "subject", required=True)
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        raise ValueError("SLSA predicate must be an object")
    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if not isinstance(build_definition, Mapping) or not isinstance(run_details, Mapping):
        raise ValueError("SLSA predicate requires buildDefinition and runDetails objects")
    build_type = _bounded_text(build_definition.get("buildType"), "buildType")
    external_parameters = build_definition.get("externalParameters")
    if not isinstance(external_parameters, Mapping):
        raise ValueError("externalParameters must be an object")
    internal_parameters = build_definition.get("internalParameters")
    if internal_parameters is not None and not isinstance(internal_parameters, Mapping):
        raise ValueError("internalParameters must be an object, null, or absent")
    dependencies = _resource_list(
        build_definition.get("resolvedDependencies"),
        "resolvedDependencies",
        required=False,
    )
    if len(subjects) + len(dependencies) + 2 > MAX_COMPONENTS:
        raise ValueError(f"SLSA mapping exceeds the AgentBOM {MAX_COMPONENTS}-component limit")
    builder = run_details.get("builder")
    if not isinstance(builder, Mapping):
        raise ValueError("runDetails.builder must be an object")
    builder_id = _bounded_text(builder.get("id"), "builder.id")
    try:
        canonical_sha256(statement)
        canonical_sha256(external_parameters)
        canonical_sha256(builder)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"SLSA input is not canonical JSON data: {exc}") from exc
    return {
        "subjects": subjects,
        "dependencies": dependencies,
        "build_type": build_type,
        "external_parameters": deepcopy(dict(external_parameters)),
        "builder": deepcopy(dict(builder)),
        "builder_id": builder_id,
    }


def _resource_list(value: object, label: str, *, required: bool) -> list[dict[str, Any]]:
    if value is None and not required:
        return []
    if not isinstance(value, list) or (required and not value):
        suffix = " a non-empty array" if required else " an array, null, or absent"
        raise ValueError(f"{label} must be{suffix}")
    resources = []
    identities: set[str] = set()
    for index, resource in enumerate(value):
        if not isinstance(resource, Mapping):
            raise ValueError(f"{label}[{index}] must be an object")
        digests = resource.get("digest")
        sha256 = digests.get("sha256") if isinstance(digests, Mapping) else None
        if not isinstance(sha256, str) or not _DIGEST.fullmatch(sha256):
            raise ValueError(f"{label}[{index}] must declare a lowercase SHA-256 digest")
        identity = {
            key: resource[key]
            for key in ("name", "uri")
            if isinstance(resource.get(key), str) and resource[key]
        }
        if not identity:
            raise ValueError(f"{label}[{index}] requires name or uri for stable mapping")
        if any(len(item) > MAX_TEXT for item in identity.values()):
            raise ValueError(f"{label}[{index}] name or uri exceeds {MAX_TEXT} characters")
        try:
            descriptor_sha256 = canonical_sha256(resource)
            identity_sha256 = canonical_sha256(identity)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}[{index}] is not canonical JSON data: {exc}") from exc
        if identity_sha256 in identities:
            raise ValueError(f"{label} contains a duplicate name/uri identity")
        identities.add(identity_sha256)
        resources.append(
            {
                "artifact_sha256": sha256,
                "descriptor_sha256": descriptor_sha256,
                "identity_sha256": identity_sha256,
            }
        )
    return sorted(
        resources,
        key=lambda item: (item["identity_sha256"], item["artifact_sha256"]),
    )


def _build_inventory(
    parsed: Mapping[str, Any], *, inventory_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    used: set[str] = set()
    subjects = [
        _artifact_component(item, "slsa-subject", "SLSA output subject", used)
        for item in parsed["subjects"]
    ]
    dependencies = [
        _artifact_component(
            item,
            "slsa-dependency",
            "SLSA resolved build dependency",
            used,
        )
        for item in parsed["dependencies"]
    ]
    build_definition_identity = {
        "buildType": parsed["build_type"],
        "externalParameters": parsed["external_parameters"],
    }
    build_definition_digest = canonical_sha256(build_definition_identity)
    build_definition = _metadata_component(
        "slsa-build-definition",
        "policy",
        "SLSA external build definition",
        build_definition_digest,
        _text_sha256(parsed["build_type"]),
        used,
    )
    builder_digest = canonical_sha256(parsed["builder"])
    builder = _metadata_component(
        "slsa-builder",
        "infrastructure",
        "SLSA build platform identity",
        builder_digest,
        _text_sha256(parsed["builder_id"]),
        used,
    )
    relationships = [
        {
            "from_component_id": item["component_id"],
            "to_component_id": build_definition["component_id"],
            "relationship": "depends-on",
        }
        for item in subjects
    ]
    relationships.extend(
        {
            "from_component_id": build_definition["component_id"],
            "to_component_id": item["component_id"],
            "relationship": "depends-on",
        }
        for item in dependencies
    )
    relationships.append(
        {
            "from_component_id": build_definition["component_id"],
            "to_component_id": builder["component_id"],
            "relationship": "runs-on",
        }
    )
    inventory = seal_inventory(
        {
            "schema_version": 1,
            "inventory_type": INVENTORY_TYPE,
            "inventory_id": inventory_id,
            "title": "Privacy-minimized SLSA Provenance component inventory",
            "owner": "replace-with-accountable-inventory-owner",
            "boundary": (
                "Incomplete local SLSA Provenance v1 import; raw names, URIs, builder/build-type "
                "identifiers, parameters, run metadata, byproducts, annotations, and content "
                "are not retained. Owner enrichment and attestation verification are required."
            ),
            "complete": False,
            "components": sorted(
                [*subjects, build_definition, builder, *dependencies],
                key=lambda item: item["component_id"],
            ),
            "relationships": sorted(
                relationships,
                key=lambda item: (
                    item["from_component_id"],
                    item["to_component_id"],
                    item["relationship"],
                ),
            ),
            "required_claim_ids": [],
            "claim_bindings": [],
            "claim_boundary": AGENTBOM_CLAIM_BOUNDARY,
        }
    )
    if errors := validate_inventory(inventory):
        raise ValueError("mapped AgentBOM is invalid: " + "; ".join(errors))
    mapping = {
        "subject_component_ids": sorted(item["component_id"] for item in subjects),
        "build_definition_component_id": build_definition["component_id"],
        "builder_component_id": builder["component_id"],
        "resolved_dependency_component_ids": sorted(item["component_id"] for item in dependencies),
    }
    return inventory, mapping


def _artifact_component(
    resource: Mapping[str, str],
    prefix: str,
    name: str,
    used: set[str],
) -> dict[str, Any]:
    digest = resource["artifact_sha256"]
    identity_sha256 = resource["identity_sha256"]
    component_id = _unique_component_id(prefix, identity_sha256, used)
    return {
        "component_id": component_id,
        "component_type": "dependency",
        "name": name,
        "version": f"sha256:{digest[:12]}",
        "supplier": "undeclared-supplier",
        "digest": digest,
        "locator": f"slsa-resource-identity:sha256:{identity_sha256}",
        "criticality": "moderate",
        "external": True,
    }


def _metadata_component(
    prefix: str,
    component_type: str,
    name: str,
    digest: str,
    identity_sha256: str,
    used: set[str],
) -> dict[str, Any]:
    return {
        "component_id": _unique_component_id(prefix, identity_sha256, used),
        "component_type": component_type,
        "name": name,
        "version": f"identity-sha256:{digest[:12]}",
        "supplier": "undeclared-supplier",
        "digest": digest,
        "locator": f"slsa-identity:sha256:{identity_sha256}",
        "criticality": "moderate",
        "external": True,
    }


def _unique_component_id(prefix: str, digest: str, used: set[str]) -> str:
    base = f"{prefix}-{digest[:12]}"
    candidate, suffix = base, 2
    while candidate in used:
        candidate = f"{base}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _bounded_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be a non-empty string of at most {MAX_TEXT} characters")
    return value


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
