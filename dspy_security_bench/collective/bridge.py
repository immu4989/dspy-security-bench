"""EvidenceBridge: strict, content-free ingestion for CollectiveGuard v2."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from dspy_security_bench.collective.proof import validate_scenario as validate_v1_scenario
from dspy_security_bench.collective.v2 import (
    CONTENT_BOUNDARY,
    SCENARIO_TYPE,
    SOURCE_TYPES,
    validate_scenario,
)
from dspy_security_bench.mission.loader import canonical_sha256

BRIDGE_TYPE = "dspy-security-bench-collective-evidence-bridge"
BRIDGE_VERSION = "evidencebridge-v1"
ADAPTER_PROFILES: dict[str, dict[str, Any]] = {
    "runtime-neutral-json": {
        "maturity": "stable",
        "source_types": list(SOURCE_TYPES),
        "interface": "canonical structural JSON manifest",
    },
    "otel-genai-development": {
        "maturity": "development",
        "source_types": ["runtime", "evaluator", "response"],
        "interface": "owner-mapped OpenTelemetry GenAI/agent span identifiers",
    },
    "iam-decision-log": {
        "maturity": "stable-contract",
        "source_types": ["identity"],
        "interface": "authorization decision and revocation identifiers",
    },
    "network-policy-log": {
        "maturity": "stable-contract",
        "source_types": ["network", "control"],
        "interface": "egress decision and control-state identifiers",
    },
    "siem-response-log": {
        "maturity": "stable-contract",
        "source_types": ["response", "control"],
        "interface": "alert, containment, and evidence-preservation identifiers",
    },
}
DISCLAIMER = (
    "EvidenceBridge validates a structural mapping contract; it does not authenticate a source, "
    "run a named backend, validate vendor telemetry, collect sensitive content, or establish that "
    "the source record is complete. Adapter maturity labels and source hashes must be reviewed by "
    "the evidence owner."
)

_ROOT_FIELDS = {
    "schema_version",
    "bridge_type",
    "bridge_version",
    "adapter_profile",
    "scenario_id",
    "title",
    "description",
    "collective_scenario",
    "sources",
    "observations",
    "evidence_policy",
    "claim_boundary",
}


def bridge_contract() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "bridge_version": BRIDGE_VERSION,
        "adapter_profiles": deepcopy(ADAPTER_PROFILES),
        "accepted_content": [
            "structural event identifiers",
            "relative timing",
            "source identifiers",
            "source content digests",
            "field-name coverage",
            "provenance classification",
        ],
        "rejected_content": [
            "prompts",
            "messages",
            "chain-of-thought",
            "tool arguments",
            "tool results",
            "credentials",
            "exploit payloads",
        ],
        "claim_boundary": DISCLAIMER,
    }


def build_v2_scenario(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a strict bridge manifest into a v2 scenario and validate the result."""

    if set(payload) != _ROOT_FIELDS:
        raise ValueError("EvidenceBridge fields are incomplete or unsupported")
    if (
        payload.get("schema_version") != 1
        or payload.get("bridge_type") != BRIDGE_TYPE
        or payload.get("bridge_version") != BRIDGE_VERSION
    ):
        raise ValueError("EvidenceBridge metadata is unsupported")
    if payload.get("adapter_profile") not in ADAPTER_PROFILES:
        raise ValueError("EvidenceBridge adapter_profile is unsupported")
    if payload.get("claim_boundary") != DISCLAIMER:
        raise ValueError("EvidenceBridge claim_boundary is unsupported")
    collective = payload.get("collective_scenario")
    if not isinstance(collective, Mapping):
        raise ValueError("collective_scenario must be an object")
    v1_errors = validate_v1_scenario(collective)
    if v1_errors:
        raise ValueError("invalid v1 scenario: " + "; ".join(v1_errors))
    # The v2 validator intentionally applies all strict source, observation, identifier, and
    # content-boundary checks. No arbitrary source records survive this conversion.
    scenario = {
        "schema_version": 2,
        "scenario_type": SCENARIO_TYPE,
        "scenario_id": payload.get("scenario_id"),
        "title": payload.get("title"),
        "description": payload.get("description"),
        "collective_scenario": deepcopy(dict(collective)),
        "sources": deepcopy(payload.get("sources")),
        "event_bindings": deepcopy(payload.get("observations")),
        "evidence_policy": deepcopy(payload.get("evidence_policy")),
    }
    errors = validate_scenario(scenario)
    if errors:
        raise ValueError("invalid EvidenceBridge mapping: " + "; ".join(errors))
    return scenario


def bridge_manifest_from_v2(scenario: Mapping[str, Any], *, adapter_profile: str) -> dict[str, Any]:
    """Create a reviewable bridge manifest from a valid v2 scenario."""

    errors = validate_scenario(scenario)
    if errors:
        raise ValueError("invalid CollectiveGuard v2 scenario: " + "; ".join(errors))
    if adapter_profile not in ADAPTER_PROFILES:
        raise ValueError("EvidenceBridge adapter_profile is unsupported")
    return {
        "schema_version": 1,
        "bridge_type": BRIDGE_TYPE,
        "bridge_version": BRIDGE_VERSION,
        "adapter_profile": adapter_profile,
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "description": scenario["description"],
        "collective_scenario": deepcopy(scenario["collective_scenario"]),
        "sources": deepcopy(scenario["sources"]),
        "observations": deepcopy(scenario["event_bindings"]),
        "evidence_policy": deepcopy(scenario["evidence_policy"]),
        "claim_boundary": DISCLAIMER,
    }


def source_descriptor(
    *,
    source_id: str,
    source_type: str,
    adapter: str,
    adapter_version: str,
    source_payload: Mapping[str, Any],
    collection_status: str = "complete",
    clock_domain: str = "unix-nanoseconds",
) -> dict[str, Any]:
    """Hash owner-supplied source bytes represented as canonical JSON without embedding them."""

    return {
        "source_id": source_id,
        "source_type": source_type,
        "adapter": adapter,
        "adapter_version": adapter_version,
        "source_sha256": canonical_sha256(source_payload),
        "collection_status": collection_status,
        "clock_domain": clock_domain,
        "content_boundary": CONTENT_BOUNDARY,
    }
