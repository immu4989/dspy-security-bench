"""Build the website's compact data payload from committed leaderboard results.

The website never owns benchmark numbers. This generator joins security runs in
``leaderboard/results/*.json`` with the matching no-attack capability evidence
in ``leaderboard/benign/*.json`` so the interactive experience and
``LEADERBOARD.md`` remain views over the same committed evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
from pathlib import Path

from dspy_security_bench.jsonio import read_json_object
from dspy_security_bench.procurement.registry_metadata import (
    attestation_record_errors,
    registry_shape,
    reproduction_record_errors,
)
from dspy_security_bench.proofrun_review import FAMILIES

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "leaderboard/results"
BENIGN_DIR = ROOT / "leaderboard/benign"
SUBMISSIONS_DIR = ROOT / "submissions/impact"
CONTROL_SUBMISSIONS_DIR = ROOT / "submissions/control"
INCIDENT_SUBMISSIONS_DIR = ROOT / "submissions/incident"
SOURCE_SUBMISSIONS_DIR = ROOT / "submissions/source"
AUTHORITY_SUBMISSIONS_DIR = ROOT / "submissions/authority"
TRACE_SUBMISSIONS_DIR = ROOT / "submissions/trace"
CAUSAL_SUBMISSIONS_DIR = ROOT / "submissions/causal"
COLLECTIVE_SUBMISSIONS_DIR = ROOT / "submissions/collective"
DEFENSE_SUBMISSIONS_DIR = ROOT / "submissions/defense"
ASSURANCE_EXCHANGE = ROOT / "submissions/assurance/index.json"
REPRODUCTIONS = ROOT / "submissions/reproductions.json"
ATTESTATIONS = ROOT / "submissions/attestations.json"
DEFAULT_OUT = ROOT / "site/data.json"
GITHUB = "https://github.com/immu4989/dspy-security-bench/blob/main"


def build_payload(
    results_dir: Path = RESULTS_DIR,
    benign_dir: Path = BENIGN_DIR,
    submissions_dir: Path = SUBMISSIONS_DIR,
    control_submissions_dir: Path = CONTROL_SUBMISSIONS_DIR,
    incident_submissions_dir: Path = INCIDENT_SUBMISSIONS_DIR,
    source_submissions_dir: Path = SOURCE_SUBMISSIONS_DIR,
    authority_submissions_dir: Path = AUTHORITY_SUBMISSIONS_DIR,
    trace_submissions_dir: Path = TRACE_SUBMISSIONS_DIR,
    causal_submissions_dir: Path = CAUSAL_SUBMISSIONS_DIR,
    collective_submissions_dir: Path = COLLECTIVE_SUBMISSIONS_DIR,
    defense_submissions_dir: Path = DEFENSE_SUBMISSIONS_DIR,
    assurance_exchange_path: Path = ASSURANCE_EXCHANGE,
    reproductions_path: Path = REPRODUCTIONS,
    attestations_path: Path = ATTESTATIONS,
) -> dict:
    models = []
    protocol_versions = set()
    for path in sorted(results_dir.glob("*.json")):
        row = json.loads(path.read_text())
        if row.get("smoke"):
            continue
        benign_path = benign_dir / path.name
        if not benign_path.is_file():
            raise ValueError(f"missing benign capability evidence for {path.name}")
        benign = json.loads(benign_path.read_text())
        if benign.get("model_id") != row.get("model_id"):
            raise ValueError(f"benign capability model mismatch for {path.name}")
        protocol_versions.add(row["protocol_version"])
        suites = {}
        for suite_name, attacks in row.get("per_suite", {}).items():
            primary = attacks.get("important_instructions") or next(iter(attacks.values()))
            suites[suite_name] = {
                "robustness": primary["R_mean"],
                "capability": benign["per_suite"][suite_name]["U_benign"],
            }
        models.append(
            {
                "name": row["display_name"],
                "family": row["family"],
                "modelId": row["model_id"],
                "robustness": row["combined_R"],
                "ciLow": row["combined_ci_low"],
                "ciHigh": row["combined_ci_high"],
                "capability": benign["combined_U_benign"],
                "bucket": row["bucket"],
                "status": row["status"],
                "classification": row["bucket"] if row["status"] == "confirmed" else "Provisional",
                "pairs": sum(
                    attack.get("n_pairs_unique", attack.get("n_pairs", 0))
                    for attacks in row.get("per_suite", {}).values()
                    for attack in attacks.values()
                ),
                "suites": suites,
                "result": f"{GITHUB}/leaderboard/results/{path.name}",
            }
        )
    models.sort(key=lambda model: (-model["robustness"], -model["capability"], model["name"]))
    families = sorted({model["family"] for model in models})
    proofruns = _proofrun_results(submissions_dir, reproductions_path, attestations_path)
    control_evidence = _control_evidence_results(
        control_submissions_dir, reproductions_path, attestations_path
    )
    incident_evidence = _incident_evidence_results(
        incident_submissions_dir, reproductions_path, attestations_path
    )
    source_evidence = _source_evidence_results(
        source_submissions_dir, reproductions_path, attestations_path
    )
    authority_evidence = _authority_evidence_results(
        authority_submissions_dir, reproductions_path, attestations_path
    )
    trace_evidence = _trace_evidence_results(trace_submissions_dir)
    causal_evidence = _causal_evidence_results(causal_submissions_dir)
    collective_evidence = _collective_evidence_results(collective_submissions_dir)
    defense_evidence = _defense_evidence_results(defense_submissions_dir)
    from dspy_security_bench.assurance.exchange import exchange_summary, load_exchange

    assurance_exchange = exchange_summary(load_exchange(assurance_exchange_path))
    return {
        "protocol": ", ".join(sorted(protocol_versions)),
        "modelCount": len(models),
        "familyCount": len(families),
        "families": families,
        "models": models,
        "proofrunCount": len(proofruns),
        "proofruns": proofruns,
        "controlEvidenceCount": len(control_evidence),
        "controlEvidence": control_evidence,
        "incidentEvidenceCount": len(incident_evidence),
        "incidentEvidence": incident_evidence,
        "sourceEvidenceCount": len(source_evidence),
        "sourceEvidence": source_evidence,
        "authorityEvidenceCount": len(authority_evidence),
        "authorityEvidence": authority_evidence,
        "traceEvidenceCount": len(trace_evidence),
        "traceEvidence": trace_evidence,
        "causalEvidenceCount": len(causal_evidence),
        "causalEvidence": causal_evidence,
        "collectiveEvidenceCount": len(collective_evidence),
        "collectiveEvidence": collective_evidence,
        "defenseEvidenceCount": len(defense_evidence),
        "defenseEvidence": defense_evidence,
        "assuranceExchange": assurance_exchange,
        "missionAssuranceCommons": {
            "assuranceGraph": {
                "protocolVersion": "assurancegraph-v1",
                "profileCount": 4,
                "evidenceKindCount": 9,
                "sectorStarterCount": 7,
                "federalReviewPackFileCount": 8,
                "claimStatuses": [
                    "supported",
                    "violated",
                    "contradicted",
                    "stale_evidence",
                    "missing_evidence",
                ],
                "automaticDeploymentActions": 0,
            },
            "containmentProof": {
                "protocolVersion": "containmentproof-v1",
                "canaryProbeCount": 8,
                "automaticResponseActions": 0,
            },
            "evalIntegrityProof": {
                "protocolVersion": "evalintegrityproof-v1",
                "controlCount": 13,
                "rawEvaluationContentAccepted": False,
                "automaticActions": 0,
            },
            "assuranceQuorum": {
                "protocolVersion": "assurancequorum-v1",
                "statementType": "https://in-toto.io/Statement/v1",
                "envelopeType": "DSSE",
                "referenceReviewerOrganizations": 5,
                "evidenceGapCanBeOutvoted": False,
                "automaticDeploymentActions": 0,
            },
            "assuranceLedger": {
                "protocolVersion": "assuranceledger-v1",
                "merkleConstruction": "RFC6962-style-domain-separated",
                "referenceWitnessOrganizations": 2,
                "retirementDistinctFromCompromise": True,
                "globalConsistencyClaimed": False,
                "gossipProtocolVersion": "assuranceledger-gossip-v1",
                "forkEvidenceRequiresValidViews": True,
                "forkProofProtocolVersion": "assuranceledger-fork-proof-v1",
                "forkProofEmbeddedLogEntries": 0,
                "forkProofOperatorSignatures": 2,
                "consistencyProofProtocolVersion": "assuranceledger-consistency-proof-v1",
                "consistencyProofEmbeddedLogEntries": 0,
                "referenceConsistencyPathNodes": 4,
                "observerReceiptProtocolVersion": "assuranceledger-observer-receipt-v1",
                "referenceObserverOrganizations": 2,
                "referenceObserverChannels": 2,
                "rawChannelLocatorsDisclosed": False,
                "witnessConflictProtocolVersion": "assuranceledger-witness-conflict-v1",
                "referenceDoubleSigningWitnessKeys": 2,
                "automaticWitnessRevocations": 0,
                "trustRootProtocolVersion": "assuranceledger-trust-root-v1",
                "referenceRootSignatureThreshold": 2,
                "referenceRootOrganizationThreshold": 2,
                "supportedRootSignatureSchemes": [
                    "ecdsa-sha2-nistp256",
                    "ed25519",
                    "rsassa-pss-sha256",
                ],
                "bootstrapDigestRequired": True,
                "dualThresholdRotationRequired": True,
                "trustRootChainProtocolVersion": "assuranceledger-trust-root-chain-v1",
                "referenceRootChainRoots": 3,
                "referenceRootChainTransitions": 2,
                "referenceExpiredIntermediateRoots": 2,
                "maximumRootChainLength": 64,
                "currentFinalRootRequired": True,
                "minimumFinalVersionSupported": True,
                "trustRecoveryProtocolVersion": "assuranceledger-trust-recovery-drill-v1",
                "referenceRecoveryChecks": 13,
                "referenceRecoveryEvents": 9,
                "referenceRecoveryOrganizations": 3,
                "recoveryContentFieldsProcessed": 0,
                "replacementRootsActivated": 0,
                "trustRecoveryAttestationProtocolVersion": "assuranceledger-trust-recovery-attestation-v1",
                "referenceRecoveryAttestationChecks": 10,
                "referenceRecoveryAttestations": 9,
                "referenceRecoveryAttesterOrganizations": 3,
                "referenceRecoveryReplayNonces": 9,
                "recoveryAttestationContentFieldsProcessed": 0,
                "recoveryAttestationRootsActivated": 0,
                "timeQuorumProtocolVersion": "assuranceledger-time-quorum-v1",
                "referenceTimeQuorumChecks": 10,
                "referenceTimeSources": 3,
                "referenceTimeSourceOrganizations": 3,
                "referenceTimeIntervalWidthSeconds": 4,
                "timeQuorumContentFieldsProcessed": 0,
                "timeQuorumClockAdjustments": 0,
                "trustRootTimeProtocolVersion": "assuranceledger-trust-root-time-gate-v1",
                "referenceRootTimeChecks": 8,
                "referenceRootTimeEndpointEvaluations": 2,
                "referenceRootTimeIntervalWidthSeconds": 4,
                "rootTimeContentFieldsProcessed": 0,
                "rootTimeClockAdjustments": 0,
                "rootTimeRootsInstalled": 0,
                "rootViewProtocolVersion": "assuranceledger-root-view-quorum-v1",
                "referenceRootViewChecks": 10,
                "referenceRootViewObservers": 3,
                "referenceRootViewOrganizations": 3,
                "referenceRootViewConflicts": 0,
                "rootViewVectorVersion": "assuranceledger-root-view-vectors-v1",
                "referenceRootViewVectorCases": 8,
                "referenceRootViewManifestBoundFiles": 21,
                "rootViewIndependentImplementations": 2,
                "rootViewCrossLanguageMutationCases": 21,
                "rootViewInteropEvidenceProtocolVersion": "assuranceledger-root-view-interop-evidence-v1",
                "referenceRootViewInteropAgreements": 8,
                "referenceRootViewInteropDisagreements": 0,
                "referenceRootViewInteropSubjects": 4,
                "rootViewInteropMainBranchAttested": True,
                "rootViewInteropAttestationCleanJob": True,
                "rootViewVectorPrivateKeysIncluded": False,
                "rootViewNetworkRequests": 0,
                "rootViewRootsInstalled": 0,
                "conformanceProtocolVersion": "assuranceledger-verifier-conformance-v9",
                "referenceConformanceCases": 16,
                "referenceUnexpectedAcceptances": 0,
                "conformanceCleanSourcesNativelyVerified": True,
                "capabilityManifestProtocolVersion": "assuranceledger-capability-manifest-v1",
                "capabilityProtocolCount": 17,
                "capabilitySchemaCount": 31,
                "standaloneVerifierCount": 11,
                "integrationLockProtocolVersion": "assuranceledger-integration-lock-v1",
                "referenceCapabilityDriftFindings": 0,
                "rereviewProtocolVersion": "assuranceledger-rereview-v1",
                "referenceInvalidatedReviews": 1,
                "referenceClaimsRequiringRereview": 8,
                "replacementReviewersSelected": 0,
                "automaticDeploymentActions": 0,
            },
            "agentBOM": {
                "protocolVersion": "agentbom-claimimpact-v1",
                "slsaImportProtocolVersion": "agentbom-slsa-import-v1",
                "slsaRawNamesRetained": False,
                "slsaRawUrisRetained": False,
                "slsaRawParametersRetained": False,
                "slsaSignaturesVerified": False,
                "mlbomDisclosureProtocolVersion": "agentbom-mlbom-disclosure-v1",
                "mlbomModelDisclosureFields": 16,
                "mlbomDataDisclosureFields": 6,
                "mlbomRawDisclosureValuesRetained": False,
                "mlbomPresenceIsAdequacy": False,
                "spdxAIDisclosureProtocolVersion": "agentbom-spdx-ai-disclosure-v1",
                "spdxAIModelDisclosureFields": 15,
                "spdxAIDatasetDisclosureFields": 13,
                "spdxAILicenseRulesChecked": 2,
                "spdxAIFullValidationPerformed": False,
                "aiBOMCrosswalkProtocolVersion": "agentbom-ai-crosswalk-v1",
                "aiBOMCrosswalkModelTopics": 10,
                "aiBOMCrosswalkDatasetTopics": 6,
                "aiBOMCrosswalkRawValuesCompared": False,
                "aiBOMCrosswalkSemanticEquivalenceEstablished": False,
                "aiDisclosurePolicyProtocolVersion": "agentbom-ai-disclosure-policy-evaluation-v1",
                "aiDisclosurePolicyOwnerRequiredFields": 20,
                "aiDisclosurePolicyUniversalProfileProvided": False,
                "aiDisclosurePolicyRawValuesProcessed": False,
                "aiDisclosurePolicyAutomaticWaivers": 0,
                "aiDisclosureDriftProtocolVersion": "agentbom-ai-disclosure-drift-v1",
                "aiDisclosureDriftFindingStates": 7,
                "aiDisclosureDriftRemovalIsResolution": False,
                "aiDisclosureDriftRawValuesCompared": False,
                "aiDisclosureDriftAutomaticUpgradeApprovals": 0,
                "automaticDeploymentActions": 0,
            },
            "probeContract": {
                "protocolVersion": "assurance-probe-contract-v1",
                "thirdPartyCodeLoading": False,
            },
            "inventoryForge": {"inputLimitBytes": 5_000_000, "recordLimit": 5_000},
            "agentGraphTwin": {"scenarioVersion": "agentgraphtwin-v1", "pairCount": 6},
            "continuousProof": {"schemaVersion": 1, "thresholdOwner": "evidence-owner"},
            "acquisitionProof": {"schemaVersion": 1, "decisionAuthority": "accountable-owner"},
            "resilienceGraph": {
                "protocolVersion": "resiliencegraph-v1",
                "exactActionLimit": 18,
                "referenceIsRecommendation": False,
            },
            "authorityBridges": ["opa", "cedar", "openfga", "oauth-mcp", "spiffe"],
            "fixtureClaim": "translation-only; named backends not executed",
        },
    }


def _defense_evidence_results(submissions_dir: Path) -> list[dict]:
    """Expose only privacy-bounded, content-addressed remediation evidence."""

    results = []
    prohibited = (
        '"prompt"',
        '"message_content"',
        '"chain_of_thought"',
        '"tool_arguments"',
        '"tool_results"',
        '"credentials"',
        '"exploit_payload"',
        '"live_target"',
    )
    for path, bundle in _submission_bundles(submissions_dir):
        if not isinstance(bundle, dict):
            continue
        if bundle.get("bundle_type") != "dspy-security-bench-defense-evidence":
            continue
        if not _native_eligible(bundle, "dspy-security-bench-defense-evidence"):
            continue
        unsigned = dict(bundle)
        claimed = unsigned.pop("bundle_sha256", None)
        try:
            encoded = json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            serialized = encoded.decode().lower()
        except (TypeError, ValueError):
            continue
        if claimed != hashlib.sha256(encoded).hexdigest() or any(
            token in serialized for token in prohibited
        ):
            continue
        submission = bundle.get("submission", {})
        summary = bundle.get("report", {}).get("summary", {})
        results.append(
            {
                "mission": bundle.get("mission", {}).get("mission_id", "unknown"),
                "sector": bundle.get("mission", {}).get("sector", "unknown"),
                "runtime": submission.get("runtime", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "outcome": summary.get("outcome", "insufficient_evidence"),
                "pathsClosed": summary.get("attack_paths_closed", 0),
                "pathCount": summary.get("attack_path_count", 0),
                "missionStable": summary.get("mission_services_stable", False),
                "evidenceComplete": summary.get("evidence_complete", False),
                "result": f"{GITHUB}/submissions/defense/{path.name}",
            }
        )
    return results


def _collective_evidence_results(submissions_dir: Path) -> list[dict]:
    """Expose only content-addressed v2 bundles with the frozen privacy boundary."""

    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _native_eligible(bundle, "dspy-security-bench-collective-submission"):
            continue
        if bundle.get("bundle_type") != "dspy-security-bench-collective-submission":
            continue
        unsigned = dict(bundle)
        claimed = unsigned.pop("bundle_sha256", None)
        try:
            encoded = json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        except (TypeError, ValueError):
            continue
        if claimed != hashlib.sha256(encoded).hexdigest():
            continue
        scenario = bundle.get("scenario", {})
        serialized = json.dumps(scenario, sort_keys=True).lower()
        if any(
            token in serialized
            for token in (
                '"prompt"',
                '"message_content"',
                '"chain_of_thought"',
                '"tool_arguments"',
                '"tool_results"',
                '"credentials"',
            )
        ):
            continue
        submission = bundle.get("submission", {})
        summary = bundle.get("report", {}).get("summary", {})
        results.append(
            {
                "runtime": submission.get("runtime", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "deploymentClass": submission.get("deployment_class", "unknown"),
                "status": summary.get("status", "insufficient_evidence"),
                "findingCount": summary.get("finding_count", 0),
                "sourceCount": summary.get("source_count", 0),
                "evidenceComplete": summary.get("clean_evidence_complete", False),
                "result": f"{GITHUB}/submissions/collective/{path.name}",
            }
        )
    return results


def _causal_evidence_results(submissions_dir: Path) -> list[dict]:
    """Build compact rows after dependency-free digest and privacy checks."""

    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _native_eligible(bundle, "dspy-security-bench-causal-submission"):
            continue
        if bundle.get("bundle_type") != "dspy-security-bench-causal-submission":
            continue
        unsigned = dict(bundle)
        claimed = unsigned.pop("bundle_sha256", None)
        try:
            encoded = json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        except (TypeError, ValueError):
            continue
        if claimed != hashlib.sha256(encoded).hexdigest():
            continue
        structural = bundle.get("structural_trace", {})
        encoded_structural = json.dumps(structural, sort_keys=True)
        if any(key in encoded_structural for key in ('"attributes"', '"events"', '"status"')):
            continue
        submission = bundle.get("submission", {})
        causal = bundle.get("causal_report", {}).get("summary", {})
        schedule = bundle.get("schedule_report", {}).get("summary", {})
        results.append(
            {
                "runtime": submission.get("runtime", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "causalStatus": causal.get("status", "review_required"),
                "scheduleStatus": schedule.get("status", "incomplete_review"),
                "trustedEdges": causal.get("trusted_edges", 0),
                "result": f"{GITHUB}/submissions/causal/{path.name}",
            }
        )
    return results


def _proofrun_results(
    submissions_dir: Path,
    reproductions_path: Path,
    attestations_path: Path,
) -> list[dict]:
    reproduced = _registry_records(reproductions_path, "reproductions")
    attestations = _registry_records(attestations_path, "attestations")
    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _site_eligible(bundle):
            continue
        report = bundle.get("report", {})
        summary = report.get("summary", {})
        resistance = summary.get("attack_resistance", {})
        submission = bundle.get("submission", {})
        provenance = bundle.get("provenance", {})
        digest = bundle.get("bundle_sha256", "")
        tier = _evidence_tier(digest, provenance, attestations, reproduced)
        usage = summary.get("usage", {})
        results.append(
            {
                "agent": report.get("agent", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "agentSource": submission.get("agent_source_url", ""),
                "createdAt": submission.get("created_at", ""),
                "trials": summary.get("trials", 0),
                "rate": resistance.get("rate", 0),
                "lower": resistance.get("lower", 0),
                "upper": resistance.get("upper", 0),
                "unstablePairs": summary.get("unstable_pairs", 0),
                "costUsd": usage.get("estimated_cost_usd"),
                "evidenceTier": tier,
                "runUrl": provenance.get("run_url", ""),
                "result": f"{GITHUB}/submissions/impact/{path.name}",
            }
        )
    tier_rank = {
        "maintainer_reproduced": 3,
        "trusted_builder": 2,
        "github_attested": 1,
        "github_attestation_unverified": 0,
        "self_attested": 0,
    }
    results.sort(key=lambda row: (-tier_rank[row["evidenceTier"]], -row["lower"], row["agent"]))
    return results


def _control_evidence_results(
    submissions_dir: Path,
    reproductions_path: Path,
    attestations_path: Path,
) -> list[dict]:
    """Build public control rows without trusting claimed evidence tiers."""
    reproduced = _registry_records(reproductions_path, "reproductions")
    attestations = _registry_records(attestations_path, "attestations")
    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _site_control_eligible(bundle):
            continue
        report = bundle["report"]
        summary = report["summary"]
        submission = bundle["submission"]
        provenance = bundle.get("provenance", {})
        policy = report["policy"]
        digest = bundle["bundle_sha256"]
        usage = summary.get("usage", {})
        results.append(
            {
                "agent": report.get("agent", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "agentSource": submission.get("agent_source_url", ""),
                "policy": policy.get("name", "unknown"),
                "policySha256": policy.get("sha256", ""),
                "policySource": submission.get("policy_source_url", ""),
                "createdAt": submission.get("created_at", ""),
                "trials": summary.get("trials", 0),
                "containment": _estimate(summary.get("harm_containment_efficacy")),
                "recovery": _estimate(summary.get("safe_mission_recovery")),
                "cleanPreservation": _estimate(summary.get("clean_utility_preservation")),
                "controlledResistance": _estimate(summary.get("controlled_attack_resistance")),
                "unstablePairs": summary.get("unstable_pairs", 0),
                "riskReductionUsd": summary.get("mean_synthetic_funds_risk_reduction_usd", 0),
                "estimatedCostDeltaUsd": usage.get("estimated_cost_delta_usd"),
                "evidenceTier": _evidence_tier(digest, provenance, attestations, reproduced),
                "runUrl": provenance.get("run_url", ""),
                "result": f"{GITHUB}/submissions/control/{path.name}",
            }
        )
    tier_rank = {
        "maintainer_reproduced": 3,
        "trusted_builder": 2,
        "github_attested": 1,
        "github_attestation_unverified": 0,
        "self_attested": 0,
    }
    results.sort(
        key=lambda row: (
            -tier_rank[row["evidenceTier"]],
            -_lower(row["containment"]),
            row["agent"],
            row["policy"],
        )
    )
    return results


def _incident_evidence_results(
    submissions_dir: Path,
    reproductions_path: Path,
    attestations_path: Path,
) -> list[dict]:
    """Build public IncidentTwin rows without trusting claimed evidence tiers."""
    reproduced = _registry_records(reproductions_path, "reproductions")
    attestations = _registry_records(attestations_path, "attestations")
    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _site_incident_eligible(bundle):
            continue
        report = bundle["report"]
        summary = report["summary"]
        submission = bundle["submission"]
        provenance = bundle.get("provenance", {})
        digest = bundle["bundle_sha256"]
        results.append(
            {
                "agent": report.get("agent", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "createdAt": submission.get("created_at", ""),
                "trials": summary.get("trials", 0),
                "attackResistance": _estimate(summary.get("attack_resistance")),
                "harmFree": _estimate(summary.get("harm_free")),
                "cleanUtility": _estimate(summary.get("clean_mission_utility")),
                "unstablePairs": summary.get("unstable_pairs", 0),
                "evidenceTier": _evidence_tier(digest, provenance, attestations, reproduced),
                "result": f"{GITHUB}/submissions/incident/{path.name}",
            }
        )
    tier_rank = {
        "maintainer_reproduced": 3,
        "trusted_builder": 2,
        "github_attested": 1,
        "github_attestation_unverified": 0,
        "self_attested": 0,
    }
    results.sort(
        key=lambda row: (
            -tier_rank[row["evidenceTier"]],
            -_lower(row["attackResistance"]),
            row["agent"],
        )
    )
    return results


def _source_evidence_results(
    submissions_dir: Path,
    reproductions_path: Path,
    attestations_path: Path,
) -> list[dict]:
    """Build public MissionPack rows without trusting claimed evidence tiers."""
    reproduced = _registry_records(reproductions_path, "reproductions")
    attestations = _registry_records(attestations_path, "attestations")
    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _site_source_eligible(bundle):
            continue
        report = bundle["report"]
        summary = report["summary"]
        submission = bundle["submission"]
        provenance = bundle.get("provenance", {})
        digest = bundle["bundle_sha256"]
        results.append(
            {
                "agent": report.get("agent", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "packId": report.get("pack_id", "unknown"),
                "packSha256": report.get("pack_sha256", ""),
                "createdAt": submission.get("created_at", ""),
                "trials": summary.get("trials", 0),
                "attackResistance": _estimate(summary.get("attack_resistance")),
                "faithfulness": _estimate(summary.get("citation_faithfulness")),
                "completeness": _estimate(summary.get("citation_completeness")),
                "sufficiency": _estimate(summary.get("citation_sufficiency")),
                "sourcePreference": _estimate(summary.get("authoritative_source_preference")),
                "unstablePairs": summary.get("unstable_pairs", 0),
                "evidenceTier": _evidence_tier(digest, provenance, attestations, reproduced),
                "result": f"{GITHUB}/submissions/source/{path.name}",
            }
        )
    tier_rank = {
        "maintainer_reproduced": 3,
        "trusted_builder": 2,
        "github_attested": 1,
        "github_attestation_unverified": 0,
        "self_attested": 0,
    }
    results.sort(
        key=lambda row: (
            -tier_rank[row["evidenceTier"]],
            -_lower(row["attackResistance"]),
            row["agent"],
        )
    )
    return results


def _authority_evidence_results(
    submissions_dir: Path,
    reproductions_path: Path,
    attestations_path: Path,
) -> list[dict]:
    """Build public AuthorityTwin rows without trusting claimed evidence tiers."""
    reproduced = _registry_records(reproductions_path, "reproductions")
    attestations = _registry_records(attestations_path, "attestations")
    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _site_authority_eligible(bundle):
            continue
        report = bundle["report"]
        summary = report["summary"]
        submission = bundle["submission"]
        provenance = bundle.get("provenance", {})
        digest = bundle["bundle_sha256"]
        results.append(
            {
                "adapter": report.get("adapter", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "adapterSource": submission.get("adapter_source_url", ""),
                "createdAt": submission.get("created_at", ""),
                "trials": summary.get("trials", 0),
                "attackResistance": _estimate(summary.get("attack_resistance")),
                "harmContainment": _estimate(summary.get("harm_containment")),
                "cleanUtility": _estimate(summary.get("clean_mission_utility")),
                "decisionAccuracy": _estimate(summary.get("injected_authorization_accuracy")),
                "receiptIntegrity": _estimate(summary.get("receipt_integrity")),
                "falseAllows": summary.get("false_allows", 0),
                "unstablePairs": summary.get("unstable_pairs", 0),
                "evidenceTier": _evidence_tier(digest, provenance, attestations, reproduced),
                "result": f"{GITHUB}/submissions/authority/{path.name}",
            }
        )
    tier_rank = {
        "maintainer_reproduced": 3,
        "trusted_builder": 2,
        "github_attested": 1,
        "github_attestation_unverified": 0,
        "self_attested": 0,
    }
    results.sort(
        key=lambda row: (
            -tier_rank[row["evidenceTier"]],
            -_lower(row["attackResistance"]),
            row["adapter"],
        )
    )
    return results


def _trace_evidence_results(submissions_dir: Path) -> list[dict]:
    """Build public TraceProof rows from CI-admitted privacy-bounded bundles."""
    results = []
    for path, bundle in _submission_bundles(submissions_dir):
        if not _site_trace_eligible(bundle):
            continue
        evidence = bundle["evidence"]
        report = bundle["report"]
        summary = report["summary"]
        submission = bundle["submission"]
        policy = evidence.get("policy", {})
        mcp_report = bundle.get("mcp_report")
        mcp_summary = mcp_report.get("summary", {}) if isinstance(mcp_report, dict) else {}
        results.append(
            {
                "runtime": submission.get("runtime", "unknown"),
                "submitter": submission.get("submitter", "unknown"),
                "createdAt": submission.get("created_at", ""),
                "traceCount": summary.get("trace_count", 0),
                "spanCount": summary.get("span_count", 0),
                "findingCount": summary.get("finding_count", 0),
                "critical": summary.get("critical", 0),
                "high": summary.get("high", 0),
                "policyId": policy.get("policy_id", "unknown"),
                "mcpRequiredPass": mcp_summary.get("required_pass_count"),
                "mcpRequiredCount": mcp_summary.get("required_check_count"),
                "mcpConformanceReady": mcp_summary.get("conformance_ready"),
                "evidenceTier": "self_attested",
                "result": f"{GITHUB}/submissions/trace/{path.name}",
            }
        )
    results.sort(key=lambda row: (-row["spanCount"], row["runtime"], row["submitter"]))
    return results


def _registry_records(path: Path, key: str) -> dict:
    if not _ordinary_input(path):
        return {}
    try:
        payload = read_json_object(path, 5_000_000)
    except (OSError, ValueError):
        return {}
    return payload[key] if registry_shape(payload, key) else {}


def _ordinary_input(path: Path) -> bool:
    return path.is_file() and not any(item.is_symlink() for item in (path, *path.parents))


def _submission_bundles(directory: Path):
    if any(item.is_symlink() for item in (directory, *directory.parents)):
        return
    for path in sorted(directory.glob("*.json")):
        if not _ordinary_input(path):
            continue
        try:
            yield path, read_json_object(path, 50_000_000)
        except (OSError, ValueError):
            continue


def _evidence_tier(digest: str, provenance: dict, attestations: dict, reproduced: dict) -> str:
    provenance = provenance if isinstance(provenance, dict) else {}
    tier = (
        "github_attestation_unverified"
        if provenance.get("provider") == "github_actions"
        else "self_attested"
    )
    verified = attestations.get(digest, {})
    if not attestation_record_errors(verified, provenance):
        tier = verified["evidence_tier"]
    if digest in reproduced and not reproduction_record_errors(reproduced[digest]):
        tier = "maintainer_reproduced"
    return tier


def _estimate(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return {
        "rate": value.get("rate", 0),
        "lower": value.get("lower", 0),
        "upper": value.get("upper", 0),
    }


def _lower(estimate: dict | None) -> float:
    return float(estimate.get("lower", 0)) if estimate else -1.0


def _native_eligible(bundle, bundle_type: str) -> bool:
    """Full offline native admission; no model calls or signature lookup."""
    if not isinstance(bundle, dict) or bundle.get("bundle_type") != bundle_type:
        return False
    structural = {
        "dspy-security-bench-traceproof-community-evidence": ("dspy_security_bench.trace.evidence", "verify_trace_submission_bundle"),
        "dspy-security-bench-causal-submission": ("dspy_security_bench.causal.registry", "verify_causal_submission_bundle"),
        "dspy-security-bench-collective-submission": ("dspy_security_bench.collective.registry", "verify_collective_submission_bundle"),
        "dspy-security-bench-defense-evidence": ("dspy_security_bench.defend.evidence", "verify_evidence_bundle"),
    }
    if bundle_type in FAMILIES:
        module_name, function_name, eligibility_field, _ = FAMILIES[bundle_type]
    else:
        module_name, function_name = structural[bundle_type]
        eligibility_field = "community_eligible"
    # Missing verifier dependencies are build errors, not a reason to silently
    # drop all rows. Data-derived verifier failures only reject that input.
    verify = getattr(importlib.import_module(module_name), function_name)
    try:
        result = verify(bundle)
        return not result.errors and getattr(result, "valid", True) and getattr(result, eligibility_field)
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        return False


def _site_eligible(bundle: dict) -> bool:
    return _native_eligible(bundle, "dspy-security-bench-community-submission")


def _site_control_eligible(bundle: dict) -> bool:
    return _native_eligible(bundle, "dspy-security-bench-control-evidence-submission")


def _site_incident_eligible(bundle: dict) -> bool:
    return _native_eligible(bundle, "dspy-security-bench-incident-evidence-submission")


def _site_source_eligible(bundle: dict) -> bool:
    return _native_eligible(bundle, "dspy-security-bench-source-evidence-submission")


def _site_authority_eligible(bundle: dict) -> bool:
    return _native_eligible(bundle, "dspy-security-bench-authority-evidence-submission")


def _site_trace_eligible(bundle: dict) -> bool:
    return _native_eligible(bundle, "dspy-security-bench-traceproof-community-evidence")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    payload = build_payload()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {args.out} ({payload['modelCount']} models)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
