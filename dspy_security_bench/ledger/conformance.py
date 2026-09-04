"""Adversarial mutation conformance matrix for AssuranceLedger verifiers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.consistency import verify_consistency_proof
from dspy_security_bench.ledger.gossip import verify_gossip_report
from dspy_security_bench.ledger.misbehavior import verify_fork_proof
from dspy_security_bench.ledger.observation import verify_observer_report
from dspy_security_bench.ledger.proof import verify_ledger_report
from dspy_security_bench.ledger.rereview import verify_rereview_report
from dspy_security_bench.ledger.trust_chain import verify_trust_root_chain_report
from dspy_security_bench.ledger.trust_root import verify_trust_root_report
from dspy_security_bench.ledger.witness_conflict import verify_witness_conflict_report
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AssuranceLedger VerifierConformance / Adversarial mutation matrix"
PROTOCOL_VERSION = "assuranceledger-verifier-conformance-v4"
RUNNER = "deterministic-rehashed-semantic-mutation-runner-v4"
MAX_ARTIFACT_BYTES = 100_000_000
ARTIFACT_FILES = {
    "ledger": "current-trust.report.json",
    "gossip": "view-comparison.report.json",
    "rereview": "rereview-plan.report.json",
    "fork_proof": "fork-proof.report.json",
    "consistency_proof": "consistency-proof.report.json",
    "observer": "observer-comparison.report.json",
    "witness_conflict": "witness-conflict.report.json",
    "trust_root": "trust-root.report.json",
    "trust_chain": "trust-root-chain.report.json",
    "capability_manifest": "capability-manifest.json",
    "integration_lock": "integration-lock.json",
    "integration_lock_check": "integration-lock-check.report.json",
}
CLAIM_BOUNDARY = (
    "AssuranceLedger VerifierConformance applies eleven deterministic, rehashed adversarial "
    "mutations to valid local reference artifacts and confirms each native verifier rejects "
    "the intended semantic or cryptographic violation. Passing demonstrates behavior for these "
    "exact vectors only; it is not a security proof, implementation certification, fuzzing "
    "result, interoperability claim, compliance determination, authorization to operate, or "
    "deployment approval."
)
LIMITATIONS = (
    "The matrix is finite and deterministic; it cannot establish the absence of untested verifier flaws.",
    "Inputs must first be valid reference artifacts generated or supplied by the caller.",
    "A passing result applies to the exact verifier code and artifact digests recorded in the report.",
    "The runner performs no network access, deployment action, notification, revocation, or risk acceptance.",
)


def load_conformance_artifacts(artifact_dir: str | Path) -> dict[str, dict[str, Any]]:
    import json

    root = Path(artifact_dir)
    artifacts = {}
    for name, filename in ARTIFACT_FILES.items():
        path = root / filename
        if not path.is_file():
            raise ValueError(f"{filename} must be a regular file")
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError(f"{filename} exceeds {MAX_ARTIFACT_BYTES} bytes")
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            raise ValueError(f"{filename} must contain a JSON object")
        artifacts[name] = payload
    return artifacts


def run_conformance(
    artifacts: Mapping[str, Mapping[str, Any]],
    *,
    evidence_root: str | Path,
    schema_root: str | Path | None = None,
) -> dict[str, Any]:
    from dspy_security_bench.ledger.capabilities import verify_capability_manifest
    from dspy_security_bench.ledger.integration_lock import verify_integration_lock_check

    missing = set(ARTIFACT_FILES) - set(artifacts)
    extra = set(artifacts) - set(ARTIFACT_FILES)
    if missing or extra:
        raise ValueError(
            f"artifact set mismatch: missing={sorted(missing)}, unexpected={sorted(extra)}"
        )
    source_verifiers: dict[str, Callable[[Mapping[str, Any]], tuple[str, ...]]] = {
        "ledger": lambda value: verify_ledger_report(value, evidence_root=evidence_root),
        "gossip": lambda value: verify_gossip_report(value, evidence_root=evidence_root),
        "rereview": lambda value: verify_rereview_report(value, evidence_root=evidence_root),
        "fork_proof": verify_fork_proof,
        "consistency_proof": verify_consistency_proof,
        "observer": verify_observer_report,
        "witness_conflict": verify_witness_conflict_report,
        "trust_root": verify_trust_root_report,
        "trust_chain": verify_trust_root_chain_report,
        "capability_manifest": lambda value: verify_capability_manifest(value, schema_root),
        "integration_lock_check": lambda value: verify_integration_lock_check(
            value,
            artifacts["integration_lock"],
            artifacts["capability_manifest"],
            schema_root,
        ),
    }
    for artifact_kind, verifier in source_verifiers.items():
        if errors := verifier(artifacts[artifact_kind]):
            raise ValueError(f"source artifact {artifact_kind} is not valid: {'; '.join(errors)}")
    cases = [
        _case(
            "fork-root-signature-binding",
            "fork_proof",
            artifacts["fork_proof"],
            _mutate_fork_root,
            verify_fork_proof,
            "operator signature Ed25519 signature is invalid",
        ),
        _case(
            "consistency-path-root-reconstruction",
            "consistency_proof",
            artifacts["consistency_proof"],
            _mutate_consistency_path,
            verify_consistency_proof,
            "does not reconstruct",
        ),
        _case(
            "observer-signature-semantic-recompute",
            "observer",
            artifacts["observer"],
            _mutate_observer_signature,
            verify_observer_report,
            "ObserverReceipt report does not recompute exactly",
        ),
        _case(
            "witness-attribution-semantic-recompute",
            "witness_conflict",
            artifacts["witness_conflict"],
            _mutate_witness_summary,
            verify_witness_conflict_report,
            "WitnessConflict report does not recompute exactly",
        ),
        _case(
            "trust-root-threshold-signature-recompute",
            "trust_root",
            artifacts["trust_root"],
            _mutate_trust_root_signature,
            verify_trust_root_report,
            "AssuranceTrustRoot report does not recompute exactly",
        ),
        _case(
            "trust-chain-hop-count-recompute",
            "trust_chain",
            artifacts["trust_chain"],
            _mutate_trust_chain_hop_count,
            verify_trust_root_chain_report,
            "AssuranceTrustRootChain report does not recompute exactly",
        ),
        _case(
            "rereview-impact-semantic-recompute",
            "rereview",
            artifacts["rereview"],
            _mutate_rereview_summary,
            lambda value: verify_rereview_report(value, evidence_root=evidence_root),
            "ReReview report does not recompute exactly",
        ),
        _case(
            "gossip-outcome-semantic-recompute",
            "gossip",
            artifacts["gossip"],
            _mutate_gossip_summary,
            lambda value: verify_gossip_report(value, evidence_root=evidence_root),
            "AssuranceLedger Gossip report does not recompute exactly",
        ),
        _case(
            "ledger-checkpoint-signature-binding",
            "ledger",
            artifacts["ledger"],
            _mutate_ledger_signature,
            lambda value: verify_ledger_report(value, evidence_root=evidence_root),
            "AssuranceLedger report does not recompute exactly",
        ),
        _case(
            "capability-contract-semantic-recompute",
            "capability_manifest",
            artifacts["capability_manifest"],
            _mutate_capability_contract,
            lambda value: verify_capability_manifest(value, schema_root),
            "CapabilityManifest does not match local schemas and capabilities",
            digest_field="manifest_sha256",
        ),
        _case(
            "integration-lock-check-semantic-recompute",
            "integration_lock_check",
            artifacts["integration_lock_check"],
            _mutate_integration_lock_status,
            lambda value: verify_integration_lock_check(
                value,
                artifacts["integration_lock"],
                artifacts["capability_manifest"],
                schema_root,
            ),
            "IntegrationLockCheck does not recompute exactly",
        ),
    ]
    passed = sum(item["status"] == "expected_rejection_observed" for item in cases)
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "runner": RUNNER,
        "source_artifact_sha256": {
            name: canonical_sha256(artifacts[name]) for name in sorted(ARTIFACT_FILES)
        },
        "cases": cases,
        "summary": {
            "status": "conformance_passed" if passed == len(cases) else "conformance_failed",
            "case_count": len(cases),
            "expected_rejections_observed": passed,
            "unexpected_acceptances": len(cases) - passed,
            "automatic_actions": 0,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_conformance_report(
    report: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    *,
    evidence_root: str | Path,
    schema_root: str | Path | None = None,
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report must be an object",)
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger VerifierConformance report")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        expected = run_conformance(artifacts, evidence_root=evidence_root, schema_root=schema_root)
    except (TypeError, ValueError) as exc:
        errors.append(f"report cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("VerifierConformance report does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def _case(
    case_id: str,
    artifact_kind: str,
    original: Mapping[str, Any],
    mutate: Callable[[dict[str, Any]], None],
    verify: Callable[[Mapping[str, Any]], tuple[str, ...]],
    expected_error_fragment: str,
    *,
    digest_field: str = "report_sha256",
) -> dict[str, Any]:
    tampered = deepcopy(dict(original))
    mutate(tampered)
    _rehash(tampered, digest_field=digest_field)
    errors = list(verify(tampered))
    detected = any(expected_error_fragment in item for item in errors)
    return {
        "case_id": case_id,
        "artifact_kind": artifact_kind,
        "mutation_sha256": canonical_sha256(tampered),
        "expected_error_fragment": expected_error_fragment,
        "status": "expected_rejection_observed" if detected else "unexpected_acceptance",
        "verifier_errors": errors,
    }


def _rehash(payload: dict[str, Any], *, digest_field: str = "report_sha256") -> None:
    payload.pop(digest_field, None)
    payload[digest_field] = canonical_sha256(payload)


def _mutate_fork_root(payload: dict[str, Any]) -> None:
    payload["checkpoints"][1]["signed_checkpoint"]["checkpoint"]["root_sha256"] = "a" * 64
    payload["finding"]["right_root_sha256"] = "a" * 64


def _mutate_consistency_path(payload: dict[str, Any]) -> None:
    payload["consistency"]["path_sha256"][0] = "a" * 64


def _mutate_observer_signature(payload: dict[str, Any]) -> None:
    payload["receipts"][0]["observer_signature"]["signature_base64"] = "aW52YWxpZA=="


def _mutate_witness_summary(payload: dict[str, Any]) -> None:
    payload["summary"]["shared_witness_keys"] = 0


def _mutate_trust_root_signature(payload: dict[str, Any]) -> None:
    root = payload["candidate_root"]
    root["signatures"][0]["signature_base64"] = "aW52YWxpZA=="
    root.pop("root_sha256")
    root["root_sha256"] = canonical_sha256(root)


def _mutate_trust_chain_hop_count(payload: dict[str, Any]) -> None:
    payload["summary"]["transitions_verified"] -= 1


def _mutate_rereview_summary(payload: dict[str, Any]) -> None:
    payload["summary"]["claims_requiring_rereview"] = 0


def _mutate_gossip_summary(payload: dict[str, Any]) -> None:
    payload["summary"]["status"] = "views_consistent"


def _mutate_ledger_signature(payload: dict[str, Any]) -> None:
    payload["checkpoint"]["operator_signature"]["signature_base64"] = "aW52YWxpZA=="


def _mutate_capability_contract(payload: dict[str, Any]) -> None:
    payload["protocols"][0]["network_required"] = True


def _mutate_integration_lock_status(payload: dict[str, Any]) -> None:
    payload["summary"]["status"] = "capability_drift"
