"""Build the website's compact data payload from committed leaderboard results.

The website never owns benchmark numbers. This generator joins security runs in
``leaderboard/results/*.json`` with the matching no-attack capability evidence
in ``leaderboard/benign/*.json`` so the interactive experience and
``LEADERBOARD.md`` remain views over the same committed evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "leaderboard/results"
BENIGN_DIR = ROOT / "leaderboard/benign"
SUBMISSIONS_DIR = ROOT / "submissions/impact"
CONTROL_SUBMISSIONS_DIR = ROOT / "submissions/control"
REPRODUCTIONS = ROOT / "submissions/reproductions.json"
ATTESTATIONS = ROOT / "submissions/attestations.json"
DEFAULT_OUT = ROOT / "site/data.json"
GITHUB = "https://github.com/immu4989/dspy-security-bench/blob/main"


def build_payload(
    results_dir: Path = RESULTS_DIR,
    benign_dir: Path = BENIGN_DIR,
    submissions_dir: Path = SUBMISSIONS_DIR,
    control_submissions_dir: Path = CONTROL_SUBMISSIONS_DIR,
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
    }


def _proofrun_results(
    submissions_dir: Path,
    reproductions_path: Path,
    attestations_path: Path,
) -> list[dict]:
    reproduced = {}
    if reproductions_path.is_file():
        registry = json.loads(reproductions_path.read_text())
        reproduced = registry.get("reproductions", {})
    attestations = {}
    if attestations_path.is_file():
        registry = json.loads(attestations_path.read_text())
        attestations = registry.get("attestations", {})
    results = []
    for path in sorted(submissions_dir.glob("*.json")):
        bundle = json.loads(path.read_text())
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
    for path in sorted(submissions_dir.glob("*.json")):
        bundle = json.loads(path.read_text())
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


def _registry_records(path: Path, key: str) -> dict:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text())
    records = payload.get(key, {})
    return records if isinstance(records, dict) else {}


def _evidence_tier(digest: str, provenance: dict, attestations: dict, reproduced: dict) -> str:
    tier = (
        "github_attestation_unverified"
        if provenance.get("provider") == "github_actions"
        else "self_attested"
    )
    verified = attestations.get(digest, {})
    if verified.get("evidence_tier") in {"github_attested", "trusted_builder"}:
        tier = verified["evidence_tier"]
    if digest in reproduced:
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


def _site_eligible(bundle: dict) -> bool:
    """Apply dependency-free admission checks; submission CI performs full recomputation."""
    claimed = bundle.get("bundle_sha256")
    unsigned = dict(bundle)
    unsigned.pop("bundle_sha256", None)
    try:
        encoded = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        return False
    if claimed != hashlib.sha256(encoded).hexdigest():
        return False
    report = bundle.get("report")
    if not isinstance(report, dict):
        return False
    trials = report.get("trials")
    return (
        isinstance(trials, list)
        and len(trials) >= 5
        and report.get("trial_isolation") == "fresh_agent_per_case"
        and not str(report.get("agent", "")).startswith("reference-")
    )


def _site_control_eligible(bundle: dict) -> bool:
    """Apply safe display checks; submission CI performs complete recomputation."""
    if bundle.get("bundle_type") != "dspy-security-bench-control-evidence-submission":
        return False
    claimed = bundle.get("bundle_sha256")
    unsigned = dict(bundle)
    unsigned.pop("bundle_sha256", None)
    try:
        encoded = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        return False
    if claimed != hashlib.sha256(encoded).hexdigest():
        return False
    report = bundle.get("report")
    if not isinstance(report, dict):
        return False
    policy = report.get("policy")
    trials = report.get("trials")
    return (
        isinstance(policy, dict)
        and policy.get("arguments_captured") is False
        and isinstance(trials, list)
        and len(trials) >= 5
        and report.get("trial_isolation") == "fresh_agent_per_case_and_condition"
        and not str(report.get("agent", "")).startswith("reference-")
        and _control_runtime_errors(report) == 0
    )


def _control_runtime_errors(report: dict) -> int:
    total = 0
    for record in report.get("trials", []):
        control = record.get("control", {}) if isinstance(record, dict) else {}
        for condition in ("baseline", "controlled"):
            impact = control.get(condition, {}) if isinstance(control, dict) else {}
            for pair in impact.get("pairs", []) if isinstance(impact, dict) else []:
                if not isinstance(pair, dict):
                    continue
                for case_name in ("clean", "injected"):
                    case = pair.get(case_name)
                    total += bool(isinstance(case, dict) and case.get("error"))
    return total


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
