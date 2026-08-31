"""AssuranceQuorum command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from dspy_security_bench.assurance.case import analyze_case, built_in_case, seal_case
from dspy_security_bench.assurance.cli import _demo_evidence
from dspy_security_bench.mission.commons import generate_ed25519_keypair
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.quorum.proof import (
    DECISIONS,
    PRESETS,
    REASON_CODES,
    analyze_quorum,
    build_policy,
    reviewer_from_public_key,
    sign_review,
    verify_quorum_report,
)
from dspy_security_bench.quorum.sarif import report_to_sarif

MAX_JSON_BYTES = 50_000_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench quorum",
        description="Create role-separated, DSSE-signed review evidence for AssuranceGraph.",
    )
    commands = parser.add_subparsers(dest="command")
    keygen = commands.add_parser("keygen", help="create an Ed25519 reviewer keypair")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    policy = commands.add_parser(
        "policy-init", help="bind reviewers and claim requirements to an AssuranceGraph report"
    )
    policy.add_argument("assurance_report")
    policy.add_argument("--evidence-root", required=True)
    policy.add_argument("--policy-id", required=True)
    policy.add_argument("--title", required=True)
    policy.add_argument("--preset", choices=PRESETS, default="independent-two-party")
    policy.add_argument("--not-before", type=int, required=True)
    policy.add_argument("--not-after", type=int, required=True)
    policy.add_argument(
        "--reviewer",
        action="append",
        required=True,
        help="comma-separated signer_id=,role=,organization_id=,public_key= fields",
    )
    policy.add_argument("--out", required=True)
    sign = commands.add_parser("sign", help="sign one role-scoped in-toto review statement")
    sign.add_argument("policy")
    sign.add_argument("assurance_report")
    sign.add_argument("--evidence-root", required=True)
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--signer-id", required=True)
    sign.add_argument("--decision", choices=DECISIONS, required=True)
    sign.add_argument("--claims", required=True, help="comma-separated claim IDs")
    sign.add_argument("--reason-code", action="append", choices=REASON_CODES, required=True)
    sign.add_argument("--issued-at", type=int, required=True)
    sign.add_argument("--expires-at", type=int, required=True)
    sign.add_argument("--out", required=True)
    evaluate = commands.add_parser(
        "evaluate", help="evaluate signed reviews against the quorum policy"
    )
    evaluate.add_argument("policy")
    evaluate.add_argument("assurance_report")
    evaluate.add_argument("reviews", nargs="+")
    evaluate.add_argument("--evidence-root", required=True)
    evaluate.add_argument("--evaluation-time", type=int, required=True)
    evaluate.add_argument("--out", required=True)
    evaluate.add_argument("--sarif-out")
    evaluate.add_argument("--fail-on-review", action="store_true")
    verify = commands.add_parser("verify", help="recompute an AssuranceQuorum report offline")
    verify.add_argument("report")
    verify.add_argument("--evidence-root", required=True)
    demo = commands.add_parser(
        "demo", help="write satisfied and evidence-gap fictional review cases"
    )
    demo.add_argument("--out-dir", required=True)
    demo.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "keygen":
            private, public = generate_ed25519_keypair(args.private_key, args.public_key)
            print(f"[quorum] wrote {private} (0600) and {public}")
            return 0
        if args.command == "policy-init":
            report = _read_json(Path(args.assurance_report))
            reviewers = [_parse_reviewer(item) for item in args.reviewer]
            policy_payload = build_policy(
                report,
                reviewers,
                policy_id=args.policy_id,
                title=args.title,
                not_before=args.not_before,
                not_after=args.not_after,
                preset=args.preset,
                evidence_root=args.evidence_root,
            )
            _write_json(Path(args.out), policy_payload)
            print(f"[quorum] wrote {args.out}")
            return 0
        if args.command == "sign":
            policy_payload = _read_json(Path(args.policy))
            report = _read_json(Path(args.assurance_report))
            envelope = sign_review(
                policy_payload,
                report,
                args.private_key,
                signer_id=args.signer_id,
                decision=args.decision,
                claim_ids=[item for item in args.claims.split(",") if item],
                reason_codes=args.reason_code,
                issued_at=args.issued_at,
                expires_at=args.expires_at,
                evidence_root=args.evidence_root,
            )
            _write_json(Path(args.out), envelope)
            print(f"[quorum] wrote role-scoped DSSE review {args.out}")
            return 0
        if args.command == "evaluate":
            policy_payload = _read_json(Path(args.policy))
            report = _read_json(Path(args.assurance_report))
            reviews = [_read_json(Path(item)) for item in args.reviews]
            result = analyze_quorum(
                policy_payload,
                report,
                reviews,
                evidence_root=args.evidence_root,
                evaluation_time=args.evaluation_time,
            )
            _write_json(Path(args.out), result)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), report_to_sarif(result))
            print(f"[quorum] {result['summary']['status']}: wrote {args.out}")
            return int(args.fail_on_review and result["summary"]["status"] != "quorum_satisfied")
        if args.command == "verify":
            report = _read_json(Path(args.report))
            errors = verify_quorum_report(report, evidence_root=args.evidence_root)
            if errors:
                raise ValueError("; ".join(errors))
            print(f"[quorum] verified {args.report}")
            return 0
        if args.command == "demo":
            _demo(Path(args.out_dir), force=args.force)
            return 0
    except (OSError, RuntimeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[quorum] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _demo(out_dir: Path, *, force: bool) -> None:
    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise ValueError(f"output directory is not empty: {out_dir} (use --force)")
    evidence = _demo_evidence()
    case = built_in_case("critical-infrastructure")
    case["decision_owner"] = "fictional-accountable-owner"
    for item in case["evidence"]:
        payload = evidence[item["evidence_kind"]]
        target = out_dir / item["path"]
        _write_json(target, payload)
        item["expected_sha256"] = canonical_sha256(payload)
        item["owner"] = "fictional-evidence-owner"
    case = seal_case(case)
    assurance_report = analyze_case(case, out_dir)
    _write_json(out_dir / "assurance-case.json", case)
    _write_json(out_dir / "assurance-report.json", assurance_report)
    roles = (
        "system-owner",
        "evaluation-owner",
        "security-reviewer",
        "privacy-reviewer",
        "mission-owner",
        "independent-reviewer",
    )
    with tempfile.TemporaryDirectory(prefix="assurance-quorum-demo-") as temp:
        key_root = Path(temp)
        reviewers = []
        private_paths: dict[str, Path] = {}
        for index, role in enumerate(roles):
            private = key_root / f"{role}.private.pem"
            public = key_root / f"{role}.public.pem"
            generate_ed25519_keypair(private, public)
            signer_id = f"fictional-{role}"
            private_paths[signer_id] = private
            reviewers.append(
                reviewer_from_public_key(
                    public,
                    signer_id=signer_id,
                    role=role,
                    organization_id=f"fictional-organization-{index + 1}",
                )
            )
        policy = build_policy(
            assurance_report,
            reviewers,
            policy_id="fictional-critical-service-review",
            title="Fictional separated assurance review policy",
            not_before=1_788_048_000,
            not_after=1_788_134_400,
            preset="federal-separation",
            evidence_root=out_dir,
        )
        _write_json(out_dir / "quorum-policy.json", policy)
        required_by_role = {
            role: [
                item["claim_id"]
                for item in policy["claim_requirements"]
                if role in item["required_roles"]
            ]
            for role in roles
        }
        satisfied_reviews = []
        gap_reviews = []
        for reviewer in reviewers:
            signer_id = reviewer["signer_id"]
            claims = required_by_role[reviewer["role"]]
            if not claims:
                continue
            sufficient = sign_review(
                policy,
                assurance_report,
                private_paths[signer_id],
                signer_id=signer_id,
                decision="evidence-sufficient",
                claim_ids=claims,
                reason_codes=[
                    "boundary-reviewed",
                    "claim-predicates-reviewed",
                    "native-verification-reviewed",
                ],
                issued_at=1_788_048_100,
                expires_at=1_788_134_300,
                evidence_root=out_dir,
            )
            satisfied_reviews.append(sufficient)
            decision = (
                "evidence-gap"
                if reviewer["role"] == "independent-reviewer"
                else "evidence-sufficient"
            )
            reasons = (
                ["insufficient-source-independence"]
                if decision == "evidence-gap"
                else ["native-verification-reviewed"]
            )
            gap_reviews.append(
                sign_review(
                    policy,
                    assurance_report,
                    private_paths[signer_id],
                    signer_id=signer_id,
                    decision=decision,
                    claim_ids=claims,
                    reason_codes=reasons,
                    issued_at=1_788_048_100,
                    expires_at=1_788_134_300,
                    evidence_root=out_dir,
                )
            )
        review_dir = out_dir / "reviews"
        for index, envelope in enumerate(satisfied_reviews, start=1):
            _write_json(review_dir / f"satisfied-{index:02d}.dsse.json", envelope)
        satisfied = analyze_quorum(
            policy,
            assurance_report,
            satisfied_reviews,
            evidence_root=out_dir,
            evaluation_time=1_788_048_200,
        )
        gap = analyze_quorum(
            policy,
            assurance_report,
            gap_reviews,
            evidence_root=out_dir,
            evaluation_time=1_788_048_200,
        )
        _write_json(out_dir / "quorum-satisfied.report.json", satisfied)
        _write_json(out_dir / "quorum-satisfied.sarif", report_to_sarif(satisfied))
        _write_json(out_dir / "review-gap.report.json", gap)
        _write_json(out_dir / "review-gap.sarif", report_to_sarif(gap))
    print(
        "[quorum] quorum_satisfied and review_gap_recorded: wrote fictional review evidence to "
        + str(out_dir)
    )


def _parse_reviewer(spec: str) -> dict[str, Any]:
    fields = {}
    for part in spec.split(","):
        key, separator, value = part.partition("=")
        if not separator or not key or not value:
            raise ValueError("reviewer fields must use key=value")
        fields[key] = value
    required = {"signer_id", "role", "organization_id", "public_key"}
    if set(fields) != required:
        raise ValueError("reviewer requires signer_id, role, organization_id, and public_key")
    return reviewer_from_public_key(
        fields["public_key"],
        signer_id=fields["signer_id"],
        role=fields["role"],
        organization_id=fields["organization_id"],
    )


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"input exceeds {MAX_JSON_BYTES} bytes")
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
