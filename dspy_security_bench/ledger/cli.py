"""AssuranceLedger command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.capabilities import (
    build_capability_manifest,
    verify_capability_manifest,
)
from dspy_security_bench.ledger.conformance import (
    load_conformance_artifacts,
    run_conformance,
    verify_conformance_report,
)
from dspy_security_bench.ledger.conformance_sarif import (
    report_to_sarif as conformance_to_sarif,
)
from dspy_security_bench.ledger.consistency import (
    export_consistency_proof,
    verify_consistency_proof,
)
from dspy_security_bench.ledger.consistency_sarif import (
    report_to_sarif as consistency_to_sarif,
)
from dspy_security_bench.ledger.gossip import compare_views, verify_gossip_report
from dspy_security_bench.ledger.gossip_sarif import report_to_sarif as gossip_to_sarif
from dspy_security_bench.ledger.integration_lock import (
    build_integration_lock,
    check_integration_lock,
    verify_integration_lock_check,
)
from dspy_security_bench.ledger.integration_lock_sarif import (
    report_to_sarif as integration_lock_to_sarif,
)
from dspy_security_bench.ledger.misbehavior import export_fork_proof, verify_fork_proof
from dspy_security_bench.ledger.misbehavior_sarif import report_to_sarif as fork_to_sarif
from dspy_security_bench.ledger.observation import (
    CHANNEL_CLASSES,
    analyze_observer_receipts,
    build_observer_policy,
    create_observer_receipt,
    verify_observer_report,
)
from dspy_security_bench.ledger.observation_sarif import (
    report_to_sarif as observation_to_sarif,
)
from dspy_security_bench.ledger.proof import (
    analyze_ledger,
    build_policy,
    cosign_checkpoint,
    create_checkpoint,
    key_descriptor,
    make_registration_event,
    make_review_event,
    make_revocation_event,
    verify_ledger_report,
)
from dspy_security_bench.ledger.rereview import (
    HISTORICAL_POLICIES,
    plan_rereview,
    verify_rereview_report,
)
from dspy_security_bench.ledger.rereview_sarif import report_to_sarif as rereview_to_sarif
from dspy_security_bench.ledger.sarif import report_to_sarif
from dspy_security_bench.ledger.witness_conflict import (
    analyze_witness_conflict,
    verify_witness_conflict_report,
)
from dspy_security_bench.ledger.witness_conflict_sarif import (
    report_to_sarif as witness_conflict_to_sarif,
)
from dspy_security_bench.mission.commons import generate_ed25519_keypair
from dspy_security_bench.quorum.cli import _demo as quorum_demo

MAX_JSON_BYTES = 100_000_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench ledger",
        description="Verify witnessed append-only reviewer-key lifecycle evidence.",
    )
    commands = parser.add_subparsers(dest="command")
    evaluate = commands.add_parser("evaluate", help="evaluate a self-contained ledger bundle")
    evaluate.add_argument("bundle")
    evaluate.add_argument("--evidence-root", required=True)
    evaluate.add_argument("--evaluation-time", required=True, type=int)
    evaluate.add_argument("--out", required=True)
    evaluate.add_argument("--sarif-out")
    evaluate.add_argument("--fail-on-trust", action="store_true")
    verify = commands.add_parser("verify", help="recompute an AssuranceLedger report offline")
    verify.add_argument("report")
    verify.add_argument("--evidence-root", required=True)
    compare = commands.add_parser(
        "compare", help="compare independently obtained ledger views for a fork"
    )
    compare.add_argument("reports", nargs="+")
    compare.add_argument("--evidence-root", required=True)
    compare.add_argument("--out", required=True)
    compare.add_argument("--sarif-out")
    compare.add_argument("--fail-on-fork", action="store_true")
    gossip_verify = commands.add_parser(
        "verify-comparison", help="recompute a saved cross-view comparison"
    )
    gossip_verify.add_argument("report")
    gossip_verify.add_argument("--evidence-root", required=True)
    fork_export = commands.add_parser(
        "export-fork-proof",
        help="minimize a verified same-size fork into an offline disclosure artifact",
    )
    fork_export.add_argument("comparison_report")
    fork_export.add_argument("--evidence-root", required=True)
    fork_export.add_argument("--out", required=True)
    fork_export.add_argument("--sarif-out")
    fork_verify = commands.add_parser(
        "verify-fork-proof",
        help="verify a compact fork proof without source ledgers",
    )
    fork_verify.add_argument("report")
    consistency_export = commands.add_parser(
        "export-consistency-proof",
        help="prove a newer checkpoint extends an older one without embedding log entries",
    )
    consistency_export.add_argument("older_report")
    consistency_export.add_argument("newer_report")
    consistency_export.add_argument("--evidence-root", required=True)
    consistency_export.add_argument("--out", required=True)
    consistency_export.add_argument("--sarif-out")
    consistency_verify = commands.add_parser(
        "verify-consistency-proof",
        help="verify compact append-only evidence without source ledgers",
    )
    consistency_verify.add_argument("report")
    observe = commands.add_parser(
        "observe", help="sign a privacy-bounded receipt for one verified ledger view"
    )
    observe.add_argument("ledger_report")
    observe.add_argument("--observer-policy", required=True)
    observe.add_argument("--observer-private-key", required=True)
    observe.add_argument("--observer-id", required=True)
    observe.add_argument("--channel-class", choices=CHANNEL_CLASSES, required=True)
    observe.add_argument("--channel-locator", required=True)
    observe.add_argument("--observed-at", type=int, required=True)
    observe.add_argument("--evidence-root", required=True)
    observe.add_argument("--out", required=True)
    receipt_compare = commands.add_parser(
        "compare-receipts", help="verify observer receipts and declared source independence"
    )
    receipt_compare.add_argument("receipts", nargs="+")
    receipt_compare.add_argument("--observer-policy", required=True)
    receipt_compare.add_argument("--ledger-policy", required=True)
    receipt_compare.add_argument("--out", required=True)
    receipt_compare.add_argument("--sarif-out")
    receipt_compare.add_argument("--fail-on-fork", action="store_true")
    receipt_verify = commands.add_parser(
        "verify-receipt-comparison", help="recompute a saved observer-receipt analysis"
    )
    receipt_verify.add_argument("report")
    witness_conflict = commands.add_parser(
        "analyze-witness-conflict",
        help="attribute witness keys that signed both sides of a compact fork proof",
    )
    witness_conflict.add_argument("fork_proof")
    witness_conflict.add_argument("--out", required=True)
    witness_conflict.add_argument("--sarif-out")
    witness_conflict_verify = commands.add_parser(
        "verify-witness-conflict", help="recompute saved fork cosignature attribution"
    )
    witness_conflict_verify.add_argument("report")
    conformance = commands.add_parser(
        "conformance",
        help="run deterministic rehashed-tampering vectors against native verifiers",
    )
    conformance.add_argument("artifact_dir")
    conformance.add_argument("--evidence-root", required=True)
    conformance.add_argument("--schema-root")
    conformance.add_argument("--out", required=True)
    conformance.add_argument("--sarif-out")
    conformance.add_argument("--fail-on-miss", action="store_true")
    conformance_verify = commands.add_parser(
        "verify-conformance", help="recompute a saved verifier-conformance matrix"
    )
    conformance_verify.add_argument("report")
    conformance_verify.add_argument("--artifact-dir", required=True)
    conformance_verify.add_argument("--evidence-root", required=True)
    conformance_verify.add_argument("--schema-root")
    capabilities = commands.add_parser(
        "capabilities",
        help="emit the deterministic protocol, schema, verifier, and privacy contract",
    )
    capabilities.add_argument("--schema-root")
    capabilities.add_argument("--out", required=True)
    capabilities_verify = commands.add_parser(
        "verify-capabilities",
        help="recompute a capability manifest from local shipped schemas",
    )
    capabilities_verify.add_argument("manifest")
    capabilities_verify.add_argument("--schema-root")
    lock_capabilities = commands.add_parser(
        "lock-capabilities", help="pin an owner-reviewed protocol and schema baseline"
    )
    lock_capabilities.add_argument("manifest")
    lock_capabilities.add_argument("--schema-root")
    lock_capabilities.add_argument("--out", required=True)
    check_lock = commands.add_parser(
        "check-capability-lock", help="check a locally verified manifest against an owner lock"
    )
    check_lock.add_argument("lock")
    check_lock.add_argument("manifest")
    check_lock.add_argument("--schema-root")
    check_lock.add_argument("--out", required=True)
    check_lock.add_argument("--sarif-out")
    check_lock.add_argument("--fail-on-drift", action="store_true")
    verify_lock = commands.add_parser(
        "verify-capability-lock", help="recompute a saved capability-lock check"
    )
    verify_lock.add_argument("report")
    verify_lock.add_argument("lock")
    verify_lock.add_argument("manifest")
    verify_lock.add_argument("--schema-root")
    plan = commands.add_parser("plan-rereview", help="compute the minimal claim/role re-review set")
    plan.add_argument("ledger_report")
    plan.add_argument("--evidence-root", required=True)
    plan.add_argument(
        "--historical-policy", choices=HISTORICAL_POLICIES, default=HISTORICAL_POLICIES[0]
    )
    plan.add_argument("--out", required=True)
    plan.add_argument("--sarif-out")
    plan.add_argument("--fail-on-review", action="store_true")
    plan_verify = commands.add_parser(
        "verify-rereview", help="recompute a saved minimal re-review plan"
    )
    plan_verify.add_argument("report")
    plan_verify.add_argument("--evidence-root", required=True)
    demo = commands.add_parser(
        "demo", help="write current-trust and compromise-invalidation fictional cases"
    )
    demo.add_argument("--out-dir", required=True)
    demo.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "evaluate":
            bundle = _read_json(Path(args.bundle))
            report = analyze_ledger(
                bundle["policy"],
                bundle["quorum_report"],
                bundle["entries"],
                bundle["checkpoint"],
                previous_checkpoint=bundle.get("previous_checkpoint"),
                evidence_root=args.evidence_root,
                evaluation_time=args.evaluation_time,
            )
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), report_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return int(
                args.fail_on_trust and report["summary"]["status"] != "reviewer_trust_current"
            )
        if args.command == "verify":
            report = _read_json(Path(args.report))
            if errors := verify_ledger_report(report, evidence_root=args.evidence_root):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified {args.report}")
            return 0
        if args.command == "compare":
            reports = [_read_json(Path(item)) for item in args.reports]
            report = compare_views(reports, evidence_root=args.evidence_root)
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), gossip_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return int(args.fail_on_fork and report["summary"]["status"] != "views_consistent")
        if args.command == "verify-comparison":
            report = _read_json(Path(args.report))
            if errors := verify_gossip_report(report, evidence_root=args.evidence_root):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified cross-view comparison {args.report}")
            return 0
        if args.command == "export-fork-proof":
            comparison = _read_json(Path(args.comparison_report))
            report = export_fork_proof(comparison, evidence_root=args.evidence_root)
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), fork_to_sarif(report))
            print(f"[ledger] operator_equivocation_proved: wrote {args.out}")
            return 0
        if args.command == "verify-fork-proof":
            report = _read_json(Path(args.report))
            if errors := verify_fork_proof(report):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified compact fork proof {args.report}")
            return 0
        if args.command == "export-consistency-proof":
            older = _read_json(Path(args.older_report))
            newer = _read_json(Path(args.newer_report))
            report = export_consistency_proof(
                older,
                newer,
                evidence_root=args.evidence_root,
            )
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), consistency_to_sarif(report))
            print(f"[ledger] append_only_extension_proved: wrote {args.out}")
            return 0
        if args.command == "verify-consistency-proof":
            report = _read_json(Path(args.report))
            if errors := verify_consistency_proof(report):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified compact consistency proof {args.report}")
            return 0
        if args.command == "observe":
            observer_policy = _read_json(Path(args.observer_policy))
            ledger_report = _read_json(Path(args.ledger_report))
            receipt = create_observer_receipt(
                observer_policy,
                ledger_report,
                args.observer_private_key,
                observer_id=args.observer_id,
                channel_class=args.channel_class,
                channel_locator=args.channel_locator,
                observed_at=args.observed_at,
                evidence_root=args.evidence_root,
            )
            _write_json(Path(args.out), receipt)
            print(f"[ledger] signed observer receipt: wrote {args.out}")
            return 0
        if args.command == "compare-receipts":
            observer_policy = _read_json(Path(args.observer_policy))
            ledger_policy = _read_json(Path(args.ledger_policy))
            receipts = [_read_json(Path(item)) for item in args.receipts]
            report = analyze_observer_receipts(observer_policy, ledger_policy, receipts)
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), observation_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return int(
                args.fail_on_fork
                and report["summary"]["status"] == "independently_observed_equivocation"
            )
        if args.command == "verify-receipt-comparison":
            report = _read_json(Path(args.report))
            if errors := verify_observer_report(report):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified observer-receipt analysis {args.report}")
            return 0
        if args.command == "analyze-witness-conflict":
            fork_proof = _read_json(Path(args.fork_proof))
            report = analyze_witness_conflict(fork_proof)
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), witness_conflict_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return 0
        if args.command == "verify-witness-conflict":
            report = _read_json(Path(args.report))
            if errors := verify_witness_conflict_report(report):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified witness-conflict attribution {args.report}")
            return 0
        if args.command == "conformance":
            artifacts = load_conformance_artifacts(args.artifact_dir)
            report = run_conformance(
                artifacts,
                evidence_root=args.evidence_root,
                schema_root=args.schema_root,
            )
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), conformance_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return int(args.fail_on_miss and report["summary"]["status"] != "conformance_passed")
        if args.command == "verify-conformance":
            report = _read_json(Path(args.report))
            artifacts = load_conformance_artifacts(args.artifact_dir)
            if errors := verify_conformance_report(
                report,
                artifacts,
                evidence_root=args.evidence_root,
                schema_root=args.schema_root,
            ):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified conformance matrix {args.report}")
            return 0
        if args.command == "capabilities":
            manifest = build_capability_manifest(args.schema_root)
            _write_json(Path(args.out), manifest)
            print(f"[ledger] wrote deterministic capability manifest to {args.out}")
            return 0
        if args.command == "verify-capabilities":
            manifest = _read_json(Path(args.manifest))
            if errors := verify_capability_manifest(manifest, args.schema_root):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified capability manifest {args.manifest}")
            return 0
        if args.command == "lock-capabilities":
            manifest = _read_json(Path(args.manifest))
            lock = build_integration_lock(manifest, args.schema_root)
            _write_json(Path(args.out), lock)
            print(f"[ledger] wrote owner-pinned integration lock to {args.out}")
            return 0
        if args.command == "check-capability-lock":
            lock = _read_json(Path(args.lock))
            manifest = _read_json(Path(args.manifest))
            report = check_integration_lock(lock, manifest, args.schema_root)
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), integration_lock_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return int(
                args.fail_on_drift and report["summary"]["status"] != "requirements_satisfied"
            )
        if args.command == "verify-capability-lock":
            report = _read_json(Path(args.report))
            lock = _read_json(Path(args.lock))
            manifest = _read_json(Path(args.manifest))
            if errors := verify_integration_lock_check(report, lock, manifest, args.schema_root):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified integration-lock check {args.report}")
            return 0
        if args.command == "plan-rereview":
            ledger_report = _read_json(Path(args.ledger_report))
            report = plan_rereview(
                ledger_report,
                evidence_root=args.evidence_root,
                historical_policy=args.historical_policy,
            )
            _write_json(Path(args.out), report)
            if args.sarif_out:
                _write_json(Path(args.sarif_out), rereview_to_sarif(report))
            print(f"[ledger] {report['summary']['status']}: wrote {args.out}")
            return int(
                args.fail_on_review and report["summary"]["status"] != "no_rereview_indicated"
            )
        if args.command == "verify-rereview":
            report = _read_json(Path(args.report))
            if errors := verify_rereview_report(report, evidence_root=args.evidence_root):
                raise ValueError("; ".join(errors))
            print(f"[ledger] verified re-review plan {args.report}")
            return 0
        if args.command == "demo":
            _demo(Path(args.out_dir), force=args.force)
            return 0
    except (KeyError, OSError, RuntimeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"[ledger] {args.command} failed: {exc}", file=sys.stderr)
        return 2
    return 0


def _demo(out_dir: Path, *, force: bool) -> None:
    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise ValueError(f"output directory is not empty: {out_dir} (use --force)")
    quorum_root = out_dir / "quorum"
    quorum_demo(quorum_root, force=True)
    quorum_report = _read_json(quorum_root / "quorum-satisfied.report.json")
    with tempfile.TemporaryDirectory(prefix="assurance-ledger-demo-") as temp:
        key_root = Path(temp)
        key_paths: dict[str, Path] = {}
        descriptors = {}
        identities = (
            ("fictional-log-operator", "fictional-program-office"),
            ("fictional-witness-one", "fictional-independent-lab"),
            ("fictional-witness-two", "fictional-civil-society-observer"),
            ("fictional-observer-one", "fictional-state-university"),
            ("fictional-observer-two", "fictional-industry-isac"),
        )
        for entity_id, organization_id in identities:
            private = key_root / f"{entity_id}.private.pem"
            public = key_root / f"{entity_id}.public.pem"
            generate_ed25519_keypair(private, public)
            key_paths[entity_id] = private
            descriptors[entity_id] = key_descriptor(
                public, entity_id=entity_id, organization_id=organization_id
            )
        operator_id = "fictional-log-operator"
        witness_ids = ("fictional-witness-one", "fictional-witness-two")
        policy = build_policy(
            descriptors[operator_id],
            [descriptors[item] for item in witness_ids],
            registry_id="fictional-reviewer-trust-registry",
            log_origin="fictional-agency.example/ai-assurance",
            minimum_witnesses=2,
            minimum_distinct_witness_organizations=2,
            maximum_checkpoint_age_seconds=86_400,
        )
        observer_ids = ("fictional-observer-one", "fictional-observer-two")
        observer_policy = build_observer_policy(
            [descriptors[item] for item in observer_ids],
            exchange_id="fictional-cross-organization-exchange",
            minimum_observers=2,
            minimum_distinct_organizations=2,
            minimum_distinct_channels=2,
            maximum_observation_delay_seconds=3_600,
        )
        entries = []
        for reviewer in quorum_report["policy"]["reviewers"]:
            entries.append(
                make_registration_event(
                    reviewer,
                    sequence=len(entries),
                    integrated_at=1_788_047_900,
                    valid_from=1_788_048_000,
                    valid_until=1_788_134_400,
                )
            )
        for envelope in quorum_report["review_envelopes"]:
            entries.append(
                make_review_event(
                    envelope,
                    sequence=len(entries),
                    integrated_at=1_788_048_200,
                )
            )
        first = create_checkpoint(
            policy,
            entries,
            key_paths[operator_id],
            issued_at=1_788_048_300,
        )
        for witness_id in witness_ids:
            first = cosign_checkpoint(
                policy,
                first,
                entries,
                key_paths[witness_id],
                witness_id=witness_id,
            )
        current = analyze_ledger(
            policy,
            quorum_report,
            entries,
            first,
            previous_checkpoint=None,
            evidence_root=quorum_root,
            evaluation_time=1_788_048_400,
        )
        independent = next(
            item
            for item in quorum_report["policy"]["reviewers"]
            if item["role"] == "independent-reviewer"
        )
        fork_entries = [
            *entries[:-1],
            make_revocation_event(
                signer_id=independent["signer_id"],
                public_key_sha256=independent["public_key_sha256"],
                sequence=len(entries) - 1,
                integrated_at=1_788_048_200,
                effective_at=1_788_048_200,
                compromise_since=None,
                reason="Fictional same-size fork for checkpoint-gossip demonstration.",
            ),
        ]
        fork_checkpoint = create_checkpoint(
            policy,
            fork_entries,
            key_paths[operator_id],
            issued_at=1_788_048_300,
        )
        for witness_id in witness_ids:
            fork_checkpoint = cosign_checkpoint(
                policy,
                fork_checkpoint,
                fork_entries,
                key_paths[witness_id],
                witness_id=witness_id,
            )
        forked = analyze_ledger(
            policy,
            quorum_report,
            fork_entries,
            fork_checkpoint,
            previous_checkpoint=None,
            evidence_root=quorum_root,
            evaluation_time=1_788_048_400,
        )
        extended_entries = [
            *entries,
            make_revocation_event(
                signer_id=independent["signer_id"],
                public_key_sha256=independent["public_key_sha256"],
                sequence=len(entries),
                integrated_at=1_788_048_500,
                effective_at=1_788_048_500,
                compromise_since=1_788_048_000,
                reason="Fictional retrospective compromise declaration for protocol demonstration.",
            ),
        ]
        retired_entries = [
            *entries,
            make_revocation_event(
                signer_id=independent["signer_id"],
                public_key_sha256=independent["public_key_sha256"],
                sequence=len(entries),
                integrated_at=1_788_048_500,
                effective_at=1_788_048_500,
                compromise_since=None,
                reason="Fictional routine key retirement after review issuance.",
            ),
        ]
        retired_checkpoint = create_checkpoint(
            policy,
            retired_entries,
            key_paths[operator_id],
            issued_at=1_788_048_600,
            previous_checkpoint=first,
        )
        for witness_id in witness_ids:
            retired_checkpoint = cosign_checkpoint(
                policy,
                retired_checkpoint,
                retired_entries,
                key_paths[witness_id],
                witness_id=witness_id,
                previous_checkpoint=first,
            )
        retired = analyze_ledger(
            policy,
            quorum_report,
            retired_entries,
            retired_checkpoint,
            previous_checkpoint=first,
            evidence_root=quorum_root,
            evaluation_time=1_788_048_700,
        )
        second = create_checkpoint(
            policy,
            extended_entries,
            key_paths[operator_id],
            issued_at=1_788_048_600,
            previous_checkpoint=first,
        )
        for witness_id in witness_ids:
            second = cosign_checkpoint(
                policy,
                second,
                extended_entries,
                key_paths[witness_id],
                witness_id=witness_id,
                previous_checkpoint=first,
            )
        invalidated = analyze_ledger(
            policy,
            quorum_report,
            extended_entries,
            second,
            previous_checkpoint=first,
            evidence_root=quorum_root,
            evaluation_time=1_788_048_700,
        )
        comparison = compare_views([current, forked], evidence_root=quorum_root)
        fork_proof = export_fork_proof(comparison, evidence_root=quorum_root)
        witness_conflict = analyze_witness_conflict(fork_proof)
        observer_receipts = [
            create_observer_receipt(
                observer_policy,
                report,
                key_paths[observer_id],
                observer_id=observer_id,
                channel_class=channel_class,
                channel_locator=channel_locator,
                observed_at=1_788_048_400,
                evidence_root=quorum_root,
            )
            for observer_id, report, channel_class, channel_locator in (
                (
                    observer_ids[0],
                    current,
                    "offline-transfer",
                    "fictional-airgap-drop-a",
                ),
                (
                    observer_ids[1],
                    forked,
                    "transparency-distributor",
                    "fictional-distributor-b",
                ),
            )
        ]
        observer_report = analyze_observer_receipts(
            observer_policy,
            policy,
            observer_receipts,
        )
        consistency_proof = export_consistency_proof(
            current,
            invalidated,
            evidence_root=quorum_root,
        )
        rereview = plan_rereview(invalidated, evidence_root=quorum_root)
        capability_manifest = build_capability_manifest()
        integration_lock = build_integration_lock(capability_manifest)
        integration_lock_check = check_integration_lock(integration_lock, capability_manifest)
        conformance_report = run_conformance(
            {
                "ledger": current,
                "gossip": comparison,
                "rereview": rereview,
                "fork_proof": fork_proof,
                "consistency_proof": consistency_proof,
                "observer": observer_report,
                "witness_conflict": witness_conflict,
                "capability_manifest": capability_manifest,
                "integration_lock": integration_lock,
                "integration_lock_check": integration_lock_check,
            },
            evidence_root=quorum_root,
        )
    _write_json(out_dir / "ledger-policy.json", policy)
    _write_json(out_dir / "observer-policy.json", observer_policy)
    _write_json(out_dir / "current-trust.bundle.json", _bundle(current))
    _write_json(out_dir / "current-trust.report.json", current)
    _write_json(out_dir / "current-trust.sarif", report_to_sarif(current))
    _write_json(out_dir / "compromise-invalidation.bundle.json", _bundle(invalidated))
    _write_json(out_dir / "compromise-invalidation.report.json", invalidated)
    _write_json(out_dir / "compromise-invalidation.sarif", report_to_sarif(invalidated))
    _write_json(out_dir / "key-retirement.report.json", retired)
    _write_json(out_dir / "key-retirement.sarif", report_to_sarif(retired))
    _write_json(out_dir / "forked-view.report.json", forked)
    _write_json(out_dir / "view-comparison.report.json", comparison)
    _write_json(out_dir / "view-comparison.sarif", gossip_to_sarif(comparison))
    _write_json(out_dir / "fork-proof.report.json", fork_proof)
    _write_json(out_dir / "fork-proof.sarif", fork_to_sarif(fork_proof))
    _write_json(out_dir / "witness-conflict.report.json", witness_conflict)
    _write_json(
        out_dir / "witness-conflict.sarif",
        witness_conflict_to_sarif(witness_conflict),
    )
    _write_json(out_dir / "consistency-proof.report.json", consistency_proof)
    _write_json(out_dir / "consistency-proof.sarif", consistency_to_sarif(consistency_proof))
    _write_json(out_dir / "observer-one.receipt.json", observer_receipts[0])
    _write_json(out_dir / "observer-two.receipt.json", observer_receipts[1])
    _write_json(out_dir / "observer-comparison.report.json", observer_report)
    _write_json(out_dir / "observer-comparison.sarif", observation_to_sarif(observer_report))
    _write_json(out_dir / "rereview-plan.report.json", rereview)
    _write_json(out_dir / "rereview-plan.sarif", rereview_to_sarif(rereview))
    _write_json(out_dir / "verifier-conformance.report.json", conformance_report)
    _write_json(
        out_dir / "verifier-conformance.sarif",
        conformance_to_sarif(conformance_report),
    )
    _write_json(out_dir / "capability-manifest.json", capability_manifest)
    _write_json(out_dir / "integration-lock.json", integration_lock)
    _write_json(out_dir / "integration-lock-check.report.json", integration_lock_check)
    _write_json(
        out_dir / "integration-lock-check.sarif",
        integration_lock_to_sarif(integration_lock_check),
    )
    print(
        "[ledger] current trust, compromise invalidation, and cross-view equivocation: "
        f"wrote fictional witnessed evidence to {out_dir}"
    )


def _bundle(report: dict[str, Any]) -> dict[str, Any]:
    return {
        field: report[field]
        for field in ("policy", "quorum_report", "entries", "checkpoint", "previous_checkpoint")
    }


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
