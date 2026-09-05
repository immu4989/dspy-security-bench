from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.root_view import (
    TRUSTED_STATUS,
    build_root_view_policy,
    create_root_view_receipt,
    evaluate_root_view_quorum,
    root_view_observer_descriptor,
    verify_root_view_report,
)
from dspy_security_bench.ledger.root_view_sarif import report_to_sarif
from dspy_security_bench.ledger.trust_root import (
    ROLE_NAMES,
    build_trust_root,
    sign_trust_root,
    trust_key_descriptor,
)
from dspy_security_bench.mission.commons import generate_ed25519_keypair
from dspy_security_bench.mission.loader import canonical_sha256

DOMAIN = "fictional-national-ai-assurance-exchange"
NONCE = "fresh-root-view-challenge-0001"


def _signed_root(
    tmp_path: Path,
    *,
    suffix: str = "candidate",
    version: int = 1,
    previous: dict | None = None,
    previous_private_paths: list[Path] | None = None,
) -> dict:
    descriptors = []
    private_paths = []
    for index in range(2):
        private = tmp_path / f"root-{suffix}-{index}.private.pem"
        public = tmp_path / f"root-{suffix}-{index}.public.pem"
        generate_ed25519_keypair(private, public)
        private_paths.append(private)
        descriptors.append(
            trust_key_descriptor(
                public,
                entity_id=f"root-{suffix}-{index + 1}",
                organization_id=f"root-organization-{suffix}-{index + 1}",
            )
        )
    keyids = sorted(item["keyid"] for item in descriptors)
    roles = {
        role: {
            "keyids": keyids,
            "signature_threshold": 2 if role == "root" else 1,
            "minimum_distinct_organizations": 2 if role == "root" else 1,
        }
        for role in ROLE_NAMES
    }
    root = build_trust_root(
        descriptors,
        roles,
        [
            {
                "policy_type": "dspy-security-bench-assurance-ledger-policy",
                "policy_sha256": canonical_sha256({"fixture": suffix}),
            }
        ],
        trust_domain=DOMAIN,
        version=version,
        issued_at=1_800_000_000 + version,
        expires_at=1_900_000_000 + (1 if suffix == "conflict" else 0),
        previous_root_sha256=previous["root_sha256"] if previous else None,
    )
    for private in private_paths:
        root = sign_trust_root(root, private)
    if previous is not None:
        if previous_private_paths is None:
            raise AssertionError("successor fixture requires predecessor private keys")
        for private in previous_private_paths:
            root = sign_trust_root(root, private, signing_root=previous)
    return root


def _public_root(root: dict) -> dict:
    return deepcopy(root)


def _fixture(tmp_path: Path, *, minimum_observers: int = 2) -> tuple[dict, list[Path], dict]:
    descriptors = []
    private_paths = []
    for index in range(3):
        private = tmp_path / f"observer-{index}.private.pem"
        public = tmp_path / f"observer-{index}.public.pem"
        generate_ed25519_keypair(private, public)
        private_paths.append(private)
        descriptors.append(
            root_view_observer_descriptor(
                public,
                observer_id=f"root-observer-{index + 1}",
                organization_id=f"independent-root-organization-{index + 1}",
            )
        )
    policy = build_root_view_policy(
        descriptors,
        quorum_id="fictional-root-distribution-quorum",
        trust_domain=DOMAIN,
        minimum_observers=minimum_observers,
        minimum_distinct_organizations=2,
    )
    candidate = _public_root(_signed_root(tmp_path))
    return policy, private_paths, candidate


def _receipts(policy: dict, private_paths: list[Path], candidate: dict) -> list[dict]:
    return [
        create_root_view_receipt(
            policy,
            private,
            candidate,
            observer_id=f"root-observer-{index + 1}",
            candidate_root_sha256=candidate["root_sha256"],
            request_nonce=NONCE,
        )
        for index, private in enumerate(private_paths)
    ]


def _evaluate(policy: dict, candidate: dict, receipts: list[dict]) -> dict:
    return evaluate_root_view_quorum(
        policy,
        candidate,
        receipts,
        expected_policy_sha256=policy["policy_sha256"],
        expected_request_nonce=NONCE,
    )


def test_independent_observers_corroborate_exact_candidate_root(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    report = _evaluate(policy, candidate, _receipts(policy, private_paths, candidate))
    assert report["summary"]["status"] == TRUSTED_STATUS
    assert report["summary"]["matching_observers"] == 3
    assert report["summary"]["matching_organizations"] == 3
    assert report["summary"]["passed_checks"] == 10
    assert report["summary"]["content_fields_processed"] == 0
    assert report["summary"]["network_requests"] == 0
    assert report["summary"]["roots_installed"] == 0
    assert report["summary"]["automatic_actions"] == 0
    assert verify_root_view_report(report) == ()
    assert report_to_sarif(report)["runs"][0]["results"] == []


def test_same_version_conflict_is_non_outvotable(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    receipts = _receipts(policy, private_paths, candidate)
    conflict = _public_root(_signed_root(tmp_path, suffix="conflict"))
    receipts[2] = create_root_view_receipt(
        policy,
        private_paths[2],
        conflict,
        observer_id="root-observer-3",
        candidate_root_sha256=candidate["root_sha256"],
        request_nonce=NONCE,
    )
    report = _evaluate(policy, candidate, receipts)
    assert report["summary"]["status"] == "same_version_root_conflict"
    assert report["summary"]["matching_observers"] == 2
    assert report["summary"]["same_version_conflicts"] == 1
    assert report_to_sarif(report)["runs"][0]["results"][0]["ruleId"] == "ARV101"


def test_higher_version_report_is_non_outvotable(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    root_private_paths = [tmp_path / f"root-candidate-{index}.private.pem" for index in range(2)]
    newer = _public_root(
        _signed_root(
            tmp_path,
            suffix="newer",
            version=2,
            previous=candidate,
            previous_private_paths=root_private_paths,
        )
    )
    receipts = _receipts(policy, private_paths, candidate)
    receipts[2] = create_root_view_receipt(
        policy,
        private_paths[2],
        newer,
        observer_id="root-observer-3",
        candidate_root_sha256=candidate["root_sha256"],
        request_nonce=NONCE,
    )
    report = _evaluate(policy, candidate, receipts)
    assert report["summary"]["status"] == "newer_root_reported"
    assert report["summary"]["newer_root_reports"] == 1


def test_lagging_observer_is_reported_but_does_not_block_matching_quorum(tmp_path):
    policy, private_paths, older = _fixture(tmp_path)
    candidate = _public_root(
        _signed_root(
            tmp_path,
            suffix="successor",
            version=2,
            previous=older,
            previous_private_paths=[
                tmp_path / f"root-candidate-{index}.private.pem" for index in range(2)
            ],
        )
    )
    receipts = _receipts(policy, private_paths, candidate)
    receipts[2] = create_root_view_receipt(
        policy,
        private_paths[2],
        older,
        observer_id="root-observer-3",
        candidate_root_sha256=candidate["root_sha256"],
        request_nonce=NONCE,
    )
    report = _evaluate(policy, candidate, receipts)
    assert report["summary"]["status"] == TRUSTED_STATUS
    assert report["summary"]["matching_observers"] == 2
    assert report["summary"]["lagging_observers"] == 1


def test_matching_observer_count_cannot_bypass_organization_threshold(tmp_path):
    policy, private_paths, older = _fixture(tmp_path)
    policy = build_root_view_policy(
        policy["observers"],
        quorum_id=policy["quorum_id"],
        trust_domain=DOMAIN,
        minimum_observers=2,
        minimum_distinct_organizations=3,
    )
    candidate = _public_root(
        _signed_root(
            tmp_path,
            suffix="diversity-successor",
            version=2,
            previous=older,
            previous_private_paths=[
                tmp_path / f"root-candidate-{index}.private.pem" for index in range(2)
            ],
        )
    )
    receipts = _receipts(policy, private_paths, candidate)
    receipts[2] = create_root_view_receipt(
        policy,
        private_paths[2],
        older,
        observer_id="root-observer-3",
        candidate_root_sha256=candidate["root_sha256"],
        request_nonce=NONCE,
    )
    report = _evaluate(policy, candidate, receipts)
    assert report["summary"]["status"] == "insufficient_root_observer_diversity"
    assert report["summary"]["matching_observers"] == 2
    assert report["summary"]["matching_organizations"] == 2


def test_duplicate_observer_cannot_manufacture_quorum(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path, minimum_observers=3)
    receipts = _receipts(policy, private_paths, candidate)
    report = _evaluate(policy, candidate, [receipts[0], receipts[0], receipts[1]])
    assert report["summary"]["status"] == "insufficient_root_observers"
    assert report["summary"]["distinct_observers"] == 2


def test_nonce_or_policy_rebinding_fails_as_distinct_anchor_error(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    receipts = _receipts(policy, private_paths, candidate)
    nonce_report = evaluate_root_view_quorum(
        policy,
        candidate,
        receipts,
        expected_policy_sha256=policy["policy_sha256"],
        expected_request_nonce="different-root-view-challenge-0002",
    )
    assert nonce_report["summary"]["status"] == "root_view_request_mismatch"
    policy_report = evaluate_root_view_quorum(
        policy,
        candidate,
        receipts,
        expected_policy_sha256="f" * 64,
        expected_request_nonce=NONCE,
    )
    assert policy_report["summary"]["status"] == "root_view_policy_not_pinned"


def test_embedded_root_and_rehashed_summary_tampering_are_detected(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    receipts = _receipts(policy, private_paths, candidate)
    broken = deepcopy(receipts)
    broken[0]["observed_root"]["expires_at"] += 1
    invalid = _evaluate(policy, candidate, broken)
    assert invalid["summary"]["status"] == "invalid_root_view_evidence"

    report = _evaluate(policy, candidate, receipts)
    tampered = deepcopy(report)
    tampered["summary"]["matching_observers"] = 0
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "RootViewQuorum report does not recompute exactly" in verify_root_view_report(
        tampered
    )


def test_invalid_observer_signature_invalidates_the_evidence_set(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    receipts = _receipts(policy, private_paths, candidate)
    receipts[0]["observer_signature"]["signature_base64"] = "aW52YWxpZA=="
    report = _evaluate(policy, candidate, receipts)
    assert report["summary"]["status"] == "invalid_root_view_evidence"
    assert report["summary"]["valid_receipts"] == 2
    assert "Ed25519 signature is invalid" in " ".join(report["receipt_results"][0]["errors"])


def test_reverification_enforces_caller_retained_anchors(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    report = _evaluate(policy, candidate, _receipts(policy, private_paths, candidate))
    assert verify_root_view_report(
        report,
        expected_policy_sha256=policy["policy_sha256"],
        expected_candidate_root_sha256=candidate["root_sha256"],
        expected_request_nonce=NONCE,
    ) == ()
    assert "report candidate root does not match the caller-retained expectation" in (
        verify_root_view_report(report, expected_candidate_root_sha256="a" * 64)
    )


def test_cli_describes_signs_evaluates_and_verifies_root_views(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    receipts = _receipts(policy, private_paths, candidate)
    policy_path = tmp_path / "root-view-policy.json"
    root_path = tmp_path / "candidate-root.json"
    root_path.write_text(json.dumps(candidate))
    descriptor_path = tmp_path / "observer.json"
    assert ledger_main(
        [
            "describe-root-view-observer",
            str(tmp_path / "observer-0.public.pem"),
            "--observer-id",
            "root-observer-1",
            "--organization-id",
            "independent-root-organization-1",
            "--out",
            str(descriptor_path),
        ]
    ) == 0
    assert json.loads(descriptor_path.read_text()) == policy["observers"][0]
    spec_path = tmp_path / "root-view-policy-spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "quorum_id": policy["quorum_id"],
                "trust_domain": policy["trust_domain"],
                "observers": policy["observers"],
                "minimum_observers": policy["minimum_observers"],
                "minimum_distinct_organizations": policy[
                    "minimum_distinct_organizations"
                ],
            }
        )
    )
    assert ledger_main(
        [
            "create-root-view-policy",
            str(spec_path),
            "--out",
            str(policy_path),
        ]
    ) == 0
    assert json.loads(policy_path.read_text()) == policy
    issued_path = tmp_path / "issued-root-view.json"
    assert ledger_main(
        [
            "sign-root-view",
            str(policy_path),
            str(private_paths[0]),
            str(root_path),
            "--observer-id",
            "root-observer-1",
            "--candidate-root-sha256",
            candidate["root_sha256"],
            "--request-nonce",
            NONCE,
            "--out",
            str(issued_path),
        ]
    ) == 0
    assert json.loads(issued_path.read_text()) == receipts[0]
    receipt_paths = []
    for index, receipt in enumerate(receipts):
        path = tmp_path / f"root-view-{index}.json"
        path.write_text(json.dumps(receipt))
        receipt_paths.append(path)
    report_path = tmp_path / "root-view.report.json"
    sarif_path = tmp_path / "root-view.sarif"
    assert ledger_main(
        [
            "evaluate-root-view",
            str(policy_path),
            str(root_path),
            *(str(path) for path in receipt_paths),
            "--expected-policy-sha256",
            policy["policy_sha256"],
            "--request-nonce",
            NONCE,
            "--out",
            str(report_path),
            "--sarif-out",
            str(sarif_path),
            "--fail-on-view",
        ]
    ) == 0
    assert ledger_main(
        [
            "verify-root-view",
            str(report_path),
            "--candidate-root-sha256",
            candidate["root_sha256"],
            "--request-nonce",
            NONCE,
        ]
    ) == 0
    assert sarif_path.is_file()


def test_reference_artifacts_validate_against_strict_schemas(tmp_path):
    policy, private_paths, candidate = _fixture(tmp_path)
    receipts = _receipts(policy, private_paths, candidate)
    report = _evaluate(policy, candidate, receipts)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-trust-root.schema.json",
        "assuranceledger-root-view-policy.schema.json",
        "assuranceledger-root-view-receipt.schema.json",
        "assuranceledger-root-view-report.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[1], registry=registry).validate(policy)
    jsonschema.Draft202012Validator(schemas[2], registry=registry).validate(receipts[0])
    jsonschema.Draft202012Validator(schemas[3], registry=registry).validate(report)
