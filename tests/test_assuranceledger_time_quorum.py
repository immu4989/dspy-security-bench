from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.time_quorum import (
    TRUSTED_STATUS,
    build_time_policy,
    create_time_receipt,
    evaluate_time_quorum,
    time_source_descriptor,
    verify_time_quorum_report,
)
from dspy_security_bench.ledger.time_quorum_sarif import report_to_sarif
from dspy_security_bench.mission.commons import generate_ed25519_keypair
from dspy_security_bench.mission.loader import canonical_sha256

SUBJECT = canonical_sha256({"artifact": "fictional-root-v3"})
NONCE = "fresh-verifier-challenge-0001"


def _fixture(tmp_path: Path, *, maximum_width: int = 5) -> tuple[dict, list[dict], dict]:
    descriptors = []
    private_paths = []
    for index in range(3):
        private = tmp_path / f"source-{index}.private.pem"
        public = tmp_path / f"source-{index}.public.pem"
        generate_ed25519_keypair(private, public)
        private_paths.append(private)
        descriptors.append(
            time_source_descriptor(
                public,
                source_id=f"time-source-{index + 1}",
                organization_id=f"independent-time-organization-{index + 1}",
            )
        )
    policy = build_time_policy(
        descriptors,
        quorum_id="fictional-assurance-time-quorum",
        trust_domain="fictional-national-ai-assurance-exchange",
        minimum_sources=3,
        minimum_distinct_organizations=3,
        maximum_radius_seconds=10,
        maximum_interval_width_seconds=maximum_width,
    )
    receipts = [
        create_time_receipt(
            policy,
            private_paths[index],
            source_id=f"time-source-{index + 1}",
            subject_sha256=SUBJECT,
            request_nonce=NONCE,
            midpoint_unix=1_819_700_000 + midpoint_offset,
            radius_seconds=radius,
        )
        for index, (midpoint_offset, radius) in enumerate(((0, 3), (2, 3), (1, 2)))
    ]
    report = evaluate_time_quorum(
        policy,
        receipts,
        expected_policy_sha256=policy["policy_sha256"],
        expected_subject_sha256=SUBJECT,
        expected_request_nonce=NONCE,
    )
    return policy, receipts, report


def test_three_organizations_produce_conservative_time_intersection(tmp_path):
    _, _, report = _fixture(tmp_path)
    assert report["summary"]["status"] == TRUSTED_STATUS
    assert report["summary"]["valid_receipts"] == 3
    assert report["summary"]["distinct_sources"] == 3
    assert report["summary"]["distinct_organizations"] == 3
    assert report["summary"]["passed_checks"] == 10
    assert report["conservative_interval"] == {
        "lower_bound_unix": 1_819_699_999,
        "upper_bound_unix": 1_819_700_003,
        "width_seconds": 4,
    }
    assert report["summary"]["content_fields_processed"] == 0
    assert report["summary"]["clock_adjustments"] == 0
    assert verify_time_quorum_report(report) == ()


def test_nonoverlapping_signed_intervals_fail_closed(tmp_path):
    policy, receipts, _ = _fixture(tmp_path)
    private = tmp_path / "source-2.private.pem"
    receipts[2] = create_time_receipt(
        policy,
        private,
        source_id="time-source-3",
        subject_sha256=SUBJECT,
        request_nonce=NONCE,
        midpoint_unix=1_819_700_100,
        radius_seconds=2,
    )
    report = evaluate_time_quorum(
        policy,
        receipts,
        expected_policy_sha256=policy["policy_sha256"],
        expected_subject_sha256=SUBJECT,
        expected_request_nonce=NONCE,
    )
    assert report["summary"]["status"] == "time_sources_inconsistent"
    assert report["conservative_interval"]["width_seconds"] is None
    assert report_to_sarif(report)["runs"][0]["results"][0]["ruleId"] == "ATQ103"


def test_duplicate_source_cannot_manufacture_quorum(tmp_path):
    policy, receipts, _ = _fixture(tmp_path)
    report = evaluate_time_quorum(
        policy,
        [receipts[0], receipts[0], receipts[1]],
        expected_policy_sha256=policy["policy_sha256"],
        expected_subject_sha256=SUBJECT,
        expected_request_nonce=NONCE,
    )
    assert report["summary"]["status"] == "insufficient_time_sources"
    assert report["summary"]["distinct_sources"] == 2


def test_subject_or_nonce_rebinding_is_a_distinct_failure(tmp_path):
    policy, receipts, _ = _fixture(tmp_path)
    report = evaluate_time_quorum(
        policy,
        receipts,
        expected_policy_sha256=policy["policy_sha256"],
        expected_subject_sha256=SUBJECT,
        expected_request_nonce="different-verifier-challenge-0002",
    )
    assert report["summary"]["status"] == "time_request_mismatch"
    assert report["findings"][3]["status"] == "failed"


def test_replacement_policy_is_not_trusted_without_the_external_pin(tmp_path):
    policy, receipts, _ = _fixture(tmp_path)
    report = evaluate_time_quorum(
        policy,
        receipts,
        expected_policy_sha256="f" * 64,
        expected_subject_sha256=SUBJECT,
        expected_request_nonce=NONCE,
    )
    assert report["summary"]["status"] == "time_policy_not_pinned"
    assert report["findings"][0]["rule_id"] == "ATQ001"
    assert report["findings"][0]["status"] == "failed"


def test_rehashed_signature_or_summary_tampering_does_not_verify(tmp_path):
    _, _, report = _fixture(tmp_path)
    tampered = deepcopy(report)
    tampered["receipts"][0]["time_source_signature"]["signature_base64"] = "aW52YWxpZA=="
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AssuranceTimeQuorum report does not recompute exactly" in verify_time_quorum_report(
        tampered
    )

    tampered = deepcopy(report)
    tampered["conservative_interval"]["lower_bound_unix"] -= 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AssuranceTimeQuorum report does not recompute exactly" in verify_time_quorum_report(
        tampered
    )


def test_external_expectations_are_enforced_when_reverifying(tmp_path):
    policy, _, report = _fixture(tmp_path)
    assert verify_time_quorum_report(
        report,
        expected_policy_sha256=policy["policy_sha256"],
        expected_subject_sha256=SUBJECT,
        expected_request_nonce=NONCE,
    ) == ()
    assert "report request nonce does not match the caller-retained expectation" in (
        verify_time_quorum_report(report, expected_request_nonce="retained-other-nonce-0003")
    )


def test_cli_issues_evaluates_and_reverifies_time_evidence(tmp_path):
    policy, receipts, _ = _fixture(tmp_path)
    policy_path = tmp_path / "time-policy.json"
    policy_path.write_text(json.dumps(policy))
    descriptor_path = tmp_path / "described-source.json"
    assert (
        ledger_main(
            [
                "describe-time-source",
                str(tmp_path / "source-0.public.pem"),
                "--source-id",
                "time-source-1",
                "--organization-id",
                "independent-time-organization-1",
                "--out",
                str(descriptor_path),
            ]
        )
        == 0
    )
    assert json.loads(descriptor_path.read_text()) == policy["sources"][0]
    issued_path = tmp_path / "issued.receipt.json"
    assert (
        ledger_main(
            [
                "issue-time-receipt",
                str(policy_path),
                str(tmp_path / "source-0.private.pem"),
                "--source-id",
                "time-source-1",
                "--subject-sha256",
                SUBJECT,
                "--request-nonce",
                NONCE,
                "--midpoint-unix",
                "1819700000",
                "--radius-seconds",
                "3",
                "--out",
                str(issued_path),
            ]
        )
        == 0
    )
    assert json.loads(issued_path.read_text()) == receipts[0]
    receipt_paths = []
    for index, receipt in enumerate(receipts):
        path = tmp_path / f"receipt-{index}.json"
        path.write_text(json.dumps(receipt))
        receipt_paths.append(path)
    report_path = tmp_path / "time.report.json"
    sarif_path = tmp_path / "time.sarif"
    assert (
        ledger_main(
            [
                "evaluate-time-quorum",
                str(policy_path),
                *(str(path) for path in receipt_paths),
                "--expected-policy-sha256",
                policy["policy_sha256"],
                "--subject-sha256",
                SUBJECT,
                "--request-nonce",
                NONCE,
                "--out",
                str(report_path),
                "--sarif-out",
                str(sarif_path),
                "--fail-on-time",
            ]
        )
        == 0
    )
    assert ledger_main(["verify-time-quorum", str(report_path)]) == 0
    assert sarif_path.is_file()


def test_reference_report_validates_against_strict_schemas(tmp_path):
    _, receipts, report = _fixture(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-time-quorum-policy.schema.json",
        "assuranceledger-time-receipt.schema.json",
        "assuranceledger-time-quorum-report.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[0], registry=registry).validate(
        report["time_policy"]
    )
    jsonschema.Draft202012Validator(schemas[1], registry=registry).validate(receipts[0])
    jsonschema.Draft202012Validator(schemas[2], registry=registry).validate(report)
