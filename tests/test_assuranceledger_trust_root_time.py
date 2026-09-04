from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.time_quorum import (
    build_time_policy,
    create_time_receipt,
    evaluate_time_quorum,
    time_source_descriptor,
)
from dspy_security_bench.ledger.trust_root import (
    ROLE_NAMES,
    build_trust_root,
    sign_trust_root,
    trust_key_descriptor,
)
from dspy_security_bench.ledger.trust_root_time import (
    TRUSTED_STATUS,
    evaluate_trust_root_time,
    verify_trust_root_time_report,
)
from dspy_security_bench.ledger.trust_root_time_sarif import report_to_sarif
from dspy_security_bench.mission.commons import generate_ed25519_keypair
from dspy_security_bench.mission.loader import canonical_sha256

NONCE = "retained-root-time-challenge-0001"
DOMAIN = "fictional-temporal-root-domain"


def _fixture(
    tmp_path: Path,
    *,
    root_issued_at: int = 900,
    root_expires_at: int = 1_100,
) -> tuple[dict, dict, dict]:
    root_descriptors = []
    root_private = []
    for index in range(2):
        private = tmp_path / f"root-{index}.private.pem"
        public = tmp_path / f"root-{index}.public.pem"
        generate_ed25519_keypair(private, public)
        root_private.append(private)
        root_descriptors.append(
            trust_key_descriptor(
                public,
                entity_id=f"root-signer-{index + 1}",
                organization_id=f"root-organization-{index + 1}",
            )
        )
    keyids = sorted(item["keyid"] for item in root_descriptors)
    roles = {
        role: {
            "keyids": keyids,
            "signature_threshold": 2 if role == "root" else 1,
            "minimum_distinct_organizations": 2 if role == "root" else 1,
        }
        for role in ROLE_NAMES
    }
    root = build_trust_root(
        root_descriptors,
        roles,
        [
            {
                "policy_type": "dspy-security-bench-assurance-ledger-policy",
                "policy_sha256": "a" * 64,
            }
        ],
        trust_domain=DOMAIN,
        version=1,
        issued_at=root_issued_at,
        expires_at=root_expires_at,
    )
    for private in root_private:
        root = sign_trust_root(root, private)

    source_descriptors = []
    source_private = []
    for index in range(3):
        private = tmp_path / f"time-{index}.private.pem"
        public = tmp_path / f"time-{index}.public.pem"
        generate_ed25519_keypair(private, public)
        source_private.append(private)
        source_descriptors.append(
            time_source_descriptor(
                public,
                source_id=f"time-source-{index + 1}",
                organization_id=f"time-organization-{index + 1}",
            )
        )
    time_policy = build_time_policy(
        source_descriptors,
        quorum_id="fictional-root-time-quorum",
        trust_domain=DOMAIN,
        minimum_sources=3,
        minimum_distinct_organizations=3,
        maximum_radius_seconds=10,
        maximum_interval_width_seconds=5,
    )
    receipts = [
        create_time_receipt(
            time_policy,
            source_private[index],
            source_id=f"time-source-{index + 1}",
            subject_sha256=root["root_sha256"],
            request_nonce=NONCE,
            midpoint_unix=1_000 + offset,
            radius_seconds=radius,
        )
        for index, (offset, radius) in enumerate(((0, 3), (2, 3), (1, 2)))
    ]
    time_report = evaluate_time_quorum(
        time_policy,
        receipts,
        expected_policy_sha256=time_policy["policy_sha256"],
        expected_subject_sha256=root["root_sha256"],
        expected_request_nonce=NONCE,
    )
    gate = evaluate_trust_root_time(
        root,
        time_report,
        expected_time_policy_sha256=time_policy["policy_sha256"],
        expected_request_nonce=NONCE,
        expected_root_sha256=root["root_sha256"],
        expected_trust_domain=DOMAIN,
        minimum_version=1,
    )
    return root, time_report, gate


def test_root_must_be_trusted_through_entire_conservative_interval(tmp_path):
    _, _, report = _fixture(tmp_path)
    assert report["summary"] == {
        "status": TRUSTED_STATUS,
        "lower_bound_unix": 999,
        "upper_bound_unix": 1_003,
        "interval_width_seconds": 4,
        "lower_bound_root_status": "trusted_bootstrap",
        "upper_bound_root_status": "trusted_bootstrap",
        "passed_checks": 8,
        "failed_checks": 0,
        "content_fields_processed": 0,
        "clock_adjustments": 0,
        "roots_installed": 0,
        "automatic_actions": 0,
    }
    assert verify_trust_root_time_report(report) == ()
    assert report_to_sarif(report)["runs"][0]["results"] == []


def test_rehashed_invalid_time_report_never_reaches_root_evaluation(tmp_path):
    root, time_report, _ = _fixture(tmp_path)
    tampered = deepcopy(time_report)
    tampered["conservative_interval"]["lower_bound_unix"] += 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    report = evaluate_trust_root_time(
        root,
        tampered,
        expected_time_policy_sha256=time_report["expectations"]["expected_policy_sha256"],
        expected_request_nonce=NONCE,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "invalid_time_quorum"
    assert report["lower_bound_root_report"] is None
    assert report["upper_bound_root_report"] is None
    assert report["findings"][0]["status"] == "failed"


def test_expiration_inside_uncertainty_interval_fails_closed(tmp_path):
    _, _, report = _fixture(tmp_path, root_expires_at=1_002)
    assert report["summary"]["status"] == "root_expires_within_interval"
    assert report["summary"]["lower_bound_root_status"] == "trusted_bootstrap"
    assert report["summary"]["upper_bound_root_status"] == "expired_trust_root"
    assert report_to_sarif(report)["runs"][0]["results"][0]["ruleId"] == "ART102"


def test_issue_time_inside_interval_is_not_rounded_into_trust(tmp_path):
    _, _, report = _fixture(tmp_path, root_issued_at=1_000)
    assert report["summary"]["status"] == "root_not_yet_valid_for_interval"
    assert report["summary"]["lower_bound_root_status"] == "not_yet_valid_trust_root"


def test_wrong_retained_policy_or_nonce_has_distinct_outcome(tmp_path):
    root, time_report, _ = _fixture(tmp_path)
    report = evaluate_trust_root_time(
        root,
        time_report,
        expected_time_policy_sha256="f" * 64,
        expected_request_nonce=NONCE,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "time_policy_not_pinned"
    report = evaluate_trust_root_time(
        root,
        time_report,
        expected_time_policy_sha256=time_report["expectations"]["expected_policy_sha256"],
        expected_request_nonce="different-retained-challenge-0002",
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "time_request_mismatch"


def test_time_subject_cannot_be_rebound_to_another_root(tmp_path):
    root, time_report, _ = _fixture(tmp_path)
    other = deepcopy(root)
    other["expires_at"] += 1
    other["signatures"] = []
    other.pop("root_sha256")
    other["root_sha256"] = canonical_sha256(other)
    report = evaluate_trust_root_time(
        other,
        time_report,
        expected_time_policy_sha256=time_report["expectations"]["expected_policy_sha256"],
        expected_request_nonce=NONCE,
        expected_root_sha256=other["root_sha256"],
    )
    assert report["summary"]["status"] == "time_subject_mismatch"


def test_rehashed_endpoint_or_summary_tampering_is_rejected(tmp_path):
    _, _, report = _fixture(tmp_path)
    tampered = deepcopy(report)
    tampered["upper_bound_root_report"]["summary"]["status"] = "expired_trust_root"
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "TrustRootTimeGate report does not recompute exactly" in (
        verify_trust_root_time_report(tampered)
    )


def test_saved_gate_is_checked_against_caller_retained_anchors(tmp_path):
    _, _, report = _fixture(tmp_path)
    assert "report time-policy pin does not match" in verify_trust_root_time_report(
        report, expected_time_policy_sha256="f" * 64
    )[0]
    assert "report nonce does not match" in verify_trust_root_time_report(
        report, expected_request_nonce="different-retained-challenge-0002"
    )[0]


def test_cli_evaluates_and_reverifies_temporal_root_gate(tmp_path):
    root, time_report, _ = _fixture(tmp_path)
    root_path = tmp_path / "root.json"
    time_path = tmp_path / "time.json"
    output = tmp_path / "gate.json"
    sarif = tmp_path / "gate.sarif"
    root_path.write_text(json.dumps(root))
    time_path.write_text(json.dumps(time_report))
    pin = time_report["expectations"]["expected_policy_sha256"]
    assert (
        ledger_main(
            [
                "evaluate-trust-root-time",
                str(root_path),
                str(time_path),
                "--expected-time-policy-sha256",
                pin,
                "--expected-request-nonce",
                NONCE,
                "--expected-root-sha256",
                root["root_sha256"],
                "--expected-domain",
                DOMAIN,
                "--minimum-version",
                "1",
                "--out",
                str(output),
                "--sarif-out",
                str(sarif),
                "--fail-on-trust",
            ]
        )
        == 0
    )
    assert (
        ledger_main(
            [
                "verify-trust-root-time",
                str(output),
                "--expected-time-policy-sha256",
                pin,
                "--expected-request-nonce",
                NONCE,
            ]
        )
        == 0
    )
    assert sarif.is_file()


def test_reference_gate_validates_against_strict_schema(tmp_path):
    _, _, report = _fixture(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-trust-root.schema.json",
        "assuranceledger-trust-root-report.schema.json",
        "assuranceledger-time-quorum-policy.schema.json",
        "assuranceledger-time-receipt.schema.json",
        "assuranceledger-time-quorum-report.schema.json",
        "assuranceledger-trust-root-time-gate.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(report)
