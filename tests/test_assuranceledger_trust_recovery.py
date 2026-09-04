from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from referencing import Registry, Resource

from dspy_security_bench.ledger.trust_recovery import (
    EVENT_ROLES,
    build_recovery_drill,
    build_recovery_policy,
    evaluate_recovery_drill,
    recovery_event,
    validate_recovery_drill,
    validate_recovery_policy,
    verify_recovery_drill_report,
)
from dspy_security_bench.ledger.trust_recovery_sarif import report_to_sarif
from dspy_security_bench.ledger.trust_root import (
    ROLE_NAMES,
    build_trust_root,
    policy_descriptor,
    sign_trust_root,
    trust_key_descriptor,
)
from dspy_security_bench.mission.loader import canonical_sha256

BASE_TIME = 1_800_000_000


def _write_key(tmp_path: Path, name: str) -> tuple[Path, dict]:
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / f"{name}.private.pem"
    public_path = tmp_path / f"{name}.public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, trust_key_descriptor(
        public_path,
        entity_id=name,
        organization_id=f"{name}-organization",
    )


def _role_assignments(*, shared_control: bool = False) -> dict:
    approver = (
        {"actor_id": "key-custodian-one", "organization_id": "agency-program"}
        if shared_control
        else {"actor_id": "independent-approver-one", "organization_id": "oversight-office"}
    )
    return {
        "auditor": [{"actor_id": "auditor-one", "organization_id": "oversight-office"}],
        "distributor": [{"actor_id": "distributor-one", "organization_id": "industry-isac"}],
        "incident-commander": [
            {"actor_id": "incident-commander-one", "organization_id": "agency-program"}
        ],
        "independent-approver": [approver],
        "key-custodian": [{"actor_id": "key-custodian-one", "organization_id": "agency-program"}],
    }


def _policy(*, shared_control: bool = False) -> dict:
    return build_recovery_policy(
        plan_id="fictional-root-compromise-recovery",
        trust_domain="fictional-national-ai-assurance-exchange",
        root_version=1,
        issued_at=BASE_TIME - 10_000,
        expires_at=BASE_TIME + 31_536_000,
        role_assignments=_role_assignments(shared_control=shared_control),
        separation_constraints=[
            {"left_role": "independent-approver", "right_role": "key-custodian"},
            {"left_role": "key-custodian", "right_role": "auditor"},
        ],
        minimum_distinct_organizations=3,
        time_limits={
            "detection_to_declaration_seconds": 120,
            "declaration_to_replacement_seconds": 300,
            "replacement_to_distribution_seconds": 300,
            "distribution_to_verification_seconds": 120,
            "maximum_drill_age_seconds": 3_600,
        },
    )


def _root(tmp_path: Path, policy: dict, *, authorize: bool = True) -> dict:
    private_a, descriptor_a = _write_key(tmp_path, "recovery-root-a")
    private_b, descriptor_b = _write_key(tmp_path, "recovery-root-b")
    keyids = sorted([descriptor_a["keyid"], descriptor_b["keyid"]])
    roles = {
        role: {
            "keyids": keyids,
            "signature_threshold": 2 if role == "root" else 1,
            "minimum_distinct_organizations": 2 if role == "root" else 1,
        }
        for role in ROLE_NAMES
    }
    authorized = (
        [policy_descriptor(policy)]
        if authorize
        else [
            {
                "policy_type": "dspy-security-bench-assurance-ledger-policy",
                "policy_sha256": "a" * 64,
            }
        ]
    )
    root = build_trust_root(
        [descriptor_a, descriptor_b],
        roles,
        authorized,
        trust_domain=policy["trust_domain"],
        version=1,
        issued_at=BASE_TIME - 20_000,
        expires_at=BASE_TIME + 31_536_000,
    )
    root = sign_trust_root(root, private_a)
    return sign_trust_root(root, private_b)


def _events(policy: dict) -> list[dict]:
    assignments = policy["role_assignments"]
    timeline = [
        ("compromise-detected", 0),
        ("incident-declared", 60),
        ("affected-signatures-inventoried", 90),
        ("damage-assessment-completed", 120),
        ("replacement-root-prepared", 180),
        ("independent-approval-recorded", 220),
        ("out-of-band-distribution-rehearsed", 300),
        ("replacement-verification-completed", 360),
        ("lessons-retained", 420),
    ]
    result = []
    for sequence, (event_type, offset) in enumerate(timeline):
        actor = assignments[EVENT_ROLES[event_type]][0]
        result.append(
            recovery_event(
                sequence,
                event_type,
                BASE_TIME + offset,
                actor_id=actor["actor_id"],
                organization_id=actor["organization_id"],
                evidence_sha256=hashlib.sha256(event_type.encode()).hexdigest(),
            )
        )
    return result


def _fixture(tmp_path: Path, *, shared_control: bool = False) -> tuple[dict, dict, dict]:
    policy = _policy(shared_control=shared_control)
    root = _root(tmp_path, policy)
    drill = build_recovery_drill(
        policy,
        root,
        _events(policy),
        drill_id="fictional-quarterly-recovery-exercise",
    )
    return policy, drill, root


def test_recovery_drill_evidences_preplanned_role_separated_readiness(tmp_path):
    policy, drill, root = _fixture(tmp_path)
    assert validate_recovery_policy(policy) == ()
    assert validate_recovery_drill(drill) == ()
    report = evaluate_recovery_drill(
        policy,
        drill,
        root,
        evaluation_time=BASE_TIME + 600,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"] == {
        "status": "recovery_readiness_evidenced",
        "checks_total": 13,
        "checks_passed": 13,
        "checks_failed": 0,
        "events_observed": 9,
        "required_events": 9,
        "distinct_organizations_observed": 3,
        "drill_age_seconds": 180,
        "content_fields_processed": 0,
        "replacement_roots_activated": 0,
        "automatic_actions": 0,
    }
    assert report_to_sarif(report)["runs"][0]["results"] == []
    assert verify_recovery_drill_report(report) == ()


def test_recovery_policy_requires_exact_root_authorization(tmp_path):
    policy = _policy()
    root = _root(tmp_path, policy, authorize=False)
    drill = build_recovery_drill(
        policy, root, _events(policy), drill_id="fictional-unauthorized-policy-drill"
    )
    report = evaluate_recovery_drill(
        policy,
        drill,
        root,
        evaluation_time=BASE_TIME + 600,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "recovery_policy_not_authorized"
    assert report_to_sarif(report)["runs"][0]["results"][0]["ruleId"] == "TRD102"


def test_recovery_drill_detects_missing_stages_and_role_collapse(tmp_path):
    policy, _, root = _fixture(tmp_path, shared_control=True)
    drill = build_recovery_drill(
        policy,
        root,
        _events(policy)[:-1],
        drill_id="fictional-incomplete-recovery-exercise",
    )
    report = evaluate_recovery_drill(
        policy,
        drill,
        root,
        evaluation_time=BASE_TIME + 600,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "recovery_readiness_not_evidenced"
    failed = {item["rule_id"] for item in report["findings"] if item["status"] == "failed"}
    assert {"TRD001", "TRD004"} <= failed


def test_recovery_drill_distinguishes_stale_evidence(tmp_path):
    policy, drill, root = _fixture(tmp_path)
    report = evaluate_recovery_drill(
        policy,
        drill,
        root,
        evaluation_time=BASE_TIME + 5_000,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "stale_recovery_drill"
    result = report_to_sarif(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "TRD013"
    assert result["properties"]["automaticActions"] == 0


def test_recovery_drill_detects_response_window_and_root_binding_failures(tmp_path):
    policy, drill, root = _fixture(tmp_path)
    changed = deepcopy(drill)
    changed["events"][1]["occurred_at"] += 1_000
    changed["root_sha256"] = "b" * 64
    changed.pop("drill_sha256")
    changed["drill_sha256"] = canonical_sha256(changed)
    report = evaluate_recovery_drill(
        policy,
        changed,
        root,
        evaluation_time=BASE_TIME + 2_000,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "recovery_readiness_not_evidenced"
    failed = {item["rule_id"] for item in report["findings"] if item["status"] == "failed"}
    assert {"TRD002", "TRD007", "TRD009"} <= failed


def test_recovery_report_rejects_rehashed_semantic_tampering(tmp_path):
    policy, drill, root = _fixture(tmp_path)
    report = evaluate_recovery_drill(
        policy,
        drill,
        root,
        evaluation_time=BASE_TIME + 600,
        expected_root_sha256=root["root_sha256"],
    )
    tampered = deepcopy(report)
    tampered["summary"]["replacement_roots_activated"] = 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "TrustRecoveryDrill report does not recompute exactly" in (
        verify_recovery_drill_report(tampered)
    )


def test_recovery_drill_cli_evaluates_and_recomputes_report(tmp_path):
    from dspy_security_bench.ledger.cli import main as ledger_main

    policy, drill, root = _fixture(tmp_path)
    policy_path = tmp_path / "recovery-policy.json"
    drill_path = tmp_path / "recovery-drill.json"
    root_path = tmp_path / "trust-root.json"
    report_path = tmp_path / "recovery-drill.report.json"
    sarif_path = tmp_path / "recovery-drill.sarif"
    for path, payload in (
        (policy_path, policy),
        (drill_path, drill),
        (root_path, root),
    ):
        path.write_text(json.dumps(payload))
    assert (
        ledger_main(
            [
                "evaluate-recovery-drill",
                str(policy_path),
                str(drill_path),
                str(root_path),
                "--expected-root-sha256",
                root["root_sha256"],
                "--evaluation-time",
                str(BASE_TIME + 600),
                "--out",
                str(report_path),
                "--sarif-out",
                str(sarif_path),
                "--fail-on-readiness",
            ]
        )
        == 0
    )
    assert ledger_main(["verify-recovery-drill", str(report_path)]) == 0
    assert json.loads(report_path.read_text())["summary"]["status"] == (
        "recovery_readiness_evidenced"
    )
    assert json.loads(sarif_path.read_text())["runs"][0]["results"] == []


def test_recovery_schemas_validate_reference_artifacts(tmp_path):
    policy, drill, root = _fixture(tmp_path)
    report = evaluate_recovery_drill(
        policy,
        drill,
        root,
        evaluation_time=BASE_TIME + 600,
        expected_root_sha256=root["root_sha256"],
    )
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-trust-root.schema.json",
        "assuranceledger-trust-root-report.schema.json",
        "assuranceledger-trust-recovery-policy.schema.json",
        "assuranceledger-trust-recovery-drill.schema.json",
        "assuranceledger-trust-recovery-report.schema.json",
    )
    schemas = {name: json.loads((schema_root / name).read_text()) for name in names}
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[names[2]], registry=registry).validate(policy)
    jsonschema.Draft202012Validator(schemas[names[3]], registry=registry).validate(drill)
    jsonschema.Draft202012Validator(schemas[names[4]], registry=registry).validate(report)
