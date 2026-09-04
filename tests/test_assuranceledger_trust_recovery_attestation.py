from __future__ import annotations

import base64
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
    ROLE_NAMES,
    build_recovery_drill,
    build_recovery_policy,
    recovery_event,
)
from dspy_security_bench.ledger.trust_recovery_attestation import (
    GENESIS_ATTESTATION_SHA256,
    TRUSTED_STATUS,
    attester_descriptor,
    build_attestation_policy,
    evaluate_recovery_attestations,
    sign_recovery_event,
    validate_attestation_policy,
    verify_recovery_attestation_report,
    verify_recovery_event_attestation,
)
from dspy_security_bench.ledger.trust_recovery_attestation_sarif import report_to_sarif
from dspy_security_bench.ledger.trust_root import (
    ROLE_NAMES as ROOT_ROLE_NAMES,
)
from dspy_security_bench.ledger.trust_root import (
    build_trust_root,
    policy_descriptor,
    sign_trust_root,
    trust_key_descriptor,
)
from dspy_security_bench.mission.loader import canonical_sha256

BASE_TIME = 1_800_000_000


def _write_key(tmp_path: Path, name: str) -> tuple[Path, Path]:
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
    return private_path, public_path


def _recovery_policy() -> dict:
    return build_recovery_policy(
        plan_id="fictional-root-compromise-recovery",
        trust_domain="fictional-national-ai-assurance-exchange",
        root_version=1,
        issued_at=BASE_TIME - 10_000,
        expires_at=BASE_TIME + 31_536_000,
        role_assignments={
            "auditor": [{"actor_id": "auditor-one", "organization_id": "oversight-office"}],
            "distributor": [{"actor_id": "distributor-one", "organization_id": "industry-isac"}],
            "incident-commander": [
                {"actor_id": "incident-commander-one", "organization_id": "agency-program"}
            ],
            "independent-approver": [
                {
                    "actor_id": "independent-approver-one",
                    "organization_id": "oversight-office",
                }
            ],
            "key-custodian": [
                {"actor_id": "key-custodian-one", "organization_id": "agency-program"}
            ],
        },
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


def _attestation_policy(tmp_path: Path, recovery_policy: dict) -> tuple[dict, dict[str, Path]]:
    private_keys: dict[str, Path] = {}
    signers = []
    for role in ROLE_NAMES:
        assignment = recovery_policy["role_assignments"][role][0]
        private, public = _write_key(tmp_path, assignment["actor_id"])
        private_keys[assignment["actor_id"]] = private
        signers.append(
            attester_descriptor(
                public,
                signer_id=assignment["actor_id"],
                recovery_role=role,
                organization_id=assignment["organization_id"],
            )
        )
    return (
        build_attestation_policy(
            recovery_policy,
            signers,
            attestation_policy_id="fictional-recovery-handoff-attesters",
            issued_at=BASE_TIME - 5_000,
            expires_at=BASE_TIME + 86_400,
        ),
        private_keys,
    )


def _root(tmp_path: Path, policies: list[dict]) -> dict:
    root_private_paths = []
    root_descriptors = []
    for name in ("root-a", "root-b"):
        private, public = _write_key(tmp_path, name)
        root_private_paths.append(private)
        root_descriptors.append(
            trust_key_descriptor(
                public,
                entity_id=name,
                organization_id=f"{name}-organization",
            )
        )
    keyids = sorted(item["keyid"] for item in root_descriptors)
    roles = {
        role: {
            "keyids": keyids,
            "signature_threshold": 2 if role == "root" else 1,
            "minimum_distinct_organizations": 2 if role == "root" else 1,
        }
        for role in ROOT_ROLE_NAMES
    }
    root = build_trust_root(
        root_descriptors,
        roles,
        [policy_descriptor(policy) for policy in policies],
        trust_domain=policies[0]["trust_domain"],
        version=1,
        issued_at=BASE_TIME - 20_000,
        expires_at=BASE_TIME + 31_536_000,
    )
    for private in root_private_paths:
        root = sign_trust_root(root, private)
    return root


def _events(policy: dict) -> list[dict]:
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
    events = []
    for sequence, (event_type, offset) in enumerate(timeline):
        actor = policy["role_assignments"][EVENT_ROLES[event_type]][0]
        events.append(
            recovery_event(
                sequence,
                event_type,
                BASE_TIME + offset,
                actor_id=actor["actor_id"],
                organization_id=actor["organization_id"],
                evidence_sha256=hashlib.sha256(event_type.encode()).hexdigest(),
            )
        )
    return events


def _fixture(
    tmp_path: Path,
) -> tuple[dict, dict, dict, dict, list[dict], dict[str, Path], dict]:
    recovery_policy = _recovery_policy()
    attestation_policy, private_keys = _attestation_policy(tmp_path, recovery_policy)
    root = _root(tmp_path, [recovery_policy, attestation_policy])
    drill = build_recovery_drill(
        recovery_policy,
        root,
        _events(recovery_policy),
        drill_id="fictional-quarterly-recovery-exercise",
    )
    envelopes = []
    previous = GENESIS_ATTESTATION_SHA256
    for index, event in enumerate(drill["events"]):
        envelope = sign_recovery_event(
            attestation_policy,
            recovery_policy,
            drill,
            private_keys[event["actor_id"]],
            event_index=index,
            issued_at=event["occurred_at"] + 5,
            nonce=f"handoff-{index + 1}",
            previous_attestation_sha256=previous,
        )
        envelopes.append(envelope)
        previous = canonical_sha256(envelope)
    report = evaluate_recovery_attestations(
        attestation_policy,
        recovery_policy,
        drill,
        root,
        envelopes,
        evaluation_time=BASE_TIME + 700,
        expected_root_sha256=root["root_sha256"],
    )
    return attestation_policy, recovery_policy, drill, root, envelopes, private_keys, report


def _rehash(report: dict) -> None:
    report["report_sha256"] = canonical_sha256(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )


def test_complete_dsse_handoff_chain_is_authenticated(tmp_path):
    policy, recovery_policy, drill, root, envelopes, _, report = _fixture(tmp_path)
    assert validate_attestation_policy(policy, recovery_policy) == ()
    assert report["summary"] == {
        "status": TRUSTED_STATUS,
        "checks_total": 10,
        "checks_passed": 10,
        "checks_failed": 0,
        "events_expected": 9,
        "attestations_observed": 9,
        "valid_attestations": 9,
        "distinct_signer_organizations": 3,
        "terminal_attestation_sha256": canonical_sha256(envelopes[-1]),
        "content_fields_processed": 0,
        "replacement_roots_activated": 0,
        "automatic_actions": 0,
    }
    assert verify_recovery_attestation_report(report) == ()
    assert report_to_sarif(report)["runs"][0]["results"] == []
    statement, errors = verify_recovery_event_attestation(
        envelopes[0],
        policy,
        recovery_policy,
        drill,
        event_index=0,
        evaluation_time=BASE_TIME + 700,
        expected_previous_sha256=GENESIS_ATTESTATION_SHA256,
    )
    assert errors == ()
    assert statement["predicate"]["event_type"] == "compromise-detected"


def test_missing_or_reordered_attestations_fail_closed(tmp_path):
    policy, recovery_policy, drill, root, envelopes, _, _ = _fixture(tmp_path)
    missing = evaluate_recovery_attestations(
        policy,
        recovery_policy,
        drill,
        root,
        envelopes[:-1],
        evaluation_time=BASE_TIME + 700,
        expected_root_sha256=root["root_sha256"],
    )
    assert missing["summary"]["status"] == "recovery_handoffs_not_authenticated"
    assert {item["rule_id"] for item in missing["findings"] if item["status"] == "failed"} >= {
        "TRA001",
        "TRA002",
    }

    reordered = deepcopy(envelopes)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    report = evaluate_recovery_attestations(
        policy,
        recovery_policy,
        drill,
        root,
        reordered,
        evaluation_time=BASE_TIME + 700,
        expected_root_sha256=root["root_sha256"],
    )
    failed = {item["rule_id"] for item in report["findings"] if item["status"] == "failed"}
    assert {"TRA001", "TRA003", "TRA009"} <= failed


def test_payload_or_signature_tampering_is_detected_even_when_report_is_rehashed(tmp_path):
    *_, report = _fixture(tmp_path)
    tampered = deepcopy(report)
    envelope = tampered["attestation_envelopes"][4]
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["predicate"]["evidence_sha256"] = "a" * 64
    envelope["payload"] = base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    _rehash(tampered)
    errors = verify_recovery_attestation_report(tampered)
    assert "TrustRecoveryAttestation report does not recompute exactly" in errors


def test_replayed_nonce_and_broken_chain_are_separate_failures(tmp_path):
    policy, recovery_policy, drill, root, envelopes, private_keys, _ = _fixture(tmp_path)
    replayed = deepcopy(envelopes)
    event = drill["events"][1]
    replayed[1] = sign_recovery_event(
        policy,
        recovery_policy,
        drill,
        private_keys[event["actor_id"]],
        event_index=1,
        issued_at=event["occurred_at"] + 5,
        nonce="handoff-1",
        previous_attestation_sha256="f" * 64,
    )
    report = evaluate_recovery_attestations(
        policy,
        recovery_policy,
        drill,
        root,
        replayed,
        evaluation_time=BASE_TIME + 700,
        expected_root_sha256=root["root_sha256"],
    )
    failed = {item["rule_id"] for item in report["findings"] if item["status"] == "failed"}
    assert {"TRA008", "TRA009"} <= failed
    sarif = report_to_sarif(report)
    assert {item["ruleId"] for item in sarif["runs"][0]["results"]} >= {
        "TRA008",
        "TRA009",
    }
    assert all(item["properties"]["automaticActions"] == 0 for item in sarif["runs"][0]["results"])


def test_wrong_private_key_cannot_sign_an_actor_event(tmp_path):
    policy, recovery_policy, drill, _, _, private_keys, _ = _fixture(tmp_path)
    try:
        sign_recovery_event(
            policy,
            recovery_policy,
            drill,
            private_keys["auditor-one"],
            event_index=0,
            issued_at=BASE_TIME + 5,
            nonce="wrong-key-attempt",
            previous_attestation_sha256=GENESIS_ATTESTATION_SHA256,
        )
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("wrong private key unexpectedly signed the event")


def test_attestation_policy_must_be_exactly_root_authorized(tmp_path):
    policy, recovery_policy, drill, _, envelopes, _, _ = _fixture(tmp_path)
    root = _root(tmp_path, [recovery_policy])
    rebound = build_recovery_drill(
        recovery_policy,
        root,
        drill["events"],
        drill_id=drill["drill_id"],
    )
    report = evaluate_recovery_attestations(
        policy,
        recovery_policy,
        rebound,
        root,
        envelopes,
        evaluation_time=BASE_TIME + 700,
        expected_root_sha256=root["root_sha256"],
    )
    assert report["summary"]["status"] == "recovery_attestation_policy_not_authorized"


def test_recovery_attestation_schemas_validate_reference_artifacts(tmp_path):
    policy, recovery_policy, drill, root, envelopes, _, report = _fixture(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-trust-root.schema.json",
        "assuranceledger-trust-root-report.schema.json",
        "assuranceledger-trust-recovery-policy.schema.json",
        "assuranceledger-trust-recovery-drill.schema.json",
        "assuranceledger-trust-recovery-report.schema.json",
        "assuranceledger-trust-recovery-attestation-policy.schema.json",
        "assuranceledger-trust-recovery-event-attestation.schema.json",
        "assuranceledger-trust-recovery-attestation-report.schema.json",
    )
    schemas = {name: json.loads((schema_root / name).read_text()) for name in names}
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[names[5]], registry=registry).validate(policy)
    jsonschema.Draft202012Validator(schemas[names[6]], registry=registry).validate(envelopes[0])
    jsonschema.Draft202012Validator(schemas[names[7]], registry=registry).validate(report)
    assert root["root_sha256"] == drill["root_sha256"]
    assert recovery_policy["policy_sha256"] == drill["policy_sha256"]


def test_recovery_attestation_cli_evaluates_and_recomputes(tmp_path):
    from dspy_security_bench.ledger.cli import main as ledger_main

    policy, recovery_policy, drill, root, envelopes, _, _ = _fixture(tmp_path)
    inputs = {
        "attestation-policy.json": policy,
        "recovery-policy.json": recovery_policy,
        "recovery-drill.json": drill,
        "trust-root.json": root,
    }
    for filename, payload in inputs.items():
        (tmp_path / filename).write_text(json.dumps(payload))
    envelope_paths = []
    for index, envelope in enumerate(envelopes):
        path = tmp_path / f"event-{index}.attestation.json"
        path.write_text(json.dumps(envelope))
        envelope_paths.append(path)
    report_path = tmp_path / "recovery-attestations.report.json"
    sarif_path = tmp_path / "recovery-attestations.sarif"
    argv = [
        "evaluate-recovery-attestations",
        str(tmp_path / "attestation-policy.json"),
        str(tmp_path / "recovery-policy.json"),
        str(tmp_path / "recovery-drill.json"),
        str(tmp_path / "trust-root.json"),
        *[str(path) for path in envelope_paths],
        "--expected-root-sha256",
        root["root_sha256"],
        "--evaluation-time",
        str(BASE_TIME + 700),
        "--out",
        str(report_path),
        "--sarif-out",
        str(sarif_path),
        "--fail-on-authentication",
    ]
    assert ledger_main(argv) == 0
    assert ledger_main(["verify-recovery-attestations", str(report_path)]) == 0
    assert json.loads(report_path.read_text())["summary"]["status"] == TRUSTED_STATUS
    assert json.loads(sarif_path.read_text())["runs"][0]["results"] == []


def test_recovery_attestation_cli_describes_and_signs_one_handoff(tmp_path):
    from dspy_security_bench.ledger.cli import main as ledger_main

    policy, recovery_policy, drill, _, envelopes, private_keys, _ = _fixture(tmp_path)
    event = drill["events"][0]
    descriptor_path = tmp_path / "described-attester.json"
    assert (
        ledger_main(
            [
                "describe-recovery-attester",
                str(tmp_path / f"{event['actor_id']}.public.pem"),
                "--signer-id",
                event["actor_id"],
                "--recovery-role",
                EVENT_ROLES[event["event_type"]],
                "--organization-id",
                event["organization_id"],
                "--out",
                str(descriptor_path),
            ]
        )
        == 0
    )
    expected = next(item for item in policy["signers"] if item["signer_id"] == event["actor_id"])
    assert json.loads(descriptor_path.read_text()) == expected

    policy_path = tmp_path / "attestation-policy.json"
    recovery_path = tmp_path / "recovery-policy.json"
    drill_path = tmp_path / "drill.json"
    output = tmp_path / "signed-event.json"
    policy_path.write_text(json.dumps(policy))
    recovery_path.write_text(json.dumps(recovery_policy))
    drill_path.write_text(json.dumps(drill))
    assert (
        ledger_main(
            [
                "sign-recovery-event",
                str(policy_path),
                str(recovery_path),
                str(drill_path),
                str(private_keys[event["actor_id"]]),
                "--event-index",
                "0",
                "--issued-at",
                str(event["occurred_at"] + 5),
                "--nonce",
                "cli-handoff-1",
                "--out",
                str(output),
            ]
        )
        == 0
    )
    signed = json.loads(output.read_text())
    statement, errors = verify_recovery_event_attestation(
        signed,
        policy,
        recovery_policy,
        drill,
        event_index=0,
        evaluation_time=BASE_TIME + 700,
        expected_previous_sha256=GENESIS_ATTESTATION_SHA256,
    )
    assert errors == ()
    assert statement["predicate"]["nonce"] == "cli-handoff-1"
    assert signed != envelopes[0]
