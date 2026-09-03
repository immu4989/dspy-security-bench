from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from referencing import Registry, Resource

from dspy_security_bench.ledger.trust_root import (
    ROLE_NAMES,
    TRUSTED_STATUSES,
    build_trust_root,
    evaluate_trust_root,
    policy_descriptor,
    sign_trust_root,
    trust_key_descriptor,
    validate_trust_root,
    verify_trust_root_report,
)
from dspy_security_bench.ledger.trust_root_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _write_private(tmp_path: Path, name: str, private) -> tuple[Path, Path]:
    private_path = tmp_path / f"{name}.private.pem"
    public_path = tmp_path / f"{name}.public.pem"
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _policy(name: str = "current") -> dict:
    policy = {
        "schema_version": 1,
        "policy_type": "dspy-security-bench-assurance-ledger-policy",
        "fixture_name": name,
    }
    policy["policy_sha256"] = canonical_sha256(policy)
    return policy


def _roles(*descriptors: dict) -> dict:
    keyids = sorted(item["keyid"] for item in descriptors)
    return {
        role: {
            "keyids": keyids,
            "signature_threshold": len(keyids) if role == "root" else 1,
            "minimum_distinct_organizations": len(keyids) if role == "root" else 1,
        }
        for role in ROLE_NAMES
    }


def _roots(tmp_path: Path) -> tuple[dict, dict, dict, dict]:
    algorithms = {
        "root-ed": Ed25519PrivateKey.generate(),
        "root-ec": ec.generate_private_key(ec.SECP256R1()),
        "root-rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    }
    paths = {}
    descriptors = {}
    for index, (name, private) in enumerate(algorithms.items(), start=1):
        private_path, public_path = _write_private(tmp_path, name, private)
        paths[name] = private_path
        descriptors[name] = trust_key_descriptor(
            public_path,
            entity_id=name,
            organization_id=f"fictional-root-org-{index}",
        )
    policy = _policy()
    first = build_trust_root(
        [descriptors["root-ed"], descriptors["root-ec"]],
        _roles(descriptors["root-ed"], descriptors["root-ec"]),
        [policy_descriptor(policy)],
        trust_domain="fictional-critical-infrastructure-assurance",
        version=1,
        issued_at=1_788_048_000,
        expires_at=1_819_584_000,
    )
    first = sign_trust_root(first, paths["root-ed"])
    first = sign_trust_root(first, paths["root-ec"])
    second = build_trust_root(
        [descriptors["root-ed"], descriptors["root-rsa"]],
        _roles(descriptors["root-ed"], descriptors["root-rsa"]),
        [policy_descriptor(policy)],
        trust_domain="fictional-critical-infrastructure-assurance",
        version=2,
        issued_at=1_788_134_400,
        expires_at=1_819_670_400,
        previous_root_sha256=first["root_sha256"],
    )
    for signer in ("root-ed", "root-rsa"):
        second = sign_trust_root(second, paths[signer])
    for signer in ("root-ed", "root-ec"):
        second = sign_trust_root(second, paths[signer], signing_root=first)
    return first, second, policy, {"descriptors": descriptors, "private_paths": paths}


def test_dual_threshold_rotation_supports_algorithm_migration(tmp_path):
    first, second, policy, _ = _roots(tmp_path)
    assert validate_trust_root(first) == ()
    assert validate_trust_root(second) == ()
    report = evaluate_trust_root(
        second,
        trusted_root=first,
        evaluation_time=1_788_220_800,
        expected_trust_domain="fictional-critical-infrastructure-assurance",
        policies=[policy],
    )
    assert report["summary"]["status"] == "trusted_rotation"
    assert report["summary"]["current_valid_root_signatures"] == 2
    assert report["summary"]["previous_valid_root_signatures"] == 2
    assert report["summary"]["current_distinct_root_organizations"] == 2
    assert report["algorithm_transition"] == {
        "previous_schemes": ["ecdsa-sha2-nistp256", "ed25519"],
        "candidate_schemes": ["ed25519", "rsassa-pss-sha256"],
        "added_schemes": ["rsassa-pss-sha256"],
        "removed_schemes": ["ecdsa-sha2-nistp256"],
    }
    assert report["summary"]["authorized_policies"] == 1
    assert verify_trust_root_report(report) == ()


def test_bootstrap_requires_an_independently_pinned_digest(tmp_path):
    first, _, policy, _ = _roots(tmp_path)
    unanchored = evaluate_trust_root(
        first, evaluation_time=1_788_048_100, policies=[policy]
    )
    assert unanchored["summary"]["status"] == "untrusted_bootstrap"
    anchored = evaluate_trust_root(
        first,
        evaluation_time=1_788_048_100,
        expected_root_sha256=first["root_sha256"],
        policies=[policy],
    )
    assert anchored["summary"]["status"] == "trusted_bootstrap"
    assert anchored["summary"]["status"] in TRUSTED_STATUSES


def test_exact_next_version_and_predecessor_digest_are_required(tmp_path):
    first, _, policy, fixture = _roots(tmp_path)
    descriptors = fixture["descriptors"]
    paths = fixture["private_paths"]
    gap = build_trust_root(
        [descriptors["root-ed"], descriptors["root-ec"]],
        _roles(descriptors["root-ed"], descriptors["root-ec"]),
        [policy_descriptor(policy)],
        trust_domain=first["trust_domain"],
        version=3,
        issued_at=1_788_134_400,
        expires_at=1_819_670_400,
        previous_root_sha256=first["root_sha256"],
    )
    for signer in ("root-ed", "root-ec"):
        gap = sign_trust_root(gap, paths[signer])
        gap = sign_trust_root(gap, paths[signer], signing_root=first)
    report = evaluate_trust_root(
        gap, trusted_root=first, evaluation_time=1_788_220_800, policies=[policy]
    )
    assert report["summary"]["status"] == "version_gap_detected"

    rollback = evaluate_trust_root(
        first, trusted_root=first, evaluation_time=1_788_220_800, policies=[policy]
    )
    assert rollback["summary"]["status"] == "rollback_detected"


def test_missing_predecessor_threshold_fails_closed(tmp_path):
    first, second, policy, _ = _roots(tmp_path)
    incomplete = deepcopy(second)
    incomplete["previous_root_signatures"] = incomplete["previous_root_signatures"][:1]
    incomplete.pop("root_sha256")
    incomplete["root_sha256"] = canonical_sha256(incomplete)
    report = evaluate_trust_root(
        incomplete,
        trusted_root=first,
        evaluation_time=1_788_220_800,
        policies=[policy],
    )
    assert report["summary"]["status"] == "trust_discontinuity"
    assert "previous root signature threshold unmet" in " ".join(report["trust_errors"])


def test_expiration_is_not_translated_into_trust(tmp_path):
    first, _, policy, _ = _roots(tmp_path)
    report = evaluate_trust_root(
        first,
        evaluation_time=first["expires_at"],
        expected_root_sha256=first["root_sha256"],
        policies=[policy],
    )
    assert report["summary"]["status"] == "expired_trust_root"


def test_root_authorizes_exact_policy_bytes(tmp_path):
    first, _, policy, _ = _roots(tmp_path)
    changed = _policy("changed")
    report = evaluate_trust_root(
        first,
        evaluation_time=1_788_048_100,
        expected_root_sha256=first["root_sha256"],
        policies=[policy, changed],
    )
    assert report["summary"]["status"] == "policy_not_authorized"
    assert [item["status"] for item in report["policy_results"]] == [
        "authorized",
        "unauthorized_policy",
    ]


def test_rehashed_signature_tampering_is_rejected(tmp_path):
    first, _, policy, _ = _roots(tmp_path)
    tampered = deepcopy(first)
    tampered["signatures"][0]["signature_base64"] = "aW52YWxpZA=="
    tampered.pop("root_sha256")
    tampered["root_sha256"] = canonical_sha256(tampered)
    report = evaluate_trust_root(
        tampered,
        evaluation_time=1_788_048_100,
        expected_root_sha256=tampered["root_sha256"],
        policies=[policy],
    )
    assert report["summary"]["status"] == "invalid_trust_evidence"
    assert "cryptographic signature is invalid" in " ".join(report["source_errors"])


def test_sarif_surfaces_expired_root_without_automatic_action(tmp_path):
    first, _, policy, _ = _roots(tmp_path)
    report = evaluate_trust_root(
        first,
        evaluation_time=first["expires_at"],
        expected_root_sha256=first["root_sha256"],
        policies=[policy],
    )
    result = report_to_sarif(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "ALTR003"
    assert result["properties"]["automaticActions"] == 0


def test_cli_evaluates_and_recomputes_rotation_report(tmp_path):
    from dspy_security_bench.ledger.cli import main as ledger_main

    first, second, policy, _ = _roots(tmp_path)
    first_path = tmp_path / "root-v1.json"
    second_path = tmp_path / "root-v2.json"
    policy_path = tmp_path / "ledger-policy.json"
    report_path = tmp_path / "trust-root.report.json"
    sarif_path = tmp_path / "trust-root.sarif"
    for path, payload in (
        (first_path, first),
        (second_path, second),
        (policy_path, policy),
    ):
        path.write_text(json.dumps(payload))
    assert (
        ledger_main(
            [
                "evaluate-trust-root",
                str(second_path),
                "--trusted-root",
                str(first_path),
                "--evaluation-time",
                "1788220800",
                "--policy",
                str(policy_path),
                "--out",
                str(report_path),
                "--sarif-out",
                str(sarif_path),
                "--fail-on-trust",
            ]
        )
        == 0
    )
    assert ledger_main(["verify-trust-root", str(report_path)]) == 0
    assert json.loads(report_path.read_text())["summary"]["status"] == "trusted_rotation"
    assert json.loads(sarif_path.read_text())["runs"][0]["results"] == []


def test_cli_creates_a_threshold_signed_root_from_data_only_spec(tmp_path):
    from dspy_security_bench.ledger.cli import main as ledger_main

    first, _, _, fixture = _roots(tmp_path)
    spec = {
        field: first[field]
        for field in (
            "trust_domain",
            "version",
            "issued_at",
            "expires_at",
            "keys",
            "roles",
            "authorized_policies",
        )
    }
    spec_path = tmp_path / "trust-root-spec.json"
    output = tmp_path / "created-root.json"
    spec_path.write_text(json.dumps(spec))
    paths = fixture["private_paths"]
    assert (
        ledger_main(
            [
                "create-trust-root",
                str(spec_path),
                "--private-key",
                str(paths["root-ed"]),
                "--private-key",
                str(paths["root-ec"]),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    created = json.loads(output.read_text())
    assert validate_trust_root(created) == ()
    assert {item["signature_scheme"] for item in created["signatures"]} == {
        "ed25519",
        "ecdsa-sha2-nistp256",
    }


def test_trust_root_schemas_validate_reference_artifacts(tmp_path):
    first, second, policy, _ = _roots(tmp_path)
    report = evaluate_trust_root(
        second,
        trusted_root=first,
        evaluation_time=1_788_220_800,
        policies=[policy],
    )
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    root_schema = json.loads(
        (schema_root / "assuranceledger-trust-root.schema.json").read_text()
    )
    report_schema = json.loads(
        (schema_root / "assuranceledger-trust-root-report.schema.json").read_text()
    )
    registry = Registry().with_resource(root_schema["$id"], Resource.from_contents(root_schema))
    jsonschema.Draft202012Validator(root_schema, registry=registry).validate(first)
    jsonschema.Draft202012Validator(report_schema, registry=registry).validate(report)
