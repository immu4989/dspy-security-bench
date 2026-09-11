from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dspy_security_bench.ledger.root_view import (
    build_root_view_policy,
    create_root_view_receipt,
    evaluate_root_view_quorum,
    root_view_observer_descriptor,
    verify_root_view_report,
)
from dspy_security_bench.ledger.trust_root import (
    ROLE_NAMES,
    build_trust_root,
    sign_trust_root,
    trust_key_descriptor,
)
from dspy_security_bench.mission.commons import generate_ed25519_keypair
from dspy_security_bench.mission.loader import canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "interop" / "root-view-quorum-node" / "verify.mjs"
PACK = REPO_ROOT / "interop" / "root-view-quorum-v1"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _run(pack: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(NODE), str(RUNNER), str(pack)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def _run_report(report: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(NODE), str(RUNNER), "--report", str(report)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


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


def _multi_scheme_report(tmp_path: Path) -> dict:
    domain = "node-cross-language-root-view"
    root_keys = [
        ("ed25519-root", Ed25519PrivateKey.generate()),
        ("p256-root", ec.generate_private_key(ec.SECP256R1())),
        ("rsa-root", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ]
    private_paths = []
    descriptors = []
    for index, (name, private) in enumerate(root_keys, start=1):
        private_path, public_path = _write_private(tmp_path, name, private)
        private_paths.append(private_path)
        descriptors.append(
            trust_key_descriptor(
                public_path,
                entity_id=name,
                organization_id=f"root-organization-{index}",
            )
        )
    keyids = sorted(item["keyid"] for item in descriptors)
    root = build_trust_root(
        descriptors,
        {
            role: {
                "keyids": keyids,
                "signature_threshold": 3 if role == "root" else 1,
                "minimum_distinct_organizations": 3 if role == "root" else 1,
            }
            for role in ROLE_NAMES
        },
        [
            {
                "policy_type": "dspy-security-bench-assurance-ledger-policy",
                "policy_sha256": canonical_sha256({"fixture": "node-multi-scheme"}),
            }
        ],
        trust_domain=domain,
        version=1,
        issued_at=1_800_000_000,
        expires_at=1_900_000_000,
    )
    for private_path in private_paths:
        root = sign_trust_root(root, private_path)

    observer_private_paths = []
    observers = []
    for index in range(2):
        private_path = tmp_path / f"observer-{index}.private.pem"
        public_path = tmp_path / f"observer-{index}.public.pem"
        generate_ed25519_keypair(private_path, public_path)
        observer_private_paths.append(private_path)
        observers.append(
            root_view_observer_descriptor(
                public_path,
                observer_id=f"observer-{index + 1}",
                organization_id=f"observer-organization-{index + 1}",
            )
        )
    policy = build_root_view_policy(
        observers,
        quorum_id="node-cross-language-quorum",
        trust_domain=domain,
        minimum_observers=2,
        minimum_distinct_organizations=2,
    )
    nonce = "node-cross-language-nonce-0001"
    receipts = [
        create_root_view_receipt(
            policy,
            private_path,
            root,
            observer_id=f"observer-{index + 1}",
            candidate_root_sha256=root["root_sha256"],
            request_nonce=nonce,
        )
        for index, private_path in enumerate(observer_private_paths)
    ]
    return evaluate_root_view_quorum(
        policy,
        root,
        receipts,
        expected_policy_sha256=policy["policy_sha256"],
        expected_request_nonce=nonce,
    )


def test_independent_node_runner_executes_all_known_answer_cases():
    completed = _run(PACK)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    manifest = json.loads((PACK / "vector-manifest.json").read_text())
    assert result["implementation"] == "dspy-security-bench-root-view-node-v1"
    assert result["implementation_sha256"] == hashlib.sha256(RUNNER.read_bytes()).hexdigest()
    assert result["manifest_sha256"] == manifest["manifest_sha256"]
    assert [item["case_id"] for item in result["cases"]] == [
        item["case_id"] for item in manifest["cases"]
    ]
    assert result["cases"][-1]["verifier_accepted"] is False
    assert result["cases"][0]["observed_status"] == "root_view_corroborated"
    assert result["summary"] == {"passed": 8, "failed": 0, "automatic_actions": 0}


def test_independent_node_runner_rejects_byte_drift(tmp_path):
    pack = tmp_path / "pack"
    shutil.copytree(PACK, pack)
    policy = pack / "policy.json"
    policy.write_bytes(policy.read_bytes() + b"\n")
    completed = _run(pack)
    assert completed.returncode == 1
    assert "policy.json file digest mismatch" in completed.stderr


def test_independent_node_report_verifier_supports_all_root_signature_schemes(tmp_path):
    report = _multi_scheme_report(tmp_path)
    assert verify_root_view_report(report) == ()
    path = tmp_path / "multi-scheme.report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    completed = _run_report(path)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["accepted"] is True
    assert result["evidence_status"] == "root_view_corroborated"


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("summary", "candidate_root_version"),
        ("summary", "submitted_receipts"),
        ("summary", "valid_receipts"),
        ("summary", "distinct_observers"),
        ("summary", "matching_observers"),
        ("summary", "matching_organizations"),
        ("summary", "lagging_observers"),
        ("summary", "newer_root_reports"),
        ("summary", "same_version_conflicts"),
        ("summary", "passed_checks"),
        ("summary", "failed_checks"),
        ("summary", "content_fields_processed"),
        ("summary", "network_requests"),
        ("summary", "roots_installed"),
        ("summary", "automatic_actions"),
        ("findings", 0),
        ("receipt_results", 0),
        ("top", "analyzer"),
        ("top", "claim_boundary"),
        ("top", "limitations"),
        ("receipt_signature", 0),
    ],
)
def test_python_and_node_both_reject_rehashed_semantic_mutations(
    tmp_path, section, field
):
    report = json.loads((PACK / "reports" / "matching-quorum.json").read_text())
    if section == "summary":
        report["summary"][field] += 1
    elif section == "findings":
        report["findings"][field]["detail"] = "tampered"
    elif section == "receipt_results":
        report["receipt_results"][field]["classification"] = "newer"
    elif section == "receipt_signature":
        signature = report["receipts"][field]["observer_signature"]["signature_base64"]
        report["receipts"][field]["observer_signature"]["signature_base64"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:]
        )
    elif field == "limitations":
        report[field].append("tampered")
    else:
        report[field] = f"{report[field]}-tampered"
    report.pop("report_sha256")
    report["report_sha256"] = canonical_sha256(report)
    assert verify_root_view_report(report)
    path = tmp_path / f"{section}-{field}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    completed = _run_report(path)
    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert result["accepted"] is False
    assert "RootViewQuorum report does not recompute exactly" in result["errors"]


def test_independent_runner_does_not_delegate_to_python():
    source = RUNNER.read_text()
    assert "node:child_process" not in source
    assert "dspy_security_bench" not in source
