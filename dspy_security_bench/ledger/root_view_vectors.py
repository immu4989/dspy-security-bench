"""Deterministic, language-neutral known-answer vectors for RootViewQuorum."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from dspy_security_bench.ledger.root_view import (
    PROTOCOL_VERSION as ROOT_VIEW_PROTOCOL_VERSION,
)
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
from dspy_security_bench.mission.loader import canonical_sha256

VECTOR_SUITE = "dspy-security-bench-root-view-known-answer-vectors"
VECTOR_VERSION = "assuranceledger-root-view-vectors-v1"
GENERATOR = "deterministic-root-view-vector-generator-v1"
MANIFEST_FILE = "vector-manifest.json"
EXPECTED_MANIFEST_SHA256 = "e39be2384f1ff8e49d8e62e26df112a01d181e5ece06a9e9f7df36dd93750e08"
MAX_VECTOR_FILES = 100
MAX_VECTOR_FILE_BYTES = 5_000_000
ALLOWED_UNBOUND_FILES = {"README.md"}
CANONICALIZATION = (
    "Protocol digests are SHA-256 over UTF-8 JSON with recursively sorted object keys, "
    "no insignificant whitespace, Unicode emitted directly, and non-finite numbers rejected; "
    "files use sorted keys, two-space indentation, and one LF terminator"
)
EXPECTED_CASE_IDS = (
    "matching-quorum",
    "lagging-view-preserved",
    "same-version-conflict",
    "newer-root-reported",
    "duplicate-observer",
    "nonce-mismatch",
    "invalid-observer-signature",
    "rehashed-summary-tamper",
)
CLAIM_BOUNDARY = (
    "RootViewQuorum KnownAnswerVectors binds deterministic public test artifacts, expected "
    "evaluation outcomes, verifier acceptance decisions, and exact file bytes for a finite "
    "RootViewQuorum v1 interoperability corpus. Passing the pack verifier demonstrates only "
    "behavior on these exact vectors; it is not general conformance, cryptographic-module "
    "validation, implementation certification, security certification, or deployment approval."
)
LIMITATIONS = (
    "The generator derives intentionally public test-only private keys from fixed labels; those keys must never be used outside fixtures.",
    "Generated artifacts contain public keys and signatures but no private-key material.",
    "The finite corpus cannot establish the absence of parser, canonicalization, signature, policy, or state-machine defects outside its cases.",
    "Expected error fragments describe this implementation's verifier surface and are not a cross-language error-message requirement.",
    "The pack is not NIST ACVP/CAVP, FIPS validation, TUF conformance, Sigstore conformance, government endorsement, or an authorization to operate.",
    "Generation and verification perform no network access, root installation, deployment, notification, revocation, or automatic remediation.",
)
DOMAIN = "root-view-vector.example/assurance"
REQUEST_NONCE_V1 = "known-answer-root-view-challenge-0001"
REQUEST_NONCE_MISMATCH = "known-answer-root-view-challenge-0002"

_MANIFEST_FIELDS = {
    "schema_version",
    "vector_suite",
    "vector_version",
    "root_view_protocol_version",
    "generator",
    "canonicalization",
    "test_only_keys",
    "private_keys_included",
    "file_sha256",
    "cases",
    "claim_boundary",
    "limitations",
    "manifest_sha256",
}
_CASE_FIELDS = {
    "case_id",
    "operation",
    "policy_file",
    "candidate_root_file",
    "receipt_files",
    "expected_policy_sha256",
    "expected_request_nonce",
    "report_file",
    "expected_status",
    "expected_verifier_acceptance",
    "expected_error_fragment",
}


def generate_root_view_vector_pack(out_dir: str | Path) -> dict[str, Any]:
    """Generate a byte-stable RootViewQuorum v1 interoperability pack."""

    destination = Path(out_dir)
    if destination.exists():
        raise ValueError(f"vector output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="root-view-vectors-") as temporary:
        workspace = Path(temporary)
        staging = workspace / "pack"
        staging.mkdir()
        artifacts, cases = _build_vector_artifacts(workspace)
        for relative, payload in artifacts.items():
            _write_json(staging / relative, payload)
        file_sha256 = {
            relative: hashlib.sha256((staging / relative).read_bytes()).hexdigest()
            for relative in sorted(artifacts)
        }
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "vector_suite": VECTOR_SUITE,
            "vector_version": VECTOR_VERSION,
            "root_view_protocol_version": ROOT_VIEW_PROTOCOL_VERSION,
            "generator": GENERATOR,
            "canonicalization": CANONICALIZATION,
            "test_only_keys": True,
            "private_keys_included": False,
            "file_sha256": file_sha256,
            "cases": cases,
            "claim_boundary": CLAIM_BOUNDARY,
            "limitations": list(LIMITATIONS),
        }
        manifest["manifest_sha256"] = canonical_sha256(manifest)
        _write_json(staging / MANIFEST_FILE, manifest)
        shutil.copytree(staging, destination)
    errors = verify_root_view_vector_pack(destination)
    if errors:
        raise RuntimeError("generated vector pack failed verification: " + "; ".join(errors))
    return manifest


def verify_root_view_vector_pack(pack_dir: str | Path) -> tuple[str, ...]:
    """Verify exact bytes and execute every evaluation or rejection vector."""

    root = Path(pack_dir)
    errors: list[str] = []
    try:
        manifest = _read_json(root / MANIFEST_FILE)
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        return (f"cannot read vector manifest: {exc}",)
    errors.extend(_validate_manifest(manifest))
    if errors:
        return tuple(dict.fromkeys(errors))
    file_digests = manifest.get("file_sha256")
    declared = set(file_digests) if isinstance(file_digests, Mapping) else set()
    try:
        entries = list(root.rglob("*"))
        symlinks = sorted(
            path.relative_to(root).as_posix() for path in entries if path.is_symlink()
        )
        if symlinks:
            errors.append(f"vector pack contains symbolic links: {symlinks}")
        actual_files = {
            path.relative_to(root).as_posix() for path in entries if path.is_file()
        }
        actual = {
            relative
            for relative in actual_files
            if relative.endswith(".json") and relative != MANIFEST_FILE
        }
        unexpected_files = actual_files - declared - {MANIFEST_FILE} - ALLOWED_UNBOUND_FILES
        if unexpected_files:
            errors.append(f"vector pack contains unexpected files: {sorted(unexpected_files)}")
    except OSError as exc:
        errors.append(f"cannot enumerate vector files: {exc}")
        actual = set()
    if declared != actual:
        errors.append(
            f"vector file set mismatch: missing={sorted(declared - actual)}, "
            f"unexpected={sorted(actual - declared)}"
        )
    for relative in sorted(declared):
        try:
            path = _vector_path(root, relative)
            raw = _bounded_bytes(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{relative}: {exc}")
            continue
        claimed = file_digests.get(relative) if isinstance(file_digests, Mapping) else None
        if claimed != hashlib.sha256(raw).hexdigest():
            errors.append(f"{relative}: file SHA-256 does not match the manifest")
    if errors:
        return tuple(dict.fromkeys(errors))

    for case in manifest["cases"]:
        case_id = case["case_id"]
        try:
            report = _read_vector_json(root, case["report_file"])
            if case["operation"] == "evaluate":
                expected = evaluate_root_view_quorum(
                    _read_vector_json(root, case["policy_file"]),
                    _read_vector_json(root, case["candidate_root_file"]),
                    [
                        _read_vector_json(root, relative)
                        for relative in case["receipt_files"]
                    ],
                    expected_policy_sha256=case["expected_policy_sha256"],
                    expected_request_nonce=case["expected_request_nonce"],
                )
                if report != expected:
                    errors.append(f"{case_id}: stored report does not match native evaluation")
                if report.get("summary", {}).get("status") != case["expected_status"]:
                    errors.append(f"{case_id}: evaluation status does not match the manifest")
            verifier_errors = verify_root_view_report(report)
            accepted = not verifier_errors
            if accepted != case["expected_verifier_acceptance"]:
                errors.append(f"{case_id}: verifier acceptance does not match the manifest")
            fragment = case["expected_error_fragment"]
            if fragment is not None and not any(fragment in item for item in verifier_errors):
                errors.append(f"{case_id}: expected verifier error fragment was not observed")
        except (KeyError, OSError, TypeError, ValueError) as exc:
            errors.append(f"{case_id}: vector execution failed: {exc}")
    return tuple(dict.fromkeys(errors))


def _build_vector_artifacts(
    workspace: Path,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    key_root = workspace / "keys"
    key_root.mkdir()
    root_private_paths = []
    root_descriptors = []
    for index in range(2):
        private, public = _fixed_ed25519_keypair(key_root, f"root-{index + 1}")
        root_private_paths.append(private)
        root_descriptors.append(
            trust_key_descriptor(
                public,
                entity_id=f"vector-root-{index + 1}",
                organization_id=f"vector-root-organization-{index + 1}",
            )
        )
    observer_private_paths = []
    observer_descriptors = []
    for index in range(3):
        private, public = _fixed_ed25519_keypair(key_root, f"observer-{index + 1}")
        observer_private_paths.append(private)
        observer_descriptors.append(
            root_view_observer_descriptor(
                public,
                observer_id=f"vector-observer-{index + 1}",
                organization_id=f"vector-observer-organization-{index + 1}",
            )
        )
    policy = build_root_view_policy(
        observer_descriptors,
        quorum_id="root-view-known-answer",
        trust_domain=DOMAIN,
        minimum_observers=2,
        minimum_distinct_organizations=2,
    )
    roles = _root_roles(root_descriptors)
    authorized_policies = [
        {
            "policy_type": "dspy-security-bench-assurance-ledger-policy",
            "policy_sha256": canonical_sha256({"known_answer_policy": 1}),
        }
    ]
    root_v1 = _sign_root(
        build_trust_root(
            root_descriptors,
            roles,
            authorized_policies,
            trust_domain=DOMAIN,
            version=1,
            issued_at=1_800_000_000,
            expires_at=1_900_000_000,
        ),
        root_private_paths,
    )
    conflicting_v1 = _sign_root(
        build_trust_root(
            root_descriptors,
            roles,
            authorized_policies,
            trust_domain=DOMAIN,
            version=1,
            issued_at=1_800_000_000,
            expires_at=1_900_000_001,
        ),
        root_private_paths,
    )
    root_v2 = _sign_root(
        build_trust_root(
            root_descriptors,
            roles,
            authorized_policies,
            trust_domain=DOMAIN,
            version=2,
            issued_at=1_800_000_100,
            expires_at=1_900_000_100,
            previous_root_sha256=root_v1["root_sha256"],
        ),
        root_private_paths,
    )
    for private in root_private_paths:
        root_v2 = sign_trust_root(root_v2, private, signing_root=root_v1)

    matching_v1 = _observer_receipts(
        policy, observer_private_paths, root_v1, root_v1["root_sha256"]
    )
    matching_v2 = _observer_receipts(
        policy, observer_private_paths, root_v2, root_v2["root_sha256"]
    )
    conflict_receipt = create_root_view_receipt(
        policy,
        observer_private_paths[2],
        conflicting_v1,
        observer_id="vector-observer-3",
        candidate_root_sha256=root_v1["root_sha256"],
        request_nonce=REQUEST_NONCE_V1,
    )
    newer_receipt = create_root_view_receipt(
        policy,
        observer_private_paths[2],
        root_v2,
        observer_id="vector-observer-3",
        candidate_root_sha256=root_v1["root_sha256"],
        request_nonce=REQUEST_NONCE_V1,
    )
    lagging_receipt = create_root_view_receipt(
        policy,
        observer_private_paths[2],
        root_v1,
        observer_id="vector-observer-3",
        candidate_root_sha256=root_v2["root_sha256"],
        request_nonce=REQUEST_NONCE_V1,
    )
    invalid_signature = deepcopy(matching_v1[0])
    invalid_signature["observer_signature"]["signature_base64"] = "aW52YWxpZA=="

    artifacts: dict[str, dict[str, Any]] = {
        "policy.json": policy,
        "roots/candidate-v1.json": root_v1,
        "roots/candidate-v2.json": root_v2,
        "roots/conflicting-v1.json": conflicting_v1,
    }
    for index, receipt in enumerate(matching_v1, start=1):
        artifacts[f"receipts/matching-v1-observer-{index}.json"] = receipt
    for index, receipt in enumerate(matching_v2[:2], start=1):
        artifacts[f"receipts/matching-v2-observer-{index}.json"] = receipt
    artifacts.update(
        {
            "receipts/conflicting-v1-observer-3.json": conflict_receipt,
            "receipts/newer-v2-observer-3.json": newer_receipt,
            "receipts/lagging-v1-observer-3.json": lagging_receipt,
            "receipts/invalid-signature-observer-1.json": invalid_signature,
        }
    )

    evaluation_specs = (
        (
            "matching-quorum",
            root_v1,
            "roots/candidate-v1.json",
            matching_v1,
            [f"receipts/matching-v1-observer-{index}.json" for index in range(1, 4)],
            REQUEST_NONCE_V1,
            "root_view_corroborated",
        ),
        (
            "lagging-view-preserved",
            root_v2,
            "roots/candidate-v2.json",
            [matching_v2[0], matching_v2[1], lagging_receipt],
            [
                "receipts/matching-v2-observer-1.json",
                "receipts/matching-v2-observer-2.json",
                "receipts/lagging-v1-observer-3.json",
            ],
            REQUEST_NONCE_V1,
            "root_view_corroborated",
        ),
        (
            "same-version-conflict",
            root_v1,
            "roots/candidate-v1.json",
            [matching_v1[0], matching_v1[1], conflict_receipt],
            [
                "receipts/matching-v1-observer-1.json",
                "receipts/matching-v1-observer-2.json",
                "receipts/conflicting-v1-observer-3.json",
            ],
            REQUEST_NONCE_V1,
            "same_version_root_conflict",
        ),
        (
            "newer-root-reported",
            root_v1,
            "roots/candidate-v1.json",
            [matching_v1[0], matching_v1[1], newer_receipt],
            [
                "receipts/matching-v1-observer-1.json",
                "receipts/matching-v1-observer-2.json",
                "receipts/newer-v2-observer-3.json",
            ],
            REQUEST_NONCE_V1,
            "newer_root_reported",
        ),
        (
            "duplicate-observer",
            root_v1,
            "roots/candidate-v1.json",
            [matching_v1[0], matching_v1[0], matching_v1[1]],
            [
                "receipts/matching-v1-observer-1.json",
                "receipts/matching-v1-observer-1.json",
                "receipts/matching-v1-observer-2.json",
            ],
            REQUEST_NONCE_V1,
            "insufficient_root_observers",
        ),
        (
            "nonce-mismatch",
            root_v1,
            "roots/candidate-v1.json",
            matching_v1,
            [f"receipts/matching-v1-observer-{index}.json" for index in range(1, 4)],
            REQUEST_NONCE_MISMATCH,
            "root_view_request_mismatch",
        ),
        (
            "invalid-observer-signature",
            root_v1,
            "roots/candidate-v1.json",
            [invalid_signature, matching_v1[1], matching_v1[2]],
            [
                "receipts/invalid-signature-observer-1.json",
                "receipts/matching-v1-observer-2.json",
                "receipts/matching-v1-observer-3.json",
            ],
            REQUEST_NONCE_V1,
            "invalid_root_view_evidence",
        ),
    )
    cases = []
    matching_report: dict[str, Any] | None = None
    for (
        case_id,
        candidate,
        candidate_file,
        receipts,
        receipt_files,
        expected_nonce,
        expected_status,
    ) in evaluation_specs:
        report = evaluate_root_view_quorum(
            policy,
            candidate,
            receipts,
            expected_policy_sha256=policy["policy_sha256"],
            expected_request_nonce=expected_nonce,
        )
        report_file = f"reports/{case_id}.json"
        artifacts[report_file] = report
        if case_id == "matching-quorum":
            matching_report = report
        cases.append(
            _case(
                case_id,
                operation="evaluate",
                policy_file="policy.json",
                candidate_root_file=candidate_file,
                receipt_files=receipt_files,
                expected_policy_sha256=policy["policy_sha256"],
                expected_request_nonce=expected_nonce,
                report_file=report_file,
                expected_status=expected_status,
                expected_verifier_acceptance=True,
                expected_error_fragment=None,
            )
        )
    if matching_report is None:
        raise RuntimeError("matching vector was not generated")
    tampered = deepcopy(matching_report)
    tampered["summary"]["matching_observers"] = 0
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    artifacts["reports/rehashed-summary-tamper.json"] = tampered
    cases.append(
        _case(
            "rehashed-summary-tamper",
            operation="verify-report",
            policy_file=None,
            candidate_root_file=None,
            receipt_files=[],
            expected_policy_sha256=None,
            expected_request_nonce=None,
            report_file="reports/rehashed-summary-tamper.json",
            expected_status=None,
            expected_verifier_acceptance=False,
            expected_error_fragment="RootViewQuorum report does not recompute exactly",
        )
    )
    return artifacts, cases


def _fixed_ed25519_keypair(root: Path, label: str) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(f"dspy-security-bench/{VECTOR_VERSION}/{label}".encode()).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    private_path = root / f"{label}.private.pem"
    public_path = root / f"{label}.public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _root_roles(descriptors: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    keyids = sorted(item["keyid"] for item in descriptors)
    return {
        role: {
            "keyids": keyids,
            "signature_threshold": 2 if role == "root" else 1,
            "minimum_distinct_organizations": 2 if role == "root" else 1,
        }
        for role in ROLE_NAMES
    }


def _sign_root(root: dict[str, Any], private_paths: list[Path]) -> dict[str, Any]:
    result = root
    for private in private_paths:
        result = sign_trust_root(result, private)
    return result


def _observer_receipts(
    policy: Mapping[str, Any],
    private_paths: list[Path],
    observed_root: Mapping[str, Any],
    candidate_root_sha256: str,
) -> list[dict[str, Any]]:
    return [
        create_root_view_receipt(
            policy,
            private,
            observed_root,
            observer_id=f"vector-observer-{index + 1}",
            candidate_root_sha256=candidate_root_sha256,
            request_nonce=REQUEST_NONCE_V1,
        )
        for index, private in enumerate(private_paths)
    ]


def _case(case_id: str, **values: Any) -> dict[str, Any]:
    return {"case_id": case_id, **values}


def _validate_manifest(manifest: Any) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(manifest, Mapping):
        return ("vector manifest must be an object",)
    if set(manifest) != _MANIFEST_FIELDS:
        errors.append("vector manifest fields are not exact")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("vector_suite") != VECTOR_SUITE
        or manifest.get("vector_version") != VECTOR_VERSION
        or manifest.get("root_view_protocol_version") != ROOT_VIEW_PROTOCOL_VERSION
        or manifest.get("generator") != GENERATOR
    ):
        errors.append("vector manifest metadata is unsupported")
    if manifest.get("canonicalization") != CANONICALIZATION:
        errors.append("vector manifest canonicalization contract is invalid")
    if manifest.get("test_only_keys") is not True:
        errors.append("vector manifest must identify test-only keys")
    if manifest.get("private_keys_included") is not False:
        errors.append("vector manifest must declare that private keys are absent")
    if manifest.get("claim_boundary") != CLAIM_BOUNDARY:
        errors.append("vector manifest claim_boundary is invalid")
    if manifest.get("limitations") != list(LIMITATIONS):
        errors.append("vector manifest limitations are invalid")
    files = manifest.get("file_sha256")
    if not isinstance(files, Mapping) or not 1 <= len(files) <= MAX_VECTOR_FILES:
        errors.append(f"file_sha256 must contain 1 to {MAX_VECTOR_FILES} entries")
        files = {}
    for relative, digest in files.items():
        if not _safe_relative_json(relative):
            errors.append(f"file_sha256 contains unsafe path {relative!r}")
        if not _is_digest(digest):
            errors.append(f"file_sha256 for {relative!r} is invalid")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASE_IDS):
        errors.append(f"cases must contain exactly {len(EXPECTED_CASE_IDS)} entries")
        cases = []
    elif [item.get("case_id") if isinstance(item, Mapping) else None for item in cases] != list(
        EXPECTED_CASE_IDS
    ):
        errors.append("case identifiers or ordering do not match known-answer v1")
    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping) or set(case) != _CASE_FIELDS:
            errors.append(f"cases[{index}] fields are not exact")
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(f"cases[{index}].case_id is invalid")
        elif case_id in case_ids:
            errors.append(f"case_id {case_id!r} is duplicated")
        else:
            case_ids.add(case_id)
        operation = case.get("operation")
        if operation not in {"evaluate", "verify-report"}:
            errors.append(f"cases[{index}].operation is unsupported")
        receipt_files = case.get("receipt_files")
        if not isinstance(receipt_files, list):
            errors.append(f"cases[{index}].receipt_files must be an array")
            receipt_files = []
        paths = [case.get("report_file"), *receipt_files]
        for field in ("policy_file", "candidate_root_file"):
            value = case.get(field)
            if value is not None:
                paths.append(value)
        if any(not _safe_relative_json(path) or path not in files for path in paths):
            errors.append(f"cases[{index}] references an undeclared or unsafe file")
        if operation == "evaluate":
            if case.get("policy_file") is None or case.get("candidate_root_file") is None:
                errors.append(f"cases[{index}] evaluation inputs are missing")
            if not receipt_files:
                errors.append(f"cases[{index}] receipts are missing")
            if not _is_digest(case.get("expected_policy_sha256")):
                errors.append(f"cases[{index}] expected policy digest is invalid")
            if not isinstance(case.get("expected_request_nonce"), str):
                errors.append(f"cases[{index}] expected request nonce is invalid")
            if not isinstance(case.get("expected_status"), str):
                errors.append(f"cases[{index}] expected status is invalid")
            if case.get("expected_verifier_acceptance") is not True:
                errors.append(f"cases[{index}] evaluation must be verifier-accepted")
            if case.get("expected_error_fragment") is not None:
                errors.append(f"cases[{index}] evaluation cannot expect a verifier error")
        elif operation == "verify-report":
            if any(
                case.get(field) is not None
                for field in (
                    "policy_file",
                    "candidate_root_file",
                    "expected_policy_sha256",
                    "expected_request_nonce",
                    "expected_status",
                )
            ):
                errors.append(f"cases[{index}] report-rejection inputs must be null")
            if receipt_files:
                errors.append(f"cases[{index}] report-rejection receipts must be empty")
            if case.get("expected_verifier_acceptance") is not False:
                errors.append(f"cases[{index}] report rejection must not be verifier-accepted")
            if not isinstance(case.get("expected_error_fragment"), str) or not case.get(
                "expected_error_fragment"
            ):
                errors.append(f"cases[{index}] report rejection must name an error fragment")
        if not isinstance(case.get("expected_verifier_acceptance"), bool):
            errors.append(f"cases[{index}] verifier expectation is invalid")
        fragment = case.get("expected_error_fragment")
        if fragment is not None and not isinstance(fragment, str):
            errors.append(f"cases[{index}] error fragment is invalid")
    unsigned = dict(manifest)
    claimed = unsigned.pop("manifest_sha256", None)
    if not _is_digest(claimed):
        errors.append("manifest_sha256 is invalid")
    elif claimed != EXPECTED_MANIFEST_SHA256:
        errors.append("manifest_sha256 does not match immutable known-answer v1")
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("manifest_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("vector manifest is not canonical JSON data")
    return tuple(dict.fromkeys(errors))


def _read_vector_json(root: Path, relative: str) -> dict[str, Any]:
    return _read_json(_vector_path(root, relative))


def _vector_path(root: Path, relative: str) -> Path:
    if not _safe_relative_json(relative):
        raise ValueError("vector path must be a safe relative JSON path")
    path = root / relative
    if not path.is_file():
        raise ValueError("vector path must be a regular file")
    return path


def _bounded_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("path must be a regular file")
    if path.stat().st_size > MAX_VECTOR_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_VECTOR_FILE_BYTES} bytes")
    return path.read_bytes()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(_bounded_bytes(path))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be an object")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )


def _safe_relative_json(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith(".json"):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value == path.as_posix()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
