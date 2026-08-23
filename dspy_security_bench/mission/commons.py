"""Ed25519-signed MissionPack envelopes and a content-addressed local catalog."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dspy_security_bench.mission.loader import canonical_sha256, load_mission_pack

ENVELOPE_TYPE = "dspy-security-bench-signed-mission-pack"
CATALOG_TYPE = "dspy-security-bench-mission-pack-commons"
DISCLAIMER = (
    "A valid signature establishes byte integrity and possession of the corresponding private "
    "key; it does not establish author identity, agency authorship, source accuracy, safety, "
    "fitness, approval, certification, or government endorsement. Catalog maintainers must "
    "govern trusted key fingerprints and review pack content independently."
)


def generate_ed25519_keypair(
    private_path: str | Path, public_path: str | Path
) -> tuple[Path, Path]:
    Ed25519PrivateKey, _, serialization, _ = _crypto()
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_target, public_target = Path(private_path), Path(public_path)
    for target in (private_target, public_target):
        if target.exists():
            raise FileExistsError(f"kept existing {target}; choose new paths")
        target.parent.mkdir(parents=True, exist_ok=True)
    private_target.write_bytes(private_bytes)
    os.chmod(private_target, 0o600)
    public_target.write_bytes(public_bytes)
    return private_target, public_target


def sign_mission_pack(
    pack_source: str | Path | Mapping[str, Any],
    private_key_path: str | Path,
    *,
    signer: str,
) -> dict[str, Any]:
    if not isinstance(signer, str) or not signer.strip():
        raise ValueError("signer must be a non-empty accountable identifier")
    Ed25519PrivateKey, _, serialization, _ = _crypto()
    try:
        private = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=None
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"could not load Ed25519 private key: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("MissionPack signing requires an Ed25519 private key")
    pack = load_mission_pack(pack_source)
    payload_bytes = _canonical_bytes(pack.raw)
    signature = private.sign(payload_bytes)
    public_der = private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    envelope: dict[str, Any] = {
        "schema_version": 1,
        "envelope_type": ENVELOPE_TYPE,
        "algorithm": "Ed25519",
        "signer": signer.strip(),
        "public_key_spki_base64": base64.b64encode(public_der).decode(),
        "public_key_sha256": hashlib.sha256(public_der).hexdigest(),
        "payload": pack.raw,
        "payload_sha256": pack.protocol_sha256,
        "signature_base64": base64.b64encode(signature).decode(),
        "trust_status": "cryptographically_valid_unreviewed",
        "disclaimer": DISCLAIMER,
    }
    envelope["envelope_sha256"] = canonical_sha256(envelope)
    return envelope


def verify_signed_mission_pack(envelope: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "envelope_type",
        "algorithm",
        "signer",
        "public_key_spki_base64",
        "public_key_sha256",
        "payload",
        "payload_sha256",
        "signature_base64",
        "trust_status",
        "disclaimer",
        "envelope_sha256",
    }
    if set(envelope) != fields:
        errors.append("signed MissionPack envelope fields are incomplete or unsupported")
    if envelope.get("schema_version") != 1 or envelope.get("envelope_type") != ENVELOPE_TYPE:
        errors.append("unsupported signed MissionPack envelope version or type")
    if envelope.get("algorithm") != "Ed25519":
        errors.append("unsupported MissionPack signature algorithm")
    if envelope.get("trust_status") != "cryptographically_valid_unreviewed":
        errors.append("signed MissionPack trust_status must remain unreviewed")
    if envelope.get("disclaimer") != DISCLAIMER:
        errors.append("signed MissionPack disclaimer does not match the protocol")
    if not isinstance(envelope.get("signer"), str) or not envelope["signer"].strip():
        errors.append("signed MissionPack signer must be non-empty")
    try:
        pack = load_mission_pack(envelope.get("payload", {}))
        if envelope.get("payload_sha256") != pack.protocol_sha256:
            errors.append("payload_sha256 does not match the MissionPack")
    except ValueError as exc:
        errors.append(f"invalid signed MissionPack payload: {exc}")
        pack = None
    try:
        public_der = base64.b64decode(
            str(envelope.get("public_key_spki_base64", "")), validate=True
        )
        signature = base64.b64decode(str(envelope.get("signature_base64", "")), validate=True)
    except (ValueError, TypeError) as exc:
        errors.append(f"invalid signed MissionPack base64: {exc}")
        public_der, signature = b"", b""
    if envelope.get("public_key_sha256") != hashlib.sha256(public_der).hexdigest():
        errors.append("public_key_sha256 does not match the embedded public key")
    if pack is not None and public_der and signature:
        try:
            _, Ed25519PublicKey, serialization, InvalidSignature = _crypto()
            public = serialization.load_der_public_key(public_der)
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("embedded key is not Ed25519")
            public.verify(signature, _canonical_bytes(pack.raw))
        except InvalidSignature:
            errors.append("MissionPack Ed25519 signature is invalid")
        except (TypeError, ValueError) as exc:
            errors.append(f"invalid embedded MissionPack public key: {exc}")
    unsigned = dict(envelope)
    claimed = unsigned.pop("envelope_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError):
        actual = None
    if claimed != actual:
        errors.append("envelope_sha256 does not match canonical envelope content")
    return tuple(dict.fromkeys(errors))


def build_mission_pack_catalog(envelope_paths: list[str | Path]) -> dict[str, Any]:
    if not envelope_paths:
        raise ValueError("catalog requires at least one signed MissionPack envelope")
    entries = []
    identities: set[tuple[str, str]] = set()
    names: set[str] = set()
    for source in envelope_paths:
        path = Path(source)
        if path.name in names:
            raise ValueError(f"duplicate envelope file name {path.name!r}")
        try:
            envelope = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"could not read signed MissionPack {path}: {exc}") from exc
        if not isinstance(envelope, Mapping):
            raise ValueError(f"signed MissionPack {path} must be an object")
        errors = verify_signed_mission_pack(envelope)
        if errors:
            raise ValueError(f"invalid signed MissionPack {path}: {'; '.join(errors)}")
        payload = envelope["payload"]
        identity = (payload["pack_id"], payload["version"])
        if identity in identities:
            raise ValueError(f"duplicate MissionPack identity {identity[0]}@{identity[1]}")
        identities.add(identity)
        names.add(path.name)
        entries.append(
            {
                "pack_id": identity[0],
                "version": identity[1],
                "name": payload["name"],
                "domain": payload["domain"],
                "license": payload["license"],
                "signer": envelope["signer"],
                "public_key_sha256": envelope["public_key_sha256"],
                "payload_sha256": envelope["payload_sha256"],
                "envelope_sha256": envelope["envelope_sha256"],
                "envelope_file": path.name,
                "review_status": "unreviewed",
            }
        )
    entries.sort(key=lambda item: (item["pack_id"], item["version"]))
    catalog: dict[str, Any] = {
        "schema_version": 1,
        "catalog_type": CATALOG_TYPE,
        "entries": entries,
        "trust_model": "signature validity plus separately governed key and content review",
        "disclaimer": DISCLAIMER,
    }
    catalog["catalog_sha256"] = canonical_sha256(catalog)
    return catalog


def verify_mission_pack_catalog(catalog: Mapping[str, Any], root: str | Path) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "catalog_type",
        "entries",
        "trust_model",
        "disclaimer",
        "catalog_sha256",
    }
    if set(catalog) != fields:
        errors.append("MissionPack catalog fields are incomplete or unsupported")
    if catalog.get("schema_version") != 1 or catalog.get("catalog_type") != CATALOG_TYPE:
        errors.append("unsupported MissionPack catalog version or type")
    if (
        catalog.get("trust_model")
        != "signature validity plus separately governed key and content review"
    ):
        errors.append("MissionPack catalog trust_model does not match the protocol")
    if catalog.get("disclaimer") != DISCLAIMER:
        errors.append("MissionPack catalog disclaimer does not match the protocol")
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("MissionPack catalog entries must be non-empty")
    else:
        expected_fields = {
            "pack_id",
            "version",
            "name",
            "domain",
            "license",
            "signer",
            "public_key_sha256",
            "payload_sha256",
            "envelope_sha256",
            "envelope_file",
            "review_status",
        }
        identities = set()
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != expected_fields:
                errors.append("MissionPack catalog entry fields are invalid")
                continue
            identity = (entry.get("pack_id"), entry.get("version"))
            if identity in identities:
                errors.append(f"duplicate MissionPack catalog identity {identity}")
            identities.add(identity)
            name = entry.get("envelope_file")
            if not isinstance(name, str) or Path(name).name != name:
                errors.append("MissionPack catalog contains an unsafe envelope_file")
                continue
            path = Path(root) / name
            try:
                envelope = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"could not read catalog envelope {name}: {exc}")
                continue
            envelope_errors = verify_signed_mission_pack(envelope)
            errors.extend(f"{name}: {item}" for item in envelope_errors)
            comparisons = {
                "pack_id": envelope.get("payload", {}).get("pack_id"),
                "version": envelope.get("payload", {}).get("version"),
                "name": envelope.get("payload", {}).get("name"),
                "domain": envelope.get("payload", {}).get("domain"),
                "license": envelope.get("payload", {}).get("license"),
                "signer": envelope.get("signer"),
                "public_key_sha256": envelope.get("public_key_sha256"),
                "payload_sha256": envelope.get("payload_sha256"),
                "envelope_sha256": envelope.get("envelope_sha256"),
                "review_status": "unreviewed",
            }
            for field, expected in comparisons.items():
                if entry.get(field) != expected:
                    errors.append(f"{name}: catalog {field} does not match envelope")
        if entries != sorted(
            entries, key=lambda item: (item.get("pack_id", ""), item.get("version", ""))
        ):
            errors.append("MissionPack catalog entries are not canonically sorted")
    unsigned = dict(catalog)
    claimed = unsigned.pop("catalog_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError):
        actual = None
    if claimed != actual:
        errors.append("catalog_sha256 does not match canonical catalog content")
    return tuple(dict.fromkeys(errors))


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - depends on optional environment
        raise RuntimeError(
            "MissionPack signing requires: pip install 'dspy-security-bench[signing]'"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature
