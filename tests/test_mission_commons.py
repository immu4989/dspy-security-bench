import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.mission.commons import (
    build_mission_pack_catalog,
    generate_ed25519_keypair,
    sign_mission_pack,
    verify_mission_pack_catalog,
    verify_signed_mission_pack,
)
from dspy_security_bench.mission.loader import load_mission_pack


@pytest.mark.parametrize(
    "name",
    [
        "benefits-assistance",
        "grants-review",
        "emergency-logistics",
        "records-release",
        "critical-infrastructure",
    ],
)
def test_public_service_packs_are_valid_bounded_synthetic_data(name):
    pack = load_mission_pack(name)
    assert len(pack.cases) == 1
    assert "Synthetic exercise only" in pack.raw["disclaimer"]
    assert all(
        source["authority"] != "untrusted" or not source["content"] for source in pack.sources
    )


def test_signed_pack_and_catalog_round_trip(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    assert private.stat().st_mode & 0o777 == 0o600
    envelope = sign_mission_pack("source-twin", private, signer="test-maintainer")
    assert verify_signed_mission_pack(envelope) == ()
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/signed-mission-pack.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(envelope)
    envelope_path = tmp_path / "source-twin.json"
    envelope_path.write_text(json.dumps(envelope))
    catalog = build_mission_pack_catalog([envelope_path])
    assert verify_mission_pack_catalog(catalog, tmp_path) == ()


def test_signed_pack_rejects_payload_tampering(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    envelope = sign_mission_pack("source-twin", private, signer="test-maintainer")
    tampered = deepcopy(envelope)
    tampered["payload"]["name"] = "Tampered"
    errors = verify_signed_mission_pack(tampered)
    assert "payload_sha256 does not match the MissionPack" in errors
    assert "MissionPack Ed25519 signature is invalid" in errors


def test_signed_pack_cli_round_trip(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    envelope, catalog = tmp_path / "pack.json", tmp_path / "catalog.json"
    assert (
        root_main(["pack", "keygen", "--private-key", str(private), "--public-key", str(public)])
        == 0
    )
    assert (
        root_main(
            [
                "pack",
                "sign",
                "source-twin",
                "--private-key",
                str(private),
                "--signer",
                "test",
                "--out",
                str(envelope),
            ]
        )
        == 0
    )
    assert root_main(["pack", "verify-signature", str(envelope)]) == 0
    assert root_main(["pack", "catalog-build", str(envelope), "--out", str(catalog)]) == 0
    assert root_main(["pack", "catalog-verify", str(catalog)]) == 0
