import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.inventory.forge import draft_mission_pack
from dspy_security_bench.inventory.loader import (
    find_use_case,
    load_inventory_report,
    load_public_inventory,
    verify_inventory_report,
)
from dspy_security_bench.mission.loader import load_mission_pack


def _csv(tmp_path):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "Use Case ID,Use Case Name,Agency,Summary of Use Case,Use Case Topic Area,Contact Email\n"
        "TEST-1,Acquisition helper,Example Agency,Helps draft outcome-based requirements,Procurement,person@example.gov\n"
    )
    return path


def test_public_inventory_normalizes_without_preserving_contacts(tmp_path):
    report = load_public_inventory(_csv(tmp_path))
    payload = report.to_dict()
    assert payload["record_count"] == 1
    assert payload["records"][0]["use_case_id"] == "TEST-1"
    assert "person@example.gov" not in json.dumps(payload)
    assert any("contact fields" in warning for warning in payload["warnings"])
    assert verify_inventory_report(payload) == ()


def test_inventory_report_rejects_nested_and_digest_tampering(tmp_path):
    payload = load_public_inventory(_csv(tmp_path)).to_dict()
    tampered = deepcopy(payload)
    tampered["records"][0]["summary"] = "changed"
    assert "report_sha256 does not match canonical report content" in verify_inventory_report(
        tampered
    )


def test_inventory_draft_is_schema_valid_and_explicitly_non_authoritative(tmp_path):
    payload = load_public_inventory(_csv(tmp_path)).to_dict()
    record = find_use_case(payload, "TEST-1")
    pack, manifest = draft_mission_pack(record)
    assert pack.raw["domain"] == "public-acquisition"
    assert len(pack.cases) == 3
    assert manifest["required_human_review"] is True
    assert "not agency-authored" in manifest["non_claims"]
    assert pack.protocol_sha256 == manifest["mission_pack_sha256"]


def test_inventory_cli_round_trip_and_schema(tmp_path, capsys):
    normalized = tmp_path / "normalized.json"
    pack_path = tmp_path / "pack.yaml"
    assert root_main(["inventory", "import", str(_csv(tmp_path)), "--out", str(normalized)]) == 0
    assert root_main(["inventory", "verify", str(normalized)]) == 0
    assert root_main(["inventory", "list", str(normalized)]) == 0
    assert "TEST-1" in capsys.readouterr().out
    assert (
        root_main(
            [
                "inventory",
                "draft-pack",
                str(normalized),
                "TEST-1",
                "--out",
                str(pack_path),
            ]
        )
        == 0
    )
    assert load_mission_pack(pack_path).pack_id == "public-inventory-test-1"
    report = load_inventory_report(normalized)
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("inventory-report.schema.json")
        .read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_inventory_import_does_not_overwrite_without_force(tmp_path):
    normalized = tmp_path / "normalized.json"
    normalized.write_text("owner content")
    assert root_main(["inventory", "import", str(_csv(tmp_path)), "--out", str(normalized)]) == 1
    assert normalized.read_text() == "owner content"
