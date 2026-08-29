from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.authority.passport import (
    analyze_passport,
    built_in_passport,
    validate_passport,
    verify_report,
)
from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.mission.loader import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


def _redigest(passport):
    passport.pop("passport_sha256", None)
    passport["passport_sha256"] = canonical_sha256(passport)


def test_passport_fixtures_validate_against_code_and_schema():
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/agent-identity-passport.schema.json").read_text()
    )
    for profile in ("bounded", "revoked", "ambient"):
        passport = built_in_passport(profile)
        assert validate_passport(passport) == ()
        jsonschema.validate(passport, schema)


def test_bounded_passport_verifies_and_recomputes():
    report = analyze_passport(built_in_passport("bounded"))
    schema = json.loads(
        (
            ROOT / "dspy_security_bench/schemas/agent-identity-passport-report.schema.json"
        ).read_text()
    )
    jsonschema.validate(report, schema)
    assert report["summary"]["status"] == "verified"
    assert report["summary"]["finding_count"] == 0
    assert verify_report(report) == ()


def test_revocation_prevents_effect_authority_claim():
    report = analyze_passport(built_in_passport("revoked"))
    assert report["summary"]["status"] == "review_required"
    assert {item["rule_id"] for item in report["findings"]} == {"IP004"}


def test_effect_must_match_action_resource_and_audience_exactly():
    passport = built_in_passport("bounded")
    passport["effect_receipts"][0]["resource_id"] = "record-2"
    _redigest(passport)
    report = analyze_passport(passport)
    assert "IP005" in {item["rule_id"] for item in report["findings"]}


def test_delegation_cannot_expand_scope():
    passport = built_in_passport("bounded")
    first = passport["delegation_chain"][0]
    first["delegate_id"] = "agent-worker"
    passport["delegation_chain"].append(
        {
            **deepcopy(first),
            "link_id": "delegation-2",
            "parent_link_id": "delegation-1",
            "delegator_id": "agent-worker",
            "delegate_id": "agent-orchestrator",
            "scopes": ["records:read", "records:write"],
        }
    )
    _redigest(passport)
    report = analyze_passport(passport)
    assert "IP002" in {item["rule_id"] for item in report["findings"]}


def test_passport_cli_round_trip(tmp_path):
    passport = tmp_path / "passport.json"
    report = tmp_path / "report.json"
    assert umbrella_main(["authority", "passport", "init", "--out", str(passport)]) == 0
    assert umbrella_main(["authority", "passport", "run", str(passport), "--out", str(report)]) == 0
    assert umbrella_main(["authority", "passport", "verify", str(report)]) == 0
