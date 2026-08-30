from __future__ import annotations

import json

from dspy_security_bench.assurance.case import CLAIM_BOUNDARY, validate_case
from dspy_security_bench.assurance.cli import main
from dspy_security_bench.assurance.sectors import (
    SECTOR_BOUNDARY,
    sector_case,
    sector_ids,
    sector_profile,
)


def test_seven_sector_starters_are_sealed_valid_and_explicitly_incomplete():
    assert sector_ids() == (
        "emergency-logistics",
        "financial-investigation",
        "healthcare-administration",
        "manufacturing-maintenance",
        "public-benefits",
        "software-development",
        "water-operations",
    )
    for sector_id in sector_ids():
        case = sector_case(sector_id)
        assert validate_case(case) == ()
        assert case["claim_boundary"] == CLAIM_BOUNDARY
        assert SECTOR_BOUNDARY in case["description"]
        assert case["system"]["boundary"]
        assert case["decision_owner"].startswith("replace-")
        assert all(item["expected_sha256"] == "0" * 64 for item in case["evidence"])


def test_sector_profiles_are_copied_and_reject_unknown_ids():
    first = sector_profile("public-benefits")
    first["title"] = "changed"
    assert sector_profile("public-benefits")["title"] != "changed"
    try:
        sector_profile("unknown")
    except ValueError as exc:
        assert "unknown AssuranceGraph sector" in str(exc)
    else:
        raise AssertionError("unknown sector must fail")


def test_sector_cli_lists_inspects_and_initializes(tmp_path, capsys):
    assert main(["sectors"]) == 0
    assert "water-operations" in capsys.readouterr().out
    assert main(["sectors", "public-benefits", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["profile_id"] == "federal-high-impact"

    target = tmp_path / "case.json"
    assert (
        main(
            [
                "init",
                "--sector",
                "software-development",
                "--case-id",
                "software-pilot",
                "--evaluation-time",
                "100",
                "--out",
                str(target),
            ]
        )
        == 0
    )
    payload = json.loads(target.read_text())
    assert payload["case_id"] == "software-pilot"
    assert payload["evaluation_time"] == 100
    assert payload["profile_id"] == "enterprise-agent"
    assert validate_case(payload) == ()
