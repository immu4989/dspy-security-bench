from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.assurance.cli import main
from dspy_security_bench.assurance.exchange import (
    empty_exchange,
    exchange_summary,
    load_exchange,
    seal_exchange,
    validate_exchange,
)

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "submissions/assurance/index.json"


def _entry():
    return {
        "case_id": "synthetic-benefits-pilot",
        "profile_id": "federal-high-impact",
        "sector": "public-benefits",
        "report_sha256": "1" * 64,
        "case_sha256": "2" * 64,
        "source_repository": "https://github.com/example/assurance-case",
        "source_revision": "a1b2c3d4e5f6a7b8",
        "report_url": "https://github.com/example/assurance-case/blob/a1b2c3d4/report.json",
        "submitted_by": "independent-research-team",
        "disclosure": "synthetic",
        "status": "active",
        "claim_outcomes": {
            "supported": 6,
            "violated": 0,
            "contradicted": 0,
            "stale_evidence": 0,
            "missing_evidence": 1,
        },
        "evidence_kinds": [
            "authority",
            "trace",
            "collective-v2",
            "schedule",
            "verified-defense",
            "containment",
            "dependency-impact",
        ],
        "independent_reproductions": [
            {
                "reproduced_by": "second-independent-team",
                "report_sha256": "1" * 64,
                "source_repository": "https://github.com/example/reproduction",
                "source_revision": "d4e5f6a7b8c9d0e1",
                "reproduced_at": 1_788_048_100,
                "known_gap": "Recomputed structure does not establish observation truth.",
            }
        ],
        "updated_at": 1_788_048_000,
        "known_gaps": ["Synthetic records do not establish production telemetry completeness."],
    }


def test_committed_exchange_is_empty_valid_nonranking_and_schema_valid():
    exchange = load_exchange(INDEX)
    assert exchange == empty_exchange()
    assert validate_exchange(exchange) == ()
    assert exchange_summary(exchange) == {
        "entryCount": 0,
        "activeEntryCount": 0,
        "independentReproductionCount": 0,
        "sectorCount": 0,
        "rankingEnabled": False,
        "automaticEndorsements": 0,
    }
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/assurance-exchange.schema.json").read_text()
    )
    jsonschema.validate(exchange, schema)


def test_exchange_accepts_unfavorable_outcomes_and_counts_reproductions():
    exchange = empty_exchange()
    exchange["entries"] = [_entry()]
    exchange = seal_exchange(exchange)
    assert validate_exchange(exchange) == ()
    summary = exchange_summary(exchange)
    assert summary["entryCount"] == 1
    assert summary["independentReproductionCount"] == 1
    assert summary["rankingEnabled"] is False


def test_exchange_rejects_mutable_shape_credentials_duplicates_and_tamper():
    exchange = empty_exchange()
    entry = _entry()
    entry["source_repository"] = "https://user:secret@example.com/repository"
    exchange["entries"] = [entry, deepcopy(entry)]
    exchange = seal_exchange(exchange)
    errors = "; ".join(validate_exchange(exchange))
    assert "without credentials" in errors
    assert "duplicates a case/report identity" in errors

    tampered = deepcopy(exchange)
    tampered["ranking_enabled"] = True
    errors = "; ".join(validate_exchange(tampered))
    assert "ranking_enabled must be false" in errors
    assert "registry_sha256" in errors


def test_exchange_binds_outcome_counts_evidence_kinds_and_reproductions_to_report():
    entry = _entry()
    entry["claim_outcomes"]["supported"] = 5
    entry["evidence_kinds"].pop()
    entry["independent_reproductions"][0]["report_sha256"] = "4" * 64
    exchange = empty_exchange()
    exchange["entries"] = [entry]
    errors = "; ".join(validate_exchange(seal_exchange(exchange)))
    assert "must sum to the selected profile claim count" in errors
    assert "evidence_kinds must match the selected profile" in errors
    assert "report_sha256 must match the indexed report" in errors


def test_exchange_cli_verifies_and_reseals_an_edited_index(tmp_path, capsys):
    assert main(["exchange-verify", str(INDEX), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["entryCount"] == 0
    assert result["rankingEnabled"] is False

    edited = json.loads(INDEX.read_text())
    edited["entries"] = [_entry()]
    source = tmp_path / "edited.json"
    source.write_text(json.dumps(edited))
    sealed = tmp_path / "sealed.json"
    assert main(["exchange-seal", str(source), "--out", str(sealed)]) == 0
    assert "sealed exchange" in capsys.readouterr().out
    assert main(["exchange-verify", str(sealed)]) == 0
