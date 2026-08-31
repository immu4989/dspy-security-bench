from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.gossip import compare_views, verify_gossip_report
from dspy_security_bench.ledger.gossip_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> tuple[dict, dict, dict, dict]:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    current = json.loads((tmp_path / "current-trust.report.json").read_text())
    extended = json.loads((tmp_path / "compromise-invalidation.report.json").read_text())
    forked = json.loads((tmp_path / "forked-view.report.json").read_text())
    comparison = json.loads((tmp_path / "view-comparison.report.json").read_text())
    return current, extended, forked, comparison


def test_same_size_operator_signed_fork_is_cryptographic_equivocation_evidence(tmp_path):
    current, _, forked, comparison = _demo(tmp_path)
    assert (
        current["checkpoint"]["checkpoint"]["tree_size"]
        == forked["checkpoint"]["checkpoint"]["tree_size"]
    )
    assert (
        current["checkpoint"]["checkpoint"]["root_sha256"]
        != forked["checkpoint"]["checkpoint"]["root_sha256"]
    )
    assert comparison["summary"]["status"] == "equivocation_evidenced"
    assert comparison["summary"]["equivocation_pairs"] == 1
    assert comparison["comparisons"][0]["status"] == "equivocation_evidenced"
    assert verify_gossip_report(comparison, evidence_root=tmp_path / "quorum") == ()
    assert report_to_sarif(comparison)["runs"][0]["results"][0]["ruleId"] == "ALG001"


def test_later_checkpoint_with_exact_old_prefix_is_consistent(tmp_path):
    current, extended, _, _ = _demo(tmp_path)
    comparison = compare_views([current, extended], evidence_root=tmp_path / "quorum")
    assert comparison["summary"]["status"] == "views_consistent"
    assert comparison["comparisons"][0]["prefix_matches"] is True
    assert comparison["comparisons"][0]["prefix_root_matches"] is True
    assert report_to_sarif(comparison)["runs"][0]["results"] == []


def test_duplicate_checkpoint_has_insufficient_view_diversity(tmp_path):
    current, _, _, _ = _demo(tmp_path)
    comparison = compare_views([current, current], evidence_root=tmp_path / "quorum")
    assert comparison["summary"]["status"] == "insufficient_view_diversity"
    assert comparison["summary"]["distinct_checkpoints"] == 1


def test_invalid_ledger_view_cannot_be_used_as_fork_evidence(tmp_path):
    current, _, forked, _ = _demo(tmp_path)
    forked["checkpoint"]["operator_signature"]["signature_base64"] = "aW52YWxpZA=="
    forked.pop("report_sha256")
    forked["report_sha256"] = canonical_sha256(forked)
    comparison = compare_views([current, forked], evidence_root=tmp_path / "quorum")
    assert comparison["summary"]["status"] == "invalid_view_evidence"
    assert comparison["summary"]["equivocation_pairs"] == 0


def test_rehashed_summary_tampering_fails_semantic_recomputation(tmp_path):
    _, _, _, comparison = _demo(tmp_path)
    tampered = deepcopy(comparison)
    tampered["summary"]["status"] = "views_consistent"
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "AssuranceLedger Gossip report does not recompute exactly" in verify_gossip_report(
        tampered, evidence_root=tmp_path / "quorum"
    )


def test_compare_cli_emits_recomputable_report(tmp_path):
    current, extended, _, _ = _demo(tmp_path)
    current_path = tmp_path / "current-copy.json"
    extended_path = tmp_path / "extended-copy.json"
    output = tmp_path / "consistent-comparison.json"
    current_path.write_text(json.dumps(current))
    extended_path.write_text(json.dumps(extended))
    assert (
        ledger_main(
            [
                "compare",
                str(current_path),
                str(extended_path),
                "--evidence-root",
                str(tmp_path / "quorum"),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["summary"]["status"] == "views_consistent"


def test_gossip_schema_validates_reference_equivocation(tmp_path):
    _, _, _, comparison = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assurancequorum-policy.schema.json",
        "assurancequorum-report.schema.json",
        "assuranceledger-policy.schema.json",
        "assuranceledger-report.schema.json",
        "assuranceledger-gossip-report.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(comparison)
