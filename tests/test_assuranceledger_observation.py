from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.observation import (
    analyze_observer_receipts,
    verify_observer_report,
)
from dspy_security_bench.ledger.observation_sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256


def _demo(tmp_path: Path) -> tuple[dict, dict, list[dict], dict]:
    assert ledger_main(["demo", "--out-dir", str(tmp_path)]) == 0
    observer_policy = json.loads((tmp_path / "observer-policy.json").read_text())
    ledger_policy = json.loads((tmp_path / "ledger-policy.json").read_text())
    receipts = [
        json.loads((tmp_path / f"observer-{name}.receipt.json").read_text())
        for name in ("one", "two")
    ]
    report = json.loads((tmp_path / "observer-comparison.report.json").read_text())
    return observer_policy, ledger_policy, receipts, report


def test_two_organizations_and_channels_evidence_observed_fork(tmp_path):
    _, _, _, report = _demo(tmp_path)
    assert report["summary"]["status"] == "independently_observed_equivocation"
    assert report["summary"]["distinct_organizations"] == 2
    assert report["summary"]["distinct_channels"] == 2
    assert report["summary"]["same_size_fork_pairs"] == 1
    assert verify_observer_report(report) == ()


def test_receipts_disclose_channel_digest_but_not_locator_or_log_entries(tmp_path):
    _, _, _, report = _demo(tmp_path)
    serialized = json.dumps(report, sort_keys=True)
    assert "fictional-airgap-drop-a" not in serialized
    assert "fictional-distributor-b" not in serialized
    assert '"entries"' not in serialized
    assert '"quorum_report"' not in serialized
    assert report["summary"]["embedded_log_entries"] == 0


def test_duplicate_observer_does_not_satisfy_independence(tmp_path):
    observer_policy, ledger_policy, receipts, _ = _demo(tmp_path)
    report = analyze_observer_receipts(observer_policy, ledger_policy, [receipts[0], receipts[0]])
    assert report["summary"]["status"] == "insufficient_observer_independence"
    assert report["summary"]["distinct_observers"] == 1


def test_rehashed_observer_signature_tampering_fails_semantic_verification(tmp_path):
    _, _, _, report = _demo(tmp_path)
    tampered = deepcopy(report)
    tampered["receipts"][0]["observer_signature"]["signature_base64"] = "aW52YWxpZA=="
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "ObserverReceipt report does not recompute exactly" in verify_observer_report(tampered)


def test_cli_verifies_saved_observer_report(tmp_path):
    _, _, _, _ = _demo(tmp_path)
    assert (
        ledger_main(
            ["verify-receipt-comparison", str(tmp_path / "observer-comparison.report.json")]
        )
        == 0
    )


def test_observer_report_schema_validates_reference_artifact(tmp_path):
    _, _, _, report = _demo(tmp_path)
    schema_root = Path(__file__).resolve().parents[1] / "dspy_security_bench" / "schemas"
    names = (
        "assuranceledger-policy.schema.json",
        "assuranceledger-report.schema.json",
        "assuranceledger-observer-policy.schema.json",
        "assuranceledger-observer-report.schema.json",
    )
    schemas = [json.loads((schema_root / name).read_text()) for name in names]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    jsonschema.Draft202012Validator(schemas[-1], registry=registry).validate(report)


def test_sarif_surfaces_independently_observed_equivocation(tmp_path):
    _, _, _, report = _demo(tmp_path)
    result = report_to_sarif(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "ALO001"
    assert result["properties"]["automaticActions"] == 0
