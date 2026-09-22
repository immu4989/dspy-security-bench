"""Changing the comparison evidence surface must not silently erase review gaps."""

import json
from copy import deepcopy

import pytest

from dspy_security_bench.continuous.cli import main
from dspy_security_bench.continuous.proof import (
    build_evidence_snapshot,
    compare_evidence,
    verify_continuous_proof,
    verify_snapshot_source,
)
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.value.proof import build_value_proof, measurement_template


def source():
    return build_value_proof(measurement_template())


def rehash(payload):
    payload.pop("proof_sha256", None)
    payload["proof_sha256"] = canonical_sha256(payload)
    return payload


@pytest.mark.parametrize("change", ["remove", "add", "empty"])
def test_metric_coverage_changes_cannot_report_within_threshold(change):
    before = build_evidence_snapshot(source(), label="before")
    after = deepcopy(before)
    if change == "remove":
        after["metrics"].pop(next(iter(after["metrics"])))
    elif change == "add":
        after["metrics"]["new.metric"] = 1.0
    else:
        before["metrics"] = {}
        rehash(before)
        after["metrics"] = {}
    rehash(after)
    with pytest.raises(ValueError, match="metric coverage"):
        compare_evidence(before, after)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), True, -1, 10**400])
def test_invalid_regression_thresholds_are_rejected(value):
    snapshot = build_evidence_snapshot(source(), label="reference")
    with pytest.raises(ValueError):
        compare_evidence(snapshot, snapshot, max_regression=value)


def test_boolean_schema_version_does_not_pass_after_rehash():
    snapshot = build_evidence_snapshot(source(), label="reference")
    snapshot["schema_version"] = True
    assert verify_continuous_proof(rehash(snapshot))


def test_boolean_drift_outcome_does_not_alias_integer_after_rehash():
    snapshot = build_evidence_snapshot(source(), label="reference")
    drift = compare_evidence(snapshot, snapshot)
    drift["metric_changes"][0]["threshold_exceeded"] = 0
    assert verify_continuous_proof(rehash(drift))


def test_self_consistent_snapshot_still_needs_source_reconstruction():
    evidence = source()
    snapshot = build_evidence_snapshot(evidence, label="reference")
    assert verify_snapshot_source(snapshot, evidence) == ()
    snapshot["metrics"][next(iter(snapshot["metrics"]))] += 0.25
    rehash(snapshot)
    assert verify_continuous_proof(snapshot) == ()
    assert verify_snapshot_source(snapshot, evidence)


def test_cli_source_verification_and_strict_json_intake(tmp_path, capsys):
    evidence = source()
    snapshot = build_evidence_snapshot(evidence, label="reference")
    source_path, snapshot_path = tmp_path / "source.json", tmp_path / "snapshot.json"
    source_path.write_text(json.dumps(evidence))
    snapshot_path.write_text(json.dumps(snapshot))
    assert main(["verify", str(snapshot_path), "--evidence", str(source_path)]) == 0
    assert main(["verify", str(snapshot_path)]) == 0
    assert "self-consistency only" in capsys.readouterr().out
    source_path.write_text('{"private-value":1,"private-value":2}')
    assert main(["verify", str(snapshot_path), "--evidence", str(source_path)]) == 2
    assert "private-value" not in capsys.readouterr().err


def test_source_option_rejects_drift_reports_rather_than_claiming_source_verification(tmp_path):
    evidence = source()
    snapshot = build_evidence_snapshot(evidence, label="reference")
    drift = compare_evidence(snapshot, snapshot)
    a, b = tmp_path / "drift.json", tmp_path / "source.json"
    a.write_text(json.dumps(drift))
    b.write_text(json.dumps(evidence))
    assert main(["verify", str(a), "--evidence", str(b)]) == 2
