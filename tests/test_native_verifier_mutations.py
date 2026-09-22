"""Cross-family malformed and self-rehashed artifact probes, entirely fictional."""

from copy import deepcopy

import pytest

from dspy_security_bench.assurance.cli import _demo_evidence
from dspy_security_bench.continuous.proof import build_evidence_snapshot
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.trace.proof import (
    analyze_trace_evidence,
    build_trace_evidence,
    demo_otlp_payload,
    verify_trace_report,
)


@pytest.fixture(scope="module")
def reports():
    return _demo_evidence()


def rehash(report):
    if "report_sha256" in report:
        report.pop("report_sha256")
        report["report_sha256"] = canonical_sha256(report)
    return report


@pytest.mark.parametrize("kind", ["authority", "trace", "collective-v2", "schedule", "verified-defense", "defense-portfolio", "containment", "evaluation-integrity", "dependency-impact"])
def test_rehashed_wrong_top_level_types_are_rejected_without_unhandled_crashes(reports, kind):
    original = reports[kind]
    tested = 0
    for field in original:
        if field.endswith("sha256"):
            continue
        for replacement in (None, [], {}, True, 0):
            candidate = deepcopy(original)
            candidate[field] = replacement
            if canonical_sha256(candidate) == canonical_sha256(original):
                continue
            rehash(candidate)
            tested += 1
            with pytest.raises((TypeError, ValueError)):
                build_evidence_snapshot(candidate, label="mutation-probe")
    assert tested >= 20


@pytest.mark.parametrize("location", ["report", "pair", "case"])
def test_authority_rejects_unsupported_claim_fields(reports, location):
    report = deepcopy(reports["authority"])
    target = report if location == "report" else report["pairs"][0]
    if location == "case":
        target = target["clean"]
    target["unsupported_claim"] = True
    with pytest.raises(ValueError, match="unsupported"):
        build_evidence_snapshot(report, label="mutation-probe")


def test_trace_rule_severity_cannot_be_downgraded_with_new_hashes():
    report = analyze_trace_evidence(build_trace_evidence(demo_otlp_payload()))
    finding = next(item for item in report["findings"] if item["severity"] == "critical")
    finding["severity"] = "low"
    finding.pop("finding_id")
    finding["finding_id"] = canonical_sha256(finding)[:24]
    report["summary"]["critical"] -= 1
    report["summary"]["low"] += 1
    rehash(report)
    assert "findings are invalid" in verify_trace_report(report)
    with pytest.raises(ValueError):
        build_evidence_snapshot(report, label="mutation-probe")


@pytest.mark.parametrize("field", ["trace_count", "span_count", "review_required", "critical"])
def test_trace_summary_rejects_boolean_numeric_aliases(field):
    report = analyze_trace_evidence(build_trace_evidence(demo_otlp_payload()))
    report["summary"][field] = 1 if field == "review_required" else True
    assert verify_trace_report(rehash(report))


@pytest.mark.parametrize("value", [None, True, 0, -1, 10001, {}, []])
def test_trace_report_requires_bounded_real_span_counts(value):
    report = analyze_trace_evidence(build_trace_evidence(demo_otlp_payload()))
    report["summary"]["span_count"] = value
    assert verify_trace_report(rehash(report))
