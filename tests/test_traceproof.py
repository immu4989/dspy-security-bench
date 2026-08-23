import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.trace.proof import (
    analyze_trace_evidence,
    build_trace_evidence,
    demo_otlp_payload,
    export_oscal,
    export_sarif,
    synthesize_trace_twin,
    verify_trace_artifact,
    verify_trace_evidence,
    verify_trace_report,
)


def test_traceproof_redacts_content_and_detects_authority_failures():
    evidence = build_trace_evidence(demo_otlp_payload())
    encoded = json.dumps(evidence)
    assert "Synthetic prompt" not in encoded
    assert "Bearer synthetic" not in encoded
    assert "unsafe sensitive production-like name" not in encoded
    assert evidence["span_count"] == 1
    assert evidence["redaction_summary"]["content_fields_removed"] >= 1
    assert evidence["redaction_summary"]["secret_fields_removed"] >= 1
    assert verify_trace_evidence(evidence) == ()

    report = analyze_trace_evidence(evidence)
    assert report["summary"] == {
        "trace_count": 1,
        "span_count": 1,
        "finding_count": 5,
        "critical": 2,
        "high": 3,
        "medium": 0,
        "low": 0,
        "review_required": True,
    }
    assert {item["rule_id"] for item in report["findings"]} == {
        "TP002",
        "TP003",
        "TP004",
        "TP005",
        "TP012",
    }
    assert verify_trace_report(report) == ()
    assert export_sarif(report)["version"] == "2.1.0"
    assert export_oscal(report)["assessment-results"]["metadata"]["oscal-version"] == "1.2.2"

    twin = synthesize_trace_twin(evidence, report)
    assert len(twin["scenarios"]) == 5
    assert verify_trace_artifact(twin) == ()


def test_traceproof_schemas_validate_evidence_and_report():
    evidence = build_trace_evidence(demo_otlp_payload())
    report = analyze_trace_evidence(evidence)
    package = files("dspy_security_bench").joinpath("schemas")
    evidence_schema = json.loads(package.joinpath("trace-evidence.schema.json").read_text())
    report_schema = json.loads(package.joinpath("trace-report.schema.json").read_text())
    jsonschema.Draft202012Validator(evidence_schema).validate(evidence)
    jsonschema.Draft202012Validator(report_schema).validate(report)


def test_traceproof_verifiers_reject_tampering():
    evidence = build_trace_evidence(demo_otlp_payload())
    tampered = deepcopy(evidence)
    tampered["spans"][0]["attributes"]["gen_ai.prompt"] = "leaked"
    assert "evidence_sha256 does not match canonical evidence content" in verify_trace_evidence(
        tampered
    )

    report = analyze_trace_evidence(evidence)
    tampered_report = deepcopy(report)
    tampered_report["findings"][0]["severity"] = "low"
    errors = verify_trace_report(tampered_report)
    assert "report_sha256 does not match canonical report content" in errors
    assert "findings are invalid" in errors


def test_traceproof_cli_demo_and_round_trip(tmp_path):
    output = tmp_path / "demo"
    assert root_main(["trace", "demo", "--out-dir", str(output)]) == 0
    evidence = output / "trace-evidence.json"
    report = output / "trace-report.json"
    assert root_main(["trace", "verify", str(evidence)]) == 0
    assert root_main(["trace", "verify", str(report)]) == 0
    assert (
        root_main(
            [
                "trace",
                "export",
                str(report),
                "--format",
                "sarif",
                "--out",
                str(tmp_path / "out.sarif"),
            ]
        )
        == 0
    )
