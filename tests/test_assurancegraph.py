from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.assurance.case import (
    CLAIM_BOUNDARY,
    analyze_case,
    built_in_case,
    protocol_payload,
    seal_case,
    validate_case,
    verify_report,
)
from dspy_security_bench.assurance.cli import _demo_evidence
from dspy_security_bench.assurance.exports import export_oscal, export_sarif, render_html
from dspy_security_bench.assurance.profiles import built_in_profile, profile_ids
from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.trace.proof import (
    analyze_trace_evidence,
    build_trace_evidence,
    demo_otlp_payload,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_profile_evidence(root: Path, case: dict, evidence: dict | None = None) -> dict:
    supplied = _demo_evidence() if evidence is None else evidence
    for item in case["evidence"]:
        payload = supplied[item["evidence_kind"]]
        target = root / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload))
        item["expected_sha256"] = canonical_sha256(payload)
        item["owner"] = "test-evidence-owner"
    return seal_case(case)


def test_every_profile_is_content_addressed_and_has_distinct_evidence_claims():
    assert profile_ids() == (
        "critical-infrastructure",
        "enterprise-agent",
        "federal-high-impact",
        "frontier-lab",
    )
    for profile_id in profile_ids():
        profile = built_in_profile(profile_id)
        assert profile["profile_sha256"] == canonical_sha256(
            {key: value for key, value in profile.items() if key != "profile_sha256"}
        )
        claims = profile["claims"]
        assert len({item["claim_id"] for item in claims}) == len(claims)
        assert len({item["evidence_kind"] for item in claims}) == len(claims)
        assert all(item["conditions"] for item in claims)
        assert profile["mapping_status"] == "informative-not-determinative"


def test_complete_critical_infrastructure_case_supports_all_claims(tmp_path):
    case = _write_profile_evidence(tmp_path, built_in_case("critical-infrastructure"))
    assert validate_case(case) == ()
    report = analyze_case(case, tmp_path)

    assert report["summary"]["status"] == "profile_evidence_supported"
    assert report["summary"]["claim_status_counts"] == {
        "supported": 8,
        "violated": 0,
        "contradicted": 0,
        "stale_evidence": 0,
        "missing_evidence": 0,
    }
    assert report["summary"]["automatic_deployment_actions"] == 0
    assert report["summary"]["automatic_risk_acceptances"] == 0
    assert all(
        item["verification_status"] == "verified_current" for item in report["evidence_results"]
    )
    assert verify_report(report, tmp_path) == ()


def test_missing_stale_invalid_and_violating_evidence_remain_distinct(tmp_path):
    base = built_in_case("enterprise-agent")
    supplied = _demo_evidence()
    case = _write_profile_evidence(tmp_path, base, supplied)

    missing_path = tmp_path / "evidence" / "verified-defense.json"
    missing_path.unlink()
    missing = analyze_case(case, tmp_path)
    by_claim = {item["claim_id"]: item for item in missing["claim_results"]}
    assert by_claim["verified-remediation"]["status"] == "missing_evidence"
    assert missing["summary"]["status"] == "review_required"

    missing_path.write_text(json.dumps(supplied["verified-defense"]))
    stale_case = deepcopy(case)
    stale_item = next(item for item in stale_case["evidence"] if item["evidence_kind"] == "trace")
    stale_item["observed_at"] -= stale_item["max_age_seconds"] + 1
    stale_case = seal_case(stale_case)
    stale = analyze_case(stale_case, tmp_path)
    by_claim = {item["claim_id"]: item for item in stale["claim_results"]}
    assert by_claim["observable-effects"]["status"] == "stale_evidence"

    invalid_case = deepcopy(case)
    invalid_item = next(
        item for item in invalid_case["evidence"] if item["evidence_kind"] == "authority"
    )
    invalid_item["expected_sha256"] = "0" * 64
    invalid_case = seal_case(invalid_case)
    invalid = analyze_case(invalid_case, tmp_path)
    by_claim = {item["claim_id"]: item for item in invalid["claim_results"]}
    assert by_claim["bounded-authority"]["status"] == "missing_evidence"
    assert invalid["summary"]["invalid_evidence"] == 1

    unsafe_trace = analyze_trace_evidence(build_trace_evidence(demo_otlp_payload()))
    trace_path = tmp_path / "evidence" / "trace.json"
    trace_path.write_text(json.dumps(unsafe_trace))
    violated_case = deepcopy(case)
    trace_item = next(
        item for item in violated_case["evidence"] if item["evidence_kind"] == "trace"
    )
    trace_item["expected_sha256"] = canonical_sha256(unsafe_trace)
    violated_case = seal_case(violated_case)
    violated = analyze_case(violated_case, tmp_path)
    by_claim = {item["claim_id"]: item for item in violated["claim_results"]}
    assert by_claim["observable-effects"]["status"] == "violated"
    assert violated["summary"]["status"] == "evidence_contradicts_deployment"


def test_conflicting_current_evidence_is_not_silently_resolved(tmp_path):
    supplied = _demo_evidence()
    case = _write_profile_evidence(tmp_path, built_in_case("enterprise-agent"), supplied)
    unsafe = analyze_trace_evidence(build_trace_evidence(demo_otlp_payload()))
    (tmp_path / "evidence" / "trace-unsafe.json").write_text(json.dumps(unsafe))
    template = next(item for item in case["evidence"] if item["evidence_kind"] == "trace")
    case["evidence"].append(
        {
            **template,
            "evidence_id": "trace-contradicting-evidence",
            "path": "evidence/trace-unsafe.json",
            "expected_sha256": canonical_sha256(unsafe),
        }
    )
    case = seal_case(case)
    report = analyze_case(case, tmp_path)
    trace_claim = next(
        item for item in report["claim_results"] if item["claim_id"] == "observable-effects"
    )
    assert trace_claim["status"] == "contradicted"
    assert trace_claim["supporting_evidence_ids"] == ["trace-evidence"]
    assert trace_claim["violating_evidence_ids"] == ["trace-contradicting-evidence"]


def test_case_rejects_path_escape_unknown_fields_future_evidence_and_digest_tampering(tmp_path):
    case = built_in_case("enterprise-agent")
    case["evidence"][0]["path"] = "../secret.json"
    case = seal_case(case)
    assert any("relative path" in item for item in validate_case(case))

    extended = built_in_case("enterprise-agent")
    extended["risk_score"] = 99
    extended = seal_case(extended)
    assert any("unsupported fields" in item for item in validate_case(extended))

    valid = _write_profile_evidence(tmp_path, built_in_case("enterprise-agent"))
    future = deepcopy(valid)
    future["evidence"][0]["observed_at"] = future["evaluation_time"] + 1
    future = seal_case(future)
    report = analyze_case(future, tmp_path)
    assert report["evidence_results"][0]["verification_status"] == "invalid"

    valid["title"] = "changed after sealing"
    assert "case_sha256 does not recompute" in validate_case(valid)


def test_report_recomputation_detects_semantic_tampering_even_after_rehash(tmp_path):
    case = _write_profile_evidence(tmp_path, built_in_case("enterprise-agent"))
    report = analyze_case(case, tmp_path)
    report["summary"]["status"] = "review_required"
    report.pop("report_sha256")
    report["report_sha256"] = canonical_sha256(report)
    assert "AssuranceGraph report does not recompute exactly" in verify_report(report, tmp_path)


def test_schemas_exports_and_html_are_bounded_views(tmp_path):
    case = _write_profile_evidence(tmp_path, built_in_case("critical-infrastructure"))
    report = analyze_case(case, tmp_path)
    case_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/assurance-case.schema.json").read_text()
    )
    report_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/assurancegraph-report.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(case_schema).validate(case)
    jsonschema.Draft202012Validator(report_schema).validate(report)

    extended = deepcopy(case)
    extended["system"]["certified"] = True
    try:
        jsonschema.Draft202012Validator(case_schema).validate(extended)
    except jsonschema.ValidationError:
        pass
    else:
        raise AssertionError("case schema accepted a nested extension")

    sarif = export_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    oscal = export_oscal(report)
    assert oscal["assessment-results"]["metadata"]["oscal-version"] == "1.2.2"
    assert oscal["assessment-results"]["metadata"]["last-modified"].endswith("Z")
    assert oscal["assessment-results"]["results"][0]["findings"] == []
    rendered = render_html(report)
    assert "profile evidence supported" in rendered
    assert "Automatic deployment actions: 0" in rendered
    assert CLAIM_BOUNDARY in rendered


def test_protocol_has_no_hidden_score_or_automatic_authority():
    protocol = protocol_payload()
    encoded = json.dumps(protocol).lower()
    assert "universal safety or compliance score" in encoded
    assert "authorization to operate" in encoded
    assert "automatic" not in protocol["status_semantics"]["supported"]
    assert protocol["evidence_verification"].startswith("native offline")
    assert all(
        item["expected_sha256"] == "0" * 64
        for item in built_in_case("enterprise-agent")["evidence"]
    )


def test_umbrella_cli_init_evaluate_verify_and_demo(tmp_path, capsys):
    init_path = tmp_path / "starter.json"
    assert (
        umbrella_main(
            [
                "assure",
                "init",
                "--profile",
                "enterprise-agent",
                "--evaluation-time",
                "1788048000",
                "--out",
                str(init_path),
            ]
        )
        == 0
    )
    assert json.loads(init_path.read_text())["profile_id"] == "enterprise-agent"

    authority_path = tmp_path / "authority.json"
    authority = _demo_evidence()["authority"]
    authority_path.write_text(json.dumps(authority))
    assert umbrella_main(["assure", "digest", str(authority_path), "--json"]) == 0
    digest_output = capsys.readouterr().out
    assert canonical_sha256(authority) in digest_output
    assert '"evidence_kind": "authority"' in digest_output

    unsupported_path = tmp_path / "unsupported.json"
    unsupported_path.write_text('{"report_type":"arbitrary-assertion"}')
    assert umbrella_main(["assure", "digest", str(unsupported_path)]) == 2
    assert "unsupported evidence" in capsys.readouterr().err

    demo_dir = tmp_path / "demo"
    assert umbrella_main(["assure", "demo", "--out-dir", str(demo_dir)]) == 0
    assert (demo_dir / "index.html").is_file()
    assert (demo_dir / "assurance.sarif").is_file()
    assert (
        umbrella_main(
            [
                "assure",
                "verify",
                str(demo_dir / "assurance-report.json"),
                "--evidence-root",
                str(demo_dir),
            ]
        )
        == 0
    )
    assert "profile_evidence_supported" in capsys.readouterr().out
