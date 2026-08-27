import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.causal.proof import (
    analyze_causality,
    build_demo_inputs,
    validate_manifest,
    verify_causal_report,
)
from dspy_security_bench.causal.registry import (
    build_causal_submission_bundle,
    verify_causal_submission_bundle,
)
from dspy_security_bench.cli import main as root_main
from dspy_security_bench.schedule.proof import analyze_scenario, validate_scenario


def test_causalproof_separates_parent_assertion_link_and_timing_provenance():
    trace, manifest = build_demo_inputs()
    report = analyze_causality(trace, manifest)
    summary = report["summary"]
    assert summary["status"] == "ready"
    assert summary["observed_parent_edges"] == 3
    assert summary["asserted_edges"] == 1
    assert summary["observed_links"] == 1
    assert summary["timing_candidates"] > 0

    relations = report["relations"]
    for item in relations:
        expected = item["provenance"] in {"observed_parent", "asserted"}
        assert item["schedule_eligible"] is expected
    scenario_edges = {tuple(edge) for edge in report["schedule_scenario"]["happens_before"]}
    assert ("grant", "exchange") in scenario_edges
    assert ("approve", "commit") in scenario_edges
    assert ("grant", "approve") not in scenario_edges  # the generic span link is undirected
    timing_pairs = {
        (item["from_event"], item["to_event"])
        for item in relations
        if item["provenance"] == "timing_candidate"
    }
    assert ("grant", "commit") not in timing_pairs  # already ordered through exchange


def test_generated_schedule_is_valid_and_exposes_the_revocation_race():
    trace, manifest = build_demo_inputs()
    scenario = analyze_causality(trace, manifest)["schedule_scenario"]
    assert validate_scenario(scenario) == ()
    schedule_report = analyze_scenario(scenario)
    assert schedule_report["summary"]["status"] == "unsafe"
    assert schedule_report["minimal_counterexample"]["violation_id"] == "SP001"


def test_names_attributes_events_and_status_do_not_affect_causal_report():
    trace, manifest = build_demo_inputs()
    baseline = analyze_causality(trace, manifest)
    mutated = deepcopy(trace)
    span = mutated["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["name"] = "PRIVATE-PROMPT"
    span["attributes"] = [{"key": "secret", "value": {"stringValue": "TOKEN"}}]
    span["events"] = [{"name": "PRIVATE", "attributes": []}]
    span["status"] = {"message": "PRIVATE"}
    changed = analyze_causality(mutated, manifest, source_sha256=baseline["source_sha256"])
    assert changed == baseline


def test_missing_bound_span_and_dropped_records_force_human_review():
    trace, manifest = build_demo_inputs()
    spans = trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans.pop()
    spans[0]["droppedLinksCount"] = 2
    report = analyze_causality(trace, manifest)
    assert report["summary"]["status"] == "review_required"
    assert {item["code"] for item in report["diagnostics"]} >= {"CP002", "CP005"}


def test_manifest_and_report_match_packaged_strict_schemas():
    trace, manifest = build_demo_inputs()
    report = analyze_causality(trace, manifest)
    root = files("dspy_security_bench").joinpath("schemas")
    manifest_schema = json.loads(root.joinpath("causalproof-manifest.schema.json").read_text())
    report_schema = json.loads(root.joinpath("causalproof-report.schema.json").read_text())
    jsonschema.Draft202012Validator(manifest_schema).validate(manifest)
    jsonschema.Draft202012Validator(report_schema).validate(report)


def test_manifest_unknown_fields_duplicates_and_bad_assertions_are_rejected():
    _, manifest = build_demo_inputs()
    manifest["unexpected"] = True
    manifest["bindings"][1]["event"]["id"] = manifest["bindings"][0]["event"]["id"]
    manifest["asserted_edges"][0]["after"] = "missing"
    errors = validate_manifest(manifest)
    assert "manifest fields are incomplete or unsupported" in errors
    assert "bound event ids must be unique" in errors
    assert "asserted edge 0 references an unknown event" in errors


def test_report_tampering_fails_offline_recomputation():
    trace, manifest = build_demo_inputs()
    report = analyze_causality(trace, manifest)
    tampered = deepcopy(report)
    tampered["summary"]["trusted_edges"] = 99
    errors = verify_causal_report(tampered, trace, manifest)
    assert "report_sha256 does not match canonical report content" in errors
    assert "CausalProof report does not recompute from the supplied trace and manifest" in errors


def test_causal_cli_init_run_gate_and_verify(tmp_path):
    trace = tmp_path / "trace.json"
    manifest = tmp_path / "manifest.json"
    report = tmp_path / "causal-report.json"
    scenario = tmp_path / "schedule.json"
    schedule_report = tmp_path / "schedule-report.json"
    assert root_main(
        [
            "causal", "init", "--trace-out", str(trace), "--manifest-out", str(manifest)
        ]
    ) == 0
    assert root_main(
        [
            "causal", "run", str(trace), str(manifest), "--report-out", str(report),
            "--scenario-out", str(scenario), "--schedule-report-out", str(schedule_report),
        ]
    ) == 0
    assert root_main(["causal", "verify", str(report), str(trace), str(manifest)]) == 0
    assert json.loads(schedule_report.read_text())["summary"]["status"] == "unsafe"
    assert root_main(
        [
            "causal", "run", str(trace), str(manifest), "--report-out", str(report),
            "--fail-on-unsafe",
        ]
    ) == 1


def test_content_free_community_bundle_recomputes_and_matches_schema(tmp_path):
    trace, manifest = build_demo_inputs()
    bundle = build_causal_submission_bundle(
        trace,
        manifest,
        submitter="@independent-lab",
        runtime="fictional-runtime@1.0",
        source_repository="https://github.com/example/lab/tree/0123456789abcdef",
        known_gaps=["synthetic fixture"],
        created_at="2026-08-27",
    )
    result = verify_causal_submission_bundle(bundle)
    assert result.community_eligible
    assert result.errors == ()
    encoded = json.dumps(bundle["structural_trace"])
    for forbidden in ("ignored.content", "never-read", "attributes", "events", "status"):
        assert forbidden not in encoded
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/causal-submission.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(bundle)

    path = tmp_path / "causal-submission.json"
    path.write_text(json.dumps(bundle))
    assert root_main(["causal", "verify-submission", str(path)]) == 0
