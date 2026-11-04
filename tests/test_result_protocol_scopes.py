"""Typed-result execution is a new scope, not a relabeling of archived measurements."""

import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest

from dspy_security_bench.scan.compare import compare_scan_evidence
from dspy_security_bench.scan.demo import build_demo_artifacts
from dspy_security_bench.scan.evidence import (
    build_scan_evidence,
    expected_observation_keys,
    verify_scan_evidence,
)
from dspy_security_bench.scan.gate import bind_baseline_scope, verify_baseline_scope
from dspy_security_bench.scan.study import build_scan_study, build_study_plan, verify_scan_study

PROTOCOLS = ["complete-binary-observations-v1", "complete-binary-observations-v2",
             "complete-binary-observations-v4", "tool-budgeted-binary-observations-v3",
             "tool-budgeted-binary-observations-v4"]


def evidence(protocol):
    source = json.loads(build_demo_artifacts()["before.json"])
    scope = deepcopy(source["scope"])
    scope["measurement_protocol"] = protocol
    if protocol.startswith("tool-budgeted"):
        scope["execution_controls"] = {"max_tool_calls_per_task": 2}
    return build_scan_evidence(scope, source["policy"], source["observations"])


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_old_and_current_protocols_replay_under_their_own_scopes(protocol):
    payload = evidence(protocol)
    verify_scan_evidence(payload)
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-evidence.schema.json").read_text())
    jsonschema.validate(payload, schema)
    plan = build_study_plan(payload, "fixture-study", 2)
    sources = dict.fromkeys(plan["trial_ids"], payload)
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": payload["evidence_sha256"]}
              for name in plan["trial_ids"]]
    report = build_scan_study(plan, trials, sources)
    study_schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-study.schema.json").read_text())
    assert schema["$defs"]["scope"] == study_schema["$defs"]["scope"]
    jsonschema.validate(report, study_schema)
    verify_scan_study(report, plan, trials, sources)
    assert payload["scope"]["measurement_protocol"] == protocol


@pytest.mark.parametrize("legacy,current", [
    (PROTOCOLS[0], PROTOCOLS[2]), (PROTOCOLS[1], PROTOCOLS[2]), (PROTOCOLS[3], PROTOCOLS[4]),
])
def test_typed_result_scope_rejects_legacy_baselines_comparisons_and_study_trials(legacy, current):
    before, after = evidence(legacy), evidence(current)
    with pytest.raises(ValueError, match="scope differs"):
        verify_baseline_scope(bind_baseline_scope({}, before["scope"]), after["scope"])
    with pytest.raises(ValueError, match="matched scopes"):
        compare_scan_evidence(before, after)
    plan = build_study_plan(after, "fixture-study", 2)
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": before["evidence_sha256"]}
              for name in plan["trial_ids"]]
    with pytest.raises(ValueError, match="scope"):
        build_scan_study(plan, trials, dict.fromkeys(plan["trial_ids"], before))


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_native_and_schema_scope_checks_agree_about_budget_declarations(protocol):
    scope = evidence(protocol)["scope"]
    if protocol.startswith("tool-budgeted"):
        scope.pop("execution_controls")
    else:
        scope["execution_controls"] = {"max_tool_calls_per_task": 2}
    with pytest.raises(ValueError):
        expected_observation_keys(scope)
    for name in ("scan-evidence.schema.json", "scan-study.schema.json"):
        schema = json.loads(files("dspy_security_bench.schemas").joinpath(name).read_text())
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(scope, {"$ref": "#/$defs/scope", "$defs": schema["$defs"]})
