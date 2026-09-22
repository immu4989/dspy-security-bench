"""Adversarial replay tests: no model, no reliance on saved aggregate scores."""

import json
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pandas as pd
import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.config import GateSpec
from dspy_security_bench.scan.evidence import (
    build_scan_evidence,
    evidence_policy,
    expected_observation_keys,
    verify_scan_evidence,
    write_scan_evidence,
)


def scope(n=5):
    return {
        "scope_version": 1, "benchmark_version": "v1",
        "agentdojo_distribution_version": "fixture-only",
        "measurement_protocol": "complete-binary-observations-v1",
        "agent_name": "fictional-agent", "defenses": ["none"],
        "suites": [{"suite": "fictional-suite", "user_task_ids": [f"u{i}" for i in range(n)],
                    "attacks": [{"attack": "direct", "is_dos_attack": False,
                                 "injection_task_ids": ["i0"]}]}],
    }


def rows(n=5, success=1):
    return [{"suite": "fictional-suite", "agent": "fictional-agent", "defense": "none",
             "attack": "direct", "user_task_id": f"u{i}", "injection_task_id": "i0",
             "utility": 1, "security": success, "injection_succeeded": 1 - success}
            for i in range(n)]


def artifact():
    return build_scan_evidence(scope(), evidence_policy(GateSpec(), "error"), rows())


def test_evidence_matches_shipped_structural_schema():
    schema = json.loads(files("dspy_security_bench.schemas").joinpath("scan-evidence.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(artifact(), schema)
    invalid = artifact()
    invalid["observations"][0]["security"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(invalid, schema)


def rehash(payload):
    payload["evidence_sha256"] = canonical_sha256({k: v for k, v in payload.items() if k != "evidence_sha256"})


def test_evidence_reconstructs_counts_and_verdict_with_optional_independent_pin(tmp_path):
    output = tmp_path / "evidence.json"
    payload = write_scan_evidence(output, scope(), evidence_policy(GateSpec(), "error"), rows())
    report = verify_scan_evidence(json.loads(output.read_text()), payload["evidence_sha256"])
    assert report["requirements_met"]
    assert report["findings"][0]["security_successes"] == 5
    with pytest.raises(FileExistsError):
        write_scan_evidence(output, scope(), evidence_policy(GateSpec(), "error"), rows())
    with pytest.raises(ValueError, match="retained digest"):
        verify_scan_evidence(payload, "0" * 64)


@pytest.mark.parametrize("mutation", [
    "drop-row", "duplicate", "substitute", "bool", "nonbinary", "not-complementary",
    "hidden-content", "forged-report", "forged-protocol", "forged-boundary", "schema-bool",
    "forged-scope", "report-type-coercion", "unknown-field", "reordered-rows",
])
def test_self_rehashed_semantic_tampering_is_rejected(mutation):
    payload = artifact()
    if mutation == "drop-row":
        payload["observations"].pop()
    elif mutation == "duplicate":
        payload["observations"][0] = deepcopy(payload["observations"][1])
    elif mutation == "substitute":
        payload["observations"][0]["user_task_id"] = "outside-scope"
    elif mutation == "bool":
        payload["observations"][0]["security"] = True
    elif mutation == "nonbinary":
        payload["observations"][0]["security"] = 2
    elif mutation == "not-complementary":
        payload["observations"][0]["injection_succeeded"] = 1
    elif mutation == "hidden-content":
        payload["observations"][0]["prompt"] = "private input must not be accepted"
    elif mutation == "forged-report":
        payload["report"]["findings"][0]["n_runs"] = 500
    elif mutation == "forged-protocol":
        payload["protocol_version"] = "different"
    elif mutation == "forged-boundary":
        payload["claim_boundary"] = "certified safe"
    elif mutation == "schema-bool":
        payload["schema_version"] = True
    elif mutation == "forged-scope":
        payload["scope"]["suites"][0]["user_task_ids"].pop()
    elif mutation == "report-type-coercion":
        payload["report"]["passed"] = 1
    elif mutation == "unknown-field":
        payload["extra"] = "unexpected"
    else:
        payload["observations"].reverse()
    rehash(payload)
    with pytest.raises(ValueError):
        verify_scan_evidence(payload)


def test_consistent_alternate_observations_need_independent_pin_to_distinguish():
    original = artifact()
    changed = build_scan_evidence(scope(), original["policy"], rows(success=0))
    assert not verify_scan_evidence(changed)["requirements_met"]
    with pytest.raises(ValueError, match="retained digest"):
        verify_scan_evidence(changed, original["evidence_sha256"])


def test_wilson_policy_replays_from_retained_counts():
    payload = build_scan_evidence(scope(40), evidence_policy(GateSpec(statistic="wilson_lower"), "error"), rows(40))
    report = verify_scan_evidence(payload)
    assert report["requirements_met"]
    assert report["findings"][0]["security_lower"] > 0.9


@pytest.mark.parametrize("mutation", ["duplicate-suite", "duplicate-defense", "empty-users", "oversize", "dos-multiple", "label-control"])
def test_scope_is_bounded_before_expanding_expected_matrix(mutation):
    data = scope()
    if mutation == "duplicate-suite":
        data["suites"].append(deepcopy(data["suites"][0]))
    elif mutation == "duplicate-defense":
        data["defenses"] *= 2
    elif mutation == "empty-users":
        data["suites"][0]["user_task_ids"] = []
    elif mutation == "oversize":
        data["suites"][0]["user_task_ids"] = [f"u{i}" for i in range(1000)]
        data["suites"][0]["attacks"][0]["injection_task_ids"] = [f"i{i}" for i in range(1000)]
    elif mutation == "dos-multiple":
        data["suites"][0]["attacks"][0].update(is_dos_attack=True, injection_task_ids=["i0", "i1"])
    else:
        data["agent_name"] = "\x1b[31m"
    with pytest.raises(ValueError):
        expected_observation_keys(data)


def test_verify_cli_separates_validity_from_satisfaction_without_model(monkeypatch, tmp_path):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda _: pytest.fail("no agent"))
    output = tmp_path / "evidence.json"
    write_scan_evidence(output, scope(), evidence_policy(GateSpec(), "never"), rows(success=0))
    assert main(["verify", str(output)]) == 0
    assert main(["verify", str(output), "--fail-on-shortfalls"]) == 1
    output.write_text('{"secret": 1, "secret": 2}')
    assert main(["verify", str(output)]) == 2


def test_live_scan_export_uses_allowlisted_rows_and_retained_baseline(monkeypatch, tmp_path):
    declared = scope()
    plan = [{"suite": "fictional-suite", "user_tasks": 5, "user_task_ids": [f"u{i}" for i in range(5)],
             "injection_task_ids": ["i0"], "attack_cases": [{"attack": "direct", "injection_tasks": 1}]}]
    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_plan", lambda cfg: plan)
    monkeypatch.setattr("dspy_security_bench.scan.cli.build_scan_scope", lambda cfg, p: declared)
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda cfg: object())
    baseline = tmp_path / "private-baseline-location.json"
    baseline.write_text(json.dumps({"security_by_cell": {"fictional-suite|fictional-agent|none|direct": 1.0}}))

    def evaluate(**kwargs):
        baseline.write_text("mutated after preflight")
        return pd.DataFrame([{**row, "private_trace": "secret content"} for row in rows()]).drop(columns="suite")

    monkeypatch.setattr("dspy_security_bench.runner.evaluate_agents", evaluate)
    output = tmp_path / "evidence.json"
    assert main(["--agent-model", "fictional-agent", "--baseline", str(baseline), "--evidence-json", str(output)]) == 0
    assert "private_trace" not in output.read_text()
    assert "private-baseline-location" not in output.read_text()
    payload = json.loads(output.read_text())
    assert verify_scan_evidence(payload)["requirements_met"]
    assert payload["baseline"]["security_by_cell"]


@pytest.mark.parametrize("other", ["--plan", "--write-baseline", "--plan-json", "--json"])
def test_evidence_output_conflicts_stop_before_agent_construction(monkeypatch, tmp_path, other):
    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", lambda cfg: pytest.fail("no agent"))
    output = tmp_path / "same.json"
    args = ["--agent-model", "fixture", "--evidence-json", str(output), other]
    if other != "--plan":
        args.append(str(output))
    assert main(args) == 2
    assert not output.exists()
