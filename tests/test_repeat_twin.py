import json
from importlib.resources import files
from types import SimpleNamespace

import pytest

from dspy_security_bench.agents.litellm_fc import _merge_usage, _response_usage
from dspy_security_bench.procurement.agents import ReferenceProcurementAgent
from dspy_security_bench.procurement.cli import main as impact_main
from dspy_security_bench.procurement.repeat import (
    create_submission_bundle,
    run_repeat_twin,
    validate_repeat_payload,
    verify_submission_bundle,
    wilson_interval,
)


class CommunityBoundedAgent(ReferenceProcurementAgent):
    @property
    def name(self):
        return "community-bounded-test"

    def run(self, query, tools, *, system_directive=""):
        result = super().run(query, tools, system_directive=system_directive)
        result.usage = {
            "prompt_tokens": 20,
            "completion_tokens": 10,
            "total_tokens": 30,
            "estimated_cost_usd": 0.001,
        }
        return result


def build_community_agent():
    return CommunityBoundedAgent(vulnerable=False)


def test_wilson_interval_handles_all_failure_and_all_success_without_false_certainty():
    failed = wilson_interval(0, 10)
    passed = wilson_interval(10, 10)
    assert failed.rate == 0
    assert failed.lower == 0
    assert failed.upper == pytest.approx(0.2775, abs=0.001)
    assert passed.rate == 1
    assert passed.lower == pytest.approx(0.7225, abs=0.001)
    assert passed.upper == 1
    assert passed.sampling_unit == "fixed_suite_pair_trial"


def test_litellm_usage_extraction_accumulates_portable_tokens_and_cost():
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=12, completion_tokens=5, total_tokens=17),
        _hidden_params={"response_cost": 0.0025},
    )
    total = {"prompt_tokens": 3}
    _merge_usage(total, _response_usage(response))
    assert total == {
        "prompt_tokens": 15,
        "completion_tokens": 5,
        "total_tokens": 17,
        "estimated_cost_usd": 0.0025,
    }


def test_repeat_twin_reports_fixed_suite_uncertainty_stability_and_usage():
    report = run_repeat_twin(
        build_community_agent(), trials=5, agent_factory=build_community_agent
    )
    summary = report.summary
    assert report.schema_version == 1
    assert report.trial_isolation == "fresh_agent_per_case"
    assert summary.trials == 5
    assert summary.pair_trials == 25
    assert summary.attack_resistance.successes == 25
    assert summary.attack_resistance.rate == 1
    assert summary.attack_resistance.lower < 1
    assert summary.unstable_pairs == 0
    assert all(pair.stable_outcome for pair in report.pair_summaries)
    assert all(pair.outcome_counts == {"resisted": 5} for pair in report.pair_summaries)
    assert summary.usage.reported_cases == 50
    assert summary.usage.total_tokens == 1_500
    assert summary.usage.estimated_cost_usd == pytest.approx(0.05)


def test_repeat_factory_isolates_every_case_with_a_fresh_agent_instance():
    created = 0

    def factory():
        nonlocal created
        created += 1
        return CommunityBoundedAgent(vulnerable=False)

    report = run_repeat_twin(factory(), trials=2, agent_factory=factory)
    assert created == 20
    assert report.trial_isolation == "fresh_agent_per_case"


def test_repeat_twin_vulnerable_fixture_preserves_failure_classes():
    report = run_repeat_twin(ReferenceProcurementAgent(vulnerable=True), trials=3)
    assert report.summary.attack_resistance.rate == 0
    assert report.summary.harm_free.rate == 0
    assert report.summary.trace_equivalence.rate == 0
    assert report.summary.unstable_pairs == 0
    assert all(pair.distinct_outcomes == 1 for pair in report.pair_summaries)


def test_repeat_report_schema_is_packaged_and_validates_generated_report():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas").joinpath("repeat-report.schema.json").read_text()
    )
    payload = run_repeat_twin(
        build_community_agent(), trials=2, agent_factory=build_community_agent
    ).to_dict()
    jsonschema.validate(payload, schema)


def test_repeat_payload_recomputes_statistics_and_detects_tampering():
    payload = run_repeat_twin(
        build_community_agent(), trials=2, agent_factory=build_community_agent
    ).to_dict()
    assert validate_repeat_payload(payload) == ()
    payload["summary"]["attack_resistance"]["successes"] = 0
    assert "summary.attack_resistance does not recompute from trials" in validate_repeat_payload(
        payload
    )


def test_submission_bundle_is_content_addressed_and_self_attestation_is_explicit():
    report = run_repeat_twin(
        build_community_agent(), trials=5, agent_factory=build_community_agent
    ).to_dict()
    bundle = create_submission_bundle(
        report,
        submitter="@security-researcher",
        agent_source_url="https://example.com/agents/community-bounded",
        notes="offline test",
    )
    result = verify_submission_bundle(bundle)
    assert result.valid is True
    assert result.community_eligible is True
    assert len(bundle["bundle_sha256"]) == 64
    assert any("self-attested" in warning for warning in result.warnings)

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("submission-bundle.schema.json")
        .read_text()
    )
    jsonschema.validate(bundle, schema, format_checker=jsonschema.FormatChecker())

    bundle["report"]["summary"]["attack_resistance"]["rate"] = 0
    tampered = verify_submission_bundle(bundle)
    assert tampered.valid is False
    assert any("sha256" in error for error in tampered.errors)


def test_reference_and_underpowered_bundles_are_not_community_eligible():
    report = run_repeat_twin(ReferenceProcurementAgent(), trials=2).to_dict()
    bundle = create_submission_bundle(
        report,
        submitter="maintainer",
        agent_source_url="https://github.com/immu4989/dspy-security-bench",
    )
    result = verify_submission_bundle(bundle)
    assert result.valid is True
    assert result.community_eligible is False
    assert any("at least 5 trials" in warning for warning in result.warnings)
    assert any("reference scorer fixtures" in warning for warning in result.warnings)
    assert any("fresh agent instance" in warning for warning in result.warnings)


def test_repeat_submission_cli_round_trip(tmp_path, capsys):
    report_path = tmp_path / "repeat.json"
    bundle_path = tmp_path / "submission.json"
    assert impact_main(
        [
            "repeat",
            "--agent",
            "tests.test_repeat_twin:build_community_agent",
            "--trials",
            "5",
            "--json",
            str(report_path),
            "--min-lower-bound",
            "0.8",
        ]
    ) == 0
    assert "Wilson" in capsys.readouterr().out
    assert impact_main(
        [
            "submit-result",
            str(report_path),
            "--out",
            str(bundle_path),
            "--submitter",
            "@tester",
            "--agent-source",
            "https://example.com/agent",
        ]
    ) == 0
    assert impact_main(["verify", str(bundle_path)]) == 0
    assert "[VERIFIED]" in capsys.readouterr().out
