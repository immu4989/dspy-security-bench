import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.authority.adapter import (
    BoundedAuthorityAdapter,
    build_ambient_authority_adapter,
    build_bounded_authority_adapter,
)
from dspy_security_bench.authority.benchmark import (
    run_authority_twin,
    verify_authority_report,
)
from dspy_security_bench.authority.cli import main as authority_main
from dspy_security_bench.authority.protocol import (
    build_authority_scenarios,
    policy_sha256,
    protocol_sha256,
)
from dspy_security_bench.authority.repeat import (
    create_authority_submission_bundle,
    run_repeat_authority_twin,
    verify_authority_submission_bundle,
    verify_repeat_authority_report,
)
from dspy_security_bench.cli import main as root_main


class CommunityAuthorityAdapter(BoundedAuthorityAdapter):
    name = "example-community-authority-adapter"


def build_community_authority_adapter():
    return CommunityAuthorityAdapter()


def test_frozen_protocol_has_ten_clean_injected_control_pairs():
    scenarios = build_authority_scenarios()
    assert len(scenarios) == 20
    assert len({item.pair_id for item in scenarios}) == 10
    assert len({item.control for item in scenarios}) == 10
    for pair_id in {item.pair_id for item in scenarios}:
        pair = [item for item in scenarios if item.pair_id == pair_id]
        assert {item.variant for item in pair} == {"clean", "injected"}
        assert next(item for item in pair if item.variant == "clean").expected_outcome == "allow"
    assert len(protocol_sha256()) == len(policy_sha256()) == 64


def test_protocol_returns_fresh_data_and_keeps_identity_stable():
    before = protocol_sha256()
    scenarios = build_authority_scenarios()
    scenarios[0].request["agent_id"] = "mutated"
    assert build_authority_scenarios()[0].request["agent_id"] == "agent-orchestrator"
    assert protocol_sha256() == before


def test_bounded_adapter_passes_every_authority_control_and_verifies():
    report = run_authority_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    )
    assert report.summary["clean_mission_utility"] == 1
    assert report.summary["attack_resistance"] == 1
    assert report.summary["harm_containment"] == 1
    assert report.summary["receipt_integrity"] == 1
    assert report.summary["false_allows"] == 0
    assert all(report.summary["control_results"].values())
    assert verify_authority_report(report.to_dict()) == ()


def test_ambient_credentials_preserve_clean_utility_but_fail_every_attack():
    report = run_authority_twin(
        build_ambient_authority_adapter(), adapter_factory=build_ambient_authority_adapter
    )
    assert report.summary["clean_mission_utility"] == 1
    assert report.summary["attack_resistance"] == 0
    assert report.summary["harm_containment"] == 0
    assert report.summary["false_allows"] == 10
    assert report.summary["unsafe_side_effects"] == 10
    assert report.summary["receipt_integrity"] == 1
    assert verify_authority_report(report.to_dict()) == ()


def test_report_verifier_rejects_trace_receipt_and_summary_tampering():
    payload = run_authority_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    ).to_dict()
    receipt_tamper = deepcopy(payload)
    receipt_tamper["pairs"][0]["injected"]["action_trace"][1]["details"]["receipt"]["agent_id"] = (
        "forged-agent"
    )
    assert any("receipt" in error for error in verify_authority_report(receipt_tamper))

    trace_tamper = deepcopy(payload)
    trace_tamper["pairs"][1]["injected"]["action_trace"][0]["details"]["request_sha256"] = "0" * 64
    assert any("request trace" in error for error in verify_authority_report(trace_tamper))

    summary_tamper = deepcopy(payload)
    summary_tamper["summary"]["false_allows"] = 7
    assert "summary does not recompute from pairs" in verify_authority_report(summary_tamper)


def test_repeat_report_has_wilson_intervals_and_recomputes():
    report = run_repeat_authority_twin(build_community_authority_adapter, trials=2)
    assert report.summary.trials == 2
    assert report.summary.pair_trials == 20
    assert report.summary.attack_resistance.successes == 20
    assert report.summary.attack_resistance.lower < 1
    assert report.summary.false_allows == 0
    assert verify_repeat_authority_report(report.to_dict()) == ()


def test_repeat_report_rejects_content_tampering():
    payload = run_repeat_authority_twin(build_community_authority_adapter, trials=2).to_dict()
    payload["trials"][0]["pairs"][0]["attack_resisted"] = False
    errors = verify_repeat_authority_report(payload)
    assert any("report_sha256" in error for error in errors)
    assert any("trial 1" in error for error in errors)


def test_repeat_report_rejects_claimed_method_scope_and_adapter_tampering():
    original = run_repeat_authority_twin(build_community_authority_adapter, trials=2).to_dict()
    for field, value in (
        ("statistical_method", "normal approximation"),
        ("inference_scope", "all production systems"),
        ("adapter", ""),
    ):
        payload = deepcopy(original)
        payload[field] = value
        errors = verify_repeat_authority_report(payload)
        assert any(field in error for error in errors)


def test_bundle_is_content_addressed_and_registry_rules_exclude_references():
    community = run_repeat_authority_twin(build_community_authority_adapter, trials=5).to_dict()
    bundle = create_authority_submission_bundle(
        community,
        submitter="@example",
        adapter_source_url="https://github.com/example/authority-adapter",
    )
    result = verify_authority_submission_bundle(bundle)
    assert result.valid
    assert result.community_eligible

    reference = run_repeat_authority_twin(build_bounded_authority_adapter, trials=5).to_dict()
    reference_bundle = create_authority_submission_bundle(
        reference,
        submitter="@fixture",
        adapter_source_url="https://example.com/reference",
    )
    result = verify_authority_submission_bundle(reference_bundle)
    assert result.valid
    assert not result.community_eligible
    assert any("reference adapters" in warning for warning in result.warnings)


def test_bundle_verifier_detects_nested_and_digest_tampering():
    report = run_repeat_authority_twin(build_community_authority_adapter, trials=2).to_dict()
    bundle = create_authority_submission_bundle(
        report,
        submitter="@example",
        adapter_source_url="https://example.com/adapter",
    )
    tampered = deepcopy(bundle)
    tampered["report"]["summary"]["false_allows"] = 9
    result = verify_authority_submission_bundle(tampered, minimum_trials=2)
    assert not result.valid
    assert any("sha256" in error for error in result.errors)


def test_report_and_bundle_conform_to_packaged_schemas():
    report = run_authority_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    ).to_dict()
    report_schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("authority-report.schema.json")
        .read_text()
    )
    jsonschema.Draft202012Validator(report_schema).validate(report)

    repeated = run_repeat_authority_twin(build_community_authority_adapter, trials=2).to_dict()
    bundle = create_authority_submission_bundle(
        repeated,
        submitter="@example",
        adapter_source_url="https://example.com/adapter",
    )
    bundle_schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("authority-submission-bundle.schema.json")
        .read_text()
    )
    jsonschema.Draft202012Validator(
        bundle_schema, format_checker=jsonschema.FormatChecker()
    ).validate(bundle)


def test_authority_cli_describe_demo_run_repeat_bundle_and_verify(tmp_path, capsys):
    assert root_main(["authority", "describe"]) == 0
    assert "identity-substitution" in capsys.readouterr().out
    assert authority_main(["demo", "--reference", "ambient"]) == 0
    assert "False allows: 10" in capsys.readouterr().out

    single = tmp_path / "single.json"
    assert authority_main(["run", "--reference", "bounded", "--json-out", str(single)]) == 0
    assert authority_main(["verify", str(single)]) == 0

    repeated = tmp_path / "repeat.json"
    assert (
        authority_main(
            [
                "repeat",
                "--adapter",
                "tests.test_authoritytwin:build_community_authority_adapter",
                "--trials",
                "2",
                "--report-out",
                str(repeated),
            ]
        )
        == 0
    )
    bundle = tmp_path / "bundle.json"
    assert (
        authority_main(
            [
                "bundle",
                str(repeated),
                "--out",
                str(bundle),
                "--submitter",
                "@example",
                "--adapter-source",
                "https://example.com/adapter",
            ]
        )
        == 0
    )
    assert authority_main(["verify", str(bundle), "--minimum-trials", "2"]) == 0


def test_proofrun_authority_creates_and_verifies_attestation_ready_bundle(tmp_path):
    bundle = tmp_path / "proofrun-authority.json"
    assert (
        root_main(
            [
                "proofrun",
                "authority",
                "--adapter",
                "tests.test_authoritytwin:build_community_authority_adapter",
                "--trials",
                "2",
                "--out",
                str(bundle),
                "--submitter",
                "@example",
                "--adapter-source",
                "https://github.com/example/authority-adapter",
            ]
        )
        == 0
    )
    payload = json.loads(bundle.read_text())
    assert payload["bundle_type"] == "dspy-security-bench-authority-evidence-submission"
    assert payload["provenance"]["provider"] == "local"
    assert root_main(["proofrun", "verify", str(bundle), "--offline", "--minimum-trials", "2"]) == 0
