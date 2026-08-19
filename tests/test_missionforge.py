import copy
import json
from importlib.resources import files

import pytest
import yaml

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.mission.agents import (
    ReferenceSourceAgent,
    build_bounded_source_reference,
    build_vulnerable_source_reference,
)
from dspy_security_bench.mission.benchmark import (
    run_mission_pack,
    verify_mission_report,
)
from dspy_security_bench.mission.loader import (
    load_mission_pack,
    mission_pack_template,
    validate_mission_pack,
)
from dspy_security_bench.mission.repeat import (
    create_source_submission_bundle,
    run_repeat_mission_pack,
    verify_repeat_source_report,
    verify_source_submission_bundle,
)


class CommunitySourceAgent(ReferenceSourceAgent):
    @property
    def name(self) -> str:
        return "community-source-agent"


def build_community_source_agent() -> CommunitySourceAgent:
    return CommunitySourceAgent(vulnerable=False)


def test_builtin_source_twin_is_a_frozen_five_pair_data_only_protocol():
    pack = load_mission_pack("source-twin")
    assert pack.pack_id == "source-twin-v1"
    assert len(pack.cases) == 5
    assert len(pack.protocol_sha256) == 64
    assert {case["id"] for case in pack.cases} == {
        "fabricated-authority",
        "embedded-instruction",
        "material-omission",
        "superseded-guidance",
        "insufficient-evidence",
    }
    assert all(set(case["variants"]) == {"clean", "injected"} for case in pack.cases)


def test_bounded_reference_passes_and_vulnerable_reference_fails_functionally():
    pack = load_mission_pack("source-twin")
    bounded = run_mission_pack(
        build_bounded_source_reference(),
        pack,
        agent_factory=build_bounded_source_reference,
    )
    vulnerable = run_mission_pack(
        build_vulnerable_source_reference(),
        pack,
        agent_factory=build_vulnerable_source_reference,
    )
    assert bounded.summary["attack_resistance"] == 1.0
    assert bounded.summary["citation_faithfulness"] == 1.0
    assert bounded.summary["harmful_outcomes"] == 0
    assert vulnerable.summary["clean_mission_utility"] == 1.0
    assert vulnerable.summary["attack_resistance"] == 0.0
    assert vulnerable.summary["harmful_outcomes"] == 5
    assert not verify_mission_report(bounded.to_dict())
    assert not verify_mission_report(vulnerable.to_dict())


def test_single_agent_api_reports_shared_state_instead_of_claiming_fresh_isolation():
    report = run_mission_pack(build_bounded_source_reference(), load_mission_pack("source-twin"))
    assert report.trial_isolation == "shared_agent_across_cases"
    assert not verify_mission_report(report.to_dict())


def test_report_verifier_recomputes_trace_and_counterfactual_claims():
    pack = load_mission_pack("source-twin")
    payload = run_mission_pack(
        build_bounded_source_reference(),
        pack,
        agent_factory=build_bounded_source_reference,
    ).to_dict()
    payload["pairs"][0]["injected"]["mission_completed"] = False
    payload["pairs"][0]["attack_resisted"] = False
    payload["summary"]["attack_resistance"] = 0.8
    errors = verify_mission_report(payload)
    assert any("mission_completed does not recompute" in error for error in errors)
    assert any("attack_resisted does not recompute" in error for error in errors)


def test_report_verifier_rejects_a_counterfeit_builtin_pack_even_if_rehashed():
    pack = load_mission_pack("source-twin")
    payload = run_mission_pack(
        build_bounded_source_reference(),
        pack,
        agent_factory=build_bounded_source_reference,
    ).to_dict()
    payload["pack"]["description"] = "Counterfeit protocol with the reserved identity."
    altered = validate_mission_pack(payload["pack"])
    payload["pack_sha256"] = altered.protocol_sha256
    assert "source-twin-v1 does not match the packaged frozen protocol" in verify_mission_report(
        payload
    )


def test_pack_validator_rejects_executable_and_broken_protocol_shapes():
    payload = mission_pack_template()
    payload["python_hook"] = "os.system"
    with pytest.raises(ValueError, match="unsupported fields"):
        validate_mission_pack(payload)

    payload = mission_pack_template()
    payload["cases"][0]["expected"]["required_claims"] = ["missing-claim"]
    with pytest.raises(ValueError, match="unknown id"):
        validate_mission_pack(payload)

    payload = mission_pack_template()
    payload["cases"][0]["variants"]["injected"] = payload["cases"][0]["variants"]["clean"]
    with pytest.raises(ValueError, match="must differ"):
        validate_mission_pack(payload)

    payload = mission_pack_template()
    payload["claims"] = payload["claims"] * 501
    with pytest.raises(ValueError, match="more than 1000"):
        validate_mission_pack(payload)


def test_repeat_report_recomputes_wilson_intervals_and_nested_trials():
    pack = load_mission_pack("source-twin")
    report = run_repeat_mission_pack(
        build_bounded_source_reference,
        pack,
        trials=2,
    ).to_dict()
    assert report["summary"]["pair_trials"] == 10
    assert report["summary"]["attack_resistance"]["successes"] == 10
    assert report["summary"]["attack_resistance"]["lower"] < 1
    assert not verify_repeat_source_report(report)

    tampered = copy.deepcopy(report)
    tampered["trials"][0]["pairs"][0]["injected"]["action_trace"][-1]["details"]["disposition"] = (
        "abstain"
    )
    errors = verify_repeat_source_report(tampered)
    assert errors
    assert any("trial 1" in error or "report_sha256" in error for error in errors)


def test_source_bundle_is_content_addressed_and_nested_verifiable():
    pack = load_mission_pack("source-twin")
    report = run_repeat_mission_pack(
        build_bounded_source_reference,
        pack,
        trials=2,
    ).to_dict()
    bundle = create_source_submission_bundle(
        report,
        submitter="@public-lab",
        agent_source_url="https://github.com/example/public-agent",
    )
    result = verify_source_submission_bundle(bundle, minimum_trials=2)
    assert result.valid is True
    assert result.community_eligible is False
    assert result.bundle_sha256 == bundle["bundle_sha256"]
    assert any("reference scorer" in warning for warning in result.warnings)

    bundle["report"]["summary"]["attack_resistance"]["successes"] = 0
    result = verify_source_submission_bundle(bundle, minimum_trials=2)
    assert result.valid is False
    assert "bundle_sha256 does not match canonical bundle content" in result.errors


def test_missionpack_json_schema_accepts_builtin_pack():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("mission-pack.schema.json")
        .read_text()
    )
    jsonschema.validate(load_mission_pack("source-twin").raw, schema)


def test_source_submission_schema_accepts_generated_bundle():
    jsonschema = pytest.importorskip("jsonschema")
    report = run_repeat_mission_pack(
        build_bounded_source_reference,
        load_mission_pack("source-twin"),
        trials=2,
    ).to_dict()
    bundle = create_source_submission_bundle(
        report,
        submitter="@public-lab",
        agent_source_url="https://github.com/example/public-agent",
    )
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas")
        .joinpath("source-submission-bundle.schema.json")
        .read_text()
    )
    jsonschema.validate(bundle, schema, format_checker=jsonschema.FormatChecker())


def test_pack_cli_init_validate_describe_run_repeat_and_verify(tmp_path, capsys):
    template = tmp_path / "mission.yaml"
    assert root_main(["pack", "init", "--out", str(template)]) == 0
    assert root_main(["pack", "validate", str(template)]) == 0
    assert root_main(["pack", "describe", "source-twin"]) == 0
    single = tmp_path / "source-report.json"
    assert (
        root_main(
            [
                "pack",
                "run",
                "source-twin",
                "--reference",
                "bounded",
                "--json-out",
                str(single),
                "--min-attack-resistance",
                "1",
            ]
        )
        == 0
    )
    repeated = tmp_path / "repeat.json"
    assert (
        root_main(
            [
                "pack",
                "repeat",
                "source-twin",
                "--reference",
                "bounded",
                "--trials",
                "2",
                "--report-out",
                str(repeated),
            ]
        )
        == 0
    )
    assert root_main(["pack", "verify", str(repeated), "--minimum-trials", "2"]) == 0
    output = capsys.readouterr().out
    assert "SourceTwin Public-Service Grounding Protocol" in output
    assert "Attack resistance" in output


def test_pack_yaml_template_round_trips_without_code_execution(tmp_path):
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(mission_pack_template(), sort_keys=False))
    loaded = load_mission_pack(path)
    assert loaded.pack_id == "my-mission-pack"


def test_proofrun_source_writes_and_offline_verifies_attestation_ready_bundle(tmp_path, capsys):
    bundle = tmp_path / "source-proofrun.json"
    report = tmp_path / "source-report.json"
    assert (
        root_main(
            [
                "proofrun",
                "source",
                "--agent",
                "tests.test_missionforge:build_community_source_agent",
                "--trials",
                "2",
                "--out",
                str(bundle),
                "--report-out",
                str(report),
                "--submitter",
                "@public-lab",
                "--agent-source",
                "https://github.com/example/public-agent",
            ]
        )
        == 0
    )
    assert (
        root_main(
            [
                "proofrun",
                "verify",
                str(bundle),
                "--offline",
                "--minimum-trials",
                "2",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "MissionForge / source-twin-v1 repeated" in output
    assert "Source registry eligibility: yes" in output
