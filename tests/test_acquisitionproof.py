import json
from importlib.resources import files

import jsonschema

from dspy_security_bench.acquisition.pack import export_acquisition_pack, verify_acquisition_pack
from dspy_security_bench.acquisition.profile import example_profile, validate_acquisition_profile
from dspy_security_bench.authority.adapter import build_bounded_authority_adapter
from dspy_security_bench.graph.benchmark import run_agent_graph_twin


def _report():
    return run_agent_graph_twin(
        build_bounded_authority_adapter(), adapter_factory=build_bounded_authority_adapter
    )


def test_acquisition_pack_is_vendor_neutral_and_offline_verifiable(tmp_path):
    profile_payload = example_profile()
    profile_payload["acquisition_id"] = "mission-agent-evaluation"
    profile = validate_acquisition_profile(profile_payload)
    schema = json.loads(
        files("dspy_security_bench").joinpath("schemas/acquisition-profile.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(profile.raw)
    output = tmp_path / "pack"
    manifest = export_acquisition_pack(_report(), profile, output)
    assert manifest["decision_authority"] == "accountable acquisition and mission owners"
    assert verify_acquisition_pack(output) == ()
    objectives = json.loads((output / "qasp-objectives.json").read_text())
    assert objectives["objectives"][0]["status"] == "met"
    assert (
        json.loads((output / "cost-observation.json").read_text())["status"]
        == "unpopulated_owner_input"
    )


def test_acquisition_pack_detects_file_tampering(tmp_path):
    profile_payload = example_profile()
    profile_payload["acquisition_id"] = "mission-agent-evaluation"
    output = tmp_path / "pack"
    export_acquisition_pack(_report(), validate_acquisition_profile(profile_payload), output)
    (output / "portability-checklist.md").write_text("changed")
    assert "file digest mismatch: portability-checklist.md" in verify_acquisition_pack(output)


def test_acquisition_pack_recomputes_artifacts_even_if_attacker_rehashes(tmp_path):
    profile_payload = example_profile()
    profile_payload["acquisition_id"] = "mission-agent-evaluation"
    output = tmp_path / "pack"
    export_acquisition_pack(_report(), validate_acquisition_profile(profile_payload), output)
    qasp = output / "qasp-objectives.json"
    qasp.write_text(qasp.read_text().replace('"status": "met"', '"status": "not_met"'))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    import hashlib

    from dspy_security_bench.mission.loader import canonical_sha256

    manifest["files"][qasp.name] = hashlib.sha256(qasp.read_bytes()).hexdigest()
    manifest.pop("pack_sha256")
    manifest["pack_sha256"] = canonical_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest))
    assert "generated artifact does not recompute: qasp-objectives.json" in verify_acquisition_pack(
        output
    )


def test_profile_rejects_implicit_or_missing_objectives():
    payload = example_profile()
    payload["outcomes"] = []
    try:
        validate_acquisition_profile(payload)
    except ValueError as exc:
        assert "at least one" in str(exc)
    else:
        raise AssertionError("expected validation error")
