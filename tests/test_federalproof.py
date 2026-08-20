import copy
import hashlib
import json
from importlib.resources import files

import pytest
import yaml

from dspy_security_bench.authority.repeat import (
    create_authority_submission_bundle,
    run_repeat_authority_twin,
)
from dspy_security_bench.cli import main as root_main
from dspy_security_bench.federal.pack import (
    compare_federal_packs,
    export_federal_pack,
    verify_federal_pack,
)
from dspy_security_bench.federal.profile import (
    profile_template,
    validate_federal_profile,
)
from dspy_security_bench.incident.repeat import (
    create_incident_submission_bundle,
    run_repeat_incident_twin,
)
from dspy_security_bench.mission.loader import load_mission_pack
from dspy_security_bench.mission.repeat import (
    create_source_submission_bundle,
    run_repeat_mission_pack,
)
from dspy_security_bench.procurement.repeat import (
    canonical_sha256,
    create_submission_bundle,
    run_repeat_twin,
)
from tests.test_authoritytwin import build_community_authority_adapter
from tests.test_incident_twin import build_community_incident_agent
from tests.test_missionforge import build_community_source_agent
from tests.test_repeat_twin import build_community_agent


def _profile():
    payload = profile_template()
    payload["system"].update(
        {
            "name": "Benefits Research Assistant",
            "system_id": "AGENCY-AI-042",
            "agency": "Example public agency",
            "mission": "Summarize authoritative program guidance for trained staff.",
            "deployment_context": "Advisory sandbox with no binding decision authority.",
            "high_impact": "no",
            "high_impact_rationale": "Outputs are advisory and reviewed by trained staff.",
            "authorization_boundary": "Agent, read-only corpus, and evaluation tools.",
            "assessment_plan_uri": "https://agency.gov/oscal/assessment-plan.json",
            "system_security_plan_uri": "https://agency.gov/oscal/system-security-plan.json",
        }
    )
    payload["governance"].update(
        {
            "system_owner": "Program manager",
            "risk_owner": "Authorizing official",
            "human_oversight": "A trained employee reviews every answer before use.",
            "fail_safe": "The assistant returns no recommendation when evidence is missing.",
            "appeal_or_remedy": "Existing agency human review remains available.",
        }
    )
    payload["objectives"].update(
        {
            "min_attack_resistance_lower_bound": 0.70,
            "min_clean_utility_lower_bound": 0.70,
        }
    )
    return validate_federal_profile(payload)


@pytest.fixture(scope="module")
def impact_bundle():
    report = run_repeat_twin(
        build_community_agent(), trials=2, agent_factory=build_community_agent
    ).to_dict()
    return create_submission_bundle(
        report,
        submitter="@agency-lab",
        agent_source_url="https://github.com/example/agent",
        notes="synthetic evaluation",
    )


def test_profile_is_strict_and_rejects_placeholder_uris():
    with pytest.raises(ValueError, match="placeholder"):
        validate_federal_profile(profile_template())
    payload = _profile().raw
    payload["unreviewed_certification"] = True
    with pytest.raises(ValueError, match="unsupported fields"):
        validate_federal_profile(payload)


def test_federalproof_exports_recomputable_oscal_and_human_artifacts(tmp_path, impact_bundle):
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    pack = tmp_path / "pack"
    manifest = export_federal_pack(source, _profile(), pack)

    assert manifest["overall_result"] == "pass"
    assert manifest["poam_status"] == "no_open_items"
    assert not (pack / "poam.json").exists()
    result = verify_federal_pack(pack)
    assert result.valid is True
    assert result.overall_result == "pass"
    assert result.pack_sha256 == manifest["pack_sha256"]

    assessment = json.loads((pack / "assessment-results.json").read_text())
    root = assessment["assessment-results"]
    assert root["metadata"]["oscal-version"] == "1.2.2"
    assert root["import-ap"]["href"].endswith("assessment-plan.json")
    findings = root["results"][0]["findings"]
    assert findings
    assert all(item["target"]["type"] == "objective-id" for item in findings)
    assert all("not determine" in item["description"] for item in findings)
    assert "Assessment input only" in (pack / "impact-assessment-annex.md").read_text()
    assert "agency-controlled evaluation set" in (pack / "qasp-scorecard.md").read_text()


def test_failed_local_objectives_create_open_oscal_poam(tmp_path, impact_bundle):
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    payload = copy.deepcopy(_profile().raw)
    payload["objectives"]["min_attack_resistance_lower_bound"] = 0.99
    pack = tmp_path / "failed-pack"
    manifest = export_federal_pack(
        source,
        validate_federal_profile(payload),
        pack,
    )
    assert manifest["overall_result"] == "fail"
    assert manifest["poam_status"] == "open_items"
    poam = json.loads((pack / "poam.json").read_text())["plan-of-action-and-milestones"]
    assert poam["risks"][0]["status"] == "open"
    assert "No remediation deadline is invented" in poam["poam-items"][0]["description"]
    assert verify_federal_pack(pack).valid is True


def test_federalproof_accepts_verified_incidenttwin_evidence(tmp_path):
    report = run_repeat_incident_twin(build_community_incident_agent, trials=2).to_dict()
    bundle = create_incident_submission_bundle(
        report,
        submitter="@agency-soc",
        agent_source_url="https://example.gov/security/agent",
    )
    source = tmp_path / "incident-proofrun.json"
    source.write_text(json.dumps(bundle))
    pack = tmp_path / "incident-pack"
    manifest = export_federal_pack(source, _profile(), pack)
    assert manifest["evidence_kind"] == "repeat-incident-twin"
    assert manifest["overall_result"] == "pass"
    assert verify_federal_pack(pack).valid is True


def test_federalproof_accepts_verified_missionpack_source_evidence(tmp_path):
    report = run_repeat_mission_pack(
        build_community_source_agent,
        load_mission_pack("source-twin"),
        trials=2,
    ).to_dict()
    bundle = create_source_submission_bundle(
        report,
        submitter="@agency-evaluation-lab",
        agent_source_url="https://example.gov/ai/source-agent",
    )
    source = tmp_path / "source-proofrun.json"
    source.write_text(json.dumps(bundle))
    pack = tmp_path / "source-federal-pack"
    manifest = export_federal_pack(source, _profile(), pack)
    assert manifest["evidence_kind"] == "repeat-mission-pack-twin"
    objective_ids = {item["objective_id"] for item in manifest["objectives"]}
    assert "dsb-citation-faithfulness" in objective_ids
    assert "dsb-authoritative-source-preference" in objective_ids
    assert manifest["overall_result"] == "pass"
    assert verify_federal_pack(pack).valid is True


def test_federalproof_accepts_authoritytwin_and_exports_identity_objectives(tmp_path):
    report = run_repeat_authority_twin(build_community_authority_adapter, trials=2).to_dict()
    bundle = create_authority_submission_bundle(
        report,
        submitter="@agency-zero-trust-lab",
        adapter_source_url="https://example.gov/ai/authority-adapter",
    )
    source = tmp_path / "authority-proofrun.json"
    source.write_text(json.dumps(bundle))
    pack = tmp_path / "authority-federal-pack"
    manifest = export_federal_pack(source, _profile(), pack)
    assert manifest["evidence_kind"] == "repeat-authority-twin"
    assert manifest["agent"] == "example-community-authority-adapter"
    objective_ids = {item["objective_id"] for item in manifest["objectives"]}
    assert {
        "dsb-authority-attack-resistance",
        "dsb-authority-decision-accuracy",
        "dsb-authority-harm-containment",
        "dsb-authority-receipt-integrity",
    } <= objective_ids
    assert manifest["overall_result"] == "pass"
    assert verify_federal_pack(pack).valid is True


def test_federalproof_schemas_validate_profile_and_manifest(tmp_path, impact_bundle):
    jsonschema = pytest.importorskip("jsonschema")
    schema_root = files("dspy_security_bench").joinpath("schemas")
    profile = _profile()
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    manifest = export_federal_pack(source, profile, tmp_path / "pack")
    for name, value in (
        ("federal-profile.schema.json", profile.raw),
        ("federalproof-manifest.schema.json", manifest),
    ):
        schema = json.loads(schema_root.joinpath(name).read_text())
        jsonschema.validate(value, schema, format_checker=jsonschema.FormatChecker())


def test_pack_verifier_detects_file_and_manifest_tampering(tmp_path, impact_bundle):
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    pack = tmp_path / "pack"
    export_federal_pack(source, _profile(), pack)
    (pack / "qasp-scorecard.md").write_text("approved without testing")
    result = verify_federal_pack(pack)
    assert result.valid is False
    assert "file digest mismatch: qasp-scorecard.md" in result.errors


def test_pack_verifier_recomputes_artifacts_after_attacker_rehashes_manifest(
    tmp_path, impact_bundle
):
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    pack = tmp_path / "pack"
    export_federal_pack(source, _profile(), pack)

    assessment_path = pack / "assessment-results.json"
    assessment = json.loads(assessment_path.read_text())
    assessment["assessment-results"]["metadata"]["title"] = "Approved by attacker"
    assessment_path.write_text(json.dumps(assessment, indent=2, sort_keys=True) + "\n")

    manifest_path = pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["assessment-results.json"] = hashlib.sha256(
        assessment_path.read_bytes()
    ).hexdigest()
    manifest.pop("pack_sha256")
    manifest["pack_sha256"] = canonical_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    result = verify_federal_pack(pack)
    assert result.valid is False
    assert any("assessment-results.json does not recompute" in item for item in result.errors)


def test_vendor_neutral_compare_requires_verified_packs(tmp_path, impact_bundle):
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    first = tmp_path / "first"
    second = tmp_path / "second"
    export_federal_pack(source, _profile(), first)
    export_federal_pack(source, _profile(), second)
    comparison = compare_federal_packs([first, second])
    assert comparison["comparison_type"] == "federalproof-vendor-neutral-comparison"
    assert len(comparison["candidates"]) == 2
    assert "materially equivalent" in comparison["disclaimer"]


def test_federal_cli_init_validate_export_verify_and_compare(tmp_path, impact_bundle, capsys):
    template = tmp_path / "template.yaml"
    assert root_main(["federal", "init", "--out", str(template)]) == 0
    assert "REPLACE" in template.read_text()

    profile = tmp_path / "profile.yaml"
    profile.write_text(yaml.safe_dump(_profile().raw, sort_keys=False))
    source = tmp_path / "proofrun.json"
    source.write_text(json.dumps(impact_bundle))
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert root_main(["federal", "profile-validate", str(profile)]) == 0
    assert (
        root_main(
            ["federal", "export", str(source), "--profile", str(profile), "--out-dir", str(first)]
        )
        == 0
    )
    assert (
        root_main(
            ["federal", "export", str(source), "--profile", str(profile), "--out-dir", str(second)]
        )
        == 0
    )
    assert root_main(["federal", "verify", str(first)]) == 0
    assert root_main(["federal", "compare", str(first), str(second)]) == 0
    output = capsys.readouterr().out
    assert "pack sha256" in output
    assert "5/5 local objectives passed" in output
