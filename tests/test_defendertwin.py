from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.defend.conformance import (
    adapter_manifest_template,
    validate_adapter_manifest,
)
from dspy_security_bench.defend.conformance import (
    test_adapter as run_adapter_conformance,
)
from dspy_security_bench.defend.evidence import (
    build_evidence_bundle,
    verify_evidence_bundle,
)
from dspy_security_bench.defend.oscal import report_to_oscal
from dspy_security_bench.defend.protocol import (
    BUILT_IN_MISSIONS,
    RULES,
    analyze_remediation,
    built_in_mission,
    built_in_proposal,
    seal_mission,
    validate_mission,
    validate_proposal,
    verify_report,
)
from dspy_security_bench.defend.sarif import report_to_sarif
from dspy_security_bench.mission.loader import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


def _rebind_proposal(proposal, mission):
    rebound = deepcopy(proposal)
    rebound["mission_sha256"] = mission["mission_sha256"]
    rebound.pop("proposal_sha256", None)
    rebound["proposal_sha256"] = canonical_sha256(rebound)
    return rebound


def test_all_sector_missions_validate_and_bounded_reference_is_safe():
    assert set(BUILT_IN_MISSIONS) == {
        "community-hospital",
        "water-utility",
        "local-government",
        "open-source-maintainer",
        "small-business",
    }
    for name in BUILT_IN_MISSIONS:
        mission = built_in_mission(name)
        assert validate_mission(mission) == ()
        proposal = built_in_proposal(mission)
        assert validate_proposal(proposal, mission) == ()
        report = analyze_remediation(mission, proposal)
        assert report["summary"]["outcome"] == "effective_and_safe"
        assert report["summary"]["attack_paths_closed"] == report["summary"]["attack_path_count"]
        assert report["summary"]["mission_services_stable"] is True
        assert report["summary"]["rollback_verified"] is True
        assert report["summary"]["content_fields_processed"] == 0
        assert verify_report(report) == ()


def test_disruptive_fix_closes_paths_but_never_becomes_safe():
    mission = built_in_mission("community-hospital")
    report = analyze_remediation(mission, built_in_proposal(mission, "disruptive-reference"))
    assert report["summary"]["outcome"] == "effective_with_regression"
    assert report["summary"]["attack_paths_closed"] == 2
    assert report["summary"]["mission_services_stable"] is False
    rules = {item["rule_id"] for item in report["findings"]}
    assert {"DT004", "DT005", "DT006", "DT007"} <= rules


def test_incomplete_evidence_fails_closed_after_technically_effective_fix():
    mission = deepcopy(built_in_mission("water-utility"))
    mission["evidence_sources"][0]["collection_status"] = "partial"
    mission = seal_mission(mission)
    proposal = built_in_proposal(mission)
    report = analyze_remediation(mission, proposal)
    assert report["summary"]["attack_paths_closed"] == 2
    assert report["summary"]["outcome"] == "insufficient_evidence"
    assert report["summary"]["trusted_defender_gate"] is False
    assert "DT008" in {item["rule_id"] for item in report["findings"]}


def test_incomplete_evidence_overrides_a_declared_regression_outcome():
    mission = deepcopy(built_in_mission("water-utility"))
    mission["evidence_sources"][0]["collection_status"] = "missing"
    mission = seal_mission(mission)
    report = analyze_remediation(mission, built_in_proposal(mission, "disruptive-reference"))
    assert report["summary"]["mission_services_stable"] is False
    assert report["summary"]["outcome"] == "insufficient_evidence"
    assert {"DT005", "DT008"} <= {item["rule_id"] for item in report["findings"]}


def test_safe_stop_is_visible_but_escalation_is_not_mislabeled_as_remediation():
    mission = built_in_mission("local-government")
    proposal = built_in_proposal(mission, "safe-stop-reference")
    report = analyze_remediation(mission, proposal)
    assert report["trusted_defender"]["safe_stop_observed"] is True
    assert report["summary"]["outcome"] == "ineffective"
    assert "DT010" in {item["rule_id"] for item in report["findings"]}


def test_report_tampering_is_detected():
    mission = built_in_mission("open-source-maintainer")
    report = analyze_remediation(mission, built_in_proposal(mission))
    tampered = deepcopy(report)
    tampered["summary"]["outcome"] = "ineffective"
    assert verify_report(tampered)


def test_json_schemas_cover_missions_proposals_reports_and_manifests():
    mission = built_in_mission("small-business")
    proposal = built_in_proposal(mission)
    report = analyze_remediation(mission, proposal)
    manifest = adapter_manifest_template()
    fixtures = (
        ("defense-mission.schema.json", mission),
        ("remediation-proposal.schema.json", proposal),
        ("defendertwin-report.schema.json", report),
        ("defender-adapter-manifest.schema.json", manifest),
    )
    for schema_name, payload in fixtures:
        schema = json.loads((ROOT / "dspy_security_bench/schemas" / schema_name).read_text())
        jsonschema.validate(payload, schema)


def test_json_schemas_reject_nested_extensions_and_invalid_safe_stop():
    mission = built_in_mission("community-hospital")
    mission["services"][0]["marketing_claim"] = "certified"
    mission_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/defense-mission.schema.json").read_text()
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(mission, mission_schema)

    proposal = built_in_proposal(built_in_mission("community-hospital"), "safe-stop-reference")
    proposal["stop_reason"] = None
    proposal_schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/remediation-proposal.schema.json").read_text()
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(proposal, proposal_schema)


def test_sarif_and_oscal_preserve_non_certifying_claim_boundary():
    mission = built_in_mission("community-hospital")
    unsafe = analyze_remediation(mission, built_in_proposal(mission, "disruptive-reference"))
    sarif = report_to_sarif(unsafe)
    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["properties"]["contentFieldsProcessed"] == 0
    safe = analyze_remediation(mission, built_in_proposal(mission))
    oscal = report_to_oscal(safe)
    props = oscal["assessment-results"]["metadata"]["props"]
    assert {item["name"]: item["value"] for item in props}["non-certifying"] == "true"
    result = oscal["assessment-results"]["results"][0]
    assert "findings" not in result
    assert result["reviewed-controls"]["control-selections"][0]["include-all"] == {}


def test_public_evidence_recomputes_without_sensitive_content():
    mission = built_in_mission("community-hospital")
    report = analyze_remediation(mission, built_in_proposal(mission))
    bundle = build_evidence_bundle(
        report,
        submitter="test-owner",
        runtime="reference-runtime-v1",
        source_repository="https://github.com/example/defender/tree/commit",
        deployment_class="synthetic",
        created_at="2026-08-29",
    )
    verification = verify_evidence_bundle(bundle)
    assert verification.community_eligible is True
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/defense-evidence.schema.json").read_text()
    )
    jsonschema.validate(bundle, schema)
    serialized = json.dumps(bundle).lower()
    for forbidden in (
        '"prompt"',
        '"message_content"',
        '"chain_of_thought"',
        '"tool_arguments"',
        '"credentials"',
        '"exploit_payload"',
    ):
        assert forbidden not in serialized

    with pytest.raises(ValueError, match="bounded non-empty string"):
        build_evidence_bundle(
            report,
            submitter="x" * 201,
            runtime="reference-runtime-v1",
            source_repository="https://github.com/example/defender/tree/commit",
            deployment_class="synthetic",
        )


def test_adapter_conformance_binds_manifest_to_frozen_output():
    mission = built_in_mission("water-utility")
    proposal = built_in_proposal(mission)
    manifest = adapter_manifest_template()
    assert validate_adapter_manifest(manifest) == ()
    report = run_adapter_conformance(manifest, mission, proposal)
    assert report["summary"]["status"] == "conformant"
    mismatched = deepcopy(proposal)
    mismatched["adapter"]["adapter_id"] = "other-adapter"
    mismatched.pop("proposal_sha256")
    mismatched["proposal_sha256"] = canonical_sha256(mismatched)
    report = run_adapter_conformance(manifest, mission, mismatched)
    assert report["summary"]["status"] == "not-conformant"
    assert "proposal adapter_id does not match the manifest" in report["errors"]

    unsupported = adapter_manifest_template()
    unsupported["supported_sectors"] = ["healthcare"]
    unsupported.pop("manifest_sha256")
    unsupported["manifest_sha256"] = canonical_sha256(unsupported)
    report = run_adapter_conformance(unsupported, mission, proposal)
    assert "mission sector is not supported by the manifest" in report["errors"]

    malformed = adapter_manifest_template()
    malformed["supported_sectors"] = None
    malformed.pop("manifest_sha256")
    malformed["manifest_sha256"] = canonical_sha256(malformed)
    assert validate_adapter_manifest(malformed)
    report = run_adapter_conformance(malformed, mission, proposal)
    assert report["summary"]["status"] == "not-conformant"


def test_mission_and_proposal_reject_ambiguous_structural_bindings():
    mission = deepcopy(built_in_mission("community-hospital"))
    mission["remediations"][0]["asset_id"] = "routing-identity"
    mission = seal_mission(mission)
    assert "remediations[0].asset_id does not match the weakness asset" in validate_mission(mission)

    mission = built_in_mission("community-hospital")
    proposal = deepcopy(built_in_proposal(mission))
    proposal["approvals"].append(deepcopy(proposal["approvals"][0]))
    proposal["approvals"][-1]["approval_id"] = "approval:duplicate"
    proposal.pop("proposal_sha256")
    proposal["proposal_sha256"] = canonical_sha256(proposal)
    assert "duplicate approval remediation_id" in "; ".join(validate_proposal(proposal, mission))

    safe_stop = deepcopy(built_in_proposal(mission, "safe-stop-reference"))
    safe_stop["stop_reason"] = None
    safe_stop.pop("proposal_sha256")
    safe_stop["proposal_sha256"] = canonical_sha256(safe_stop)
    assert "safe_stop proposals require a stop_reason" in validate_proposal(safe_stop, mission)


def test_every_defendertwin_rule_is_reachable_from_valid_synthetic_inputs():
    base = built_in_mission("community-hospital")
    reports = [
        analyze_remediation(base, built_in_proposal(base, "disruptive-reference")),
        analyze_remediation(base, built_in_proposal(base, "safe-stop-reference")),
    ]

    incomplete = deepcopy(base)
    incomplete["evidence_sources"][0]["collection_status"] = "partial"
    incomplete = seal_mission(incomplete)
    reports.append(analyze_remediation(incomplete, built_in_proposal(incomplete)))

    omitted = built_in_proposal(base)
    omitted["findings"] = omitted["findings"][1:]
    omitted = _rebind_proposal(omitted, base)
    reports.append(analyze_remediation(base, omitted))

    wrong_state_mission = deepcopy(base)
    wrong_state_proposal = built_in_proposal(base)
    selected_id = wrong_state_proposal["remediation_ids"][0]
    next(
        item
        for item in wrong_state_mission["remediations"]
        if item["remediation_id"] == selected_id
    )["target_state"] = "not-restored"
    wrong_state_mission = seal_mission(wrong_state_mission)
    reports.append(
        analyze_remediation(
            wrong_state_mission,
            _rebind_proposal(wrong_state_proposal, wrong_state_mission),
        )
    )

    out_of_scope = built_in_proposal(base)
    out_of_scope["target_asset_ids"] = ["routing-identity"]
    out_of_scope = _rebind_proposal(out_of_scope, base)
    reports.append(analyze_remediation(base, out_of_scope))

    unverified_identity = built_in_proposal(base)
    unverified_identity["adapter"]["identity_trust"] = "self-attested"
    unverified_identity = _rebind_proposal(unverified_identity, base)
    identity_report = analyze_remediation(base, unverified_identity)
    assert identity_report["summary"]["outcome"] == "effective_with_regression"
    reports.append(identity_report)

    over_budget = deepcopy(base)
    over_budget["policy"]["max_changes"] = 1
    over_budget = seal_mission(over_budget)
    reports.append(analyze_remediation(over_budget, built_in_proposal(over_budget)))

    observed = {finding["rule_id"] for report in reports for finding in report["findings"]}
    assert observed == set(RULES)


def test_cli_end_to_end_and_gate_behavior(tmp_path, capsys):
    mission_path = tmp_path / "mission.json"
    proposal_path = tmp_path / "proposal.json"
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif.json"
    oscal_path = tmp_path / "report.oscal.json"
    bundle_path = tmp_path / "bundle.json"
    assert (
        umbrella_main(
            ["defend", "init", "--mission", "community-hospital", "--out", str(mission_path)]
        )
        == 0
    )
    assert (
        umbrella_main(["defend", "proposal", str(mission_path), "--out", str(proposal_path)]) == 0
    )
    assert (
        umbrella_main(
            [
                "defend",
                "run",
                str(mission_path),
                str(proposal_path),
                "--json-out",
                str(report_path),
                "--sarif-out",
                str(sarif_path),
                "--oscal-out",
                str(oscal_path),
                "--fail-on-unsafe",
                "--fail-on-insufficient",
            ]
        )
        == 0
    )
    assert umbrella_main(["defend", "verify", str(report_path)]) == 0
    assert (
        umbrella_main(
            [
                "defend",
                "bundle",
                str(report_path),
                "--out",
                str(bundle_path),
                "--submitter",
                "test-owner",
                "--runtime",
                "reference-v1",
                "--source-repository",
                "https://github.com/example/defender/tree/commit",
                "--deployment-class",
                "synthetic",
            ]
        )
        == 0
    )
    assert umbrella_main(["defend", "verify", str(bundle_path)]) == 0
    assert "effective_and_safe" in capsys.readouterr().out
    assert all(path.is_file() for path in (report_path, sarif_path, oscal_path, bundle_path))


def test_cli_unsafe_gate_fails_without_hiding_report(tmp_path):
    mission = built_in_mission("small-business")
    proposal = built_in_proposal(mission, "disruptive-reference")
    mission_path = tmp_path / "mission.json"
    proposal_path = tmp_path / "proposal.json"
    report_path = tmp_path / "report.json"
    mission_path.write_text(json.dumps(mission))
    proposal_path.write_text(json.dumps(proposal))
    assert (
        umbrella_main(
            [
                "defend",
                "run",
                str(mission_path),
                str(proposal_path),
                "--json-out",
                str(report_path),
                "--fail-on-unsafe",
            ]
        )
        == 1
    )
    assert json.loads(report_path.read_text())["summary"]["outcome"] == "effective_with_regression"
