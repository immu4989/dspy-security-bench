"""Dashboard rows require real native evidence, not just self-rehashed summaries."""

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from dspy_security_bench.authority.repeat import (
    create_authority_submission_bundle,
    run_repeat_authority_twin,
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
from dspy_security_bench.procurement.control_registry import create_control_submission_bundle
from dspy_security_bench.procurement.repeat import (
    canonical_sha256,
    create_submission_bundle,
    run_repeat_twin,
)
from dspy_security_bench.procurement.repeat_control import run_repeat_control_twin
from dspy_security_bench.proofrun import capture_provenance
from scripts import generate_site_data as site
from tests.test_authoritytwin import build_community_authority_adapter
from tests.test_control_registry import _policy, build_community_control_agent
from tests.test_incident_twin import build_community_incident_agent
from tests.test_missionforge import build_community_source_agent
from tests.test_proofrun import GITHUB_ENV
from tests.test_repeat_twin import build_community_agent
from tests.test_submission_ci_intake import attestation_record


@pytest.fixture(scope="module", params=["impact", "control", "incident", "source", "authority"])
def bundle_family(request):
    metadata = {"submitter": "synthetic", "agent_source_url": "https://example.com/agent",
                "provenance": capture_provenance(GITHUB_ENV)}
    if request.param == "impact":
        report = run_repeat_twin(build_community_agent(), trials=5, agent_factory=build_community_agent)
        bundle = create_submission_bundle(report.to_dict(), **metadata)
        render = site._proofrun_results
    elif request.param == "control":
        report = run_repeat_control_twin(build_community_control_agent, _policy(), trials=5)
        bundle = create_control_submission_bundle(report.to_dict(), **metadata, policy_source_url="https://example.com/policy")
        render = site._control_evidence_results
    elif request.param == "incident":
        report = run_repeat_incident_twin(build_community_incident_agent, trials=5)
        bundle = create_incident_submission_bundle(report.to_dict(), **metadata)
        render = site._incident_evidence_results
    elif request.param == "source":
        report = run_repeat_mission_pack(build_community_source_agent, load_mission_pack("source-twin"), trials=5)
        bundle = create_source_submission_bundle(report.to_dict(), **metadata)
        render = site._source_evidence_results
    else:
        report = run_repeat_authority_twin(build_community_authority_adapter, trials=5)
        metadata["adapter_source_url"] = metadata.pop("agent_source_url")
        bundle = create_authority_submission_bundle(report.to_dict(), **metadata)
        render = site._authority_evidence_results
    return bundle, render


@pytest.fixture
def inputs(tmp_path, bundle_family):
    bundle, render = bundle_family
    submissions = tmp_path / "entries"
    submissions.mkdir()
    (submissions / "agent.json").write_text(json.dumps(bundle))
    attestations, reproductions = tmp_path / "attestations.json", tmp_path / "reproductions.json"
    for path, key in ((attestations, "attestations"), (reproductions, "reproductions")):
        path.write_text(json.dumps({"schema_version": 1, key: {}}))
    return bundle, lambda: render(submissions, reproductions, attestations), submissions, attestations, reproductions


def test_complete_native_evidence_and_reviewed_record_projection(inputs):
    bundle, rows, _, attestations, reproductions = inputs
    assert rows()[0]["evidenceTier"] == "github_attestation_unverified"
    digest = bundle["bundle_sha256"]
    attestations.write_text(json.dumps({"schema_version": 1, "attestations": {digest: attestation_record(bundle)}}))
    assert rows()[0]["evidenceTier"] == "trusted_builder"
    reproductions.write_text(json.dumps({"schema_version": 1, "reproductions": {digest: {
        "reproduced_by": "owner-reviewed", "run_url": "https://example.com/run", "created_at": "2026-10-10T00:00:00Z",
    }}}))
    assert rows()[0]["evidenceTier"] == "maintainer_reproduced"


@pytest.mark.parametrize("mutation", ["partial", "wrong_commit", "bad_time", "null_reproduction", "null_attestation", "credentials"])
def test_malformed_tier_records_never_upgrade_valid_rows(inputs, mutation):
    bundle, rows, _, attestations, reproductions = inputs
    record = attestation_record(bundle)
    if mutation == "partial":
        record = {"evidence_tier": "trusted_builder"}
    elif mutation == "wrong_commit":
        record["source_commit"] = "c" * 40
    elif mutation == "bad_time":
        record["verified_at"] = "not-a-time"
    elif mutation == "credentials":
        record["run_url"] = "https://user:PRIVATE@example.com/run"
    elif mutation == "null_attestation":
        record = None
    else:
        reproductions.write_text(json.dumps({"schema_version": 1, "reproductions": {bundle["bundle_sha256"]: None}}))
        record = None
    attestations.write_text(json.dumps({"schema_version": 1, "attestations": {bundle["bundle_sha256"]: record}}))
    assert rows()[0]["evidenceTier"] == "github_attestation_unverified"


def test_rehashed_invalid_report_is_not_a_public_row(inputs):
    bundle, rows, submissions, _, _ = inputs
    bad = deepcopy(bundle)
    bad["report"]["trials"] = [{}, {}, {}, {}, {}]
    bad["report_sha256"] = canonical_sha256(bad["report"])
    bad.pop("bundle_sha256")
    bad["bundle_sha256"] = canonical_sha256(bad)
    (submissions / "agent.json").write_text(json.dumps(bad))
    assert rows() == []


def test_malformed_input_is_skipped_without_hiding_valid_neighbor(inputs):
    _, rows, submissions, attestations, _ = inputs
    for index, raw in enumerate((b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\\ud800"}')):
        (submissions / f"bad-{index}.json").write_bytes(raw)
    (submissions / "linked.json").symlink_to(submissions / "agent.json")
    attestations.write_text('{"schema_version":true,"attestations":{}}')
    assert len(rows()) == 1
    assert rows()[0]["evidenceTier"] == "github_attestation_unverified"


def test_local_provenance_cannot_receive_an_attestation_label():
    record = {"evidence_tier": "trusted_builder", "verified_by": "synthetic", "verified_at": "2026-10-10T00:00:00Z",
              "run_url": "https://example.com/run", "source_commit": "a" * 40,
              "signer_workflow": "synthetic"}
    assert site._evidence_tier("a" * 64, {"provider": "local"}, {"a" * 64: record}, {}) == "self_attested"


def test_all_verifiers_and_site_generation_work_with_only_stdlib_and_yaml():
    root = Path(__file__).resolve().parents[1]
    bootstrap = f"""
import importlib.abc, json, pathlib, socket, sys
sys.path[:0] = [{str(root)!r}, {str(Path(yaml.__file__).resolve().parent.parent)!r}]
allowed = set(sys.stdlib_module_names) | {{'dspy_security_bench', 'scripts', 'yaml', '_yaml'}}
class MinimalImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in allowed:
            raise ModuleNotFoundError('optional dependency unavailable: ' + fullname, name=fullname)
sys.meta_path.insert(0, MinimalImports())
def offline(*args, **kwargs):
    raise RuntimeError('site admission must not call a network')
socket.socket.connect = offline
socket.create_connection = offline
from scripts import validate_impact_submissions, generate_site_data
assert callable(validate_impact_submissions.main)
assert generate_site_data.build_payload() == json.loads(pathlib.Path({str(root / 'site/data.json')!r}).read_text())
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", bootstrap], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind", ["trace", "causal", "collective", "defense"])
def test_structural_registry_rows_require_native_recomputation(kind, tmp_path):
    metadata = {"submitter": "synthetic", "runtime": "synthetic-runtime"}
    if kind == "trace":
        from dspy_security_bench.trace.evidence import build_trace_submission_bundle
        from dspy_security_bench.trace.proof import analyze_trace_evidence, build_trace_evidence
        from dspy_security_bench.trace.runtime import TraceRecorder

        recorder = TraceRecorder(service_name="synthetic")
        recorder.record(operation="invoke_agent", agent_name="synthetic")
        evidence = build_trace_evidence(recorder.to_otlp_json())
        bundle = build_trace_submission_bundle(evidence, analyze_trace_evidence(evidence), **metadata,
                                               source_repository_url="https://example.com/source")
        render = site._trace_evidence_results
    elif kind == "causal":
        from dspy_security_bench.causal.proof import build_demo_inputs
        from dspy_security_bench.causal.registry import build_causal_submission_bundle

        trace, manifest = build_demo_inputs()
        bundle = build_causal_submission_bundle(trace, manifest, **metadata, source_repository="https://example.com/source")
        render = site._causal_evidence_results
    elif kind == "collective":
        from dspy_security_bench.collective.registry import build_collective_submission_bundle
        from dspy_security_bench.collective.v2 import built_in_scenario_v2

        bundle = build_collective_submission_bundle(built_in_scenario_v2("hardened-complete"), **metadata,
                                                    source_repository="https://example.com/source", deployment_class="synthetic")
        render = site._collective_evidence_results
    else:
        from dspy_security_bench.defend.evidence import build_evidence_bundle
        from dspy_security_bench.defend.protocol import (
            analyze_remediation,
            built_in_mission,
            built_in_proposal,
        )

        mission = built_in_mission("community-hospital")
        bundle = build_evidence_bundle(analyze_remediation(mission, built_in_proposal(mission)), **metadata,
                                       source_repository="https://example.com/source", deployment_class="synthetic")
        render = site._defense_evidence_results
    path = tmp_path / "example.json"
    path.write_text(json.dumps(bundle))
    assert len(render(tmp_path)) == 1
    bundle["causal_report" if kind == "causal" else "report"] = {"summary": {"status": "ready"}}
    bundle.pop("bundle_sha256")
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    path.write_text(json.dumps(bundle))
    assert render(tmp_path) == []


def test_pages_gates_before_generation_with_separate_read_only_build_permissions():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.load((root / ".github/workflows/pages.yml").read_text(), Loader=yaml.BaseLoader)
    build = workflow["jobs"]["build"]
    assert build["permissions"] == {"contents": "read", "attestations": "read"}
    steps = build["steps"]
    gate = next(i for i, step in enumerate(steps) if step.get("run") == "python scripts/validate_impact_submissions.py")
    generation = next(i for i, step in enumerate(steps) if step.get("run") == "python scripts/generate_site_data.py")
    upload = next(i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/upload-pages-artifact@"))
    assert gate < generation < upload
    assert "continue-on-error" not in steps[gate] and "if" not in steps[gate]
    assert steps[gate]["env"] == {"GH_TOKEN": "${{ github.token }}"}
    assert "GH_TOKEN" not in build.get("env", {})
    assert workflow["jobs"]["deploy"]["needs"] == "build"
    assert workflow["jobs"]["deploy"]["permissions"] == {"pages": "write", "id-token": "write"}
    assert "dspy_security_bench/**" in workflow["on"]["push"]["paths"]
