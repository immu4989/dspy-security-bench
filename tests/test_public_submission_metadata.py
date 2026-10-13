"""Rehashing malformed declarations cannot admit public structural evidence."""

import importlib
import json
from copy import deepcopy

import pytest

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.public_submission import prepare_submission
from scripts import generate_site_data as site
from scripts import validate_impact_submissions as intake


@pytest.fixture(scope="module", params=["trace", "causal", "collective", "defense"])
def family(request):
    kind = request.param
    metadata = {"submitter": "synthetic", "runtime": "synthetic", "source_repository": "https://example.com/source"}
    if kind == "trace":
        from dspy_security_bench.trace import evidence as module
        from dspy_security_bench.trace.proof import analyze_trace_evidence, build_trace_evidence
        from dspy_security_bench.trace.runtime import TraceRecorder
        recorder = TraceRecorder(service_name="synthetic")
        recorder.record(operation="invoke_agent", agent_name="synthetic")
        evidence = build_trace_evidence(recorder.to_otlp_json())
        metadata["source_repository_url"] = metadata.pop("source_repository")
        create = module.build_trace_submission_bundle
        args = (evidence, analyze_trace_evidence(evidence))
        verify = module.verify_trace_submission_bundle
    elif kind == "causal":
        from dspy_security_bench.causal import registry as module
        from dspy_security_bench.causal.proof import build_demo_inputs
        create, args, verify = module.build_causal_submission_bundle, build_demo_inputs(), module.verify_causal_submission_bundle
    elif kind == "collective":
        from dspy_security_bench.collective import registry as module
        from dspy_security_bench.collective.v2 import built_in_scenario_v2
        metadata["deployment_class"] = "synthetic"
        create, args, verify = module.build_collective_submission_bundle, (built_in_scenario_v2("hardened-complete"),), module.verify_collective_submission_bundle
    else:
        from dspy_security_bench.defend import evidence as module
        from dspy_security_bench.defend.protocol import (
            analyze_remediation,
            built_in_mission,
            built_in_proposal,
        )
        mission = built_in_mission("community-hospital")
        metadata["deployment_class"] = "synthetic"
        create, args, verify = module.build_evidence_bundle, (analyze_remediation(mission, built_in_proposal(mission)),), module.verify_evidence_bundle
    return kind, create(*args, **metadata), verify, create, args, metadata


def rehash(bundle):
    bundle.pop("bundle_sha256", None)
    bundle["bundle_sha256"] = canonical_sha256(bundle)


@pytest.mark.parametrize("mutation", [
    "bool_version", "float_version", "list_version", "digest", "submission", "unknown",
    "submitter", "runtime", "credentials", "empty_user", "empty_host", "bad_port", "space", "control", "date",
])
def test_rehashed_metadata_is_rejected_before_native_replay(family, mutation, monkeypatch):
    kind, original, verify, *_ = family
    bundle = deepcopy(original)
    field = "source_repository_url" if kind == "trace" else "source_repository"
    if mutation.endswith("_version"):
        bundle["schema_version"] = {"bool_version": True, "float_version": 1.0, "list_version": []}[mutation]
    elif mutation == "submission":
        bundle["submission"] = None
    elif mutation == "unknown":
        bundle["submission"]["PRIVATE-key"] = "PRIVATE-value"
    elif mutation in ("submitter", "runtime"):
        bundle["submission"][mutation] = None
    elif mutation == "date":
        bundle["submission"]["created_at"] = 20261012
    elif mutation != "digest":
        bundle["submission"][field] = {
            "credentials": "https://user:PRIVATE@example.com/repo", "empty_user": "https://@example.com/repo",
            "empty_host": "https://", "bad_port": "https://example.com:PRIVATE/repo",
            "space": "https://exa mple.com/PRIVATE", "control": "https://example.com/\x00PRIVATE",
        }[mutation]
    rehash(bundle)
    if mutation == "digest":
        bundle["bundle_sha256"] = None
    monkeypatch.setattr(importlib.import_module(verify.__module__), "canonical_sha256",
                        lambda *a: pytest.fail("malformed declarations reached canonicalization/replay"))
    result = verify(bundle)
    assert result.errors and not result.community_eligible
    assert "PRIVATE" not in " ".join(result.errors + result.warnings)


@pytest.mark.parametrize("root", [None, [], True, "PRIVATE"])
def test_nonobject_roots_are_invalid_results_not_exceptions(family, root):
    result = family[2](root)
    assert result.errors and not result.community_eligible
    assert "PRIVATE" not in " ".join(result.errors)


def test_surrogate_text_fails_before_hashing(family):
    _, bundle, verify, *_ = family
    changed = deepcopy(bundle)
    changed["submission"]["runtime"] = "PRIVATE\ud800"
    result = verify(changed)
    assert result.errors and not result.community_eligible
    assert "PRIVATE" not in " ".join(result.errors)


@pytest.mark.parametrize("change", [{"submitter": None}, {"runtime": True}, {"source": "https://user:PRIVATE@example.com/repo"}])
def test_creators_fail_before_touching_evidence(family, change, monkeypatch):
    kind, _, _, create, args, metadata = family
    kwargs = {**metadata, **change}
    if "source" in kwargs:
        kwargs["source_repository_url" if kind == "trace" else "source_repository"] = kwargs.pop("source")
    module = importlib.import_module(create.__module__)
    # These are the first evidence-processing operations of each creator.
    name = {"trace": "verify_trace_evidence", "causal": "structural_trace", "collective": "validate_scenario", "defense": "verify_report"}[kind]
    monkeypatch.setattr(module, name, lambda *a: pytest.fail("bad metadata reached evidence processing"))
    with pytest.raises(ValueError) as caught:
        create(*args, **kwargs)
    assert "PRIVATE" not in str(caught.value)


def test_valid_source_is_unchanged_and_site_and_intake_reject_rehashed_bad_version(family, tmp_path, monkeypatch):
    kind, bundle, verify, *_ = family
    original = deepcopy(bundle)
    assert verify(bundle).community_eligible
    assert bundle == original
    folder = tmp_path / "submissions" / kind
    folder.mkdir(parents=True)
    for name in ("attestations", "reproductions"):
        (folder.parent / f"{name}.json").write_text(
            json.dumps({"schema_version": 1, name: {}}), encoding="utf-8",
        )
    path = folder / "synthetic.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    monkeypatch.setattr(intake, "verify_github_attestation", lambda *a, **k: pytest.fail("self-attested evidence requested network"))
    assert intake.main(tmp_path) == 0
    assert site._native_eligible(bundle, bundle["bundle_type"])
    changed = deepcopy(bundle)
    changed["schema_version"] = True
    rehash(changed)
    path.write_text(json.dumps(changed), encoding="utf-8")
    assert intake.main(tmp_path) == 1
    assert not site._native_eligible(changed, changed["bundle_type"])


@pytest.mark.parametrize("kind", ["causal", "collective", "defense"])
@pytest.mark.parametrize("change", [{"created_at": 20261012}, {"created_at": "20261012"}, {"created_at": ""},
                                    {"known_gaps": "PRIVATE"}, {"known_gaps": []}, {"known_gaps": [None]}])
def test_date_and_gap_declarations_are_not_silently_coerced(kind, change):
    with pytest.raises(ValueError) as caught:
        prepare_submission(family=kind, submitter="synthetic", runtime="synthetic", deployment_class="synthetic",
                           source_repository="https://example.com/source", **change)
    assert "PRIVATE" not in str(caught.value)


def test_preparation_copies_retained_gap_declarations():
    gaps = ["owner-declared gap"]
    prepared = prepare_submission(family="collective", submitter="synthetic", runtime="synthetic",
                                  source_repository="https://example.com/source", deployment_class="synthetic",
                                  known_gaps=gaps, created_at="2026-10-12")
    gaps.append("new caller value")
    assert prepared["known_gaps"] == ["owner-declared gap"]
