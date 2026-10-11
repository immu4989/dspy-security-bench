"""A valid nested report must not legitimize type-confused submission metadata."""

from copy import deepcopy

import pytest

from dspy_security_bench.authority.repeat import (
    create_authority_submission_bundle,
    run_repeat_authority_twin,
    verify_authority_submission_bundle,
)
from dspy_security_bench.incident.repeat import (
    create_incident_submission_bundle,
    run_repeat_incident_twin,
    verify_incident_submission_bundle,
)
from dspy_security_bench.mission.loader import load_mission_pack
from dspy_security_bench.mission.repeat import (
    create_source_submission_bundle,
    run_repeat_mission_pack,
    verify_source_submission_bundle,
)
from dspy_security_bench.procurement.agents import build_vulnerable_reference
from dspy_security_bench.procurement.control_registry import (
    create_control_submission_bundle,
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.repeat import (
    canonical_sha256,
    create_submission_bundle,
    run_repeat_twin,
    verify_submission_bundle,
)
from dspy_security_bench.procurement.repeat_control import run_repeat_control_twin
from dspy_security_bench.proofrun import capture_provenance
from tests.test_authoritytwin import build_community_authority_adapter
from tests.test_control_twin import _procurement_policy
from tests.test_incident_twin import build_community_incident_agent
from tests.test_missionforge import build_community_source_agent
from tests.test_proofrun import GITHUB_ENV


@pytest.fixture(scope="module", params=["repeat", "control", "incident", "source", "authority"])
def family(request):
    metadata = {"submitter": "synthetic", "agent_source_url": "https://example.com/agent"}
    if request.param == "repeat":
        report = run_repeat_twin(build_vulnerable_reference(), trials=2).to_dict()
        return create_submission_bundle(report, **metadata), verify_submission_bundle
    if request.param == "incident":
        report = run_repeat_incident_twin(build_community_incident_agent, trials=2).to_dict()
        return create_incident_submission_bundle(report, **metadata), verify_incident_submission_bundle
    if request.param == "source":
        report = run_repeat_mission_pack(build_community_source_agent, load_mission_pack("source-twin"), trials=2).to_dict()
        return create_source_submission_bundle(report, **metadata), verify_source_submission_bundle
    if request.param == "authority":
        report = run_repeat_authority_twin(build_community_authority_adapter, trials=2).to_dict()
        metadata["adapter_source_url"] = metadata.pop("agent_source_url")
        return create_authority_submission_bundle(report, **metadata), verify_authority_submission_bundle
    report = run_repeat_control_twin(build_vulnerable_reference, _procurement_policy(), trials=2).to_dict()
    return create_control_submission_bundle(
        report, **metadata, policy_source_url="https://example.com/policy",
    ), verify_control_submission_bundle


def rehash(bundle):
    bundle.pop("bundle_sha256", None)
    bundle["bundle_sha256"] = canonical_sha256(bundle)


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(bundle_schema_version=True),
    lambda b: b.update(bundle_schema_version=1.0),
    lambda b: b.update(bundle_schema_version=[]),
    lambda b: b["submission"].update(submitter=None),
    lambda b: b["submission"].update(submitter=123),
    lambda b: b["submission"].update(attestation=[]),
    lambda b: b["submission"].update(notes=[]),
    lambda b: b["submission"].pop("created_at"),
    lambda b: b["submission"].update(created_at="not-a-timestamp"),
    lambda b: b["submission"].update(created_at="2026-10-10T00:00:00+01:00"),
    lambda b: b["submission"].update(agent_source_url="https://user:PRIVATE@example.com/repo"),
    lambda b: b["submission"].update(agent_source_url="https://"),
    lambda b: b["submission"].update(agent_source_url="https://example.com:bad/repo"),
    lambda b: b["submission"].update(agent_source_url="https://exa mple.com/repo"),
    lambda b: b["producer"].update(platform=[]),
    lambda b: b["producer"].update(package="PRIVATE"),
    lambda b: b["producer"].pop("python_version"),
    lambda b: b.pop("producer"),
    lambda b: b.update(provenance=None),
    lambda b: b.update(**{"PRIVATE-UNKNOWN-KEY": "PRIVATE"}),
    lambda b: b["producer"].update(**{"PRIVATE-UNKNOWN-KEY": "PRIVATE"}),
    lambda b: b["submission"].update(**{"PRIVATE-UNKNOWN-KEY": "PRIVATE"}),
])
def test_rehashed_metadata_rejected_without_copying_source_content(family, mutate):
    bundle, verify = family
    changed = deepcopy(bundle)
    mutate(changed)
    if "adapter_source_url" in changed["submission"] and "agent_source_url" in changed["submission"]:
        changed["submission"]["adapter_source_url"] = changed["submission"].pop("agent_source_url")
    rehash(changed)
    result = verify(changed)
    assert result.valid is False
    assert result.bundle_sha256 is None
    assert "PRIVATE" not in " ".join(result.errors + result.warnings)


@pytest.mark.parametrize("field,value", [
    ("provider", []), ("repository", ["PRIVATE"]), ("repository_id", 123),
    ("run_id", "１２３"), ("run_attempt", True), ("action_ref", None),
    ("workflow_ref", []), ("ref", "main"), ("repository", "owner/repo/extra"),
    ("builder_kind", []), ("runner_environment", {}), ("run_url", "https://"),
])
def test_github_metadata_types_and_shapes_fail_closed(family, field, value):
    bundle, verify = family
    changed = deepcopy(bundle)
    changed["bundle_schema_version"] = 2
    changed["submission"]["attestation"] = "github_actions_provenance_requested"
    changed["provenance"] = capture_provenance(GITHUB_ENV)
    changed["provenance"][field] = value
    rehash(changed)
    result = verify(changed)
    assert not result.valid
    assert "PRIVATE" not in " ".join(result.errors)


@pytest.mark.parametrize("provenance", [None, "local", "github"])
def test_supported_versions_remain_valid_and_unmodified(family, provenance):
    bundle, verify = family
    source = deepcopy(bundle)
    if provenance is not None:
        source["bundle_schema_version"] = 2
        source["provenance"] = capture_provenance(GITHUB_ENV if provenance == "github" else {})
        if provenance == "github":
            source["submission"]["attestation"] = "github_actions_provenance_requested"
        rehash(source)
    original = deepcopy(source)
    result = verify(source)
    assert result.valid
    assert source == original
    assert result.evidence_tier in ("self_attested", "github_attestation_unverified")


@pytest.mark.parametrize("source", [None, [], True, 3, "PRIVATE"])
def test_nonobject_roots_return_invalid_results(family, source):
    result = family[1](source)
    assert not result.valid
    assert "PRIVATE" not in " ".join(result.errors)


@pytest.mark.parametrize("minimum", [True, 1, 2.0, "5", None, -1])
def test_caller_trial_policy_is_not_coerced(family, minimum):
    with pytest.raises(ValueError, match="minimum_trials"):
        family[1](family[0], minimum_trials=minimum)


def test_missing_submission_with_github_provenance_does_not_crash(family):
    bundle, verify = family
    changed = deepcopy(bundle)
    changed.update(bundle_schema_version=2, submission=None, provenance=capture_provenance(GITHUB_ENV))
    rehash(changed)
    assert not verify(changed).valid


def test_unpaired_surrogates_fail_before_canonical_hashing(family):
    bundle, verify = family
    changed = deepcopy(bundle)
    changed["submission"]["notes"] = "PRIVATE\ud800"
    result = verify(changed)
    assert not result.valid
    assert "PRIVATE" not in " ".join(result.errors)
