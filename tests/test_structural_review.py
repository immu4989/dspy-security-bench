"""One review interface without promoting structural declarations to trials."""

import hashlib
import importlib
import json
from copy import deepcopy

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_review as reviews
from tests import test_proofrun_verification_intake as repeated_fixtures
from tests.test_proofrun_review import schema as schema
from tests.test_public_submission_metadata import family as family
from tests.test_public_submission_metadata import rehash

repeated = repeated_fixtures.family


def write(tmp_path, bundle):
    path = tmp_path / "PRIVATE.json"
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def no_attestation_lookup(monkeypatch):
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("structural review reached gh"))


@pytest.mark.parametrize("case", ["offline", "online", "builder", "mismatch", "pin", "tamper", "metadata", "semantic"])
def test_structural_cli_decisions(family, case, tmp_path, capsys, schema):
    kind, bundle, *_ = family
    bundle = deepcopy(bundle)
    bundle["submission"]["submitter"] = "PRIVATE-owner"
    source = "source_repository_url" if kind == "trace" else "source_repository"
    bundle["submission"][source] = "https://example.com/PRIVATE"
    rehash(bundle)
    options = ["--structural", "--offline"]
    code, reason = 0, "offline_verified"
    if case in {"online", "builder"}:
        options = ["--structural"] + (["--require-trusted-builder"] if case == "builder" else [])
        code, reason = 1, "attestation_unverified"
    elif case == "mismatch":
        options = ["--offline"]
        code, reason = 2, "policy_not_applicable"
    elif case == "pin":
        options += ["--expected-file-sha256", "0" * 64]
        code, reason = 2, "pin_mismatch"
    elif case == "tamper":
        bundle["bundle_sha256"] = "0" * 64
        code, reason = 2, "invalid_evidence"
    elif case == "metadata":
        bundle["schema_version"] = True
        rehash(bundle)
        code, reason = 2, "invalid_evidence"
    elif case == "semantic":
        bundle["schedule_report" if kind == "causal" else "report"]["summary"]["PRIVATE"] = "PRIVATE"
        rehash(bundle)
        code, reason = 2, "invalid_evidence"
    path = write(tmp_path, bundle)
    assert cli.main(["verify", str(path), "--json", *options]) == code
    output = capsys.readouterr()
    assert output.err == "" and "PRIVATE" not in output.out
    result = json.loads(output.out)
    schema.validate(result)
    assert result["reason_code"] == reason
    assert result["input_file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["review_is_attestation"] is False and result["execution_reproduced"] is False
    if code != 2:
        assert result["integrity"] == "valid" and result["eligibility"] == "eligible"
        assert result["bundle_sha256"] == bundle["bundle_sha256"]
        assert result["evidence_tier"] == "self_attested"
        assert result["policy"]["minimum_trials"] is None
        assert result["provenance"] == ("not_checked" if case == "offline" else "unverified")
    if case != "pin":
        assert "Structural review" in reviews.render_review(result)
        assert "adverse findings" in reviews.render_review(result)
    else:
        assert result["bundle_type"] is None  # Pin rejection precedes dispatch.


def test_repeated_bundles_cannot_disable_trial_policy(repeated, tmp_path, schema, monkeypatch):
    module, name, *_ = reviews.FAMILIES[repeated["bundle_type"]]
    monkeypatch.setattr(importlib.import_module(module), name, lambda *a, **k: pytest.fail("inapplicable policy reached replay"))
    result = reviews.review_bundle(write(tmp_path, repeated), policy=reviews.ReviewPolicy(minimum_trials=None, offline=True))
    schema.validate(result)
    assert result["reason_code"] == "policy_not_applicable"
    assert result["integrity"] == "not_checked" and result["bundle_sha256"] is None


@pytest.mark.parametrize("value", ["0", "2", "5", "05", "+5", "10"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("equals", [False, True])
def test_cli_cannot_silently_drop_an_explicit_trial_requirement(value, reverse, equals, monkeypatch):
    explicit = [f"--minimum-trials={value}"] if equals else ["--minimum-trials", value]
    options = [*explicit, "--structural"] if reverse else ["--structural", *explicit]
    monkeypatch.setattr(cli, "review_bundle", lambda *a, **k: pytest.fail("conflicting policy reached input review"))
    with pytest.raises(SystemExit) as caught:
        cli.main(["verify", "unused", *options, "--json"])
    assert caught.value.code == 2


@pytest.mark.parametrize("options,expected", [([], 5), (["--minimum-trials", "5"], 5),
                                           (["--minimum-trials", "2"], 2), (["--minimum-trials", "0"], 0),
                                           (["--structural"], None)])
def test_deferred_trial_default_preserves_explicit_policy(options, expected, monkeypatch, capsys):
    policies = []
    def review(path, *, policy):
        policies.append(policy)
        return {"exit_code": 0}
    monkeypatch.setattr(cli, "review_bundle", review)
    assert cli.main(["verify", "unused", *options, "--json"]) == 0
    assert len(policies) == 1 and policies[0].minimum_trials == expected
    assert capsys.readouterr().err == ""


def ineligible(family):
    kind, _, verify, create, args, metadata = family
    args = deepcopy(args)
    metadata = dict(metadata)
    if kind == "trace":
        from dspy_security_bench.trace.proof import (
            analyze_trace_evidence,
            build_trace_evidence,
            demo_otlp_payload,
        )
        evidence = build_trace_evidence(demo_otlp_payload())
        args = (evidence, analyze_trace_evidence(evidence))
    elif kind == "causal":
        args[0]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["droppedLinksCount"] = 2
    elif kind == "collective":
        from dspy_security_bench.collective.v2 import built_in_scenario_v2
        args = (built_in_scenario_v2("hardened-partial"),)
    else:
        metadata["disclosure_status"] = "private"
    bundle = create(*args, **metadata)
    native = verify(bundle)
    assert not native.errors and native.warnings and not native.community_eligible
    return bundle


@pytest.mark.parametrize("offline", [True, False])
def test_native_warnings_remain_valid_but_ineligible(family, offline, tmp_path, schema):
    bundle = ineligible(family)
    policy = reviews.ReviewPolicy(minimum_trials=None, offline=offline)
    result = reviews.review_bundle(write(tmp_path, bundle), policy=policy)
    schema.validate(result)
    assert result["exit_code"] == 1 and result["reason_code"] == "not_eligible"
    assert result["integrity"] == "valid" and result["provenance"] == "not_checked"
    assert result["bundle_sha256"] == bundle["bundle_sha256"]


def test_structural_pin_and_decision_bind_one_snapshot(family, tmp_path, monkeypatch, schema):
    _, bundle, verify, *_ = family
    path = write(tmp_path, bundle)
    pin = hashlib.sha256(path.read_bytes()).hexdigest()

    def verify_then_replace(data):
        result = verify(data)
        path.write_text('{"PRIVATE":"replaced"}', encoding="utf-8")
        return result

    monkeypatch.setattr(importlib.import_module(verify.__module__), verify.__name__, verify_then_replace)
    result = reviews.review_bundle(path, policy=reviews.ReviewPolicy(minimum_trials=None, offline=True, expected_file_sha256=pin))
    schema.validate(result)
    assert result["exit_code"] == 0 and result["input_file_sha256"] == pin
    assert result["bundle_sha256"] == bundle["bundle_sha256"]
    assert "PRIVATE" not in json.dumps(result)


def test_native_failure_is_bounded_and_redacted(family, tmp_path, monkeypatch, schema):
    _, bundle, verify, *_ = family

    def fail(data):
        raise ValueError("PRIVATE diagnostic")

    monkeypatch.setattr(importlib.import_module(verify.__module__), verify.__name__, fail)
    result = reviews.review_bundle(write(tmp_path, bundle), policy=reviews.ReviewPolicy(minimum_trials=None, offline=True))
    schema.validate(result)
    assert result["reason_code"] == "verification_error"
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("change", [
    {"provenance": "verified"}, {"evidence_tier": "trusted_builder"},
    {"evidence_tier": "github_attestation_unverified"}, {"review_is_attestation": True},
    {"execution_reproduced": True}, {"bundle_sha256": None}, {"eligibility": "ineligible"},
])
def test_schema_cannot_promote_structural_evidence(family, change, tmp_path, schema):
    result = reviews.review_bundle(write(tmp_path, family[1]), policy=reviews.ReviewPolicy(minimum_trials=None, offline=True))
    schema.validate(result)
    result.update(change)
    assert list(schema.iter_errors(result))


def test_schema_binds_null_trials_to_structural_policy(family, tmp_path, schema):
    result = reviews.review_bundle(write(tmp_path, family[1]), policy=reviews.ReviewPolicy(minimum_trials=None, offline=True))
    result["policy"]["minimum_trials"] = 5
    assert list(schema.iter_errors(result))


def test_schema_rejects_forged_online_structural_success(family, tmp_path, schema):
    result = reviews.review_bundle(write(tmp_path, family[1]), policy=reviews.ReviewPolicy(minimum_trials=None))
    schema.validate(result)
    result.update(verdict="pass", exit_code=0, reason_code="online_verified", provenance="verified", evidence_tier="github_attested")
    assert list(schema.iter_errors(result))


@pytest.mark.parametrize("raw", [b'{"PRIVATE":1,"PRIVATE":2}', b'[]', b'{"PRIVATE":NaN}', b'{"PRIVATE":"\\ud800"}'])
def test_structural_mode_retains_strict_redacted_intake(raw, tmp_path, schema):
    path = tmp_path / "PRIVATE.json"
    path.write_bytes(raw)
    result = reviews.review_bundle(path, policy=reviews.ReviewPolicy(minimum_trials=None, offline=True))
    schema.validate(result)
    assert result["reason_code"] == "invalid_input"
    assert result["input_file_sha256"] is None and "PRIVATE" not in json.dumps(result)


def test_structural_pin_covers_exact_formatting(family, tmp_path, schema):
    path = write(tmp_path, family[1])
    raw = path.read_bytes()
    policy = reviews.ReviewPolicy(minimum_trials=None, offline=True, expected_file_sha256=hashlib.sha256(raw).hexdigest())
    first = reviews.review_bundle(path, policy=policy)
    assert first == reviews.review_bundle(path, policy=policy)
    path.write_bytes(raw + b"\n")
    changed = reviews.review_bundle(path, policy=policy)
    schema.validate(changed)
    assert changed["reason_code"] == "pin_mismatch"
    assert changed["input_file_sha256"] != first["input_file_sha256"]


def test_unsafe_causal_schedule_is_evidence_not_deployment_approval(family, tmp_path):
    if family[0] != "causal":
        return
    bundle = family[1]
    assert bundle["schedule_report"]["summary"]["status"] == "unsafe"
    result = reviews.review_bundle(write(tmp_path, bundle), policy=reviews.ReviewPolicy(minimum_trials=None, offline=True))
    assert result["exit_code"] == 0
    assert "adverse findings" in reviews.render_review(result)
