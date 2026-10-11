"""Review automation must not confuse integrity, eligibility, and identity."""

import hashlib
import json
from copy import deepcopy
from importlib.resources import files
from types import SimpleNamespace

import pytest

import dspy_security_bench.proofrun as proof
import dspy_security_bench.proofrun_cli as cli
import dspy_security_bench.proofrun_review as reviews
from dspy_security_bench.procurement.repeat import canonical_sha256
from dspy_security_bench.proofrun_review import ReviewPolicy, review_bundle
from tests.test_proofrun_verification_intake import attested as attested
from tests.test_proofrun_verification_intake import family as family


@pytest.fixture(scope="module")
def schema():
    jsonschema = pytest.importorskip("jsonschema")
    source = json.loads(files("dspy_security_bench.schemas").joinpath("proofrun-review.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(source)
    return jsonschema.Draft202012Validator(source)


@pytest.mark.parametrize("case", ["valid", "ineligible", "invalid", "broken", "pin", "unknown", "policy", "unreadable"])
def test_one_json_decision_for_each_family_and_outcome(family, case, tmp_path, capsys, schema):
    bundle = deepcopy(family)
    path = tmp_path / "PRIVATE-filename.json"
    options = ["--offline", "--minimum-trials", "2"]
    code, reason = 0, "offline_verified"
    if case == "ineligible":
        options = ["--offline"]
        code, reason = 1, "not_eligible"
    elif case == "invalid":
        bundle["PRIVATE-FIELD"] = "PRIVATE"
        code, reason = 2, "invalid_evidence"
    elif case == "pin":
        options += ["--expected-file-sha256", "0" * 64]
        code, reason = 2, "pin_mismatch"
    elif case == "unknown":
        bundle["bundle_type"] = "PRIVATE"
        code, reason = 2, "unsupported_bundle_type"
    elif case == "policy":
        options += ["--require-trusted-builder"]
        code, reason = 2, "invalid_policy"
    elif case in ("broken", "unreadable"):
        code, reason = 2, "invalid_input"
    if case != "unreadable":
        path.write_text('{"PRIVATE":NaN}' if case == "broken" else json.dumps(bundle), encoding="utf-8")
    assert cli.main(["verify", str(path), "--json", *options]) == code
    output = capsys.readouterr()
    assert output.err == ""
    assert "PRIVATE" not in output.out
    result = json.loads(output.out)
    schema.validate(result)
    assert result["exit_code"] == code
    assert result["reason_code"] == reason
    assert not result["review_is_attestation"] and not result["execution_reproduced"]
    assert result["provenance"] == "not_checked"


def test_valid_source_strings_never_copied_into_review(family, tmp_path, schema):
    bundle = deepcopy(family)
    bundle["submission"].update(submitter="PRIVATE-team", notes="PRIVATE-notes")
    source_key = "adapter_source_url" if "adapter_source_url" in bundle["submission"] else "agent_source_url"
    bundle["submission"][source_key] = "https://example.com/PRIVATE"
    bundle.pop("bundle_sha256")
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    path = tmp_path / "PRIVATE.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    policy = ReviewPolicy(minimum_trials=2, offline=True, attestation_repository="PRIVATE/vendor")
    result = review_bundle(path, policy=policy)
    schema.validate(result)
    assert result["exit_code"] == 0
    assert "PRIVATE" not in json.dumps(result)
    assert result["policy"]["expected_repository_sha256"] == hashlib.sha256(b"PRIVATE/vendor").hexdigest()
    assert result == review_bundle(str(path), policy=policy)
    assert result["input_file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["bundle_sha256"] == bundle["bundle_sha256"]


@pytest.mark.parametrize("change", [
    {"minimum_trials": True}, {"minimum_trials": 1}, {"minimum_trials": 2.0},
    {"offline": "false"}, {"allow_self_hosted_runner": 1}, {"require_trusted_builder": None},
    {"expected_file_sha256": "PRIVATE"}, {"attestation_repository": []},
    {"attestation_repository": "PRIVATE"}, {"attestation_repository": "PRIVATE/\ud800"},
    {"attestation_repository": "PRIVATE/\x00"}, {"offline": True, "require_trusted_builder": True},
])
def test_invalid_python_policy_is_typed_and_source_redacted(change, monkeypatch, schema):
    monkeypatch.setattr(reviews, "read_json_snapshot", lambda *a: pytest.fail("invalid policy reached intake"))
    result = review_bundle("PRIVATE", policy=ReviewPolicy(**change))
    schema.validate(result)
    assert result["reason_code"] == "invalid_policy"
    assert result["policy"] is None
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("authenticated", [False, True])
def test_online_json_distinguishes_authentication_from_integrity(attested, authenticated, monkeypatch, capsys, schema):
    path, _, _, certificate = attested
    monkeypatch.setattr(proof.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0 if authenticated else 1, stdout=json.dumps([certificate]), stderr="PRIVATE",
    ))
    assert cli.main(["verify", str(path), "--json", "--require-trusted-builder"]) == (0 if authenticated else 1)
    output = capsys.readouterr()
    assert output.err == ""
    assert "PRIVATE" not in output.out
    result = json.loads(output.out)
    schema.validate(result)
    assert result["integrity"] == "valid" and result["eligibility"] == "eligible"
    assert result["provenance"] == ("verified" if authenticated else "unverified")
    assert result["evidence_tier"] == ("trusted_builder" if authenticated else "github_attestation_unverified")


def test_ineligible_evidence_never_attempts_online_authentication(family, tmp_path, monkeypatch, schema):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(family), encoding="utf-8")
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("ineligible evidence reached network"))
    result = review_bundle(path)
    schema.validate(result)
    assert result["reason_code"] == "not_eligible"
    assert result["provenance"] == "not_checked"


def test_native_exception_is_a_structured_failure(attested, monkeypatch, schema):
    import dspy_security_bench.procurement.repeat as repeat

    def fail(*args, **kwargs):
        raise AttributeError("PRIVATE")

    monkeypatch.setattr(repeat, "verify_submission_bundle", fail)
    result = review_bundle(attested[0], policy=ReviewPolicy(offline=True))
    schema.validate(result)
    assert result["reason_code"] == "verification_error"
    assert "PRIVATE" not in json.dumps(result)


def test_attestation_exception_remains_unverified_not_success(attested, monkeypatch, schema):
    def fail(*args, **kwargs):
        raise ValueError("PRIVATE")

    monkeypatch.setattr(reviews, "verify_github_attestation", fail)
    result = review_bundle(attested[0])
    schema.validate(result)
    assert result["integrity"] == "valid"
    assert result["provenance"] == "unverified"
    assert result["exit_code"] == 1
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("mutation", [
    {"provenance": "verified"}, {"evidence_tier": "github_attested"},
    {"exit_code": 1}, {"review_is_attestation": True}, {"execution_reproduced": True},
    {"eligibility": "not_checked"}, {"bundle_sha256": None}, {"PRIVATE": "PRIVATE"},
])
def test_schema_rejects_contradictory_or_extra_offline_claims(attested, mutation, schema):
    result = review_bundle(attested[0], policy=ReviewPolicy(offline=True))
    schema.validate(result)
    result.update(mutation)
    assert list(schema.iter_errors(result))
