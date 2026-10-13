"""An owner must see every requirement change before approving new plan bytes."""

import hashlib
import json
from copy import deepcopy
from importlib.resources import files

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_collection as collection
from dspy_security_bench import proofrun_plan_diff as diff
from dspy_security_bench import proofrun_review as reviews


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def plan(prefix="private", count=2):
    return {"schema_version": 1, "plan_type": collection.PLAN_TYPE, "entries": [
        {"id": f"{prefix}-{i}", "path": f"{prefix}-{i}.json", "file_sha256": digest(f"{prefix}-{i}".encode()),
         "bundle_type": next(iter(reviews.FAMILIES)), "policy": {
             "minimum_trials": 5, "offline": False, "attestation_repository": "PRIVATE/organization",
             "require_trusted_builder": True, "allow_self_hosted_runner": False,
         }} for i in range(count)
    ]}


@pytest.fixture
def schema():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    registry = Registry()
    for name in ("proofrun-review", "proofrun-plan-comparison"):
        source = json.loads(files("dspy_security_bench.schemas").joinpath(name + ".schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(source)
        registry = registry.with_resource(source["$id"], Resource.from_contents(source))
    return jsonschema.Draft202012Validator(source, registry=registry)


@pytest.fixture(autouse=True)
def never_review_artifacts(monkeypatch):
    def fail(*a, **k):
        pytest.fail("plan comparison attempted artifact verification or network access")
    monkeypatch.setattr(collection, "_entry_path", fail)
    monkeypatch.setattr(collection, "review_bundle_bytes", fail)
    monkeypatch.setattr(reviews, "verify_github_attestation", fail)


def compare(tmp_path, before, after, schema):
    left, right = tmp_path / "PRIVATE-baseline.json", tmp_path / "PRIVATE-candidate.json"
    left.write_bytes(json.dumps(before).encode())
    right.write_bytes(json.dumps(after).encode())
    result = diff.compare_plans(left, right, expected_baseline_file_sha256=digest(left.read_bytes()))
    check(result, schema)
    return result


def check(result, schema):
    schema.validate(result)
    assert "private" not in json.dumps(result).lower()
    assert "private" not in diff.render_plan_comparison(result).lower()
    assert not result["comparison_is_approval"] and not result["artifact_evidence_verified"]
    assert not result["requirements_completeness_established"]
    assert sum(result["summary"].values()) == len(result["entries"])
    for status, count in result["summary"].items():
        assert count == sum(row["status"] == status for row in result["entries"])


def test_identical_plans_do_not_claim_to_have_verified_missing_artifacts(tmp_path, schema):
    result = compare(tmp_path, plan(), plan(), schema)
    assert result["exit_code"] == 0 and result["reason_code"] == "unchanged"
    assert result["summary"] == {"added": 0, "removed": 0, "modified": 0, "unchanged": 2}
    assert result["baseline_file_sha256"] == result["candidate_file_sha256"]
    assert all(row["before"] == row["after"] for row in result["entries"])


@pytest.mark.parametrize("field,value", [
    ("path", "new-private.json"), ("file_sha256", "0" * 64),
    ("bundle_type", list(reviews.FAMILIES)[1]),
    ("policy.minimum_trials", 2), ("policy.minimum_trials", 10),
    ("policy.attestation_repository", None), ("policy.attestation_repository", "PRIVATE/new"),
    ("policy.require_trusted_builder", False), ("policy.allow_self_hosted_runner", True),
])
def test_every_changed_requirement_requires_review_not_a_safety_ranking(tmp_path, schema, field, value):
    before, after = plan(), plan()
    target = after["entries"][0]
    if field.startswith("policy."):
        target["policy"][field.split(".")[1]] = value
    else:
        target[field] = value
    result = compare(tmp_path, before, after, schema)
    assert result["exit_code"] == 1 and result["reason_code"] == "requirements_changed"
    assert result["entries"][0]["changed_fields"] == [field]
    assert result["summary"]["modified"] == result["summary"]["unchanged"] == 1


def test_switch_to_offline_exposes_all_policy_changes(tmp_path, schema):
    before, after = plan(), plan()
    after["entries"][0]["policy"].update(offline=True, require_trusted_builder=False)
    result = compare(tmp_path, before, after, schema)
    assert result["entries"][0]["changed_fields"] == ["policy.offline", "policy.require_trusted_builder"]
    assert result["entries"][0]["before"]["policy"]["mode"] == "online"
    assert result["entries"][0]["after"]["policy"]["mode"] == "offline"


def test_family_protocol_change_is_visible_and_must_still_be_valid(tmp_path, schema):
    before, after = plan(), plan()
    after["entries"][0]["bundle_type"] = next(iter(reviews.STRUCTURAL_FAMILIES))
    result = compare(tmp_path, before, after, schema)
    assert result["reason_code"] == "invalid_candidate"
    after["entries"][0]["policy"]["minimum_trials"] = None
    result = compare(tmp_path, before, after, schema)
    assert result["entries"][0]["changed_fields"] == ["bundle_type", "policy.minimum_trials"]


def test_reordering_is_a_change_because_budgets_apply_in_plan_order(tmp_path, schema):
    before, after = plan(), plan()
    after["entries"].reverse()
    result = compare(tmp_path, before, after, schema)
    assert result["summary"]["modified"] == 2
    assert all(row["changed_fields"] == ["position"] for row in result["entries"])


def test_renames_are_removal_plus_addition_not_inferred_identity(tmp_path, schema):
    before, after = plan(), plan()
    after["entries"][0]["id"] = "renamed-private"
    result = compare(tmp_path, before, after, schema)
    assert result["summary"] == {"added": 1, "removed": 1, "modified": 0, "unchanged": 1}
    assert [r["status"] for r in result["entries"]] == ["removed", "unchanged", "added"]


def test_maximum_disjoint_plans_preserve_all_fifty_slots(tmp_path, schema):
    result = compare(tmp_path, plan("private-old", 25), plan("private-new", 25), schema)
    assert result["summary"] == {"added": 25, "removed": 25, "modified": 0, "unchanged": 0}
    assert len(result["entries"]) == 50


def test_format_only_changes_still_need_a_new_owner_pin(tmp_path, schema):
    source = plan()
    left, right = tmp_path / "before.json", tmp_path / "after.json"
    left.write_bytes(json.dumps(source).encode())
    right.write_bytes(json.dumps(source, sort_keys=True, indent=2).encode() + b"\r\n")
    result = diff.compare_plans(left, right, expected_baseline_file_sha256=digest(left.read_bytes()))
    check(result, schema)
    assert result["exit_code"] == 1 and result["reason_code"] == "format_only"
    assert result["summary"]["unchanged"] == 2
    assert result["candidate_file_sha256"] != result["baseline_file_sha256"]


@pytest.mark.parametrize("pin", [None, True, 1, "PRIVATE", "A" * 64, "a" * 63])
def test_invalid_baseline_pin_prevents_all_file_reads(pin, monkeypatch, schema):
    monkeypatch.setattr(diff, "read_json_snapshot", lambda *a: pytest.fail("invalid pin read a file"))
    result = diff.compare_plans("PRIVATE", "PRIVATE", expected_baseline_file_sha256=pin)
    check(result, schema)
    assert result["reason_code"] == "invalid_policy"


def test_mismatched_baseline_prevents_candidate_read(tmp_path, schema, monkeypatch):
    left = tmp_path / "before.json"
    left.write_bytes(json.dumps(plan()).encode())
    original, reads = diff.read_json_snapshot, []
    def read(path, maximum):
        reads.append(path)
        return original(path, maximum)
    monkeypatch.setattr(diff, "read_json_snapshot", read)
    result = diff.compare_plans(left, "PRIVATE-missing", expected_baseline_file_sha256="0" * 64)
    check(result, schema)
    assert result["reason_code"] == "baseline_pin_mismatch" and reads == [left]


@pytest.mark.parametrize("side", ["baseline", "candidate"])
@pytest.mark.parametrize("raw", [b'{}', b'[]', b'{"PRIVATE":1,"PRIVATE":2}', b'NaN', b'{"PRIVATE":"\xff"}'])
def test_bad_plans_return_redacted_invalid_decisions(tmp_path, schema, side, raw):
    left, right = tmp_path / "before.json", tmp_path / "after.json"
    left.write_bytes(raw if side == "baseline" else json.dumps(plan()).encode())
    right.write_bytes(raw if side == "candidate" else json.dumps(plan()).encode())
    result = diff.compare_plans(left, right, expected_baseline_file_sha256=digest(left.read_bytes()))
    check(result, schema)
    assert result["reason_code"] == "invalid_" + side and result["entries"] == []


def test_byte_budget_uses_shared_bounded_intake(tmp_path, schema, monkeypatch):
    monkeypatch.setattr(diff, "MAX_PLAN_BYTES", 50)
    result = compare(tmp_path, plan(), plan(), schema)
    assert result["reason_code"] == "invalid_baseline"


@pytest.mark.parametrize("change", ["duplicate", "bool_version", "bad_path", "bad_policy", "extra_field"])
def test_existing_plan_validation_cannot_be_bypassed(tmp_path, schema, change):
    before, after = plan(), plan()
    if change == "duplicate":
        after["entries"].append(deepcopy(after["entries"][0]))
    elif change == "bool_version":
        after["schema_version"] = True
    elif change == "bad_path":
        after["entries"][0]["path"] = "../PRIVATE.json"
    elif change == "bad_policy":
        after["entries"][0]["policy"]["minimum_trials"] = True
    else:
        after["PRIVATE"] = "PRIVATE"
    assert compare(tmp_path, before, after, schema)["reason_code"] == "invalid_candidate"


@pytest.mark.parametrize("mode,code", [("same", 0), ("change", 1), ("bad", 2)])
def test_cli_preserves_json_exit_codes_and_source_redaction(tmp_path, schema, capsys, mode, code):
    left, right = tmp_path / "PRIVATE-before.json", tmp_path / "PRIVATE-after.json"
    left.write_bytes(json.dumps(plan()).encode())
    candidate = plan()
    if mode == "change":
        candidate["entries"][0]["policy"]["minimum_trials"] = 2
    right.write_bytes(b"{}" if mode == "bad" else json.dumps(candidate).encode())
    assert cli.main(["compare-plans", str(left), str(right), "--expected-baseline-file-sha256",
                     digest(left.read_bytes()), "--json"]) == code
    captured = capsys.readouterr()
    assert captured.err == ""
    check(json.loads(captured.out), schema)


def test_schema_rejects_approval_and_hidden_change_claims(tmp_path, schema):
    result = compare(tmp_path, plan(), plan(), schema)
    for field in ("comparison_is_approval", "artifact_evidence_verified", "requirements_completeness_established"):
        changed = deepcopy(result)
        changed[field] = True
        assert not schema.is_valid(changed)
    changed = deepcopy(result)
    changed["entries"][0]["status"] = "modified"
    changed["entries"][0]["changed_fields"] = ["path"]
    assert not schema.is_valid(changed)
