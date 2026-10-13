"""Required collections cannot silently omit, substitute, or promote evidence."""

import hashlib
import json
import os
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_collection as collection
from dspy_security_bench import proofrun_review as reviews
from tests import test_proofrun_verification_intake as repeated_fixtures
from tests import test_public_submission_metadata as structural_fixtures

repeated = repeated_fixtures.family
structural = structural_fixtures.family
attested = repeated_fixtures.attested


@pytest.fixture(scope="module")
def schemas():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    sources = {}
    registry = Registry()
    for name in ("proofrun-review", "proofrun-collection-plan", "proofrun-collection-review"):
        source = json.loads(files("dspy_security_bench.schemas").joinpath(name + ".schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(source)
        registry = registry.with_resource(source["$id"], Resource.from_contents(source))
        sources[name] = source
    return {name: jsonschema.Draft202012Validator(source, registry=registry) for name, source in sources.items()}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def policy(bundle_type, *, offline=True):
    return {
        "minimum_trials": None if bundle_type in reviews.STRUCTURAL_FAMILIES else 2,
        "offline": offline, "attestation_repository": None,
        "require_trusted_builder": False, "allow_self_hosted_runner": False,
    }


def entry(tmp_path, bundle, *, name="private-a", offline=True):
    raw = json.dumps(bundle, indent=2).encode()
    (tmp_path / f"{name}.json").write_bytes(raw)
    return {"id": name, "path": f"{name}.json", "bundle_type": bundle["bundle_type"],
            "file_sha256": digest(raw), "policy": policy(bundle["bundle_type"], offline=offline)}


def save_plan(tmp_path, entries):
    plan = {"schema_version": 1, "plan_type": collection.PLAN_TYPE, "entries": entries}
    path = tmp_path / "private-plan.json"
    path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return path, plan


@pytest.fixture
def healthy(tmp_path):
    from dspy_security_bench.collective.registry import build_collective_submission_bundle
    from dspy_security_bench.collective.v2 import built_in_scenario_v2
    entries = []
    for name in ("private-a", "private-b", "private-c"):
        bundle = build_collective_submission_bundle(
            built_in_scenario_v2("hardened-complete"), submitter=name, runtime="synthetic",
            source_repository="https://example.com/private", deployment_class="synthetic",
        )
        entries.append(entry(tmp_path, bundle, name=name))
    return save_plan(tmp_path, entries)


def check(result, schemas):
    schemas["proofrun-collection-review"].validate(result)
    encoded = json.dumps(result)
    assert "private" not in encoded.lower()
    assert not result["review_is_attestation"] and not result["execution_reproduced"] and not result["requirements_completeness_established"]
    summary = result["summary"]
    assert summary["required"] == len(result["entries"])
    assert summary["reviewed"] == sum(row["review"] is not None for row in result["entries"])
    assert summary["required"] == summary["passed"] + summary["not_passed"] + summary["invalid"]
    for index, row in enumerate(result["entries"]):
        assert row["index"] == index
        if row["review"] is not None:
            assert row["review"]["input_file_sha256"] == row["input_file_sha256"] == row["expected_file_sha256"]
            assert row["review"]["bundle_type"] == row["expected_bundle_type"]


def test_mixed_collection_preserves_each_native_policy(repeated, structural, tmp_path, schemas, monkeypatch):
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("offline collection reached gh"))
    path, plan = save_plan(tmp_path, [entry(tmp_path, repeated), entry(tmp_path, structural[1], name="private-b")])
    schemas["proofrun-collection-plan"].validate(plan)
    pin = digest(path.read_bytes())
    result = collection.review_collection(path, expected_plan_file_sha256=pin)
    check(result, schemas)
    assert result["exit_code"] == 0 and result["summary"]["passed"] == 2
    assert result["plan_file_sha256"] == result["expected_plan_file_sha256"] == pin
    assert result["entries"][0]["review"]["policy"]["minimum_trials"] == 2
    assert result["entries"][1]["review"]["policy"]["minimum_trials"] is None
    assert result == collection.review_collection(str(path), expected_plan_file_sha256=pin)


@pytest.mark.parametrize("change", ["missing", "bytes", "type", "invalid_json", "native", "online"])
def test_one_bad_entry_cannot_hide_later_entries(healthy, change, tmp_path, schemas, monkeypatch, capsys):
    path, plan = healthy
    first = plan["entries"][0]
    source = tmp_path / first["path"]
    expected_status, code = "reviewed", 2
    if change == "missing":
        source.unlink()
        expected_status = "invalid_input"
    elif change == "bytes":
        source.write_bytes(source.read_bytes() + b"\n")
        expected_status = "pin_mismatch"
    elif change == "type":
        first["bundle_type"] = "dspy-security-bench-defense-evidence"
        expected_status = "bundle_type_mismatch"
    elif change == "invalid_json":
        source.write_bytes(b'{"private":1,"private":2}')
        first["file_sha256"] = digest(source.read_bytes())
        expected_status = "invalid_input"
    elif change == "native":
        bundle = json.loads(source.read_bytes())
        bundle["bundle_sha256"] = "0" * 64
        source.write_text(json.dumps(bundle), encoding="utf-8")
        first["file_sha256"] = digest(source.read_bytes())
    else:
        first["policy"]["offline"] = False
        code = 1
    path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("structural collection reached gh"))
    assert cli.main(["verify-collection", str(path), "--json"]) == code
    captured = capsys.readouterr()
    assert captured.err == "" and "private" not in captured.out
    result = json.loads(captured.out)
    check(result, schemas)
    assert result["entries"][0]["status"] == expected_status
    assert result["summary"]["passed"] == 2 and result["summary"]["required"] == 3
    assert all(row["review"]["exit_code"] == 0 for row in result["entries"][1:])


@pytest.mark.parametrize("change", [
    "empty", "count", "bool_version", "unknown", "duplicate_id", "duplicate_path", "duplicate_pin",
    "path_case", "bad_pin", "bad_policy", "wrong_policy", "missing_policy", "unknown_type", "untyped_flag",
])
def test_invalid_plan_fails_before_any_referenced_read(healthy, change, schemas, monkeypatch):
    path, plan = healthy
    first, second = plan["entries"][:2]
    if change == "empty":
        plan["entries"] = []
    elif change == "count":
        plan["entries"] *= 9
    elif change == "bool_version":
        plan["schema_version"] = True
    elif change == "unknown":
        first["private-field"] = "private-value"
    elif change in {"duplicate_id", "duplicate_path", "duplicate_pin"}:
        field = {"duplicate_id": "id", "duplicate_path": "path", "duplicate_pin": "file_sha256"}[change]
        second[field] = first[field]
    elif change == "path_case":
        second["path"] = first["path"].upper().replace(".JSON", ".json")
    elif change == "bad_pin":
        first["file_sha256"] = "private"
    elif change == "bad_policy":
        first["policy"]["require_trusted_builder"] = True
    elif change == "wrong_policy":
        first["policy"]["minimum_trials"] = 5
    elif change == "missing_policy":
        del first["policy"]["offline"]
    elif change == "unknown_type":
        first["bundle_type"] = "private"
    else:
        first["policy"]["offline"] = "false"
    path.write_text(json.dumps(plan), encoding="utf-8")
    reader = collection._read_regular
    reads = []

    def only_plan(source, maximum):
        reads.append(source)
        assert source == path
        return reader(source, maximum)

    monkeypatch.setattr(collection, "_read_regular", only_plan)
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["reason_code"] == "invalid_plan" and result["entries"] == []
    assert reads == [path]


@pytest.mark.parametrize("relative", ["../private.json", "/private.json", "file:///private.json", "https://example.com/private.json",
                                      "C:/private.json", "folder\\private.json", "a/../private.json", "./private.json",
                                      "a//private.json", "CON.json", "a./private.json", "a/private\x00.json"])
def test_unsafe_nonportable_paths_reject_plan(healthy, relative, schemas):
    path, plan = healthy
    plan["entries"][0]["path"] = relative
    path.write_text(json.dumps(plan), encoding="utf-8")
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["reason_code"] == "invalid_plan"


def test_plan_pin_precedes_entry_read_and_covers_whitespace(healthy, schemas, monkeypatch):
    path, _ = healthy
    pin = digest(path.read_bytes())
    path.write_bytes(path.read_bytes() + b"\n")
    monkeypatch.setattr(collection, "_entry_path", lambda *a: pytest.fail("plan pin mismatch read entry"))
    result = collection.review_collection(path, expected_plan_file_sha256=pin)
    check(result, schemas)
    assert result["reason_code"] == "plan_pin_mismatch" and result["entries"] == []


def test_invalid_pin_fails_before_read(schemas, monkeypatch):
    monkeypatch.setattr(collection, "_read_regular", lambda *a: pytest.fail("invalid pin read plan"))
    result = collection.review_collection("private", expected_plan_file_sha256="private")
    check(result, schemas)
    assert result["reason_code"] == "invalid_policy"


def test_plan_and_file_replacement_cannot_change_reviewed_snapshot(healthy, tmp_path, schemas, monkeypatch):
    path, plan = healthy
    original_pin = digest(path.read_bytes())
    review = collection.review_bundle_bytes
    calls = []

    def replace_then_review(raw, **kwargs):
        index = len(calls)
        calls.append(raw)
        (tmp_path / plan["entries"][index]["path"]).write_bytes(b'{"private":"replacement"}')
        path.write_bytes(b'{"private":"replacement-plan"}')
        return review(raw, **kwargs)

    monkeypatch.setattr(collection, "review_bundle_bytes", replace_then_review)
    result = collection.review_collection(path, expected_plan_file_sha256=original_pin)
    check(result, schemas)
    assert result["exit_code"] == 0 and len(calls) == 3
    assert [digest(raw) for raw in calls] == [e["file_sha256"] for e in plan["entries"]]
    assert result["plan_file_sha256"] == original_pin


def test_online_authentication_uses_the_pinned_exact_bytes(attested, tmp_path, schemas, monkeypatch):
    _, raw, bundle, certificate = attested
    path, plan = save_plan(tmp_path, [entry(tmp_path, bundle, offline=False)])
    expected = (tmp_path / plan["entries"][0]["path"]).read_bytes()
    import dspy_security_bench.proofrun as proof

    def gh(command, **kwargs):
        assert Path(command[3]).read_bytes() == expected == raw
        return SimpleNamespace(returncode=0, stdout=json.dumps([certificate]), stderr="private")

    monkeypatch.setattr(proof.subprocess, "run", gh)
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["exit_code"] == 0
    assert result["entries"][0]["review"]["provenance"] == "verified"


def test_byte_budget_records_unreviewed_entries_without_success(healthy, tmp_path, schemas, monkeypatch):
    path, plan = healthy
    first_bytes = (tmp_path / plan["entries"][0]["path"]).stat().st_size
    monkeypatch.setattr(collection, "MAX_TOTAL_BYTES", first_bytes)
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["exit_code"] == 2
    assert result["summary"] == {"required": 3, "reviewed": 1, "passed": 1, "not_passed": 0, "invalid": 2}
    assert [row["status"] for row in result["entries"]] == ["reviewed", "byte_budget_exceeded", "byte_budget_exceeded"]


def test_per_file_budget_is_not_an_aggregate_success(healthy, schemas, monkeypatch):
    monkeypatch.setattr(collection, "MAX_BUNDLE_BYTES", 10)
    result = collection.review_collection(healthy[0])
    check(result, schemas)
    assert result["summary"]["invalid"] == 3 and result["summary"]["reviewed"] == 0


@pytest.mark.parametrize("raw", [b"[]", b'{"private":1,"private":2}', b'{"private":NaN}', b'{"private":"\xff"}'])
def test_malformed_plans_are_bounded_redacted_failures(raw, tmp_path, schemas):
    path = tmp_path / "private.json"
    path.write_bytes(raw)
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["reason_code"] == "invalid_plan"


@pytest.mark.parametrize("location", ["file", "parent", "plan"])
def test_static_symlinks_are_rejected(healthy, tmp_path, location, schemas):
    path, plan = healthy
    try:
        if location == "file":
            link = tmp_path / "linked.json"
            link.symlink_to(tmp_path / plan["entries"][0]["path"])
            plan["entries"][0]["path"] = link.name
        elif location == "parent":
            (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
            plan["entries"][0]["path"] = "linked/" + plan["entries"][0]["path"]
        else:
            link = tmp_path / "linked-plan.json"
            link.symlink_to(path)
            result = collection.review_collection(link)
            check(result, schemas)
            assert result["reason_code"] == "invalid_plan"
            return
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error.errno}")
    path.write_text(json.dumps(plan), encoding="utf-8")
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["entries"][0]["status"] == "invalid_input"
    assert result["summary"]["passed"] == 2


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO only")
def test_fifo_rejected_before_open(tmp_path, monkeypatch):
    path = tmp_path / "private.json"
    os.mkfifo(path)
    monkeypatch.setattr(collection.os, "open", lambda *a: pytest.fail("FIFO was opened"))
    with pytest.raises(ValueError):
        collection._read_regular(path, 100)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO race only")
def test_fifo_replacement_at_open_is_nonblocking(tmp_path, monkeypatch):
    path = tmp_path / "private.json"
    path.write_bytes(b"{}")
    original = os.open

    def replace(source, flags):
        assert flags & os.O_NONBLOCK
        source.unlink()
        os.mkfifo(source)
        return original(source, flags)

    monkeypatch.setattr(collection.os, "open", replace)
    with pytest.raises(ValueError):
        collection._read_regular(path, 100)


@pytest.mark.parametrize("field", ["review_is_attestation", "execution_reproduced", "requirements_completeness_established"])
def test_schema_rejects_forged_collection_authority(healthy, field, schemas):
    result = collection.review_collection(healthy[0])
    check(result, schemas)
    result[field] = True
    assert list(schemas["proofrun-collection-review"].iter_errors(result))


def test_bytes_api_cannot_bypass_strict_intake_or_policy(schemas):
    for raw in (b"[]", b'{"private":1,"private":2}', b'{"private":NaN}'):
        result = reviews.review_bundle_bytes(raw)
        schemas["proofrun-review"].validate(result)
        assert result["reason_code"] == "invalid_input"
    result = reviews.review_bundle_bytes(b"{}", policy=reviews.ReviewPolicy(minimum_trials=True))
    schemas["proofrun-review"].validate(result)
    assert result["reason_code"] == "invalid_policy"


def test_repeated_trial_shortfall_remains_an_unmet_requirement(repeated, tmp_path, schemas):
    required = entry(tmp_path, repeated)
    required["policy"]["minimum_trials"] = 5
    path, _ = save_plan(tmp_path, [required])
    result = collection.review_collection(path)
    check(result, schemas)
    assert result["exit_code"] == 1
    assert result["summary"] == {"required": 1, "reviewed": 1, "passed": 0, "not_passed": 1, "invalid": 0}
    assert result["entries"][0]["review"]["reason_code"] == "not_eligible"


def test_plan_size_bound_precedes_reference_reads(healthy, schemas, monkeypatch):
    monkeypatch.setattr(collection, "MAX_PLAN_BYTES", 16)
    monkeypatch.setattr(collection, "_entry_path", lambda *a: pytest.fail("oversized plan read entry"))
    result = collection.review_collection(healthy[0])
    check(result, schemas)
    assert result["reason_code"] == "invalid_plan" and result["plan_file_sha256"] is None


def test_partial_read_error_is_charged_conservatively(healthy, schemas, monkeypatch):
    path, plan = healthy
    reader = collection._read_regular
    monkeypatch.setattr(collection, "MAX_TOTAL_BYTES", collection.MAX_BUNDLE_BYTES)

    def failed_read(source, maximum):
        if source.name == plan["entries"][0]["path"]:
            raise OSError("private read error after unknown partial consumption")
        return reader(source, maximum)

    monkeypatch.setattr(collection, "_read_regular", failed_read)
    result = collection.review_collection(path)
    check(result, schemas)
    assert [row["status"] for row in result["entries"]] == ["invalid_input", "byte_budget_exceeded", "byte_budget_exceeded"]


def test_schema_rejects_success_with_unreviewed_required_input(healthy, schemas):
    path, plan = healthy
    (path.parent / plan["entries"][0]["path"]).unlink()
    result = collection.review_collection(path)
    check(result, schemas)
    result.update(exit_code=0, verdict="pass")
    result["summary"].update(invalid=0, passed=3)
    assert list(schemas["proofrun-collection-review"].iter_errors(result))
