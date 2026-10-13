"""Plan preparation preserves owner choices and never approves observed evidence."""

import hashlib
import json
import stat
from copy import deepcopy
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_collection as collection
from dspy_security_bench import proofrun_prepare as prep
from dspy_security_bench import proofrun_review as reviews
from tests import test_proofrun_collection as collection_fixtures

healthy = collection_fixtures.healthy
policy = collection_fixtures.policy


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(scope="module")
def schemas():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    registry, sources = Registry(), {}
    for name in ("proofrun-review", "proofrun-collection-plan", "proofrun-collection-requirements", "proofrun-plan-preparation"):
        source = json.loads(files("dspy_security_bench.schemas").joinpath(name + ".schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(source)
        registry = registry.with_resource(source["$id"], Resource.from_contents(source))
        sources[name] = source
    return {name: jsonschema.Draft202012Validator(source, registry=registry) for name, source in sources.items()}


def save(tmp_path, requirements):
    source = tmp_path / "PRIVATE-requirements.json"
    source.write_bytes(json.dumps(requirements).encode())
    return source


def fixture(tmp_path, types=None):
    types = types or [next(iter(reviews.FAMILIES))] * 2
    entries = []
    for i, family in enumerate(types):
        name = f"private-{i}"
        entries.append({"id": name, "path": name + ".json", "bundle_type": family, "policy": policy(family)})
        # Deliberately not native-valid evidence: preparing byte pins must not
        # imply semantic verification or hide this later failure.
        raw = json.dumps({"bundle_type": family, "PRIVATE": name}).encode()
        (tmp_path / (name + ".json")).write_bytes(raw)
    requirements = {"schema_version": 1, "requirements_type": prep.REQUIREMENTS_TYPE, "entries": entries}
    return save(tmp_path, requirements), requirements


def check(plan, receipt, schemas):
    schemas["proofrun-plan-preparation"].validate(receipt)
    assert "private" not in json.dumps(receipt).lower()
    assert "private" not in prep.render_preparation(receipt).lower()
    assert not receipt["plan_is_approved"] and not receipt["artifact_evidence_verified"]
    assert not receipt["requirements_completeness_established"]
    assert 0 <= receipt["observed_entries"] <= receipt["required_entries"]
    if plan is None:
        assert receipt["exit_code"] == 2 and receipt["plan_file_sha256"] is None
    else:
        assert receipt["exit_code"] == 0
        schemas["proofrun-collection-plan"].validate(plan)
        collection.validate_plan(plan)
        assert receipt["plan_file_sha256"] == digest(prep.encode_plan(plan))
        assert receipt["required_entries"] == receipt["observed_entries"] == len(plan["entries"])


@pytest.mark.parametrize("family", list(reviews.ALL_FAMILIES))
def test_explicit_policies_are_preserved_for_every_family_without_native_verification(tmp_path, schemas, monkeypatch, family):
    source, requirements = fixture(tmp_path, [family])
    schemas["proofrun-collection-requirements"].validate(requirements)
    monkeypatch.setattr(reviews, "review_bundle_bytes", lambda *a, **k: pytest.fail("preparation verified evidence"))
    monkeypatch.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("preparation contacted GitHub"))
    pin = digest(source.read_bytes())
    plan, receipt = prep.prepare_plan(source, expected_requirements_file_sha256=pin)
    check(plan, receipt, schemas)
    assert receipt["requirements_file_sha256"] == receipt["expected_requirements_file_sha256"] == pin
    assert {k: v for k, v in plan["entries"][0].items() if k != "file_sha256"} == requirements["entries"][0]
    assert plan["entries"][0]["file_sha256"] == digest((tmp_path / requirements["entries"][0]["path"]).read_bytes())
    assert prep.prepare_plan(str(source), expected_requirements_file_sha256=pin) == (plan, receipt)


def test_prepared_draft_round_trips_through_actual_collection_verification(healthy, tmp_path, schemas):
    _, original = healthy
    requirements = {"schema_version": 1, "requirements_type": prep.REQUIREMENTS_TYPE,
                    "entries": [{k: v for k, v in entry.items() if k != "file_sha256"} for entry in original["entries"]]}
    source, output = save(tmp_path, requirements), tmp_path / "draft.json"
    receipt = prep.prepare_plan_file(source, output)
    plan = json.loads(output.read_bytes())
    check(plan, receipt, schemas)
    assert plan == original
    result = collection.review_collection(output, expected_plan_file_sha256=receipt["plan_file_sha256"])
    assert result["exit_code"] == 0 and result["summary"]["passed"] == 3


def test_preparation_success_does_not_promote_invalid_native_evidence(tmp_path, schemas):
    source, _ = fixture(tmp_path)
    output = tmp_path / "draft.json"
    receipt = prep.prepare_plan_file(source, output)
    check(json.loads(output.read_bytes()), receipt, schemas)
    result = collection.review_collection(output, expected_plan_file_sha256=receipt["plan_file_sha256"])
    assert result["exit_code"] == 2 and result["summary"]["invalid"] == 2


@pytest.mark.parametrize("pin", [None, True, 1, "PRIVATE", "A" * 64])
def test_optional_pin_is_never_claimed_verified_when_absent_or_invalid(tmp_path, schemas, pin):
    source, _ = fixture(tmp_path)
    plan, receipt = prep.prepare_plan(source, expected_requirements_file_sha256=pin)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == ("prepared" if pin is None else "invalid_policy")
    assert receipt["expected_requirements_file_sha256"] is None


def test_wrong_requirement_pin_prevents_artifact_intake(tmp_path, schemas, monkeypatch):
    source, _ = fixture(tmp_path)
    monkeypatch.setattr(prep, "read_regular_bytes", lambda *a: pytest.fail("mismatched requirements read an artifact"))
    plan, receipt = prep.prepare_plan(source, expected_requirements_file_sha256="0" * 64)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == "requirements_pin_mismatch"


@pytest.mark.parametrize("change", ["empty", "unknown", "bool_version", "pre_pinned", "duplicate", "case_path", "traversal", "policy", "family"])
def test_entire_requirements_contract_is_admitted_before_artifacts(tmp_path, schemas, monkeypatch, change):
    _, requirements = fixture(tmp_path)
    if change == "empty":
        requirements["entries"] = []
    elif change == "unknown":
        requirements["PRIVATE"] = True
    elif change == "bool_version":
        requirements["schema_version"] = True
    elif change == "pre_pinned":
        requirements["entries"][1]["file_sha256"] = "0" * 64
    elif change == "duplicate":
        requirements["entries"][1]["id"] = requirements["entries"][0]["id"]
    elif change == "case_path":
        requirements["entries"][1]["path"] = "PRIVATE-0.json"
    elif change == "traversal":
        requirements["entries"][1]["path"] = "../PRIVATE.json"
    elif change == "policy":
        requirements["entries"][1]["policy"]["minimum_trials"] = True
    else:
        requirements["entries"][1]["bundle_type"] = "PRIVATE"
    source = save(tmp_path, requirements)
    monkeypatch.setattr(prep, "read_regular_bytes", lambda *a: pytest.fail("invalid requirements read an artifact"))
    plan, receipt = prep.prepare_plan(source)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == "invalid_requirements"


@pytest.mark.parametrize("problem,reason", [("missing", "invalid_artifact"), ("directory", "invalid_artifact"),
                                         ("json", "invalid_artifact"), ("type", "bundle_type_mismatch"),
                                         ("duplicate", "duplicate_artifact")])
def test_required_artifact_failure_never_returns_partial_plan(tmp_path, schemas, problem, reason):
    source, _ = fixture(tmp_path)
    second = tmp_path / "private-1.json"
    if problem in {"missing", "directory"}:
        second.unlink()
        if problem == "directory":
            second.mkdir()
    elif problem == "json":
        second.write_bytes(b'{"PRIVATE":1,"PRIVATE":2}')
    elif problem == "type":
        second.write_bytes(b'{"bundle_type":"PRIVATE"}')
    else:
        second.write_bytes((tmp_path / "private-0.json").read_bytes())
    plan, receipt = prep.prepare_plan(source)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == reason and receipt["failed_entry_index"] == 1
    assert receipt["observed_entries"] == 1
    output = tmp_path / "draft.json"
    assert prep.prepare_plan_file(source, output)["exit_code"] == 2
    assert not output.exists()


@pytest.mark.parametrize("budget", ["file", "total"])
def test_byte_limits_prevent_partial_drafts(tmp_path, schemas, monkeypatch, budget):
    source, _ = fixture(tmp_path)
    length = len((tmp_path / "private-0.json").read_bytes())
    monkeypatch.setattr(prep, "MAX_BUNDLE_BYTES" if budget == "file" else "MAX_TOTAL_BYTES", length - 1 if budget == "file" else length)
    plan, receipt = prep.prepare_plan(source)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == "byte_budget_exceeded"
    assert receipt["failed_entry_index"] == (0 if budget == "file" else 1)


def test_encoded_draft_budget_is_checked_before_artifact_reads(tmp_path, schemas, monkeypatch):
    source, requirements = fixture(tmp_path)
    # The unpinned compact requirements fit, but the indented pinned draft does not.
    monkeypatch.setattr(prep, "MAX_PLAN_BYTES", len(source.read_bytes()) + 1)
    monkeypatch.setattr(prep, "read_regular_bytes", lambda *a: pytest.fail("oversized draft read an artifact"))
    plan, receipt = prep.prepare_plan(source)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == "invalid_requirements"


@pytest.mark.parametrize("kind", ["existing", "same_input", "elsewhere", "missing_parent", "bad_name"])
def test_output_preflight_prevents_intake_and_preserves_existing_files(tmp_path, schemas, monkeypatch, kind):
    source, _ = fixture(tmp_path)
    output = tmp_path / "draft.json"
    if kind == "existing":
        output.write_bytes(b"KEEP")
    elif kind == "same_input":
        output = source
    elif kind == "elsewhere":
        folder = tmp_path / "other"
        folder.mkdir()
        output = folder / "draft.json"
    elif kind == "missing_parent":
        output = tmp_path / "missing" / "draft.json"
    else:
        output = tmp_path / "PRIVATE.txt"
    original = source.read_bytes()
    monkeypatch.setattr(prep, "prepare_plan", lambda *a, **k: pytest.fail("invalid destination started preparation"))
    receipt = prep.prepare_plan_file(source, output)
    check(None, receipt, schemas)
    assert receipt["reason_code"] == "invalid_output"
    assert source.read_bytes() == original
    if kind == "existing":
        assert output.read_bytes() == b"KEEP"


def test_output_created_during_intake_is_not_overwritten(tmp_path, schemas, monkeypatch):
    source, _ = fixture(tmp_path)
    output = tmp_path / "draft.json"
    original = prep.prepare_plan
    def prepare(*a, **kw):
        result = original(*a, **kw)
        output.write_bytes(b"KEEP")
        return result
    monkeypatch.setattr(prep, "prepare_plan", prepare)
    receipt = prep.prepare_plan_file(source, output)
    check(None, receipt, schemas)
    assert receipt["reason_code"] == "output_error" and output.read_bytes() == b"KEEP"


def test_write_failure_reports_partial_new_file_without_a_success_pin(tmp_path, schemas, monkeypatch):
    source, _ = fixture(tmp_path)
    output = tmp_path / "draft.json"
    original = Path.open

    class BrokenWriter:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def write(self, raw):
            self.stream.write(raw[:10])
            raise OSError("PRIVATE")

    def open_file(path, *args, **kwargs):
        stream = original(path, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        return BrokenWriter(stream) if path == output and mode == "xb" else stream

    monkeypatch.setattr(Path, "open", open_file)
    receipt = prep.prepare_plan_file(source, output)
    check(None, receipt, schemas)
    assert receipt["reason_code"] == "output_error" and len(output.read_bytes()) == 10
    assert "partial" in prep.render_preparation(receipt)


def test_observed_windows_output_reparse_parent_is_rejected(tmp_path, schemas, monkeypatch):
    source, _ = fixture(tmp_path)
    original = Path.lstat
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024, raising=False)
    def metadata(path, *a, **kw):
        if path == tmp_path:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=1024)
        return original(path, *a, **kw)
    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(prep, "prepare_plan", lambda *a, **k: pytest.fail("reparse output reached input reads"))
    receipt = prep.prepare_plan_file(source, tmp_path / "draft.json")
    check(None, receipt, schemas)
    assert receipt["reason_code"] == "invalid_output"


def test_snapshot_hash_does_not_reopen_changed_artifacts(tmp_path, schemas, monkeypatch):
    source, requirements = fixture(tmp_path)
    original, observed = prep.read_regular_bytes, []
    def read(path, maximum):
        raw = original(path, maximum)
        observed.append(raw)
        path.write_bytes(b'{"replaced":true}')
        return raw
    monkeypatch.setattr(prep, "read_regular_bytes", read)
    plan, receipt = prep.prepare_plan(source)
    check(plan, receipt, schemas)
    assert [entry["file_sha256"] for entry in plan["entries"]] == [digest(raw) for raw in observed]
    assert all(entry["file_sha256"] != digest((tmp_path / entry["path"]).read_bytes()) for entry in plan["entries"])


def test_static_artifact_links_and_output_parent_links_are_rejected(tmp_path, schemas):
    source, _ = fixture(tmp_path)
    target, link = tmp_path / "private-1.json", tmp_path / "linked"
    target.unlink()
    try:
        target.symlink_to(tmp_path / "private-0.json")
        link.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    plan, receipt = prep.prepare_plan(source)
    check(plan, receipt, schemas)
    assert receipt["reason_code"] == "invalid_artifact"
    receipt = prep.prepare_plan_file(source, link / "draft.json")
    check(None, receipt, schemas)
    assert receipt["reason_code"] == "invalid_output"


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_writes_exact_bytes_but_emits_only_redacted_receipt(tmp_path, schemas, capsys, as_json):
    source, _ = fixture(tmp_path)
    output = tmp_path / "draft.json"
    options = ["--json"] if as_json else []
    assert cli.main(["prepare-plan", str(source), "--out", str(output), *options]) == 0
    captured = capsys.readouterr()
    assert "private" not in (captured.out + captured.err).lower()
    assert "private-0" in output.read_text(encoding="utf-8")
    if as_json:
        receipt = json.loads(captured.out)
        check(json.loads(output.read_bytes()), receipt, schemas)
        assert receipt["plan_file_sha256"] == digest(output.read_bytes())
    else:
        assert digest(output.read_bytes()) in captured.out
    before = output.read_bytes()
    assert cli.main(["prepare-plan", str(source), "--out", str(output), *options]) == 2
    assert output.read_bytes() == before


def test_receipt_schema_does_not_allow_approval_claims(tmp_path, schemas):
    source, _ = fixture(tmp_path)
    plan, receipt = prep.prepare_plan(source)
    for field in ("plan_is_approved", "artifact_evidence_verified", "requirements_completeness_established"):
        changed = deepcopy(receipt)
        changed[field] = True
        assert not schemas["proofrun-plan-preparation"].is_valid(changed)
