"""Recipients replay exact owner-pinned snapshots without sender-side paths."""

import json
import os
import stat
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_collection as collection
from dspy_security_bench import proofrun_review as reviews
from dspy_security_bench import proofrun_snapshot as snapshot
from tests import test_proofrun_collection as fixtures

healthy = fixtures.healthy
repeated = fixtures.repeated
structural = fixtures.structural
attested = fixtures.attested
digest = fixtures.digest


@pytest.fixture(scope="module")
def schema():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    registry = Registry()
    for name in ("proofrun-review", "proofrun-collection-snapshot"):
        source = json.loads(files("dspy_security_bench.schemas").joinpath(name + ".schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(source)
        registry = registry.with_resource(source["$id"], Resource.from_contents(source))
    return jsonschema.Draft202012Validator(source, registry=registry)


def check(receipt, schema):
    schema.validate(receipt)
    assert "private" not in json.dumps(receipt).lower()
    assert "private" not in snapshot.render_snapshot(receipt).lower()
    assert not any(receipt[key] for key in ("artifact_evidence_verified", "requirements_completeness_established",
                                           "snapshot_is_approval", "snapshot_is_redacted"))
    assert 0 <= receipt["written_entries"] <= receipt["observed_entries"] <= receipt["required_entries"]
    assert receipt["snapshot_complete"] == (receipt["exit_code"] == 0)


def run(path, output, schema, pin=None):
    receipt = snapshot.snapshot_collection(path, output, expected_plan_file_sha256=pin or digest(path.read_bytes()))
    check(receipt, schema)
    return receipt


def test_exact_full_content_handoff_survives_source_removal(healthy, tmp_path, schema, monkeypatch):
    path, plan = healthy
    first = plan["entries"][0]
    nested = tmp_path / "nested"
    nested.mkdir()
    original = tmp_path / first["path"]
    original.rename(nested / original.name)
    first["path"] = "nested/" + original.name
    # Whitespace is part of the pin; it must not be JSON-reserialized.
    plan_raw = (json.dumps(plan, ensure_ascii=False, indent=3) + "\r\n").encode()
    path.write_bytes(plan_raw)
    originals = {e["path"]: (tmp_path / e["path"]).read_bytes() for e in plan["entries"]}
    output = tmp_path / "transfer"
    with monkeypatch.context() as scoped:
        scoped.setattr(collection, "review_bundle_bytes", lambda *a, **k: pytest.fail("snapshot invoked native review"))
        scoped.setattr(reviews, "verify_github_attestation", lambda *a, **k: pytest.fail("snapshot invoked gh"))
        receipt = run(path, output, schema)
    assert receipt["exit_code"] == 0
    assert receipt["artifact_bytes"] == sum(map(len, originals.values()))
    assert receipt["required_entries"] == receipt["observed_entries"] == receipt["written_entries"] == 3
    assert (output / snapshot.PLAN_FILENAME).read_bytes() == plan_raw
    assert {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()} == {*originals, snapshot.PLAN_FILENAME}
    for relative, raw in originals.items():
        assert (output / relative).read_bytes() == raw
        (tmp_path / relative).unlink()
    path.unlink()
    recipient = collection.review_collection(output / snapshot.PLAN_FILENAME, expected_plan_file_sha256=digest(plan_raw))
    assert recipient["exit_code"] == 0 and recipient["summary"]["passed"] == 3
    assert b"private" in (output / snapshot.PLAN_FILENAME).read_bytes()
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert stat.S_IMODE((output / snapshot.PLAN_FILENAME).stat().st_mode) == 0o600


def test_every_repeated_family_retains_recipient_verdict(repeated, tmp_path, schema):
    family_roundtrip(repeated, tmp_path, schema)


def test_every_structural_family_retains_recipient_verdict(structural, tmp_path, schema):
    family_roundtrip(structural[1], tmp_path, schema)


def family_roundtrip(bundle, tmp_path, schema):
    path, _ = fixtures.save_plan(tmp_path, [fixtures.entry(tmp_path, bundle)])
    pin = digest(path.read_bytes())
    before = collection.review_collection(path, expected_plan_file_sha256=pin)
    output = tmp_path / "transfer"
    assert run(path, output, schema)["exit_code"] == 0
    assert collection.review_collection(output / snapshot.PLAN_FILENAME, expected_plan_file_sha256=pin) == before


@pytest.mark.parametrize("change,code", [("native", 2), ("online", 1)])
def test_snapshot_does_not_promote_adverse_evidence_or_change_policy(healthy, tmp_path, schema, change, code):
    path, plan = healthy
    entry = plan["entries"][0]
    if change == "native":
        source = tmp_path / entry["path"]
        bundle = json.loads(source.read_bytes())
        bundle["bundle_sha256"] = "0" * 64
        source.write_text(json.dumps(bundle), encoding="utf-8")
        entry["file_sha256"] = digest(source.read_bytes())
    else:
        entry["policy"]["offline"] = False
    path.write_text(json.dumps(plan), encoding="utf-8")
    output = tmp_path / "transfer"
    assert run(path, output, schema)["exit_code"] == 0
    recipient = collection.review_collection(output / snapshot.PLAN_FILENAME, expected_plan_file_sha256=digest(path.read_bytes()))
    assert recipient["exit_code"] == code and recipient["summary"]["passed"] == 2


def test_recipient_online_verification_consumes_original_attested_bytes(attested, tmp_path, schema, monkeypatch):
    from dspy_security_bench import proofrun as proof
    source, raw, bundle, certificate = attested
    policy = fixtures.policy(bundle["bundle_type"], offline=False)
    policy.update(minimum_trials=5, require_trusted_builder=True)
    path, _ = fixtures.save_plan(tmp_path, [{"id": "private", "path": source.name,
                                           "bundle_type": bundle["bundle_type"], "file_sha256": digest(raw), "policy": policy}])
    output = tmp_path / "out"
    monkeypatch.setattr(proof, "run_bounded", lambda *a, **k: pytest.fail("snapshot attempted online verification"))
    assert run(path, output, schema)["exit_code"] == 0
    source.unlink()
    calls = []

    def verify(command, **kwargs):
        calls.append(command)
        assert Path(command[3]).read_bytes() == raw
        return SimpleNamespace(returncode=0, stdout=json.dumps([certificate]).encode(), stderr=None)

    monkeypatch.setattr(proof, "run_bounded", verify)
    result = collection.review_collection(output / snapshot.PLAN_FILENAME,
                                          expected_plan_file_sha256=digest(path.read_bytes()))
    assert result["exit_code"] == 0 and len(calls) == 1
    assert result["entries"][0]["review"]["provenance"] == "verified"


@pytest.mark.parametrize("pin", [None, "", "PRIVATE", "A" * 64, True, 5])
def test_invalid_pin_precedes_all_io(tmp_path, schema, monkeypatch, pin):
    monkeypatch.setattr(snapshot, "_destination", lambda *a: pytest.fail("invalid pin touched output"))
    monkeypatch.setattr(snapshot, "read_regular_bytes", lambda *a: pytest.fail("invalid pin read input"))
    receipt = snapshot.snapshot_collection(tmp_path / "PRIVATE", tmp_path / "out", expected_plan_file_sha256=pin)
    check(receipt, schema)
    assert receipt["reason_code"] == "invalid_policy"


def test_wrong_plan_pin_precedes_artifact_reads(healthy, tmp_path, schema, monkeypatch):
    path, _ = healthy
    monkeypatch.setattr(snapshot, "_entry_path", lambda *a: pytest.fail("mismatched plan read artifact"))
    output = tmp_path / "transfer"
    assert run(path, output, schema, "0" * 64)["reason_code"] == "plan_pin_mismatch"
    assert not output.exists()


@pytest.mark.parametrize("raw", [b"{}", b'{"private":1,"private":2}', b'{"private":NaN}', b'[]', b'\xff'])
def test_invalid_plan_leaves_no_output(tmp_path, schema, monkeypatch, raw):
    path = tmp_path / "PRIVATE.json"
    path.write_bytes(raw)
    monkeypatch.setattr(snapshot, "_entry_path", lambda *a: pytest.fail("invalid plan read artifact"))
    assert run(path, tmp_path / "out", schema)["reason_code"] == "invalid_plan"
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("paths", [
    ["collection-plan.json"], ["COLLECTION-PLAN.json"], ["collection-plan.json/a.json"],
    ["a.json", "a.json/b.json"], ["A.json/c.json", "a.json"],
    ["folder/a.json", "FOLDER/b.json"], ["a/b/c.json", "a/B/d.json"],
])
def test_output_namespace_conflicts_reject_before_artifacts(healthy, tmp_path, schema, monkeypatch, paths):
    path, plan = healthy
    plan["entries"] = plan["entries"][:len(paths)]
    for entry, relative in zip(plan["entries"], paths, strict=True):
        entry["path"] = relative
    path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(snapshot, "_entry_path", lambda *a: pytest.fail("conflicting plan read artifact"))
    assert run(path, tmp_path / "out", schema)["reason_code"] == "path_conflict"
    assert not (tmp_path / "out").exists()


def test_shared_parent_paths_with_consistent_casing_are_portable(healthy, tmp_path, schema):
    path, plan = healthy
    (tmp_path / "Nested").mkdir()
    for entry in plan["entries"]:
        old = tmp_path / entry["path"]
        old.rename(tmp_path / "Nested" / old.name)
        entry["path"] = "Nested/" + old.name
    path.write_text(json.dumps(plan), encoding="utf-8")
    output = tmp_path / "out"
    assert run(path, output, schema)["exit_code"] == 0
    assert collection.review_collection(output / snapshot.PLAN_FILENAME,
                                        expected_plan_file_sha256=digest(path.read_bytes()))["exit_code"] == 0


@pytest.mark.parametrize("problem,reason", [("missing", "invalid_artifact"), ("directory", "invalid_artifact"),
                                         ("json", "invalid_artifact"), ("type", "bundle_type_mismatch"),
                                         ("pin", "artifact_pin_mismatch")])
def test_missing_or_changed_required_input_never_produces_partial_snapshot(healthy, tmp_path, schema, problem, reason):
    path, plan = healthy
    entry = plan["entries"][1]
    source = tmp_path / entry["path"]
    if problem in {"missing", "directory"}:
        source.unlink()
        if problem == "directory":
            source.mkdir()
    else:
        source.write_bytes(b'{"PRIVATE":NaN}' if problem == "json" else b'{"bundle_type":"PRIVATE"}')
        if problem != "pin":
            entry["file_sha256"] = digest(source.read_bytes())
            path.write_text(json.dumps(plan), encoding="utf-8")
    receipt = run(path, tmp_path / "out", schema)
    assert receipt["reason_code"] == reason and receipt["failed_entry_index"] == 1
    assert receipt["observed_entries"] == 1 and receipt["written_entries"] == 0
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("kind", ["file", "directory", "missing_parent"])
def test_invalid_destinations_reject_before_input(healthy, tmp_path, schema, monkeypatch, kind):
    path, _ = healthy
    output = tmp_path / "out"
    if kind == "file":
        output.write_bytes(b"KEEP")
    elif kind == "directory":
        output.mkdir()
        (output / "keep.txt").write_bytes(b"KEEP")
    else:
        output = output / "missing"
    monkeypatch.setattr(snapshot, "read_regular_bytes", lambda *a: pytest.fail("invalid destination read input"))
    assert run(path, output, schema)["reason_code"] == "invalid_output"
    if kind == "file":
        assert output.read_bytes() == b"KEEP"
    elif kind == "directory":
        assert (output / "keep.txt").read_bytes() == b"KEEP"


@pytest.mark.parametrize("where", ["source", "source_parent", "destination", "destination_parent"])
def test_links_are_not_followed(healthy, tmp_path, schema, where):
    path, plan = healthy
    output = tmp_path / "out"
    try:
        if where == "source":
            source = tmp_path / plan["entries"][0]["path"]
            source.rename(tmp_path / "original.json")
            source.symlink_to(tmp_path / "original.json")
        elif where == "source_parent":
            (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
            plan["entries"][0]["path"] = "linked/" + plan["entries"][0]["path"]
            path.write_text(json.dumps(plan), encoding="utf-8")
        elif where == "destination":
            output.symlink_to(tmp_path / "missing", target_is_directory=True)
        else:
            (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
            output = tmp_path / "linked" / "out"
    except OSError:
        pytest.skip("symlink creation unavailable")
    result = run(path, output, schema)
    assert result["reason_code"] == ("invalid_artifact" if where.startswith("source") else "invalid_output")


@pytest.mark.parametrize("budget", ["plan", "file", "total"])
def test_byte_budgets_bound_snapshot_intake(healthy, tmp_path, schema, monkeypatch, budget):
    path, plan = healthy
    length = len((tmp_path / plan["entries"][0]["path"]).read_bytes())
    key, limit = {"plan": ("MAX_PLAN_BYTES", len(path.read_bytes()) - 1), "file": ("MAX_BUNDLE_BYTES", length - 1),
                  "total": ("MAX_TOTAL_BYTES", length)}[budget]
    monkeypatch.setattr(snapshot, key, limit)
    result = run(path, tmp_path / "out", schema)
    assert result["reason_code"] == ("invalid_plan" if budget == "plan" else "byte_budget_exceeded")
    assert not (tmp_path / "out").exists()


def test_pinned_bytes_are_read_once_and_survive_later_source_mutation(healthy, tmp_path, schema, monkeypatch):
    path, plan = healthy
    original = snapshot.read_regular_bytes
    reads = []

    def read_once(source, maximum):
        assert source not in reads
        reads.append(source)
        raw = original(source, maximum)
        source.write_bytes(b"CHANGED AFTER SNAPSHOT")
        return raw

    pin = digest(path.read_bytes())
    monkeypatch.setattr(snapshot, "read_regular_bytes", read_once)
    output = tmp_path / "out"
    assert run(path, output, schema, pin)["exit_code"] == 0
    assert len(reads) == 4
    assert collection.review_collection(output / snapshot.PLAN_FILENAME, expected_plan_file_sha256=pin)["exit_code"] == 0


@pytest.mark.parametrize("at", [0, 1, 3])
def test_io_failure_leaves_explicit_incomplete_snapshot_and_publishes_plan_last(healthy, tmp_path, schema, monkeypatch, at):
    path, _ = healthy
    original = snapshot._write_new
    writes = []

    def fail(destination, raw):
        writes.append(destination.name)
        if len(writes) == at + 1:
            raise OSError("PRIVATE storage failure")
        original(destination, raw)

    monkeypatch.setattr(snapshot, "_write_new", fail)
    output = tmp_path / "out"
    result = run(path, output, schema)
    assert result["reason_code"] == "output_error" and not result["snapshot_complete"]
    assert result["written_entries"] == at
    assert not (output / snapshot.PLAN_FILENAME).exists()
    assert result["failed_entry_index"] == (at if at < 3 else None)
    if at == 3:
        assert writes[-1] == snapshot.PLAN_FILENAME


def test_destination_race_does_not_overwrite_existing_directory(healthy, tmp_path, schema, monkeypatch):
    path, _ = healthy
    output = tmp_path / "out"
    original = snapshot._destination
    calls = []

    def race(destination):
        calls.append(destination)
        if len(calls) == 2:
            output.mkdir()
            (output / "keep.txt").write_bytes(b"KEEP")
        return original(destination)

    monkeypatch.setattr(snapshot, "_destination", race)
    assert run(path, output, schema)["reason_code"] == "output_error"
    assert list(output.iterdir()) == [output / "keep.txt"]
    assert (output / "keep.txt").read_bytes() == b"KEEP"


def test_windows_reparse_parent_is_rejected(healthy, tmp_path, schema, monkeypatch):
    path, _ = healthy
    original = Path.lstat
    flag = 1024
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", flag, raising=False)

    def lstat(source, *args, **kwargs):
        info = original(source, *args, **kwargs)
        if source == tmp_path:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=flag)
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    assert run(path, tmp_path / "out", schema)["reason_code"] == "invalid_output"


@pytest.mark.parametrize("machine", [True, False])
def test_cli_preserves_exit_and_redacted_diagnostics(healthy, tmp_path, capsys, machine):
    path, _ = healthy
    args = ["snapshot-collection", str(path), "--out", str(tmp_path / "out"),
            "--expected-plan-file-sha256", digest(path.read_bytes()), *(["--json"] if machine else [])]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert "private" not in captured.out.lower() and captured.err == ""
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    assert "private" not in (captured.out + captured.err).lower()
    assert bool(captured.out) == machine and bool(captured.err) != machine


def test_cli_requires_independent_plan_pin():
    with pytest.raises(SystemExit) as error:
        cli.main(["snapshot-collection", "unused.json", "--out", "out"])
    assert error.value.code == 2


@pytest.mark.parametrize("change", ["policy", "duplicate", "traversal", "unknown", "bool", "empty", "count"])
def test_entire_plan_admission_precedes_artifact_reads(healthy, tmp_path, schema, monkeypatch, change):
    path, plan = healthy
    if change == "policy":
        plan["entries"][-1]["policy"]["offline"] = "PRIVATE"
    elif change == "duplicate":
        plan["entries"][-1]["file_sha256"] = plan["entries"][0]["file_sha256"]
    elif change == "traversal":
        plan["entries"][-1]["path"] = "../PRIVATE.json"
    elif change == "unknown":
        plan["entries"][-1]["PRIVATE"] = True
    elif change == "bool":
        plan["schema_version"] = True
    elif change == "empty":
        plan["entries"] = []
    else:
        plan["entries"] *= 9
    path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(snapshot, "_entry_path", lambda *a: pytest.fail("invalid plan read artifact"))
    assert run(path, tmp_path / "out", schema)["reason_code"] == "invalid_plan"
    assert not (tmp_path / "out").exists()


def test_partial_plan_write_is_not_reported_as_complete(healthy, tmp_path, schema, monkeypatch):
    path, _ = healthy
    original = snapshot._write_new

    def fail(destination, raw):
        if destination.name == snapshot.PLAN_FILENAME:
            original(destination, raw[:10])
            raise OSError("PRIVATE write interrupted")
        original(destination, raw)

    monkeypatch.setattr(snapshot, "_write_new", fail)
    output = tmp_path / "out"
    receipt = run(path, output, schema)
    assert receipt["reason_code"] == "output_error" and receipt["written_entries"] == 3
    assert (output / snapshot.PLAN_FILENAME).read_bytes() == path.read_bytes()[:10]
    assert collection.review_collection(output / snapshot.PLAN_FILENAME,
                                        expected_plan_file_sha256=digest(path.read_bytes()))["exit_code"] == 2


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes")
def test_named_pipe_is_rejected_without_opening_it(healthy, tmp_path, schema):
    path, plan = healthy
    source = tmp_path / plan["entries"][0]["path"]
    source.unlink()
    os.mkfifo(source)
    assert run(path, tmp_path / "out", schema)["reason_code"] == "invalid_artifact"


def test_exclusive_file_creation_rejects_existing_and_dangling_links(tmp_path):
    target = tmp_path / "KEEP.json"
    target.write_bytes(b"KEEP")
    with pytest.raises(FileExistsError):
        snapshot._write_new(target, b"CHANGE")
    assert target.read_bytes() == b"KEEP"
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(tmp_path / "absent.json")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(FileExistsError):
        snapshot._write_new(linked, b"CHANGE")
    assert not (tmp_path / "absent.json").exists()
