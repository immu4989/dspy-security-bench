"""All report formats must describe one fresh review, including failed reviews."""

import hashlib
import json
import os
import stat
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_reports as reports
from dspy_security_bench.proofrun_review import ReviewPolicy
from tests import test_proofrun_collection as fixtures

healthy = fixtures.healthy
repeated = fixtures.repeated
structural = fixtures.structural
attested = fixtures.attested
digest = fixtures.digest


@pytest.fixture(scope="module")
def schemas():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    registry, sources = Registry(), {}
    for name in ("proofrun-review", "proofrun-report-export", "proofrun-report-manifest"):
        source = json.loads(files("dspy_security_bench.schemas").joinpath(name + ".schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(source)
        registry = registry.with_resource(source["$id"], Resource.from_contents(source))
        sources[name] = source
    return {name: jsonschema.Draft202012Validator(source, registry=registry) for name, source in sources.items()}


def check(receipt, schemas):
    schemas["proofrun-report-export"].validate(receipt)
    assert "private" not in json.dumps(receipt).lower()
    assert not receipt["review_is_attestation"] and not receipt["execution_reproduced"]


def complete(output, receipt, schemas, *, code, entries):
    check(receipt, schemas)
    assert receipt["report_set_complete"] and receipt["reason_code"] == "exported"
    assert receipt["native_exit_code"] == receipt["exit_code"] == code
    assert {p.name for p in output.iterdir()} == {"review.json", "review.html", "review.xml", "manifest.json"}
    manifest = json.loads((output / "manifest.json").read_bytes())
    schemas["proofrun-report-manifest"].validate(manifest)
    assert manifest["native_exit_code"] == code
    assert receipt["manifest_file_sha256"] == digest((output / "manifest.json").read_bytes())
    for item in manifest["files"]:
        raw = (output / item["path"]).read_bytes()
        assert item["sha256"] == digest(raw) and item["size_bytes"] == len(raw)
        assert b"private" not in raw.lower()
    review = json.loads((output / "review.json").read_bytes())
    assert receipt["review_file_sha256"] == digest((output / "review.json").read_bytes())
    assert review["exit_code"] == code
    assert f"Native exit code {code}" in (output / "review.html").read_text(encoding="utf-8")
    suite = ET.parse(output / "review.xml").getroot().find("testsuite")
    assert int(suite.get("tests")) == entries
    assert suite.get("skipped") == "0"
    if code == 2:
        assert int(suite.get("errors")) >= 1
    elif code == 1:
        assert int(suite.get("failures")) >= 1
    return review


@pytest.mark.parametrize("outcome", [0, 1, 2])
def test_all_repeated_families_preserve_native_outcomes(repeated, outcome, tmp_path, schemas):
    single(repeated, 2, outcome, tmp_path, schemas)


@pytest.mark.parametrize("outcome", [0, 1, 2])
def test_all_structural_families_preserve_native_outcomes(structural, outcome, tmp_path, schemas):
    single(structural[1], None, outcome, tmp_path, schemas)


def single(bundle, minimum, outcome, tmp_path, schemas):
    path = tmp_path / "PRIVATE.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    policy = ReviewPolicy(minimum_trials=minimum, offline=outcome != 1,
                          expected_file_sha256="0" * 64 if outcome == 2 else None)
    output = tmp_path / "reports"
    receipt = reports.export_bundle_reports(path, output, policy=policy)
    complete(output, receipt, schemas, code=outcome, entries=1)
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in output.iterdir())


@pytest.mark.parametrize("problem,code,entries", [("none", 0, 3), ("online", 1, 3), ("missing", 2, 3),
                                                ("mixed", 2, 3), ("pin", 2, 1), ("invalid_plan", 2, 1)])
def test_collection_keeps_all_required_outcomes(healthy, tmp_path, schemas, problem, code, entries):
    path, plan = healthy
    pin = None
    if problem in {"missing", "mixed"}:
        (tmp_path / plan["entries"][0]["path"]).unlink()
    if problem in {"online", "mixed"}:
        plan["entries"][1]["policy"]["offline"] = False
        path.write_text(json.dumps(plan), encoding="utf-8")
    if problem == "pin":
        pin = "0" * 64
    elif problem == "invalid_plan":
        path.write_bytes(b"{}")
    output = tmp_path / "reports"
    receipt = reports.export_collection_reports(path, output, expected_plan_file_sha256=pin)
    complete(output, receipt, schemas, code=code, entries=entries)


def test_online_review_runs_once_for_all_formats_and_uses_one_snapshot(attested, tmp_path, monkeypatch, schemas):
    from dspy_security_bench import proofrun as proof
    path, raw, _, certificate = attested
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        assert Path(command[3]).read_bytes() == raw
        path.write_bytes(b"PRIVATE modified during verification")
        return SimpleNamespace(returncode=0, stdout=json.dumps([certificate]).encode(), stderr=None)

    monkeypatch.setattr(proof, "run_bounded", execute)
    output = tmp_path / "reports"
    receipt = reports.export_bundle_reports(path, output, policy=ReviewPolicy(require_trusted_builder=True))
    review = complete(output, receipt, schemas, code=0, entries=1)
    assert len(calls) == 1
    assert review["input_file_sha256"] == digest(raw) and review["provenance"] == "verified"


def test_collection_is_evaluated_once_and_saved_formats_equal_standalone_renderers(healthy, tmp_path, monkeypatch, schemas):
    path, _ = healthy
    native = reports.review_collection
    calls = []

    def evaluate(*args, **kwargs):
        calls.append(native(*args, **kwargs))
        return calls[-1]

    monkeypatch.setattr(reports, "review_collection", evaluate)
    output = tmp_path / "reports"
    receipt = reports.export_collection_reports(path, output)
    review = complete(output, receipt, schemas, code=0, entries=3)
    assert len(calls) == 1 and review == calls[0]
    assert (output / "review.html").read_bytes() == (reports.render_collection_html(review) + "\n").encode()
    assert (output / "review.xml").read_bytes() == (reports.render_collection_junit(review, scope=str(path)) + "\n").encode()
    second = tmp_path / "second"
    reports.export_collection_reports(path, second)
    assert all(p.read_bytes() == (second / p.name).read_bytes() for p in output.iterdir())


@pytest.mark.parametrize("kind", ["file", "directory", "missing_parent", "link", "linked_parent"])
@pytest.mark.parametrize("collection", [True, False])
def test_invalid_destination_prevents_native_review(healthy, tmp_path, monkeypatch, schemas, kind, collection):
    path, _ = healthy
    output = tmp_path / "reports"
    if kind == "file":
        output.write_bytes(b"KEEP")
    elif kind == "directory":
        output.mkdir()
        (output / "keep").write_bytes(b"KEEP")
    elif kind == "missing_parent":
        output = output / "child"
    else:
        try:
            output.symlink_to(tmp_path / "absent" if kind == "link" else tmp_path, target_is_directory=True)
        except OSError:
            pytest.skip("symlink creation unavailable")
        if kind == "linked_parent":
            output = output / "child"
    monkeypatch.setattr(reports, "review_collection", lambda *a, **k: pytest.fail("bad output invoked review"))
    monkeypatch.setattr(reports, "review_bundle", lambda *a, **k: pytest.fail("bad output invoked review"))
    receipt = (reports.export_collection_reports if collection else reports.export_bundle_reports)(path, output)
    check(receipt, schemas)
    assert receipt["reason_code"] == "invalid_output"
    if kind == "file":
        assert output.read_bytes() == b"KEEP"
    elif kind == "directory":
        assert (output / "keep").read_bytes() == b"KEEP"


@pytest.mark.parametrize("stage,reason", [("review_collection", "review_error"), ("render_collection_html", "render_error"),
                                       ("render_collection_junit", "render_error")])
def test_failed_evaluation_or_rendering_does_not_publish_outputs(healthy, tmp_path, monkeypatch, schemas, stage, reason):
    path, _ = healthy

    def fail(*a, **k):
        raise RuntimeError("PRIVATE source diagnostics")

    monkeypatch.setattr(reports, stage, fail)
    output = tmp_path / "reports"
    receipt = reports.export_collection_reports(path, output)
    check(receipt, schemas)
    assert receipt["reason_code"] == reason and not output.exists()
    assert receipt["native_exit_code"] == (None if reason == "review_error" else 0)


@pytest.mark.parametrize("position", [0, 1, 2, 3])
def test_write_failure_is_distinct_from_native_success(healthy, tmp_path, monkeypatch, schemas, position):
    path, _ = healthy
    original = reports.write_new_file
    writes = []

    def fail(destination, raw):
        writes.append(destination.name)
        if len(writes) == position + 1:
            original(destination, raw[:10])
            raise OSError("PRIVATE disk failure")
        original(destination, raw)

    monkeypatch.setattr(reports, "write_new_file", fail)
    output = tmp_path / "reports"
    receipt = reports.export_collection_reports(path, output)
    check(receipt, schemas)
    assert receipt["exit_code"] == 2 and receipt["native_exit_code"] == 0
    assert not receipt["report_set_complete"] and receipt["manifest_file_sha256"] is None
    assert receipt["files_written"] == position
    assert writes == ["review.json", "review.html", "review.xml", "manifest.json"][:position + 1]
    assert len((output / writes[-1]).read_bytes()) == 10


def test_output_race_preserves_existing_files(healthy, tmp_path, monkeypatch, schemas):
    path, _ = healthy
    output = tmp_path / "reports"
    original = reports.check_new_directory
    calls = []

    def race(destination):
        calls.append(destination)
        if len(calls) == 2:
            output.mkdir()
            (output / "keep").write_bytes(b"KEEP")
        return original(destination)

    monkeypatch.setattr(reports, "check_new_directory", race)
    receipt = reports.export_collection_reports(path, output)
    check(receipt, schemas)
    assert receipt["reason_code"] == "output_error"
    assert list(output.iterdir()) == [output / "keep"] and (output / "keep").read_bytes() == b"KEEP"


@pytest.mark.parametrize("command", ["verify", "verify-collection"])
@pytest.mark.parametrize("other", ["--json", "--html", "--junit"])
def test_report_directory_is_exclusive_with_stdout_formats(command, other, tmp_path):
    with pytest.raises(SystemExit) as error:
        cli.main([command, "unused.json", "--report-dir", str(tmp_path / "reports"), other])
    assert error.value.code == 2 and not (tmp_path / "reports").exists()


@pytest.mark.parametrize("command", ["verify", "verify-collection"])
def test_cli_failed_review_still_publishes_complete_reports_and_nonzero_receipt(command, tmp_path, capsys, schemas):
    output = tmp_path / "reports"
    assert cli.main([command, str(tmp_path / "PRIVATE.json"), "--report-dir", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and "PRIVATE" not in captured.out
    complete(output, json.loads(captured.out), schemas, code=2, entries=1)


def test_claims_and_manifest_integrity_are_not_inferred_from_filename(healthy, tmp_path, schemas):
    path, _ = healthy
    output = tmp_path / "reports"
    receipt = reports.export_collection_reports(path, output)
    complete(output, receipt, schemas, code=0, entries=3)
    before = receipt["review_file_sha256"]
    (output / "review.json").write_bytes(b"{}")
    assert hashlib.sha256((output / "review.json").read_bytes()).hexdigest() != before
    assert not json.loads((output / "manifest.json").read_bytes())["review_is_attestation"]
