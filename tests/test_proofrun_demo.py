"""The onboarding walkthrough must exercise real commands and adverse outcomes."""

import hashlib
import json
import shlex
import socket

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_demo as demo
from dspy_security_bench import proofrun_review as review
from dspy_security_bench.proofrun_collection import review_collection


@pytest.fixture
def generated(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        pytest.fail("synthetic tutorial attempted network/provenance access")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(review, "verify_github_attestation", forbidden)
    output = tmp_path / "walkthrough"
    result = demo.create_collection_demo(output)
    assert result["exit_code"] == 0 and result["demo_complete"]
    return output, result


def test_native_demo_preserves_all_three_outcomes_and_every_required_slot(generated):
    output, result = generated
    assert json.loads((output / "demo.json").read_bytes()) == result
    assert result["synthetic"] and "no external model" in result["claim_boundary"]
    assert [case["observed_exit_code"] for case in result["cases"]] == [0, 1, 2]
    for case in result["cases"]:
        source = output / case["plan"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == case["plan_file_sha256"]
        reviewed = review_collection(source, expected_plan_file_sha256=case["plan_file_sha256"])
        assert reviewed["exit_code"] == case["expected_exit_code"]
        assert reviewed["summary"]["required"] == 3
        assert not reviewed["review_is_attestation"] and not reviewed["requirements_completeness_established"]
        assert json.loads((output / case["reports"] / "review.json").read_bytes()) == reviewed
        assert (output / case["reports"] / "review.html").is_file()
        assert (output / case["reports"] / "review.xml").is_file()
    missing = json.loads((output / "missing-reports/review.json").read_bytes())
    assert missing["summary"] == {"required": 3, "reviewed": 2, "passed": 2, "not_passed": 0, "invalid": 1}
    assert not (output / "missing/defense.json").exists()
    assert (output / "missing/collection-plan.json").read_bytes() == (output / "owner/collection-plan.json").read_bytes()
    assert json.loads((output / "policy-comparison.json").read_bytes())["entries"][0]["changed_fields"] == ["policy.offline"]


def test_readme_commands_replay_the_documented_expected_exits(generated, monkeypatch, capsys):
    output, _ = generated
    monkeypatch.chdir(output)
    text = (output / "README.md").read_text(encoding="utf-8")
    commands = [shlex.split(line)[2:] for line in text.splitlines() if line.startswith("dspy-security-bench proofrun ")]
    assert len(commands) == 6
    for args, expected in zip(commands, [0, 0, 0, 1, 1, 2], strict=True):
        assert cli.main(args) == expected
        capsys.readouterr()
    assert (output / "owner/replayed-plan.json").read_bytes() == (output / "owner/collection-plan.json").read_bytes()
    assert (output / "replay-handoff/collection-plan.json").read_bytes() == (output / "owner/collection-plan.json").read_bytes()
    assert json.loads((output / "replay-reports/review.json").read_bytes())["exit_code"] == 0
    assert cli.main(commands[0]) == 2  # Never overwrite the replay's first draft.


def test_recipient_does_not_need_the_owner_directory(generated):
    output, result = generated
    (output / "owner").rename(output / "retained-owner")
    case = result["cases"][0]
    assert review_collection(output / case["plan"], expected_plan_file_sha256=case["plan_file_sha256"])["exit_code"] == 0


def test_all_original_artifacts_are_explicitly_synthetic(generated):
    output, _ = generated
    families = set()
    for name in ("collective.json", "causal.json", "defense.json"):
        bundle = json.loads((output / "owner" / name).read_bytes())
        families.add(bundle["bundle_type"])
        submission = bundle["submission"]
        assert "synthetic" in submission["submitter"] and "no-live-system" in submission["runtime"]
        assert submission["source_repository"].startswith("https://example.com/")
        assert submission["created_at"] == "2026-01-01"
        assert "no external model" in submission["known_gaps"][0]
        assert (output / "recipient" / name).read_bytes() == (output / "owner" / name).read_bytes()
    assert len(families) == 3


def test_fixture_bytes_and_plan_pins_are_deterministic(generated, tmp_path):
    first, result = generated
    second = tmp_path / "second"
    other = demo.create_collection_demo(second)
    assert other["exit_code"] == 0 and other["cases"] == result["cases"]
    for source in (first / "owner").iterdir():
        assert source.read_bytes() == (second / "owner" / source.name).read_bytes()


@pytest.mark.parametrize("kind", ["file", "directory", "missing_parent", "link"])
def test_invalid_output_fails_before_generating_fixtures(tmp_path, monkeypatch, kind):
    output = tmp_path / "demo"
    if kind == "file":
        output.write_bytes(b"KEEP")
    elif kind == "directory":
        output.mkdir()
        (output / "keep").write_bytes(b"KEEP")
    elif kind == "missing_parent":
        output = output / "child"
    else:
        try:
            output.symlink_to(tmp_path / "absent", target_is_directory=True)
        except OSError:
            pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(demo, "_fixtures", lambda: pytest.fail("invalid output generated fixtures"))
    result = demo.create_collection_demo(output)
    assert result["reason_code"] == "invalid_output" and result["exit_code"] == 2
    assert not result["demo_complete"]
    if kind == "file":
        assert output.read_bytes() == b"KEEP"
    elif kind == "directory":
        assert list(output.iterdir()) == [output / "keep"]
        assert (output / "keep").read_bytes() == b"KEEP"


def test_broken_fixture_does_not_create_output_or_echo_diagnostics(tmp_path, monkeypatch):
    def fail():
        raise RuntimeError("PRIVATE source")
    monkeypatch.setattr(demo, "_fixtures", fail)
    output = tmp_path / "out"
    result = demo.create_collection_demo(output)
    assert result["reason_code"] == "fixture_error" and "PRIVATE" not in json.dumps(result)
    assert not output.exists()


@pytest.mark.parametrize("stage,reason", [("prepare_plan_file", "preparation_error"), ("snapshot_collection", "snapshot_error")])
def test_failed_workflow_stage_never_produces_completion(tmp_path, monkeypatch, stage, reason):
    monkeypatch.setattr(demo, stage, lambda *a, **k: {"exit_code": 2})
    output = tmp_path / "out"
    result = demo.create_collection_demo(output)
    assert result["reason_code"] == reason and not result["demo_complete"]
    assert not (output / "demo.json").exists()


def test_unexpected_native_outcome_cannot_be_relabelled_as_expected(tmp_path, monkeypatch):
    native = demo.export_collection_reports

    def changed(*a, **k):
        receipt = native(*a, **k)
        return {**receipt, "native_exit_code": 2, "exit_code": 2}

    monkeypatch.setattr(demo, "export_collection_reports", changed)
    output = tmp_path / "out"
    result = demo.create_collection_demo(output)
    assert result["reason_code"] == "unexpected_demo_outcome"
    assert result["cases"][0]["expected_exit_code"] == 0
    assert result["cases"][0]["observed_exit_code"] == 2
    assert not (output / "demo.json").exists()


def test_partial_write_leaves_explicit_failed_generation(tmp_path, monkeypatch):
    original = demo.write_new_file

    def fail(path, raw):
        if path.name == "demo.json":
            original(path, raw[:10])
            raise OSError("PRIVATE storage")
        original(path, raw)

    monkeypatch.setattr(demo, "write_new_file", fail)
    output = tmp_path / "out"
    result = demo.create_collection_demo(output)
    assert result["reason_code"] == "demo_error" and not result["demo_complete"]
    assert "PRIVATE" not in json.dumps(result)
    assert len((output / "demo.json").read_bytes()) == 10


def test_expected_exit_with_wrong_native_reason_is_not_a_successful_tutorial(tmp_path, monkeypatch):
    original = demo.export_collection_reports

    def change(path, output, **kwargs):
        receipt = original(path, output, **kwargs)
        if output.name == "provenance-reports":
            report_path = output / "review.json"
            value = json.loads(report_path.read_bytes())
            value["entries"][0]["review"]["reason_code"] = "not_eligible"
            raw = json.dumps(value).encode()
            report_path.write_bytes(raw)
            receipt["review_file_sha256"] = hashlib.sha256(raw).hexdigest()
        return receipt

    monkeypatch.setattr(demo, "export_collection_reports", change)
    result = demo.create_collection_demo(tmp_path / "out")
    assert result["reason_code"] == "unexpected_demo_outcome" and not result["demo_complete"]
    assert result["cases"][1]["observed_exit_code"] == 1


@pytest.mark.parametrize("machine", [False, True])
def test_cli_exit_and_nonclaim_guidance(tmp_path, capsys, machine):
    args = ["collection-demo", "--out", str(tmp_path / "out"), *(["--json"] if machine else [])]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and "Synthetic" in captured.out
    assert "deployment approval" in captured.out
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    assert bool(captured.out) == machine and bool(captured.err) != machine
