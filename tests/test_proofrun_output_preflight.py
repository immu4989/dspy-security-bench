"""Reject destructive output layouts before invoking an agent or adapter."""

import pytest

import dspy_security_bench.proofrun_cli as cli


def arguments(command, output, report=None, card=None):
    args = [command, "--submitter", "synthetic", "--out", str(output), "--trials", "2"]
    if command == "authority":
        args += ["--reference", "bounded", "--adapter-source", "https://example.com/adapter"]
    else:
        args += ["--agent", "never_import_this:factory", "--agent-source", "https://example.com/agent"]
    if command == "control":
        args += ["--policy", "never-read.yaml", "--policy-source", "https://example.com/policy"]
    if report is not None:
        args += ["--report-out", str(report)]
    if card is not None:
        args += ["--card-out", str(card)]
    return args


@pytest.mark.parametrize("command", ["run", "control", "incident", "source", "authority"])
@pytest.mark.parametrize("layout", ["existing", "directory", "collision", "alias", "symlink", "dangling", "parent_symlink", "hardlink", "missing_parent"])
def test_bad_layouts_stop_before_any_execution(command, layout, tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid outputs reached execution")

    monkeypatch.setattr(cli, "_" + command, forbidden)
    marker = tmp_path / "retained.json"
    marker.write_text("PRIVATE-RETAINED-CONTENT")
    output, report = tmp_path / "output.json", None
    if layout == "existing":
        output = marker
    elif layout == "directory":
        output.mkdir()
    elif layout == "collision":
        report = output
    elif layout == "alias":
        child = tmp_path / "child"
        child.mkdir()
        report = child / ".." / "output.json"
    elif layout == "symlink":
        output.symlink_to(marker)
    elif layout == "dangling":
        output.symlink_to(tmp_path / "absent.json")
    elif layout == "parent_symlink":
        link = tmp_path / "linked-parent"
        link.symlink_to(tmp_path, target_is_directory=True)
        output = link / "new.json"
    elif layout == "hardlink":
        output.hardlink_to(marker)
    else:
        output = tmp_path / "absent" / "output.json"
    assert cli.main(arguments(command, output, report)) == 2
    assert marker.read_text() == "PRIVATE-RETAINED-CONTENT"
    assert not (tmp_path / "absent").exists()
    captured = capsys.readouterr()
    assert "PRIVATE-RETAINED-CONTENT" not in captured.out + captured.err


@pytest.mark.parametrize("target", ["bundle", "report", "existing"])
def test_card_cannot_replace_other_outputs(target, tmp_path, monkeypatch):
    def forbidden(*args):
        pytest.fail("colliding card reached policy execution")

    monkeypatch.setattr(cli, "_control", forbidden)
    output, report = tmp_path / "bundle.json", tmp_path / "report.json"
    card = {"bundle": output, "report": report, "existing": tmp_path / "card.svg"}[target]
    if target == "existing":
        card.write_text("preserve")
    assert cli.main(arguments("control", output, report, card)) == 2


def test_write_rechecks_destination_after_execution(tmp_path):
    output = tmp_path / "output.json"
    cli._checked_output(output)
    output.write_text("created-by-another-process")
    with pytest.raises(ValueError):
        cli._write_json(output, {"replacement": True})
    assert output.read_text() == "created-by-another-process"


def test_exclusive_creation_protects_final_component_race(tmp_path, monkeypatch):
    output = tmp_path / "output.json"
    check = cli._checked_output

    def race(path):
        checked = check(path)
        path.write_text("created-after-last-check")
        return checked

    monkeypatch.setattr(cli, "_checked_output", race)
    with pytest.raises(FileExistsError):
        cli._write_json(output, {"replacement": True})
    assert output.read_text() == "created-after-last-check"


def test_nonfinite_output_fails_before_creating_file(tmp_path):
    output = tmp_path / "output.json"
    with pytest.raises(ValueError):
        cli._write_json(output, {"measurement": float("nan")})
    assert not output.exists()


def test_real_offline_run_preserves_bundle_and_standalone_report(tmp_path, monkeypatch):
    import socket

    from dspy_security_bench.jsonio import read_json_object
    from dspy_security_bench.procurement.repeat import canonical_sha256, verify_submission_bundle

    def forbidden(*args, **kwargs):
        pytest.fail("reference fixture must not access a network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(cli, "capture_provenance", lambda: {
        "provider": "local", "builder_kind": "local_process", "runner_environment": "local",
    })
    output, report = tmp_path / "bundle.json", tmp_path / "report.json"
    args = arguments("run", output, report)
    args[args.index("--agent") + 1] = "dspy_security_bench.procurement.agents:build_bounded_reference"
    assert cli.main(args) == 0
    bundle = read_json_object(output, 50_000_000)
    standalone = read_json_object(report, 50_000_000)
    assert verify_submission_bundle(bundle).valid
    assert canonical_sha256(standalone) == bundle["report_sha256"]
    retained = {path: path.read_bytes() for path in (output, report)}
    assert cli.main(args) == 2
    assert all(path.read_bytes() == data for path, data in retained.items())
