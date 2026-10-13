"""Offline study review presentation, safe output, and fictional rehearsal."""

import json
import socket
from copy import deepcopy
from pathlib import Path

import pytest

from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.study_demo import build_study_demo_artifacts
from dspy_security_bench.scan.study_html import MAX_PREVIEW_CASES, render_scan_study_html


@pytest.mark.parametrize("default_encoding", ["utf-8", "cp1252"])
def test_study_demo_is_deterministic_and_recomputes_offline(tmp_path, monkeypatch, default_encoding):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline demo must not access the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    # Model a non-UTF-8 host without changing the process locale or suppressing
    # encoding failures. Explicit UTF-8 artifact I/O must work in both cases.
    original_open = Path.open

    def host_open(path, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        if "b" not in mode and encoding in (None, "locale"):
            encoding = default_encoding
        return original_open(path, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", host_open)
    artifacts = build_study_demo_artifacts()
    assert artifacts == build_study_demo_artifacts()
    assert len(artifacts) == 6
    destination = tmp_path / "demo"
    assert main(["study", "demo", "--out", str(destination)]) == 0
    manifest, report = str(destination / "manifest.json"), str(destination / "study.json")
    assert main(["study", "review", manifest, "--verify", report]) == 0
    assert main(["study", "review", manifest, "--verify", report, "--fail-on-shortfalls"]) == 1
    assert "Fictional teaching demo." in artifacts["review.html"]
    assert "deliberately reused" in artifacts["review.html"]
    assert main(["study", "demo", "--out", str(destination)]) == 2
    assert (destination / "review.html").read_text(encoding="utf-8") == artifacts["review.html"]


def test_html_is_script_free_and_escapes_source_identifiers():
    report = json.loads(build_study_demo_artifacts()["study.json"])
    report["cases"][0]["suite"] = '<img src="https://private.invalid" onerror="alert(1)">'
    html = render_scan_study_html(report)
    assert '<img src=' not in html and '&lt;img src=' in html
    assert "<script" not in html and "<link" not in html and "<iframe" not in html
    assert "default-src 'none'" in html
    assert 'tabindex="0" role="region"' in html
    assert "Review incomplete" in html
    assert "3 / 5 trials complete" in html
    assert "1 missing · 1 execution errors" in html
    assert "18 observed of 30 planned" in html
    assert "condition on complete trials only" in html


def test_case_preview_labels_omissions_and_prioritizes_variability():
    report = json.loads(build_study_demo_artifacts()["study.json"])
    stable = deepcopy(report["cases"][-1])
    report["cases"] = []
    for i in range(60):
        case = deepcopy(stable)
        case["user_task_id"] = f"fixture-{i:03d}"
        report["cases"].append(case)
    varied = report["cases"][-1]
    varied["security"]["varied"] = True
    html = render_scan_study_html(report)
    assert f"Showing {MAX_PREVIEW_CASES} of 60 cases; 10 omitted" in html
    assert html.index("fixture-059") < html.index("fixture-000")
    assert "fixture-058" not in html


def test_new_html_output_requires_native_source_verification(tmp_path):
    folder = tmp_path / "demo"
    assert main(["study", "demo", "--out", str(folder)]) == 0
    path = str(folder / "manifest.json")
    output = tmp_path / "new-review.html"
    assert main(["study", "review", path, "--html", str(output), "--fail-on-shortfalls"]) == 1
    assert "Every attempt" in output.read_text()
    marker = output.read_bytes()
    assert main(["study", "review", path, "--html", str(output)]) == 2
    assert output.read_bytes() == marker
    collision = tmp_path / "collision"
    assert main(["study", "review", path, "--html", str(collision), "--json", str(collision)]) == 2
    assert not collision.exists()
    source = folder / "before.json"
    value = json.loads(source.read_text())
    value["observations"][0]["security"] = 0
    source.write_text(json.dumps(value))
    invalid = tmp_path / "invalid.html"
    assert main(["study", "review", path, "--html", str(invalid)]) == 2
    assert not invalid.exists()


def test_demo_does_not_create_parents_or_follow_existing_destination_symlink(tmp_path):
    assert main(["study", "demo", "--out", str(tmp_path / "missing/demo")]) == 2
    assert not (tmp_path / "missing").exists()
    existing = tmp_path / "existing"
    existing.mkdir()
    link = tmp_path / "link"
    link.symlink_to(existing, target_is_directory=True)
    assert main(["study", "demo", "--out", str(link)]) == 2
    assert list(existing.iterdir()) == []
