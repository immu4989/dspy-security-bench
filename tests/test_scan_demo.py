"""The teaching workflow must be reproducible, offline, and non-destructive."""

import json
import socket

from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.demo import build_demo_artifacts


def test_demo_is_offline_and_replays_with_documented_exit_codes(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("demo must not connect to the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    destination = tmp_path / "demo"
    assert main(["demo", "--out", str(destination)]) == 0
    before, after = str(destination / "before.json"), str(destination / "after.json")
    assert main(["verify", before]) == 0
    assert main(["verify", after, "--fail-on-shortfalls"]) == 1
    assert main(["compare", before, after, "--verify", str(destination / "comparison.json")]) == 0
    assert main(["compare", before, after, "--fail-on-regression"]) == 1
    assert "Fictional teaching demo." in (destination / "review.html").read_text()


def test_demo_is_deterministic_and_explicitly_fictional():
    first = build_demo_artifacts()
    assert first == build_demo_artifacts()
    assert len(first) == 5
    report = json.loads(first["comparison.json"])
    for axis in ("security", "utility"):
        counts = report["summary"][axis]
        assert counts["before_successes"] == counts["after_successes"]
        assert counts["new_failures"] == 1
    assert "not AgentDojo benchmark results" in first["README.md"]


def test_demo_refuses_existing_directory_or_symlink(tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "before.json"
    marker.write_text("preserve")
    assert main(["demo", "--out", str(existing)]) == 2
    link = tmp_path / "link"
    link.symlink_to(existing, target_is_directory=True)
    assert main(["demo", "--out", str(link)]) == 2
    assert marker.read_text() == "preserve"
    assert list(existing.iterdir()) == [marker]


def test_demo_missing_parent_is_not_created(tmp_path):
    assert main(["demo", "--out", str(tmp_path / "missing" / "demo")]) == 2
    assert not (tmp_path / "missing").exists()
