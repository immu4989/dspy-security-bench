"""CI failures must remain visible on non-UTF-8 hosts without command injection."""

import sys
from xml.etree import ElementTree

import pytest

from scripts import report_pytest_failures as diagnostics


def write_report(path, *, kind="failure", detail="failure details", count=1):
    root = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(root, "testsuite")
    for _ in range(count):
        case = ElementTree.SubElement(suite, "testcase", classname="suite", name="name,:汉\n::warning::injection")
        ElementTree.SubElement(case, kind).text = detail
    path.write_bytes(ElementTree.tostring(root, encoding="utf-8"))


@pytest.mark.parametrize("kind", ["failure", "error"])
def test_annotations_escape_properties_lines_and_nonascii(kind, tmp_path, capsys):
    path = tmp_path / "result.xml"
    write_report(path, kind=kind, detail="中文 50%\n::notice::not a new command\rmore")
    diagnostics.report_failures(path)
    output = capsys.readouterr().out
    output.encode("ascii")
    assert output.count("\n") == 1
    assert "name%2C%3A" in output and "%0A%3A%3Awarning%3A%3A" in output
    # XML normalizes literal carriage returns to line feeds while parsing.
    assert "50%25%0A::notice::not a new command%0Amore" in output
    assert diagnostics.escape("\r") == "%0D"
    assert "\\u4e2d" in output


@pytest.mark.parametrize("contents", [None, b"not XML", b"<testsuite>"])
def test_missing_or_broken_report_does_not_hide_original_test_failure(contents, tmp_path, capsys):
    path = tmp_path / "report.xml"
    if contents is not None:
        path.write_bytes(contents)
    diagnostics.report_failures(path)
    assert "No readable bounded JUnit report" in capsys.readouterr().out


def test_report_bytes_failure_count_and_details_are_bounded(tmp_path, monkeypatch, capsys):
    path = tmp_path / "report.xml"
    write_report(path, detail="x" * 100, count=3)
    monkeypatch.setattr(diagnostics, "MAX_DETAIL_CHARACTERS", 10)
    monkeypatch.setattr(diagnostics, "MAX_FAILURES", 2)
    diagnostics.report_failures(path)
    output = capsys.readouterr().out
    assert output.count("::error title=") == 2
    assert "[diagnostic truncated]" in output
    assert "3 failing/error cases" in output
    monkeypatch.setattr(diagnostics, "MAX_REPORT_BYTES", path.stat().st_size - 1)
    diagnostics.report_failures(path)
    assert "No readable bounded JUnit report" in capsys.readouterr().out


def test_cli_accepts_a_report_and_keeps_diagnostics_separate_from_verdict(tmp_path, monkeypatch, capsys):
    path = tmp_path / "report.xml"
    write_report(path)
    monkeypatch.setattr(sys, "argv", ["report_pytest_failures.py", str(path)])
    assert diagnostics.main() == 0
    assert "failure details" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["report_pytest_failures.py"])
    assert diagnostics.main() == 2
