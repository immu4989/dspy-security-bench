"""Stress fixtures must not become giant log lines or inherited environment IDs."""

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from tests import conftest as policy


@pytest.mark.parametrize("value", [b"PRIVATE" * 200000, "PRIVATE" * 200000, "\x00PRIVATE", "\x1b[2JPRIVATE",
                                  "\u202ePRIVATE", "\ud800PRIVATE", 10 ** 1000, -(10 ** 1000)],
                         ids=["large-bytes", "large-text", "nul", "escape", "bidi", "surrogate", "large-int", "negative-int"])
def test_automatic_ids_are_short_stable_and_do_not_echo_payloads(value):
    label = policy.pytest_make_parametrize_id(value, "raw")
    assert label.isascii() and label.isprintable() and len(label) < 64
    assert "PRIVATE" not in label
    assert policy.pytest_make_parametrize_id(value, "raw") == label


@pytest.mark.parametrize("value", ["ordinary", "", "a" * 80, 12, False, None, 1.5, {}, []])
def test_short_values_keep_normal_pytest_labels(value):
    assert policy.pytest_make_parametrize_id(value, "raw") is None


def test_fixture_kind_sign_and_bytes_are_part_of_identity():
    samples = [b"a" * 100, "a" * 100, b"a" * 101, 10 ** 1000, -(10 ** 1000)]
    assert len({policy.pytest_make_parametrize_id(value, "raw") for value in samples}) == len(samples)


def test_argument_name_is_also_bounded_and_console_safe():
    value = policy.pytest_make_parametrize_id(b"PRIVATE", "arg\n\x1b" * 2000)
    assert value.isascii() and value.isprintable() and len(value) < 80


def item(nodeid):
    return SimpleNamespace(nodeid=nodeid, path=Path("test_fixture.py"), location=("test_fixture.py", 12, "test_case"))


@pytest.mark.parametrize("nodeid", ["a" * 513, "PRIVATE\nforged", "PRIVATE\x00", "PRIVATE\x7f"],
                         ids=["over-budget", "newline", "nul", "del"])
def test_explicit_ids_cannot_bypass_collection_budget(nodeid):
    with pytest.raises(pytest.UsageError) as error:
        policy.pytest_collection_modifyitems([item(nodeid)])
    assert "PRIVATE" not in str(error.value)
    assert "test_fixture.py:13" in str(error.value)


def test_collection_boundary_and_bounded_diagnostics():
    assert policy.pytest_collection_modifyitems([item("a" * 512)]) is None
    with pytest.raises(pytest.UsageError) as error:
        policy.pytest_collection_modifyitems([item("PRIVATE" * 100)] * 100)
    text = str(error.value)
    assert text.startswith("100 test IDs") and text.count("test_fixture.py:13") == 5
    assert len(text) < 500 and "PRIVATE" not in text


def run_pytest(tmp_path, source, *options):
    # Exercise real pytest collection, verbose logging, JUnit, and environment
    # propagation. Use an isolated synthetic test module, not recursive repo runs.
    (tmp_path / "conftest.py").write_text(Path(policy.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "test_fixture.py").write_text(source, encoding="utf-8")
    env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTEST_PLUGINS", None)
    return subprocess.run([sys.executable, "-m", "pytest", "-v", "--tb=short", "-p", "no:cacheprovider",
                           "--junitxml=report.xml", *options], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30, check=False)


def test_real_verbose_run_retains_full_fixture_and_bounded_junit_and_environment(tmp_path):
    result = run_pytest(tmp_path, '''import os
import pytest

@pytest.mark.parametrize("raw", [b"x" * 1000001])
def test_large(raw):
    assert len(raw) == 1000001
    assert len(os.environ["PYTEST_CURRENT_TEST"]) < 512

@pytest.mark.parametrize("raw", [b"x" * 1000001], ids=["large-explicit"])
def test_explicit(raw):
    assert len(raw) == 1000001
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout and "large-explicit" in result.stdout
    assert len(result.stdout) < 10000 and "x" * 1000 not in result.stdout
    cases = ElementTree.parse(tmp_path / "report.xml").findall(".//testcase")
    assert len(cases) == 2 and all(len(case.get("name")) < 100 for case in cases)
    assert "raw-bytes-sha256-" in cases[0].get("name")


def test_real_collection_rejects_oversized_explicit_id_before_test_execution(tmp_path):
    result = run_pytest(tmp_path, '''from pathlib import Path
import pytest

@pytest.mark.parametrize("value", [1], ids=["PRIVATE" * 1000])
def test_bad(value):
    Path("EXECUTED").touch()
''')
    assert result.returncode == 4 and "Use short descriptive ids=" in result.stderr
    assert "PRIVATE" not in result.stdout + result.stderr
    assert len(result.stdout + result.stderr) < 10000
    assert not (tmp_path / "EXECUTED").exists()


def test_full_suite_ids_fit_the_declared_bound(request):
    ids = [entry.nodeid for entry in request.session.items]
    assert ids and max(map(len, ids)) <= policy.MAX_NODE_ID_CHARACTERS
    assert len(ids) == len(set(ids))
