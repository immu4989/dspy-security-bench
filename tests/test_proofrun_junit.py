"""CI presentation preserves evidence verdicts without exposing source labels."""

import json
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_collection as collections
from dspy_security_bench import proofrun_junit as junit
from dspy_security_bench import proofrun_review as reviews
from scripts.report_pytest_failures import report_failures
from tests import test_proofrun_verification_intake as repeated_fixtures
from tests import test_public_submission_metadata as structural_fixtures
from tests.test_proofrun_collection import healthy as healthy

repeated = repeated_fixtures.family
structural = structural_fixtures.family
attested = repeated_fixtures.attested


def parse(source, *, tests, failures, errors):
    assert source.startswith("<?xml")
    assert source.isascii() and "PRIVATE" not in source.upper()
    root = ET.fromstring(source)
    assert root.tag == "testsuites" and len(root) == 1
    suite = root[0]
    assert suite.tag == "testsuite"
    assert suite.attrib == {"name": suite.get("name"), "tests": str(tests),
                            "failures": str(failures), "errors": str(errors), "skipped": "0"}
    cases = suite.findall("testcase")
    assert len(cases) == tests
    assert len(suite.findall(".//failure")) == failures
    assert len(suite.findall(".//error")) == errors
    assert not suite.findall(".//skipped")
    assert suite.find("properties") is not None
    for case in cases:
        assert set(case.attrib) == {"name", "classname"}
        assert case.find("properties") is None  # Compatible suite-level properties only.
        assert {child.tag for child in case} <= {"failure", "error", "system-out"}
        assert json.loads(case.findtext("system-out"))["claim_boundary"] == junit._BOUNDARY
    return suite


@pytest.mark.parametrize("mode", ["pass", "online", "pin", "native", "malformed", "unreadable"])
def test_single_review_junit_for_every_repeated_family(repeated, mode, tmp_path, capsys, monkeypatch):
    run_single(repeated, mode, False, tmp_path, capsys, monkeypatch)


@pytest.mark.parametrize("mode", ["pass", "online", "pin", "native", "malformed", "unreadable"])
def test_single_review_junit_for_every_structural_family(structural, mode, tmp_path, capsys, monkeypatch):
    run_single(structural[1], mode, True, tmp_path, capsys, monkeypatch)


def run_single(bundle, mode, structural, tmp_path, capsys, monkeypatch):
    path = tmp_path / "PRIVATE-input.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    options = ["--structural"] if structural else ["--minimum-trials", "2"]
    options += [] if mode == "online" else ["--offline"]
    code = 1 if mode == "online" else 0
    if mode == "pin":
        options += ["--expected-file-sha256", "0" * 64]
        code = 2
    elif mode == "native":
        path.write_text(json.dumps({**bundle, "bundle_sha256": "0" * 64}), encoding="utf-8")
        code = 2
    elif mode == "malformed":
        path.write_text('{"PRIVATE":NaN}', encoding="utf-8")
        code = 2
    elif mode == "unreadable":
        path.unlink()
        code = 2
    # A valid self-attested repeated bundle may use the normal verifier, but
    # there must never be a real subprocess/network call in this test.
    import dspy_security_bench.proofrun as proof
    monkeypatch.setattr(proof.subprocess, "run", lambda *a, **k: pytest.fail("self-attested JUnit review reached gh"))
    assert cli.main(["verify", str(path), "--junit", *options]) == code
    captured = capsys.readouterr()
    assert captured.err == ""
    suite = parse(captured.out, tests=1, failures=int(code == 1), errors=int(code == 2))
    case = suite.find("testcase")
    assert case.get("name").startswith("artifact-")
    decision = json.loads(case.findtext("system-out"))
    assert decision["exit_code"] == code
    assert not decision["review_is_attestation"] and not decision["execution_reproduced"]


@pytest.mark.parametrize("problem", ["none", "missing", "online", "mixed", "budget", "invalid_plan", "pin"])
def test_collection_xml_preserves_required_outcomes(healthy, problem, monkeypatch, capsys, tmp_path):
    path, plan = healthy
    options = []
    code, failures, errors, tests = 0, 0, 0, 3
    if problem == "missing":
        (tmp_path / plan["entries"][0]["path"]).unlink()
        code, errors = 2, 1
    elif problem == "online":
        plan["entries"][0]["policy"]["offline"] = False
        path.write_text(json.dumps(plan), encoding="utf-8")
        code, failures = 1, 1
    elif problem == "mixed":
        (tmp_path / plan["entries"][0]["path"]).unlink()
        plan["entries"][1]["policy"]["offline"] = False
        path.write_text(json.dumps(plan), encoding="utf-8")
        code, errors, failures = 2, 1, 1
    elif problem == "budget":
        monkeypatch.setattr(collections, "MAX_TOTAL_BYTES", 1)
        code, errors = 2, 3
    elif problem == "invalid_plan":
        path.write_bytes(b'{"private":true}')
        code, errors, tests = 2, 1, 1
    elif problem == "pin":
        options = ["--expected-plan-file-sha256", "0" * 64]
        code, errors, tests = 2, 1, 1
    assert cli.main(["verify-collection", str(path), "--junit", *options]) == code
    captured = capsys.readouterr()
    assert captured.err == ""
    suite = parse(captured.out, tests=tests, failures=failures, errors=errors)
    if tests == 1:
        assert suite.find("testcase").get("name").startswith("plan-admission-")
    else:
        assert [case.get("name")[:10] for case in suite.findall("testcase")] == ["entry-0001", "entry-0002", "entry-0003"]
    props = {item.get("name"): json.loads(item.get("value")) for item in suite.findall("properties/property")}
    assert props["exit_code"] == code and props["requirements_completeness_established"] is False
    xml = tmp_path / "receipt.xml"
    xml.write_text(captured.out, encoding="utf-8")
    report_failures(xml)
    diagnostics = capsys.readouterr().out
    assert diagnostics.count("::error title=") == failures + errors
    assert "PRIVATE" not in diagnostics.upper()


@pytest.mark.parametrize("command", ["verify", "verify-collection"])
def test_output_formats_are_mutually_exclusive(command):
    with pytest.raises(SystemExit) as error:
        cli.main([command, "unused.json", "--json", "--junit"])
    assert error.value.code == 2


def test_rendering_is_deterministic_projected_and_xml_safe(healthy):
    review = collections.review_collection(healthy[0])
    baseline = junit.render_collection_junit(review)
    assert baseline == junit.render_collection_junit(review)
    review["PRIVATE-extra"] = "PRIVATE"
    review["entries"][0]["PRIVATE-extra"] = "PRIVATE"
    review["entries"][0]["review"]["PRIVATE-extra"] = "PRIVATE"
    review["entries"][0]["review"]["policy"]["PRIVATE-extra"] = "PRIVATE"
    assert junit.render_collection_junit(review) == baseline
    review["verifier_version"] = 'synthetic<&"\x00\ud800'
    changed = junit.render_collection_junit(review)
    parse(changed, tests=3, failures=0, errors=0)
    suite = ET.fromstring(changed)[0]
    props = {item.get("name"): json.loads(item.get("value")) for item in suite.findall("properties/property")}
    assert props["verifier_version"] == review["verifier_version"]


def test_emitted_junit_counts_come_from_cases_not_copied_summary(healthy):
    review = collections.review_collection(healthy[0])
    review["summary"] = {"passed": 999}
    parse(junit.render_collection_junit(review), tests=3, failures=0, errors=0)


def test_invalid_policy_still_produces_a_junit_error(capsys):
    code = cli.main(["verify", "PRIVATE", "--offline", "--require-trusted-builder", "--junit"])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    parse(captured.out, tests=1, failures=0, errors=1)


def test_junit_renderer_does_not_claim_to_reverify_saved_decisions():
    assert "not a verifier" in junit.__doc__
    assert "not deployment approval" in junit._BOUNDARY
    assert reviews.ReviewPolicy().minimum_trials == 5


def test_authenticated_online_review_remains_a_pass_not_an_execution_claim(attested, monkeypatch, capsys):
    import dspy_security_bench.proofrun as proof

    path, _, _, certificate = attested
    monkeypatch.setattr(proof.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps([certificate]), stderr="PRIVATE",
    ))
    assert cli.main(["verify", str(path), "--require-trusted-builder", "--junit"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    suite = parse(captured.out, tests=1, failures=0, errors=0)
    review = json.loads(suite.findtext("testcase/system-out"))
    assert review["provenance"] == "verified" and review["evidence_tier"] == "trusted_builder"
    assert review["review_is_attestation"] is False and review["execution_reproduced"] is False


def test_ci_namespace_separates_inputs_and_policies_without_copying_private_scope(healthy):
    collection = collections.review_collection(healthy[0])
    first = junit.render_collection_junit(collection, scope="PRIVATE/one.json")
    second = junit.render_collection_junit(collection, scope="PRIVATE/two.json")
    first_cases = parse(first, tests=3, failures=0, errors=0).findall("testcase")
    second_cases = parse(second, tests=3, failures=0, errors=0).findall("testcase")
    identities = {(case.get("classname"), case.get("name")) for case in first_cases + second_cases}
    assert len(identities) == 6
    review = collection["entries"][0]["review"]
    before = ET.fromstring(junit.render_review_junit(review)).find("testsuite/testcase").get("name")
    review["policy"]["expected_file_sha256"] = "0" * 64
    after = ET.fromstring(junit.render_review_junit(review)).find("testsuite/testcase").get("name")
    assert before != after


def test_distinct_unreadable_cli_inputs_do_not_collapse_in_ci(capsys):
    identities = []
    for path in ("PRIVATE-missing-a.json", "PRIVATE-missing-b.json"):
        assert cli.main(["verify", path, "--offline", "--junit"]) == 2
        suite = parse(capsys.readouterr().out, tests=1, failures=0, errors=1)
        identities.append(suite.find("testcase").get("name"))
    assert len(set(identities)) == 2
