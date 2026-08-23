import json
from copy import deepcopy
from importlib.resources import files

import jsonschema

from dspy_security_bench.cli import main as root_main
from dspy_security_bench.trace.challenge import (
    run_redaction_challenge,
    verify_redaction_challenge,
)


def test_frozen_redaction_challenge_has_no_canary_escapes():
    report = run_redaction_challenge()
    assert report["challenge_version"] == "traceproof-redaction-challenge-v1"
    assert report["case_count"] == 20
    assert report["passed_count"] == 20
    assert report["escaped_count"] == 0
    assert report["status"] == "pass"
    assert verify_redaction_challenge(report) == ()
    schema = json.loads(
        files("dspy_security_bench")
        .joinpath("schemas/trace-redaction-challenge.schema.json")
        .read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_redaction_challenge_recomputes_every_case():
    report = run_redaction_challenge()
    tampered = deepcopy(report)
    tampered["cases"][0]["passed"] = False
    assert verify_redaction_challenge(tampered)


def test_redaction_challenge_cli_writes_report(tmp_path):
    destination = tmp_path / "challenge.json"
    assert root_main(["trace", "challenge", "--out", str(destination)]) == 0
    assert destination.is_file()
    assert '"escaped_count": 0' in destination.read_text()
