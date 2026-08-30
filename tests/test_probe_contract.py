from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema

from dspy_security_bench.cli import main as umbrella_main
from dspy_security_bench.containment.proof import (
    REPORT_TYPE,
    analyze_scenario,
    built_in_scenario,
)
from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.probes.cli import main
from dspy_security_bench.probes.contract import (
    MAX_FIXTURE_BYTES,
    build_manifest,
    run_conformance,
    seal_manifest,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]


def _fixture_manifest(tmp_path):
    favorable = analyze_scenario(built_in_scenario("hardened-reference"))
    unfavorable = analyze_scenario(built_in_scenario("egress-violation"))
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    (fixture_dir / "favorable.json").write_text(json.dumps(favorable))
    (fixture_dir / "unfavorable.json").write_text(json.dumps(unfavorable))
    manifest = build_manifest(
        probe_id="containment-canary",
        name="Containment canary evidence",
        evidence_kind="containment",
        report_type=REPORT_TYPE,
        favorable_fixture="fixtures/favorable.json",
        unfavorable_fixture="fixtures/unfavorable.json",
        favorable_sha256=canonical_sha256(favorable),
        unfavorable_sha256=canonical_sha256(unfavorable),
    )
    return manifest


def test_conformance_uses_two_native_fixtures_without_loading_code(tmp_path):
    manifest = _fixture_manifest(tmp_path)
    assert validate_manifest(manifest) == ()
    report = run_conformance(manifest, tmp_path)
    assert report["status"] == "conformant"
    assert [item["role"] for item in report["checks"]] == ["favorable", "unfavorable"]
    assert all(item["native_verifier"] == "passed" for item in report["checks"])
    assert report["third_party_code_loaded"] is False
    assert report["network_requests"] == report["production_actions"] == 0


def test_contract_rejects_executable_boundaries_escape_tamper_and_same_fixture(tmp_path):
    manifest = _fixture_manifest(tmp_path)
    executable = deepcopy(manifest)
    executable["execution_boundary"]["third_party_code_loading"] = True
    executable = seal_manifest(executable)
    assert "frozen non-executing boundary" in "; ".join(validate_manifest(executable))

    escaped = deepcopy(manifest)
    escaped["fixtures"]["favorable"]["path"] = "../favorable.json"
    escaped = seal_manifest(escaped)
    assert "local relative path" in "; ".join(validate_manifest(escaped))

    tampered = deepcopy(manifest)
    tampered["name"] = "changed"
    assert "manifest_sha256" in "; ".join(validate_manifest(tampered))

    same = deepcopy(manifest)
    same["fixtures"]["unfavorable"]["path"] = same["fixtures"]["favorable"]["path"]
    same["fixtures"]["unfavorable"]["expected_sha256"] = same["fixtures"]["favorable"][
        "expected_sha256"
    ]
    same = seal_manifest(same)
    try:
        run_conformance(same, tmp_path)
    except ValueError as exc:
        assert "must be distinct" in str(exc)
    else:
        raise AssertionError("identical fixtures must fail conformance")


def test_manifest_schema_accepts_a_valid_contract(tmp_path):
    schema = json.loads(
        (ROOT / "dspy_security_bench/schemas/assurance-probe-manifest.schema.json").read_text()
    )
    jsonschema.validate(_fixture_manifest(tmp_path), schema)


def test_probe_cli_init_validate_conformance_and_umbrella(tmp_path, capsys):
    manifest = _fixture_manifest(tmp_path)
    path = tmp_path / "probe.json"
    path.write_text(json.dumps(manifest))
    assert main(["validate", str(path)]) == 0
    assert main(["conformance", str(path), "--fixture-root", str(tmp_path)]) == 0
    assert "third_party_code_loaded=false" in capsys.readouterr().out
    assert umbrella_main(["probe", "describe", "--json"]) == 0
    assert "assurance-probe-contract-v1" in capsys.readouterr().out

    starter = tmp_path / "starter.json"
    assert (
        main(
            [
                "init",
                "--probe-id",
                "new-probe",
                "--name",
                "New probe",
                "--evidence-kind",
                "containment",
                "--report-type",
                REPORT_TYPE,
                "--out",
                str(starter),
            ]
        )
        == 0
    )
    payload = json.loads(starter.read_text())
    assert payload["execution_boundary"]["repository_auto_exec"] is False
    assert payload["execution_boundary"]["max_fixture_bytes"] == MAX_FIXTURE_BYTES
