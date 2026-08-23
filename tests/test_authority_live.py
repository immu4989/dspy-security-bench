import sys
from copy import deepcopy

from dspy_security_bench.authority.live import (
    run_live_bridge_conformance,
    verify_live_bridge_conformance,
)
from dspy_security_bench.cli import main as root_main


def backend_script(tmp_path):
    script = tmp_path / "backend.py"
    script.write_text(
        """import json, sys
from dspy_security_bench.authority.adapter import BoundedAuthorityAdapter
payload = json.load(sys.stdin)
outcome, reason = BoundedAuthorityAdapter._evaluate(payload[\"request\"], payload[\"context\"])
print(json.dumps({\"result\": {\"allow\": outcome == \"allow\", \"review\": outcome == \"review\", \"reason_code\": reason}}))
"""
    )
    return f"{sys.executable} {script}"


def test_operator_command_bridge_creates_self_attested_real_backend_evidence(tmp_path):
    report = run_live_bridge_conformance(
        backend="opa", backend_version="test-fixture-1", command=backend_script(tmp_path)
    )
    assert report["authority_report"]["summary"]["attack_resistance"] == 1.0
    assert report["authority_report"]["summary"]["clean_mission_utility"] == 1.0
    assert report["evidence_tier"] == "self_attested_local_execution"
    assert verify_live_bridge_conformance(report) == ()


def test_live_bridge_verifier_rejects_tampering(tmp_path):
    report = run_live_bridge_conformance(
        backend="opa", backend_version="test-fixture-1", command=backend_script(tmp_path)
    )
    tampered = deepcopy(report)
    tampered["backend_version"] = "other"
    errors = verify_live_bridge_conformance(tampered)
    assert "authority_report adapter does not match backend declaration" in errors
    assert "report_sha256 does not match canonical report content" in errors


def test_live_bridge_cli_round_trip(tmp_path):
    output = tmp_path / "live.json"
    assert (
        root_main(
            [
                "authority",
                "bridge",
                "run",
                "opa",
                "--backend-version",
                "test-fixture-1",
                "--command",
                backend_script(tmp_path),
                "--json-out",
                str(output),
            ]
        )
        == 0
    )
    assert root_main(["authority", "bridge", "verify", str(output)]) == 0
