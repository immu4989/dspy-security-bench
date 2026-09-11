from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "interop" / "root-view-quorum-node" / "verify.mjs"
PACK = REPO_ROOT / "interop" / "root-view-quorum-v1"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _run(pack: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(NODE), str(RUNNER), str(pack)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def test_independent_node_runner_executes_all_known_answer_cases():
    completed = _run(PACK)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    manifest = json.loads((PACK / "vector-manifest.json").read_text())
    assert result["implementation"] == "dspy-security-bench-root-view-node-v1"
    assert result["manifest_sha256"] == manifest["manifest_sha256"]
    assert [item["case_id"] for item in result["cases"]] == [
        item["case_id"] for item in manifest["cases"]
    ]
    assert result["cases"][-1]["verifier_accepted"] is False
    assert result["summary"] == {"passed": 8, "failed": 0, "automatic_actions": 0}


def test_independent_node_runner_rejects_byte_drift(tmp_path):
    pack = tmp_path / "pack"
    shutil.copytree(PACK, pack)
    policy = pack / "policy.json"
    policy.write_bytes(policy.read_bytes() + b"\n")
    completed = _run(pack)
    assert completed.returncode == 1
    assert "policy.json file digest mismatch" in completed.stderr


def test_independent_runner_does_not_delegate_to_python():
    source = RUNNER.read_text()
    assert "node:child_process" not in source
    assert "dspy_security_bench" not in source
