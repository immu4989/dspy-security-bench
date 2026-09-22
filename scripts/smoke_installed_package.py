"""Exercise an installed wheel outside the checkout, without provider calls.

Run using the interpreter into which the wheel was installed. This is a release
smoke check, not a dependency-resolution test or an operating-system sandbox.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

BOOTSTRAP = r'''
import importlib.metadata
import importlib.resources
import json
import pathlib
import socket
import sys
import sysconfig

def offline(*args, **kwargs):
    raise RuntimeError("installed-package smoke must not access the network")

socket.socket.connect = offline
socket.socket.connect_ex = offline
socket.create_connection = offline
socket.getaddrinfo = offline

import dspy_security_bench.cli
package = pathlib.Path(dspy_security_bench.cli.__file__).resolve()
site = pathlib.Path(sysconfig.get_path("purelib")).resolve()
if not package.is_relative_to(site):
    raise RuntimeError("smoke requires the wheel installed in this interpreter's site-packages")
distribution = importlib.metadata.distribution("dspy-security-bench")
origin = json.loads(distribution.read_text("direct_url.json") or "{}")
if origin.get("dir_info", {}).get("editable"):
    raise RuntimeError("editable installation is not a release wheel")
entry = [item for item in distribution.entry_points
         if item.group == "console_scripts" and item.name == "dspy-security-bench"]
if len(entry) != 1 or entry[0].value != "dspy_security_bench.cli:main":
    raise RuntimeError("installed CLI entry point is missing or changed")
resources = importlib.resources.files("dspy_security_bench")
for name in ("scan-evidence.schema.json", "scan-comparison.schema.json"):
    json.loads(resources.joinpath("schemas", name).read_text(encoding="utf-8"))
if "workflow_dispatch" not in resources.joinpath("templates", "github-action.yml").read_text(encoding="utf-8"):
    raise RuntimeError("safe workflow template missing from installed wheel")
raise SystemExit(entry[0].load()(sys.argv[1:]))
'''


def run_cli(directory: Path, arguments: list[str], expected: int = 0) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", BOOTSTRAP, *arguments],
        cwd=directory, capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"installed CLI {arguments[:2]!r}: expected exit {expected}, got {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="dsb-installed-smoke-") as temporary:
        directory = Path(temporary)
        run_cli(directory, ["--version"])
        run_cli(directory, ["scan", "demo", "--out", "demo"])
        run_cli(directory, ["scan", "verify", "demo/before.json"])
        run_cli(directory, ["scan", "verify", "demo/after.json", "--fail-on-shortfalls"], 1)
        run_cli(directory, ["scan", "compare", "demo/before.json", "demo/after.json",
                            "--verify", "demo/comparison.json"])
        run_cli(directory, ["scan", "compare", "demo/before.json", "demo/after.json",
                            "--fail-on-regression"], 1)
        evidence = json.loads((directory / "demo/before.json").read_text(encoding="utf-8"))
        evidence["evidence_sha256"] = "0" * 64
        (directory / "tampered.json").write_text(json.dumps(evidence), encoding="utf-8")
        run_cli(directory, ["scan", "verify", "tampered.json"], 2)
        run_cli(directory, ["init", "--no-workflow"])
        if not (directory / ".dspy-security-bench.yaml").is_file():
            raise RuntimeError("installed init did not create its config")
    print("Installed wheel smoke passed: resources, CLI, offline replay, policy exits, tamper rejection, scaffold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
