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
for name in ("scan-evidence.schema.json", "scan-comparison.schema.json", "scan-study.schema.json",
             "scan-policy-review.schema.json"):
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
        run_cli(directory, ["scan", "study", "demo", "--out", "study"])
        run_cli(directory, ["scan", "study", "review", "study/manifest.json",
                            "--verify", "study/study.json", "--html", "study/replayed.html"])
        run_cli(directory, ["scan", "study", "review", "study/manifest.json",
                            "--html", "study/replayed-again.html"])
        if (directory / "study/replayed.html").read_bytes() != (directory / "study/replayed-again.html").read_bytes():
            raise RuntimeError("installed study HTML does not replay exactly")
        run_cli(directory, ["scan", "study", "review", "study/manifest.json",
                            "--fail-on-shortfalls"], 1)
        run_cli(directory, ["scan", "study", "review", "study/manifest.json",
                            "--expected-plan-sha256", "0" * 64], 2)
        run_cli(directory, ["scan", "study", "init", "demo/before.json", "--study-id", "wheel-smoke",
                            "--trials", "2", "--out", "planned.json"])
        run_cli(directory, ["scan", "study", "review", "planned.json", "--fail-on-shortfalls"], 1)
        study = json.loads((directory / "study/study.json").read_text(encoding="utf-8"))
        study["summary"]["missing_trials"] = 0
        (directory / "study/tampered.json").write_text(json.dumps(study), encoding="utf-8")
        run_cli(directory, ["scan", "study", "review", "study/manifest.json",
                            "--verify", "study/tampered.json"], 2)
        smoke_portable_reviews(directory)
        # Invalid configuration must exit before the deliberately nonexistent
        # provider can be imported or contacted, even with fail_on=never.
        (directory / "invalid.yaml").write_text(
            "agent: {model: nonexistent/provider}\ngate: {min_security: .nan}\nfail_on: never\n",
            encoding="utf-8",
        )
        run_cli(directory, ["scan", "--config", "invalid.yaml", "--plan"], 2)
        run_cli(directory, ["init", "--no-workflow"])
        if not (directory / ".dspy-security-bench.yaml").is_file():
            raise RuntimeError("installed init did not create its config")
    print("Installed wheel smoke passed: resources, CLI, offline scan/study/policy replay, "
          "portable bundles, joint-policy exits, pins, tamper rejection, strict configuration, scaffold.")
    return 0


def smoke_portable_reviews(directory: Path) -> None:
    """Exercise recipient workflows without importing the source package here."""
    source_path = directory / "demo/before.json"
    source_bytes = source_path.read_bytes()
    source = json.loads(source_bytes)
    source_pin = source["evidence_sha256"]
    run_cli(directory, ["scan", "policy", "init", "demo/before.json",
                        "--expected-source-sha256", source_pin, "--out", "policy.json"])
    policy_path = directory / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy.update(min_security=0, min_joint_success=1, fail_on="never")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    run_cli(directory, ["scan", "policy", "review", "demo/before.json", "--policy", "policy.json",
                        "--out", "policy-review.json", "--html", "policy.html",
                        "--expected-source-sha256", source_pin, "--fail-on-shortfalls"], 1)
    review = json.loads((directory / "policy-review.json").read_text(encoding="utf-8"))
    if (review["summary"]["reviewed_requirements_met"]
            or review["summary"]["model_calls_performed"] != 0
            or review["summary"]["reviewed_enforcement_status"] != "non_blocking_shortfalls"
            or source_path.read_bytes() != source_bytes):
        raise RuntimeError("policy review changed observations or hid the joint shortfall")
    run_cli(directory, ["scan", "policy", "verify", "policy-review.json",
                        "--expected-source-sha256", source_pin,
                        "--expected-review-sha256", review["review_sha256"], "--html", "policy-replay.html"])
    if (directory / "policy.html").read_bytes() != (directory / "policy-replay.html").read_bytes():
        raise RuntimeError("installed policy HTML does not replay exactly")
    run_cli(directory, ["scan", "policy", "verify", "policy-review.json", "--fail-on-shortfalls"], 1)
    run_cli(directory, ["scan", "policy", "verify", "policy-review.json",
                        "--expected-source-sha256", "0" * 64], 2)
    run_cli(directory, ["scan", "policy", "verify", "policy-review.json",
                        "--expected-review-sha256", "0" * 64], 2)
    # Refuse clobbering even when the existing file happens to be a valid review.
    run_cli(directory, ["scan", "policy", "review", "demo/before.json", "--policy", "policy.json",
                        "--out", "policy-review.json"], 2)
    study = json.loads((directory / "study/study.json").read_text(encoding="utf-8"))
    plan_pin = study["plan"]["plan_sha256"]
    run_cli(directory, ["scan", "study", "bundle", "study/manifest.json",
                        "--expected-plan-sha256", plan_pin, "--out", "bundle.json"])
    bundle = json.loads((directory / "bundle.json").read_text(encoding="utf-8"))
    # A recipient has the bundle only; rename the synthetic source directory so
    # accidental dependence on its paths cannot make this check pass.
    (directory / "study").rename(directory / "retained-study")
    run_cli(directory, ["scan", "study", "verify-bundle", "bundle.json",
                        "--expected-plan-sha256", plan_pin,
                        "--expected-bundle-sha256", bundle["bundle_sha256"], "--html", "bundle.html"])
    run_cli(directory, ["scan", "study", "verify-bundle", "bundle.json", "--fail-on-shortfalls"], 1)
    run_cli(directory, ["scan", "study", "verify-bundle", "bundle.json",
                        "--expected-bundle-sha256", "0" * 64], 2)
    if (directory / "bundle.html").read_bytes() != (directory / "retained-study/replayed.html").read_bytes():
        raise RuntimeError("portable bundle HTML differs from its original study")


if __name__ == "__main__":
    raise SystemExit(main())
