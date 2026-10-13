"""Exercise an installed wheel outside the checkout, without provider calls.

Run using the interpreter into which the wheel was installed. This is a release
smoke check, not a dependency-resolution test or an operating-system sandbox.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

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
             "scan-policy-review.schema.json", "repeat-report.schema.json", "proofrun-review.schema.json",
             "proofrun-collection-plan.schema.json", "proofrun-collection-review.schema.json",
             "proofrun-plan-comparison.schema.json", "proofrun-collection-requirements.schema.json",
             "proofrun-plan-preparation.schema.json"):
    json.loads(resources.joinpath("schemas", name).read_text(encoding="utf-8"))
if "workflow_dispatch" not in resources.joinpath("templates", "github-action.yml").read_text(encoding="utf-8"):
    raise RuntimeError("safe workflow template missing from installed wheel")
if sys.argv[1:] == ["--version"]:
    from dspy_security_bench.processio import BoundedProcessError, run_bounded
    result = run_bounded([sys.executable, "-I", "-c", "import os; os.write(1, b'[]')"],
                         maximum_stdout=2, timeout=5)
    if result.returncode != 0 or result.stdout != b"[]":
        raise RuntimeError("installed bounded collector changed exact stdout")
    try:
        run_bounded([sys.executable, "-I", "-c", "import os; os.write(1, b'x' * 10000)"],
                    maximum_stdout=20, timeout=5)
    except BoundedProcessError:
        pass
    else:
        raise RuntimeError("installed bounded collector accepted overflow")
raise SystemExit(entry[0].load()(sys.argv[1:]))
'''


def run_cli(directory: Path, arguments: list[str], expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, "-I", "-c", BOOTSTRAP, *arguments],
        cwd=directory, capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"installed CLI {arguments[:2]!r}: expected exit {expected}, got {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout


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
        run_cli(directory, ["scan", "compare", "demo/before.json", "demo/after.json",
                            "--max-new-joint-failures", "0", "--json", "joint-comparison.json",
                            "--fail-on-regression"], 1)
        run_cli(directory, ["scan", "compare", "demo/before.json", "demo/after.json",
                            "--max-new-joint-failures", "0", "--verify", "joint-comparison.json"])
        run_cli(directory, ["scan", "compare", "demo/before.json", "demo/after.json",
                            "--verify", "joint-comparison.json"], 2)
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
        run_cli(directory, ["impact", "repeat", "--agent",
                            "dspy_security_bench.procurement.agents:build_bounded_reference",
                            "--trials", "2", "--json", "repeat.json"])
        submission = ["--submitter", "fictional-wheel-smoke",
                      "--agent-source", "https://example.com/fictional-wheel-smoke"]
        run_cli(directory, ["impact", "submit-result", "repeat.json", *submission,
                            "--out", "repeat-bundle.json"])
        # Reference fixtures intentionally cannot qualify as community results.
        run_cli(directory, ["impact", "verify", "repeat-bundle.json", "--minimum-trials", "2"], 1)
        file_pin = hashlib.sha256((directory / "repeat-bundle.json").read_bytes()).hexdigest()
        decision = json.loads(run_cli(directory, ["proofrun", "verify", "repeat-bundle.json", "--offline", "--json",
                            "--expected-file-sha256", file_pin], 1))
        if (decision["exit_code"] != 1 or decision["reason_code"] != "not_eligible"
                or decision["input_file_sha256"] != file_pin or decision["provenance"] != "not_checked"
                or decision["review_is_attestation"] is not False):
            raise RuntimeError("installed structured review confused evidence eligibility with authentication")
        run_cli(directory, ["proofrun", "verify", "repeat-bundle.json", "--offline",
                            "--expected-file-sha256", "0" * 64], 2)
        (directory / "ambiguous-bundle.json").write_text('{"private":1,"private":2}', encoding="utf-8")
        run_cli(directory, ["proofrun", "verify", "ambiguous-bundle.json", "--offline"], 2)
        run_cli(directory, ["impact", "sharing-review", "repeat-bundle.json",
                            "--out", "sharing-review.json"])
        run_cli(directory, ["impact", "sharing-review", "repeat-bundle.json",
                            "--verify", "sharing-review.json"])
        run_cli(directory, ["impact", "sharing-review", "repeat-bundle.json",
                            "--out", "sharing-review.json"], 2)
        invalid_metadata = json.loads((directory / "repeat-bundle.json").read_text(encoding="utf-8"))
        invalid_metadata["producer"]["python_version"] = False
        invalid_metadata.pop("bundle_sha256")
        invalid_metadata["bundle_sha256"] = hashlib.sha256(json.dumps(
            invalid_metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode()).hexdigest()
        (directory / "invalid-metadata.json").write_text(json.dumps(invalid_metadata), encoding="utf-8")
        run_cli(directory, ["proofrun", "verify", "invalid-metadata.json", "--offline"], 2)
        run_cli(directory, ["impact", "sharing-review", "invalid-metadata.json",
                            "--out", "invalid-metadata-review.json"], 2)
        if (directory / "invalid-metadata-review.json").exists():
            raise RuntimeError("invalid submission metadata was admitted to a verified review")
        repeat = json.loads((directory / "repeat.json").read_text(encoding="utf-8"))
        repeat["trials"][0]["pairs"][0]["causal_evidence"]["recommended_control"]["action"] = "allow"
        (directory / "repeat-altered.json").write_text(json.dumps(repeat), encoding="utf-8")
        run_cli(directory, ["impact", "submit-result", "repeat-altered.json", *submission,
                            "--out", "invalid-repeat-bundle.json"], 2)
        if (directory / "invalid-repeat-bundle.json").exists():
            raise RuntimeError("inconsistent retained evidence was published as a bundle")
        run_cli(directory, ["impact", "control-demo", "--json", "control.json"])
        run_cli(directory, ["impact", "control-verify", "control.json"])
        run_cli(directory, ["impact", "control-repeat-demo", "--trials", "2", "--confidence", "0.8",
                            "--json", "control-repeat.json"])
        run_cli(directory, ["impact", "control-repeat-verify", "control-repeat.json"])
        run_cli(directory, ["impact", "control-submit", "control-repeat.json", *submission,
                            "--policy-source", "https://example.com/synthetic-policy",
                            "--out", "control-bundle.json"])
        run_cli(directory, ["impact", "control-card", "control-bundle.json", "--out", "control-card.svg"])
        card = (directory / "control-card.svg").read_text(encoding="utf-8")
        if card.count("80% Wilson") != 3 or "95% Wilson" in card:
            raise RuntimeError("installed card does not display its retained confidence level")
        control = json.loads((directory / "control.json").read_text(encoding="utf-8"))
        control["pairs"][0]["policy_events"][0]["index"] = False
        control.pop("report_sha256")
        control["report_sha256"] = hashlib.sha256(json.dumps(
            control, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode()).hexdigest()
        (directory / "control-altered.json").write_text(json.dumps(control), encoding="utf-8")
        run_cli(directory, ["impact", "control-verify", "control-altered.json"], 2)
        run_cli(directory, ["impact", "review-demo", "--out", "synthetic-handoff"])
        handoff = directory / "synthetic-handoff"
        run_cli(handoff, ["impact", "control-repeat-verify", "report.json"])
        run_cli(handoff, ["impact", "control-submission-verify", "bundle.json"], 1)
        run_cli(handoff, ["impact", "sharing-review", "bundle.json", "--verify", "sharing-review.json"])
        run_cli(handoff, ["impact", "control-submission-verify", "invalid-bundle.json"], 1)
        run_cli(directory, ["impact", "review-demo", "--out", "synthetic-handoff"], 2)
        proofrun = ["proofrun", "run", "--agent",
                    "dspy_security_bench.procurement.agents:build_bounded_reference",
                    "--trials", "2", *submission,
                    "--out", "proofrun-bundle.json", "--report-out", "proofrun-report.json"]
        run_cli(directory, proofrun)
        retained = {name: (directory / name).read_bytes()
                    for name in ("proofrun-bundle.json", "proofrun-report.json")}
        run_cli(directory, proofrun, 2)
        if any((directory / name).read_bytes() != content for name, content in retained.items()):
            raise RuntimeError("ProofRun replaced retained evidence")
        run_cli(directory, [*proofrun[:-4], "--out", "collision.json", "--report-out", "collision.json"], 2)
        if (directory / "collision.json").exists():
            raise RuntimeError("ProofRun admitted colliding output files")
        for command, target in (
            ("incident", ["--agent", "dspy_security_bench.incident.agents:build_bounded_reference"]),
            ("source", ["--agent", "dspy_security_bench.mission.agents:build_bounded_source_reference"]),
            ("authority", ["--reference", "bounded"]),
        ):
            source_flag = "--adapter-source" if command == "authority" else "--agent-source"
            output = f"{command}-bundle.json"
            run_cli(directory, ["proofrun", command, *target, "--trials", "2",
                                "--submitter", "fictional-wheel-smoke", source_flag,
                                "https://example.com/synthetic", "--out", output])
            decision = json.loads(run_cli(directory, ["proofrun", "verify", output, "--offline", "--json"], 1))
            if decision["integrity"] != "valid" or decision["eligibility"] != "ineligible":
                raise RuntimeError("installed reference evidence must be valid but registry-ineligible")
            bundle = json.loads((directory / output).read_text(encoding="utf-8"))
            bundle["submission"]["submitter"] = None
            bundle.pop("bundle_sha256")
            bundle["bundle_sha256"] = hashlib.sha256(json.dumps(
                bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
            ).encode()).hexdigest()
            altered = f"{command}-bad-metadata.json"
            (directory / altered).write_text(json.dumps(bundle), encoding="utf-8")
            decision = json.loads(run_cli(directory, ["proofrun", "verify", altered, "--offline", "--json"], 2))
            if decision["integrity"] != "invalid" or decision["bundle_sha256"] is not None:
                raise RuntimeError("installed verifier accepted rehashed malformed metadata")
        smoke_structural_reviews(directory)
        smoke_collection_reviews(directory)
        smoke_junit_reviews(directory)
        smoke_html_reviews(directory)
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
          "portable bundles, procurement consistency, structural/collection reviews, joint-policy exits, pins, tamper rejection, strict configuration, scaffold.")
    return 0


def smoke_structural_reviews(directory: Path) -> None:
    """Create each structural family through installed CLI, then review it."""
    metadata = ["--submitter", "fictional-wheel-smoke", "--runtime", "synthetic",
                "--source-repository", "https://example.com/synthetic"]
    run_cli(directory, ["trace", "demo", "--out-dir", "trace"])
    run_cli(directory, ["trace", "bundle", "trace/trace-evidence.json", "trace/trace-report.json",
                        *metadata, "--out", "trace-bundle.json"])
    run_cli(directory, ["causal", "init", "--trace-out", "causal-trace.json", "--manifest-out", "causal-manifest.json"])
    run_cli(directory, ["causal", "bundle", "causal-trace.json", "causal-manifest.json",
                        *metadata, "--out", "causal-bundle.json"])
    run_cli(directory, ["collective", "plane", "init", "--out", "collective-scenario.json"])
    run_cli(directory, ["collective", "plane", "bundle", "collective-scenario.json", *metadata,
                        "--deployment-class", "synthetic", "--out", "collective-bundle.json"])
    run_cli(directory, ["defend", "demo", "--mission", "community-hospital", "--out-dir", "defense"])
    run_cli(directory, ["defend", "bundle", "defense/community-hospital-bounded-reference.report.json", *metadata,
                        "--deployment-class", "synthetic", "--out", "defense-bundle.json"])
    for family in ("trace", "causal", "collective", "defense"):
        output = f"{family}-bundle.json"
        pin = hashlib.sha256((directory / output).read_bytes()).hexdigest()
        # The known TraceProof demo is deliberately registry-ineligible.
        expected = 1 if family == "trace" else 0
        review = json.loads(run_cli(directory, ["proofrun", "verify", output, "--structural", "--offline", "--json",
                                                "--expected-file-sha256", pin], expected))
        if (review["integrity"] != "valid" or review["policy"]["minimum_trials"] is not None
                or review["evidence_tier"] != "self_attested" or review["provenance"] != "not_checked"
                or review["input_file_sha256"] != pin):
            raise RuntimeError("installed structural review confused integrity, trials, or provenance")
        mismatch = json.loads(run_cli(directory, ["proofrun", "verify", output, "--offline", "--json"], 2))
        if mismatch["reason_code"] != "policy_not_applicable":
            raise RuntimeError("installed reviewer silently discarded the repeated-trial policy")


def smoke_collection_reviews(directory: Path) -> None:
    entries = {}
    for family in ("collective", "defense", "trace"):
        path = directory / f"{family}-bundle.json"
        raw = path.read_bytes()
        entries[family] = {
            "id": family, "path": path.name, "bundle_type": json.loads(raw)["bundle_type"],
            "file_sha256": hashlib.sha256(raw).hexdigest(),
            "policy": {"minimum_trials": None, "offline": True, "attestation_repository": None,
                       "require_trusted_builder": False, "allow_self_hosted_runner": False},
        }
    plan = {"schema_version": 1, "plan_type": "ProofRun review collection plan",
            "entries": [entries["collective"], entries["defense"]]}
    path = directory / "collection-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    requirements = {"schema_version": 1, "requirements_type": "ProofRun collection requirements",
                    "entries": [{k: v for k, v in entry.items() if k != "file_sha256"} for entry in plan["entries"]]}
    requirements_path = directory / "collection-requirements.json"
    requirements_path.write_text(json.dumps(requirements), encoding="utf-8")
    requirements_pin = hashlib.sha256(requirements_path.read_bytes()).hexdigest()
    prepare_args = ["proofrun", "prepare-plan", requirements_path.name, "--out", "prepared-collection.json", "--json"]
    run_cli(directory, [*prepare_args, "--expected-requirements-file-sha256", "0" * 64], 2)
    draft = directory / "prepared-collection.json"
    if draft.exists():
        raise RuntimeError("installed preparation wrote a draft after a requirements-pin mismatch")
    receipt = json.loads(run_cli(directory, [*prepare_args, "--expected-requirements-file-sha256", requirements_pin]))
    draft_bytes = draft.read_bytes()
    if (json.loads(draft_bytes) != plan or receipt["plan_file_sha256"] != hashlib.sha256(draft_bytes).hexdigest()
            or receipt["artifact_evidence_verified"] or receipt["plan_is_approved"]):
        raise RuntimeError("installed preparation changed owner policy, exact-byte pins, or claim boundaries")
    run_cli(directory, prepare_args, 2)
    if draft.read_bytes() != draft_bytes:
        raise RuntimeError("installed preparation overwrote an existing plan")
    run_cli(directory, ["proofrun", "verify-collection", draft.name,
                        "--expected-plan-file-sha256", receipt["plan_file_sha256"], "--json"])
    baseline = directory / "baseline-plan.json"
    baseline.write_bytes(path.read_bytes())
    comparison_args = ["proofrun", "compare-plans", baseline.name, path.name,
                       "--expected-baseline-file-sha256", pin, "--json"]
    comparison = json.loads(run_cli(directory, comparison_args))
    if comparison["reason_code"] != "unchanged" or comparison["artifact_evidence_verified"]:
        raise RuntimeError("installed plan comparison changed its no-evidence-verification contract")
    run_cli(directory, ["proofrun", "compare-plans", baseline.name, path.name,
                        "--expected-baseline-file-sha256", "0" * 64, "--json"], 2)
    result = json.loads(run_cli(directory, ["proofrun", "verify-collection", path.name, "--json",
                                            "--expected-plan-file-sha256", pin]))
    if result["summary"] != {"required": 2, "reviewed": 2, "passed": 2, "not_passed": 0, "invalid": 0}:
        raise RuntimeError("installed collection did not review every required entry")
    smoke_collection_snapshot(directory, path, plan, pin)
    run_cli(directory, ["proofrun", "verify-collection", path.name, "--expected-plan-file-sha256", "0" * 64], 2)
    plan["entries"].insert(1, entries["trace"])
    path.write_text(json.dumps(plan), encoding="utf-8")
    comparison = json.loads(run_cli(directory, comparison_args, 1))
    if comparison["summary"]["added"] != 1 or comparison["summary"]["modified"] != 1:
        raise RuntimeError("installed plan comparison hid an added or reordered evidence slot")
    result = json.loads(run_cli(directory, ["proofrun", "verify-collection", path.name, "--json"], 1))
    if result["summary"]["not_passed"] != 1 or result["summary"]["passed"] != 2:
        raise RuntimeError("installed collection silently admitted ineligible reference evidence")
    plan["entries"][1]["path"] = "missing-trace.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    result = json.loads(run_cli(directory, ["proofrun", "verify-collection", path.name, "--json"], 2))
    if result["summary"]["invalid"] != 1 or result["summary"]["passed"] != 2:
        raise RuntimeError("installed collection omitted missing evidence or skipped later entries")


def smoke_collection_snapshot(directory: Path, path: Path, plan: dict, pin: str) -> None:
    args = ["proofrun", "snapshot-collection", path.name, "--out", "handoff", "--json"]
    run_cli(directory, [*args, "--expected-plan-file-sha256", "0" * 64], 2)
    receipt = json.loads(run_cli(directory, [*args, "--expected-plan-file-sha256", pin]))
    transfer = directory / "handoff"
    if (not receipt["snapshot_complete"] or receipt["snapshot_is_redacted"] or receipt["artifact_evidence_verified"]
            or (transfer / "collection-plan.json").read_bytes() != path.read_bytes()):
        raise RuntimeError("installed snapshot changed exact bytes or claim boundaries")
    run_cli(directory, [*args, "--expected-plan-file-sha256", pin], 2)
    originals = [(directory / entry["path"], (directory / entry["path"]).read_bytes()) for entry in plan["entries"]]
    try:
        for original, raw in originals:
            if (transfer / original.relative_to(directory)).read_bytes() != raw:
                raise RuntimeError("installed snapshot rewrote artifact bytes")
            original.write_bytes(b"synthetic source unavailable")
        run_cli(directory, ["proofrun", "verify-collection", "handoff/collection-plan.json",
                            "--expected-plan-file-sha256", pin, "--json"])
    finally:
        for original, raw in originals:
            original.write_bytes(raw)
    (transfer / plan["entries"][0]["path"]).write_bytes(b"synthetic recipient tampering")
    result = json.loads(run_cli(directory, ["proofrun", "verify-collection", "handoff/collection-plan.json",
                                           "--expected-plan-file-sha256", pin, "--json"], 2))
    if result["entries"][0]["status"] != "pin_mismatch" or result["summary"]["passed"] != 1:
        raise RuntimeError("installed snapshot recipient accepted substituted evidence or omitted another slot")


def smoke_junit_reviews(directory: Path) -> None:
    for path, code in (("collective-bundle.json", 0), ("trace-bundle.json", 1), ("missing.json", 2)):
        source = run_cli(directory, ["proofrun", "verify", path, "--structural", "--offline", "--junit"], code)
        suite = ET.fromstring(source).find("testsuite")
        if (suite.get("tests") != "1" or suite.get("failures") != str(int(code == 1))
                or suite.get("errors") != str(int(code == 2))):
            raise RuntimeError("installed JUnit presentation changed an individual evidence verdict")
    for options, required in (([], "3"), (["--expected-plan-file-sha256", "0" * 64], "1")):
        source = run_cli(directory, ["proofrun", "verify-collection", "collection-plan.json", "--junit", *options], 2)
        suite = ET.fromstring(source).find("testsuite")
        if suite.get("tests") != required or suite.get("errors") != "1" or suite.get("skipped") != "0":
            raise RuntimeError("installed JUnit presentation hid missing required evidence or plan rejection")


def smoke_html_reviews(directory: Path) -> None:
    for path, code in (("collective-bundle.json", 0), ("trace-bundle.json", 1), ("missing.json", 2)):
        source = run_cli(directory, ["proofrun", "verify", path, "--structural", "--offline", "--html"], code)
        if (not source.startswith("<!doctype html>") or f"Native exit code {code}" not in source
                or source.count('<details class="entry"') != 1 or "<script" in source):
            raise RuntimeError("installed HTML presentation changed an individual evidence verdict")
    for options, required in (([], 3), (["--expected-plan-file-sha256", "0" * 64], 0)):
        source = run_cli(directory, ["proofrun", "verify-collection", "collection-plan.json", "--html", *options], 2)
        if ("Native exit code 2" not in source or source.count('<details class="entry"') != required
                or (required == 0 and "No evidence reviewed" not in source)):
            raise RuntimeError("installed HTML presentation hid missing required evidence or plan rejection")


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
