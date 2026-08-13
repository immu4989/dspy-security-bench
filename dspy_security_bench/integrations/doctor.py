"""No-model-call preflight checks for BYOA targets and ProofRun workflows."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dspy_security_bench.integrations.catalog import detect_frameworks, get_framework
from dspy_security_bench.integrations.scaffold import MANIFEST_PATH, WORKFLOW_PATH


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "checks": [asdict(check) for check in self.checks]}


def _load_factory(agent_import: str, root: Path):
    if ":" not in agent_import:
        raise ValueError("agent import must be module:callable")
    module_name, callable_name = agent_import.split(":", 1)
    sys.path.insert(0, str(root.resolve()))
    try:
        importlib.invalidate_caches()
        sys.modules.pop(module_name, None)
        module = importlib.import_module(module_name)
        return getattr(module, callable_name)
    finally:
        sys.path.pop(0)


def run_doctor(root: str | Path = ".", *, agent_import: str | None = None) -> DoctorReport:
    root = Path(root)
    checks: list[DoctorCheck] = []
    manifest_file = root / MANIFEST_PATH
    manifest: dict[str, Any] = {}
    if manifest_file.is_file():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            if manifest.get("schema_version") != 1:
                raise ValueError("unsupported schema_version")
            checks.append(DoctorCheck("manifest", "pass", str(MANIFEST_PATH)))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            checks.append(DoctorCheck("manifest", "fail", f"invalid integration manifest: {exc}"))
    else:
        checks.append(DoctorCheck("manifest", "fail", "run `dspy-security-bench integrate` first"))

    framework_name = manifest.get("framework")
    spec = None
    if isinstance(framework_name, str):
        try:
            spec = get_framework(framework_name)
            detected = {item.key for item, _ in detect_frameworks(root)}
            status = "pass" if spec.key in detected or spec.key == "mcp" else "warn"
            message = (
                spec.label
                if status == "pass"
                else f"{spec.label} is not declared in a dependency manifest"
            )
            checks.append(DoctorCheck("framework", status, message))
        except ValueError as exc:
            checks.append(DoctorCheck("framework", "fail", str(exc)))

    required_import = manifest.get("required_import")
    if required_import:
        hint = manifest.get("package_hint", required_import)
        python_incompatible = bool(spec and spec.key == "crewai" and sys.version_info >= (3, 14))
        available = (
            not python_incompatible and importlib.util.find_spec(str(required_import)) is not None
        )
        missing = (
            "CrewAI's current dependency stack requires Python 3.10-3.13"
            if python_incompatible
            else f"missing {required_import}; install {hint}"
        )
        checks.append(
            DoctorCheck(
                "framework-import",
                "pass" if available else "fail",
                str(required_import) if available else missing,
            )
        )
    elif spec and spec.key == "mcp":
        checks.append(DoctorCheck("framework-import", "pass", "custom callback bridge selected"))

    chosen_import = agent_import or manifest.get("agent")
    if isinstance(chosen_import, str):
        try:
            factory = _load_factory(chosen_import, root)
            if not callable(factory):
                raise TypeError("target is not callable")
            first = factory()
            second = factory()
            if first is second:
                raise TypeError("factory returned the same agent instance twice")
            if not isinstance(getattr(first, "name", None), str) or not callable(
                getattr(first, "run", None)
            ):
                raise TypeError("agent must expose non-empty name and callable run")
            checks.append(
                DoctorCheck("agent-contract", "pass", f"{chosen_import} returns fresh agents")
            )
        except Exception as exc:
            checks.append(DoctorCheck("agent-contract", "fail", f"{chosen_import}: {exc}"))
    else:
        checks.append(DoctorCheck("agent-contract", "fail", "no agent import configured"))

    workflow_file = root / WORKFLOW_PATH
    if workflow_file.is_file():
        workflow = workflow_file.read_text(encoding="utf-8")
        problems = []
        if "id-token: write" not in workflow or "attestations: write" not in workflow:
            problems.append("missing attestation permissions")
        if re.search(r"proofrun\.yml@main\b", workflow):
            problems.append("mutable @main engine ref")
        engine_ref = manifest.get("engine_ref")
        if engine_ref and f"proofrun.yml@{engine_ref}" not in workflow:
            problems.append(f"workflow does not use {engine_ref}")
        if chosen_import and f"agent: {chosen_import}" not in workflow:
            problems.append("workflow agent does not match manifest")
        checks.append(
            DoctorCheck(
                "workflow",
                "fail" if problems else "pass",
                "; ".join(problems)
                if problems
                else f"{WORKFLOW_PATH} is pinned and attestation-ready",
            )
        )
    else:
        checks.append(DoctorCheck("workflow", "warn", f"{WORKFLOW_PATH} not generated"))

    for key in manifest.get("required_env", []):
        present = bool(os.environ.get(str(key)))
        checks.append(
            DoctorCheck(
                f"credential:{key}",
                "pass" if present else "warn",
                "set locally"
                if present
                else "not set locally; add it as a GitHub Actions secret before a live run",
            )
        )
    return DoctorReport(tuple(checks))


def render_doctor(report: DoctorReport) -> str:
    lines = []
    icons = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
    for check in report.checks:
        lines.append(f"[{icons[check.status]}] {check.name}: {check.message}")
    lines.append("Doctor did not invoke agent.run().")
    lines.append(f"Verdict: {'READY' if report.passed else 'NOT READY'}")
    return "\n".join(lines)
