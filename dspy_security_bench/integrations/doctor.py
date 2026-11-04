"""Integration preflight; runtime mode imports and constructs trusted target code."""

from __future__ import annotations

import importlib
import importlib.util
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dspy_security_bench.integrations.catalog import detect_frameworks, get_framework
from dspy_security_bench.integrations.preflight import inspect_workflow, read_manifest, valid_target
from dspy_security_bench.integrations.scaffold import MANIFEST_PATH, WORKFLOW_PATH


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]
    mode: str = "runtime"
    target_import_attempted: bool = False
    factory_calls_attempted: int = 0

    @property
    def passed(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "mode": self.mode,
                "target_import_attempted": self.target_import_attempted,
                "factory_calls_attempted": self.factory_calls_attempted,
                "checks": [asdict(check) for check in self.checks]}


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


class _Discard(io.TextIOBase):
    def write(self, text):
        return len(text)

    def flush(self):
        pass


def run_doctor(root: str | Path = ".", *, agent_import: str | None = None,
               manifest_only: bool = False) -> DoctorReport:
    """Inspect declarations first; only runtime mode may load trusted target code.

    Static failures stop factory imports. Stream redirection and fixed errors
    keep ordinary target prints out of diagnostics; they are not an OS sandbox.
    """
    root = Path(root)
    checks: list[DoctorCheck] = []
    mode = "manifest_only" if manifest_only else "runtime"
    try:
        manifest = read_manifest(root, MANIFEST_PATH)
    except (OSError, ValueError, TypeError):
        checks.append(DoctorCheck("manifest", "fail", "missing or invalid bounded integration manifest; regenerate with integrate or review its typed fields"))
        checks.append(DoctorCheck("agent-contract", "not_checked", "invalid static configuration; target code was not loaded"))
        return DoctorReport(tuple(checks), mode)
    checks.append(DoctorCheck("manifest", "pass", str(MANIFEST_PATH)))
    spec = get_framework(manifest["framework"])
    chosen_import = agent_import if agent_import is not None else manifest["agent"]
    if not valid_target(chosen_import):
        checks.append(DoctorCheck("target", "fail", "target must be a bounded module:callable identifier"))
    if manifest_only:
        checks.append(DoctorCheck("framework", "pass", f"declared framework: {spec.label}; installation not checked"))
    else:
        try:
            detected = {item.key for item, _ in detect_frameworks(root)}
            status = "pass" if spec.key in detected or spec.key == "mcp" else "warn"
            message = spec.label if status == "pass" else f"{spec.label} is not declared in a dependency manifest"
            checks.append(DoctorCheck("framework", status, message))
        except (OSError, ValueError):
            checks.append(DoctorCheck("framework", "fail", "dependency declaration inspection failed; details withheld"))

    if manifest_only:
        checks.append(DoctorCheck("framework-import", "not_checked", "manifest-only mode does not inspect Python import hooks"))
    elif spec.import_name:
        python_incompatible = spec.key == "crewai" and sys.version_info >= (3, 14)
        try:
            available = not python_incompatible and importlib.util.find_spec(spec.import_name) is not None
        except (ImportError, ValueError, AttributeError):
            available = False
        missing = ("CrewAI's current dependency stack requires Python 3.10-3.13" if python_incompatible
                   else f"missing {spec.import_name}; install {spec.package_hint}")
        checks.append(DoctorCheck("framework-import", "pass" if available else "fail", spec.import_name if available else missing))
    else:
        checks.append(DoctorCheck("framework-import", "pass", "custom callback bridge selected"))

    try:
        problems = inspect_workflow(root, WORKFLOW_PATH, manifest, chosen_import)
        checks.append(DoctorCheck("workflow", "fail" if problems else "pass", "; ".join(problems)
                                  if problems else "reusable-workflow declarations agree; hosted execution not checked"))
    except FileNotFoundError:
        checks.append(DoctorCheck("workflow", "warn", f"{WORKFLOW_PATH} not generated"))
    except (OSError, ValueError, TypeError):
        checks.append(DoctorCheck("workflow", "fail", "workflow must be bounded unambiguous YAML in an unlinked regular file; details withheld"))
    immutable = len(manifest["engine_ref"]) == 40 and not manifest["engine_ref"].startswith("v")
    checks.append(DoctorCheck("engine-ref", "pass" if immutable else "warn", "full commit SHA declared; authenticity not checked" if immutable
                              else "version tag declared; tags can move, so use a reviewed full commit SHA for immutable pinning"))

    imported, calls = False, 0
    if manifest_only or any(check.status == "fail" for check in checks):
        checks.append(DoctorCheck("agent-contract", "not_checked", "target imports and factory calls were not attempted"))
    else:
        try:
            with redirect_stdout(_Discard()), redirect_stderr(_Discard()):
                imported = True
                factory = _load_factory(chosen_import, root)
                if not callable(factory):
                    raise TypeError("target is not callable")
                calls += 1
                first = factory()
                calls += 1
                second = factory()
                if first is second:
                    raise TypeError("factory returned the same instance")
                for agent in (first, second):
                    name = getattr(agent, "name", None)
                    if not isinstance(name, str) or not name.strip() or not callable(getattr(agent, "run", None)):
                        raise TypeError("invalid agent contract")
            checks.append(DoctorCheck("agent-contract", "pass", "factory returned two distinct agents with non-empty names and callable run methods"))
        except Exception:
            checks.append(DoctorCheck("agent-contract", "fail", "target import, construction, or fresh-agent contract failed; raw diagnostics withheld"))

    for key in manifest.get("required_env", []):
        if manifest_only:
            checks.append(DoctorCheck(f"credential:{key}", "not_checked", "credential presence not inspected in manifest-only mode"))
            continue
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
    return DoctorReport(tuple(checks), mode, imported, calls)


def render_doctor(report: DoctorReport) -> str:
    lines = []
    icons = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "not_checked": "NOT CHECKED"}
    for check in report.checks:
        lines.append(f"[{icons[check.status]}] {check.name}: {check.message}")
    lines.append("Doctor did not invoke agent.run().")
    lines.append(f"Mode: {report.mode}; target import attempted: {report.target_import_attempted}; factory calls attempted: {report.factory_calls_attempted}.")
    lines.append(f"Verdict: {'CHECKS PASS' if report.passed else 'CHECKS FAILED'}; not a hosted-execution or safety approval.")
    return "\n".join(lines)
