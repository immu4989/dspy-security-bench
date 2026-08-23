"""User-controlled command bridge for real AuthorityTwin backend evidence.

The command receives one canonical JSON document on stdin and must return one backend
response JSON object on stdout. It is started without a shell. Credentials, network
access, backend deployment, and policy remain entirely operator controlled.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any

from dspy_security_bench.authority.benchmark import run_authority_twin, verify_authority_report
from dspy_security_bench.authority.bridges import PolicyEngineAuthorityBridge, get_authority_bridge
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = "AuthorityBridge / Operator-executed backend conformance"
DISCLAIMER = (
    "This report records an operator-supplied command exercising a declared backend and version. "
    "It is self-attested technical conformance evidence, not independent product validation, "
    "certification, compliance, policy correctness, non-repudiation, or an authorization to operate."
)
MAX_RESPONSE_BYTES = 1_000_000


class CommandAuthorityEvaluator:
    """Callable JSON-lines boundary used by :class:`PolicyEngineAuthorityBridge`."""

    def __init__(self, command: str | Sequence[str], *, timeout_seconds: float = 15.0) -> None:
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError("authority backend command must contain at least one argument")
        if not 0.1 <= timeout_seconds <= 120:
            raise ValueError("authority backend timeout must be between 0.1 and 120 seconds")
        self.argv = tuple(argv)
        self.timeout_seconds = float(timeout_seconds)

    @property
    def command_sha256(self) -> str:
        return canonical_sha256(list(self.argv))

    def __call__(self, input_document: Mapping[str, Any]) -> Mapping[str, Any]:
        encoded = json.dumps(input_document, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            completed = subprocess.run(
                self.argv,
                input=encoded,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"backend command could not complete: {type(exc).__name__}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"backend command returned status {completed.returncode}")
        if len(completed.stdout.encode()) > MAX_RESPONSE_BYTES:
            raise RuntimeError("backend command response exceeds 1 MB")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("backend command did not return one JSON object") from exc
        if not isinstance(payload, Mapping):
            raise RuntimeError("backend command JSON response must be an object")
        return dict(payload)


def run_live_bridge_conformance(
    *,
    backend: str,
    backend_version: str,
    command: str | Sequence[str],
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    spec = get_authority_bridge(backend)
    if (
        not isinstance(backend_version, str)
        or not backend_version.strip()
        or len(backend_version) > 128
        or any(ord(char) < 32 for char in backend_version)
    ):
        raise ValueError(
            "backend_version must be a non-empty operator-declared version up to 128 characters"
        )
    evaluator = CommandAuthorityEvaluator(command, timeout_seconds=timeout_seconds)

    def factory() -> PolicyEngineAuthorityBridge:
        return PolicyEngineAuthorityBridge(
            spec.key,
            evaluator,
            name=f"live-{spec.key}-{backend_version.strip()}",
        )

    authority_report = run_authority_twin(factory(), adapter_factory=factory).to_dict()
    payload: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "backend": spec.key,
        "backend_version": backend_version.strip(),
        "execution_mode": "operator-supplied-command-without-shell",
        "command_sha256": evaluator.command_sha256,
        "timeout_seconds": timeout_seconds,
        "authority_report": authority_report,
        "evidence_tier": "self_attested_local_execution",
        "disclaimer": DISCLAIMER,
    }
    payload["report_sha256"] = canonical_sha256(payload)
    return payload


def verify_live_bridge_conformance(payload: Mapping[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema_version",
        "report_type",
        "backend",
        "backend_version",
        "execution_mode",
        "command_sha256",
        "timeout_seconds",
        "authority_report",
        "evidence_tier",
        "disclaimer",
        "report_sha256",
    }
    if set(payload) != fields:
        errors.append("live conformance report fields are incomplete or unsupported")
    if payload.get("schema_version") != 1 or payload.get("report_type") != REPORT_TYPE:
        errors.append("unsupported live conformance report version or type")
    try:
        backend = get_authority_bridge(str(payload.get("backend", ""))).key
    except ValueError as exc:
        errors.append(str(exc))
        backend = None
    version = payload.get("backend_version")
    if (
        not isinstance(version, str)
        or not version.strip()
        or len(version) > 128
        or any(ord(char) < 32 for char in version)
    ):
        errors.append("backend_version must be non-empty and at most 128 characters")
    digest = payload.get("command_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        errors.append("command_sha256 must be a SHA-256 digest")
    timeout = payload.get("timeout_seconds")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0.1 <= timeout <= 120
    ):
        errors.append("timeout_seconds is outside the supported boundary")
    if payload.get("execution_mode") != "operator-supplied-command-without-shell":
        errors.append("unsupported live conformance execution_mode")
    if payload.get("evidence_tier") != "self_attested_local_execution":
        errors.append("unsupported live conformance evidence_tier")
    if payload.get("disclaimer") != DISCLAIMER:
        errors.append("live conformance disclaimer does not match the protocol")
    authority = payload.get("authority_report")
    if not isinstance(authority, Mapping):
        errors.append("authority_report must be an object")
    else:
        errors.extend(f"authority_report: {item}" for item in verify_authority_report(authority))
        if backend and authority.get("adapter") != f"live-{backend}-{str(version).strip()}":
            errors.append("authority_report adapter does not match backend declaration")
        if authority.get("trial_isolation") != "fresh_adapter_per_case":
            errors.append("live conformance requires fresh_adapter_per_case isolation")
    unsigned = dict(payload)
    claimed = unsigned.pop("report_sha256", None)
    try:
        actual = canonical_sha256(unsigned)
    except (TypeError, ValueError):
        actual = None
    if claimed != actual:
        errors.append("report_sha256 does not match canonical report content")
    return tuple(dict.fromkeys(errors))
