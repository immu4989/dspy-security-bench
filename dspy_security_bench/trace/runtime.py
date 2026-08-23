"""Framework-neutral, content-free runtime instrumentation for TraceProof.

The recorder sits at the package's existing ``Agent``/``BenchTool`` boundary,
so the same wrapper works with OpenAI Agents SDK, LangChain/LangGraph,
Pydantic AI, CrewAI, AutoGen, DSPy, MCP callbacks, and custom agents. It never
records the query, system directive, tool arguments, tool result, or provider
credentials.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dspy_security_bench.agents import Agent, AgentResult, BenchTool
from dspy_security_bench.integrations.catalog import detect_frameworks, get_framework

RUNTIME_SCHEMA_VERSION = 1
MAX_RUNTIME_SPANS = 10_000
_IMPORT_TARGET = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*$")
_SECURITY_PREFIXES = ("dsb.auth.", "dsb.approval.", "dsb.effect.", "dsb.delegation.", "dsb.mcp.")


@dataclass(frozen=True)
class RuntimePreset:
    key: str
    label: str
    integration: str
    hook: str
    no_content_boundary: str

    def to_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "label": self.label,
            "integration": self.integration,
            "hook": self.hook,
            "no_content_boundary": self.no_content_boundary,
        }


RUNTIME_PRESETS: tuple[RuntimePreset, ...] = (
    RuntimePreset(
        "openai-agents",
        "OpenAI Agents SDK",
        "OpenAIAgentsAdapter + TraceRecordingAgent",
        "benchmark-owned BenchTool call boundary",
        "no prompts, responses, arguments, or tool results",
    ),
    RuntimePreset(
        "langchain",
        "LangChain / LangGraph",
        "LangChainAdapter + TraceRecordingAgent",
        "benchmark-owned BenchTool call boundary",
        "no messages, state, arguments, or tool results",
    ),
    RuntimePreset(
        "pydantic-ai",
        "Pydantic AI",
        "PydanticAIAdapter + TraceRecordingAgent",
        "benchmark-owned BenchTool call boundary",
        "no prompts, dependencies, arguments, or tool results",
    ),
    RuntimePreset(
        "crewai",
        "CrewAI",
        "CrewAIAdapter + TraceRecordingAgent",
        "benchmark-owned BenchTool call boundary",
        "no tasks, backstory, arguments, or tool results",
    ),
    RuntimePreset(
        "autogen",
        "Microsoft AutoGen AgentChat",
        "AutoGenAdapter + TraceRecordingAgent",
        "benchmark-owned BenchTool call boundary",
        "no messages, events, arguments, or tool results",
    ),
    RuntimePreset(
        "dspy",
        "DSPy / ReActV2",
        "Agent protocol + TraceRecordingAgent",
        "benchmark-owned BenchTool call boundary",
        "no signatures, prompts, arguments, or tool results",
    ),
    RuntimePreset(
        "mcp",
        "MCP or custom loop",
        "CallbackAdapter + TraceRecordingAgent",
        "local callable tool boundary",
        "no JSON-RPC content, arguments, results, or tokens",
    ),
)
_PRESET_KEYS = {item.key for item in RUNTIME_PRESETS}


class TraceRecorder:
    """Small in-process OTLP JSON recorder with a strict metadata-only contract."""

    def __init__(self, *, service_name: str = "traceproof-instrumented-agent") -> None:
        if not _safe_name(service_name):
            raise ValueError("TraceRecorder service_name must use safe identifier characters")
        self.service_name = service_name
        self._trace_id = secrets.token_hex(16)
        self._spans: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def span_count(self) -> int:
        return len(self._spans)

    def record(
        self,
        *,
        operation: str,
        agent_name: str,
        tool_name: str | None = None,
        security_attributes: Mapping[str, Any] | None = None,
        parent_span_id: str | None = None,
        span_id: str | None = None,
        started_ns: int | None = None,
        ended_ns: int | None = None,
        status: str = "OK",
        error_type: str | None = None,
    ) -> str:
        """Record one metadata-only span; arbitrary application attributes are rejected."""

        if not _safe_name(operation) or not _safe_name(agent_name):
            raise ValueError("runtime operation and agent_name must use safe identifier characters")
        if tool_name is not None and not _safe_name(tool_name):
            raise ValueError("runtime tool_name must use safe identifier characters")
        if parent_span_id is not None and not re.fullmatch(r"[0-9a-f]{16}", parent_span_id):
            raise ValueError("runtime parent_span_id must be a 16-character lowercase hex value")
        if span_id is not None and not re.fullmatch(r"[0-9a-f]{16}", span_id):
            raise ValueError("runtime span_id must be a 16-character lowercase hex value")
        attributes = {
            "gen_ai.operation.name": operation,
            "gen_ai.agent.name": agent_name,
        }
        if tool_name is not None:
            attributes["gen_ai.tool.name"] = tool_name
        for key, value in dict(security_attributes or {}).items():
            if not isinstance(key, str) or not key.startswith(_SECURITY_PREFIXES):
                raise ValueError(f"runtime security attribute {key!r} is outside the dsb namespace")
            attributes[key] = _bounded_security_value(value)
        if error_type:
            attributes["error.type"] = _safe_error_type(error_type)
        start = time.time_ns() if started_ns is None else int(started_ns)
        end = time.time_ns() if ended_ns is None else int(ended_ns)
        if start < 0 or end < start:
            raise ValueError("runtime span timestamps must be ordered non-negative integers")
        span_id = span_id or secrets.token_hex(8)
        span = {
            "traceId": self._trace_id,
            "spanId": span_id,
            "name": operation,
            "kind": 3 if tool_name else 1,
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(end),
            "status": {"code": "STATUS_CODE_ERROR" if status == "ERROR" else "STATUS_CODE_OK"},
            "attributes": _otlp_attributes(attributes),
        }
        if parent_span_id:
            span["parentSpanId"] = parent_span_id
        with self._lock:
            if len(self._spans) >= MAX_RUNTIME_SPANS:
                raise RuntimeError("TraceRecorder reached the 10000-span boundary")
            self._spans.append(span)
        return span_id

    def to_otlp_json(self) -> dict[str, Any]:
        with self._lock:
            spans = json.loads(json.dumps(self._spans, ensure_ascii=False, allow_nan=False))
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": _otlp_attributes({"service.name": self.service_name})
                    },
                    "scopeSpans": [
                        {
                            "scope": {
                                "name": "dspy_security_bench.trace.runtime",
                                "version": str(RUNTIME_SCHEMA_VERSION),
                            },
                            "spans": spans,
                        }
                    ],
                }
            ]
        }

    def write(self, path: str | Path) -> Path:
        """Atomically write metadata-only OTLP JSON to an operator-chosen local path."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_otlp_json(), indent=2, sort_keys=True) + "\n"
        if len(payload.encode()) > 50 * 1024 * 1024:
            raise RuntimeError("TraceRecorder output exceeds the 50 MiB TraceProof boundary")
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(payload, encoding="utf-8")
            temporary.replace(destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return destination


class TraceRecordingAgent:
    """Wrap any framework-neutral Agent and record only its tool boundary metadata."""

    def __init__(
        self,
        agent: Agent,
        *,
        output_path: str | Path,
        security_context: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
        service_name: str | None = None,
    ) -> None:
        if not isinstance(getattr(agent, "name", None), str) or not agent.name:
            raise TypeError("TraceRecordingAgent requires a named Agent")
        self.agent = agent
        self.name = f"trace-recording:{agent.name}"
        self.output_path = Path(output_path)
        self.security_context = security_context or _unclassified_security_context
        self.recorder = TraceRecorder(service_name=service_name or _safe_service_name(agent.name))

    def run(self, query: str, tools: list[BenchTool], *, system_directive: str = "") -> AgentResult:
        started = time.time_ns()
        parent_id = secrets.token_hex(8)
        wrapped = [self._wrap_tool(tool, parent_id) for tool in tools]
        try:
            result = self.agent.run(query, wrapped, system_directive=system_directive)
        except Exception as exc:
            self.recorder.record(
                operation="invoke_agent",
                agent_name=_safe_service_name(self.agent.name),
                span_id=parent_id,
                started_ns=started,
                ended_ns=time.time_ns(),
                status="ERROR",
                error_type=type(exc).__name__,
            )
            self.recorder.write(self.output_path)
            raise
        self.recorder.record(
            operation="invoke_agent",
            agent_name=_safe_service_name(self.agent.name),
            span_id=parent_id,
            started_ns=started,
            ended_ns=time.time_ns(),
        )
        self.recorder.write(self.output_path)
        return result

    def _wrap_tool(self, tool: BenchTool, parent_id: str) -> BenchTool:
        def invoke(**arguments) -> str:
            started = time.time_ns()
            try:
                context = self.security_context(tool.name, arguments)
                if not isinstance(context, Mapping):
                    raise TypeError("security_context must return a mapping")
                result = tool(**arguments)
            except Exception as exc:
                self.recorder.record(
                    operation="execute_tool",
                    agent_name=_safe_service_name(self.agent.name),
                    tool_name=_safe_service_name(tool.name),
                    security_attributes=context if "context" in locals() else {},
                    parent_span_id=parent_id,
                    started_ns=started,
                    ended_ns=time.time_ns(),
                    status="ERROR",
                    error_type=type(exc).__name__,
                )
                raise
            self.recorder.record(
                operation="execute_tool",
                agent_name=_safe_service_name(self.agent.name),
                tool_name=_safe_service_name(tool.name),
                security_attributes=context,
                parent_span_id=parent_id,
                started_ns=started,
                ended_ns=time.time_ns(),
            )
            return result

        return BenchTool(
            name=tool.name,
            description=tool.description,
            parameters=tool.parameters,
            _call=invoke,
        )


def runtime_doctor(root: str | Path = ".", *, framework: str | None = None) -> dict[str, Any]:
    """Inspect manifests only; never import or execute the target agent."""

    path = Path(root)
    detected = detect_frameworks(path)
    detected_keys = [item.key for item, _ in detected]
    selected = get_framework(framework).key if framework else None
    if selected == "mcp":
        selected = "mcp"
    checks = [
        {
            "name": "project-root",
            "status": "pass" if path.is_dir() else "fail",
            "detail": str(path.resolve()),
        },
        {
            "name": "framework-declaration",
            "status": "pass"
            if selected in detected_keys or (not selected and detected_keys)
            else "warn",
            "detail": ", ".join(detected_keys)
            if detected_keys
            else "no supported direct dependency detected",
        },
        {
            "name": "content-boundary",
            "status": "pass",
            "detail": "TraceRecordingAgent omits queries, directives, arguments, results, and credentials",
        },
    ]
    policy = path / "traceproof-redaction.yaml"
    checks.append(
        {
            "name": "redaction-policy",
            "status": "pass" if policy.is_file() else "warn",
            "detail": str(policy)
            if policy.is_file()
            else "run trace init-policy and review the allowlist",
        }
    )
    return {
        "schema_version": 1,
        "runtime": "TraceProof Runtime Kit",
        "selected_framework": selected,
        "detected_frameworks": detected_keys,
        "checks": checks,
        "ready": all(item["status"] != "fail" for item in checks),
        "non_execution_claim": "manifest inspection only; no agent, model, tool, or credential was loaded",
    }


def runtime_scaffold(
    agent_import: str, *, output_path: str = "artifacts/traceproof-otlp.json"
) -> str:
    if not _IMPORT_TARGET.fullmatch(agent_import):
        raise ValueError("runtime agent target must use module:callable")
    module, factory = agent_import.split(":", 1)
    return f'''"""Generated TraceProof runtime boundary. Review before production use."""

from {module} import {factory}
from dspy_security_bench.trace.runtime import TraceRecordingAgent


def security_context(tool_name, arguments):
    # Arguments are available to your local policy lookup but are never recorded.
    # Replace this explicit unknown decision with evidence from your authority plane.
    return {{"dsb.auth.required": True, "dsb.auth.decision": "unknown"}}


def build_traced_agent():
    return TraceRecordingAgent(
        {factory}(),
        output_path={output_path!r},
        security_context=security_context,
    )
'''


def runtime_catalog() -> list[dict[str, str]]:
    return [item.to_dict() for item in RUNTIME_PRESETS]


def _unclassified_security_context(
    tool_name: str, arguments: Mapping[str, Any]
) -> Mapping[str, Any]:
    return {"dsb.auth.required": True, "dsb.auth.decision": "unknown"}


def _safe_name(value: str) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value))


def _safe_service_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.:/-]", "-", str(value))[:128]
    return normalized or "agent"


def _safe_error_type(value: str) -> str:
    return _safe_service_name(value)


def _bounded_security_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and value != value:
            raise ValueError("runtime security attributes cannot contain NaN")
        return value
    if isinstance(value, str):
        if len(value) > 512:
            raise ValueError("runtime security string attributes are limited to 512 characters")
        return value
    if isinstance(value, (list, tuple)) and len(value) <= 64:
        return [_bounded_security_value(item) for item in value]
    raise ValueError("runtime security attributes must be bounded scalar or scalar-array values")


def _otlp_attributes(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    attributes = []
    for key, value in values.items():
        if isinstance(value, bool):
            wrapped = {"boolValue": value}
        elif isinstance(value, list):
            wrapped = {"arrayValue": {"values": [_otlp_scalar(item) for item in value]}}
        elif isinstance(value, int):
            wrapped = {"intValue": str(value)}
        elif isinstance(value, float):
            wrapped = {"doubleValue": value}
        else:
            wrapped = {"stringValue": str(value)}
        attributes.append({"key": key, "value": wrapped})
    return attributes


def _otlp_scalar(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}
