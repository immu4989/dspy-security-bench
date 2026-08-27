"""Privacy-bounded runtime bridges for CausalProof.

The bridges read runtime structure and operator-supplied atomic event bindings.
They deliberately never inspect prompts, model responses, graph state, tool
arguments, tool results, native span payloads, errors, or arbitrary metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dspy_security_bench.causal.proof import MAX_SPANS, validate_manifest

try:  # Optional SDK: the core package remains dependency-light.
    from agents.tracing import TracingProcessor as _OpenAITracingProcessor
except ImportError:  # pragma: no cover - exercised by the default dependency set

    class _OpenAITracingProcessor:  # type: ignore[no-redef]
        pass


try:  # Optional SDK: LangGraph installs langchain-core.
    from langchain_core.callbacks import BaseCallbackHandler as _LangChainCallback
except ImportError:  # pragma: no cover - exercised by the default dependency set

    class _LangChainCallback:  # type: ignore[no-redef]
        pass


INTEGRATIONS: tuple[dict[str, str], ...] = (
    {
        "key": "openai-agents",
        "label": "OpenAI Agents SDK",
        "hook": "TracingProcessor",
        "structural_source": "trace_id, span_id, parent_id, started_at, ended_at",
        "content_boundary": "span_data, errors, trace metadata, prompts, and tool I/O are ignored",
    },
    {
        "key": "langgraph",
        "label": "LangGraph",
        "hook": "BaseCallbackHandler",
        "structural_source": "run_id, parent_run_id, langgraph_node, callback lifecycle",
        "content_boundary": "graph inputs, outputs, state, messages, errors, and tool I/O are ignored",
    },
)
_INTEGRATION_KEYS = {item["key"] for item in INTEGRATIONS}


class CausalRuntimeSession:
    """Collect structural spans and explicit ScheduleProof event bindings.

    Native runtime identifiers are deterministically pseudonymized into W3C-sized
    lowercase hexadecimal identifiers. The session does not accept arbitrary
    span attributes or application payloads.
    """

    def __init__(
        self,
        *,
        scenario_id: str,
        title: str,
        description: str,
        invariants: Sequence[str],
        asserted_edges: Sequence[Mapping[str, str]] = (),
        max_schedules: int = 100_000,
    ) -> None:
        self.scenario_id = scenario_id
        self.title = title
        self.description = description
        self.invariants = list(invariants)
        self.asserted_edges = [dict(item) for item in asserted_edges]
        self.max_schedules = max_schedules
        self._spans: dict[tuple[str, str], dict[str, Any]] = {}
        self._bindings: dict[tuple[str, str], dict[str, Any]] = {}
        self._event_keys: dict[str, tuple[str, str]] = {}
        self._failures: list[str] = []
        self._lock = threading.RLock()

    @property
    def span_count(self) -> int:
        with self._lock:
            return len(self._spans)

    @property
    def binding_count(self) -> int:
        with self._lock:
            return len(self._bindings)

    def capture_span(
        self,
        *,
        trace_id: object,
        span_id: object,
        parent_span_id: object | None,
        started_ns: int,
        ended_ns: int,
    ) -> tuple[str, str]:
        """Capture only identity, parentage, and timestamps from one runtime span."""

        start, end = int(started_ns), int(ended_ns)
        if start < 0 or end < start:
            raise ValueError("runtime span timestamps must be ordered non-negative integers")
        native_trace, native_span = _native_id(trace_id), _native_id(span_id)
        key = (_trace_id(native_trace), _span_id(native_span))
        parent = _span_id(_native_id(parent_span_id)) if parent_span_id is not None else None
        payload: dict[str, Any] = {
            "traceId": key[0],
            "spanId": key[1],
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(end),
        }
        if parent:
            payload["parentSpanId"] = parent
        with self._lock:
            if key not in self._spans and len(self._spans) >= MAX_SPANS:
                raise RuntimeError(f"CausalProof runtime session reached {MAX_SPANS} spans")
            existing = self._spans.get(key)
            if existing is not None and existing != payload:
                raise ValueError("one runtime span identity was observed with conflicting structure")
            self._spans[key] = payload
        return key

    def bind_event(
        self, *, trace_id: object, span_id: object, event: Mapping[str, Any]
    ) -> tuple[str, str]:
        """Bind one native span identity to an operator-supplied atomic event."""

        native_trace, native_span = _native_id(trace_id), _native_id(span_id)
        key = (_trace_id(native_trace), _span_id(native_span))
        event_copy = deepcopy(dict(event))
        event_id = event_copy.get("id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("a runtime binding requires a non-empty event id")
        with self._lock:
            prior_key = self._event_keys.get(event_id)
            if prior_key is not None and prior_key != key:
                raise ValueError(f"event id {event_id!r} is already bound to another span")
            prior_event = self._bindings.get(key)
            if prior_event is not None and prior_event != event_copy:
                raise ValueError("one runtime span cannot bind to multiple atomic events")
            self._event_keys[event_id] = key
            self._bindings[key] = event_copy
        return key

    def note_failure(self, message: str) -> None:
        """Remember a structural extraction failure without interrupting the agent."""

        with self._lock:
            if message not in self._failures:
                self._failures.append(message)

    def build(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return canonical structural OTLP and a strict binding manifest."""

        with self._lock:
            if self._failures:
                raise ValueError("runtime structural capture is incomplete: " + "; ".join(self._failures))
            spans = [deepcopy(self._spans[key]) for key in sorted(self._spans)]
            bindings = [
                {
                    "trace_id": key[0],
                    "span_id": key[1],
                    "event": deepcopy(event),
                }
                for key, event in sorted(
                    self._bindings.items(), key=lambda item: str(item[1].get("id", ""))
                )
            ]
        trace = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
        manifest = {
            "schema_version": 1,
            "manifest_type": "dspy-security-bench-causalproof-manifest",
            "scenario_id": self.scenario_id,
            "title": self.title,
            "description": self.description,
            "bindings": bindings,
            "asserted_edges": deepcopy(self.asserted_edges),
            "invariants": list(self.invariants),
            "exploration": {"max_schedules": self.max_schedules},
        }
        errors = validate_manifest(manifest)
        if errors:
            raise ValueError("runtime binding manifest is invalid: " + "; ".join(errors))
        return trace, manifest

    def write(self, trace_path: str | Path, manifest_path: str | Path) -> tuple[Path, Path]:
        """Write both artifacts using an atomic replacement for each file."""

        trace, manifest = self.build()
        destinations = (Path(trace_path), Path(manifest_path))
        payloads = (trace, manifest)
        temporary: list[Path] = []
        try:
            for destination, payload in zip(destinations, payloads, strict=True):
                destination.parent.mkdir(parents=True, exist_ok=True)
                temp = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
                temp.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                temporary.append(temp)
            for temp, destination in zip(temporary, destinations, strict=True):
                temp.replace(destination)
        finally:
            for temp in temporary:
                if temp.exists():
                    temp.unlink()
        return destinations


class OpenAIAgentsCausalProcessor(_OpenAITracingProcessor):
    """OpenAI Agents SDK tracing processor that reads structural fields only."""

    def __init__(
        self,
        session: CausalRuntimeSession,
        *,
        trace_path: str | Path | None = None,
        manifest_path: str | Path | None = None,
    ) -> None:
        self.session = session
        self.trace_path = Path(trace_path) if trace_path is not None else None
        self.manifest_path = Path(manifest_path) if manifest_path is not None else None
        if (self.trace_path is None) != (self.manifest_path is None):
            raise ValueError("trace_path and manifest_path must be supplied together")

    def bind_span(self, span: object, event: Mapping[str, Any]) -> tuple[str, str]:
        """Bind an SDK span without reading its ``span_data`` payload."""

        return self.session.bind_event(
            trace_id=span.trace_id,  # type: ignore[attr-defined]
            span_id=span.span_id,  # type: ignore[attr-defined]
            event=event,
        )

    def bind_current(self, event: Mapping[str, Any]) -> tuple[str, str]:
        """Bind the current SDK span inside an agent, tool, or custom span context."""

        try:
            from agents.tracing import get_current_span
        except ImportError as exc:  # pragma: no cover - optional dependency guidance
            raise RuntimeError("install dspy-security-bench[openai-agents]") from exc
        span = get_current_span()
        if span is None:
            raise RuntimeError("no current OpenAI Agents SDK span is active")
        return self.bind_span(span, event)

    def on_trace_start(self, trace: object) -> None:
        return None

    def on_trace_end(self, trace: object) -> None:
        return None

    def on_span_start(self, span: object) -> None:
        return None

    def on_span_end(self, span: object) -> None:
        try:
            started = _iso_to_ns(span.started_at)  # type: ignore[attr-defined]
            ended = _iso_to_ns(span.ended_at)  # type: ignore[attr-defined]
            self.session.capture_span(
                trace_id=span.trace_id,  # type: ignore[attr-defined]
                span_id=span.span_id,  # type: ignore[attr-defined]
                parent_span_id=span.parent_id,  # type: ignore[attr-defined]
                started_ns=started,
                ended_ns=ended,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            self.session.note_failure(f"OpenAI Agents span structure: {exc}")

    def force_flush(self) -> None:
        if self.trace_path is not None and self.manifest_path is not None:
            self.session.write(self.trace_path, self.manifest_path)

    def shutdown(self) -> None:
        self.force_flush()

    def write(self) -> tuple[Path, Path]:
        if self.trace_path is None or self.manifest_path is None:
            raise ValueError("processor output paths were not configured")
        return self.session.write(self.trace_path, self.manifest_path)


class LangGraphCausalCallback(_LangChainCallback):
    """LangGraph callback that binds selected graph nodes without reading state."""

    run_inline = True
    raise_error = False

    def __init__(
        self,
        session: CausalRuntimeSession,
        *,
        node_events: Mapping[
            str, Mapping[str, Any] | Callable[[str, int], Mapping[str, Any]]
        ],
        trace_path: str | Path | None = None,
        manifest_path: str | Path | None = None,
    ) -> None:
        super().__init__()
        self.session = session
        self.node_events = dict(node_events)
        self.trace_path = Path(trace_path) if trace_path is not None else None
        self.manifest_path = Path(manifest_path) if manifest_path is not None else None
        if (self.trace_path is None) != (self.manifest_path is None):
            raise ValueError("trace_path and manifest_path must be supplied together")
        self._roots: dict[str, str] = {}
        self._active: dict[str, tuple[str, str | None, int]] = {}
        self._bound_runs: set[str] = set()
        self._occurrences: dict[str, int] = {}
        self._lock = threading.RLock()

    @property
    def ignore_llm(self) -> bool:
        return True

    @property
    def ignore_chat_model(self) -> bool:
        return True

    @property
    def ignore_retriever(self) -> bool:
        return True

    def on_chain_start(
        self,
        serialized: Mapping[str, Any] | None,
        inputs: Mapping[str, Any],
        *,
        run_id: object,
        parent_run_id: object | None = None,
        tags: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        del serialized, inputs, tags, kwargs  # Explicit content boundary.
        run, parent = str(run_id), str(parent_run_id) if parent_run_id is not None else None
        with self._lock:
            root = self._roots.get(parent, parent) if parent is not None else run
            self._roots[run] = root
            node = metadata.get("langgraph_node") if isinstance(metadata, Mapping) else None
            if not isinstance(node, str) or node not in self.node_events:
                return
            if parent in self._bound_runs:
                return  # Ignore nested runnable callbacks inheriting the same node metadata.
            occurrence = self._occurrences.get(node, 0) + 1
            self._occurrences[node] = occurrence
            configured = self.node_events[node]
            if callable(configured):
                event = configured(node, occurrence)
            elif occurrence == 1:
                event = configured
            else:
                self.session.note_failure(
                    f"LangGraph node {node!r} ran more than once; use an occurrence event factory"
                )
                return
            self.session.bind_event(trace_id=root, span_id=run, event=event)
            structural_parent = parent if parent in self._bound_runs else None
            self._active[run] = (root, structural_parent, time.time_ns())
            self._bound_runs.add(run)

    def on_chain_end(
        self,
        outputs: Mapping[str, Any],
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: Any,
    ) -> None:
        del outputs, parent_run_id, kwargs  # Explicit content boundary.
        self._finish(str(run_id))

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: object,
        parent_run_id: object | None = None,
        **kwargs: Any,
    ) -> None:
        del error, parent_run_id, kwargs  # Error messages may contain application content.
        self._finish(str(run_id))

    def _finish(self, run: str) -> None:
        with self._lock:
            active = self._active.pop(run, None)
        if active is None:
            return
        trace, parent, started = active
        try:
            self.session.capture_span(
                trace_id=trace,
                span_id=run,
                parent_span_id=parent,
                started_ns=started,
                ended_ns=time.time_ns(),
            )
        except (TypeError, ValueError) as exc:
            self.session.note_failure(f"LangGraph callback structure: {exc}")

    def write(self) -> tuple[Path, Path]:
        if self.trace_path is None or self.manifest_path is None:
            raise ValueError("callback output paths were not configured")
        return self.session.write(self.trace_path, self.manifest_path)


def integration_catalog() -> list[dict[str, str]]:
    return [dict(item) for item in INTEGRATIONS]


def integration_scaffold(framework: str) -> str:
    """Return a review-first starter module for one supported runtime."""

    if framework not in _INTEGRATION_KEYS:
        raise ValueError(
            f"unknown CausalProof integration {framework!r}; choose: "
            + ", ".join(sorted(_INTEGRATION_KEYS))
        )
    if framework == "openai-agents":
        return _OPENAI_SCAFFOLD
    return _LANGGRAPH_SCAFFOLD


def _native_id(value: object) -> str:
    if value is None:
        raise ValueError("runtime trace and span identifiers cannot be null")
    encoded = str(value)
    if not encoded or len(encoded) > 512:
        raise ValueError("runtime trace and span identifiers must contain 1 to 512 characters")
    return encoded


def _trace_id(native: str) -> str:
    return hashlib.sha256(f"causalproof:trace:{native}".encode()).hexdigest()[:32]


def _span_id(native: str) -> str:
    return hashlib.sha256(f"causalproof:span:{native}".encode()).hexdigest()[:16]


def _iso_to_ns(value: object) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError("span start/end timestamps must be ISO-8601 strings")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("span start/end timestamps must include a timezone")
    delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


_OPENAI_SCAFFOLD = '''"""CausalProof bridge for OpenAI Agents SDK. Review all event metadata."""

from agents import set_trace_processors

from dspy_security_bench.causal.runtime import (
    CausalRuntimeSession,
    OpenAIAgentsCausalProcessor,
)

session = CausalRuntimeSession(
    scenario_id="replace-me",
    title="Replace with a bounded workflow title",
    description="Synthetic or approved metadata only.",
    invariants=["active_authority_at_use"],
    asserted_edges=[],
)
processor = OpenAIAgentsCausalProcessor(
    session,
    trace_path="artifacts/causalproof-structure.json",
    manifest_path="artifacts/causalproof-manifest.json",
)
# Replace the default exporter when local custody is required. If you retain
# other processors, evaluate their separate data-handling behavior explicitly.
set_trace_processors([processor])

# Inside the exact agent/tool/custom span representing an atomic event:
# processor.bind_current({"id": "grant", "kind": "grant", ...})
# After the trace finishes: processor.write()
'''


_LANGGRAPH_SCAFFOLD = '''"""CausalProof bridge for LangGraph. Review all event metadata."""

from dspy_security_bench.causal.runtime import CausalRuntimeSession, LangGraphCausalCallback

session = CausalRuntimeSession(
    scenario_id="replace-me",
    title="Replace with a bounded workflow title",
    description="Synthetic or approved metadata only.",
    invariants=["active_authority_at_use"],
    asserted_edges=[],
)
callback = LangGraphCausalCallback(
    session,
    node_events={
        # "authorize": {"id": "grant", "kind": "grant", ...},
        # "commit": {"id": "commit", "kind": "effect", ...},
    },
    trace_path="artifacts/causalproof-structure.json",
    manifest_path="artifacts/causalproof-manifest.json",
)

# graph.invoke(input_state, config={"callbacks": [callback]})
# callback.write()
'''
