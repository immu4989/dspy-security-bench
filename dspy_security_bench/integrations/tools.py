"""Cooperative lifetime and failure accounting for native adapter callbacks."""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from dspy_security_bench.agents import AgentResultError


class NativeToolExecutionError(RuntimeError):
    """Supplied native tool execution did not produce a complete measurement."""


class _ToolSession:
    """One native run's callbacks, not a sandbox or cancellation mechanism.

    Remember only failure categories, never exception text or traceback objects.
    A caught callback failure cannot be turned into a valid measurement. Already
    admitted callbacks may finish; new callbacks stop after a failure or closure.
    """

    def __init__(self):
        self._lock = Lock()
        self._closed = False
        self._active = 0
        self._failed = False
        self._invalid_result = False
        self._incomplete = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        with self._lock:
            self._closed = True
            self._incomplete = self._incomplete or self._active > 0
        # Never replace a model/tool exception or cancellation already escaping.
        return False

    def invoke(self, callback: Callable[[], str]) -> str:
        with self._lock:
            if self._closed:
                raise NativeToolExecutionError("native tool session is closed; callback was not executed")
            if self._failed:
                raise NativeToolExecutionError("native tool session failed; callback was not executed")
            self._active += 1
        try:
            return callback()
        except BaseException as exc:
            with self._lock:
                self._failed = True
                self._invalid_result = self._invalid_result or isinstance(exc, AgentResultError)
            raise
        finally:
            with self._lock:
                self._active -= 1

    def validate(self) -> None:
        with self._lock:
            if not self._closed or self._incomplete:
                raise NativeToolExecutionError("native run has unfinished tool callbacks; no complete measurement")
            if self._invalid_result:
                raise AgentResultError("native tool returned an invalid result; no complete measurement")
            if self._failed:
                raise NativeToolExecutionError("native tool callback failed; no complete measurement")
