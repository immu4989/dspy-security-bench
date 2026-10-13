"""Bounded stdout collection for a trusted local verifier, not a process sandbox."""

from __future__ import annotations

import asyncio
import math
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor


class BoundedProcessError(RuntimeError):
    """A fixed, source-redacted process collection failure."""


class _Collector(asyncio.SubprocessProtocol):
    def __init__(self, loop, maximum):
        self.maximum = maximum
        self.output = bytearray()
        self.transport = None
        self.failure = None
        self.closed = loop.create_future()

    def connection_made(self, transport):
        self.transport = transport
        if self.failure:
            transport.close()

    def abort(self, reason):
        if self.failure is None:
            self.failure = reason
        if self.transport is not None:
            # Close pipes as well as killing a running direct child: inherited
            # pipe handles must not keep the collector waiting after timeout.
            self.transport.close()

    def pipe_data_received(self, fd, data):
        if fd != 1 or self.failure:
            return
        remaining = self.maximum + 1 - len(self.output)
        self.output.extend(data[:remaining])
        if len(self.output) > self.maximum:
            self.abort("verifier stdout exceeded its byte limit")

    def pipe_connection_lost(self, fd, exc):
        if exc is not None:
            self.abort("verifier output pipe failed")

    def connection_lost(self, exc):
        if exc is not None and self.failure is None:
            self.failure = "verifier process transport failed"
        if not self.closed.done():
            self.closed.set_result(None)


def run_bounded(command: list[str], *, maximum_stdout: int, timeout: float) -> subprocess.CompletedProcess:
    """Collect raw stdout up to a byte budget; discard stderr and disable stdin.

    The timeout covers spawn/collection as observed by the event loop; OS process
    creation and reaping can take longer. On overflow, timeout, or interruption,
    close the pipes and kill/reap the direct child. Descendants are not contained.
    No output is spooled to disk. The buffer retains at most maximum_stdout + 1
    bytes, in addition to bounded transport chunks and the returned bytes copy.
    A private worker loop also supports callers already running an asyncio loop.
    """
    if type(maximum_stdout) is not int or maximum_stdout < 1:
        raise ValueError("stdout byte budget must be a positive integer")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("process timeout must be finite and positive")
    if (type(command) is not list or not command
            or any(type(arg) is not str or "\x00" in arg for arg in command)):
        raise ValueError("process arguments must be a nonempty list of strings")
    command = list(command)
    cancelled = threading.Event()

    def worker():
        # Do not replace the application's event-loop policy. Windows selectors
        # cannot service subprocess pipes; use the standard proactor explicitly.
        loop = asyncio.ProactorEventLoop() if os.name == "nt" else asyncio.SelectorEventLoop()
        collector = _Collector(loop, maximum_stdout)

        async def collect():
            timer = loop.call_later(timeout, collector.abort, "verifier process timed out")

            def check_cancelled():
                nonlocal cancellation_check
                if cancelled.is_set():
                    collector.abort("verifier process interrupted")
                elif not collector.closed.done():
                    cancellation_check = loop.call_later(0.05, check_cancelled)

            cancellation_check = loop.call_later(0.05, check_cancelled)
            try:
                transport, _ = await loop.subprocess_exec(
                    lambda: collector, *command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                )
                try:
                    await collector.closed
                    if collector.failure:
                        raise BoundedProcessError(collector.failure)
                    return subprocess.CompletedProcess(command, transport.get_returncode(), bytes(collector.output))
                finally:
                    transport.close()
            finally:
                timer.cancel()
                cancellation_check.cancel()

        try:
            return loop.run_until_complete(collect())
        finally:
            loop.close()

    # Joining the worker ensures its direct child and transport are cleaned up
    # before the caller's private evidence snapshot directory is removed.
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="proofrun-verifier") as executor:
        try:
            return executor.submit(worker).result()
        finally:
            cancelled.set()
