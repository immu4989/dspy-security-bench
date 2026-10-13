"""Exercise real local child processes, without GitHub or other network calls."""

import asyncio
import os
import sys
import threading
import time
from concurrent.futures import Future

import pytest

from dspy_security_bench.processio import BoundedProcessError, _Collector, run_bounded


def child(code, *, maximum=1000, timeout=5):
    return run_bounded([sys.executable, "-c", code], maximum_stdout=maximum, timeout=timeout)


def test_exact_binary_stdout_and_nonzero_status_are_preserved():
    result = child("import os; os.write(1, b'\\xff\\r\\n'); raise SystemExit(7)", maximum=3)
    assert result.returncode == 7 and result.stdout == b"\xff\r\n" and result.stderr is None


def test_stdin_is_closed_and_large_private_stderr_is_discarded(capsys):
    result = child("import os, sys; assert sys.stdin.buffer.read() == b''; "
                   "os.write(2, b'PRIVATE' * 100000); os.write(1, b'[]')", maximum=2)
    assert result.returncode == 0 and result.stdout == b"[]" and result.stderr is None
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


@pytest.fixture
def reaped(monkeypatch):
    returncodes = []
    original = _Collector.connection_lost

    def closed(self, exc):
        returncodes.append(self.transport.get_returncode())
        original(self, exc)

    monkeypatch.setattr(_Collector, "connection_lost", closed)
    return returncodes


def test_byte_limit_stops_a_continuous_writer_and_reaps_it(reaped):
    started = time.monotonic()
    with pytest.raises(BoundedProcessError, match="byte limit") as caught:
        child("import os\nwhile True: os.write(1, b'PRIVATE' * 10000)", maximum=20)
    assert time.monotonic() - started < 5
    assert "PRIVATE" not in str(caught.value)
    assert len(reaped) == 1 and reaped[0] is not None and reaped[0] != 0
    assert not any(t.name.startswith("proofrun-verifier") for t in threading.enumerate())


@pytest.mark.parametrize("code", [
    "import time; time.sleep(30)",
    "import os, time; os.close(1); time.sleep(30)",
    "import os, time; os.write(1, b'[]'); time.sleep(30)",
])
def test_timeout_requires_both_child_exit_and_pipe_completion(code, reaped):
    started = time.monotonic()
    with pytest.raises(BoundedProcessError, match="timed out"):
        child(code, timeout=0.2)
    assert time.monotonic() - started < 5
    assert len(reaped) == 1 and reaped[0] is not None and reaped[0] != 0
    assert not any(t.name.startswith("proofrun-verifier") for t in threading.enumerate())


@pytest.mark.skipif(os.name == "nt", reason="POSIX fork fixture; collector itself is cross-platform")
def test_inherited_pipe_cannot_hold_collector_open():
    # The bounded-lived descendant keeps stdout open after its parent exits.
    # It is not killed by this helper: descendants require OS containment.
    code = "import os, time\nif os.fork() == 0:\n time.sleep(3); os._exit(0)\nos._exit(0)"
    started = time.monotonic()
    with pytest.raises(BoundedProcessError, match="timed out"):
        child(code, timeout=0.2)
    assert time.monotonic() - started < 2
    assert not any(t.name.startswith("proofrun-verifier") for t in threading.enumerate())


def test_callable_inside_an_existing_event_loop():
    async def run():
        return child("import os; os.write(1, b'ok\\n')")

    result = asyncio.run(run())
    assert result.returncode == 0 and result.stdout == b"ok\n"


def test_shell_metacharacters_remain_literal_arguments():
    result = run_bounded(
        [sys.executable, "-c", "import os, sys; os.write(1, sys.argv[1].encode())", "; echo PRIVATE"],
        maximum_stdout=100, timeout=5,
    )
    assert result.returncode == 0 and result.stdout == b"; echo PRIVATE"


def test_split_multibyte_output_is_not_decoded_using_the_host_locale():
    result = child("import os, time; os.write(1, b'\\xc3'); time.sleep(0.05); os.write(1, b'\\xa9')", maximum=2)
    assert result.stdout.decode("utf-8") == "é"


def test_keyboard_interrupt_cleans_up_the_worker_and_direct_child(monkeypatch, reaped):
    def interrupt(*a, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(Future, "result", interrupt)
    with pytest.raises(KeyboardInterrupt):
        child("import time; time.sleep(30)")
    assert len(reaped) == 1 and reaped[0] is not None and reaped[0] != 0
    assert not any(t.name.startswith("proofrun-verifier") for t in threading.enumerate())


@pytest.mark.parametrize("budget", [True, 0, -1, 1.5, "PRIVATE", None])
def test_invalid_budget_does_not_start_a_worker(budget, monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", lambda *a: pytest.fail("invalid policy started a worker"))
    with pytest.raises(ValueError) as caught:
        run_bounded([sys.executable], maximum_stdout=budget, timeout=1)
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), float("nan"), "PRIVATE", None])
def test_invalid_timeout_does_not_start_a_worker(timeout, monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", lambda *a: pytest.fail("invalid policy started a worker"))
    with pytest.raises(ValueError) as caught:
        run_bounded([sys.executable], maximum_stdout=100, timeout=timeout)
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("command", ["PRIVATE", [], [None], ["PRIVATE\x00"], ("PRIVATE",)])
def test_invalid_arguments_do_not_start_a_worker(command, monkeypatch):
    monkeypatch.setattr(threading.Thread, "start", lambda *a: pytest.fail("invalid command started a worker"))
    with pytest.raises(ValueError) as caught:
        run_bounded(command, maximum_stdout=100, timeout=1)
    assert "PRIVATE" not in str(caught.value)


def test_collector_never_retains_more_than_limit_plus_probe():
    loop = asyncio.new_event_loop()
    try:
        collector = _Collector(loop, 8)
        collector.pipe_data_received(1, b"a" * 100000)
        assert bytes(collector.output) == b"a" * 9
        collector.pipe_data_received(1, b"b" * 100000)
        assert bytes(collector.output) == b"a" * 9
        assert collector.failure == "verifier stdout exceeded its byte limit"
    finally:
        loop.close()


def test_no_worker_remains_after_spawn_failure(tmp_path):
    with pytest.raises(OSError):
        run_bounded([str(tmp_path / "absent")], maximum_stdout=100, timeout=1)
    assert not any(t.name.startswith("proofrun-verifier") for t in threading.enumerate())
