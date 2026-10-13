"""Shared pytest fixtures for the dspy_security_bench test suite."""
from __future__ import annotations

import hashlib
import re

import pytest

MAX_AUTO_ID_CHARACTERS = 80
MAX_NODE_ID_CHARACTERS = 512


def pytest_make_parametrize_id(val, argname):
    """Keep adversarial fixtures out of unbounded log/environment identifiers.

    Short ordinary values keep pytest's readable defaults. Explicit ids take
    precedence; collection validates the final names without rewriting them.
    These fingerprints identify fixtures, not evidence or anonymized secrets.
    """
    if isinstance(val, bytes):
        kind, raw = "bytes", val
    elif isinstance(val, str):
        if len(val) <= MAX_AUTO_ID_CHARACTERS and val.isascii() and val.isprintable():
            return None
        kind, raw = "str", val.encode("utf-8", errors="surrogatepass")
    elif type(val) is int and val.bit_length() > 256:
        kind = "int"
        raw = (b"-" if val < 0 else b"+") + abs(val).to_bytes((val.bit_length() + 7) // 8, "big")
    else:
        return None
    name = re.sub(r"[^a-zA-Z0-9_]", "_", argname)[:32] or "parameter"
    return f"{name}-{kind}-sha256-{hashlib.sha256(raw).hexdigest()[:16]}"


def pytest_collection_modifyitems(items):
    """Fail before execution if explicit IDs bypass the automatic size guard."""
    invalid = [item for item in items if len(item.nodeid) > MAX_NODE_ID_CHARACTERS
               or any(ord(char) < 32 or ord(char) == 127 for char in item.nodeid)]
    if invalid:
        # Do not echo the very payload we are refusing to publish. Locations use
        # bounded ASCII basenames and line numbers, not parametrized node names.
        locations = []
        for item in invalid[:5]:
            name = re.sub(r"[^a-zA-Z0-9_.-]", "_", item.path.name)[:80]
            locations.append(f"{name}:{item.location[1] + 1}")
        raise pytest.UsageError(
            f"{len(invalid)} test IDs exceed {MAX_NODE_ID_CHARACTERS} characters or contain controls "
            f"({', '.join(locations)}). Use short descriptive ids= labels; fixture values are unchanged."
        )


@pytest.fixture(scope="session")
def workspace_suite():
    """Loaded once per session — the workspace AgentDojo suite."""
    from agentdojo.task_suite.load_suites import get_suite
    return get_suite("v1", "workspace")


@pytest.fixture(scope="session")
def workspace_env(workspace_suite):
    """Default workspace env state."""
    return workspace_suite.load_and_inject_default_environment({})


@pytest.fixture(scope="session")
def workspace_runtime(workspace_suite):
    """A FunctionsRuntime bound to the workspace suite's tools."""
    from agentdojo.functions_runtime import FunctionsRuntime
    return FunctionsRuntime(functions=workspace_suite.tools)
