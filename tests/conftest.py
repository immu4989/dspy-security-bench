"""Shared pytest fixtures for the dspy_security_bench test suite."""
from __future__ import annotations

import pytest


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
