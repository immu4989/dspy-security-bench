"""BYOA framework bridges, detection, scaffolding, and doctor checks."""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from dspy_security_bench.agents import AgentResult, BenchTool
from dspy_security_bench.cli import main
from dspy_security_bench.integrations import (
    AutoGenAdapter,
    CallbackAdapter,
    CrewAIAdapter,
    LangChainAdapter,
    OpenAIAgentsAdapter,
    PydanticAIAdapter,
    detect_frameworks,
    get_framework,
)
from dspy_security_bench.integrations.doctor import run_doctor
from dspy_security_bench.integrations.frameworks import _tool_callable
from dspy_security_bench.integrations.scaffold import integrate_project


def _bench_tool() -> BenchTool:
    return BenchTool(
        name="lookup_record",
        description="Look up a synthetic record.",
        parameters={
            "type": "object",
            "properties": {
                "record_id": {"type": "string"},
                "limit": {"type": "integer", "default": 1},
            },
            "required": ["record_id"],
        },
        _call=lambda **kwargs: json.dumps(kwargs, sort_keys=True),
    )


def _install_module(monkeypatch, name: str, **attributes):
    module = ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def test_dynamic_tool_preserves_schema_and_records_real_call():
    ledger = []
    function = _tool_callable(_bench_tool(), ledger)
    signature = inspect.signature(function)
    assert signature.parameters["record_id"].annotation is str
    assert signature.parameters["record_id"].default is inspect.Parameter.empty
    assert signature.parameters["limit"].default == 1
    assert '"record_id": "R-1"' in function(record_id="R-1")
    assert ledger[0].name == "lookup_record"
    assert ledger[0].args == {"record_id": "R-1"}


def test_openai_agents_adapter_uses_native_tools(monkeypatch):
    class FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeRunner:
        @staticmethod
        def run_sync(agent, query):
            assert agent.kwargs["instructions"].startswith("trusted defense")
            agent.kwargs["tools"][0](record_id="OA-1")
            return SimpleNamespace(final_output=f"done: {query}")

    _install_module(
        monkeypatch,
        "agents",
        Agent=FakeAgent,
        Runner=FakeRunner,
        function_tool=lambda function: function,
    )
    result = OpenAIAgentsAdapter().run(
        "inspect",
        [_bench_tool()],
        system_directive="trusted defense",
    )
    assert result.final_answer == "done: inspect"
    assert result.tool_calls[0].args == {"record_id": "OA-1"}


def test_langchain_adapter_uses_create_agent(monkeypatch):
    class FakeGraph:
        def __init__(self, tools):
            self.tools = tools

        def invoke(self, payload):
            self.tools[0](record_id="LC-1")
            assert payload["messages"][0]["content"] == "inspect"
            return {"messages": [SimpleNamespace(content="langchain done")]}

    def create_agent(*, model, tools, system_prompt):
        assert model == "openai:test"
        assert system_prompt.startswith("trusted defense")
        return FakeGraph(tools)

    _install_module(monkeypatch, "langchain")
    _install_module(monkeypatch, "langchain.agents", create_agent=create_agent)
    result = LangChainAdapter(model="openai:test").run(
        "inspect", [_bench_tool()], system_directive="trusted defense"
    )
    assert result.final_answer == "langchain done"
    assert result.tool_calls[0].name == "lookup_record"


def test_pydantic_ai_adapter_uses_agent_tools(monkeypatch):
    class FakeAgent:
        def __init__(self, model, *, tools, instructions):
            assert model == "openai:test"
            assert instructions.startswith("trusted defense")
            self.tools = tools

        def run_sync(self, query):
            self.tools[0](record_id="PA-1")
            return SimpleNamespace(output=f"pydantic: {query}")

    _install_module(monkeypatch, "pydantic_ai", Agent=FakeAgent)
    result = PydanticAIAdapter(model="openai:test").run(
        "inspect", [_bench_tool()], system_directive="trusted defense"
    )
    assert result.final_answer == "pydantic: inspect"
    assert result.tool_calls[0].args["record_id"] == "PA-1"


def test_crewai_adapter_uses_direct_agent_kickoff(monkeypatch):
    def tool(name):
        def decorate(function):
            assert name == "lookup_record"
            return function

        return decorate

    class FakeAgent:
        def __init__(self, **kwargs):
            assert kwargs["goal"].startswith("trusted defense")
            self.tools = kwargs["tools"]

        def kickoff(self, query):
            self.tools[0](record_id="CR-1")
            return SimpleNamespace(raw=f"crew: {query}")

    _install_module(monkeypatch, "crewai", Agent=FakeAgent)
    _install_module(monkeypatch, "crewai.tools", tool=tool)
    result = CrewAIAdapter(model="openai/test").run(
        "inspect", [_bench_tool()], system_directive="trusted defense"
    )
    assert result.final_answer == "crew: inspect"
    assert result.tool_calls[0].args["record_id"] == "CR-1"


def test_autogen_adapter_uses_fresh_agentchat_loop(monkeypatch):
    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["parallel_tool_calls"] is False

        async def close(self):
            return None

    class FakeAgent:
        def __init__(self, **kwargs):
            assert kwargs["system_message"].startswith("trusted defense")
            self.tools = kwargs["tools"]

        async def run(self, *, task):
            await self.tools[0](record_id="AG-1")
            return SimpleNamespace(messages=[SimpleNamespace(content=f"autogen: {task}")])

    _install_module(monkeypatch, "autogen_agentchat")
    _install_module(monkeypatch, "autogen_agentchat.agents", AssistantAgent=FakeAgent)
    _install_module(monkeypatch, "autogen_ext")
    _install_module(monkeypatch, "autogen_ext.models")
    _install_module(
        monkeypatch,
        "autogen_ext.models.openai",
        OpenAIChatCompletionClient=FakeClient,
    )
    result = AutoGenAdapter(model="test").run(
        "inspect", [_bench_tool()], system_directive="trusted defense"
    )
    assert result.final_answer == "autogen: inspect"
    assert result.tool_calls[0].args["record_id"] == "AG-1"


def test_callback_adapter_accepts_async_and_agent_result():
    async def async_runner(query, tools, system_directive):
        assert system_directive == "trusted defense"
        return AgentResult(final_answer=f"custom: {query}")

    result = CallbackAdapter(async_runner).run("inspect", [], system_directive="trusted defense")
    assert result.final_answer == "custom: inspect"

    async def inside_loop():
        return CallbackAdapter(async_runner).run("nested", [], system_directive="trusted defense")

    assert asyncio.run(inside_loop()).final_answer == "custom: nested"


def test_detection_uses_direct_manifests_not_transitive_lockfiles(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["langchain>=1.3"]\n')
    (tmp_path / "uv.lock").write_text('name = "crewai"\n')
    detected = detect_frameworks(tmp_path)
    assert [(spec.key, evidence) for spec, evidence in detected] == [
        ("langchain", ("pyproject.toml",))
    ]


def test_framework_aliases_are_normalized():
    assert get_framework("langgraph").key == "langchain"
    assert get_framework("openai").key == "openai-agents"
    assert get_framework("custom").key == "mcp"


def test_integrate_scaffolds_safe_target_test_manifest_and_workflow(tmp_path):
    result = integrate_project(get_framework("openai-agents"), tmp_path, model="gpt-test")
    assert len(result.created) == 4
    target = (tmp_path / "dspy_security_target.py").read_text()
    workflow = (tmp_path / ".github/workflows/dspy-proofrun.yml").read_text()
    manifest = json.loads((tmp_path / ".dspy-security-bench/integration.json").read_text())
    assert "OpenAIAgentsAdapter(model='gpt-test')" in target
    assert "proofrun.yml@v0.13.0" in workflow
    assert "  workflow_dispatch:" in workflow and "\n  pull_request:" not in workflow
    assert "id-token: write" in workflow and "attestations: write" in workflow
    parsed = yaml.safe_load(workflow)
    assert parsed["jobs"]["proofrun"]["with"]["agent"] == ("dspy_security_target:build_agent")
    assert parsed["jobs"]["proofrun"]["secrets"]["OPENAI_API_KEY"] == (
        "${{ secrets.OPENAI_API_KEY }}"
    )
    assert manifest["agent"] == "dspy_security_target:build_agent"
    assert manifest["required_env"] == ["OPENAI_API_KEY"]

    repeated = integrate_project(get_framework("openai-agents"), tmp_path, model="other")
    assert repeated.created == ()
    assert len(repeated.skipped) == 4


def test_mcp_scaffold_and_doctor_are_zero_key(tmp_path, monkeypatch):
    (tmp_path / "custom_loop.py").write_text(
        "def run_agent(query, tools, system_directive):\n    return 'ok'\n"
    )
    integrate_project(
        get_framework("mcp"),
        tmp_path,
        runner="custom_loop:run_agent",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    report = run_doctor(tmp_path)
    assert report.passed
    assert all(check.status == "pass" for check in report.checks)


def test_mcp_scaffold_rejects_malformed_runner_and_symlink_escape(tmp_path):
    spec = get_framework("mcp")
    with pytest.raises(ValueError, match="runner module"):
        integrate_project(spec, tmp_path, runner="module;payload:run")

    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / ".dspy-security-bench").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="outside project root|symlink"):
        integrate_project(spec, tmp_path, runner="custom_loop:run_agent")


def test_doctor_rejects_mutable_engine_ref(tmp_path, monkeypatch):
    (tmp_path / "custom_loop.py").write_text(
        "def run_agent(query, tools, system_directive):\n    return 'ok'\n"
    )
    integrate_project(get_framework("mcp"), tmp_path, runner="custom_loop:run_agent")
    workflow = tmp_path / ".github/workflows/dspy-proofrun.yml"
    workflow.write_text(workflow.read_text().replace("proofrun.yml@v0.13.0", "proofrun.yml@main"))
    monkeypatch.syspath_prepend(str(tmp_path))
    report = run_doctor(tmp_path)
    assert not report.passed
    assert any(check.name == "workflow" and check.status == "fail" for check in report.checks)


def test_doctor_explains_crewai_python_314_boundary(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["crewai>=1.15"]\n')
    integrate_project(get_framework("crewai"), tmp_path)
    monkeypatch.setattr("dspy_security_bench.integrations.doctor.sys.version_info", (3, 14))
    report = run_doctor(tmp_path)
    check = next(item for item in report.checks if item.name == "framework-import")
    assert check.status == "fail"
    assert "Python 3.10-3.13" in check.message


def test_integrate_and_doctor_are_exposed_by_umbrella_cli(tmp_path, capsys, monkeypatch):
    assert main(["integrate", "--list"]) == 0
    assert "openai-agents" in capsys.readouterr().out

    (tmp_path / "custom_loop.py").write_text(
        "def run_agent(query, tools, system_directive):\n    return 'ok'\n"
    )
    assert (
        main(
            [
                "integrate",
                "--framework",
                "mcp",
                "--runner",
                "custom_loop:run_agent",
                "--root",
                str(tmp_path),
            ]
        )
        == 0
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    assert main(["doctor", "--root", str(tmp_path), "--json"]) == 0
    output = capsys.readouterr().out
    assert '"passed": true' in output
