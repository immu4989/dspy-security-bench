"""Keep runtime schemas intact at the generic and reference-agent boundaries.

No native bridge schema-equivalence claim or provider request is made here.
"""

import json
import socket
import sys
from copy import deepcopy
from enum import Enum
from types import SimpleNamespace
from typing import Annotated, Literal

import jsonschema
import pytest
from agentdojo.functions_runtime import Depends, FunctionsRuntime, TaskEnvironment, make_function
from pydantic import BaseModel, ConfigDict, Field

from dspy_security_bench.adapters.generic import (
    GenericAgentElement,
    _full_json_schema,
    _make_bench_tool,
)
from dspy_security_bench.agents import AgentResult, BenchTool, LiteLLMFunctionCallingAgent, ToolCall


class Priority(str, Enum):
    routine = "routine"
    urgent = "urgent"


class LineItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sku: str = Field(pattern=r"^ITEM-[0-9]+$", description="Synthetic inventory code")
    quantity: int = Field(ge=1, le=10)


class Order(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lines: list[LineItem] = Field(min_length=1, max_length=3)
    priority: Priority = Priority.routine
    note: str | None = None


class Warehouse(TaskEnvironment):
    orders: list[dict] = Field(default_factory=list)
    counts: list[int] = Field(default_factory=list)


def place_order(warehouse: Annotated[Warehouse, Depends(lambda env: env)], order: Order) -> str:
    """Record a synthetic order.

    :param order: The synthetic order to record.
    """
    # AgentDojo passes model_dump() values to the callback, including submodels.
    warehouse.orders.append(order)
    return "recorded"


def count_items(warehouse: Annotated[Warehouse, Depends(lambda env: env)], count: int = 2) -> str:
    """Record a synthetic count using the optional default.

    :param count: The number of synthetic items.
    """
    warehouse.counts.append(count)
    return str(count)


class SearchNode(BaseModel):
    name: str
    children: list["SearchNode"] = Field(default_factory=list)


class ModelVariants(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={
        "description": "Synthetic argument metadata",
        "examples": [{"external-id": "A", "mode": "read", "choice": 1, "nullable": None}],
        "x-audit": {"labels": ["synthetic"]},
    })
    internal_id: str = Field(alias="external-id")
    mode: Literal["read", "review"]
    choice: int | str
    nullable: str | None
    optional: str = "default"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("schema tests must not contact any service")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)


@pytest.mark.parametrize("model", [Order, LineItem, SearchNode, ModelVariants])
def test_generated_schema_is_a_complete_detached_document(model):
    original = model.model_json_schema()
    function = SimpleNamespace(parameters=SimpleNamespace(model_json_schema=lambda: original))
    schema = _full_json_schema(function)
    assert schema == original
    assert schema is not original
    jsonschema.Draft202012Validator.check_schema(schema)
    schema.setdefault("$defs", {})["Synthetic"] = {"type": "null"}
    schema.setdefault("properties", {})["injected"] = {"type": "boolean"}
    assert original == model.model_json_schema()


@pytest.mark.parametrize("payload", [
    {"name": "root"},
    {"name": "root", "children": [{"name": "leaf"}]},
    {"name": "root", "children": [{"name": "branch", "children": [{"name": "leaf"}]}]},
])
def test_recursive_references_resolve_without_inlining(payload):
    schema = _full_json_schema(SimpleNamespace(parameters=SearchNode))
    assert schema["$ref"] == "#/$defs/SearchNode"
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_schema_metadata_aliases_and_required_nullable_are_preserved():
    schema = _full_json_schema(SimpleNamespace(parameters=ModelVariants))
    assert "external-id" in schema["properties"]
    assert "internal_id" not in schema["properties"]
    assert set(schema["required"]) == {"external-id", "mode", "choice", "nullable"}
    assert schema["additionalProperties"] is False
    assert schema["x-audit"] == {"labels": ["synthetic"]}
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(schema["examples"][0])
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"external-id": "A", "mode": "read", "choice": 1})


def test_no_parameter_schema_invented_for_generated_empty_model():
    class Empty(BaseModel):
        pass

    schema = _full_json_schema(SimpleNamespace(parameters=Empty))
    assert schema == Empty.model_json_schema()
    assert "required" not in schema
    jsonschema.Draft202012Validator(schema).validate({})


def test_optional_runtime_argument_is_not_declared_required():
    function = make_function(count_items)
    runtime, env = FunctionsRuntime([function]), Warehouse()
    tool = _make_bench_tool(function, runtime, env, None, "synthetic query")
    assert "required" not in tool.parameters
    assert tool.parameters["properties"]["count"]["default"] == 2
    jsonschema.Draft202012Validator(tool.parameters).validate({})
    assert tool() == "2"
    assert env.counts == [2]
    assert "warehouse" not in tool.parameters["properties"]


@pytest.mark.parametrize("order", [
    {"lines": [{"sku": "ITEM-1", "quantity": 1}]},
    {"lines": [{"sku": "ITEM-9", "quantity": 10}], "priority": "urgent", "note": None},
])
def test_nested_schema_and_real_runtime_agree_for_supported_arguments(order):
    function = make_function(place_order)
    runtime, env = FunctionsRuntime([function]), Warehouse()
    tool = _make_bench_tool(function, runtime, env, None, "synthetic query")
    assert set(tool.parameters["$defs"]) >= {"Order", "LineItem", "Priority"}
    jsonschema.Draft202012Validator(tool.parameters).validate({"order": order})
    assert tool(order=order) == "recorded"
    assert env.orders == [Order.model_validate(order).model_dump()]


@pytest.mark.parametrize("order", [
    {"lines": []},
    {"lines": [{"sku": "INVALID", "quantity": 1}]},
    {"lines": [{"sku": "ITEM-1", "quantity": 0}]},
    {"lines": [{"sku": "ITEM-1", "quantity": 11}]},
    {"lines": [{"sku": "ITEM-1"}]},
    {"lines": [{"sku": "ITEM-1", "quantity": 1, "unknown": True}]},
    {"lines": [{"sku": "ITEM-1", "quantity": 1}], "priority": "invalid"},
    {"lines": [{"sku": "ITEM-1", "quantity": 1}], "unknown": True},
    {"lines": [{"sku": "ITEM-1", "quantity": 1}] * 4},
])
def test_preserved_constraints_match_runtime_rejection_without_effects(order):
    function = make_function(place_order)
    runtime, env = FunctionsRuntime([function]), Warehouse()
    tool = _make_bench_tool(function, runtime, env, None, "synthetic query")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(tool.parameters).validate({"order": order})
    assert "ValidationError" in tool(order=order)
    assert env.orders == []


def test_generic_pipeline_hands_agent_complete_schema_and_live_binding():
    runtime = FunctionsRuntime([make_function(place_order), make_function(count_items)])
    env = Warehouse()

    class Agent:
        name = "schema-observer"

        def run(self, query, tools, *, system_directive=""):
            ledger = []
            for tool in tools:
                assert tool.parameters == runtime.functions[tool.name].parameters.model_json_schema()
                args = {"order": {"lines": [{"sku": "ITEM-1", "quantity": 1}]}} if tool.name == "place_order" else {}
                jsonschema.Draft202012Validator(tool.parameters).validate(args)
                ledger.append(ToolCall(tool.name, args, tool(**args)))
            return AgentResult("recorded", ledger)

    *_, messages, extra = GenericAgentElement(Agent()).query("synthetic request", runtime, env)
    assert messages[-1]["role"] == "assistant"
    assert env.orders and env.counts == [2]


def test_repeated_schema_exports_do_not_share_mutable_subtrees():
    original = Order.model_json_schema()
    tool = BenchTool("order", "Synthetic order", deepcopy(original), lambda **kwargs: "ok")
    first, second = tool.openai_schema(), tool.openai_schema()
    params = first["function"]["parameters"]
    params["$defs"]["LineItem"]["properties"]["quantity"]["minimum"] = -100
    params["required"].clear()
    second["function"]["parameters"]["properties"].clear()
    assert tool.parameters == original
    assert tool.openai_schema()["function"]["parameters"] == original
    tool.parameters["$defs"]["Priority"]["enum"].append("new")
    assert "new" not in params["$defs"]["Priority"]["enum"]


def test_empty_benchtool_schema_keeps_legacy_no_argument_spec():
    tool = BenchTool("empty", "Synthetic empty tool", {}, lambda: "ok")
    exported = tool.openai_schema()["function"]["parameters"]
    assert exported == {"type": "object", "properties": {}}
    exported["properties"]["injected"] = {"type": "string"}
    assert tool.parameters == {}
    assert tool.openai_schema()["function"]["parameters"]["properties"] == {}


def test_provider_schema_normalization_cannot_rewrite_source_or_later_rounds(monkeypatch):
    schema = Order.model_json_schema()
    effects, seen = [], []
    tool = BenchTool("order", "Synthetic order", deepcopy(schema), lambda **kwargs: effects.append(kwargs) or "ok")
    order = {"lines": [{"sku": "ITEM-1", "quantity": 1}]}

    def completion(**kwargs):
        specs = kwargs["tools"]
        assert specs[0]["function"]["parameters"] == schema
        seen.append(specs)
        specs[0]["function"]["parameters"]["$defs"].clear()
        specs[0]["function"]["parameters"]["required"].clear()
        if len(seen) % 2:
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call", "type": "function",
                "function": {"name": "order", "arguments": json.dumps(order)},
            }]}
            finish = "tool_calls"
        else:
            message, finish = {"role": "assistant", "content": "done"}, "stop"
        return {"choices": [{"message": message, "finish_reason": finish}]}

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    agent = LiteLLMFunctionCallingAgent("synthetic", max_iters=2)
    for _ in range(2):
        result = agent.run("query", [tool])
        assert result.final_answer == "done"
        assert result.tool_calls == [ToolCall("order", order, "ok")]
        assert tool.parameters == schema
    assert effects == [order, order]
    assert len({id(spec) for spec in seen}) == 4
