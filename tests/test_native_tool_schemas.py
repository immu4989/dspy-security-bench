"""Schema-aware native tool admission, without optional SDKs or provider calls."""

import socket
import urllib.request
from copy import deepcopy

import pytest

from dspy_security_bench.integrations import NativeToolSchemaError
from dspy_security_bench.integrations.schemas import _ToolArgumentsError, _ToolSchema


def order_schema():
    return {
        "type": "object", "additionalProperties": False,
        "properties": {
            "external-id": {"type": "string", "pattern": "^R-[0-9]+$"},
            "items": {"type": "array", "items": {"$ref": "#/$defs/item"}, "minItems": 1},
            "note": {"type": ["string", "null"]},
            "limit": {"type": "integer", "minimum": 1, "default": 2},
        },
        "required": ["external-id", "items", "note"],
        "$defs": {"item": {"type": "object", "additionalProperties": False,
                           "properties": {"mode": {"enum": ["read", "review"]},
                                          "count": {"type": "integer", "minimum": 1, "maximum": 3}},
                           "required": ["mode", "count"]}},
        "description": "Synthetic schema with nested local definitions",
        "x-audit": {"labels": ["synthetic"]},
    }


def arguments():
    return {"external-id": "R-1", "items": [{"mode": "read", "count": 1}], "note": None}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def denied(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("schema validation must not access the network")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    yield
    assert not attempts, "reference retrieval was attempted even if validation caught its error"


def test_schema_export_is_complete_detached_and_not_the_validator_state():
    original = order_schema()
    validator = _ToolSchema(original)
    first, second = validator.export(), validator.export()
    assert first == second == original
    first["$defs"].clear()
    original["properties"].clear()
    second["required"].clear()
    assert validator.export() == order_schema()
    validator.validate(arguments())
    with pytest.raises(_ToolArgumentsError):
        validator.validate({})


def test_no_defaults_coercion_or_argument_rewriting():
    validator = _ToolSchema(order_schema())
    values = arguments()
    before = deepcopy(values)
    validator.validate(values)
    assert values == before and "limit" not in values
    values["limit"] = "2"
    with pytest.raises(_ToolArgumentsError):
        validator.validate(values)
    assert values["limit"] == "2"


@pytest.mark.parametrize("replace", [
    {"external-id": "PRIVATE invalid ID"}, {"items": []},
    {"items": [{"mode": "write", "count": 1}]},
    {"items": [{"mode": "read", "count": 0}]},
    {"items": [{"mode": "read", "count": 4}]},
    {"items": [{"mode": "read", "count": True}]},
    {"items": [{"mode": "read", "count": "1"}]},
    {"items": [{"mode": "read"}]},
    {"items": [{"mode": "read", "count": 1, "PRIVATE": True}]},
    {"note": False}, {"PRIVATE": "unexpected field"}, {"limit": None},
], ids=["pattern", "empty-array", "enum", "minimum", "maximum", "bool-integer", "no-coercion",
        "nested-required", "nested-extra", "nullable", "root-extra", "non-null-default"])
def test_complete_source_constraints_reject_invalid_arguments(replace):
    validator = _ToolSchema(order_schema())
    with pytest.raises(_ToolArgumentsError) as error:
        validator.validate(arguments() | replace)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("schema,valid,invalid", [
    ({"type": "object", "properties": {"x": {"oneOf": [{"type": "integer"}, {"const": "auto"}]}},
      "required": ["x"]}, {"x": "auto"}, {"x": "other"}),
    ({"type": "object", "dependentRequired": {"x": ["y"]}}, {"x": 1, "y": 2}, {"x": 1}),
    ({"type": "object", "if": {"required": ["x"]}, "then": {"required": ["y"]}},
     {"y": 2}, {"x": 1}),
    ({"type": "object", "allOf": [{"properties": {"x": {"type": "integer"}}}],
      "unevaluatedProperties": False}, {"x": 1}, {"y": 1}),
], ids=["oneOf", "dependencies", "conditional", "unevaluated"])
def test_nontrivial_root_keywords_are_enforced(schema, valid, invalid):
    validator = _ToolSchema(schema)
    validator.validate(valid)
    with pytest.raises(_ToolArgumentsError):
        validator.validate(invalid)


def test_recursive_local_definitions_resolve_without_fetching():
    schema = {"$ref": "#/$defs/node", "$defs": {"node": {
        "type": "object", "properties": {"name": {"type": "string"},
                                         "children": {"type": "array", "items": {"$ref": "#/$defs/node"}}},
        "required": ["name"],
    }}}
    validator = _ToolSchema(schema)
    validator.validate({"name": "root", "children": [{"name": "leaf"}]})
    with pytest.raises(_ToolArgumentsError):
        validator.validate({"name": "root", "children": [{"name": 1}]})


@pytest.mark.parametrize("reference", ["https://example.invalid/PRIVATE", "file:///PRIVATE.json", "#/$defs/missing"])
def test_unresolved_references_are_configuration_errors_without_retrieval(reference):
    validator = _ToolSchema({"$ref": reference})
    with pytest.raises(NativeToolSchemaError, match="evaluated offline") as error:
        validator.validate({})
    assert "PRIVATE" not in str(error.value)


def test_format_is_an_annotation_not_an_undocumented_validator():
    validator = _ToolSchema({"type": "object", "properties": {"address": {"type": "string", "format": "email"}}})
    validator.validate({"address": "not an email"})


@pytest.mark.parametrize("schema", [None, False, [], {"type": "PRIVATE"}, {"required": True},
                                     {"$schema": "https://example.invalid/PRIVATE"}, {"$schema": None},
                                     {"properties": {"x": {"minimum": "PRIVATE"}}}],
                         ids=["none", "boolean", "list", "type", "required", "dialect", "null-dialect", "minimum"])
def test_invalid_schema_errors_do_not_echo_configuration(schema):
    with pytest.raises(NativeToolSchemaError) as error:
        _ToolSchema(schema)
    assert "PRIVATE" not in str(error.value)


class PrivateValue:
    def __repr__(self):
        pytest.fail("private values must not be represented")

    __str__ = __repr__


@pytest.mark.parametrize("value", [None, False, [], "PRIVATE", {"x": object()}, {"x": PrivateValue()},
                                    {"x": (1, 2)}, {"x": {1: "PRIVATE"}}, {"x": float("nan")},
                                    {"x": float("inf")}, {"x": "\ud800"}, {"x": 10**128}],
                         ids=["none", "bool", "list", "text", "object", "private", "tuple", "key", "nan", "inf", "unicode", "integer"])
def test_python_only_or_ambiguous_values_are_not_coerced(value):
    with pytest.raises(_ToolArgumentsError) as error:
        _ToolSchema({}).validate(value)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("kind", ["bytes", "unicode-bytes", "nodes", "depth", "cycle"])
def test_argument_resource_limits(kind):
    if kind == "bytes":
        value = {"x": "x" * 1_000_000}
    elif kind == "unicode-bytes":
        value = {"x": "é" * 500_000}
    elif kind == "nodes":
        value = {"x": [None] * 100_001}
    elif kind == "cycle":
        value = {}
        value["x"] = value
    else:
        value = {}
        for _ in range(101):
            value = {"x": value}
    with pytest.raises(_ToolArgumentsError):
        _ToolSchema({}).validate(value)


def test_schema_size_limit_uses_configuration_error_category():
    with pytest.raises(NativeToolSchemaError):
        _ToolSchema({"description": "x" * 1_000_000})


def test_empty_schema_keeps_object_argument_shorthand():
    validator = _ToolSchema({})
    assert validator.export() == {"type": "object", "properties": {}}
    validator.validate({})


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_control_flow_exceptions_are_not_model_argument_errors(monkeypatch, error):
    validator = _ToolSchema({})

    def interrupted(*args):
        raise error()

    monkeypatch.setattr(type(validator._validator), "validate", interrupted)
    with pytest.raises(error):
        validator.validate({})
