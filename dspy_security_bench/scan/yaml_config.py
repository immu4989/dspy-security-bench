"""Resource-bounded YAML intake for scan configuration, not general YAML files."""
from __future__ import annotations

import math
from pathlib import Path

import yaml

MAX_BYTES = 1_000_000
MAX_DEPTH = 50
MAX_NODES = 10_000
MAX_NUMBER_CHARS = 128


class ConfigLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.config_depth = 0
        self.config_nodes = 0

    def compose_node(self, parent, index):
        self.config_nodes += 1
        if self.config_nodes > MAX_NODES:
            raise ValueError("config exceeds YAML node limit")
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            # Scalar reuse is harmless and historically supported. Collection
            # reuse can form cycles or hide exponentially expanded structures.
            if not isinstance(self.anchors.get(event.anchor), yaml.ScalarNode):
                raise ValueError("config collection aliases are not supported")
        self.config_depth += 1
        try:
            if self.config_depth > MAX_DEPTH:
                raise ValueError("config exceeds YAML nesting limit")
            return super().compose_node(parent, index)
        finally:
            self.config_depth -= 1

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise ValueError("config requires YAML mappings")
        result = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ValueError("config YAML merges are not supported; use explicit settings")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ValueError("config mapping keys must be strings")
            if key in result:
                raise ValueError("config contains duplicate YAML keys")
            result[key] = self.construct_object(value_node, deep=deep)
        return result

    def construct_object(self, node, deep=False):
        allowed = {"null", "bool", "int", "float", "str", "seq", "map"}
        if node.tag not in {f"tag:yaml.org,2002:{name}" for name in allowed}:
            raise ValueError("config contains an unsupported YAML value type")
        if node.tag in {"tag:yaml.org,2002:int", "tag:yaml.org,2002:float"}:
            if len(node.value) > MAX_NUMBER_CHARS:
                raise ValueError("config numeric literal exceeds length limit")
        try:
            value = super().construct_object(node, deep=deep)
        except (ValueError, KeyError, OverflowError):
            raise ValueError("config contains an invalid YAML value") from None
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("config numbers must be finite")
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeError:
                raise ValueError("config strings must be valid Unicode") from None
        return value


def load_config_yaml(path: str | Path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("config exceeds 1000000 bytes")
    try:
        return yaml.load(raw.decode("utf-8"), Loader=ConfigLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError):
        # PyYAML errors include source excerpts. Do not expose private values.
        raise ValueError("config must be bounded valid UTF-8 YAML") from None
