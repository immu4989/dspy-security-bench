"""Deterministic tool-call policy enforcement for any benchmarked agent.

Prompt defenses are probabilistic. This module provides the complementary
execution boundary: even if an injection persuades the model to request a
dangerous tool call, policy decides whether that call is allowed, denied, or
requires human approval before the live tool is invoked.
"""
from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal

from dspy_security_bench.agents.base import Agent, AgentResult, BenchTool

Action = Literal["allow", "deny", "require_approval"]
Operator = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "contains",
    "matches",
    "not_matches",
    "less_than_or_equal",
    "greater_than_or_equal",
    "any_matches",
    "any_not_matches",
    "exists",
]

_ACTIONS = {"allow", "deny", "require_approval"}
_OPERATORS = {
    "equals", "not_equals", "in", "not_in", "contains", "matches", "not_matches",
    "less_than_or_equal", "greater_than_or_equal", "any_matches", "any_not_matches",
    "exists",
}
_MISSING = object()


@dataclass(frozen=True)
class Condition:
    """One predicate over a tool-call argument."""

    arg: str
    op: Operator
    value: Any = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Condition:
        if not isinstance(raw, Mapping):
            raise ValueError("each condition must be a mapping")
        unknown = set(raw) - {"arg", "op", "value"}
        if unknown:
            fields = ", ".join(sorted(repr(field) for field in unknown))
            raise ValueError(f"condition has unknown fields: {fields}")
        arg = raw.get("arg")
        op = raw.get("op")
        if not isinstance(arg, str) or not arg:
            raise ValueError("condition.arg must be a non-empty string")
        if op not in _OPERATORS:
            raise ValueError(f"condition.op must be one of {sorted(_OPERATORS)}, got {op!r}")
        if "value" not in raw:
            raise ValueError("condition.value is required")
        value = raw.get("value")
        if op in {"matches", "not_matches", "any_matches", "any_not_matches"}:
            if not isinstance(value, str):
                raise ValueError(f"condition {op} requires a regex string value")
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"condition has invalid regex {value!r}: {exc}") from exc
        if op in {"in", "not_in"} and not isinstance(value, (list, tuple, set)):
            raise ValueError(f"condition {op} requires a list value")
        if op == "exists" and not isinstance(value, bool):
            raise ValueError("condition exists requires a boolean value")
        return cls(arg=arg, op=op, value=value)

    def matches(self, arguments: Mapping[str, Any]) -> bool:
        actual = _resolve_argument(arguments, self.arg)
        if self.op == "exists":
            return (actual is not _MISSING) is self.value
        if actual is _MISSING:
            return False
        if self.op == "equals":
            return actual == self.value
        if self.op == "not_equals":
            return actual != self.value
        if self.op == "in":
            return actual in self.value
        if self.op == "not_in":
            return actual not in self.value
        if self.op == "contains":
            try:
                return self.value in actual
            except TypeError:
                return False
        if self.op == "matches":
            return bool(re.search(self.value, str(actual), flags=re.IGNORECASE))
        if self.op == "not_matches":
            return not re.search(self.value, str(actual), flags=re.IGNORECASE)
        if self.op == "less_than_or_equal":
            return _ordered_compare(actual, self.value, lambda left, right: left <= right)
        if self.op == "greater_than_or_equal":
            return _ordered_compare(actual, self.value, lambda left, right: left >= right)
        if self.op == "any_matches":
            return any(re.search(self.value, str(item), flags=re.IGNORECASE) for item in _items(actual))
        if self.op == "any_not_matches":
            return any(not re.search(self.value, str(item), flags=re.IGNORECASE) for item in _items(actual))
        return False


@dataclass(frozen=True)
class ToolRule:
    """First-match-wins rule over tool names and arguments."""

    id: str
    tools: tuple[str, ...]
    action: Action
    reason: str
    when: tuple[Condition, ...] = ()

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ToolRule:
        if not isinstance(raw, Mapping):
            raise ValueError("each rule must be a mapping")
        unknown = set(raw) - {"id", "tool", "tools", "action", "reason", "when"}
        if unknown:
            fields = ", ".join(sorted(repr(field) for field in unknown))
            raise ValueError(f"rule has unknown fields: {fields}")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("rule.id must be a non-empty string")
        if "tool" in raw and "tools" in raw:
            raise ValueError(f"rule {rule_id!r}: set either tool or tools, not both")
        tool_value = raw.get("tools", raw.get("tool"))
        if isinstance(tool_value, str) and tool_value:
            tools = (tool_value,)
        elif (
            isinstance(tool_value, list)
            and tool_value
            and all(isinstance(item, str) and item for item in tool_value)
        ):
            tools = tuple(tool_value)
        else:
            raise ValueError(f"rule {rule_id!r}: set tool or a non-empty tools list")
        action = raw.get("action")
        if action not in _ACTIONS:
            raise ValueError(f"rule {rule_id!r}: action must be one of {sorted(_ACTIONS)}")
        reason = raw.get("reason") or f"matched policy rule {rule_id}"
        if not isinstance(reason, str):
            raise ValueError(f"rule {rule_id!r}: reason must be a string")
        when_raw = raw.get("when", []) or []
        if not isinstance(when_raw, list):
            raise ValueError(f"rule {rule_id!r}: when must be a list")
        return cls(
            id=rule_id,
            tools=tools,
            action=action,
            reason=reason,
            when=tuple(Condition.from_dict(condition) for condition in when_raw),
        )

    def matches(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:
        return any(fnmatchcase(tool_name, pattern) for pattern in self.tools) and all(
            condition.matches(arguments) for condition in self.when
        )


@dataclass(frozen=True)
class PolicyDecision:
    tool: str
    action: Action
    allowed: bool
    rule_id: str
    reason: str
    approval_required: bool = False
    approved: bool | None = None
    arguments: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ToolPolicy:
    """Validated policy document with deterministic first-match evaluation."""

    name: str
    default: Literal["allow", "deny"]
    rules: tuple[ToolRule, ...]
    description: str = ""
    version: int = 1

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ToolPolicy:
        if not isinstance(raw, Mapping):
            raise ValueError("policy must be a mapping")
        unknown = set(raw) - {"version", "name", "description", "default", "rules"}
        if unknown:
            fields = ", ".join(sorted(repr(field) for field in unknown))
            raise ValueError(f"policy has unknown fields: {fields}")
        version = raw.get("version", 1)
        if not isinstance(version, int) or isinstance(version, bool) or version != 1:
            raise ValueError(f"unsupported policy version {version!r}; expected 1")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("policy.name must be a non-empty string")
        default = raw.get("default", "deny")
        if default not in {"allow", "deny"}:
            raise ValueError("policy.default must be allow or deny")
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise ValueError("policy.description must be a string")
        rules_raw = raw.get("rules", [])
        if not isinstance(rules_raw, list):
            raise ValueError("policy.rules must be a list")
        rules = tuple(ToolRule.from_dict(rule) for rule in rules_raw)
        duplicate_ids = _duplicates(rule.id for rule in rules)
        if duplicate_ids:
            raise ValueError(f"policy rule ids must be unique: {', '.join(sorted(duplicate_ids))}")
        return cls(name=name, default=default, rules=rules, description=description, version=version)

    @classmethod
    def load(cls, path: str | Path) -> ToolPolicy:
        import yaml

        source = Path(path)
        try:
            raw = yaml.safe_load(source.read_text())
        except OSError as exc:
            raise ValueError(f"could not read policy {source}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid YAML in policy {source}: {exc}") from exc
        return cls.from_dict(raw)

    def evaluate(self, tool_name: str, arguments: Mapping[str, Any]) -> PolicyDecision:
        if not isinstance(arguments, Mapping):
            raise ValueError("tool arguments must be a mapping")
        for rule in self.rules:
            if rule.matches(tool_name, arguments):
                return PolicyDecision(
                    tool=tool_name,
                    action=rule.action,
                    allowed=rule.action == "allow",
                    approval_required=rule.action == "require_approval",
                    rule_id=rule.id,
                    reason=rule.reason,
                )
        return PolicyDecision(
            tool=tool_name,
            action=self.default,
            allowed=self.default == "allow",
            rule_id="policy-default",
            reason=f"no rule matched; policy default is {self.default}",
        )


ApprovalHandler = Callable[[PolicyDecision, Mapping[str, Any]], bool]


class PolicyEnforcedAgent:
    """Wrap an ``Agent`` and enforce policy before every live tool execution.

    Approval rules fail closed when no approval handler is supplied. Audit
    records omit tool arguments by default so logs do not become a new secret
    store; opt in with ``capture_arguments=True`` when the data is safe.
    """

    def __init__(
        self,
        agent: Agent,
        policy: ToolPolicy,
        *,
        approval_handler: ApprovalHandler | None = None,
        capture_arguments: bool = False,
    ):
        self.agent = agent
        self.policy = policy
        self.approval_handler = approval_handler
        self.capture_arguments = capture_arguments
        self.name = f"{agent.name}+policy:{policy.name}"
        self._audit_log: list[PolicyDecision] = []
        self._audit_lock = threading.Lock()

    @property
    def audit_log(self) -> tuple[PolicyDecision, ...]:
        with self._audit_lock:
            return tuple(self._audit_log)

    def clear_audit_log(self) -> None:
        with self._audit_lock:
            self._audit_log.clear()

    def run(
        self,
        query: str,
        tools: list[BenchTool],
        *,
        system_directive: str = "",
    ) -> AgentResult:
        guarded = [self._guard(tool) for tool in tools]
        return self.agent.run(query, guarded, system_directive=system_directive)

    def _guard(self, tool: BenchTool) -> BenchTool:
        def guarded_call(**kwargs):
            decision = self.policy.evaluate(tool.name, kwargs)
            approved = None
            allowed = decision.allowed
            reason = decision.reason
            if decision.approval_required:
                try:
                    approved = bool(
                        self.approval_handler and self.approval_handler(decision, kwargs)
                    )
                except Exception as exc:
                    approved = False
                    reason = (
                        f"{decision.reason} Approval handler failed closed "
                        f"({type(exc).__name__})."
                    )
                allowed = approved
            recorded = PolicyDecision(
                tool=decision.tool,
                action=decision.action,
                allowed=allowed,
                rule_id=decision.rule_id,
                reason=reason,
                approval_required=decision.approval_required,
                approved=approved,
                arguments=dict(kwargs) if self.capture_arguments else None,
            )
            with self._audit_lock:
                self._audit_log.append(recorded)
            if not allowed:
                suffix = "approval required" if decision.approval_required else "denied"
                return f"[policy {suffix}] rule={decision.rule_id}: {reason}"
            return tool(**kwargs)

        return BenchTool(
            name=tool.name,
            description=tool.description,
            parameters=tool.parameters,
            _call=guarded_call,
        )

    def audit_json(self) -> str:
        return json.dumps([decision.to_dict() for decision in self.audit_log], indent=2, default=str)


def _resolve_argument(arguments: Mapping[str, Any], path: str) -> Any:
    current: Any = arguments
    for segment in path.split("."):
        if isinstance(current, Mapping) and segment in current:
            current = current[segment]
        else:
            return _MISSING
    return current


def _ordered_compare(left: Any, right: Any, compare: Callable[[Any, Any], bool]) -> bool:
    try:
        return compare(left, right)
    except (TypeError, ValueError):
        return False


def _items(value: Any) -> Sequence[Any]:
    if isinstance(value, (list, tuple, set)):
        return tuple(value)
    return (value,)


def _duplicates(values) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates
