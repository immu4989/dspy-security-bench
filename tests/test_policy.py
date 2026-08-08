import json
from importlib.resources import files

import pytest

from dspy_security_bench.agents.base import AgentResult, BenchTool, ToolCall
from dspy_security_bench.policy import Condition, PolicyEnforcedAgent, ToolPolicy
from dspy_security_bench.policy_cli import PROFILES
from dspy_security_bench.policy_cli import main as policy_main


def _policy(**overrides):
    raw = {
        "version": 1,
        "name": "test",
        "default": "deny",
        "rules": [],
    }
    raw.update(overrides)
    return ToolPolicy.from_dict(raw)


@pytest.mark.parametrize(
    ("condition", "arguments", "expected"),
    [
        ({"arg": "amount", "op": "less_than_or_equal", "value": 100}, {"amount": 99}, True),
        ({"arg": "amount", "op": "greater_than_or_equal", "value": 100}, {"amount": 99}, False),
        ({"arg": "currency", "op": "in", "value": ["USD", "CAD"]}, {"currency": "USD"}, True),
        ({"arg": "currency", "op": "not_in", "value": ["USD"]}, {"currency": "EUR"}, True),
        ({"arg": "to", "op": "matches", "value": "@example\\.com$"}, {"to": "a@example.com"}, True),
        ({"arg": "to", "op": "not_matches", "value": "@example\\.com$"}, {"to": "a@evil.com"}, True),
        ({"arg": "recipients", "op": "any_not_matches", "value": "@example\\.com$"}, {"recipients": ["a@example.com", "b@evil.com"]}, True),
        ({"arg": "meta.owner", "op": "equals", "value": "support"}, {"meta": {"owner": "support"}}, True),
        ({"arg": "missing", "op": "exists", "value": False}, {}, True),
        ({"arg": "subject", "op": "contains", "value": "invoice"}, {"subject": "new invoice"}, True),
    ],
)
def test_condition_operators(condition, arguments, expected):
    assert Condition.from_dict(condition).matches(arguments) is expected


def test_policy_is_first_match_wins():
    policy = _policy(rules=[
        {
            "id": "small-refund",
            "tool": "refund",
            "action": "allow",
            "when": [{"arg": "amount", "op": "less_than_or_equal", "value": 100}],
        },
        {"id": "other-refund", "tool": "refund", "action": "require_approval"},
    ])
    assert policy.evaluate("refund", {"amount": 50}).action == "allow"
    assert policy.evaluate("refund", {"amount": 500}).action == "require_approval"
    assert policy.evaluate("delete_account", {}).action == "deny"


@pytest.mark.parametrize(
    "raw,match",
    [
        ({"name": "x", "default": "sometimes", "rules": []}, "default"),
        ({"name": "x", "version": True, "rules": []}, "version"),
        ({"name": "x", "rules": ["not-a-rule"]}, "mapping"),
        ({"name": "x", "rules": [{"id": "a", "tool": "", "action": "deny"}]}, "non-empty"),
        ({"name": "x", "rules": [{"id": "a", "tool": "x", "tools": ["y"], "action": "deny"}]}, "either"),
        ({"name": "x", "rules": [{"id": "a", "tool": "x", "action": "explode"}]}, "action"),
        ({"name": "x", "rules": [{"id": "a", "tool": "x", "action": "deny"}, {"id": "a", "tool": "y", "action": "allow"}]}, "unique"),
        ({"name": "x", "rules": [{"id": "a", "tool": "x", "action": "deny", "when": ["not-a-condition"]}]}, "mapping"),
        ({"name": "x", "rules": [{"id": "a", "tool": "x", "action": "deny", "when": [{"arg": "x", "op": "equals"}]}]}, "value"),
        ({"name": "x", "rules": [{"id": "a", "tool": "x", "action": "deny", "when": [{"arg": "x", "op": "matches", "value": "["}]}]}, "invalid regex"),
    ],
)
def test_policy_validation_rejects_unsafe_documents(raw, match):
    with pytest.raises(ValueError, match=match):
        ToolPolicy.from_dict(raw)


class _CallingAgent:
    name = "calling-agent"

    def __init__(self, arguments):
        self.arguments = arguments

    def run(self, query, tools, *, system_directive=""):
        result = tools[0](**self.arguments)
        return AgentResult(
            final_answer=str(result),
            tool_calls=[ToolCall(name=tools[0].name, args=self.arguments, result=str(result))],
        )


def _live_tool(calls):
    def execute(**kwargs):
        calls.append(kwargs)
        return "executed"

    return BenchTool(
        name="transfer_funds",
        description="move money",
        parameters={"type": "object"},
        _call=execute,
    )


def test_policy_wrapper_blocks_live_side_effect_and_audits_without_arguments():
    calls = []
    wrapped = PolicyEnforcedAgent(_CallingAgent({"amount": 500}), _policy())
    result = wrapped.run("transfer", [_live_tool(calls)])
    assert calls == []
    assert "policy denied" in result.final_answer
    assert wrapped.audit_log[0].allowed is False
    assert wrapped.audit_log[0].arguments is None


def test_approval_fails_closed_without_handler():
    calls = []
    policy = _policy(rules=[{
        "id": "approve-transfer", "tool": "transfer_funds", "action": "require_approval",
    }])
    wrapped = PolicyEnforcedAgent(_CallingAgent({"amount": 25}), policy)
    wrapped.run("transfer", [_live_tool(calls)])
    assert calls == []
    assert wrapped.audit_log[0].approval_required is True
    assert wrapped.audit_log[0].approved is False


def test_approval_handler_can_release_exact_tool_call():
    calls = []
    approvals = []
    policy = _policy(rules=[{
        "id": "approve-transfer", "tool": "transfer_funds", "action": "require_approval",
    }])

    def approve(decision, arguments):
        approvals.append((decision.rule_id, arguments["amount"]))
        return arguments["amount"] <= 50

    wrapped = PolicyEnforcedAgent(
        _CallingAgent({"amount": 25}), policy,
        approval_handler=approve, capture_arguments=True,
    )
    result = wrapped.run("transfer", [_live_tool(calls)])
    assert result.final_answer == "executed"
    assert calls == [{"amount": 25}]
    assert approvals == [("approve-transfer", 25)]
    assert wrapped.audit_log[0].arguments == {"amount": 25}
    assert json.loads(wrapped.audit_json())[0]["allowed"] is True


def test_approval_handler_failure_is_fail_closed():
    calls = []
    policy = _policy(rules=[{
        "id": "approve-transfer", "tool": "transfer_funds", "action": "require_approval",
    }])

    def unavailable_approval_service(*_):
        raise TimeoutError("approval service unavailable")

    wrapped = PolicyEnforcedAgent(
        _CallingAgent({"amount": 25}), policy, approval_handler=unavailable_approval_service,
    )
    result = wrapped.run("transfer", [_live_tool(calls)])
    assert calls == []
    assert "failed closed" in result.final_answer
    assert wrapped.audit_log[0].approved is False


def test_every_builtin_profile_is_valid():
    for profile in PROFILES:
        resource = files("dspy_security_bench.templates").joinpath("policies", f"{profile}.yaml")
        import yaml

        policy = ToolPolicy.from_dict(yaml.safe_load(resource.read_text()))
        assert policy.name == profile
        assert policy.rules


def test_policy_json_schema_is_packaged_and_parseable():
    resource = files("dspy_security_bench").joinpath("schemas", "policy.schema.json")
    schema = json.loads(resource.read_text())
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["properties"]["version"] == {"const": 1}


def test_customer_support_profile_models_real_authority_boundaries():
    resource = files("dspy_security_bench.templates").joinpath("policies", "customer-support.yaml")
    import yaml

    policy = ToolPolicy.from_dict(yaml.safe_load(resource.read_text()))
    assert policy.evaluate("search_customer", {"q": "42"}).action == "allow"
    assert policy.evaluate("send_email", {"recipients": ["attacker@evil.com"]}).action == "deny"
    assert policy.evaluate("send_email", {"recipients": ["user@example.com"]}).action == "require_approval"
    assert policy.evaluate("issue_refund", {"amount": 50, "currency": "USD"}).action == "allow"
    assert policy.evaluate("issue_refund", {"amount": 500, "currency": "USD"}).action == "require_approval"


def test_policy_cli_scaffolds_validates_and_checks(tmp_path, capsys):
    path = tmp_path / "policy.yaml"
    assert policy_main(["init", "--profile", "research-rag", "--out", str(path)]) == 0
    assert policy_main(["validate", "--policy", str(path)]) == 0
    assert policy_main([
        "check", "--policy", str(path), "--tool", "search_web", "--args", '{"q":"x"}',
    ]) == 0
    assert policy_main([
        "check", "--policy", str(path), "--tool", "write_memory", "--args", '{"value":"x"}',
    ]) == 3
    assert "APPROVAL REQUIRED" in capsys.readouterr().out
