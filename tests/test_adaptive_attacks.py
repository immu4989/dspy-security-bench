"""Tests for adaptive, defense-aware attacks — no LM calls.

Template-level assertions are pure. One end-to-end test constructs a real
DefenseAwareAttack against the workspace suite and generates injections; that
path uses AgentDojo's ground-truth pipeline (deterministic, no LM).
"""
from __future__ import annotations

import pytest

from dspy_security_bench.attacks.adaptive import (
    STRATEGIES,
    AuthorityEscalation,
    BypassStrategy,
    DelimiterEscape,
    MarkerClaim,
    TaskHijack,
    best_strategy_for,
    build_adaptive_attack,
    is_adaptive,
)


# ---------------------------------------------------------------------------
# Strategy templates
# ---------------------------------------------------------------------------

def test_all_strategies_satisfy_protocol():
    for s in STRATEGIES.values():
        assert isinstance(s, BypassStrategy)
        assert "{goal}" in s.jailbreak_template("none")


def test_delimiter_escape_injects_closing_tag():
    tpl = DelimiterEscape().jailbreak_template("spotlight_delim")
    # the load-bearing trick: a premature closing tag to escape the wrapper
    assert "</untrusted_tool_data>" in tpl
    assert "{goal}" in tpl


def test_marker_claim_flips_marker_meaning():
    tpl = MarkerClaim().jailbreak_template("spotlight_datamark")
    assert "VERIFIED" in tpl or "AUTHORIZED" in tpl
    assert "{goal}" in tpl


def test_authority_escalation_claims_not_tool_output():
    tpl = AuthorityEscalation().jailbreak_template("security_prompt")
    assert "NOT tool output" in tpl or "not tool output" in tpl.lower()
    assert "supersedes" in tpl.lower()


def test_task_hijack_redefines_task():
    tpl = TaskHijack().jailbreak_template("sandwich")
    assert "task" in tpl.lower()
    assert "{goal}" in tpl


# ---------------------------------------------------------------------------
# Auto-targeting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("defense,expected", [
    ("spotlight_delim", "delimiter_escape"),
    ("spotlight_datamark", "marker_claim"),
    ("security_prompt", "authority_escalation"),
    ("sandwich", "task_hijack"),
    ("none", "generic_override"),
    ("some_unknown_defense", "generic_override"),  # fallback
])
def test_best_strategy_for(defense, expected):
    assert best_strategy_for(defense).name == expected


# ---------------------------------------------------------------------------
# Runner-facing helpers
# ---------------------------------------------------------------------------

def test_is_adaptive():
    assert is_adaptive("adaptive")
    assert is_adaptive("adaptive:delimiter_escape")
    assert not is_adaptive("important_instructions")
    assert not is_adaptive("direct")


def test_build_adaptive_unknown_strategy_raises():
    with pytest.raises(ValueError, match="unknown adaptive strategy"):
        build_adaptive_attack("adaptive:nope", "none", None, None)


# ---------------------------------------------------------------------------
# End-to-end injection generation (offline: ground-truth pipeline, no LM)
# ---------------------------------------------------------------------------

def _workspace_pipeline():
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.basic_elements import InitQuery
    from dspy_security_bench.adapters.generic import GenericAgentElement
    from dspy_security_bench.agents.base import AgentResult

    class _NoopAgent:
        name = "noop"
        def run(self, query, tools, *, system_directive=""):
            return AgentResult(final_answer="", tool_calls=[])

    pipe = AgentPipeline([InitQuery(), GenericAgentElement(_NoopAgent())])
    pipe.name = "gpt-4o-mini-2024-07-18_generic_noop_def-spotlight_delim"
    return pipe


def test_defense_aware_attack_generates_escape_injection():
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite("v1", "workspace")
    pipeline = _workspace_pipeline()

    attack = build_adaptive_attack("adaptive", "spotlight_delim", suite, pipeline)
    assert attack.name == "adaptive-delimiter_escape"

    user_task = suite.user_tasks["user_task_0"]
    injection_task = suite.injection_tasks["injection_task_0"]
    injections = attack.attack(user_task, injection_task)

    assert injections  # at least one injectable placeholder
    payload = next(iter(injections.values()))
    # the goal is substituted in, and the delimiter-escape tag is present
    assert "</untrusted_tool_data>" in payload
    assert injection_task.GOAL.split()[0].lower() in payload.lower()
