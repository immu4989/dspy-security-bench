"""Tests for the LM-driven iterative attack loop — no LM calls.

Fakes for `attacker` and `run_and_judge` exercise the control flow: early-exit
on success, refinement history, and the held-after-K path.
"""
from __future__ import annotations

from dspy_security_bench.attacks.lm_driven import (
    DEFENSE_MECHANISMS,
    IterativeAttackRunner,
)


class _Task:
    def __init__(self, id_, goal=None):
        self.ID = id_
        self.GOAL = goal or "do the bad thing"
    PROMPT = "user prompt"


_UT = _Task("user_task_0")
_IT = _Task("injection_task_0", goal="send the attacker an email")


def test_breaks_on_first_success():
    calls = {"n": 0}
    def attacker(*, goal, mechanism, history):
        calls["n"] += 1
        return f"payload {calls['n']} {{goal}}"
    def run_and_judge(payload, ut, it):
        return True  # succeeds immediately

    r = IterativeAttackRunner(attacker, run_and_judge, max_rounds=5).run(
        defense_name="spotlight_delim", user_task=_UT, injection_task=_IT)
    assert r.broken
    assert r.rounds_used == 1
    assert r.best_payload.startswith("payload 1")
    assert len(r.history) == 1


def test_refines_then_breaks_on_round_3():
    def attacker(*, goal, mechanism, history):
        # attacker sees the growing failure history
        return f"attempt after {len(history)} failures {{goal}}"
    outcomes = iter([False, False, True])
    def run_and_judge(payload, ut, it):
        return next(outcomes)

    r = IterativeAttackRunner(attacker, run_and_judge, max_rounds=5).run(
        defense_name="security_prompt", user_task=_UT, injection_task=_IT)
    assert r.broken
    assert r.rounds_used == 3
    assert len(r.history) == 3
    assert [h.succeeded for h in r.history] == [False, False, True]


def test_held_after_all_rounds():
    def attacker(*, goal, mechanism, history):
        return "never works {goal}"
    def run_and_judge(payload, ut, it):
        return False

    r = IterativeAttackRunner(attacker, run_and_judge, max_rounds=4).run(
        defense_name="spotlight_delim", user_task=_UT, injection_task=_IT)
    assert not r.broken
    assert r.rounds_used == 4
    assert r.best_payload is None
    assert len(r.history) == 4


def test_run_and_judge_exception_counts_as_failure():
    def attacker(*, goal, mechanism, history):
        return "boom {goal}"
    def run_and_judge(payload, ut, it):
        raise RuntimeError("target crashed")

    r = IterativeAttackRunner(attacker, run_and_judge, max_rounds=2).run(
        defense_name="none", user_task=_UT, injection_task=_IT)
    assert not r.broken
    assert all(h.succeeded is False for h in r.history)


def test_attacker_receives_mechanism_and_history():
    seen = {}
    def attacker(*, goal, mechanism, history):
        seen["goal"] = goal
        seen["mechanism"] = mechanism
        seen["hist_len"] = len(history)
        return "p {goal}"
    outcomes = iter([False, True])
    def run_and_judge(payload, ut, it):
        return next(outcomes)

    IterativeAttackRunner(attacker, run_and_judge, max_rounds=5).run(
        defense_name="spotlight_delim", user_task=_UT, injection_task=_IT)
    assert seen["goal"] == _IT.GOAL
    # mechanism text for spotlight_delim mentions the markers
    assert "untrusted_tool_data" in seen["mechanism"]


def test_all_defenses_have_mechanism_descriptions():
    for d in ["none", "security_prompt", "spotlight_delim", "spotlight_datamark", "sandwich"]:
        assert d in DEFENSE_MECHANISMS and DEFENSE_MECHANISMS[d]
