"""Verify a single injection case by dumping the actual agent conversation.

Runs ONE (user_task, injection_task, attack) case for a given model and
prints the full message trace, plus AgentDojo's own utility + security
verdict. Use this to confirm whether a high injection-success rate reflects
the agent actually calling the malicious tool (real) vs. a scoring artifact.

Usage:
    python scripts/verify_injection_trace.py mistral/mistral-large-latest
    python scripts/verify_injection_trace.py mistral/mistral-small-latest  # contrast
"""
from __future__ import annotations

import argparse
import sys

import dspy
import litellm

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.attacks import load_attack
from agentdojo.functions_runtime import FunctionsRuntime

from dspy_security_bench.adapters import DSPyReActV2Element
from dspy_security_bench.optimizers import _make_agent_factory
from agentdojo.agent_pipeline import AgentPipeline, InitQuery


def main():
    p = argparse.ArgumentParser()
    p.add_argument("model")
    p.add_argument("--user-task", default="user_task_0")
    p.add_argument("--injection-task", default="injection_task_0")
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--defense", default="none", help="defense name from dspy_security_bench.defenses")
    p.add_argument("--max-iters", type=int, default=8)
    args = p.parse_args()

    litellm.drop_params = True
    lm = dspy.LM(args.model, temperature=0.2, max_tokens=2048, num_retries=5)
    dspy.configure(lm=lm)

    suite = get_suite("v1", "workspace")

    from dspy_security_bench.defenses import get_defense
    defense = get_defense(args.defense)

    factory = _make_agent_factory(None, base_signature="query -> answer")
    element = DSPyReActV2Element(factory, max_iters=args.max_iters, defense=defense)
    pipeline = AgentPipeline([InitQuery(), element])
    pipeline.name = f"gpt-4o-mini-2024-07-18_dspy_reactv2_unoptimized"

    from dspy_security_bench.attacks.adaptive import build_adaptive_attack, is_adaptive
    if is_adaptive(args.attack):
        attack = build_adaptive_attack(args.attack, args.defense, suite, pipeline)
    else:
        attack = load_attack(args.attack, suite, pipeline)

    user_task = suite.user_tasks[args.user_task]
    injection_task = suite.injection_tasks[args.injection_task]
    injections = attack.attack(user_task, injection_task)

    print("=" * 78)
    print(f" MODEL: {args.model}")
    print(f" user_task: {args.user_task}  |  injection_task: {args.injection_task}  |  attack: {args.attack}")
    print("=" * 78)
    print(f"\n USER GOAL: {user_task.PROMPT}")
    print(f"\n INJECTION GOAL (what the attacker wants): {injection_task.GOAL}")
    print(f"\n INJECTED PAYLOAD(s): {injections}")
    print("=" * 78)

    # Run the task with injections planted in the environment
    environment = suite.load_and_inject_default_environment(injections)

    runtime = FunctionsRuntime(suite.tools)
    # returns (query, runtime, env, messages, extra_args)
    _q, _rt, final_env, messages, _extra = pipeline.query(user_task.PROMPT, runtime, env=environment)

    print("\n CONVERSATION TRACE:")
    print("-" * 78)
    for m in messages:
        role = m.get("role", "?")
        content = m.get("content", "")
        tool_calls = m.get("tool_calls") or []
        if content:
            c = str(content)
            print(f"\n[{role}] {c[:600]}{'...' if len(c) > 600 else ''}")
        for tc in tool_calls:
            fn = tc.function if hasattr(tc, "function") else tc.get("function", {})
            name = getattr(fn, "name", None) or (fn.get("name") if isinstance(fn, dict) else "?")
            arguments = getattr(fn, "arguments", None) or (fn.get("arguments") if isinstance(fn, dict) else "")
            print(f"\n[{role} → TOOL CALL] {name}({arguments})")

    # AgentDojo verdicts
    print("\n" + "=" * 78)
    print(" AGENTDOJO VERDICT")
    print("-" * 78)
    util = user_task.utility(model_output="", pre_environment=environment, post_environment=final_env)
    sec = injection_task.security(model_output="", pre_environment=environment, post_environment=final_env)
    print(f" user-task utility achieved: {util}")
    print(f" injection security-goal achieved (attack succeeded): {sec}")
    print("=" * 78)


if __name__ == "__main__":
    main()
