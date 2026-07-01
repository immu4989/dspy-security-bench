"""Smoke-test a non-OpenAI LM provider against the DSPy + AgentDojo stack.

Runs a graduated sequence of checks and reports pass/fail per stage.
Total cost with the default matrix is <$0.10.

Stages:
  1. env-var check   — required API key is set in the environment
  2. litellm direct  — raw litellm.completion() round-trip
  3. dspy.LM wrapper — dspy.Predict via the provider
  4. dspy.ReActV2    — 1 iteration with a fake tool (tool-calling smoke)
  5. AgentDojo eval  — (--full only) 2 user tasks × direct attack on workspace

Usage:
    # Fast (stages 1-4, ~$0.01):
    python scripts/smoke_test_provider.py deepseek/deepseek-chat

    # Full (stages 1-5, ~$0.05):
    python scripts/smoke_test_provider.py deepseek/deepseek-chat --full

    # Try other providers you have keys for:
    python scripts/smoke_test_provider.py mistral/mistral-small-latest
    python scripts/smoke_test_provider.py together_ai/Qwen/Qwen2.5-72B-Instruct
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import traceback


# provider prefix in the litellm model string → required env var name
PROVIDER_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "moonshot": "MOONSHOT_API_KEY",     # Kimi
    "together_ai": "TOGETHER_API_KEY",
    "hyperbolic": "HYPERBOLIC_API_KEY",
    "deepinfra": "DEEPINFRA_API_KEY",
    "dashscope": "DASHSCOPE_API_KEY",   # Alibaba (Qwen)
    "zhipuai": "ZHIPU_API_KEY",         # GLM
}


def _resolve_env_var(model_str: str) -> str | None:
    prefix = model_str.split("/", 1)[0]
    return PROVIDER_ENV.get(prefix)


class Result:
    def __init__(self):
        self.stages: list[tuple[str, bool, str, float]] = []

    def record(self, stage: str, ok: bool, detail: str, elapsed: float):
        self.stages.append((stage, ok, detail, elapsed))
        symbol = "✓" if ok else "✗"
        print(f"  [{symbol}] {stage}  ({elapsed:.2f}s)  {detail}")

    def summary(self):
        passed = sum(1 for _, ok, _, _ in self.stages if ok)
        total = len(self.stages)
        total_time = sum(t for _, _, _, t in self.stages)
        print()
        print("=" * 74)
        print(f" SMOKE TEST RESULT: {passed}/{total} passed  ({total_time:.1f}s total)")
        print("=" * 74)
        if passed == total:
            print(" All stages passed. Provider is DSPy-compatible for eval-time roles.")
            print(" See recommendation notes at the end.")
        else:
            print(f" {total - passed} stage(s) failed. Do NOT commit budget until fixed.")
        return passed == total


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

def stage_env(model_str: str, r: Result):
    t0 = time.time()
    env_var = _resolve_env_var(model_str)
    if env_var is None:
        r.record("env-var", False,
                 f"unknown provider prefix in {model_str!r}; add to PROVIDER_ENV",
                 time.time() - t0)
        return False
    if not os.environ.get(env_var):
        r.record("env-var", False, f"{env_var} not set", time.time() - t0)
        return False
    prefix = os.environ[env_var][:6]
    r.record("env-var", True, f"{env_var} set (prefix: {prefix})", time.time() - t0)
    return True


def stage_litellm(model_str: str, r: Result):
    t0 = time.time()
    try:
        import litellm
        litellm.drop_params = True  # some providers reject seed/logprobs
        resp = litellm.completion(
            model=model_str,
            messages=[{"role": "user", "content": "Reply with the single word: PING"}],
            max_tokens=8, temperature=0.0,
        )
        text = resp.choices[0].message.content
        ok = text and "PING" in text.upper()
        detail = f'response: {text!r}'
        r.record("litellm direct", ok, detail, time.time() - t0)
        return ok
    except Exception as e:
        r.record("litellm direct", False, f"{type(e).__name__}: {e}", time.time() - t0)
        return False


def stage_dspy_predict(model_str: str, r: Result):
    t0 = time.time()
    try:
        import dspy
        lm = dspy.LM(model_str, temperature=0.0, max_tokens=64)
        with dspy.context(lm=lm):
            predict = dspy.Predict("question -> answer")
            out = predict(question="What is 7 times 6? Reply with just the number.")
        answer = str(out.answer)
        ok = "42" in answer
        r.record("dspy.Predict", ok, f'answer: {answer[:80]!r}', time.time() - t0)
        return ok
    except Exception as e:
        r.record("dspy.Predict", False, f"{type(e).__name__}: {e}", time.time() - t0)
        return False


def stage_reactv2_toolcalling(model_str: str, r: Result):
    """Verify the provider's tool-calling works with dspy.ReActV2."""
    t0 = time.time()
    try:
        import dspy

        def get_current_temperature(city: str) -> str:
            """Look up the current temperature for a city in fahrenheit."""
            fixtures = {"dallas": "97F", "seattle": "68F"}
            return fixtures.get(city.lower(), "unknown")

        lm = dspy.LM(model_str, temperature=0.0, max_tokens=256)
        with dspy.context(lm=lm):
            tool = dspy.Tool(get_current_temperature)
            agent = dspy.ReActV2(
                signature="query -> answer",
                tools=[tool],
                max_iters=3,
            )
            out = agent(query="What is the current temperature in Dallas?")
        answer = str(out.answer)
        ok = "97" in answer
        r.record("dspy.ReActV2 tool call", ok, f'answer: {answer[:120]!r}', time.time() - t0)
        return ok
    except Exception as e:
        r.record("dspy.ReActV2 tool call", False,
                 f"{type(e).__name__}: {str(e)[:200]}",
                 time.time() - t0)
        return False


def stage_agentdojo_eval(model_str: str, r: Result):
    """Run 2 user tasks × direct attack on the workspace suite. This is the
    real deal — it exercises the exact code path phase 2 will use."""
    t0 = time.time()
    try:
        import dspy
        from dspy_security_bench.optimizers import _make_agent_factory
        from dspy_security_bench.runner import evaluate_factories

        lm = dspy.LM(model_str, temperature=0.2, max_tokens=1024)
        dspy.configure(lm=lm)

        factory = _make_agent_factory(None, base_signature="query -> answer")
        df = evaluate_factories(
            factories={"smoke": factory},
            suite_name="workspace",
            attacks=["direct"],
            user_task_ids=["user_task_0", "user_task_1"],
            injection_task_ids=["injection_task_0"],
            max_iters=5,
            force_rerun=True,
            verbose=False,
        )
        n_rows = len(df)
        ok = n_rows == 2
        detail = f"{n_rows} eval rows returned; utility_mean={df['utility'].mean():.2f} security_mean={df['security'].mean():.2f}"
        r.record("AgentDojo workspace eval (2 tasks, direct)", ok, detail, time.time() - t0)
        return ok
    except Exception as e:
        tb = traceback.format_exc().splitlines()
        r.record("AgentDojo workspace eval (2 tasks, direct)", False,
                 f"{type(e).__name__}: {str(e)[:200]}",
                 time.time() - t0)
        # Print the last 6 traceback lines so the failure is diagnosable
        for line in tb[-8:]:
            print(f"      | {line}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("model", help="litellm-formatted model string (e.g. deepseek/deepseek-chat)")
    p.add_argument("--full", action="store_true", help="include AgentDojo stage (adds ~$0.03-0.05)")
    args = p.parse_args()

    print("=" * 74)
    print(f" SMOKE TEST: {args.model}")
    print("=" * 74)

    r = Result()

    if not stage_env(args.model, r): r.summary(); sys.exit(1)
    if not stage_litellm(args.model, r): r.summary(); sys.exit(1)
    if not stage_dspy_predict(args.model, r): r.summary(); sys.exit(1)
    if not stage_reactv2_toolcalling(args.model, r):
        r.summary()
        print()
        print(" Note: ReActV2 tool-calling failure means this provider is NOT usable")
        print(" as the execution LM for phase 2. It may still work as a judge or")
        print(" reflection LM (both are single-shot calls without tool-calling).")
        sys.exit(1)

    if args.full:
        stage_agentdojo_eval(args.model, r)

    ok = r.summary()

    if ok and args.full:
        print()
        print(" Recommendation:")
        print("   - Judge LM: safe swap-in for phase 2 (removes same-model bias vs execution)")
        print("   - Reflection LM: safe swap-in for GEPA compile")
        print("   - Execution LM: viable if you accept losing v0.1 comparability")
        print()
        print(" Next: update `scripts/estimate_cost.py` PRICES dict with this model's")
        print(" per-token cost, then re-run --preset phase2 to see the new estimate.")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
