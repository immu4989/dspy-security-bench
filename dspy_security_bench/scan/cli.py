"""`dspy-security-bench scan` — the CI gate.

Runs the injection benchmark against a target agent, applies a pass/fail gate,
renders reports (terminal / JSON / SARIF), and exits non-zero on failure so CI
blocks the merge.
"""
from __future__ import annotations

import argparse
import importlib
import logging
import re
import sys

from dspy_security_bench.scan.config import ScanConfig
from dspy_security_bench.scan.gate import evaluate_gate
from dspy_security_bench.scan.report import emit

log = logging.getLogger("dspy_security_bench.scan")


def _resolve_agent(spec) -> object:
    """Build the agent under test from an AgentSpec."""
    if spec.import_path:
        mod_name, _, attr = spec.import_path.partition(":")
        if not attr:
            raise ValueError(f"agent.import must be 'module:callable', got {spec.import_path!r}")
        factory = getattr(importlib.import_module(mod_name), attr)
        agent = factory()
        return agent
    # built-in function-calling agent
    from dspy_security_bench.agents import LiteLLMFunctionCallingAgent
    return LiteLLMFunctionCallingAgent(spec.model, name=spec.resolved_name())


def _apply_overrides(cfg: ScanConfig, args) -> ScanConfig:
    if args.agent_model:
        cfg.agent.model, cfg.agent.import_path = args.agent_model, None
    if args.agent:
        cfg.agent.import_path, cfg.agent.model = args.agent, None
    if args.suites:
        cfg.scan.suites = args.suites
    if args.attacks:
        cfg.scan.attacks = args.attacks
    if args.defenses:
        cfg.scan.defenses = args.defenses
    if args.user_tasks is not None:
        cfg.scan.user_tasks = args.user_tasks
    if args.injection_tasks is not None:
        cfg.scan.injection_tasks = args.injection_tasks
    if args.min_security is not None:
        cfg.gate.min_security = args.min_security
    if args.baseline:
        cfg.gate.mode, cfg.gate.baseline = "regression", args.baseline
    if args.max_regression is not None:
        cfg.gate.max_regression = args.max_regression
    if args.format:
        cfg.report.formats = args.format
    if args.sarif:
        if "sarif" not in cfg.report.formats:
            cfg.report.formats.append("sarif")
        cfg.report.sarif_out = args.sarif
    if args.json:
        if "json" not in cfg.report.formats:
            cfg.report.formats.append("json")
        cfg.report.json_out = args.json
    if args.fail_on:
        cfg.fail_on = args.fail_on
    return cfg


def _natural_task_order(task_ids) -> list[str]:
    """Sort task ids numerically so selection is stable across dependency releases."""
    def key(task_id: str):
        match = re.search(r"(\d+)$", task_id)
        return (int(match.group(1)) if match else float("inf"), task_id)
    return sorted(task_ids, key=key)


_CURATED_USER_TASKS = {
    "workspace": ["user_task_0", "user_task_1", "user_task_3", "user_task_10", "user_task_11"],
}


def _select_tasks(suite_name: str, requested, *, kind: str) -> list[str] | None:
    """Resolve a count to actual suite task ids; ``None`` tells AgentDojo to run all."""
    if requested == "all":
        return None

    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", suite_name)
    available = suite.user_tasks if kind == "user" else suite.injection_tasks
    ordered = _natural_task_order(available)
    if kind == "user" and suite_name in _CURATED_USER_TASKS:
        curated = [task_id for task_id in _CURATED_USER_TASKS[suite_name] if task_id in available]
        ordered = curated + [task_id for task_id in ordered if task_id not in curated]
    if requested > len(ordered):
        raise ValueError(
            f"suite {suite_name!r} has {len(ordered)} {kind} tasks; requested {requested}"
        )
    return ordered[:requested]


def build_scan_plan(cfg: ScanConfig) -> list[dict]:
    """Resolve the exact benchmark matrix without building or calling an agent."""
    from agentdojo.attacks.attack_registry import ATTACKS
    from agentdojo.task_suite.load_suites import get_suite

    from dspy_security_bench.attacks.adaptive import STRATEGIES, is_adaptive
    from dspy_security_bench.defenses import DEFENSES

    cfg.validate()
    for defense in cfg.scan.defenses:
        if defense not in DEFENSES:
            raise ValueError(f"unknown defense {defense!r}")
    attack_kinds = {}
    for attack in cfg.scan.attacks:
        if is_adaptive(attack):
            if attack != "adaptive" and attack.split(":", 1)[1] not in STRATEGIES:
                raise ValueError(f"unknown adaptive strategy {attack!r}")
            attack_kinds[attack] = False
        elif attack not in ATTACKS:
            raise ValueError(f"unknown attack {attack!r}")
        else:
            attack_kinds[attack] = ATTACKS[attack].is_dos_attack
    plan = []
    for suite in cfg.scan.suites:
        users = _select_tasks(suite, cfg.scan.user_tasks, kind="user")
        injections = _select_tasks(suite, cfg.scan.injection_tasks, kind="injection")
        if users is None or injections is None:
            suite_obj = get_suite("v1", suite)
            user_count = len(suite_obj.user_tasks) if users is None else len(users)
            injection_count = len(suite_obj.injection_tasks) if injections is None else len(injections)
        else:
            user_count, injection_count = len(users), len(injections)
        attack_cases = []
        for attack, is_dos in attack_kinds.items():
            count = 1 if is_dos else injection_count
            attack_cases.append({
                "attack": attack, "is_dos_attack": is_dos,
                "injection_tasks": count,
                "injection_task_ids": [next(iter(get_suite("v1", suite).injection_tasks))] if is_dos else injections,
                "cases": user_count * count * len(cfg.scan.defenses),
                "auxiliary_injection_task_runs": 0 if is_dos else count * len(cfg.scan.defenses),
            })
        cases = sum(item["cases"] for item in attack_cases)
        plan.append({
            "suite": suite,
            "user_task_ids": users,
            "injection_task_ids": injections,
            "user_tasks": user_count,
            "injection_tasks": injection_count,
            "cases": cases,
            "attack_cases": attack_cases,
            "auxiliary_injection_task_runs": sum(item["auxiliary_injection_task_runs"] for item in attack_cases),
        })
    return plan


def render_scan_plan(cfg: ScanConfig, plan: list[dict]) -> str:
    lines = [f"Scan plan for {cfg.agent.resolved_name()}"]
    for item in plan:
        lines.append(
            f"- {item['suite']}: {item['cases']} cases "
            f"({item['user_tasks']} user tasks, {len(cfg.scan.attacks)} attacks, "
            f"{len(cfg.scan.defenses)} defenses; per-attack injection counts below)"
        )
        users = item["user_task_ids"] or ["all"]
        injections = item["injection_task_ids"] or ["all"]
        lines.append(f"  user tasks: {', '.join(users)}")
        lines.append(f"  injection tasks: {', '.join(injections)}")
        for attack in item["attack_cases"]:
            suffix = " (DoS single-injection convention)" if attack["is_dos_attack"] else ""
            lines.append(f"  {attack['attack']}: {attack['cases']} cases, {attack['injection_tasks']} injection tasks{suffix}")
        lines.append(f"  additional injection-task utility runs: {item['auxiliary_injection_task_runs']}")
    lines.append(f"Total benchmark cases: {sum(item['cases'] for item in plan)}")
    lines.append("No model was called. Actual LLM requests vary with the agent's tool loop.")
    return "\n".join(lines)


def build_scan_scope(cfg: ScanConfig, plan: list[dict]) -> dict:
    """Freeze actual task IDs and ordered matrix selections, not model credentials."""
    from importlib.metadata import version

    from agentdojo.task_suite.load_suites import get_suite

    suites = []
    for item in plan:
        suite = get_suite("v1", item["suite"])
        suites.append({
            "suite": item["suite"],
            "user_task_ids": item["user_task_ids"] if item["user_task_ids"] is not None else list(suite.user_tasks),
            "attacks": [{"attack": attack["attack"], "is_dos_attack": attack["is_dos_attack"],
                "injection_task_ids": attack["injection_task_ids"] if attack["injection_task_ids"] is not None else list(suite.injection_tasks)}
                for attack in item["attack_cases"]],
        })
    return {"scope_version": 1, "benchmark_version": "v1",
            "agentdojo_distribution_version": version("agentdojo"),
            "measurement_protocol": "complete-binary-observations-v1",
            "agent_name": cfg.agent.resolved_name(),
            "defenses": list(cfg.scan.defenses), "suites": suites}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dspy-security-bench scan",
        description="Scan a tool-using agent for prompt-injection robustness and gate CI on the result.",
    )
    p.add_argument("--config", help="path to a .dspy-security-bench.yaml config")
    g = p.add_argument_group("agent (overrides config)")
    g.add_argument("--agent-model", help="litellm model → built-in function-calling agent")
    g.add_argument("--agent", help="'module:callable' returning an Agent")
    s = p.add_argument_group("scope")
    s.add_argument("--suites", nargs="+")
    s.add_argument("--attacks", nargs="+")
    s.add_argument("--defenses", nargs="+")
    s.add_argument("--user-tasks", type=lambda v: v if v == "all" else int(v), dest="user_tasks")
    s.add_argument(
        "--injection-tasks", type=lambda v: v if v == "all" else int(v),
        dest="injection_tasks",
    )
    s.add_argument("--plan", action="store_true", help="show the exact run matrix without LM calls")
    gate = p.add_argument_group("gate")
    gate.add_argument("--min-security", type=float)
    gate.add_argument("--baseline", help="baseline json → regression mode")
    gate.add_argument("--max-regression", type=float)
    gate.add_argument("--write-baseline", help="run, then write per-cell security to this path and exit 0")
    gate.add_argument("--fail-on", choices=["error", "warning", "never"])
    r = p.add_argument_group("report")
    r.add_argument("--format", nargs="+", choices=["terminal", "json", "sarif"])
    r.add_argument("--sarif", help="write SARIF to this path")
    r.add_argument("--json", help="write JSON to this path")
    r.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)

    try:
        cfg = ScanConfig.load(args.config) if args.config else ScanConfig()
        cfg = _apply_overrides(cfg, args)
        cfg.validate()
        if cfg.gate.mode == "regression" and not args.write_baseline:
            from dspy_security_bench.scan.gate import load_baseline_document

            baseline_document = load_baseline_document(cfg.gate.baseline)
    except (OSError, TypeError, ValueError) as e:
        print(f"[scan] config error: {e}", file=sys.stderr)
        return 2

    try:
        plan = build_scan_plan(cfg)
        scan_scope = build_scan_scope(cfg, plan)
        scope_verified = None
        if cfg.gate.mode == "regression" and not args.write_baseline:
            from dspy_security_bench.scan.gate import verify_baseline_scope

            scope_verified = verify_baseline_scope(baseline_document, scan_scope)
            if not scope_verified:
                print("[scan] warning: legacy baseline has no verified task scope; regenerate it for scope-bound comparisons", file=sys.stderr)
    except Exception as e:
        print(f"[scan] could not plan run: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if args.plan:
        print(render_scan_plan(cfg, plan))
        return 0

    from dspy_security_bench.runner import evaluate_agents, summarize

    try:
        agent = _resolve_agent(cfg.agent)
    except Exception as e:
        print(f"[scan] could not build agent: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    agent_name = cfg.agent.resolved_name()
    all_summaries = []
    try:
        for item in plan:
            suite = item["suite"]
            df = evaluate_agents(
                agents={agent_name: agent},
                suite_name=suite,
                attacks=cfg.scan.attacks,
                defenses=cfg.scan.defenses,
                user_task_ids=item["user_task_ids"],
                injection_task_ids=item["injection_task_ids"],
            )
            summary = summarize(df)
            summary["_suite"] = suite
            all_summaries.append((suite, summary))
    except Exception as e:
        print(f"[scan] benchmark run failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # Write-baseline mode: persist and exit 0.
    if args.write_baseline:
        import json
        from pathlib import Path

        from dspy_security_bench.scan.gate import baseline_cells, bind_baseline_scope

        # Write one combined baseline keyed by suite.
        cells = {}
        try:
            for suite, summary in all_summaries:
                additions = baseline_cells(summary, suite)
                if cells.keys() & additions.keys():
                    raise ValueError("duplicate baseline cells across suites")
                cells.update(additions)
            if not cells:
                raise ValueError("cannot create a baseline without measured cells")
            Path(args.write_baseline).write_text(json.dumps(bind_baseline_scope(cells, scan_scope), indent=2, allow_nan=False))
        except (OSError, ValueError) as e:
            print(f"[scan] baseline creation failed: {e}", file=sys.stderr)
            return 2
        print(f"[scan] wrote baseline ({len(cells)} cells) → {args.write_baseline}")
        return 0

    # Gate each suite; combine findings.
    from dspy_security_bench.scan.gate import ScanReport
    combined_findings = []
    worst_exit = 0
    missing_baseline = 0
    try:
        if not all_summaries:
            raise ValueError("scan produced no suite summaries")
        for suite, summary in all_summaries:
            rep = evaluate_gate(summary, cfg.gate, suite=suite, fail_on=cfg.fail_on, scan_scope=scan_scope)
            combined_findings.extend(rep.findings)
            worst_exit = max(worst_exit, rep.exit_code)
            missing_baseline += rep.meta["baseline_cells_missing"]
    except (OSError, ValueError) as e:
        print(f"[scan] gate evaluation failed: {e}", file=sys.stderr)
        return 2
    passed = worst_exit == 0
    report = ScanReport(
        findings=combined_findings, passed=passed, exit_code=worst_exit,
        mode=cfg.gate.mode, meta={"suites": cfg.scan.suites, "fail_on": cfg.fail_on,
            "baseline_cells_missing": missing_baseline,
            "baseline_scope_verified": scope_verified,
            "baseline_coverage_complete": missing_baseline == 0 if cfg.gate.mode == "regression" else None},
    )

    config_path = args.config or ".dspy-security-bench.yaml"
    emit(report, cfg.report.formats, sarif_out=cfg.report.sarif_out,
         json_out=cfg.report.json_out, config_path=config_path, use_color=not args.no_color)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
