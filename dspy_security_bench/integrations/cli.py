"""CLI entry points for framework integration and preflight diagnostics."""

from __future__ import annotations

import argparse
import json
import sys

from dspy_security_bench.integrations.catalog import FRAMEWORKS, detect_frameworks, get_framework
from dspy_security_bench.integrations.doctor import render_doctor, run_doctor
from dspy_security_bench.integrations.scaffold import integrate_project


def integrate_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench integrate",
        description="Detect an agent framework and generate a tested ProofRun target.",
    )
    parser.add_argument("--framework", default="auto", help="framework key or auto")
    parser.add_argument("--model", help="framework model identifier")
    parser.add_argument("--runner", help="module:callable for MCP/custom loops")
    parser.add_argument("--module", default="dspy_security_target", help="generated target module")
    parser.add_argument("--root", default=".", help="project root")
    parser.add_argument("--no-workflow", action="store_true")
    parser.add_argument("--no-test", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--list", action="store_true", help="list supported frameworks")
    args = parser.parse_args(argv)

    if args.list:
        for spec in FRAMEWORKS:
            print(f"{spec.key:16} {spec.label:30} {spec.package_hint}")
        return 0

    try:
        if args.framework == "auto":
            detected = detect_frameworks(args.root)
            if not detected:
                raise ValueError(
                    "no supported framework found in direct dependencies; pass --framework"
                )
            if len(detected) > 1:
                choices = ", ".join(spec.key for spec, _ in detected)
                raise ValueError(
                    f"multiple frameworks detected ({choices}); choose one with --framework"
                )
            spec = detected[0][0]
            print(f"[integrate] detected {spec.label}")
        else:
            spec = get_framework(args.framework)
        result = integrate_project(
            spec,
            args.root,
            model=args.model,
            runner=args.runner,
            module=args.module,
            include_workflow=not args.no_workflow,
            include_test=not args.no_test,
            force=args.force,
        )
    except (OSError, ValueError) as exc:
        print(f"integrate: {exc}", file=sys.stderr)
        return 2

    for path in result.created:
        print(f"[integrate] created {path}")
    for path in result.skipped:
        print(f"[integrate] kept existing {path} (use --force to replace)")
    print(f"\nNext: dspy-security-bench doctor --root {args.root}")
    return 0


def doctor_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench doctor",
        description="Validate an integration without invoking the agent run loop.",
    )
    parser.add_argument("--root", default=".", help="project root")
    parser.add_argument("--agent", help="override module:callable target")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)
    report = run_doctor(args.root, agent_import=args.agent)
    print(json.dumps(report.to_dict(), indent=2) if args.json else render_doctor(report))
    return 0 if report.passed else 1
