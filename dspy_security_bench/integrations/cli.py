"""CLI entry points for framework integration and preflight diagnostics."""

from __future__ import annotations

import argparse
import json
import sys

from dspy_security_bench.integrations.catalog import FRAMEWORKS, detect_frameworks, get_framework
from dspy_security_bench.integrations.doctor import render_doctor, run_doctor
from dspy_security_bench.integrations.scaffold import integrate_project, plan_integration
from dspy_security_bench.integrations.scaffold_io import ScaffoldWriteError


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
    parser.add_argument("--force", action="store_true", help="explicitly replace differing selected files; inspect --dry-run first")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="list supported frameworks")
    mode.add_argument("--detect", action="store_true", help="inspect dependency declarations without generating files")
    mode.add_argument("--dry-run", action="store_true", help="preview every scaffold file and conflict without writing")
    parser.add_argument("--json", action="store_true", help="machine-readable inventory or preview (requires --detect or --dry-run)")
    args = parser.parse_args(argv)

    if args.json and not (args.detect or args.dry_run):
        parser.error("--json requires --detect or --dry-run")
    if args.list:
        for spec in FRAMEWORKS:
            print(f"{spec.key:16} {spec.label:30} {spec.package_hint}")
        return 0

    try:
        if args.detect:
            detected = detect_frameworks(args.root)
            inventory = {"schema_version": 1, "mode": "declarations_only", "detected_frameworks": [
                {"framework": spec.key, "label": spec.label, "declarations": list(paths)}
                for spec, paths in detected
            ]}
            if args.json:
                print(json.dumps(inventory, indent=2))
            else:
                print("Declared frameworks (includes optional/dev declarations; installation and use not checked):")
                for spec, paths in detected:
                    print(f"  {spec.key}: {', '.join(repr(path) for path in paths)}")
                if not detected:
                    print("  none detected")
            return 0
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
            if not args.json:
                print(f"[integrate] detected {spec.label}")
        else:
            spec = get_framework(args.framework)
        options = dict(model=args.model, runner=args.runner, module=args.module,
                       include_workflow=not args.no_workflow, include_test=not args.no_test, force=args.force)
        if args.dry_run:
            plan = plan_integration(spec, args.root, **options)
            if args.json:
                print(json.dumps(plan.to_dict(), indent=2))
            else:
                print("Scaffold preview; no files or directories written:")
                for item in plan.files:
                    print(f"  {item.action:10} {item.relative.as_posix()!r}")
                print("Conflicts stop all writes. --force explicitly permits replacements; commit or back up your work first.")
            return 1 if plan.has_conflicts else 0
        result = integrate_project(spec, args.root, **options)
    except ScaffoldWriteError as exc:
        print(f"integrate: {exc}", file=sys.stderr)
        print(f"  completed: {[path.as_posix() for path in exc.completed]!r}; attempted: {exc.attempted.as_posix()!r}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"integrate: {exc}", file=sys.stderr)
        return 2

    if result.conflicts:
        print("integrate: existing content differs; no files written. Review --dry-run, choose another module, or explicitly replace with --force.", file=sys.stderr)
        for path in result.conflicts:
            print(f"  conflict: {str(path)!r}", file=sys.stderr)
        return 1
    for path in result.created:
        print(f"[integrate] created {path}")
    for path in result.replaced:
        print(f"[integrate] replaced {path}")
    for path in result.skipped:
        print(f"[integrate] unchanged {path}")
    print(f"\nNext: dspy-security-bench doctor --root {args.root} --manifest-only")
    print("After reviewing and trusting the target imports and factory, omit --manifest-only to check construction.")
    return 0


def doctor_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench doctor",
        description="Validate an integration without invoking the agent run loop.",
    )
    parser.add_argument("--root", default=".", help="project root")
    parser.add_argument("--agent", help="override module:callable target")
    parser.add_argument("--manifest-only", action="store_true", help="inspect declarations only; no target import, factory calls, import hooks, or credential lookup")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)
    report = run_doctor(args.root, agent_import=args.agent, manifest_only=args.manifest_only)
    print(json.dumps(report.to_dict(), indent=2) if args.json else render_doctor(report))
    return 0 if report.passed else 1
