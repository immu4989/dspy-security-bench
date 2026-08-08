"""Umbrella CLI: `dspy-security-bench <subcommand>`.

Subcommands:
  init        Create a scan config and GitHub Action in the current project.
  policy      Create and test deterministic tool-call policies.
  scan        Scan an agent for prompt-injection robustness and gate CI.
  synthesize  Generate a synthetic trainset for a suite.
  validate    Validate/dedupe a synthesized trainset.
"""
from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version


def _version() -> str:
    try:
        return version("dspy-security-bench")
    except PackageNotFoundError:
        return "unknown"


def _init(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench init",
        description="Create a ready-to-run scan config and GitHub Actions workflow.",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--model", default="openai/gpt-4o-mini", help="LiteLLM model id")
    target.add_argument("--agent", help="module:callable returning your agent")
    parser.add_argument("--no-workflow", action="store_true", help="only create the config")
    parser.add_argument("--force", action="store_true", help="overwrite existing generated files")
    args = parser.parse_args(argv)

    from dspy_security_bench.scaffold import initialize_project

    result = initialize_project(
        model=args.model,
        agent_import=args.agent,
        include_workflow=not args.no_workflow,
        force=args.force,
    )
    for path in result.created:
        print(f"[init] created {path}")
    for path in result.skipped:
        print(f"[init] kept existing {path} (use --force to replace)")
    if result.created:
        print("\nNext: dspy-security-bench scan --config .dspy-security-bench.yaml --plan")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-V", "--version"):
        print(f"dspy-security-bench {_version()}")
        return 0
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("Usage: dspy-security-bench <init|scan|policy|synthesize|validate> [args...]")
        return 0

    sub, rest = argv[0], argv[1:]
    if sub == "init":
        return _init(rest)
    if sub == "scan":
        from dspy_security_bench.scan.cli import main as scan_main
        return scan_main(rest)
    if sub == "policy":
        from dspy_security_bench.policy_cli import main as policy_main
        return policy_main(rest)
    if sub == "synthesize":
        from dspy_security_bench.synthesis.generator import _cli
        sys.argv = ["dspy-security-bench-synthesize", *rest]
        return _cli() or 0
    if sub == "validate":
        from dspy_security_bench.synthesis.validator import _cli
        sys.argv = ["dspy-security-bench-validate", *rest]
        return _cli() or 0

    print(
        f"unknown subcommand {sub!r}. Use: init | scan | policy | synthesize | validate",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
