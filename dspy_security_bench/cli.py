"""Umbrella CLI: `dspy-security-bench <subcommand>`.

Subcommands:
  scan        Scan an agent for prompt-injection robustness and gate CI.
  synthesize  Generate a synthetic trainset for a suite.
  validate    Validate/dedupe a synthesized trainset.
"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("Usage: dspy-security-bench <scan|synthesize|validate> [args...]")
        return 0

    sub, rest = argv[0], argv[1:]
    if sub == "scan":
        from dspy_security_bench.scan.cli import main as scan_main
        return scan_main(rest)
    if sub == "synthesize":
        from dspy_security_bench.synthesis.generator import _cli
        sys.argv = ["dspy-security-bench-synthesize", *rest]
        return _cli() or 0
    if sub == "validate":
        from dspy_security_bench.synthesis.validator import _cli
        sys.argv = ["dspy-security-bench-validate", *rest]
        return _cli() or 0

    print(f"unknown subcommand {sub!r}. Use: scan | synthesize | validate", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
