"""CLI for validating, scaffolding, and testing tool-call policies offline."""
from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path

from dspy_security_bench.policy import ToolPolicy

PROFILES = {
    "customer-support": "Customer support: safe lookups, bounded refunds, approved outbound email",
    "financial-operations": "Finance: allowlisted destinations and approval for money movement",
    "procurement": "Procurement: protect source selection, vendor identity, and award authority",
    "research-rag": "Research/RAG: read broadly, protect memory and external side effects",
    "devops": "DevOps: inspect freely, approve changes, deny destructive execution",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dspy-security-bench policy",
        description="Enforce deterministic least-agency controls at the tool-call boundary.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("profiles", help="list built-in real-world policy profiles")

    init = sub.add_parser("init", help="write a policy profile you can customize")
    init.add_argument("--profile", required=True, choices=sorted(PROFILES))
    init.add_argument("--out", default=".dspy-security-policy.yaml", help="destination YAML path")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")

    validate = sub.add_parser("validate", help="validate a policy document")
    validate.add_argument("--policy", required=True)

    check = sub.add_parser("check", help="evaluate one proposed tool call without executing it")
    check.add_argument("--policy", required=True)
    check.add_argument("--tool", required=True)
    check.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    check.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "profiles":
        print("Built-in policy profiles:\n")
        for name, description in PROFILES.items():
            print(f"  {name:<22} {description}")
        return 0
    if args.command == "init":
        return _init_policy(args.profile, Path(args.out), force=args.force)
    if args.command == "validate":
        try:
            policy = ToolPolicy.load(args.policy)
        except ValueError as exc:
            print(f"[policy] invalid: {exc}", file=sys.stderr)
            return 2
        print(f"[policy] valid: {policy.name} ({len(policy.rules)} rules, default={policy.default})")
        return 0
    if args.command == "check":
        return _check_policy(args)
    return 2


def _init_policy(profile: str, out: Path, *, force: bool) -> int:
    if out.exists() and not force:
        print(f"[policy] kept existing {out} (use --force to replace)", file=sys.stderr)
        return 2
    template = files("dspy_security_bench.templates").joinpath("policies", f"{profile}.yaml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(template.read_text())
    print(f"[policy] created {out} from profile {profile}")
    print(f"Next: dspy-security-bench policy validate --policy {out}")
    return 0


def _check_policy(args) -> int:
    try:
        policy = ToolPolicy.load(args.policy)
        arguments = json.loads(args.args)
        if not isinstance(arguments, dict):
            raise ValueError("--args must decode to a JSON object")
        decision = policy.evaluate(args.tool, arguments)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"[policy] could not evaluate: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        labels = {"allow": "ALLOW", "deny": "DENY", "require_approval": "APPROVAL REQUIRED"}
        print(f"[{labels[decision.action]}] {decision.tool}")
        print(f"  rule:   {decision.rule_id}")
        print(f"  reason: {decision.reason}")
    if decision.action == "allow":
        return 0
    if decision.action == "require_approval":
        return 3
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
