"""AgentGraphTwin CLI."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dspy-security-bench graph")
    commands = parser.add_subparsers(dest="command")
    describe = commands.add_parser("describe", help="show the frozen multi-agent graph protocol")
    describe.add_argument("--json", action="store_true", dest="as_json")
    demo = commands.add_parser("demo", help="compare bounded and ambient reference adapters")
    demo.add_argument("--json", action="store_true", dest="as_json")
    run = commands.add_parser("run", help="evaluate an authorization adapter")
    run.add_argument("--adapter", help="module:callable returning an AuthorityAdapter")
    run.add_argument("--reference", choices=("bounded", "ambient"), default="bounded")
    run.add_argument("--json-out")
    verify = commands.add_parser("verify", help="verify a graph report offline")
    verify.add_argument("path")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    from dspy_security_bench.graph.benchmark import run_agent_graph_twin, verify_graph_report
    from dspy_security_bench.graph.protocol import (
        DISCLAIMER,
        GRAPH_SCENARIO_VERSION,
        build_graph_scenarios,
        graph_protocol_sha256,
    )

    if args.command == "describe":
        payload = {
            "scenario_version": GRAPH_SCENARIO_VERSION,
            "protocol_sha256": graph_protocol_sha256(),
            "pairs": [
                item.to_dict() for item in build_graph_scenarios() if item.variant == "clean"
            ],
            "disclaimer": DISCLAIMER,
        }
        print(json.dumps(payload, indent=2, sort_keys=True) if args.as_json else _describe(payload))
        return 0
    if args.command == "verify":
        try:
            payload = json.loads(Path(args.path).read_text())
            errors = verify_graph_report(payload)
        except (OSError, json.JSONDecodeError) as exc:
            errors = (str(exc),)
        if errors:
            print("[graph] verification failed: " + "; ".join(errors), file=sys.stderr)
            return 1
        print(f"[graph] verified {args.path}")
        return 0
    if args.command == "demo":
        reports = [_run_reference(name) for name in ("bounded", "ambient")]
        if args.as_json:
            print(json.dumps(reports, indent=2, sort_keys=True))
        else:
            for report in reports:
                summary = report["summary"]
                print(
                    f"{report['adapter']}: {summary['attack_resistance']:.0%} resistance, "
                    f"{summary['clean_mission_utility']:.0%} clean utility, "
                    f"{summary['total_unsafe_effects']} unsafe effects"
                )
        return 0
    try:
        if args.adapter:
            factory = _load_factory(args.adapter)
        else:
            factory = _reference_factory(args.reference)
        report = run_agent_graph_twin(factory(), adapter_factory=factory)
        errors = verify_graph_report(report)
        if errors:
            raise ValueError("generated report failed verification: " + "; ".join(errors))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        else:
            print(json.dumps(report["summary"], indent=2, sort_keys=True))
        return 0
    except (AttributeError, ImportError, TypeError, ValueError, OSError) as exc:
        print(f"[graph] run failed: {exc}", file=sys.stderr)
        return 2


def _run_reference(name: str) -> dict:
    from dspy_security_bench.graph.benchmark import run_agent_graph_twin

    factory = _reference_factory(name)
    return run_agent_graph_twin(factory(), adapter_factory=factory)


def _reference_factory(name: str):
    from dspy_security_bench.authority.adapter import (
        build_ambient_authority_adapter,
        build_bounded_authority_adapter,
    )

    return build_bounded_authority_adapter if name == "bounded" else build_ambient_authority_adapter


def _load_factory(value: str):
    if ":" not in value:
        raise ValueError("adapter must use module:callable")
    module, attribute = value.split(":", 1)
    factory = getattr(importlib.import_module(module), attribute)
    if not callable(factory):
        raise TypeError("adapter target must be callable")
    return factory


def _describe(payload: dict) -> str:
    lines = [
        f"AgentGraphTwin {payload['scenario_version']}",
        f"Protocol: {payload['protocol_sha256']}",
    ]
    lines.extend(f"  - {item['pair_id']}: {item['title']}" for item in payload["pairs"])
    lines.append(payload["disclaimer"])
    return "\n".join(lines)
