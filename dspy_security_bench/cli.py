"""Umbrella CLI: `dspy-security-bench <subcommand>`.

Subcommands:
  assure      Compile verified evidence into an executable agent assurance case.
  contain     Analyze harmless canary containment and response evidence.
  bom         Map agent dependencies to assurance reevaluation requirements.
  probe       Validate data-only assurance probe contributions without loading code.
  doctor      Validate a BYOA integration without invoking the agent run loop.
  federal     Export standards-aligned FederalProof assessment evidence.
  inventory   Turn public AI inventories into synthetic MissionPack drafts.
  graph       Trace authorization failures across multi-agent execution paths.
  collective  Analyze structural containment evidence for autonomous agent collectives.
  defend      Verify AI-assisted cyber-defense remediation without live target actions.
  portfolio   Plan exact, evidence-backed defense portfolios across shared services.
  causal      Convert structural runtime causality into proof-ready schedules.
  schedule    Exhaustively explore bounded agent authorization interleavings.
  watch       Detect assurance regressions from verified evidence baselines.
  acquisition Export vendor-neutral, owner-governed evaluation packages.
  trace       Turn local agent telemetry into privacy-bounded assurance evidence.
  value       Recompute owner-supplied mission economics without ranking.
  authority   Test agent identity and delegated-authorization enforcement.
  impact      Run counterfactual procurement mission-assurance tests.
  incident    Run synthetic cyber-response mission-assurance tests.
  pack        Author and run declarative MissionForge assurance packs.
  init        Create a scan config and GitHub Action in the current project.
  integrate   Detect an agent framework and scaffold a ProofRun target.
  policy      Create and test deterministic tool-call policies.
  proofrun    Produce or verify provenance-aware Impact or Control evidence.
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
        print(
            "Usage: dspy-security-bench "
            "<init|integrate|doctor|assure|contain|bom|probe|scan|impact|incident|pack|authority|inventory|graph|collective|defend|portfolio|causal|schedule|watch|acquisition|trace|value|policy|proofrun|federal|synthesize|validate> [args...]"
        )
        return 0

    sub, rest = argv[0], argv[1:]
    if sub == "init":
        return _init(rest)
    if sub == "integrate":
        from dspy_security_bench.integrations.cli import integrate_main

        return integrate_main(rest)
    if sub == "doctor":
        from dspy_security_bench.integrations.cli import doctor_main

        return doctor_main(rest)
    if sub == "assure":
        from dspy_security_bench.assurance.cli import main as assure_main

        return assure_main(rest)
    if sub == "contain":
        from dspy_security_bench.containment.cli import main as contain_main

        return contain_main(rest)
    if sub == "bom":
        from dspy_security_bench.supplychain.cli import main as bom_main

        return bom_main(rest)
    if sub == "probe":
        from dspy_security_bench.probes.cli import main as probe_main

        return probe_main(rest)
    if sub == "scan":
        from dspy_security_bench.scan.cli import main as scan_main

        return scan_main(rest)
    if sub == "impact":
        from dspy_security_bench.procurement.cli import main as impact_main

        return impact_main(rest)
    if sub == "incident":
        from dspy_security_bench.incident.cli import main as incident_main

        return incident_main(rest)
    if sub == "pack":
        from dspy_security_bench.mission.cli import main as pack_main

        return pack_main(rest)
    if sub == "authority":
        from dspy_security_bench.authority.cli import main as authority_main

        return authority_main(rest)
    if sub == "inventory":
        from dspy_security_bench.inventory.cli import main as inventory_main

        return inventory_main(rest)
    if sub == "graph":
        from dspy_security_bench.graph.cli import main as graph_main

        return graph_main(rest)
    if sub == "collective":
        from dspy_security_bench.collective.cli import main as collective_main

        return collective_main(rest)
    if sub == "defend":
        from dspy_security_bench.defend.cli import main as defend_main

        return defend_main(rest)
    if sub == "portfolio":
        from dspy_security_bench.portfolio.cli import main as portfolio_main

        return portfolio_main(rest)
    if sub == "causal":
        from dspy_security_bench.causal.cli import main as causal_main

        return causal_main(rest)
    if sub == "schedule":
        from dspy_security_bench.schedule.cli import main as schedule_main

        return schedule_main(rest)
    if sub == "watch":
        from dspy_security_bench.continuous.cli import main as watch_main

        return watch_main(rest)
    if sub == "acquisition":
        from dspy_security_bench.acquisition.cli import main as acquisition_main

        return acquisition_main(rest)
    if sub == "trace":
        from dspy_security_bench.trace.cli import main as trace_main

        return trace_main(rest)
    if sub == "value":
        from dspy_security_bench.value.cli import main as value_main

        return value_main(rest)
    if sub == "policy":
        from dspy_security_bench.policy_cli import main as policy_main

        return policy_main(rest)
    if sub == "proofrun":
        from dspy_security_bench.proofrun_cli import main as proofrun_main

        return proofrun_main(rest)
    if sub == "federal":
        from dspy_security_bench.federal.cli import main as federal_main

        return federal_main(rest)
    if sub == "synthesize":
        from dspy_security_bench.synthesis.generator import _cli

        sys.argv = ["dspy-security-bench-synthesize", *rest]
        return _cli() or 0
    if sub == "validate":
        from dspy_security_bench.synthesis.validator import _cli

        sys.argv = ["dspy-security-bench-validate", *rest]
        return _cli() or 0

    print(
        f"unknown subcommand {sub!r}. Use: "
        "init | integrate | doctor | assure | contain | bom | probe | scan | impact | incident | pack | authority | inventory | graph | collective | defend | portfolio | causal | schedule | watch | acquisition | trace | value | policy | proofrun | federal | synthesize | validate",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
