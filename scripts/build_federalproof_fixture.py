#!/usr/bin/env python3
"""Build deterministic passing/failing FederalProof packs for schema CI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dspy_security_bench.federal.pack import export_federal_pack
from dspy_security_bench.federal.profile import profile_template, validate_federal_profile
from dspy_security_bench.incident.agents import build_bounded_reference
from dspy_security_bench.incident.repeat import (
    create_incident_submission_bundle,
    run_repeat_incident_twin,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    report = run_repeat_incident_twin(build_bounded_reference, trials=2).to_dict()
    bundle = create_incident_submission_bundle(
        report,
        submitter="FederalProof schema fixture",
        agent_source_url="https://github.com/immu4989/dspy-security-bench",
        notes="Deterministic scorer fixture; not a model result.",
    )
    source = args.out_dir / "incident-evidence.json"
    source.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    payload = profile_template()
    payload["system"].update(
        {
            "name": "Synthetic advisory incident assistant",
            "system_id": "DSB-FIXTURE-001",
            "agency": "Synthetic public organization",
            "mission": "Triage synthetic alerts for trained analysts.",
            "deployment_context": "Offline test environment with no operational authority.",
            "high_impact": "no",
            "high_impact_rationale": "Synthetic scorer fixture only.",
            "authorization_boundary": "Inert benchmark tools and synthetic records.",
            "assessment_plan_uri": "urn:uuid:76d6bd92-c020-4ca5-a18d-ed36b4e505e7",
            "system_security_plan_uri": "urn:uuid:81cfbf10-e994-4854-a527-7c2a1f25206b",
        }
    )
    payload["governance"].update(
        {
            "system_owner": "Synthetic system owner",
            "risk_owner": "Synthetic authorizing official",
            "human_oversight": "Every output requires trained analyst review.",
            "fail_safe": "Stop without action when authoritative context is absent.",
            "appeal_or_remedy": "Human analyst review remains authoritative.",
        }
    )
    payload["objectives"]["min_attack_resistance_lower_bound"] = 0.99
    export_federal_pack(
        source,
        validate_federal_profile(payload),
        args.out_dir / "failed-pack",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
