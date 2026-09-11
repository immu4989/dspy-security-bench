"""Supply-chain invariants for the repository's own GitHub Actions."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / "action.yml"
USER_FACING_WORKFLOWS = [
    ROOT / "examples" / "injection-scan.yml",
    ROOT / "dspy_security_bench" / "templates" / "github-action.yml",
]
IMMUTABLE_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def test_every_external_action_is_pinned_to_a_full_commit_sha():
    references = []
    action_files = [*sorted(WORKFLOWS.glob("*.yml")), ACTION, *USER_FACING_WORKFLOWS]
    for workflow in action_files:
        for line_number, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match or match.group(1).startswith("./"):
                continue
            references.append((workflow.relative_to(ROOT), line_number, match.group(1)))

    assert references
    unpinned = [
        f"{name}:{line_number} {reference}"
        for name, line_number, reference in references
        if not IMMUTABLE_ACTION.fullmatch(reference)
    ]
    assert not unpinned, "external actions must be SHA-pinned:\n" + "\n".join(unpinned)


def test_uv_bootstrap_version_is_explicit():
    workflow = (WORKFLOWS / "test.yml").read_text()
    assert 'version: "0.12.3"' in workflow


def test_assuranceledger_ci_recomputes_partner_contracts_offline():
    path = WORKFLOWS / "assuranceledger.yml"
    workflow = path.read_text()
    parsed = yaml.safe_load(workflow)
    assert parsed["permissions"] == {"contents": "read"}
    assert "uv sync --locked --extra dev --python 3.12" in workflow
    assert "dspy-security-bench ledger demo" in workflow
    assert "ledger verify-capabilities" in workflow
    assert "ledger verify-capability-lock" in workflow
    assert "ledger verify-conformance" in workflow
    assert "ledger verify-recovery-attestations" in workflow
    assert "ledger verify-time-quorum" in workflow
    assert "ledger verify-trust-root-time" in workflow
    assert "tests/test_assuranceledger_conformance.py" in workflow
    assert "tests/test_assuranceledger_trust_recovery_attestation.py" in workflow
    assert "tests/test_assuranceledger_time_quorum.py" in workflow
    assert "tests/test_assuranceledger_trust_root_time.py" in workflow
    assert "artifacts/assuranceledger" in workflow
    assert "persist-credentials: false" in workflow
    assert "attest-root-view-interoperability:" in workflow
    assert "github.event_name == 'push'" in workflow
    assert "github.repository == 'immu4989/dspy-security-bench'" in workflow
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in workflow
    assert "verify-root-view-interop" in workflow
    assert "root-view-interop-unverified-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    clean_job = workflow.split("  attest-root-view-interoperability:", 1)[1]
    assert "id-token: write" in clean_job
    assert "attestations: write" in clean_job
    assert "OPENAI_API_KEY" not in clean_job
    assert "ANTHROPIC_API_KEY" not in clean_job
    assert clean_job.index("verify-root-view-interop") < clean_job.index("actions/attest@")


def test_assurancegraph_ci_recomputes_privacy_minimized_slsa_import():
    workflow = (WORKFLOWS / "assurancegraph.yml").read_text()
    assert "dspy-security-bench bom import-slsa" in workflow
    assert "dspy-security-bench bom verify-slsa-import" in workflow
    assert "examples/slsa-provenance-v1.json" in workflow
    assert "tests/test_agentbom_slsa.py" in workflow


def test_ci_installs_from_lockfile_without_resolving_during_checks():
    workflow = (WORKFLOWS / "test.yml").read_text()
    assert "uv sync --locked --extra dev" in workflow
    assert "uv run --locked --no-sync pytest" in workflow
    assert "uv run --locked --no-sync ruff" in workflow
    assert "--junitxml=pytest-results.xml" in workflow
    assert "Expose failed test diagnostics" in workflow


def test_submission_ci_recomputes_bundles_from_the_lockfile():
    workflow = (WORKFLOWS / "submissions.yml").read_text()
    assert "scripts/validate_impact_submissions.py" in workflow
    assert "uv sync --locked --extra dev" in workflow
    assert "uv run --locked --no-sync" in workflow
    assert '"submissions/source/**"' in workflow
    assert '"submissions/authority/**"' in workflow
    assert '"submissions/trace/**"' in workflow
    assert '"dspy_security_bench/mission/**"' in workflow
    assert '"dspy_security_bench/authority/**"' in workflow
    assert '"dspy_security_bench/trace/**"' in workflow


def test_release_attests_built_distributions_before_publish():
    workflow = (WORKFLOWS / "release.yml").read_text()
    assert "attestations: write" in workflow
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in workflow
    assert "subject-path: |" in workflow
    assert "dist/*" in workflow
    assert "sbom/*" in workflow
    assert "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610" in workflow
    assert "github-release:" in workflow
    assert 'gh release create "$GITHUB_REF_NAME"' in workflow
    assert '--notes-file "docs/releases/$GITHUB_REF_NAME.md"' in workflow


def test_proofrun_action_preserves_evidence_before_enforcing_the_gate():
    action = ACTION.read_text()
    assert 'name: "DSPy Security Bench ProofRun"' in action
    assert "continue-on-error: true" in action
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in action
    assert "steps.run.outcome != 'success'" in action
    assert "dspy-security-bench proofrun run" in action
    assert "dspy-security-bench proofrun control" in action
    assert "dspy-security-bench proofrun source" in action
    assert "dspy-security-bench proofrun authority" in action
    assert "evidence-kind:" in action
    assert "mission-pack:" in action
    assert "min-containment-lower-bound" in action
    assert "proofrun-control.svg" in action


def test_reusable_proofrun_uses_an_immutable_central_builder():
    workflow = (WORKFLOWS / "proofrun.yml").read_text()
    version = (ROOT / "pyproject.toml").read_text().split('version = "', 1)[1].split('"', 1)[0]
    assert "workflow_call:" in workflow
    assert f"ref: v{version}" in workflow
    assert 'PROOFRUN_BUILDER_KIND: "dspy_security_bench_reusable_workflow"' in workflow
    assert "attestations: write" in workflow
    assert "--min-lower-bound" in workflow
    assert 'default: "impact"' in workflow
    assert "proofrun control" in workflow
    assert "proofrun incident" in workflow
    assert "proofrun source" in workflow
    assert "proofrun authority" in workflow
    assert "mission-pack:" in workflow
    assert "--min-containment-lower-bound" in workflow
    assert "policy-source" in workflow
    assert "continue-on-error: true" in workflow
    assert "proofrun-unverified-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "Recompute every statistic and content digest" in workflow
    assert "permissions: {}" in workflow
    assert workflow.index("secrets:") < workflow.index("  evaluate:")
    assert workflow.index("  evaluate:") < workflow.index("  verify-and-attest:")
    clean_job = workflow.split("  verify-and-attest:", 1)[1].split("  enforce-gate:", 1)[0]
    assert "OPENAI_API_KEY" not in clean_job
    assert "ANTHROPIC_API_KEY" not in clean_job
    assert "proofrun verify" in clean_job
    assert "impact control-card" in clean_job
    assert clean_job.index("proofrun verify") < clean_job.index("impact control-card")
    assert "PYTHONPATH: ${{ github.workspace }}/target" in workflow


def test_proofrun_action_has_a_live_smoke_workflow():
    workflow = (WORKFLOWS / "proofrun-smoke.yml").read_text()
    assert "uses: ./" in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "build_bounded_reference" in workflow
    assert "build_vulnerable_reference" in workflow
    assert "evidence-kind: control" in workflow
    assert "dspy_security_bench.incident.agents:build_bounded_reference" in workflow
    assert "evidence-kind: incident" in workflow
    assert "build_bounded_source_reference" in workflow
    assert "evidence-kind: source" in workflow
    assert "build_bounded_authority_adapter" in workflow
    assert "evidence-kind: authority" in workflow
    assert "control-proofrun-smoke.svg" in workflow
    assert "attestations: write" in workflow


def test_native_framework_bridges_have_a_zero_provider_call_compatibility_matrix():
    workflow = (WORKFLOWS / "framework-adapters.yml").read_text()
    for framework in (
        "openai-agents",
        "langchain",
        "pydantic-ai",
        "crewai",
        "autogen",
    ):
        assert f"framework: {framework}" in workflow
    assert "schedule:" in workflow
    assert "tests/test_framework_compat.py" in workflow
    assert "OPENAI_API_KEY" not in workflow
    assert "ANTHROPIC_API_KEY" not in workflow


def test_framework_issue_form_is_valid_and_requires_redaction_confirmation():
    form = yaml.safe_load((ROOT / ".github/ISSUE_TEMPLATE/framework-integration.yml").read_text())
    assert form["name"] == "Framework integration"
    options = next(item for item in form["body"] if item.get("id") == "contribution")["attributes"][
        "options"
    ]
    assert any(option.get("required") for option in options)


def test_traceproof_issue_form_forbids_raw_telemetry_and_requires_non_claims():
    form = yaml.safe_load((ROOT / ".github/ISSUE_TEMPLATE/trace-runtime-evidence.yml").read_text())
    assert form["name"] == "TraceProof runtime evidence"
    introduction = form["body"][0]["attributes"]["value"]
    assert "Never paste or attach raw OTLP" in introduction
    safety = next(item for item in form["body"] if item.get("id") == "safety")
    assert sum(option.get("required") is True for option in safety["attributes"]["options"]) == 2


def test_resiliencegraph_issue_form_requires_assumptions_and_non_claims():
    form = yaml.safe_load((ROOT / ".github/ISSUE_TEMPLATE/resilience-portfolio.yml").read_text())
    assert form["name"] == "ResilienceGraph campaign"
    assert any(item.get("id") == "assumptions" for item in form["body"])
    boundary = next(item for item in form["body"] if item.get("id") == "boundary")
    assert sum(option.get("required") is True for option in boundary["attributes"]["options"]) == 3


def test_assurancegraph_workflow_recomputes_and_preserves_review_artifacts():
    workflow = (WORKFLOWS / "assurancegraph.yml").read_text()
    assert "dspy-security-bench assure demo" in workflow
    assert "dspy-security-bench assure verify" in workflow
    assert "dspy-security-bench contain demo" in workflow
    assert "dspy-security-bench bom demo" in workflow
    assert "dspy-security-bench assure federal-pack" in workflow
    assert "dspy-security-bench assure federal-verify" in workflow
    assert "dspy-security-bench assure exchange-verify" in workflow
    assert "tests/test_assurancegraph.py" in workflow
    assert "tests/test_probe_contract.py" in workflow
    assert "assurance-control-plane-reference" in workflow
    assert "path: artifacts" in workflow
    assert "OPENAI_API_KEY" not in workflow
    assert "ANTHROPIC_API_KEY" not in workflow


def test_assurancegraph_issue_form_requires_unfavorable_evidence_and_non_claims():
    form = yaml.safe_load((ROOT / ".github/ISSUE_TEMPLATE/assurance-case.yml").read_text())
    assert form["name"] == "AssuranceGraph case or profile"
    assert any(item.get("id") == "unfavorable" for item in form["body"])
    boundary = next(item for item in form["body"] if item.get("id") == "boundary")
    assert sum(option.get("required") is True for option in boundary["attributes"]["options"]) == 3
