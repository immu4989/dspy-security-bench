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


def test_ci_installs_from_lockfile_without_resolving_during_checks():
    workflow = (WORKFLOWS / "test.yml").read_text()
    assert "uv sync --locked --extra dev" in workflow
    assert "uv run --locked --no-sync pytest" in workflow
    assert "uv run --locked --no-sync ruff" in workflow


def test_submission_ci_recomputes_bundles_from_the_lockfile():
    workflow = (WORKFLOWS / "submissions.yml").read_text()
    assert "scripts/validate_impact_submissions.py" in workflow
    assert "uv sync --locked --extra dev" in workflow
    assert "uv run --locked --no-sync" in workflow
    assert '"submissions/source/**"' in workflow
    assert '"submissions/authority/**"' in workflow
    assert '"dspy_security_bench/mission/**"' in workflow
    assert '"dspy_security_bench/authority/**"' in workflow


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
