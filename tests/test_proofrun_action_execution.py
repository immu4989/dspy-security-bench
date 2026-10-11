"""Execute the composite action's actual shell, not a copied CLI approximation."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from dspy_security_bench.proofrun_review import ReviewPolicy, review_bundle
from scripts.proofrun_action_paths import prepare_outputs

ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
RUN = next(step for step in ACTION["runs"]["steps"] if step.get("id") == "run")
FACTORIES = {
    "impact": "dspy_security_bench.procurement.agents:build_bounded_reference",
    "control": "dspy_security_bench.procurement.agents:build_vulnerable_reference",
    "incident": "dspy_security_bench.incident.agents:build_bounded_reference",
    "source": "dspy_security_bench.mission.agents:build_bounded_source_reference",
    "authority": "dspy_security_bench.authority.adapter:build_bounded_authority_adapter",
}


def environment(kind, directory):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GITHUB_", "PROOFRUN_"))}
    env.update({"PROOFRUN_" + key.upper().replace("-", "_"): str(value.get("default", ""))
                for key, value in ACTION["inputs"].items()})
    env.update(
        PATH=str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", ""),
        GITHUB_ACTION_PATH=str(ROOT), GITHUB_OUTPUT=str(directory / "action-outputs"),
        PROOFRUN_EVIDENCE_KIND=kind, PROOFRUN_AGENT=FACTORIES[kind],
        PROOFRUN_SUBMITTER="synthetic", PROOFRUN_AGENT_SOURCE="https://example.com/agent",
        PROOFRUN_TRIALS="2", PROOFRUN_OUTPUT="new/artifacts/evidence.json",
        PROOFRUN_CARD_OUTPUT="new/cards/evidence.svg",
        PROOFRUN_POLICY=str(ROOT / "dspy_security_bench/templates/policies/procurement.yaml"),
        PROOFRUN_POLICY_SOURCE="https://example.com/policy",
        PROOFRUN_MIN_CONTAINMENT="0", PROOFRUN_MIN_CONTROLLED_HARM_FREE="0",
        PROOFRUN_MIN_CLEAN_PRESERVATION="0", PROOFRUN_MIN_CONTROLLED_RESISTANCE="0",
    )
    return env


def execute(env, directory):
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", RUN["run"]],
        cwd=directory, env=env, capture_output=True, text=True, timeout=30,
    )


@pytest.mark.parametrize("kind", FACTORIES)
@pytest.mark.parametrize("gate_failure", [False, True])
def test_actual_action_shell_creates_nested_outputs_and_preserves_failed_gates(kind, gate_failure, tmp_path):
    env = environment(kind, tmp_path)
    if gate_failure:
        env["PROOFRUN_MIN_LOWER_BOUND"] = "1"
        env["PROOFRUN_MIN_CONTROLLED_HARM_FREE"] = "1"
    result = execute(env, tmp_path)
    assert result.returncode == int(gate_failure), result.stderr
    assert (tmp_path / "action-outputs").read_text() == "evidence-ready=true\n"
    bundle = tmp_path / env["PROOFRUN_OUTPUT"]
    review = review_bundle(bundle, policy=ReviewPolicy(offline=True))
    assert review["integrity"] == "valid"
    assert review["eligibility"] == "ineligible"  # Synthetic reference, not a model result.
    assert (tmp_path / env["PROOFRUN_CARD_OUTPUT"]).exists() == (kind == "control")


@pytest.mark.parametrize("kind,failure", [
    (kind, failure) for kind in FACTORIES for failure in ("retained", "invalid_metadata", "runtime")
] + [("control", "partial_card")])
def test_errors_never_mark_stale_or_partial_evidence_ready(kind, failure, tmp_path):
    env = environment(kind, tmp_path)
    bundle = tmp_path / env["PROOFRUN_OUTPUT"]
    if failure == "retained":
        bundle.parent.mkdir(parents=True)
        bundle.write_text("PRIVATE retained evidence")
    elif failure == "invalid_metadata":
        env["PROOFRUN_AGENT_SOURCE"] = "https://user:PRIVATE@example.com/agent"
    elif failure == "runtime":
        env["PROOFRUN_AGENT"] = "not_installed:factory"
    else:
        # A directory where a card file is requested must block the entire run.
        (tmp_path / env["PROOFRUN_CARD_OUTPUT"]).mkdir(parents=True)
    result = execute(env, tmp_path)
    assert result.returncode == 2
    assert not (tmp_path / "action-outputs").exists()
    if failure == "retained":
        assert bundle.read_text() == "PRIVATE retained evidence"
    else:
        assert not bundle.exists()
    assert "PRIVATE" not in result.stdout + result.stderr


@pytest.mark.parametrize("layout", ["same", "nested", "traversal", "absolute", "glob", "newline", "empty", "symlink", "dangling", "non_directory"])
def test_complete_layout_is_validated_before_creating_any_parent(layout, tmp_path):
    workspace = tmp_path.resolve()
    env = environment("control", workspace)
    if layout == "same":
        env["PROOFRUN_CARD_OUTPUT"] = "new/artifacts/./evidence.json"
    elif layout == "nested":
        env["PROOFRUN_CARD_OUTPUT"] = "new/artifacts/evidence.json/card.svg"
    elif layout == "traversal":
        env["PROOFRUN_CARD_OUTPUT"] = "../PRIVATE/card.svg"
    elif layout == "absolute":
        env["PROOFRUN_CARD_OUTPUT"] = str(workspace / "outside.svg")
    elif layout == "glob":
        env["PROOFRUN_CARD_OUTPUT"] = "PRIVATE/*.svg"
    elif layout == "newline":
        env["PROOFRUN_CARD_OUTPUT"] = "PRIVATE\ncard.svg"
    elif layout == "empty":
        env["PROOFRUN_CARD_OUTPUT"] = ""
    elif layout in ("symlink", "dangling"):
        (workspace / "linked").symlink_to(workspace if layout == "symlink" else workspace / "missing", target_is_directory=True)
        env["PROOFRUN_CARD_OUTPUT"] = "linked/card.svg"
    else:
        (workspace / "blocked").write_text("PRIVATE")
        env["PROOFRUN_CARD_OUTPUT"] = "blocked/card.svg"
    with pytest.raises(ValueError):
        prepare_outputs(env, workspace)
    assert not (workspace / "new").exists()


def test_publication_requires_current_execution_readiness_and_cards_are_control_only():
    steps = ACTION["runs"]["steps"]
    inspect = next(step for step in steps if step.get("id") == "bundle")
    assert inspect["if"] == "always() && steps.run.outputs.evidence-ready == 'true'"
    for step in steps:
        if step.get("id") in ("metadata", "attest") or step.get("uses", "").startswith("actions/upload-artifact@"):
            assert "steps.bundle.outputs.exists == 'true'" in step["if"]
    upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert "inputs.evidence-kind == 'control' && inputs.card-output" in upload["with"]["path"]
