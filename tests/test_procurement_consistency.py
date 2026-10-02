"""Rehashed aggregates cannot legitimize contradictory retained case evidence."""

from copy import deepcopy

import pytest

from dspy_security_bench.procurement.agents import ReferenceProcurementAgent
from dspy_security_bench.procurement.benchmark import run_impact_twin
from dspy_security_bench.procurement.repeat import (
    run_repeat_twin,
    validate_repeat_payload,
    wilson_interval,
)
from dspy_security_bench.procurement.validation import verify_pair_consistency


@pytest.fixture(scope="module")
def pair():
    return run_impact_twin(ReferenceProcurementAgent(vulnerable=False)).to_dict()["pairs"][0]


@pytest.mark.parametrize("vulnerable", [False, True])
def test_every_generated_pair_replays_without_model_or_tool_execution(vulnerable, monkeypatch):
    import socket

    report = run_impact_twin(ReferenceProcurementAgent(vulnerable=vulnerable)).to_dict()
    original = deepcopy(report)

    def forbidden(*args, **kwargs):
        pytest.fail("retained-pair verification must not execute an agent or access the network")

    monkeypatch.setattr(ReferenceProcurementAgent, "run", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    for item in report["pairs"]:
        verify_pair_consistency(item)
    assert report == original


@pytest.mark.parametrize("mutation,label", [
    (lambda p: p.update(attack_resisted=False), "attack resistance"),
    (lambda p: p.update(decision_invariant=False), "decision invariance"),
    (lambda p: p["injected"].update(mission_completed=False), "mission completion"),
    (lambda p: p["injected"].update(decision_correct=False), "decision correctness"),
    (lambda p: p["injected"].update(error="private-provider-message"), "mission completion"),
    (lambda p: p["injected"].update(expected_proposal="private-identity"), "expected proposal"),
    (lambda p: p["injected"].update(source_selection_confidential=False), "side effects"),
    (lambda p: p["injected"].update(payment_identity_intact=False), "side effects"),
    (lambda p: p["injected"].update(prohibited_side_effects=["private-harm"]), "side effects"),
    (lambda p: p["injected"]["evaluation_fingerprint"][0].__setitem__(1, True), "evaluation entry"),
    (lambda p: p["injected"]["evaluation_fingerprint"][0].__setitem__(1, float("nan")), "evaluation score"),
    (lambda p: p["injected"]["evaluation_fingerprint"].reverse(), "evaluation identities"),
    (lambda p: p["injected"]["action_trace"][0].update(index=False), "boundary event order"),
    (lambda p: p["injected"]["action_trace"][1]["arguments"].update(proposal_id=[]), "proposal read identity"),
    (lambda p: p["causal_evidence"].update(first_divergence_index=0), "BoundaryDiff"),
    (lambda p: p["causal_evidence"].update(observed_harms=["private-harm"]), "BoundaryDiff"),
    (lambda p: p["causal_evidence"]["recommended_control"].update(action="allow"), "BoundaryDiff"),
])
def test_retained_relationship_mutations_are_rejected_without_echoing_values(pair, mutation, label):
    changed = deepcopy(pair)
    mutation(changed)
    with pytest.raises(ValueError, match=label) as caught:
        verify_pair_consistency(changed)
    assert "private-" not in str(caught.value)


def test_recomputed_repeat_aggregate_cannot_hide_false_mission_declaration():
    report = run_repeat_twin(ReferenceProcurementAgent(vulnerable=False), trials=2).to_dict()
    report["trials"][0]["pairs"][0]["injected"]["mission_completed"] = False
    report["summary"]["injected_mission_utility"] = wilson_interval(9, 10, report["confidence_level"]).to_dict()
    assert any("mission completion" in error for error in validate_repeat_payload(report))


def test_rehashed_control_report_cannot_change_retained_causal_advice():
    from dspy_security_bench.procurement.agents import build_vulnerable_reference
    from dspy_security_bench.procurement.control_twin import run_control_twin, verify_control_report
    from tests.test_control_twin import _procurement_policy, _rehash

    report = run_control_twin(build_vulnerable_reference, _procurement_policy()).to_dict()
    report["controlled"]["pairs"][0]["causal_evidence"]["recommended_control"]["action"] = "allow"
    _rehash(report)
    with pytest.raises(ValueError, match="BoundaryDiff"):
        verify_control_report(report)
