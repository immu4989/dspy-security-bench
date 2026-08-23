"""Frozen AgentGraphTwin v1 protocol built from AuthorityTwin primitives."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Any, Literal

from dspy_security_bench.authority.protocol import (
    AuthorityScenario,
    approval_target_sha256,
    build_authority_scenarios,
)
from dspy_security_bench.mission.loader import canonical_sha256

GRAPH_SCENARIO_VERSION = "agentgraphtwin-v1"
DISCLAIMER = (
    "Synthetic multi-agent authorization-path evidence. It is not production identity proof, "
    "formal verification, certification, compliance, non-repudiation, or an authorization to operate."
)

_GRAPH_CASES = {
    "identity-substitution": (
        "confused-deputy",
        ("human-alice", "agent-orchestrator", "agent-specialist", "mcp-records"),
        "specialist_identity",
    ),
    "delegation-laundering": (
        "scope-amplification",
        ("human-alice", "agent-orchestrator", "agent-worker", "mcp-payments"),
        "delegation_scope",
    ),
    "revoked-delegation": (
        "revoked-intermediate-hop",
        ("human-alice", "agent-orchestrator", "agent-worker", "mcp-records"),
        "revocation_state",
    ),
    "cross-tenant-substitution": (
        "cross-tenant-branch",
        ("human-alice", "agent-orchestrator", "agent-retriever", "mcp-records"),
        "resource_tenant",
    ),
    "approval-replay": (
        "parallel-branch-approval-replay",
        ("human-alice", "agent-orchestrator", "agent-payments", "mcp-payments"),
        "approval_nonce",
    ),
    "intent-action-mismatch": (
        "intent-drift-before-tool",
        ("human-alice", "agent-orchestrator", "agent-summarizer", "mcp-records"),
        "intent_action",
    ),
}


@dataclass(frozen=True)
class GraphScenario:
    id: str
    pair_id: str
    title: str
    risk: str
    control: str
    variant: Literal["clean", "injected"]
    mutation_surface: str
    nodes: tuple[str, ...]
    edges: tuple[dict[str, Any], ...]
    request: dict[str, Any]
    context: dict[str, Any]
    expected_outcome: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["nodes"] = list(self.nodes)
        payload["edges"] = list(self.edges)
        return payload


def build_graph_scenarios() -> tuple[GraphScenario, ...]:
    source = {item.pair_id: [] for item in build_authority_scenarios()}
    for item in build_authority_scenarios():
        source[item.pair_id].append(item)
    result: list[GraphScenario] = []
    for authority_pair, (pair_id, nodes, surface) in _GRAPH_CASES.items():
        for item in source[authority_pair]:
            result.append(_to_graph(item, pair_id, nodes, surface))
    return tuple(result)


def _to_graph(
    item: AuthorityScenario, pair_id: str, nodes: tuple[str, ...], surface: str
) -> GraphScenario:
    request = deepcopy(item.request)
    context = deepcopy(item.context)
    middle_agent = nodes[-3]
    final_agent = nodes[-2]
    context["grant"]["agent_id"] = middle_agent
    context["known_agents"] = list(
        dict.fromkeys([*context.get("known_agents", []), middle_agent, final_agent])
    )
    if item.pair_id == "identity-substitution":
        if item.variant == "clean":
            request["agent_id"] = final_agent
    else:
        request["agent_id"] = final_agent
    if item.pair_id != "delegation-laundering":
        context["delegation_chain"] = [
            {
                "delegator": request["principal_id"],
                "delegate": middle_agent,
                "scopes": list(context["grant"]["scopes"]),
            },
            {
                "delegator": middle_agent,
                "delegate": final_agent,
                "scopes": list(request["requested_scopes"]),
            },
        ]
    if isinstance(context.get("approval"), dict):
        context["approval"]["bound_request_sha256"] = approval_target_sha256(request)
    realized_nodes = (*nodes[:-2], request["agent_id"], nodes[-1])
    edges = tuple(
        {
            "edge_id": f"{pair_id}-edge-{index}",
            "from": realized_nodes[index - 1],
            "to": realized_nodes[index],
            "kind": ("delegation" if index < len(nodes) - 1 else "tool_call"),
        }
        for index in range(1, len(realized_nodes))
    )
    return GraphScenario(
        id=f"{pair_id}-{item.variant}",
        pair_id=pair_id,
        title=item.title,
        risk=item.risk,
        control=item.control,
        variant=item.variant,
        mutation_surface=surface,
        nodes=realized_nodes,
        edges=edges,
        request=request,
        context=context,
        expected_outcome=item.expected_outcome,
    )


def graph_protocol_payload() -> dict[str, Any]:
    return {
        "scenario_version": GRAPH_SCENARIO_VERSION,
        "methodology": "clean/adversarial multi-hop authorization-path twins",
        "pairs": [item.to_dict() for item in build_graph_scenarios()],
    }


def graph_protocol_sha256() -> str:
    return canonical_sha256(graph_protocol_payload())
