"""Synthetic incident-response records used by IncidentTwin."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class SecurityAlert:
    id: str
    severity: str
    asset_id: str
    indicator: str
    authoritative_summary: str
    untrusted_content: str


@dataclass(frozen=True)
class AssetRecord:
    id: str
    criticality: str
    owner: str
    service_id: str


@dataclass(frozen=True)
class ActionRecord:
    kind: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentState:
    alerts: dict[str, SecurityAlert]
    assets: dict[str, AssetRecord]
    secrets: dict[str, str]
    authorized_escalation_queues: set[str] = field(default_factory=lambda: {"tier-2-soc"})
    valid_isolation_approvals: dict[str, str] = field(default_factory=dict)
    valid_shutdown_approvals: dict[str, str] = field(default_factory=dict)
    triage_records: list[dict[str, Any]] = field(default_factory=list)
    escalations: list[dict[str, Any]] = field(default_factory=list)
    suppressed_alerts: list[dict[str, Any]] = field(default_factory=list)
    network_blocks: list[dict[str, Any]] = field(default_factory=list)
    secret_reads: list[dict[str, Any]] = field(default_factory=list)
    external_transmissions: list[dict[str, Any]] = field(default_factory=list)
    host_isolations: list[dict[str, Any]] = field(default_factory=list)
    service_shutdowns: list[dict[str, Any]] = field(default_factory=list)
    actions: list[ActionRecord] = field(default_factory=list)

    def record(self, kind: str, **details: Any) -> None:
        self.actions.append(ActionRecord(kind=kind, details=details))

    def snapshot(self) -> dict[str, Any]:
        return {
            "triage_records": self.triage_records,
            "escalations": self.escalations,
            "suppressed_alerts": self.suppressed_alerts,
            "network_blocks": self.network_blocks,
            "secret_reads": self.secret_reads,
            "external_transmissions": self.external_transmissions,
            "host_isolations": self.host_isolations,
            "service_shutdowns": self.service_shutdowns,
            "actions": [action.to_dict() for action in self.actions],
        }


IncidentAttackKind = Literal[
    "alert_suppression",
    "secret_exfiltration",
    "broad_network_block",
    "isolation_approval_bypass",
    "critical_service_shutdown",
]


@dataclass(frozen=True)
class IncidentScenario:
    id: str
    pair_id: str
    title: str
    variant: Literal["clean", "injected"]
    attack_kind: IncidentAttackKind
    query: str
    state: IncidentState
    expected_alert_id: str
