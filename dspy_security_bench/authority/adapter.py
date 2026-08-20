"""AuthorityTwin adapter contract and deterministic reference adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from dspy_security_bench.authority.protocol import approval_target_sha256, policy_sha256
from dspy_security_bench.mission.loader import canonical_sha256

DecisionOutcome = Literal["allow", "deny", "review"]


@dataclass(frozen=True)
class AuthorityDecision:
    outcome: DecisionOutcome
    reason_code: str
    receipt: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "receipt": self.receipt,
        }


class AuthorityAdapter(Protocol):
    @property
    def name(self) -> str: ...

    def authorize(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> AuthorityDecision | Mapping[str, Any]: ...


def build_normalized_receipt(
    *,
    adapter: str,
    request: Mapping[str, Any],
    outcome: DecisionOutcome,
    reason_code: str,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": 1,
        "receipt_type": "authoritytwin-normalized-decision",
        "adapter": adapter,
        "request_sha256": canonical_sha256(request),
        "policy_sha256": policy_sha256(),
        "principal_id": request.get("principal_id"),
        "agent_id": request.get("agent_id"),
        "decision": outcome,
        "reason_code": reason_code,
    }
    return {**unsigned, "receipt_sha256": canonical_sha256(unsigned)}


def coerce_decision(value: AuthorityDecision | Mapping[str, Any]) -> AuthorityDecision:
    if isinstance(value, AuthorityDecision):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("authority adapter must return AuthorityDecision or a mapping")
    outcome = value.get("outcome")
    reason = value.get("reason_code")
    receipt = value.get("receipt")
    if outcome not in {"allow", "deny", "review"}:
        raise ValueError("authority decision outcome must be allow, deny, or review")
    if not isinstance(reason, str) or not reason:
        raise ValueError("authority decision reason_code must be non-empty")
    if not isinstance(receipt, Mapping):
        raise ValueError("authority decision receipt must be an object")
    return AuthorityDecision(outcome=outcome, reason_code=reason, receipt=dict(receipt))


class BoundedAuthorityAdapter:
    """Reference enforcement fixture; not a production IAM implementation."""

    name = "reference-authority-bounded"

    def authorize(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> AuthorityDecision:
        outcome, reason = self._evaluate(request, context)
        return AuthorityDecision(
            outcome=outcome,
            reason_code=reason,
            receipt=build_normalized_receipt(
                adapter=self.name,
                request=request,
                outcome=outcome,
                reason_code=reason,
            ),
        )

    @staticmethod
    def _evaluate(
        request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> tuple[DecisionOutcome, str]:
        grant = context.get("grant")
        if not isinstance(grant, Mapping):
            return "deny", "grant_missing"
        if request.get("principal_id") not in context.get("known_principals", []):
            return "deny", "principal_unknown"
        if request.get("agent_id") not in context.get("known_agents", []):
            return "deny", "agent_unknown"
        for field in ("principal_id", "tenant", "token_id"):
            if request.get(field) != grant.get(field):
                return "deny", f"grant_{field}_mismatch"
        resource = request.get("resource")
        if not isinstance(resource, Mapping) or resource.get("tenant") != grant.get("tenant"):
            return "deny", "resource_tenant_mismatch"
        if request.get("audience") != grant.get("audience"):
            return "deny", "audience_mismatch"
        if grant.get("revoked") is True:
            return "deny", "grant_revoked"
        evaluation_time = context.get("evaluation_time")
        expires_at = grant.get("expires_at")
        if not isinstance(evaluation_time, int) or not isinstance(expires_at, int):
            return "deny", "grant_time_invalid"
        if expires_at < evaluation_time:
            return "deny", "grant_expired"
        requested = request.get("requested_scopes")
        granted = grant.get("scopes")
        if not _valid_scopes(requested) or not _valid_scopes(granted):
            return "deny", "scope_set_invalid"
        if not _string_set(requested).issubset(_string_set(granted)):
            return "deny", "scope_not_granted"
        if not _delegation_attenuates(
            context.get("delegation_chain"),
            principal_id=request.get("principal_id"),
            granted_agent_id=grant.get("agent_id"),
            requesting_agent_id=request.get("agent_id"),
            granted_scopes=_string_set(granted),
            requested_scopes=_string_set(requested),
        ):
            return "deny", "delegation_scope_inflation"
        intent = context.get("intent")
        if (
            not isinstance(intent, Mapping)
            or request.get("intent_id") != intent.get("intent_id")
            or request.get("action") not in intent.get("allowed_actions", [])
        ):
            return "deny", "intent_action_mismatch"
        if request.get("approval_required") is True:
            approval = context.get("approval")
            if not isinstance(approval, Mapping):
                return "deny", "approval_missing"
            nonce = approval.get("nonce")
            if nonce != request.get("nonce"):
                return "deny", "approval_nonce_mismatch"
            if nonce in context.get("used_nonces", []):
                return "deny", "approval_replayed"
            bound = approval.get("bound_request_sha256")
            if bound != approval_target_sha256(dict(request)):
                return "deny", "approval_request_mismatch"
        if context.get("audit_chain_valid") is not True:
            return "deny", "audit_chain_invalid"
        levels = {"public": 0, "internal": 1, "sensitive": 2, "restricted": 3}
        clearance = levels.get(context.get("principal_clearance"), -1)
        aggregate = levels.get(context.get("aggregate_sensitivity"), 99)
        if aggregate > clearance:
            return "review", "aggregate_sensitivity_requires_review"
        return "allow", "authorized"


class AmbientAuthorityAdapter:
    """Deliberately vulnerable ambient-credential fixture."""

    name = "reference-authority-ambient"

    def authorize(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> AuthorityDecision:
        del context
        outcome: DecisionOutcome = "allow"
        reason = "ambient_credential_present"
        return AuthorityDecision(
            outcome=outcome,
            reason_code=reason,
            receipt=build_normalized_receipt(
                adapter=self.name,
                request=request,
                outcome=outcome,
                reason_code=reason,
            ),
        )


def build_bounded_authority_adapter() -> BoundedAuthorityAdapter:
    return BoundedAuthorityAdapter()


def build_ambient_authority_adapter() -> AmbientAuthorityAdapter:
    return AmbientAuthorityAdapter()


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return set()
    return set(value)


def _valid_scopes(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def _delegation_attenuates(
    value: Any,
    *,
    principal_id: Any,
    granted_agent_id: Any,
    requesting_agent_id: Any,
    granted_scopes: set[str],
    requested_scopes: set[str],
) -> bool:
    if not isinstance(value, list) or not value:
        return False
    previous_scopes = granted_scopes
    previous_delegate = principal_id
    for index, hop in enumerate(value):
        if not isinstance(hop, Mapping):
            return False
        scopes = _string_set(hop.get("scopes"))
        if (
            not scopes
            or not scopes.issubset(previous_scopes)
            or hop.get("delegator") != previous_delegate
        ):
            return False
        if index == 0 and hop.get("delegate") != granted_agent_id:
            return False
        previous_scopes = scopes
        previous_delegate = hop.get("delegate")
    return previous_delegate == requesting_agent_id and requested_scopes.issubset(previous_scopes)
