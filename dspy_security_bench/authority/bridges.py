"""Dependency-light bridges from common policy/IAM responses to AuthorityTwin.

The bridge layer deliberately accepts injected callbacks instead of importing vendor
SDKs. Applications keep ownership of credentials, network configuration, retries, and
backend-specific policy. AuthorityTwin receives only canonical JSON input and a
normalized allow/deny/review decision.
"""

from __future__ import annotations

import textwrap
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dspy_security_bench.authority.adapter import (
    AuthorityDecision,
    BoundedAuthorityAdapter,
    DecisionOutcome,
    build_normalized_receipt,
)
from dspy_security_bench.authority.protocol import protocol_sha256


@dataclass(frozen=True)
class AuthorityBridgeSpec:
    key: str
    label: str
    interface: str
    standards: tuple[str, ...]
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "interface": self.interface,
            "standards": list(self.standards),
            "purpose": self.purpose,
        }


AUTHORITY_BRIDGES: tuple[AuthorityBridgeSpec, ...] = (
    AuthorityBridgeSpec(
        key="opa",
        label="Open Policy Agent / Rego",
        interface="result.allow or result.decision",
        standards=("policy-as-code",),
        purpose="Evaluate the complete authorization request as structured Rego input.",
    ),
    AuthorityBridgeSpec(
        key="cedar",
        label="Cedar",
        interface="decision=Allow|Deny|Review",
        standards=("policy-based access control",),
        purpose="Translate an agent action into principal, action, resource, and context.",
    ),
    AuthorityBridgeSpec(
        key="openfga",
        label="OpenFGA",
        interface="allowed=true|false",
        standards=("relationship-based access control",),
        purpose="Bind tenant, resource, principal, agent, and delegated relation checks.",
    ),
    AuthorityBridgeSpec(
        key="oauth-mcp",
        label="OAuth/OIDC + MCP",
        interface="active, audience_bound, scope_granted, delegation_valid",
        standards=("OAuth 2.x", "OpenID Connect", "Model Context Protocol"),
        purpose="Check token lifecycle, audience, scopes, human binding, and MCP tool intent.",
    ),
    AuthorityBridgeSpec(
        key="spiffe",
        label="SPIFFE/SPIRE workload identity",
        interface="authenticated, authorized, workload_id",
        standards=("SPIFFE", "SPIRE"),
        purpose="Combine workload attestation with an explicit action authorization decision.",
    ),
)

_BY_KEY = {item.key: item for item in AUTHORITY_BRIDGES}


def get_authority_bridge(name: str) -> AuthorityBridgeSpec:
    try:
        return _BY_KEY[name.strip().lower()]
    except KeyError as exc:
        raise ValueError(
            f"unknown authority bridge {name!r}; choose one of: {', '.join(_BY_KEY)}"
        ) from exc


class PolicyEngineAuthorityBridge:
    """Normalize one policy/IAM callback into the AuthorityAdapter contract.

    The callback receives a fresh JSON-like object with ``request``, ``context``,
    ``bridge`` and ``authoritytwin_protocol_sha256`` fields. It must return a mapping
    in the selected backend's response shape. No token, credential, or network client
    is read or created by this class.
    """

    def __init__(
        self,
        backend: str,
        evaluator: Callable[[Mapping[str, Any]], Mapping[str, Any] | bool],
        *,
        name: str | None = None,
    ) -> None:
        spec = get_authority_bridge(backend)
        if not callable(evaluator):
            raise TypeError("authority bridge evaluator must be callable")
        self.backend = spec.key
        self.evaluator = evaluator
        self.name = name or f"authority-bridge-{spec.key}"
        if not self.name.strip():
            raise ValueError("authority bridge name must be non-empty")

    def authorize(
        self, request: Mapping[str, Any], context: Mapping[str, Any]
    ) -> AuthorityDecision:
        input_document = {
            "schema_version": 1,
            "bridge": self.backend,
            "authoritytwin_protocol_sha256": protocol_sha256(),
            "request": deepcopy(dict(request)),
            "context": deepcopy(dict(context)),
        }
        raw = self.evaluator(input_document)
        outcome, reason = _parse_backend_decision(self.backend, raw)
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


def build_bridge_contract_fixture(backend: str) -> PolicyEngineAuthorityBridge:
    """Return a translation fixture; it does not execute the named backend product."""

    spec = get_authority_bridge(backend)
    bounded = BoundedAuthorityAdapter()

    def evaluate(input_document: Mapping[str, Any]) -> Mapping[str, Any] | bool:
        request = input_document["request"]
        context = input_document["context"]
        outcome, reason = bounded._evaluate(request, context)
        return _encode_fixture_response(spec.key, outcome, reason)

    return PolicyEngineAuthorityBridge(
        spec.key,
        evaluate,
        name=f"contract-fixture-{spec.key}",
    )


def bridge_scaffold(backend: str) -> str:
    """Return a deny-by-default, dependency-free bridge starter module."""

    spec = get_authority_bridge(backend)
    native_deny = repr(_encode_fixture_response(spec.key, "deny", "bridge_not_configured"))
    return textwrap.dedent(
        f'''\
        """{spec.label} AuthorityTwin bridge.

        Replace ``evaluate_authority`` with your existing client call. Keep credentials
        and retries in your application; the benchmark passes canonical JSON only.
        This starter denies every request until configured.
        """

        from collections.abc import Mapping
        from typing import Any

        from dspy_security_bench.authority.bridges import PolicyEngineAuthorityBridge

        BACKEND = {spec.key!r}


        def evaluate_authority(input_document: Mapping[str, Any]):
            # TODO: map input_document to {spec.label}, then return its decision response.
            # Required response interface: {spec.interface}.
            del input_document
            return {native_deny}


        def build_authority_adapter() -> PolicyEngineAuthorityBridge:
            return PolicyEngineAuthorityBridge(
                BACKEND,
                evaluate_authority,
                name="my-{spec.key}-authority-adapter",
            )
        '''
    )


def write_bridge_scaffold(path: str | Path, backend: str, *, force: bool = False) -> Path:
    destination = Path(path)
    if destination.exists() and not force:
        raise FileExistsError(f"kept existing {destination}; use --force to replace")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(bridge_scaffold(backend), encoding="utf-8")
    return destination


def _parse_backend_decision(
    backend: str, value: Mapping[str, Any] | bool
) -> tuple[DecisionOutcome, str]:
    if isinstance(value, bool):
        return ("allow", "backend_allow") if value else ("deny", "backend_deny")
    if not isinstance(value, Mapping):
        raise TypeError("authority bridge callback must return a mapping or boolean")
    payload: Mapping[str, Any] = value
    if backend == "opa" and "result" in value:
        if isinstance(value.get("result"), bool):
            allowed = value["result"]
            reason = value.get("reason_code", "opa_allow" if allowed else "opa_deny")
            if not isinstance(reason, str) or not reason:
                raise ValueError("authority bridge reason must be a non-empty string")
            return _boolean_outcome(allowed), reason
        if isinstance(value.get("result"), Mapping):
            payload = value["result"]
    normalized = payload.get("outcome")
    if isinstance(normalized, str) and normalized.lower() in {"allow", "deny", "review"}:
        outcome = normalized.lower()
    elif backend == "cedar":
        decision = str(payload.get("decision", "")).lower()
        outcome = _decision_word(decision)
    elif backend in {"opa", "openfga"}:
        if payload.get("review") is True:
            outcome = "review"
        else:
            allowed = payload.get("allow", payload.get("allowed"))
            outcome = _boolean_outcome(allowed)
    elif backend == "oauth-mcp":
        if payload.get("review") is True:
            outcome = "review"
        else:
            checks = ("active", "audience_bound", "scope_granted", "delegation_valid")
            if not all(isinstance(payload.get(field), bool) for field in checks):
                raise ValueError("oauth-mcp response must contain four boolean security checks")
            outcome = "allow" if all(payload[field] for field in checks) else "deny"
    elif backend == "spiffe":
        if payload.get("review") is True:
            outcome = "review"
        else:
            if not isinstance(payload.get("authenticated"), bool) or not isinstance(
                payload.get("authorized"), bool
            ):
                raise ValueError(
                    "spiffe response must contain authenticated and authorized booleans"
                )
            outcome = "allow" if payload["authenticated"] and payload["authorized"] else "deny"
    else:  # pragma: no cover - get_authority_bridge closes this branch
        raise ValueError(f"unsupported bridge backend {backend!r}")
    reason = payload.get("reason_code", payload.get("reason", f"{backend}_{outcome}"))
    if not isinstance(reason, str) or not reason:
        raise ValueError("authority bridge reason must be a non-empty string")
    return outcome, reason


def _decision_word(value: str) -> DecisionOutcome:
    aliases = {"allow": "allow", "deny": "deny", "review": "review"}
    try:
        return aliases[value]
    except KeyError as exc:
        raise ValueError("backend decision must be allow, deny, or review") from exc


def _boolean_outcome(value: Any) -> DecisionOutcome:
    if not isinstance(value, bool):
        raise ValueError("backend response must contain an allow/allowed boolean")
    return "allow" if value else "deny"


def _encode_fixture_response(
    backend: str, outcome: DecisionOutcome, reason: str
) -> Mapping[str, Any]:
    if backend == "opa":
        return {
            "result": {
                "allow": outcome == "allow",
                "review": outcome == "review",
                "reason_code": reason,
            }
        }
    if backend == "cedar":
        return {"decision": outcome.title(), "reason": reason}
    if backend == "openfga":
        return {
            "allowed": outcome == "allow",
            "review": outcome == "review",
            "reason": reason,
        }
    if backend == "oauth-mcp":
        allowed = outcome == "allow"
        return {
            "active": allowed,
            "audience_bound": allowed,
            "scope_granted": allowed,
            "delegation_valid": allowed,
            "review": outcome == "review",
            "reason": reason,
        }
    if backend == "spiffe":
        return {
            "authenticated": outcome == "allow",
            "authorized": outcome == "allow",
            "review": outcome == "review",
            "reason": reason,
        }
    raise ValueError(f"unsupported bridge backend {backend!r}")
