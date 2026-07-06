"""Scope receipts and approval levels for live web testing.

RAPTOR already keeps requests on the configured origin. This layer makes that
decision explicit, persists it into the run, and gives external tools the same
guardrail as the built-in HTTP client.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse
from uuid import uuid4


_RISK_ORDER = {"passive": 0, "active": 1, "intrusive": 2}


class WebPolicyError(ValueError):
    """Raised when a live web action falls outside its receipt or approval."""


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise WebPolicyError(f"Web scope target must be an absolute URL: {url}")
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        parsed.port or default_port,
    )


def _origin_text(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


@dataclass(frozen=True)
class ScopeReceipt:
    """The operator-supplied live target scope for one web run."""

    id: str
    target: str
    allowed_origins: tuple[str, ...]
    approval_level: str
    approved_tools: tuple[str, ...] = ()
    source: str = "operator_cli"
    issued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "allowed_origins": list(self.allowed_origins),
            "approval_level": self.approval_level,
            "approved_tools": list(self.approved_tools),
            "source": self.source,
            "issued_at": self.issued_at,
        }


class WebExecutionPolicy:
    """Enforce scope and approval before a live web action runs."""

    def __init__(self, receipt: ScopeReceipt, *, audit_limit: int = 1024):
        if receipt.approval_level not in _RISK_ORDER:
            raise WebPolicyError(
                "approval level must be one of passive, active, intrusive"
            )
        self.receipt = receipt
        self._allowed_origins = {_origin(origin) for origin in receipt.allowed_origins}
        self._approved_tools = set(receipt.approved_tools)
        self._audit = deque(maxlen=audit_limit)
        self._counts: Counter[str] = Counter()

    @classmethod
    def for_target(
        cls,
        target: str,
        *,
        approval_level: str = "active",
        approved_tools: Iterable[str] = (),
    ) -> "WebExecutionPolicy":
        normalized_origin = _origin_text(_origin(target))
        receipt = ScopeReceipt(
            id=f"web-scope-{uuid4().hex[:12]}",
            target=normalized_origin,
            allowed_origins=(normalized_origin,),
            approval_level=approval_level,
            approved_tools=tuple(dict.fromkeys(approved_tools)),
        )
        return cls(receipt)

    def authorize(
        self,
        *,
        tool_id: str,
        url: str,
        risk: str,
        action: str,
    ) -> None:
        if risk not in _RISK_ORDER:
            raise WebPolicyError(f"Unknown web action risk: {risk}")

        try:
            action_origin = _origin(url)
        except WebPolicyError as exc:
            self._record(tool_id, url, risk, action, "denied", str(exc))
            raise

        if action_origin not in self._allowed_origins:
            reason = f"target origin {_origin_text(action_origin)} is outside scope receipt"
            self._record(tool_id, url, risk, action, "denied", reason)
            raise WebPolicyError(reason)

        allowed_risk = _RISK_ORDER[self.receipt.approval_level]
        if _RISK_ORDER[risk] > allowed_risk and tool_id not in self._approved_tools:
            reason = (
                f"{tool_id} is {risk} but receipt only approves "
                f"{self.receipt.approval_level} actions"
            )
            self._record(tool_id, url, risk, action, "denied", reason)
            raise WebPolicyError(reason)

        self._record(tool_id, url, risk, action, "allowed", "in scope")

    def _record(
        self,
        tool_id: str,
        url: str,
        risk: str,
        action: str,
        decision: str,
        reason: str,
    ) -> None:
        try:
            logged_target = _origin_text(_origin(url))
        except WebPolicyError:
            logged_target = "<invalid-url>"
        self._counts[f"{decision}:{tool_id}"] += 1
        self._audit.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "tool_id": tool_id,
            "target_origin": logged_target,
            "risk": risk,
            "action": action,
            "decision": decision,
            "reason": reason,
        })

    def report(self) -> dict:
        return {
            "scope_receipt": self.receipt.to_dict(),
            "summary": {
                "total_actions": sum(self._counts.values()),
                "allowed_actions": sum(
                    count for key, count in self._counts.items()
                    if key.startswith("allowed:")
                ),
                "denied_actions": sum(
                    count for key, count in self._counts.items()
                    if key.startswith("denied:")
                ),
                "by_tool": dict(self._counts),
            },
            "recent_decisions": list(self._audit),
        }
