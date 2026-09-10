"""Scope receipts and approval levels for live web testing.

RAPTOR already keeps requests on the configured origin. This layer makes that
decision explicit, persists it into the run, and gives external tools the same
guardrail as the built-in HTTP client.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlparse
from uuid import uuid4

from core.security.redaction import (
    is_secret_field_name,
    redact_secrets,
    redact_url_secrets_only,
)


_RISK_ORDER = {"passive": 0, "active": 1, "intrusive": 2}
_REPLAY_METHODS = frozenset({"GET", "POST"})
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MAX_REPLAY_URL_CHARS = 8192
_MAX_REPLAY_HEADERS = 32
_MAX_REPLAY_HEADER_NAME_CHARS = 128
_MAX_REPLAY_HEADER_VALUE_CHARS = 2048
_MAX_REPLAY_BODY_FIELDS = 32
_MAX_REPLAY_BODY_FIELD_NAME_CHARS = 128
_MAX_REPLAY_BODY_VALUE_CHARS = 4096
_MAX_REPLAY_BODY_BYTES = 16 * 1024

_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})
_AUTHORITY_CHANGING_HEADERS = frozenset({
    ":authority",
    "host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-forwarded-server",
    "x-host",
    "x-original-host",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
})
_CREDENTIAL_HEADERS = frozenset({
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
})
_TRANSPORT_MANAGED_HEADERS = frozenset({
    "content-length",
})
_SENSITIVE_REPLAY_FIELDS = frozenset({
    "csrf",
    "nonce",
    "session",
    "sessionid",
    "sid",
    "state",
})


class WebPolicyError(ValueError):
    """Raised when a live web action falls outside its receipt or approval."""


@dataclass(frozen=True)
class PreparedReplayRequest:
    """Policy-sanitized request inputs for scanner-owned validation replay."""

    method: str
    url: str
    headers: dict[str, str]
    form_data: dict[str, str] | None
    omitted_headers: tuple[dict[str, str], ...] = ()
    omitted_body_fields: tuple[dict[str, str], ...] = ()

    def metadata(self) -> dict[str, Any]:
        """Return a secret-free, bounded description for replay artifacts."""
        body = self.form_data or {}
        return {
            "method": self.method,
            "url": _bounded_text(redact_secrets(self.url), 2048),
            "header_names": sorted(self.headers),
            "omitted_headers": [dict(item) for item in self.omitted_headers],
            "body_kind": "form" if self.form_data is not None else None,
            "body_field_names": sorted(body),
            "body_bytes": len(urlencode(body).encode("utf-8")) if body else 0,
            "omitted_body_fields": [
                dict(item) for item in self.omitted_body_fields
            ],
        }


def _bounded_text(value: object, limit: int) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    suffix = "...[truncated]"
    return text[: max(0, limit - len(suffix))] + suffix


def _has_control_characters(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def _is_replay_secret_field_name(name: object) -> bool:
    normalized = str(name).strip().lower().replace("-", "_")
    return (
        is_secret_field_name(normalized)
        or normalized in _SENSITIVE_REPLAY_FIELDS
        or "csrf" in normalized
        or "nonce" in normalized
        or "session" in normalized
    )


def _origin(url: str) -> tuple[str, str, int]:
    if not isinstance(url, str):
        raise WebPolicyError("Web scope target must be a URL string")
    if _has_control_characters(url):
        raise WebPolicyError("Web scope target URL contains control characters")
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
    except ValueError as exc:
        raise WebPolicyError(f"Malformed web target URL: {url}") from exc
    if scheme not in {"http", "https"}:
        raise WebPolicyError(
            f"Web scope target must use http:// or https://: {url}"
        )
    if not parsed.netloc or not hostname:
        raise WebPolicyError(
            f"Web scope target must be an absolute HTTP(S) URL with a host: {url}"
        )
    authority = parsed.netloc.rsplit("@", 1)[-1]
    if authority.endswith(":"):
        raise WebPolicyError(f"Invalid port in web target URL: {url}")
    default_port = 443 if scheme == "https" else 80
    try:
        port = parsed.port
    except ValueError as exc:
        # urlparse defers port validation to attribute access: an
        # out-of-range or non-numeric port (a hostile crawled anchor
        # like http://h:99999/x) raises a plain ValueError that would
        # sail past every 'except WebPolicyError' handler and kill the
        # calling phase. Classify it as a policy denial instead.
        raise WebPolicyError(f"Invalid port in web target URL: {url}") from exc
    return (
        scheme,
        hostname.lower(),
        port if port is not None else default_port,
    )


def _origin_text(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    # urlparse strips the brackets from IPv6 hostnames; re-bracket so
    # the rendered origin round-trips through _origin (the receipt's
    # allowed_origins are re-parsed at construction).
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}{suffix}"


def _url_userinfo(url: str) -> str | None:
    parsed = urlparse(url)
    if "@" not in parsed.netloc:
        return None
    return parsed.netloc.rsplit("@", 1)[0]


def _url_query_credentials(url: str) -> Counter[tuple[str, str]]:
    parsed = urlparse(url)
    return Counter(
        (name, value)
        for name, value in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if (
            _is_replay_secret_field_name(name)
            or redact_secrets(value) != value
        )
    )


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

    def __init__(
        self,
        receipt: ScopeReceipt,
        *,
        audit_limit: int = 1024,
        transport_target: str | None = None,
    ):
        if receipt.approval_level not in _RISK_ORDER:
            raise WebPolicyError(
                "approval level must be one of passive, active, intrusive"
            )
        self.receipt = receipt
        self._allowed_origins = {
            _origin(origin) for origin in receipt.allowed_origins
        }
        self._approved_tools = set(receipt.approved_tools)
        if transport_target is None:
            self._approved_replay_userinfo = None
            self._approved_replay_query_credentials = Counter()
        else:
            self._approved_replay_userinfo = _url_userinfo(transport_target)
            self._approved_replay_query_credentials = (
                _url_query_credentials(transport_target)
            )
        self._audit: deque[dict[str, Any]] = deque(maxlen=audit_limit)
        self._counts: Counter[str] = Counter()
        self._decision_seq = 0

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
            target=redact_url_secrets_only(target),
            allowed_origins=(normalized_origin,),
            approval_level=approval_level,
            approved_tools=tuple(dict.fromkeys(approved_tools)),
        )
        return cls(receipt, transport_target=target)

    def authorize(
        self,
        *,
        tool_id: str,
        url: str,
        risk: str,
        action: str,
    ) -> None:
        try:
            self._check_authorized(
                tool_id=tool_id,
                url=url,
                risk=risk,
            )
        except WebPolicyError as exc:
            self._record(tool_id, url, risk, action, "denied", str(exc))
            raise
        self._record(tool_id, url, risk, action, "allowed", "in scope")

    def _check_authorized(
        self,
        *,
        tool_id: str,
        url: str,
        risk: str,
    ) -> None:
        """Validate one action without mutating the policy audit."""
        if risk not in _RISK_ORDER:
            raise WebPolicyError(f"Unknown web action risk: {risk}")

        action_origin = _origin(url)
        if action_origin not in self._allowed_origins:
            reason = f"target origin {_origin_text(action_origin)} is outside scope receipt"
            raise WebPolicyError(reason)

        allowed_risk = _RISK_ORDER[self.receipt.approval_level]
        if _RISK_ORDER[risk] > allowed_risk and tool_id not in self._approved_tools:
            reason = (
                f"{tool_id} is {risk} but receipt only approves "
                f"{self.receipt.approval_level} actions"
            )
            raise WebPolicyError(reason)

    def _normalize_replay_request(
        self,
        *,
        method: object,
        url: object,
        headers: Mapping[object, object] | None,
        form_data: Mapping[object, object] | None,
        required_body_field: str | None,
    ) -> PreparedReplayRequest:
        normalized_method = self._validate_replay_method(method)
        normalized_url = self._validate_replay_url(url)
        safe_headers, omitted_headers = self._sanitize_replay_headers(
            headers,
        )
        safe_form, omitted_body_fields = self._sanitize_replay_form(
            form_data,
        )
        if normalized_method == "GET" and form_data is not None:
            raise WebPolicyError("GET validation replay cannot carry a body")
        if normalized_method == "POST" and safe_form is None:
            safe_form = {}
        if required_body_field is not None:
            if (
                normalized_method != "POST"
                or safe_form is None
                or required_body_field not in safe_form
            ):
                raise WebPolicyError(
                    "required replay body field was absent or removed "
                    "by credential sanitization"
                )
        return PreparedReplayRequest(
            method=normalized_method,
            url=normalized_url,
            headers=safe_headers,
            form_data=safe_form,
            omitted_headers=tuple(omitted_headers),
            omitted_body_fields=tuple(omitted_body_fields),
        )

    def validate_replay_request(
        self,
        *,
        method: object,
        url: object,
        headers: Mapping[object, object] | None = None,
        form_data: Mapping[object, object] | None = None,
        required_body_field: str | None = None,
    ) -> PreparedReplayRequest:
        """Validate replay inputs and approval without recording an action."""
        prepared = self._normalize_replay_request(
            method=method,
            url=url,
            headers=headers,
            form_data=form_data,
            required_body_field=required_body_field,
        )
        self._check_authorized(
            tool_id="raptor-validation-replay",
            url=prepared.url,
            risk="active",
        )
        return prepared

    def prepare_replay_request(
        self,
        *,
        method: object,
        url: object,
        headers: Mapping[object, object] | None = None,
        form_data: Mapping[object, object] | None = None,
        required_body_field: str | None = None,
        action: str,
    ) -> PreparedReplayRequest:
        """Validate and sanitize one scanner-owned replay/control request.

        Only GET and form-encoded POST are supported. Credential-bearing,
        hop-by-hop, transport-managed, and authority-changing headers never
        reach the transport. URL credentials are accepted only when they
        exactly match credentials in the operator-supplied target; artifacts
        expose only their redacted form.
        """
        raw_url = url if isinstance(url, str) else "<invalid-url>"
        try:
            prepared = self._normalize_replay_request(
                method=method,
                url=url,
                headers=headers,
                form_data=form_data,
                required_body_field=required_body_field,
            )
        except WebPolicyError as exc:
            self._record(
                "raptor-validation-replay",
                raw_url,
                "active",
                action,
                "denied",
                _bounded_text(redact_secrets(str(exc)), 300),
            )
            raise

        self.authorize(
            tool_id="raptor-validation-replay",
            url=prepared.url,
            risk="active",
            action=action,
        )
        return prepared

    @staticmethod
    def replay_limits() -> dict[str, int]:
        return {
            "max_url_chars": _MAX_REPLAY_URL_CHARS,
            "max_headers": _MAX_REPLAY_HEADERS,
            "max_header_value_chars": _MAX_REPLAY_HEADER_VALUE_CHARS,
            "max_body_fields": _MAX_REPLAY_BODY_FIELDS,
            "max_body_value_chars": _MAX_REPLAY_BODY_VALUE_CHARS,
            "max_body_bytes": _MAX_REPLAY_BODY_BYTES,
        }

    def decision_cursor(self) -> int:
        """Return the monotonic policy-decision sequence."""
        return self._decision_seq

    def decisions_since(self, cursor: int) -> list[dict[str, Any]]:
        """Return retained decisions newer than *cursor*."""
        return [
            dict(item)
            for item in self._audit
            if int(item.get("sequence", 0)) > cursor
        ]

    @staticmethod
    def _validate_replay_method(method: object) -> str:
        if not isinstance(method, str):
            raise WebPolicyError("validation replay method must be a string")
        normalized = method.strip().upper()
        if normalized not in _REPLAY_METHODS:
            raise WebPolicyError(
                "validation replay supports only GET and POST"
            )
        return normalized

    def _validate_replay_url(self, url: object) -> str:
        if not isinstance(url, str):
            raise WebPolicyError("validation replay URL must be a string")
        if not url or len(url) > _MAX_REPLAY_URL_CHARS:
            raise WebPolicyError("validation replay URL is empty or too large")
        _origin(url)
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            raise WebPolicyError("validation replay URL is malformed") from exc
        userinfo = _url_userinfo(url)
        if (
            userinfo is not None
            and userinfo != self._approved_replay_userinfo
        ):
            raise WebPolicyError(
                "validation replay URL must not contain credentials"
            )
        if parsed.fragment:
            raise WebPolicyError(
                "validation replay does not support URL fragments"
            )
        credentials = _url_query_credentials(url)
        for credential, count in credentials.items():
            if count > self._approved_replay_query_credentials[credential]:
                raise WebPolicyError(
                    "validation replay URL contains credential-bearing "
                    "query evidence"
                )
        return url

    @staticmethod
    def _sanitize_replay_headers(
        headers: Mapping[object, object] | None,
    ) -> tuple[dict[str, str], list[dict[str, str]]]:
        if headers is None:
            return {}, []
        if not isinstance(headers, Mapping):
            raise WebPolicyError(
                "validation replay headers must be a mapping"
            )
        if len(headers) > _MAX_REPLAY_HEADERS:
            raise WebPolicyError("validation replay has too many headers")

        safe: dict[str, str] = {}
        omitted: list[dict[str, str]] = []
        normalized_seen: set[str] = set()
        for raw_name, raw_value in sorted(
            headers.items(), key=lambda item: str(item[0]).lower(),
        ):
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise WebPolicyError(
                    "validation replay header names and values must be strings"
                )
            name = raw_name.strip()
            lower = name.lower()
            if (
                not name
                or len(name) > _MAX_REPLAY_HEADER_NAME_CHARS
                or not _HEADER_NAME_RE.fullmatch(name)
            ):
                raise WebPolicyError("validation replay header name is invalid")
            if lower in normalized_seen:
                raise WebPolicyError(
                    "validation replay contains duplicate header names"
                )
            normalized_seen.add(lower)
            if (
                not raw_value
                or len(raw_value) > _MAX_REPLAY_HEADER_VALUE_CHARS
                or _has_control_characters(raw_value)
            ):
                raise WebPolicyError(
                    f"validation replay header {name!r} has an invalid value"
                )

            reason = None
            if lower in _HOP_BY_HOP_HEADERS:
                reason = "hop_by_hop"
            elif lower in _AUTHORITY_CHANGING_HEADERS:
                reason = "authority_or_method_override"
            elif (
                lower in _CREDENTIAL_HEADERS
                or _is_replay_secret_field_name(lower)
            ):
                reason = "credential"
            elif lower in _TRANSPORT_MANAGED_HEADERS:
                reason = "transport_managed"
            elif redact_secrets(raw_value) != raw_value:
                reason = "secret_value"

            if reason is not None:
                omitted.append({"name": name, "reason": reason})
                continue
            safe[name] = raw_value
        return safe, omitted

    @staticmethod
    def _sanitize_replay_form(
        form_data: Mapping[object, object] | None,
    ) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
        if form_data is None:
            return None, []
        if not isinstance(form_data, Mapping):
            raise WebPolicyError(
                "validation replay form body must be a mapping"
            )
        if len(form_data) > _MAX_REPLAY_BODY_FIELDS:
            raise WebPolicyError(
                "validation replay form body has too many fields"
            )

        safe: dict[str, str] = {}
        omitted: list[dict[str, str]] = []
        for raw_name, raw_value in sorted(
            form_data.items(), key=lambda item: str(item[0]),
        ):
            if not isinstance(raw_name, str):
                raise WebPolicyError(
                    "validation replay form field names must be strings"
                )
            name = raw_name.strip()
            if (
                not name
                or len(name) > _MAX_REPLAY_BODY_FIELD_NAME_CHARS
                or _has_control_characters(name)
            ):
                raise WebPolicyError(
                    "validation replay form field name is invalid"
                )
            if isinstance(raw_value, (bytes, bytearray, memoryview)):
                raise WebPolicyError(
                    "validation replay form values must be scalar text"
                )
            if raw_value is None:
                value = ""
            elif isinstance(raw_value, (str, int, float, bool)):
                value = str(raw_value)
            else:
                raise WebPolicyError(
                    "validation replay form values must be scalar text"
                )
            if (
                len(value) > _MAX_REPLAY_BODY_VALUE_CHARS
                or _has_control_characters(value)
            ):
                raise WebPolicyError(
                    f"validation replay form field {name!r} is invalid"
                )
            if _is_replay_secret_field_name(name):
                omitted.append({"name": name, "reason": "credential"})
                continue
            if redact_secrets(value) != value:
                omitted.append({"name": name, "reason": "secret_value"})
                continue
            safe[name] = value

        if len(urlencode(safe).encode("utf-8")) > _MAX_REPLAY_BODY_BYTES:
            raise WebPolicyError(
                "validation replay form body exceeds the size limit"
            )
        return safe, omitted

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
        self._decision_seq += 1
        self._counts[f"{decision}:{tool_id}"] += 1
        self._audit.append({
            "sequence": self._decision_seq,
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
