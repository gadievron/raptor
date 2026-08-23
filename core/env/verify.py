"""The environment oracle: a check DAG executed through a RuntimeHandle.

Seven check types — ``container_status`` / ``http_check`` /
``log_check`` / ``stability_wait`` / ``exec_check`` /
``http_request_check`` / ``tcp_probe_check`` — run in plan order,
stopping at the first fatal failure. Every ``http_check`` result
carries ``response_size_bytes`` so the zero-bytes-200 trap is a hard
failure, never a silent pass.

Plans are LLM-tolerant: common synonym keys are alias-normalized
(``expect_status`` → ``expected_status``), every plan is canonicalized
to start with ``container_status`` (an early-exited instance fails
fast instead of burning a stability wait), and two injectors close
systematic plan gaps — the version-assertion injector fills a missing
version literal into version-discovery exec_checks (safe: a wrong
deployed version still fails), and the functional-smoke injector
appends benign-input probes that GRADE (a failing injected probe never
fails an otherwise-passing verify).

HTTP/TCP probes only target loopback/private addresses (the published
container-port surfaces) — a public ``host_ip`` is refused so nothing
driving a verify plan can turn this engine into an SSRF primitive.
Plans themselves are untrusted: :func:`verify_plan` discards any
plan-supplied ``host_ip`` (probes pin to the endpoint address) and
honors a per-step ``tcp_probe_check`` port only when it is in the
caller's published-port allowlist.
Probes connect DIRECTLY (no proxy): the targets are always
host-local, so the operator egress proxy must not be consulted.

Caller-supplied hooks carry the policy this module refuses to own:
failure-hint text (agent guidance) and output sanitization (response
tails can echo exploit-confirmation output).
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING


if TYPE_CHECKING:
    from core.env.handle import RuntimeHandle
    from collections.abc import Callable

CheckResult = dict[str, Any]

#: Check types that signal investment beyond minimum lifecycle probing.
#: Consumed by the smoke injector here and by callers' verify-quality
#: heuristics.
ACTIVE_PROBE_TYPES: frozenset[str] = frozenset(
    {"http_request_check", "exec_check", "tcp_probe_check"}
)

_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD"})

_LOOPBACK_HOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})

_CLOUD_METADATA_IPS = frozenset({
    "169.254.169.254",
    "169.254.170.2",
    "fd00:ec2::254",
})


@dataclass(frozen=True)
class VerifyHooks:
    """Caller-supplied policy: hints and sanitization.

    Every hook is optional. ``sanitize`` is applied to response tails
    that may echo exploit-confirmation output before they land in
    results; the hint hooks return agent-facing guidance attached under
    ``details.hint`` (empty string → no hint key added).
    """

    sanitize: Callable[[str], str] = field(default=lambda text: text)
    status_hint: Callable[[dict[str, Any], str], str] | None = None
    http_request_hint: Callable[..., str] | None = None
    tcp_hint: Callable[..., str] | None = None
    quality_warning: Callable[[list[CheckResult]], str] | None = None


_NO_HOOKS = VerifyHooks()


def assert_local_host_ip(host_ip: str) -> str | None:
    """Return None if ``host_ip`` is loopback/private/link-local; else a reason.

    Accepts: ``localhost``/``127.0.0.1``/``::1`` literals, plus any IP
    address that reports ``is_loopback`` / ``is_private`` (covers Docker
    bridge networks, RFC 1918 ranges, IPv6 ULAs). Cloud metadata
    endpoints are refused by name even though they are link-local.
    """
    if not host_ip:
        return "host_ip is empty"
    lowered = host_ip.lower().strip()
    if lowered in _LOOPBACK_HOST_NAMES:
        return None
    if lowered in _CLOUD_METADATA_IPS:
        return (
            f"host_ip {host_ip!r} is a cloud metadata endpoint; "
            "verify probes must not reach instance metadata services"
        )
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return (
            f"host_ip {host_ip!r} is not a valid IP literal; verify probes "
            "must target a published container port on loopback/private"
        )
    if ip.is_loopback or ip.is_private:
        return None
    return (
        f"host_ip {host_ip!r} is not loopback/private; verify probes only "
        "target published container ports (127.0.0.1, ::1, RFC 1918, "
        "Docker bridge subnets)"
    )


# ── direct-connection HTTP exchange ───────────────────────────────────

#: Ceiling on verify-probe response bodies. The peer is the provisioned
#: workload — a service running fully hostile target code — so the body
#: must never be trusted to terminate. Reads are chunked and stop at the
#: cap; content checks then run on the capped prefix (truncation can
#: only REMOVE marker bytes, so an oversize hostile body can never flip
#: a failing check to passing). Real verify responses are health pages
#: and banners, orders of magnitude below this.
_MAX_RESPONSE_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 65536


def _http_exchange(
    *,
    host_ip: str,
    host_port: int,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout_seconds: float,
    max_response_bytes: int = _MAX_RESPONSE_BYTES,
) -> tuple[int, bytes]:
    """One HTTP request/response over a DIRECT connection (no proxy,
    no redirects followed). Raises TimeoutError / OSError on transport
    failure — callers fold those into check results.

    The wall budget covers the ENTIRE exchange, in two layers:

    * body phase: incremental ``read1`` (at most one recv per call, so
      the check stays live) under ``max_response_bytes`` and a
      cooperative monotonic deadline of ``timeout_seconds`` — oversize
      / overtime bodies truncate to what was read in budget;
    * connect + status-line + header phase: ``conn.getresponse()``
      blocks inside http.client with only the socket *inactivity*
      timeout, so a peer dripping status/header bytes inside that
      window could hold the exchange open indefinitely. A hard
      watchdog at ``2 x timeout_seconds`` shuts the socket down,
      folding the stall into TimeoutError.

    The peer runs fully hostile target code; neither phase may trust
    it to terminate."""
    deadline = time.monotonic() + timeout_seconds
    conn = http.client.HTTPConnection(host_ip, host_port,
                                      timeout=timeout_seconds)
    watchdog_fired = threading.Event()

    def _watchdog_shutdown() -> None:
        watchdog_fired.set()
        sock = getattr(conn, "sock", None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:  # already closed — nothing to interrupt
                pass

    watchdog = threading.Timer(timeout_seconds * 2, _watchdog_shutdown)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        chunks: list[bytes] = []
        total = 0
        while total < max_response_bytes:
            if time.monotonic() > deadline:
                break
            chunk = resp.read1(min(_READ_CHUNK_BYTES,
                                   max_response_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if watchdog_fired.is_set():
            # The shutdown often surfaces as a clean EOF (http.client
            # then "completes" with whatever was parsed) — a cut
            # exchange must never masquerade as a successful response.
            raise TimeoutError(
                f"exchange exceeded the {timeout_seconds * 2:g}s wall "
                "watchdog (peer dripped the status/header phase)"
            )
        return resp.status, b"".join(chunks)
    except (OSError, http.client.HTTPException) as exc:
        if watchdog_fired.is_set():
            raise TimeoutError(
                f"exchange exceeded the {timeout_seconds * 2:g}s wall "
                "watchdog (peer dripped the status/header phase)"
            ) from exc
        raise
    finally:
        watchdog.cancel()
        conn.close()


def _url_for(host_ip: str, host_port: int, path: str) -> str:
    host = f"[{host_ip}]" if ":" in host_ip else host_ip
    return f"http://{host}:{host_port}{path}"


# ── check executors ───────────────────────────────────────────────────


def check_container_status(
    handle: RuntimeHandle,
    *,
    hooks: VerifyHooks = _NO_HOOKS,
) -> CheckResult:
    """Return ``{passed, status, details}`` for instance liveness.

    Passes when ``State.Running == True`` and ``State.Status ==
    "running"``. Exited instances with ExitCode=0 are NOT passes — a
    long-lived service that exited cleanly didn't actually start
    serving. On failure, ``details`` is enriched with ``logs_tail`` +
    the caller's classified ``hint``.
    """
    state = handle.state()
    if "_error" in state:
        return {
            "type": "container_status",
            "passed": False,
            "reason": state["_error"],
            "details": state,
        }
    running = bool(state.get("Running"))
    status = str(state.get("Status", ""))
    if running and status == "running":
        return {
            "type": "container_status",
            "passed": True,
            "details": {"status": status, "running": running},
        }
    # strip() so a fetch that yields only whitespace/joiner noise reads
    # as "no logs" — the died-with-no-logs hint depends on it.
    logs_tail = handle.logs(tail=200).strip()[-1024:]
    details: dict[str, Any] = {**state, "logs_tail": logs_tail}
    if hooks.status_hint is not None:
        hint = hooks.status_hint(state, logs_tail)
        if hint:
            details["hint"] = hint
    return {
        "type": "container_status",
        "passed": False,
        "reason": f"container status={status!r} running={running}",
        "details": details,
    }


def check_http(
    *,
    host_ip: str,
    host_port: int,
    path: str = "/",
    method: str = "GET",
    expected_status: list[int] | int = 200,
    timeout_seconds: float = 10.0,
    require_nonempty_body: bool = True,
    content_check: list[str] | None = None,
) -> CheckResult:
    """HTTP liveness probe with ``response_size_bytes`` recorded.

    Zero-body responses fail even on 200 (the zero-bytes trap).
    """
    if not isinstance(method, str):
        return {
            "type": "http_check",
            "passed": False,
            "reason": (f"check_http: method must be str, got {type(method).__name__}"),
            "details": {},
        }
    if method.upper() not in _ALLOWED_METHODS:
        return {
            "type": "http_check",
            "passed": False,
            "reason": f"method {method!r} not allowed",
            "details": {"method": method},
        }
    host_ip_reason = assert_local_host_ip(host_ip)
    if host_ip_reason is not None:
        return {
            "type": "http_check",
            "passed": False,
            "reason": host_ip_reason,
            "details": {"host_ip": host_ip, "host_port": host_port},
        }
    if content_check is not None:
        if isinstance(content_check, str):
            # Normalize single string → list-of-one (LLM shorthand).
            content_check = [content_check]
        elif not isinstance(content_check, list):
            return {
                "type": "http_check",
                "passed": False,
                "reason": (
                    f"check_http: content_check must be a list[str] or str, "
                    f"got {type(content_check).__name__}"
                ),
                "details": {},
            }

    if not isinstance(expected_status, (int, list)):
        return {
            "type": "http_check",
            "passed": False,
            "reason": (
                f"check_http: expected_status must be int or list[int], "
                f"got {type(expected_status).__name__}"
            ),
            "details": {},
        }
    expected = (
        list(expected_status)
        if isinstance(expected_status, list)
        else [int(expected_status)]
    )
    url = _url_for(host_ip, host_port, path)
    start = time.monotonic()
    try:
        status_code, content = _http_exchange(
            host_ip=host_ip, host_port=host_port,
            method=method.upper(), path=path,
            timeout_seconds=timeout_seconds,
        )
    except TimeoutError:
        return {
            "type": "http_check",
            "passed": False,
            "reason": f"timeout after {timeout_seconds}s",
            "details": {"url": url, "duration_s": time.monotonic() - start},
        }
    except (OSError, http.client.HTTPException) as exc:
        return {
            "type": "http_check",
            "passed": False,
            "reason": f"connection error: {exc}",
            "details": {"url": url, "error": str(exc)[:400]},
        }

    response_size_bytes = len(content)
    details: dict[str, Any] = {
        "url": url,
        "method": method.upper(),
        "actual_status": status_code,
        "expected_status": expected,
        "response_size_bytes": response_size_bytes,
        "duration_s": time.monotonic() - start,
    }

    if status_code not in expected:
        return {
            "type": "http_check",
            "passed": False,
            "reason": f"status {status_code} not in {expected}",
            "details": details,
        }

    if require_nonempty_body and response_size_bytes == 0:
        return {
            "type": "http_check",
            "passed": False,
            "reason": "empty body (zero-bytes trap)",
            "details": {**details, "failure_kind": "CONTENT_MISSING"},
        }

    if content_check:
        # Mark that content matching was performed so callers' verify-
        # quality heuristics can count this as functional smoke.
        details["content_check_performed"] = True
        body_text = content.decode("utf-8", errors="replace")
        missing = [needle for needle in content_check if needle not in body_text]
        if missing:
            return {
                "type": "http_check",
                "passed": False,
                "reason": f"missing content: {missing}",
                "details": {**details, "missing_content": missing},
            }

    return {"type": "http_check", "passed": True, "details": details}


def check_logs(
    handle: RuntimeHandle,
    *,
    expected_patterns: list[str],
    tail: int = 500,
) -> CheckResult:
    """Grep instance logs for required regex patterns. Passes if all match."""
    if not isinstance(expected_patterns, list):
        return {
            "type": "log_check",
            "passed": False,
            "reason": (
                f"check_logs: expected_patterns must be a list[str], "
                f"got {type(expected_patterns).__name__}"
            ),
            "details": {},
        }
    if not expected_patterns:
        return {
            "type": "log_check",
            "passed": True,
            "details": {"tail": tail, "patterns": 0},
        }

    combined = handle.logs(tail=tail)
    if not combined:
        return {
            "type": "log_check",
            "passed": False,
            "details": {
                "tail": tail,
                "error": "no logs available (fetch failed or empty)",
            },
        }

    # ReDoS guard: reject patterns with nested quantifiers or excessive
    # length that could cause catastrophic backtracking on large logs.
    _dangerous_re = re.compile(
        r"[+*]{2,}"
        r"|\(\?[^)]*\+"
        r"|\([^)]*[+*]\)[+*]"
    )
    missing: list[str] = []
    for pattern in expected_patterns:
        try:
            if _dangerous_re.search(pattern) or len(pattern) > 500:
                # Literal fallback for risky or excessively long patterns.
                matched = pattern in combined
            else:
                matched = bool(re.search(pattern, combined))
            if not matched:
                missing.append(pattern)
        except re.error as exc:
            return {
                "type": "log_check",
                "passed": False,
                "reason": f"invalid regex {pattern!r}: {exc}",
                "details": {"pattern": pattern},
            }
    if missing:
        return {
            "type": "log_check",
            "passed": False,
            "reason": f"log patterns not found: {missing}",
            "details": {"missing_patterns": missing, "log_chars": len(combined)},
        }
    return {
        "type": "log_check",
        "passed": True,
        "details": {
            "patterns_matched": len(expected_patterns),
            "log_chars": len(combined),
        },
    }


def check_http_request(
    *,
    host_ip: str,
    host_port: int,
    path: str = "/",
    method: str = "POST",
    request_body: str,
    field_name: str = "search",
    form_encoded: bool = True,
    headers: dict[str, str] | None = None,
    expected_status: list[int] | int = 200,
    expected_response_contains: str = "",
    timeout_seconds: float = 15.0,
    hooks: VerifyHooks = _NO_HOOKS,
) -> CheckResult:
    """Functional HTTP request probe.

    Sends a request carrying a body / params and asserts the response
    contains an expected output marker — functional proof, where
    ``http_check`` is only liveness proof. ``form_encoded=True``
    (default) sends ``field_name=request_body`` form-urlencoded (as
    query params for GET); ``form_encoded=False`` sends the raw body
    as text/plain.
    """
    for _str_field, _str_val in (
        ("method", method),
        ("path", path),
        ("field_name", field_name),
    ):
        if not isinstance(_str_val, str):
            return {
                "type": "http_request_check",
                "passed": False,
                "reason": (
                    f"check_http_request: {_str_field} must be str, "
                    f"got {type(_str_val).__name__}"
                ),
                "details": {},
            }
    if method.upper() not in _ALLOWED_METHODS:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": f"method {method!r} not allowed",
            "details": {"method": method},
        }
    host_ip_reason = assert_local_host_ip(host_ip)
    if host_ip_reason is not None:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": host_ip_reason,
            "details": {"host_ip": host_ip, "host_port": host_port},
        }
    if not isinstance(request_body, str):
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": (
                f"check_http_request: request_body must be str, "
                f"got {type(request_body).__name__}"
            ),
            "details": {},
        }
    if not request_body:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": "request_body is required",
            "details": {},
        }
    if not isinstance(expected_response_contains, str):
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": (
                f"check_http_request: expected_response_contains must be str, "
                f"got {type(expected_response_contains).__name__}"
            ),
            "details": {},
        }
    if not expected_response_contains:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": "expected_response_contains is required (the expected response marker)",
            "details": {},
        }
    if headers is not None and not isinstance(headers, dict):
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": (
                f"check_http_request: headers must be a dict, "
                f"got {type(headers).__name__}"
            ),
            "details": {},
        }

    if not isinstance(expected_status, (int, list)):
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": (
                f"check_http_request: expected_status must be int or list[int], "
                f"got {type(expected_status).__name__}"
            ),
            "details": {},
        }
    expected = (
        list(expected_status)
        if isinstance(expected_status, list)
        else [int(expected_status)]
    )
    url = _url_for(host_ip, host_port, path)
    req_headers: dict[str, str] = {"User-Agent": "raptor-env-verify/0.1"}
    if headers:
        req_headers.update(headers)

    request_path = path
    body: bytes | None = None
    if method.upper() == "GET":
        if form_encoded:
            sep = "&" if "?" in path else "?"
            request_path = (
                path + sep
                + urllib.parse.urlencode({field_name: request_body})
            )
    elif form_encoded:
        req_headers.setdefault("Content-Type",
                               "application/x-www-form-urlencoded")
        body = urllib.parse.urlencode({field_name: request_body}).encode()
    else:
        req_headers.setdefault("Content-Type", "text/plain")
        body = request_body.encode("utf-8")

    start = time.monotonic()
    try:
        status_code, content = _http_exchange(
            host_ip=host_ip, host_port=host_port,
            method=method.upper(), path=request_path,
            headers=req_headers, body=body,
            timeout_seconds=timeout_seconds,
        )
    except TimeoutError:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": f"timeout after {timeout_seconds}s",
            "details": {"url": url, "duration_s": time.monotonic() - start},
        }
    except (OSError, http.client.HTTPException) as exc:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": f"connection error: {exc}",
            "details": {"url": url, "error": str(exc)[:400]},
        }

    body_text = content.decode("utf-8", errors="replace")
    details: dict[str, Any] = {
        "url": url,
        "method": method.upper(),
        "actual_status": status_code,
        "expected_status": expected,
        "response_size_bytes": len(content),
        "duration_s": time.monotonic() - start,
        "expected_response_contains": expected_response_contains,
    }

    def _hint(failure_kind: str) -> dict[str, str]:
        if hooks.http_request_hint is None:
            return {}
        hint = hooks.http_request_hint(
            status_code=status_code,
            body_text=body_text,
            response_size=len(content),
            failure_kind=failure_kind,
        )
        return {"hint": hint} if hint else {}

    if status_code not in expected:
        # Response tails often echo exploit-confirmation output —
        # sanitize before they reach any LLM-facing channel.
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": f"status {status_code} not in {expected}",
            "details": {
                **details,
                "response_tail": hooks.sanitize(body_text[-400:]),
                "response_size_bytes": len(content),
                **_hint("status_mismatch"),
            },
        }
    if expected_response_contains not in body_text:
        return {
            "type": "http_request_check",
            "passed": False,
            "reason": (
                f"response missing expected response marker {expected_response_contains!r}"
            ),
            "details": {
                **details,
                "response_tail": hooks.sanitize(body_text[-400:]),
                "response_size_bytes": len(content),
                **_hint("marker_absent"),
            },
        }
    return {
        "type": "http_request_check",
        "passed": True,
        "details": details,
    }


def check_tcp_probe(
    *,
    host_ip: str,
    host_port: int,
    send_text: str = "",
    send_hex: str = "",
    expected_response_contains: str = "",
    expected_response_hex: str = "",
    read_bytes: int = 4096,
    timeout_seconds: float = 5.0,
    tls: bool = False,
    hooks: VerifyHooks = _NO_HOOKS,
) -> CheckResult:
    """Functional raw-TCP service probe (banner grab / protocol ping).

    Opens a TCP socket, optionally sends ``send_text`` (or
    ``send_hex``), reads up to ``read_bytes``, and asserts the response
    contains the text marker (or the hex marker as a byte substring).
    Confirms a non-HTTP service (Redis, MySQL, SSH, SMTP, Postgres,
    raw binary protocols) is up and responding without needing an
    in-instance client tool.

    Payload: at most one of ``send_text`` / ``send_hex``; both empty =
    banner-grab. Marker: exactly one of ``expected_response_contains``
    / ``expected_response_hex`` is required.
    """
    host_ip_reason = assert_local_host_ip(host_ip)
    if host_ip_reason is not None:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": host_ip_reason,
            "details": {"host_ip": host_ip, "host_port": host_port},
        }
    for _str_field, _str_val in (
        ("expected_response_contains", expected_response_contains),
        ("expected_response_hex", expected_response_hex),
        ("send_text", send_text),
        ("send_hex", send_hex),
    ):
        if not isinstance(_str_val, str):
            return {
                "type": "tcp_probe_check",
                "passed": False,
                "reason": (
                    f"check_tcp_probe: {_str_field} must be str, "
                    f"got {type(_str_val).__name__}"
                ),
                "details": {},
            }
    has_text = bool(send_text)
    has_hex = bool(send_hex)
    if has_text and has_hex:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": "set at most one of send_text or send_hex",
            "details": {},
        }
    has_marker_text = bool(expected_response_contains)
    has_marker_hex = bool(expected_response_hex)
    # Both-empty rejected: a pure banner-grab requires at least one marker.
    # Use expected_response_contains=' ' for minimal assertion.
    if has_marker_text == has_marker_hex:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": (
                "exactly one of expected_response_contains or "
                "expected_response_hex is required (the expected response marker)"
            ),
            "details": {},
        }

    try:
        send_bytes = bytes.fromhex(send_hex) if has_hex else send_text.encode("utf-8")
    except ValueError as exc:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": f"send_hex is not valid hex: {exc}",
            "details": {"send_hex": send_hex[:80]},
        }

    if not isinstance(timeout_seconds, (int, float)):
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": (
                f"check_tcp_probe: timeout_seconds must be int or float, "
                f"got {type(timeout_seconds).__name__}"
            ),
            "details": {},
        }
    if not isinstance(read_bytes, int):
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": (
                f"check_tcp_probe: read_bytes must be int, "
                f"got {type(read_bytes).__name__}"
            ),
            "details": {},
        }
    if not isinstance(tls, bool):
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": (
                f"check_tcp_probe: tls must be bool, "
                f"got {type(tls).__name__} — use true/false, not 'true'/'false'"
            ),
            "details": {},
        }
    if read_bytes <= 0 or read_bytes > 65536:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": f"read_bytes {read_bytes} out of range (1, 65536]",
            "details": {},
        }

    expected_marker = (
        expected_response_contains if has_marker_text else expected_response_hex
    )
    details: dict[str, Any] = {
        "host_port": host_port,
        "payload_size": len(send_bytes),
        "expected_marker": expected_marker,
        "expected_marker_kind": "hex" if has_marker_hex else "text",
        "tls": tls,
    }

    def _hint(failure_kind: str, response_size: int) -> dict[str, str]:
        if hooks.tcp_hint is None:
            return {}
        hint = hooks.tcp_hint(failure_kind=failure_kind,
                              response_size=response_size)
        return {"hint": hint} if hint else {}

    start = time.monotonic()
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        raw_sock = socket.create_connection(
            (host_ip, host_port), timeout=timeout_seconds
        )
        try:
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                sock = ctx.wrap_socket(raw_sock, server_hostname=host_ip)
            else:
                sock = raw_sock
            sock.settimeout(timeout_seconds)
            sock.sendall(send_bytes)
            response = sock.recv(read_bytes)
        finally:
            try:
                if sock is not None:
                    sock.close()
                else:
                    raw_sock.close()
            except OSError:
                pass
    except ConnectionRefusedError:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": "connection refused",
            "details": {
                **details,
                "duration_s": time.monotonic() - start,
                **_hint("connection_refused", 0),
            },
        }
    except TimeoutError:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": f"timeout after {timeout_seconds}s",
            "details": {
                **details,
                "duration_s": time.monotonic() - start,
                **_hint("timeout", 0),
            },
        }
    except ssl.SSLError as exc:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": f"TLS error: {exc}",
            "details": {
                **details,
                "duration_s": time.monotonic() - start,
                **_hint("tls_error", 0),
            },
        }
    except OSError as exc:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": f"socket error: {exc}",
            "details": {**details, "duration_s": time.monotonic() - start},
        }

    duration_s = time.monotonic() - start
    response_size = len(response)
    response_tail_hex = response[:200].hex()
    response_tail_ascii = "".join(
        chr(b) if 32 <= b < 127 else "." for b in response[:200]
    )

    if response_size == 0:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": "service closed connection without responding",
            "details": {
                **details,
                "duration_s": duration_s,
                "response_size_bytes": 0,
                **_hint("empty_response", 0),
            },
        }

    if has_marker_hex:
        try:
            marker_bytes = bytes.fromhex(expected_response_hex)
        except ValueError as exc:
            return {
                "type": "tcp_probe_check",
                "passed": False,
                "reason": f"expected_response_hex is not valid hex: {exc}",
                "details": {
                    **details,
                    "duration_s": duration_s,
                    "response_size_bytes": response_size,
                    "expected_response_hex": expected_response_hex[:80],
                },
            }
        marker_found = marker_bytes in response
    else:
        response_text = response.decode("utf-8", errors="replace")
        marker_found = expected_response_contains in response_text

    # Sanitize the ASCII tail; hex stays (binary digits carry no
    # exploit-confirmation phrasing). Protocol responses confirming
    # payload success often contain command output.
    if not marker_found:
        return {
            "type": "tcp_probe_check",
            "passed": False,
            "reason": (
                f"response missing expected response marker {expected_marker!r}"
            ),
            "details": {
                **details,
                "duration_s": duration_s,
                "response_size_bytes": response_size,
                "response_tail_hex": response_tail_hex,
                "response_tail_ascii": hooks.sanitize(response_tail_ascii),
                **_hint("marker_absent", response_size),
            },
        }

    return {
        "type": "tcp_probe_check",
        "passed": True,
        "details": {
            **details,
            "duration_s": duration_s,
            "response_size_bytes": response_size,
            "response_tail_hex": response_tail_hex,
            "response_tail_ascii": hooks.sanitize(response_tail_ascii),
        },
    }


def check_exec(
    handle: RuntimeHandle,
    *,
    command: str,
    expected_exit: int = 0,
    expected_stdout_contains: str | None = None,
    timeout_seconds: int = 30,
    workdir: str = "",
) -> CheckResult:
    """Run a command inside the environment; pass iff exit + stdout match.

    Passes iff ``exit_code == expected_exit`` AND (when
    ``expected_stdout_contains`` is set) the substring appears in stdout.
    """
    if expected_stdout_contains is not None and not isinstance(
        expected_stdout_contains, str
    ):
        return {
            "type": "exec_check",
            "passed": False,
            "reason": (
                f"check_exec: expected_stdout_contains must be str, "
                f"got {type(expected_stdout_contains).__name__}"
            ),
            "details": {},
        }
    for _exec_field, _exec_val in (("command", command), ("workdir", workdir)):
        if not isinstance(_exec_val, str):
            return {
                "type": "exec_check",
                "passed": False,
                "reason": (
                    f"check_exec: {_exec_field} must be str, "
                    f"got {type(_exec_val).__name__}"
                ),
                "details": {},
            }
    if not isinstance(expected_exit, int):
        return {
            "type": "exec_check",
            "passed": False,
            "reason": (
                f"check_exec: expected_exit must be int, "
                f"got {type(expected_exit).__name__}"
            ),
            "details": {},
        }
    if not isinstance(timeout_seconds, (int, float)):
        return {
            "type": "exec_check",
            "passed": False,
            "reason": (
                f"check_exec: timeout_seconds must be int or float, "
                f"got {type(timeout_seconds).__name__}"
            ),
            "details": {},
        }
    exec_result = handle.exec(
        command,
        timeout_seconds=float(timeout_seconds),
        workdir=workdir,
    )
    details: dict[str, Any] = {
        "command": command,
        "exit_code": exec_result.exit_code,
        "expected_exit": expected_exit,
        "duration_s": exec_result.duration_s,
        "stdout_tail": exec_result.stdout[-400:],
        "stderr_tail": exec_result.stderr[-400:],
    }
    if exec_result.exit_code != expected_exit:
        return {
            "type": "exec_check",
            "passed": False,
            "reason": (
                f"exit_code={exec_result.exit_code} != expected_exit={expected_exit}"
                + (f"; {exec_result.reason}" if exec_result.reason else "")
            ),
            "details": details,
        }
    if (
        expected_stdout_contains is not None
        and expected_stdout_contains not in exec_result.stdout
    ):
        return {
            "type": "exec_check",
            "passed": False,
            "reason": (
                f"stdout missing required substring {expected_stdout_contains!r}"
            ),
            "details": {
                **details,
                "expected_stdout_contains": expected_stdout_contains,
            },
        }
    # Propagate expected_stdout_contains into details on the PASS branch
    # too — version-marker gates downstream inspect it on PASSING checks.
    pass_details: dict[str, Any] = dict(details)
    if expected_stdout_contains is not None:
        pass_details["expected_stdout_contains"] = expected_stdout_contains
    return {
        "type": "exec_check",
        "passed": True,
        "details": pass_details,
    }


def stability_wait(
    handle: RuntimeHandle,
    *,
    wait_seconds: int,
    hooks: VerifyHooks = _NO_HOOKS,
) -> CheckResult:
    """Sleep ``wait_seconds`` then re-check instance status.

    Passes iff the instance is still running after the wait. Catches
    slow-boot apps that would 200 briefly then crash-loop.
    """
    if wait_seconds < 0 or wait_seconds > 300:
        return {
            "type": "stability_wait",
            "passed": False,
            "reason": f"wait_seconds {wait_seconds} out of range [0, 300]",
            "details": {},
        }
    time.sleep(wait_seconds)
    status = check_container_status(handle, hooks=hooks)
    return {
        "type": "stability_wait",
        "passed": status["passed"],
        "reason": status.get("reason"),
        "details": {"wait_seconds": wait_seconds, "post_status": status["details"]},
    }


# ── plan utilities ────────────────────────────────────────────────────

HTTP_KEY_ALIASES: dict[str, str] = {
    "expect_status": "expected_status",
    "expectedStatus": "expected_status",
    "expected_statuses": "expected_status",
    "require_body": "require_nonempty_body",
    "body": "content_check",
    "timeout": "timeout_seconds",
    "timeout_s": "timeout_seconds",
}

LOG_KEY_ALIASES: dict[str, str] = {
    "patterns": "expected_patterns",
    "expectedPatterns": "expected_patterns",
    "log_patterns": "expected_patterns",
}

WAIT_KEY_ALIASES: dict[str, str] = {
    "seconds": "wait_seconds",
    "wait": "wait_seconds",
    "wait_s": "wait_seconds",
}

EXEC_KEY_ALIASES: dict[str, str] = {
    "cmd": "command",
    "exit_code": "expected_exit",
    "expected_exit_code": "expected_exit",
    "stdout_contains": "expected_stdout_contains",
    "expected_stdout": "expected_stdout_contains",
    "timeout": "timeout_seconds",
    "timeout_s": "timeout_seconds",
}

HTTP_REQUEST_KEY_ALIASES: dict[str, str] = {
    "expect_status": "expected_status",
    "expectedStatus": "expected_status",
    "response_contains": "expected_response_contains",
    "expected_body_contains": "expected_response_contains",
    "marker": "expected_response_contains",
    "key": "field_name",
    "param": "field_name",
    "payload": "request_body",
    "data": "request_body",
    "body": "request_body",
    "form": "form_encoded",
    "as_form": "form_encoded",
    "timeout": "timeout_seconds",
    "timeout_s": "timeout_seconds",
}

TCP_PROBE_KEY_ALIASES: dict[str, str] = {
    # Plans commonly say host= — a synonym for host_ip. Aliased here,
    # never in the signature.
    "host": "host_ip",
    "port": "host_port",
    "port_target": "host_port",
    "data": "send_text",
    "data_hex": "send_hex",
    "hex": "send_hex",
    "marker": "expected_response_contains",
    "expected": "expected_response_contains",
    "marker_hex": "expected_response_hex",
    "expected_hex": "expected_response_hex",
    "response_contains": "expected_response_contains",
    "timeout": "timeout_seconds",
    "timeout_s": "timeout_seconds",
    "use_tls": "tls",
    "ssl": "tls",
}


def normalize_kwargs(
    kwargs: dict[str, Any], aliases: dict[str, str]
) -> dict[str, Any]:
    """Remap common LLM-synonym keys to the canonical names.

    When both an alias and its canonical key are present (e.g. ``timeout``
    AND ``timeout_seconds``), the canonical key takes precedence and the
    alias is silently dropped.
    """
    out: dict[str, Any] = {}
    for k, v in kwargs.items():
        canonical = aliases.get(k, k)
        # If this key maps to a canonical name that already exists in
        # kwargs directly (not via alias), skip the alias value.
        if canonical != k and canonical in kwargs:
            continue
        out[canonical] = v
    return out


def canonicalize_plan(plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure every verify plan starts with ``container_status``.

    A plan that starts with ``stability_wait`` on an instance that
    exits DURING the wait fails downstream with "no such object";
    forcing ``container_status`` first catches the early-exit before
    burning the wait. Strictly additive — already-canonical plans pass
    through unchanged.
    """
    if plan and isinstance(plan[0], dict) and plan[0].get("type") == "container_status":
        return plan
    return [{"type": "container_status"}, *plan]


def inject_version_assertion(
    plan: list[dict[str, Any]],
    version_literal: str,
    command_pattern: re.Pattern[str] | None,
) -> tuple[list[dict[str, Any]], set[int]]:
    r"""Fill a missing version literal into version-discovery exec_checks.

    For each ``exec_check`` whose ``command`` matches
    ``command_pattern`` AND whose ``expected_stdout_contains`` is
    missing or lacks a version literal (``\d+\.\d+``), overwrite
    ``expected_stdout_contains`` with ``version_literal``.

    Safe by construction: if the deployed version actually differs,
    the check still fails — the assertion the plan forgot was filled
    in, not the result. Returns the (potentially modified) plan + the
    set of injected indices for audit visibility.
    """
    injected: set[int] = set()
    if (
        command_pattern is None
        or not version_literal
        or not re.search(r"\d+\.\d+", version_literal)
    ):
        return plan, injected
    new_plan: list[dict[str, Any]] = []
    for i, step in enumerate(plan):
        if not isinstance(step, dict) or step.get("type") != "exec_check":
            new_plan.append(step)
            continue
        command = step.get("command")
        if not isinstance(command, str) or not command_pattern.search(command):
            new_plan.append(step)
            continue
        existing = step.get("expected_stdout_contains")
        already_has_version = (
            isinstance(existing, str) and re.search(r"\d+\.\d+", existing) is not None
        )
        if already_has_version:
            new_plan.append(step)
            continue
        new_step = dict(step)
        new_step["expected_stdout_contains"] = version_literal
        new_plan.append(new_step)
        injected.add(i)
    return new_plan, injected


def inject_functional_smoke(
    plan: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[int]]:
    """Append benign-input smoke probes when an HTTP plan lacks them.

    Fires only when the plan contains ≥1 ``http_check`` (an HTTP
    service signal) AND doesn't already satisfy the smoke heuristic
    (≥3 active probes, or an http_check with content_check, or ≥2
    distinct http paths). Appends a content-checked GET / and a
    deliberately-404 path — together providing content-check +
    distinct-path coverage. Returns the plan + the APPENDED indices;
    the runner treats those as grading probes, never gates.
    """
    injected: set[int] = set()
    if not plan:
        return plan, injected
    active_count = 0
    distinct_http_paths: set[str] = set()
    has_http_check = False
    has_content_check = False
    for step in plan:
        if not isinstance(step, dict):
            continue
        t = step.get("type")
        if t in ACTIVE_PROBE_TYPES:
            active_count += 1
        if t == "http_check":
            has_http_check = True
            p = step.get("path") or step.get("url")
            if isinstance(p, str) and p:
                distinct_http_paths.add(p)
            if step.get("content_check"):
                has_content_check = True
    if active_count >= 3 or has_content_check or len(distinct_http_paths) >= 2:
        return plan, injected
    if not has_http_check:
        return plan, injected
    new_plan = list(plan)
    start_idx = len(plan)
    smoke_checks: list[dict[str, Any]] = [
        {
            "type": "http_check",
            "path": "/",
            "expected_status": 200,
            "content_check": ["<html"],
        },
        {
            "type": "http_check",
            "path": "/_phase32_smoke_nonexistent_path_404",
            "expected_status": 404,
        },
    ]
    for i, chk in enumerate(smoke_checks):
        new_plan.append(chk)
        injected.add(start_idx + i)
    return new_plan, injected


def default_executors(
    handle: RuntimeHandle,
    hooks: VerifyHooks = _NO_HOOKS,
) -> dict[str, Callable[..., CheckResult]]:
    """The engine's per-type executor table, bound to a handle.

    Callers that need their own seams (patchable module-level check
    functions, extra decoration) pass a same-shaped table to
    :func:`verify_plan` instead. Contracts: ``container_status`` takes
    no kwargs; ``stability_wait`` takes ``wait_seconds``;
    ``tcp_probe_check`` takes explicit ``host_ip``/``host_port`` (the
    engine resolves per-step overrides); everything else receives the
    normalized step kwargs.
    """
    endpoint = handle.endpoint()
    host_ip, host_port = endpoint or ("", 0)
    return {
        "container_status": lambda: check_container_status(handle, hooks=hooks),
        "http_check": lambda **kw: check_http(
            host_ip=host_ip, host_port=host_port, **kw),
        "log_check": lambda **kw: check_logs(handle, **kw),
        "stability_wait": lambda wait_seconds: stability_wait(
            handle, wait_seconds=wait_seconds, hooks=hooks),
        "exec_check": lambda **kw: check_exec(handle, **kw),
        "http_request_check": lambda **kw: check_http_request(
            host_ip=host_ip, host_port=host_port, hooks=hooks, **kw),
        "tcp_probe_check": lambda **kw: check_tcp_probe(hooks=hooks, **kw),
    }


def verify_plan(
    handle: RuntimeHandle | None = None,
    plan: list[dict[str, Any]] | None = None,
    *,
    executors: dict[str, Callable[..., CheckResult]] | None = None,
    endpoint: tuple[str, int] | None = None,
    allowed_tcp_ports: frozenset[int] | set[int] | None = None,
    version_literal: str = "",
    version_cmd_pattern: re.Pattern[str] | None = None,
    hooks: VerifyHooks = _NO_HOOKS,
) -> CheckResult:
    """Run a check plan against a live environment; stop at first
    fatal failure.

    ``plan`` is a list of check dicts, each with a ``type`` key and the
    kwargs for that check (LLM synonym keys normalized). Executors come
    from ``executors`` or :func:`default_executors` over ``handle``
    (one of the two is required). Returns
    ``{"passed", "results", "reason"}``; when the caller supplied a
    ``quality_warning`` hook and it fires on a passing plan, the
    summary gains ``verify_quality_warning``.

    Plans are untrusted input (LLM-authored, or replayed from on-disk
    spec artifacts), so probe destinations are pinned: a plan-supplied
    ``host_ip`` is DISCARDED for every check type — probes always
    target the endpoint's address, exactly like the HTTP checks. The
    per-step ``host_port`` override on ``tcp_probe_check`` (the
    documented way to probe compose sidecar services) is honored only
    when the port is the endpoint's own port or in
    ``allowed_tcp_ports`` — callers with multi-service surfaces pass
    their published-port set; the default is endpoint-only, so a
    hostile plan cannot aim probe payloads at unrelated host-local or
    private-network services.
    """
    if executors is None:
        if handle is None:
            msg = "verify_plan needs a handle or an executor table"
            raise ValueError(msg)
        executors = default_executors(handle, hooks)
    if not isinstance(plan, list):
        return {
            "passed": False,
            "results": [],
            "reason": (
                f"verify: plan must be a list, got {type(plan).__name__} — "
                "caller may have passed json.dumps(plan) instead of plan"
            ),
        }
    if endpoint is None and handle is not None:
        endpoint = handle.endpoint()
    host_ip, host_port = endpoint or ("", 0)

    plan = canonicalize_plan(plan)
    plan, _injected_indices = inject_version_assertion(
        plan, version_literal, version_cmd_pattern
    )
    plan, _smoke_injected_indices = inject_functional_smoke(plan)
    results: list[CheckResult] = []
    for i, step in enumerate(plan):
        if not isinstance(step, dict):
            return {
                "passed": False,
                "results": results,
                "reason": (
                    f"verify: each plan step must be a dict, got {type(step).__name__}"
                ),
            }
        ctype = step.get("type")
        step_kwargs = {k: v for k, v in step.items() if k != "type"}
        if ctype == "container_status":
            out = executors["container_status"]()
        elif ctype == "http_check":
            http_kwargs = normalize_kwargs(step_kwargs, HTTP_KEY_ALIASES)
            http_kwargs.pop("host_ip", None)
            http_kwargs.pop("host_port", None)
            out = executors["http_check"](**http_kwargs)
        elif ctype == "log_check":
            out = executors["log_check"](
                **normalize_kwargs(step_kwargs, LOG_KEY_ALIASES),
            )
        elif ctype == "stability_wait":
            wait_kwargs = normalize_kwargs(step_kwargs, WAIT_KEY_ALIASES)
            _secs_raw = wait_kwargs.get("wait_seconds", 10)
            if not isinstance(_secs_raw, int):
                out = {
                    "type": "stability_wait",
                    "passed": False,
                    "reason": (
                        f"stability_wait: wait_seconds must be int, "
                        f"got {type(_secs_raw).__name__}"
                    ),
                }
            else:
                out = executors["stability_wait"](wait_seconds=_secs_raw)
        elif ctype == "exec_check":
            exec_kwargs = normalize_kwargs(step_kwargs, EXEC_KEY_ALIASES)
            out = executors["exec_check"](**exec_kwargs)
        elif ctype == "http_request_check":
            payload_kwargs = normalize_kwargs(step_kwargs,
                                              HTTP_REQUEST_KEY_ALIASES)
            payload_kwargs.pop("host_ip", None)
            payload_kwargs.pop("host_port", None)
            out = executors["http_request_check"](**payload_kwargs)
        elif ctype == "tcp_probe_check":
            tcp_kwargs = normalize_kwargs(step_kwargs, TCP_PROBE_KEY_ALIASES)
            # Plan-supplied host_ip is discarded — probes are pinned to
            # the endpoint address (see the docstring's SSRF note).
            tcp_kwargs.pop("host_ip", None)
            _tcp_port_raw = tcp_kwargs.pop("host_port", host_port)
            _port_allowlist = {host_port} | set(allowed_tcp_ports or ())
            _port_allowlist.discard(0)
            if not isinstance(_tcp_port_raw, int):
                out = {
                    "type": "tcp_probe_check",
                    "passed": False,
                    "reason": (
                        f"tcp_probe_check step: host_port must be int, "
                        f"got {type(_tcp_port_raw).__name__}"
                    ),
                }
            elif _tcp_port_raw not in _port_allowlist:
                out = {
                    "type": "tcp_probe_check",
                    "passed": False,
                    "reason": (
                        f"tcp_probe_check step: host_port {_tcp_port_raw} "
                        "is not a published endpoint of this environment "
                        f"(allowed: {sorted(_port_allowlist)})"
                    ),
                }
            else:
                out = executors["tcp_probe_check"](
                    host_ip=host_ip, host_port=_tcp_port_raw,
                    **tcp_kwargs,
                )
        else:
            out = {
                "type": ctype or "unknown",
                "passed": False,
                "reason": f"unknown check type {ctype!r}",
                "details": {},
            }
        # Audit visibility for runtime-injected assertions: analysis can
        # count plan-correct verifies vs runtime-rescued ones.
        if i in _injected_indices and isinstance(out, dict):
            out["expected_stdout_contains_source"] = "runtime_inject"
        if i in _smoke_injected_indices and isinstance(out, dict):
            out["injected_source"] = "phase32_smoke"
        results.append(out)
        if not out["passed"]:
            # Smoke-injected checks are GRADING probes, not gates: they
            # were appended to UPGRADE a passing verify; a failing one
            # must not fail an otherwise-passing plan. Plan-authored
            # checks AND version-assertion injections (wrong version =
            # wrong build) stay fatal.
            if i in _smoke_injected_indices:
                continue
            return {
                "passed": False,
                "results": results,
                "reason": f"{out.get('type')}: {out.get('reason')}",
            }
    summary: CheckResult = {"passed": True, "results": results, "reason": None}
    if hooks.quality_warning is not None:
        quality_warning = hooks.quality_warning(results)
        if quality_warning:
            summary["verify_quality_warning"] = quality_warning
    return summary
