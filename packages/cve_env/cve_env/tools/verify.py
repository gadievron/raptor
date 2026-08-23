"""Verify tool surface — the engine lives in ``core.env.verify``.

The 7-executor verify DAG (container_status / http_check / log_check /
stability_wait / exec_check / http_request_check / tcp_probe_check),
plan canonicalisation, LLM-alias normalization, and the version-
assertion + functional-smoke injectors moved to :mod:`core.env.verify`,
executed through the ``RuntimeHandle`` seam. What stays here is the
agent-facing policy layer:

* the tool signatures (container_id / host_ip / host_port), preserved
  for the agent tools and the test suite's patch seams
  (``_inspect_state``, ``_container_logs_tail``,
  ``_run_in_container.run_in_container``, ``check_container_status``);
* the failure-hint text (classified guidance the agent pivots on);
* exploit-text sanitization of response tails (B-17: verify responses
  often echo exploit-confirmation output);
* the verify-quality warning (success vs verified_partial guidance).

Every ``http_check`` result carries ``response_size_bytes`` — the
zero-bytes-200 trap stays a hard failure. HTTP/TCP probes connect
directly (loopback-only targets; guarded in core against public IPs).
"""

from __future__ import annotations

import time
from typing import Any

from core.env.handle import RuntimeHandle
from core.env.verify import (
    EXEC_KEY_ALIASES as _EXEC_KEY_ALIASES,  # noqa: F401 — test surface
)
from core.env.verify import (
    HTTP_KEY_ALIASES as _HTTP_KEY_ALIASES,  # noqa: F401 — test surface
)
from core.env.verify import (
    HTTP_REQUEST_KEY_ALIASES as _HTTP_REQUEST_KEY_ALIASES,  # noqa: F401
)
from core.env.verify import (
    LOG_KEY_ALIASES as _LOG_KEY_ALIASES,  # noqa: F401 — test surface
)
from core.env.verify import (
    TCP_PROBE_KEY_ALIASES as _TCP_PROBE_KEY_ALIASES,  # noqa: F401
)
from core.env.verify import (
    WAIT_KEY_ALIASES as _WAIT_KEY_ALIASES,  # noqa: F401 — test surface
)
from core.env.verify import (
    VerifyHooks,
    assert_local_host_ip as _assert_local_host_ip,  # noqa: F401 — test surface
    canonicalize_plan as _canonicalize_plan,  # noqa: F401 — test surface
    normalize_kwargs as _normalize_kwargs,  # noqa: F401 — test surface
    verify_plan as _core_verify_plan,
)
from core.env.verify import (
    check_http as _core_check_http,
)
from core.env.verify import (
    check_container_status as _core_check_container_status,
    check_exec as _core_check_exec,
    check_http_request as _core_check_http_request,
    check_logs as _core_check_logs,
    check_tcp_probe as _core_check_tcp_probe,
)
from core.env.verify import (
    inject_functional_smoke as _core_inject_functional_smoke,
    inject_version_assertion as _core_inject_version_assertion,
)

# Used by _inject_version_assertion.
from cve_env.config import VERSION_ASSERTION_CMD_PATTERN
from cve_env.tools import run_in_container as _run_in_container

# The active-vuln check types and the has_functional_smoke heuristic live in
# cve_env.tools._smoke. Re-imported here for back-compat for external callers
# reaching `from cve_env.tools.verify import _ACTIVE_PROBE_TYPES` or
# `has_functional_smoke`.
from cve_env.tools._smoke import (
    _ACTIVE_PROBE_TYPES as _ACTIVE_PROBE_TYPES,
)
from cve_env.tools._smoke import (
    _compute_verify_quality_warning as _compute_verify_quality_warning,
)
from cve_env.tools._smoke import (
    has_functional_smoke as has_functional_smoke,
)
from cve_env.utils.exploit_text_sanitizer import sanitize_exploit_text

CheckResult = dict[str, Any]


# ── module-level substrate seams (kept for patchability) ──────────────


def _inspect_state(container_id: str) -> dict[str, Any]:
    # timeout / missing-binary / OSError all return {"_error": ...} so a
    # docker-inspect failure can never propagate out and break verify chains.
    from core.container.containers import inspect_state

    return inspect_state(container_id)


def _container_logs_tail(container_id: str, max_output_bytes: int = 1024) -> str:
    """Fetch the last ``max_output_bytes`` of ``docker logs``.

    Post-fetch truncation on the combined stdout+stderr output. Returns
    "" on any error. Used to enrich a failed container_status check
    with diagnostic context.
    """
    from core.container.containers import container_logs_tail

    return container_logs_tail(container_id, n=200,
                               max_bytes=max_output_bytes)


def _fetch_logs(container_id: str, tail: int) -> str:
    """Combined logs for ``log_check`` grepping. "" only on fetch
    failure — success with empty logs yields the newline joiner so the
    pattern grep still runs (and reports missing patterns, not a fetch
    error)."""
    from cve_env.utils.run import run_with_timeout

    outcome = run_with_timeout(
        ["docker", "logs", "--tail", str(tail), container_id],
        timeout=30,
    )
    if outcome.timed_out or outcome.returncode is None:
        return ""
    return (outcome.stdout or "") + "\n" + (outcome.stderr or "")


class _ToolHandle(RuntimeHandle):
    """Adapter binding the tool-signature world (bare container_id +
    this module's patchable seams) to the core RuntimeHandle interface."""

    tier = "docker"

    def __init__(self, container_id: str,
                 host_ip: str = "", host_port: int = 0) -> None:
        self.container_id = container_id
        self.host_ip = host_ip
        self.host_port = int(host_port or 0)

    def endpoint(self) -> tuple[str, int] | None:
        if not self.host_port:
            return None
        return (self.host_ip, self.host_port)

    def state(self) -> dict[str, Any]:
        return _inspect_state(self.container_id)

    def logs(self, tail: int = 500) -> str:
        return _fetch_logs(self.container_id, tail)

    def exec(self, command: str, *, timeout_seconds: float = 30.0,
             workdir: str = ""):
        return _run_in_container.run_in_container(
            container_id=self.container_id,
            command=command,
            timeout_seconds=timeout_seconds,
            workdir=workdir,
        )

    def teardown(self) -> None:
        from cve_env.tools.docker_run import docker_stop

        docker_stop(self.container_id)


# ── failure-hint policy (agent guidance text) ─────────────────────────


def _container_status_failure_hint(state: dict[str, Any], logs_tail: str) -> str:
    """Classify why a container exited / failed to start.

    Common patterns — port conflicts, missing env vars, missing apt
    packages, OOM kills, ENTRYPOINT crashes.
    """
    exit_code = state.get("ExitCode", 0)
    oom = bool(state.get("OOMKilled"))
    if oom or exit_code == 137:
        return (
            "OOM-killed; container exceeded memory. Reduce workload, set "
            "lower thread/process count, or pick a smaller payload."
        )
    if not logs_tail:
        return (
            "container died with no logs. Likely ENTRYPOINT/CMD ran to "
            "completion immediately — check it points to a long-lived "
            "process (e.g., `nginx -g 'daemon off;'`, `apache2ctl -D "
            "FOREGROUND`, `php-fpm --nodaemonize`)."
        )
    sl = logs_tail.lower()
    if "address already in use" in sl or "bind: address already in use" in sl:
        return (
            "port conflict — host port already bound. Retry "
            "docker_run with port_binding=retry_ephemeral patch."
        )
    if "permission denied" in sl:
        return (
            "permission error in container. Common causes: bind-mounted "
            "host file with wrong UID, executable without +x, or app "
            "writing to a read-only path. Inspect logs_tail."
        )
    if any(
        p in sl
        for p in (
            "modulenotfounderror",
            "no module named",
            "cannot find module",
            "command not found",
        )
    ) or ("package" in sl and "not installed" in sl):
        return (
            "missing language deps. Add to install_steps "
            "(pip install / npm install / apt-get install) and rebuild."
        )
    if "no such file or directory" in sl:
        return (
            "missing file at startup — likely a config file the app expects. "
            "COPY it via dockerfile_gen(copy_ops=...) or generate it via "
            "an install_step."
        )
    if any(
        p in sl
        for p in (
            "database connection",
            "connection refused",
            "could not connect",
            "mysql",
            "postgres",
            "redis",
        )
    ) and any(
        w in sl
        for w in ("refused", "timed out", "timeout", "connection failed", "could not connect")
    ):
        return (
            "DB-connection failure. Single-container CVEs usually need "
            "an embedded SQLite — or you need docker_compose_up with a "
            "DB sidecar. Check the app's required services."
        )
    if any(
        p in sl
        for p in (
            "fatal error",
            "uncaught exception",
            "panic:",
            "traceback",
            "segmentation fault",
        )
    ):
        return (
            "app crashed at startup; read the traceback in logs_tail and "
            "fix the underlying error (often missing env var like APP_KEY, "
            "DB_URL, SECRET) via dockerfile_gen ENV / install_steps."
        )
    return (
        "container exited with non-zero code. Read logs_tail for the "
        "specific error and decide whether to (a) patch the Dockerfile, "
        "(b) supply env vars, or (c) pick a different base image version."
    )


def _http_request_check_failure_hint(
    *,
    status_code: int,
    body_text: str,
    response_size: int,
    failure_kind: str,
) -> str:
    """Best-guess introspection hint for http_request_check failures.

    The agent often gives up after one failed attempt because the result only
    says "marker absent." This hint describes the SHAPE of what came back, so
    the agent can pivot (alternate marker, different endpoint, encoding fix).
    """
    if failure_kind == "status_mismatch":
        if status_code in (401, 403):
            return "auth required; check if endpoint needs login or CSRF token first"
        if status_code == 404:
            return "endpoint not found; verify the path and HTTP method"
        if status_code == 405:
            return "method not allowed; try a different HTTP method"
        if status_code >= 500:
            return "server error; the request may have crashed the app — check container logs"
        return "unexpected status; verify the endpoint contract"
    # marker_absent
    if response_size == 0:
        return (
            "empty response; endpoint may not exist or returns 204/304 — check the path"
        )
    body_lower = body_text.lower()
    if "<html" in body_lower or "<!doctype" in body_lower:
        return (
            "endpoint reached but the expected marker was not in the response. "
            "Try: a marker that matches the app's actual output for this input, a "
            "different endpoint or field name, a different request encoding, or check "
            "the response for an error message indicating the input was rejected."
        )
    if body_text.lstrip().startswith(("{", "[")):
        return (
            "JSON response without the marker; the input may have been escaped/rejected, "
            "or the marker doesn't match the response field structure"
        )
    return (
        "marker absent; pick a marker that matches the endpoint's expected response "
        "for this input, or verify the field name and path"
    )


def _tcp_probe_check_failure_hint(*, failure_kind: str, response_size: int) -> str:
    """Introspection hint for tcp_probe_check failures.

    Same idea as ``_http_request_check_failure_hint`` but for raw-TCP probes
    where there's no HTTP status code. Failure kinds: ``connection_refused``,
    ``timeout``, ``empty_response``, ``marker_absent``, ``tls_error``.
    """
    if failure_kind == "connection_refused":
        return (
            "port not open; container_status passed but service may have died after "
            "stability_wait — try docker exec ss -tlnp (or netstat -tlnp) to see what "
            "IS listening"
        )
    if failure_kind == "timeout":
        return (
            "connection accepted but service unresponsive; probably wrong protocol or "
            "wrong port — verify the wire format and try alternate ports from CVE refs"
        )
    if failure_kind == "empty_response":
        return (
            "service closed connection without responding; protocol mismatch — verify "
            "the wire format (binary vs text, terminator bytes) and that you're "
            "speaking what the service expects"
        )
    if failure_kind == "tls_error":
        return (
            "TLS handshake error — the remote requires/refuses TLS; flip the tls flag "
            "(true→false or false→true) and retry"
        )
    if failure_kind == "marker_absent":
        if response_size == 0:
            return (
                "service responded but with empty bytes — payload may have been "
                "rejected silently; try a known-valid hello/banner request first"
            )
        return (
            "service responded but not with expected marker; first 200 bytes (hex+ascii) "
            "are logged in details.response_tail — adjust the payload or marker pattern"
        )
    return "unknown tcp probe failure"


# One hooks bundle: the exploit-text sanitizer (B-17) + the hint
# classifiers above + the verify-quality warning.
_HOOKS = VerifyHooks(
    sanitize=lambda text: sanitize_exploit_text(text, max_chars=400),
    status_hint=lambda state, logs_tail: _container_status_failure_hint(
        state, logs_tail),
    http_request_hint=lambda **kw: _http_request_check_failure_hint(**kw),
    tcp_hint=lambda **kw: _tcp_probe_check_failure_hint(**kw),
    quality_warning=lambda results: _compute_verify_quality_warning(results),
)


# ── tool-surface check functions ──────────────────────────────────────


def check_container_status(container_id: str) -> CheckResult:
    """Return ``{passed, status, details}`` for container liveness.

    Passes when ``State.Running == True`` and ``State.Status == "running"``.
    Exited containers with ExitCode=0 are NOT passes -- a long-lived
    service that exited cleanly didn't actually start serving. Failures
    are enriched with ``logs_tail`` + a classified ``hint``.
    """
    return _core_check_container_status(_ToolHandle(container_id),
                                        hooks=_HOOKS)


def check_http(**kwargs: Any) -> CheckResult:
    """HTTP probe with ``response_size_bytes`` recorded; zero-body
    responses fail even on 200. See :func:`core.env.verify.check_http`."""
    return _core_check_http(**kwargs)


def check_logs(
    container_id: str,
    *,
    expected_patterns: list[str],
    tail: int = 500,
) -> CheckResult:
    """Grep container logs for required regex patterns. Passes if all match."""
    return _core_check_logs(
        _ToolHandle(container_id),
        expected_patterns=expected_patterns,
        tail=tail,
    )


def check_http_request(**kwargs: Any) -> CheckResult:
    """Functional HTTP request probe (marker-asserted POST/GET). See
    :func:`core.env.verify.check_http_request`; failure tails are
    exploit-text-sanitized and hint-classified here."""
    return _core_check_http_request(hooks=_HOOKS, **kwargs)


def check_tcp_probe(**kwargs: Any) -> CheckResult:
    """Functional raw-TCP service probe (banner grab / protocol ping).
    See :func:`core.env.verify.check_tcp_probe`; response tails are
    exploit-text-sanitized and hint-classified here."""
    return _core_check_tcp_probe(hooks=_HOOKS, **kwargs)


def check_exec(container_id: str, **kwargs: Any) -> CheckResult:
    """Run a command inside the container; pass iff exit + stdout match.

    Routes through ``run_in_container`` (ownership-gated) so non-HTTP
    vulnerabilities can DECLARE pass from within the verify DAG.
    """
    return _core_check_exec(_ToolHandle(container_id), **kwargs)


def stability_wait(
    container_id: str,
    *,
    wait_seconds: int,
) -> CheckResult:
    """Sleep ``wait_seconds`` then re-check container_status.

    Passes iff the container is still running after the wait. Used to
    catch slow-boot apps that would 200 briefly then crash-loop.
    Composed from this module's seams (``time.sleep`` +
    ``check_container_status``) so both remain patchable here.
    """
    if wait_seconds < 0 or wait_seconds > 300:
        return {
            "type": "stability_wait",
            "passed": False,
            "reason": f"wait_seconds {wait_seconds} out of range [0, 300]",
            "details": {},
        }
    time.sleep(wait_seconds)
    status = check_container_status(container_id)
    return {
        "type": "stability_wait",
        "passed": status["passed"],
        "reason": status.get("reason"),
        "details": {"wait_seconds": wait_seconds, "post_status": status["details"]},
    }


# ── plan-utility shims (import surface preserved) ─────────────────────


def _inject_version_assertion(
    plan: list[dict[str, Any]],
    cve_version: str,
) -> tuple[list[dict[str, Any]], set[int]]:
    """Runtime version-assertion injection — the CVE version literal is
    filled into version-discovery exec_checks that forgot it. See
    :func:`core.env.verify.inject_version_assertion`."""
    return _core_inject_version_assertion(
        plan, cve_version, VERSION_ASSERTION_CMD_PATTERN
    )


def _inject_functional_smoke(
    plan: list[dict[str, Any]],
    host_ip: str,
    host_port: int,
) -> tuple[list[dict[str, Any]], set[int]]:
    """Runtime functional-smoke injection. ``host_ip``/``host_port``
    are accepted for signature compatibility; the appended probes use
    the plan-level endpoint. See
    :func:`core.env.verify.inject_functional_smoke`."""
    del host_ip, host_port
    return _core_inject_functional_smoke(plan)


def _published_run_ports(probed_container_id: str) -> frozenset[int]:
    """Loopback host ports published by THIS run's containers.

    The per-step ``host_port`` override on ``tcp_probe_check`` exists so
    compose stacks / sidecar services (redis, mysql, ...) can be probed
    on their own published ports. The engine pins per-step ports to an
    allowlist; this computes it from exactly the containers this run is
    entitled to probe: the container under verification plus the ids
    this process launched (``docker_run`` / ``docker_compose_up``
    session registry). Scoping by container id — not by label — keeps
    the allowlist per-run under concurrent cve-env runs: the owner
    label is product-global and label values are prompt-threaded, so a
    sibling run's published sidecar ports must never enter this run's
    allowlist. Fails closed: any enumeration failure returns the empty
    set (the primary endpoint port stays allowed engine-side).
    """
    from cve_env.tools.docker_run import OWNER_LABEL, session_container_ids
    from cve_env.utils.run import run_with_timeout

    run_ids = set(session_container_ids())
    if probed_container_id:
        run_ids.add(probed_container_id)
    if not run_ids:
        return frozenset()
    outcome = run_with_timeout(
        [
            "docker", "ps",
            "--filter", f"label={OWNER_LABEL}=cve-env",
            "--format", "{{.ID}}\t{{.Ports}}",
        ],
        timeout=15,
    )
    if outcome.timed_out or outcome.returncode != 0:
        return frozenset()
    import re as _re

    ports: set[int] = set()
    for line in (outcome.stdout or "").splitlines():
        short_id, _, port_text = line.partition("\t")
        short_id = short_id.strip()
        # docker ps prints truncated (12-char) ids; the registry holds
        # full 64-char ids — prefix-match ours, drop everyone else's.
        if not short_id or not any(
            rid.startswith(short_id) or short_id.startswith(rid)
            for rid in run_ids
        ):
            continue
        for match in _re.finditer(r"127\.0\.0\.1:(\d+)->", port_text):
            try:
                ports.add(int(match.group(1)))
            except ValueError:  # pragma: no cover — \d+ always int-parses
                continue
    return frozenset(ports)


def verify(
    *,
    container_id: str,
    host_ip: str,
    host_port: int,
    plan: list[dict[str, Any]],
    cve_version: str = "",
) -> CheckResult:
    """Run a list of checks in order; stop at first failure.

    ``plan`` is a list of check dicts; each has a ``type`` key and the
    kwargs for that check. Returns a ``{"passed", "results", "reason"}``
    summary. Common LLM key aliases are normalized rather than
    hard-rejected; the version-assertion and functional-smoke injectors
    close systematic plan gaps (injected smoke probes grade, never
    gate). Dispatch goes through THIS module's check functions so the
    suite's patch seams keep intercepting.

    Plans are agent-authored (untrusted): the engine pins probe
    addresses to the endpoint and per-step ``tcp_probe_check`` ports to
    the published loopback ports of this run's own containers
    (see :func:`_published_run_ports`).
    """
    executors = {
        "container_status": lambda: check_container_status(container_id),
        "http_check": lambda **kw: check_http(
            host_ip=host_ip, host_port=host_port, **kw),
        "log_check": lambda **kw: check_logs(container_id, **kw),
        "stability_wait": lambda wait_seconds: stability_wait(
            container_id, wait_seconds=wait_seconds),
        "exec_check": lambda **kw: check_exec(container_id, **kw),
        "http_request_check": lambda **kw: check_http_request(
            host_ip=host_ip, host_port=host_port, **kw),
        "tcp_probe_check": lambda **kw: check_tcp_probe(**kw),
    }
    return _core_verify_plan(
        plan=plan,
        executors=executors,
        endpoint=(host_ip, host_port),
        allowed_tcp_ports=_published_run_ports(container_id),
        version_literal=cve_version,
        version_cmd_pattern=VERSION_ASSERTION_CMD_PATTERN,
        hooks=_HOOKS,
    )
