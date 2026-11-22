"""Server-identity gate for the SAGE sidecar's loopback endpoints.

The SAGE REST transport is plain HTTP with client-side request signing
only: the client proves who IT is (Ed25519 attribution), but nothing
proves who the SERVER is. ``/health`` is spoofable, and while the
container is down any same-host process can bind the published
loopback port and serve forged recall rows, flood hint-tier text into
agent context, or harvest proposed memories. The existing layers bound
the damage — mechanical consumers only act on rowmac-verified rows,
sandboxed children are denied all TCP, and the boot payload is
guarded — but the client previously initiated the conversation with
whatever answered the port.

Architecture decision (recorded here; operator docs in
``docs/sage.md``). Real CALLER authentication needs server support the
pinned upstream image does not offer: a shared-token scheme requires
the server to verify tokens, and a unix-socket migration requires the
server to listen on one — both remain upstream asks. What the client
CAN establish without upstream changes is SERVER identity at the
transport's weakest point, the port binding: when a docker container
publishes a loopback port, dockerd's proxy/netfilter holds that
binding for the container's lifetime, so an unprivileged local process
cannot squat it; and an adversary who can run containers or instruct
dockerd is already over this machine's privilege boundary. So before
constructing a client, this gate asks docker which image publishes the
target port and requires it to be the compose-pinned image reference
(the same digest pin that anchors boot-payload trust). No match — port
squatted, container down, docker absent — and SAGE degrades to
unavailable exactly as if the server were unreachable.

Scope and escape hatches:

- Loopback URLs only. A non-loopback URL is an operator-directed
  remote deployment; which process binds a REMOTE port is not
  observable from here and the operator owns that network path.
- ``SAGE_SERVER_TRUSTED=1`` (canonical ``core.config.env_flag``
  spellings) skips the check — the operator's assertion for local
  deployments not managed by the shipped compose file (a hand-run
  server, a podman setup docker cannot see).
- Verdicts are cached for ``_GATE_TTL_SECONDS`` per (host, port,
  service) so hook-heavy pipelines do not shell out per call; the
  re-check on expiry re-covers a container that died mid-session.
- Fail-closed: an unparseable URL, a missing compose pin, a failed /
  timed-out / truncated ``docker ps`` all refuse. Refusal is a
  degrade path (SAGE is purely additive), never an error.

Consumers: ``core.sage.client`` (``is_available`` / ``_get_client``
with service ``"sage"``; the direct-embed path with service
``"ollama"``) and ``libexec/raptor-sage``'s client constructor. The
MCP boot lane keeps its own control (``raptor-sage-mcp-guard``
payload verification); ``raptor-sage-setup`` runs compose itself and
needs no gate.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from core.config import env_flag
from core.container.proc import run_cli
from core.logging import get_logger
from core.security.log_sanitisation import sanitise_for_terminal

logger = get_logger(__name__)

# Verdict lifetime. Long enough that recall/propose bursts cost one
# `docker ps`, short enough that a sidecar dying mid-session is
# noticed before much conversation rides on whatever replaced it.
_GATE_TTL_SECONDS = 60.0

_DOCKER_PS_TIMEOUT = 10.0

_LOOPBACK_HOSTS = frozenset({"localhost", "::1"})

_cache: dict[tuple[str, int, str], tuple[bool, float]] = {}
_cache_lock = threading.Lock()
_warned: set[tuple[str, int, str]] = set()


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK_HOSTS or host.startswith("127.")


def compose_pinned_image(service: str) -> str | None:
    """The image reference the shipped compose file pins for *service*.

    Minimal line scan over ``core/sage/docker-compose.yml`` rather
    than a yaml dependency (optional-dep doctrine): track the
    top-level section, remember which 2-space-indented key under
    ``services:`` we are in, and return that service's ``image:``
    value. The compose file is repo-tracked operator-authored
    configuration — the pin read here is the same digest reference the
    boot-payload trust story is anchored on. None when the file or the
    service's image line cannot be found (callers refuse).
    """
    try:
        text = (
            Path(__file__).resolve().parent / "docker-compose.yml"
        ).read_text(encoding="utf-8")
    except OSError:
        return None
    section: str | None = None
    service_key: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            section = stripped[:-1]
            service_key = None
            continue
        if section != "services":
            continue
        if indent == 2 and stripped.endswith(":"):
            service_key = stripped[:-1]
            continue
        if service_key == service and stripped.startswith("image:"):
            ref = stripped[len("image:"):].strip().strip("\"'")
            return ref or None
    return None


def _image_vouches(line: str, pinned: str) -> bool:
    """Whether one ``docker ps`` image field satisfies the *pinned* ref.

    Exact match first; because docker may normalise the creation-time
    reference, a digest-pinned ref also accepts any field carrying the
    same digest, or the bare ``repo:tag`` form of the pin. Every
    accepted form still comes verbatim from the compose pin — nothing
    attacker-nameable matches without docker control, which is over
    the privilege boundary this gate defends.
    """
    line = line.strip()
    if not line:
        return False
    if line == pinned:
        return True
    repo_tag, _, digest = pinned.partition("@")
    if digest:
        if digest in line:
            return True
        if line == repo_tag:
            return True
    return False


def _docker_binding(port: int, service: str) -> tuple[bool, str]:
    """(verdict, reason) for "the compose-pinned *service* image
    publishes loopback *port* right now". Refuses on any uncertainty:
    no compose pin, docker missing or failing, truncated output."""
    pinned = compose_pinned_image(service)
    if not pinned:
        return False, (
            f"no image pin for service {service!r} in "
            f"core/sage/docker-compose.yml"
        )
    outcome = run_cli(
        ["docker", "ps", "--filter", f"publish={port}",
         "--format", "{{.Image}}"],
        timeout=_DOCKER_PS_TIMEOUT,
    )
    if outcome.timed_out:
        return False, "docker ps timed out"
    if outcome.returncode != 0:
        # command_not_found:/os_error: prefixes land in stderr.
        return False, (
            f"docker ps failed: "
            f"{sanitise_for_terminal(outcome.stderr.strip(), max_len=200)}"
        )
    if outcome.truncated:
        return False, "docker ps output truncated"
    images = [ln.strip() for ln in outcome.stdout.splitlines() if ln.strip()]
    if any(_image_vouches(ln, pinned) for ln in images):
        return True, "pinned image publishes the port"
    if images:
        shown = sanitise_for_terminal(", ".join(images), max_len=200)
        return False, (
            f"port {port} is published by {shown!r}, not the pinned "
            f"{service!r} image"
        )
    return False, f"no docker container publishes port {port}"


def _warn_once(key: tuple[str, int, str], reason: str) -> None:
    if key in _warned:
        logger.debug("SAGE server-identity gate refused %s: %s", key, reason)
        return
    _warned.add(key)
    host, port, service = key
    logger.warning(
        "SAGE server identity unverified for %s on %s:%d — %s. Refusing "
        "to talk to it: with the container down, any same-host process "
        "can squat the loopback port and serve forged memories. SAGE "
        "degrades to unavailable. Remedies: start the sidecar "
        "(libexec/raptor-sage-setup), or set SAGE_SERVER_TRUSTED=1 to "
        "assert a self-managed local server.",
        service, host, port, reason,
    )


def server_identity_ok(url: str, service: str) -> bool:
    """Whether the server behind loopback *url* is the compose-pinned
    docker *service* (``"sage"`` / ``"ollama"``). See the module
    docstring for the trust argument, bypasses, and caching. Never
    raises — refusal is the caller's degrade path."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        host = None
        port = None
    if not host:
        _warn_once(("", 0, service), f"unparseable server URL for {service!r}")
        return False
    if not _is_loopback(host):
        # Operator-directed remote deployment — the binding of a
        # remote port is not observable from this host.
        return True
    if env_flag("SAGE_SERVER_TRUSTED", False):
        return True
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    key = (host, port, service)
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None and now < hit[1]:
            return hit[0]
    ok, reason = _docker_binding(port, service)
    with _cache_lock:
        _cache[key] = (ok, time.monotonic() + _GATE_TTL_SECONDS)
    if not ok:
        _warn_once(key, reason)
    return ok


__all__ = ["compose_pinned_image", "server_identity_ok"]
