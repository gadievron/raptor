"""image_resolve: registry probe with arch-matching (planner layer).

Given ``(product, version, host_arch)``, try a small set of common tag
conventions (official ``<product>:<version>``, ``vulhub/<product>:<version>``,
``library/<product>``) via ``docker manifest inspect`` and return the
first digest-pinned reference that advertises a matching platform.

The probe mechanics (candidate cascade, manifest inspect + failure
classification, digest pinning, host-platform pick) live in
:mod:`core.container.registry`. This module keeps the agent-facing
policy: per-CVE rate-limit/arch budgets and cooldowns, the per-call
wall budget, and the pivot ``next_step_hint`` text.

Pagination, the LLM gap filler, and the multi-registry fallback chain
are intentionally omitted. The agent can drive broader search by calling
this with different inputs.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field

from core.container.registry import (
    _TRANSIENT_PATTERNS,  # noqa: F401 — pattern-parity test imports this
    InspectClass,
    candidate_refs,
    filter_denied_registries,
    pick_digest_for_host,
    pin_digest_ref,
    probe_manifest,
    probe_manifest_once,
    worst_inspect_class,
)

# Per-CVE state surface lives in `_image_resolve_state`. All counters,
# cooldown bools, thresholds, and the reset / bump / take helpers are
# imported as `_state.*`. image_resolve.py contains zero
# `global _RATE_LIMIT_*` / `global _TRANSPORT_*` / `global _ARCH_*`
# statements (locked by
# tests/unit/test_refactor_specific.py::test_image_resolve_uses_state_via_helpers).
from cve_env.config import get_image_resolve_budget_s
from cve_env.tools import _image_resolve_state as _state

# Back-compat re-exports — agent.loop imports reset_rate_limit_budget from
# this module; tests import the bump/take helpers directly from
# image_resolve. Re-exported here to preserve the public surface.
from cve_env.tools._image_resolve_state import (
    _RESET_GLOBALS as _RESET_GLOBALS,
)
from cve_env.tools._image_resolve_state import (
    _bump_arch_incompatible_total as _bump_arch_incompatible_total,
)
from cve_env.tools._image_resolve_state import (
    _bump_rate_limit_total as _bump_rate_limit_total,
)
from cve_env.tools._image_resolve_state import (
    _take_rate_limit_cooldown as _take_rate_limit_cooldown,
)
from cve_env.tools._image_resolve_state import (
    _take_transport_cooldown as _take_transport_cooldown,
)
from cve_env.tools._image_resolve_state import (
    reset_rate_limit_budget as reset_rate_limit_budget,
)
logger = logging.getLogger(__name__)



# All per-CVE state lives in cve_env.tools._image_resolve_state. The names
# below are accessed via `_state.<name>` in this module (no `global`
# statements remain):
#
#   _RATE_LIMIT_BUDGET / _RATE_LIMIT_THRESHOLD
#   _RATE_LIMIT_TOTAL  / _RATE_LIMIT_TOTAL_THRESHOLD
#   _RATE_LIMIT_COOLDOWN_DONE / _RATE_LIMIT_COOLDOWN_S
#   _TRANSPORT_COOLDOWN_DONE  / _TRANSPORT_COOLDOWN_S
#   _ARCH_INCOMPATIBLE_TOTAL  / _ARCH_INCOMPATIBLE_THRESHOLD
#
# Helpers (all in `_state`, called as `_state.<helper>()`):
#   bump_arch_incompatible_total / bump_rate_limit_total
#   take_rate_limit_cooldown / take_transport_cooldown
#   record_rate_limit_for_product
#   reset_rate_limit_budget


@dataclass
class ResolveResult:
    ok: bool
    image_ref: str = ""
    digest_pinned_ref: str = ""
    host_arch: str = ""
    decision: str = ""  # 'native' | 'rosetta_ok' | 'arch_incompatible' | 'not_found'
    candidates_tried: list[str] = field(default_factory=list)
    reason: str = ""
    reason_class: str = "ok"  # ok / not_found / rate_limited / transport / auth
    next_step_hint: str = ""  # concrete next action on failure


def _image_resolve_next_step_hint(decision: str, product: str) -> str:
    """Pivot guidance based on resolve decision."""
    if decision in ("native", "rosetta_ok"):
        return ""
    if decision == "rate_limited_persistent":
        return (
            f"DO NOT call image_resolve(product={product!r}) again — budget "
            "exhausted. Pivot to image_resolve(product='ubuntu', version='22.04') "
            "+ install platform manually in install_steps"
        )
    if decision == "arch_incompatible":
        return (
            "host arch (arm64) doesn't match any image platform. PIVOT: "
            "(1) call source_build with the upstream GitHub repo (many "
            "vulns build clean on arm64 even when amd64-only vulhub images "
            "don't run), OR (2) retry docker_run with platform='linux/amd64' "
            "if Rosetta is available"
        )
    if decision == "arch_incompatible_persistent":
        return (
            "DO NOT call image_resolve again — multiple products in this CVE "
            "lack arm64 images. Either call source_build with the upstream "
            "repo (arm64 source builds often work even when prebuilt images "
            "don't) OR call give_up(reason=arch_incompatible) now"
        )
    # decision == "not_found" (covers default/ambiguous failures)
    return (
        "no candidate image resolved. PIVOT: (1) source_build with the "
        "upstream GitHub repo to build from scratch, OR (2) compose "
        "FROM ubuntu/debian/alpine + install the platform manually via "
        "dockerfile_gen install_steps + copy_ops"
    )


def _candidate_refs(product: str, version: str) -> list[str]:
    """Mirrors-first candidate cascade (core), filtered by the
    ``CVE_ENV_DENY_REGISTRY`` operator denylist."""
    return _filter_denied_registries(candidate_refs(product, version))


def _filter_denied_registries(candidates: list[str]) -> list[str]:
    """Filter the cascade by ``CVE_ENV_DENY_REGISTRY`` env var (if set).

    Used by experimental benches that want to test what the engine does
    when its highest-success registries are unavailable. Comma-separated
    registry tokens, URL-ish forms accepted; ``docker.io`` also drops
    bare-name and ``library/*`` refs. No-op when unset/empty (default).
    Normalisation + matching live in :mod:`core.container.registry`.
    """
    return filter_denied_registries(
        candidates, os.environ.get("CVE_ENV_DENY_REGISTRY", "")
    )


# Mechanics aliases — the module-level names remain the test/patch seams.
_worst_inspect_class = worst_inspect_class


def _inspect_ref_once(
    image_ref: str, *, timeout_seconds: int
) -> tuple[tuple[list[str], dict[str, str]] | None, InspectClass, str]:
    """Single inspect attempt — see core.container.registry.probe_manifest_once."""
    return probe_manifest_once(image_ref, timeout_seconds=timeout_seconds)


def _inspect_ref(
    image_ref: str,
    *,
    timeout_seconds: int = 30,
    enable_retry: bool = True,
) -> tuple[tuple[list[str], dict[str, str]] | None, InspectClass]:
    """Inspect a manifest with one retry on transient failure (core).

    The retry backoff sleeps through THIS module's ``time`` reference so
    the test suite's ``image_resolve.time.sleep`` patches keep metering
    the waits.
    """
    return probe_manifest(
        image_ref,
        timeout_seconds=timeout_seconds,
        enable_retry=enable_retry,
        sleep=lambda s: time.sleep(s),
    )


_pin_digest_ref = pin_digest_ref


def _attempt_resolve_retry_loop(
    *,
    candidates: list[str],
    host_platform: str,
    rosetta_available: bool,
    host_arch: str,
    tried_so_far: list[str],
    success_log_label: str,
    product_key: str,
    deadline: float | None = None,
) -> tuple[ResolveResult | None, list[str], set[InspectClass]]:
    """Retry-loop body shared by the rate-limit cooldown and the transport
    cooldown paths.

    Returns one of three outcomes plus retry data:

    - ``(ResolveResult(ok=True), retry_tried, retry_seen)`` — a candidate's
      manifest had a host-compatible platform; caller returns this directly.
    - ``(ResolveResult(ok=False, decision='arch_incompatible'), retry_tried,
      retry_seen)`` — at least one candidate returned a manifest but no
      host/rosetta-compatible platform was found; caller returns this directly.
    - ``(None, retry_tried, retry_seen)`` — every candidate failed manifest
      fetch (no manifest returned). Caller recomputes ``final_class`` from
      ``retry_seen`` and falls through to existing failure paths.

    ``success_log_label`` is interpolated into the user-facing print
    statement (e.g. ``"cooldown retry"`` or ``"transport-cooldown retry"``).
    """
    retry_tried: list[str] = []
    retry_seen: set[InspectClass] = set()
    retry_last_candidate = ""
    retry_last_platforms: list[str] = []
    for cand in candidates:
        # Stop the retry cascade once the per-call budget is spent.
        if deadline is not None and time.monotonic() > deadline:
            break
        retry_tried.append(cand)
        result, klass = _inspect_ref(cand)
        retry_seen.add(klass)
        if result is None:
            continue
        platforms, per_arch_digests = result
        retry_last_candidate = cand
        retry_last_platforms = platforms
        pick = _pick_digest_for_host(
            per_arch_digests,
            host_platform=host_platform,
            rosetta_available=rosetta_available,
        )
        if pick is None:
            continue
        chosen_platform, digest = pick
        pinned = _pin_digest_ref(cand, digest)
        decision = "native" if chosen_platform == host_platform else "rosetta_ok"
        print(  # noqa: T201
            f"⓵ image_resolve: {success_log_label} succeeded → {pinned}",
            file=sys.stderr,
            flush=True,
        )
        return (
            ResolveResult(
                ok=True,
                image_ref=cand,
                digest_pinned_ref=pinned,
                host_arch=host_arch,
                decision=decision,
                candidates_tried=tried_so_far + retry_tried,
                reason_class="ok",
            ),
            retry_tried,
            retry_seen,
        )
    if retry_last_candidate:
        return (
            ResolveResult(
                ok=False,
                image_ref=retry_last_candidate,
                host_arch=host_arch,
                decision="arch_incompatible",
                candidates_tried=tried_so_far + retry_tried,
                reason=(
                    f"{success_log_label} returned manifests but no native/"
                    f"rosetta-compatible platform; host={host_platform} "
                    f"image={retry_last_platforms}"
                ),
                reason_class="not_found",
                next_step_hint=_image_resolve_next_step_hint(
                    "arch_incompatible", product_key
                ),
            ),
            retry_tried,
            retry_seen,
        )
    return None, retry_tried, retry_seen


_pick_digest_for_host = pick_digest_for_host


def image_resolve(
    *,
    product: str,
    version: str,
    host_arch: str,
    rosetta_available: bool = False,
) -> ResolveResult:
    """Probe candidate registries for an arch-compatible digest-pinned ref."""
    candidates = _candidate_refs(product, version)
    if not candidates:
        return ResolveResult(
            ok=False,
            decision="not_found",
            reason="empty product/version",
            reason_class="not_found",
        )

    # Short-circuit after 2 rate_limited resolves for the same product. The
    # agent should pivot to a generic base + manual install rather than burn
    # turns on more version probes.
    # ALSO short-circuit after _RATE_LIMIT_TOTAL_THRESHOLD cumulative
    # rate_limited probes across ANY products in this CVE — Docker Hub anon
    # limit is per-IP not per-product, so pivoting from ubuntu→alpine→tomcat
    # won't help.
    product_key = product.strip().lower()

    # Cumulative arch_incompatible short-circuit. After 2 different products
    # have already failed arch_incompatible in this CVE, the next
    # image_resolve call returns immediately with a pivot hint — every
    # additional probe is wasted turns + cost per call.
    if _state._ARCH_INCOMPATIBLE_TOTAL >= _state._ARCH_INCOMPATIBLE_THRESHOLD:
        return ResolveResult(
            ok=False,
            host_arch=host_arch,
            decision="arch_incompatible_persistent",
            candidates_tried=[],
            reason=(
                f"already burned {_state._ARCH_INCOMPATIBLE_TOTAL} arch_incompatible "
                f"image_resolve calls across products in this CVE — host "
                f"arch ({host_arch}) cannot run these images. PIVOT NOW: "
                "call source_build with the upstream GitHub repo "
                "(arm64 source builds often work even when prebuilt images "
                "don't), OR call give_up(reason=arch_incompatible)."
            ),
            reason_class="not_found",
            next_step_hint=_image_resolve_next_step_hint(
                "arch_incompatible_persistent", product_key
            ),
        )

    per_product_hit = (
        _state._RATE_LIMIT_BUDGET.get(product_key, 0) >= _state._RATE_LIMIT_THRESHOLD
    )
    cumulative_hit = _state._RATE_LIMIT_TOTAL >= _state._RATE_LIMIT_TOTAL_THRESHOLD
    if per_product_hit or cumulative_hit:
        if cumulative_hit:
            reason_text = (
                f"already burned {_state._RATE_LIMIT_TOTAL} rate_limited probes "
                "across multiple products in this CVE — Docker Hub anonymous "
                "limit is per-IP, NOT per-product. Pivoting between products "
                "will keep failing. PIVOT NOW: use mirror.gcr.io/library/X "
                "(Phase 30 free Google mirror) via "
                "image_resolve(product='mirror.gcr.io/library/<base>') OR "
                "source_build for the host platform OR give_up(no_image)."
            )
        else:
            reason_text = (
                f"already burned {_state._RATE_LIMIT_THRESHOLD} rate_limited probes for "
                f"product={product_key!r}. STOP probing — Docker Hub anonymous "
                "limits don't clear for hours. PIVOT NOW: use a generic base "
                "(ubuntu:22.04 / debian:12 / alpine:3.19) via "
                "image_resolve(product=<generic>) and install the host "
                "platform manually in install_steps "
                "(apt-get install apache2 libapache2-mod-php for "
                "WordPress/Drupal/Joomla, etc.). Or call source_build for "
                "the host platform."
            )
        return ResolveResult(
            ok=False,
            host_arch=host_arch,
            decision="rate_limited_persistent",
            candidates_tried=[],
            reason=reason_text,
            reason_class="rate_limited",
            next_step_hint=_image_resolve_next_step_hint(
                "rate_limited_persistent", product_key
            ),
        )

    host_platform = (
        f"linux/{host_arch}" if host_arch in {"arm64", "amd64"} else "linux/amd64"
    )

    tried: list[str] = []
    last_platforms: list[str] = []
    last_candidate = ""
    # Track worst transient class across candidates so the agent can
    # distinguish "all probes hit DockerHub rate-limit" from "image truly absent".
    seen_classes: set[InspectClass] = set()

    # Per-call wall budget. A rate-limit/transport storm can make one
    # image_resolve call run ~1430s (10 candidates + a 30s cooldown re-probe of
    # 10 more), alone approaching the bench wall — and the connectivity
    # breaker is suppressed while this tool runs. Stop probing once spent; the
    # existing final_class/pivot logic below then returns the right hint.
    budget_s = get_image_resolve_budget_s()
    deadline = time.monotonic() + budget_s if budget_s > 0 else None

    for cand in candidates:
        if deadline is not None and time.monotonic() > deadline:
            break  # per-call budget exhausted; stop probing
        tried.append(cand)
        result, klass = _inspect_ref(cand)
        seen_classes.add(klass)
        if result is None:
            continue
        platforms, per_arch_digests = result
        last_candidate = cand
        last_platforms = platforms

        pick = _pick_digest_for_host(
            per_arch_digests,
            host_platform=host_platform,
            rosetta_available=rosetta_available,
        )
        if pick is None:
            continue  # claimed platforms exist but no arch-matching digest; try next candidate
        chosen_platform, digest = pick
        pinned = _pin_digest_ref(cand, digest)
        decision = "native" if chosen_platform == host_platform else "rosetta_ok"
        return ResolveResult(
            ok=True,
            image_ref=cand,
            digest_pinned_ref=pinned,
            host_arch=host_arch,
            decision=decision,
            candidates_tried=tried,
            reason_class="ok",
        )

    if last_candidate:
        # Found manifests but none matched our arch.
        # Bump CVE-level counter so the next image_resolve call
        # short-circuits if 2+ products fail arch_incompatible.
        _state._bump_arch_incompatible_total()
        return ResolveResult(
            ok=False,
            image_ref=last_candidate,
            digest_pinned_ref="",
            host_arch=host_arch,
            decision="arch_incompatible",
            candidates_tried=tried,
            reason=(
                f"no native/rosetta-compatible platform; "
                f"host={host_platform} image={last_platforms}"
            ),
            reason_class="not_found",
            next_step_hint=_image_resolve_next_step_hint(
                "arch_incompatible", product_key
            ),
        )

    # Pick the most-actionable class for the agent.
    # Prefer transient classes ("retry later" signal) over not_found.
    final_class: InspectClass = _worst_inspect_class(seen_classes)

    # When ALL candidates rate-limited (after alt registries + mirror.gcr.io
    # fallback already exhausted), sleep ~30s and retry the loop ONCE per CVE.
    # Communicates the wait to stderr so users monitoring the run see what's
    # happening.
    if (
        final_class == "rate_limited"
        and (deadline is None or time.monotonic() < deadline)  # per-call budget
        and _state._take_rate_limit_cooldown()
    ):
        cooldown = _state._RATE_LIMIT_COOLDOWN_S
        print(  # noqa: T201 -- intentional user-facing progress message
            f"⓵ image_resolve: all candidates rate-limited; sleeping "
            f"{cooldown}s then retrying alt registries before giving up "
            f"(Phase 37.2 cooldown — once per CVE).",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(cooldown)
        # Call the shared _attempt_resolve_retry_loop.
        retry_result, retry_tried, retry_seen = _attempt_resolve_retry_loop(
            candidates=candidates,
            host_platform=host_platform,
            rosetta_available=rosetta_available,
            host_arch=host_arch,
            tried_so_far=tried,
            success_log_label="cooldown retry",
            product_key=product_key,
            deadline=deadline,
        )
        if retry_result is not None:
            return retry_result
        # All candidates failed manifest fetch — recompute final_class.
        final_class = _worst_inspect_class(retry_seen)
        tried = tried + retry_tried
        if final_class == "rate_limited":
            print(  # noqa: T201
                "⓵ image_resolve: cooldown retry STILL rate-limited; "
                "agent will pivot to source_build / give_up.",
                file=sys.stderr,
                flush=True,
            )

    # When ALL candidates hit transport-class (5xx/timeout/connection-reset)
    # and the rate-limit cooldown was NOT already taken this CVE (would have
    # eaten 30s already), spend ONE cooldown to retry. A transport storm that
    # exhausts DH+mirror.gcr.io+quay+ghcr+mcr can often clear after a short
    # pause + retry.
    if (
        final_class == "transport"
        and (deadline is None or time.monotonic() < deadline)  # per-call budget
        and not _state._RATE_LIMIT_COOLDOWN_DONE  # avoid back-to-back 30s waits
        and _state._take_transport_cooldown()
    ):
        cooldown = _state._TRANSPORT_COOLDOWN_S
        print(  # noqa: T201
            f"⓵ image_resolve: all candidates hit transient transport errors; "
            f"sleeping {cooldown}s then retrying registries before giving up "
            f"(Phase 46.2 cooldown — once per CVE).",
            file=sys.stderr,
            flush=True,
        )
        time.sleep(cooldown)
        # Call the shared _attempt_resolve_retry_loop.
        retry2_result, retry2_tried, retry2_seen = _attempt_resolve_retry_loop(
            candidates=candidates,
            host_platform=host_platform,
            rosetta_available=rosetta_available,
            host_arch=host_arch,
            tried_so_far=tried,
            success_log_label="transport-cooldown retry",
            product_key=product_key,
            deadline=deadline,
        )
        if retry2_result is not None:
            return retry2_result
        final_class = _worst_inspect_class(retry2_seen)
        tried = tried + retry2_tried
        if final_class == "transport":
            print(  # noqa: T201
                "⓵ image_resolve: transport-cooldown retry STILL transport; "
                "agent should pivot to source_build / try later.",
                file=sys.stderr,
                flush=True,
            )

    # When ALL candidates hit rate_limited or transport, surface a concrete
    # pivot. The agent has the source already; the missing piece is the pivot
    # instruction (e.g. ubuntu+apache+php+WP rather than `wordpress:<v>`
    # directly).
    reason_text = "no candidate resolved via 'docker manifest inspect'"
    if final_class == "rate_limited":
        reason_text = (
            "all candidates hit Docker Hub anonymous rate-limit. PIVOT: "
            "use a generic base (ubuntu:22.04 / debian:12 / alpine:3.19) "
            "+ install the host platform manually via apt/yum (e.g. "
            "apache2 + libapache2-mod-php for WordPress/Drupal/Joomla, "
            "or nginx + php-fpm for PHP apps), then COPY the source via "
            "dockerfile_gen(copy_ops=...). Or call source_build for the "
            "host platform if it has a public Dockerfile."
        )
    elif final_class == "transport":
        reason_text = (
            "all candidates hit transient transport errors (5xx / timeout / "
            "connection-reset). Retry once after a short pause, OR pivot to "
            "a generic base (ubuntu/debian/alpine) + manual install."
        )

    # Bump per-product rate-limit counter so the next call can short-circuit
    # to a pivot. Only counts rate_limited (not transport), because transport
    # is more often a transient blip.
    # ALSO bump the CVE-level cumulative counter — catches cross-product
    # pivot thrash.
    if final_class == "rate_limited":
        _state.record_rate_limit_for_product(product_key)

    return ResolveResult(
        ok=False,
        host_arch=host_arch,
        decision="not_found",
        candidates_tried=tried,
        reason=reason_text,
        reason_class=final_class,
        next_step_hint=_image_resolve_next_step_hint("not_found", product_key),
    )


def image_resolve_to_payload(
    *,
    product: str,
    version: str,
    host_arch: str,
    rosetta_available: bool = False,
) -> dict[str, object]:
    """Agent-tool-ready dict shape."""
    r = image_resolve(
        product=product,
        version=version,
        host_arch=host_arch,
        rosetta_available=rosetta_available,
    )
    return {
        "ok": r.ok,
        "image_ref": r.image_ref,
        "digest_pinned_ref": r.digest_pinned_ref,
        "host_arch": r.host_arch,
        "decision": r.decision,
        "candidates_tried": r.candidates_tried,
        "reason": r.reason,
        "reason_class": r.reason_class,
        "next_step_hint": r.next_step_hint,
    }
