"""docker build tool surface — the build mechanics live in ``core.container.build``.

The build invocation (context handling, tempfile Dockerfile, fresh-pull
policy for external FROM bases, labels, wall bound) and the dependency
classifier (stderr → apt dev packages) moved to
:mod:`core.container.build`. What stays here is the agent-facing
layer: the raw-Dockerfile P-invariant validation, the build-loop and
GPG-recovery guards (blocking a retry that discards the recovery
hint), the ``suggested_patch`` derivation, the tag policy, and the
discriminated ``next_step_hint`` text.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from core.container.build import (
    DEPENDENCY_PACKAGE_MAP as DEPENDENCY_PACKAGE_MAP,
)
from core.container.build import (
    build_image,
    classify_build_error,
    extract_from_image as _extract_from_image,  # noqa: F401 — test surface
)

from cve_env.config import CVE_LABEL

# source_build's local naming convention (skip --pull for these bases).
_LOCAL_IMAGE_PREFIXES: tuple[str, ...] = ("cve-",)


@dataclass
class BuildResult:
    ok: bool
    image_tag: str = ""
    exit_code: int = 0
    logs_tail: str = ""
    stderr_tail: str = ""
    suggested_patch: dict[str, list[str]] | None = None
    reason: str = ""
    reason_class: str = "ok"
    next_step_hint: str = ""  # concrete next action on failure
    extras: dict[str, str] = field(default_factory=dict)
    blocked: bool = False  # build-loop guard rejected the call


# Build-loop closure guard. Tracks per-CVE which image_tags have returned a
# `suggested_patch` from a prior failed build. If the agent calls
# `docker_build` again with the SAME image_tag, the guard blocks the call with
# a strong message telling the agent to invoke `dockerfile_gen` (with the
# suggested apt_packages added) before retrying. Without this guard, the agent
# regularly discards build-recovery hints and retries the same failing build.
#
# Concurrency note: this dict is module-global mutable state. Single-threaded
# by design — the agent loop runs one CVE at a time and calls
# `reset_docker_build_state()` between CVEs. No locks needed under the current
# execution model. If parallel CVE execution ever lands, this needs to be
# moved into a per-CVE context object.
_PENDING_SUGGESTED_PATCH: dict[str, dict[str, list[str]]] = {}

# Guard for `gpg_signature` failures. When apt-get update fails inside the
# build with stale-keyring errors (Debian bullseye / mirror.gcr.io's older
# Debian images), the recovery path is to call dockerfile_gen with
# `apt_unsafe=True` OR pivot the base image. Some agents ignore that guidance
# and retry docker_build with the SAME image_tag — guaranteed to fail the same
# way. The runtime guard records every image_tag that hit gpg_signature, blocks
# the next docker_build call against the same tag, and points the agent at the
# recovery options.
_PENDING_GPG_RECOVERY: set[str] = set()

# Per-CVE state registry. See note in docker_run.py for the contract.
_RESET_GLOBALS: tuple[str, ...] = ("_PENDING_SUGGESTED_PATCH", "_PENDING_GPG_RECOVERY")


def reset_docker_build_state() -> None:
    """Clear the per-CVE build-loop guards. The agent loop calls this at the
    start of each new CVE.
    """
    _PENDING_SUGGESTED_PATCH.clear()
    _PENDING_GPG_RECOVERY.clear()


def _docker_build_next_step_hint(
    reason: str,
    reason_class: str,
    suggested_patch: dict[str, list[str]] | None,
    stderr: str,
) -> str:
    """Pick a concrete next action for docker_build failures."""
    if suggested_patch and "apt_packages" in suggested_patch:
        pkgs = ", ".join(suggested_patch["apt_packages"][:5])
        return (
            f"missing system deps detected: {pkgs}. Re-render Dockerfile via "
            "dockerfile_gen with apt_packages=<that list> + retry docker_build"
        )
    # Specific reasons before generic reason_class buckets.
    if reason == "timeout":
        return (
            "build exceeded timeout. Likely a slow apt-get / npm install — "
            "split into smaller install_steps or use a smaller base image"
        )
    if reason == "bad_context":
        return (
            "context_dir is invalid. Pass an existing absolute path "
            "(usually the source_build repo_dir or a tmpdir you created)"
        )
    if reason_class == "daemon_corruption":
        return (
            "the HOST docker daemon has CORRUPTED containerd storage (persistent "
            "I/O error / failed to retrieve image list) — this is host infra, NOT "
            "your build, and will NOT fix itself on retry (the daemon needs a "
            "restart). Do NOT keep retrying; call give_up(reason='infra_corruption', "
            "terminal=True) so the harness can heal the daemon and re-run this CVE."
        )
    if reason_class == "disk_full":
        return (
            "host docker daemon ran out of disk during build. Auto-retry "
            "already pruned + retried; if still failing, give_up and "
            "report disk pressure"
        )
    if reason_class == "transport":
        return (
            "transient network failure during base-image pull. Retry the "
            "build once after a short pause"
        )
    if reason_class == "manifest_unknown":
        return (
            "base image not on registry. Edit FROM in dockerfile_text to a "
            "different version, or use a generic base (ubuntu:22.04 / "
            "alpine:3.19) and install the platform manually"
        )
    if reason_class == "gpg_signature":
        return (
            "Phase 37.4: apt-get update failed with invalid GPG signatures "
            "(common on mirror.gcr.io's Debian bullseye images). Recovery "
            "options, in order of preference: "
            "(1) re-call dockerfile_gen with `apt_unsafe=true` to wrap "
            "apt-get with `Acquire::Check-Valid-Until=false -o "
            "AllowInsecureRepositories=true` (safe in disposable build "
            "containers); "
            "(2) pivot to a newer Debian base (`debian:12` / `ubuntu:24.04`) "
            "via dockerfile_gen; "
            "(3) pivot to alpine (different package manager, sidesteps the "
            "issue entirely)."
        )
    sl = stderr.lower()
    if "no such file or directory" in sl and "copy" in sl:
        return (
            "COPY in Dockerfile referenced a missing path. Check copy_ops "
            "src paths exist relative to context_dir"
        )
    if "permission denied" in sl:
        return (
            "permission error during build (likely a chmod / chown step). "
            "Adjust install_steps or use a different base image user"
        )
    return (
        "build failed with no auto-classifiable cause. Read stderr_tail; "
        "common pivots: smaller base image, fewer install_steps per RUN, "
        "different base version"
    )


# Built images carry the same per-CVE label as containers, so
# lifecycle.cleanup_result_images() can rmi exactly THIS CVE's result images —
# preventing tagged-image accumulation that fills the Colima VM. The label
# string is config.CVE_LABEL (single source shared by all writers + readers).


def docker_build(
    *,
    context_dir: str,
    image_tag: str = "",
    dockerfile_text: str | None = None,
    platform: str | None = None,
    timeout_seconds: int = 600,
    cve_id: str = "",
) -> BuildResult:
    """Run docker build; return structured result.

    If ``dockerfile_text`` is provided, it is written to a tempfile next
    to the context and passed via ``-f``; otherwise ``<context>/Dockerfile``
    is used.

    When ``dockerfile_text`` is provided directly, it is validated against the
    same P14 (digest-pinned base) and P17 (no-priv) invariants that
    ``dockerfile_gen`` enforces. Bypassing ``dockerfile_gen`` to feed raw text
    to ``docker_build`` would otherwise skip these checks; the build is refused
    with ``reason="P14"`` or ``reason="P17"`` and a structured next_step_hint.
    """
    # Raw-text validation: when the agent supplies a Dockerfile directly
    # (bypassing ``dockerfile_gen``), apply the same P14/P17/etc. checks.
    if dockerfile_text is not None:
        from cve_env.utils.dockerfile_hygiene import validate_dockerfile_semantics

        issues = validate_dockerfile_semantics(dockerfile_text)
        if issues:
            primary = issues[0]
            # Surface the validator's P-code (e.g. "P14") in `reason` so the
            # agent can match on a stable token; full issue list goes into
            # stderr_tail.
            _pcode = re.search(r"\bP\d+\b", primary)
            code = _pcode.group(0) if _pcode else "validation"
            return BuildResult(
                ok=False,
                reason=code,
                reason_class="unknown",
                stderr_tail="\n".join(issues),
                next_step_hint=(
                    "raw dockerfile_text failed validation: "
                    f"{primary}. Either fix the Dockerfile to satisfy the "
                    "invariant (digest-pinned base, no :latest tag, etc.) "
                    "or call `dockerfile_gen` with structured params."
                ),
            )

    if image_tag and not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$', image_tag):
        image_tag = None
    elif image_tag and re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', image_tag):
        image_tag = None
    if image_tag:
        tag = image_tag
    elif cve_id:
        # Embed the cve_id in the auto-generated default tag so a SIGKILL'd
        # build's orphan image — which can miss the cve-env.cve-id LABEL
        # (cli.py's in-process finally is bypassed on wall-kill) — is still
        # reclaimable by the cve-id-scoped TAG sweep in cleanup_result_images +
        # the bench worker kill-path backstop. cve_id is a CVE-YYYY-NNNN literal
        # (tag-safe).
        tag = f"cve-env-local:{cve_id}-{uuid.uuid4().hex[:8]}"
    else:
        tag = f"cve-env-local:{uuid.uuid4().hex[:10]}"

    # Build-loop closure guard. If the same image_tag had a previous failed
    # build with a `suggested_patch`, block this call — the agent is supposed
    # to call `dockerfile_gen` with the suggested apt_packages first, not retry
    # docker_build with the same Dockerfile.
    # gpg_signature recovery guard. If the previous build for this image_tag
    # failed with `reason_class=gpg_signature`, the agent must call
    # `dockerfile_gen` with `apt_unsafe=True` OR pivot the base image — same
    # Dockerfile WILL fail again deterministically.
    if tag in _PENDING_GPG_RECOVERY:
        return BuildResult(
            ok=False,
            blocked=True,
            image_tag=tag,
            reason="blocked_by_gpg_recovery_guard",
            reason_class="gpg_signature",
            stderr_tail="(no build attempted)",
            next_step_hint=(
                f"Phase 38.2 gpg-recovery guard: the previous docker_build "
                f"for image_tag={tag!r} failed with `reason_class=gpg_signature` "
                f"(stale apt keyring). You retried docker_build without "
                f"applying the recovery hint. Your VERY NEXT call MUST be "
                f"`dockerfile_gen` with one of: "
                f"(1) `apt_unsafe=True` (wraps apt-get with bypass flags — "
                f"safe in disposable build containers); "
                f"(2) a NEWER base image (`debian:12` / `ubuntu:24.04` / "
                f"`alpine:3.19`) — fresh keyrings, no GPG issue; "
                f"OR pass a NEW image_tag if you've authored a different "
                f"Dockerfile."
            ),
        )

    pending = _PENDING_SUGGESTED_PATCH.get(tag)
    if pending:
        # Only block when the agent explicitly passed image_tag (so
        # auto-generated random tags from a fresh dockerfile_gen aren't
        # caught — those have unique tags).
        pkgs = ", ".join(pending.get("apt_packages", [])[:5])
        return BuildResult(
            ok=False,
            blocked=True,
            image_tag=tag,
            reason="blocked_by_build_loop_guard",
            reason_class="unknown",
            stderr_tail="(no build attempted)",
            suggested_patch=pending,
            next_step_hint=(
                f"Phase 37.3 build-loop guard: the previous docker_build for "
                f"image_tag={tag!r} returned suggested_patch with apt_packages "
                f"[{pkgs}]. You retried docker_build without applying that hint. "
                f"Your VERY NEXT call MUST be `dockerfile_gen` with "
                f"`apt_packages={pending.get('apt_packages')!r}` added to your "
                f"existing install_steps (so the missing dev libs are installed "
                f"BEFORE the failing RUN line). Then docker_build will work. "
                f"OR pass a NEW image_tag if you've authored a different "
                f"Dockerfile."
            ),
        )

    # Tag the image with this CVE so cleanup_result_images can rmi exactly
    # this CVE's images (parity with docker_run container labels).
    labels = {CVE_LABEL: cve_id} if cve_id else None
    outcome = build_image(
        context_dir=context_dir,
        tag=tag,
        dockerfile_text=dockerfile_text,
        platform=platform,
        timeout_seconds=timeout_seconds,
        labels=labels,
        local_prefixes=_LOCAL_IMAGE_PREFIXES,
    )

    if outcome.reason == "bad_context":
        return BuildResult(
            ok=False,
            reason="bad_context",
            reason_class="unknown",
            stderr_tail=outcome.stderr_tail,
            next_step_hint=_docker_build_next_step_hint(
                "bad_context", "unknown", None, ""
            ),
        )
    if outcome.reason == "timeout":
        return BuildResult(
            ok=False,
            reason="timeout",
            reason_class="timeout",
            image_tag=tag,
            stderr_tail=outcome.stderr_tail,
            logs_tail=outcome.logs_tail,
            next_step_hint=_docker_build_next_step_hint(
                "timeout", "timeout", None, ""
            ),
        )
    if outcome.ok:
        return BuildResult(
            ok=True,
            image_tag=tag,
            exit_code=0,
            logs_tail=outcome.logs_tail,
            stderr_tail=outcome.stderr_tail,
            reason_class="ok",
        )

    packages = classify_build_error(outcome.stderr_tail or "")
    suggested: dict[str, list[str]] | None = None
    if packages:
        suggested = {"apt_packages": packages}
        # Remember that this image_tag had a suggested_patch. Next
        # docker_build call with the same tag will be blocked unless the
        # agent calls dockerfile_gen with these apt_packages.
        _PENDING_SUGGESTED_PATCH[tag] = suggested

    # Track gpg_signature failures by image_tag so the next docker_build
    # with the same tag is blocked (forces the agent to apply the recovery
    # hint).
    if outcome.reason_class == "gpg_signature":
        _PENDING_GPG_RECOVERY.add(tag)

    reason_str = "build_failed" if suggested is None else "missing_dependency"
    return BuildResult(
        ok=False,
        image_tag=tag,
        exit_code=outcome.exit_code,
        logs_tail=outcome.logs_tail,
        stderr_tail=outcome.stderr_tail,
        suggested_patch=suggested,
        reason=reason_str,
        reason_class=outcome.reason_class,
        next_step_hint=_docker_build_next_step_hint(
            reason_str, outcome.reason_class, suggested,
            outcome.stderr_tail or "",
        ),
    )
