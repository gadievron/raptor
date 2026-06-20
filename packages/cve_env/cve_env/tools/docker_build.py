"""docker build subprocess wrapper with DEPENDENCY_PACKAGE_MAP hints.

Runs ``docker build`` on a context directory (optionally with an
LLM-provided Dockerfile) and returns exit code + last ~200 log lines.
If the stderr tail matches :data:`DEPENDENCY_PACKAGE_MAP` regex, a
``suggested_patch`` hint is included for the agent to feed back into
the next ``dockerfile_gen`` call as additional ``apt_packages``.
"""

from __future__ import annotations

import re
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from cve_env.config import CVE_LABEL
from cve_env.tools._image_origin import _is_external_image


def _extract_from_image(dockerfile_text: str | None, ctx: Path) -> str | None:
    """Parse the FROM image reference from a Dockerfile (text first;
    fall back to <ctx>/Dockerfile). Returns the image name (e.g.,
    'debian:11', 'cve-X:build') or None if no FROM line found.

    Strips 'AS <stage>' aliases and '--platform=...' flags. Multi-stage
    Dockerfiles return the FIRST FROM (the base for stage 0); subsequent
    stages may FROM previous stages (local refs) but the gate is whether
    the BASE chain reaches an external registry.
    """
    text = dockerfile_text
    if text is None:
        dockerfile_path = ctx / "Dockerfile"
        if not dockerfile_path.is_file():
            return None
        try:
            text = dockerfile_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line.upper().startswith("FROM "):
            continue
        # Strip optional --platform=... flag
        rest = re.sub(r"^FROM\s+(?:--\S+\s+)*", "", line, flags=re.IGNORECASE)
        # Strip ' AS <stage>'
        rest = re.split(r"\s+AS\s+", rest, maxsplit=1, flags=re.IGNORECASE)[0]
        return rest.strip() or None
    return None


DEPENDENCY_PACKAGE_MAP: dict[str, str] = {
    # APR (Apache Portable Runtime)
    "apr.h": "libapr1-dev",
    "apr_util.h": "libaprutil1-dev",
    "-lapr-1": "libapr1-dev",
    "-laprutil-1": "libaprutil1-dev",
    # OpenSSL
    "openssl/ssl.h": "libssl-dev",
    "openssl/crypto.h": "libssl-dev",
    "-lssl": "libssl-dev",
    "-lcrypto": "libssl-dev",
    # PCRE
    "pcre.h": "libpcre3-dev",
    "-lpcre": "libpcre3-dev",
    # Compression
    "zlib.h": "zlib1g-dev",
    "-lz": "zlib1g-dev",
    "expat.h": "libexpat1-dev",
    "-lexpat": "libexpat1-dev",
    "bz2.h": "libbz2-dev",
    "-lbz2": "libbz2-dev",
    # XML
    "libxml/parser.h": "libxml2-dev",
    "-lxml2": "libxml2-dev",
    # Networking
    "curl/curl.h": "libcurl4-openssl-dev",
    "-lcurl": "libcurl4-openssl-dev",
    # Database
    "mysql/mysql.h": "libmysqlclient-dev",
    "-lmysqlclient": "libmysqlclient-dev",
    "postgresql/libpq-fe.h": "libpq-dev",
    "-lpq": "libpq-dev",
    # Other common
    "readline/readline.h": "libreadline-dev",
    "-lreadline": "libreadline-dev",
    "ncurses.h": "libncurses5-dev",
    "-lncurses": "libncurses5-dev",
}

_CONFIGURE_KEYWORD_MAP: dict[str, str] = {
    "openssl": "libssl-dev",
    "apr-1": "libapr1-dev",
    "pcre": "libpcre3-dev",
}

_HEADER_NOT_FOUND_RE = re.compile(
    r"fatal error:\s*([^\s:]+\.h)(?::\s*No such file)?", re.IGNORECASE
)
_LIB_NOT_FOUND_RE = re.compile(
    r"(?:cannot find|/usr/bin/ld: cannot find)\s+(-l[\w+.\-]+)", re.IGNORECASE
)


def classify_build_error(stderr: str) -> list[str]:
    """Return apt packages implied by build stderr, or ``[]``."""
    if not stderr:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def _add(pkg: str) -> None:
        if pkg not in seen:
            seen.add(pkg)
            found.append(pkg)

    for match in _HEADER_NOT_FOUND_RE.finditer(stderr):
        header = match.group(1)
        pkg = DEPENDENCY_PACKAGE_MAP.get(header)
        if pkg is not None:
            _add(pkg)
            continue
        tail = header.split("/")[-1]
        for key, mapped in DEPENDENCY_PACKAGE_MAP.items():
            if key.endswith(tail) and key.endswith(".h"):
                _add(mapped)
                break

    for match in _LIB_NOT_FOUND_RE.finditer(stderr):
        lib = match.group(1).lower()
        pkg = DEPENDENCY_PACKAGE_MAP.get(lib)
        if pkg is not None:
            _add(pkg)

    lowered = stderr.lower()
    for keyword, pkg in _CONFIGURE_KEYWORD_MAP.items():
        if keyword in lowered and ("not found" in lowered or "not correct" in lowered):
            _add(pkg)

    return found


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
# string is config.CVE_LABEL (single source shared by all writers + readers),
# re-exported here.


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
    # Auto-create a genuinely-missing context dir instead of erroring
    # bad_context. The agent frequently calls docker_build BEFORE mkdir-ing the
    # context and quits on the first bad_context. FROM+RUN Dockerfiles need no
    # COPY context; COPY ops still fail later at the COPY step (correctly).
    # Empty path and exists-but-not-a-dir stay hard rejections — only a
    # creatable missing path is auto-created.
    if not isinstance(context_dir, str) or not context_dir.strip():
        return BuildResult(
            ok=False,
            reason="bad_context",
            reason_class="unknown",
            stderr_tail="context_dir is empty",
            next_step_hint=_docker_build_next_step_hint(
                "bad_context", "unknown", None, ""
            ),
        )
    ctx = Path(context_dir)
    if not ctx.exists():
        try:
            ctx.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return BuildResult(
                ok=False,
                reason="bad_context",
                reason_class="unknown",
                stderr_tail=f"{context_dir}: cannot create context dir ({exc})",
                next_step_hint=_docker_build_next_step_hint(
                    "bad_context", "unknown", None, ""
                ),
            )
    if not ctx.is_dir():
        return BuildResult(
            ok=False,
            reason="bad_context",
            reason_class="unknown",
            stderr_tail=f"{context_dir}: not a directory",
            next_step_hint=_docker_build_next_step_hint(
                "bad_context", "unknown", None, ""
            ),
        )

    # Raw-text validation: when the agent supplies a Dockerfile directly
    # (bypassing ``dockerfile_gen``), apply the same P14/P17/etc. checks.
    # Defers to ``validate_dockerfile_semantics`` for the structural rules +
    # tag-blocklist.
    if dockerfile_text is not None:
        from cve_env.utils.dockerfile_hygiene import validate_dockerfile_semantics

        issues = validate_dockerfile_semantics(dockerfile_text)
        if issues:
            primary = issues[0]
            # Surface the validator's P-code (e.g. "P14") in `reason` so the
            # agent can match on a stable token; full issue list goes into
            # stderr_tail. Extract whatever P-code was emitted (regex) rather
            # than matching a hardcoded list — validate_dockerfile_semantics
            # only checks FROM/RUN/COPY/LABEL semantics → P14; P17/P18 are
            # image-ref / port-bind invariants enforced elsewhere.
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
    if image_tag and tag in _PENDING_GPG_RECOVERY:
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
    if pending and image_tag:
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
    cmd: list[str] = ["docker", "build", "-t", tag]
    if cve_id:
        # Tag the image with this CVE so cleanup_result_images can rmi exactly
        # this CVE's images (parity with docker_run container labels).
        cmd.extend(["--label", f"{CVE_LABEL}={cve_id}"])
    if platform:
        cmd.extend(["--platform", platform])
    # Force fresh pull of the FROM base image when it came from a public
    # registry. Bypasses the local Docker layer cache for base images, which
    # can silently re-use cached base layers even when the registry is
    # rate-limited. Skipped when FROM is locally-built (cve-X:build), since
    # `--pull` would fail with "manifest unknown" on no-upstream.
    from_image = _extract_from_image(dockerfile_text, ctx)
    if from_image and _is_external_image(from_image):
        cmd.append("--pull")

    tmpfile: Path | None = None
    try:
        if dockerfile_text is not None:
            with tempfile.NamedTemporaryFile(  # noqa: SIM115 -- delete=False intentional
                mode="w",
                suffix=".Dockerfile",
                delete=False,
                dir=str(ctx),
            ) as fd:
                fd.write(dockerfile_text)
                tmpfile = Path(fd.name)
            cmd.extend(["-f", str(tmpfile)])
        cmd.append(str(ctx))

        # Strip dangerous env vars before docker build so HTTPS_PROXY /
        # DOCKER_CONFIG-adjacent vars in the operator's shell can't redirect
        # the build context. run_with_timeout places any partial output in
        # outcome.stdout on the timed_out=True branch.
        from cve_env.utils.run import run_with_timeout
        from cve_env.utils.safe_env import safe_subprocess_env

        outcome = run_with_timeout(
            cmd,
            timeout=timeout_seconds,
            env=safe_subprocess_env(),
        )
        if outcome.timed_out:
            return BuildResult(
                ok=False,
                reason="timeout",
                reason_class="transport",
                image_tag=tag,
                stderr_tail=f"timeout after {timeout_seconds}s",
                logs_tail=outcome.stdout[-4000:] if outcome.stdout else "",
                next_step_hint=_docker_build_next_step_hint(
                    "timeout", "transport", None, ""
                ),
            )

        stdout_tail = (outcome.stdout or "").splitlines()[-200:]
        stderr_tail = (outcome.stderr or "").splitlines()[-200:]
        logs_tail = "\n".join(stdout_tail)[-4000:]
        stderr_blob = "\n".join(stderr_tail)[-4000:]

        if outcome.returncode == 0:
            return BuildResult(
                ok=True,
                image_tag=tag,
                exit_code=0,
                logs_tail=logs_tail,
                stderr_tail=stderr_blob,
                reason_class="ok",
            )

        packages = classify_build_error(outcome.stderr or "")
        suggested: dict[str, list[str]] | None = None
        if packages:
            suggested = {"apt_packages": packages}
            # Remember that this image_tag had a suggested_patch. Next
            # docker_build call with the same tag will be blocked unless the
            # agent calls dockerfile_gen with these apt_packages.
            _PENDING_SUGGESTED_PATCH[tag] = suggested
        # Classify the docker build failure (disk_full, transport, etc.).
        # If the dependency-classifier already inferred missing apt packages,
        # that's a higher-signal classification — preserve it via "missing_dependency"
        # reason but still surface reason_class for retry decisions.
        from cve_env.tools._failure_class import classify_docker_stderr

        failure_class = classify_docker_stderr(outcome.stderr or "")

        # Track gpg_signature failures by image_tag so the next docker_build
        # with the same tag is blocked (forces the agent to apply the recovery
        # hint).
        if failure_class == "gpg_signature":
            _PENDING_GPG_RECOVERY.add(tag)

        reason_str = "build_failed" if suggested is None else "missing_dependency"
        # RunOutcome.returncode is int | None (None when subprocess never
        # started OR on timeout). Normalize to -1 in the failure path —
        # matches the int-typed BuildResult.exit_code field and the
        # convention from run_in_container.py (timeout = -1).
        exit_code = outcome.returncode if outcome.returncode is not None else -1
        return BuildResult(
            ok=False,
            image_tag=tag,
            exit_code=exit_code,
            logs_tail=logs_tail,
            stderr_tail=stderr_blob,
            suggested_patch=suggested,
            reason=reason_str,
            reason_class=failure_class,
            next_step_hint=_docker_build_next_step_hint(
                reason_str, failure_class, suggested, outcome.stderr or ""
            ),
        )
    finally:
        if tmpfile is not None and tmpfile.exists():
            tmpfile.unlink()
