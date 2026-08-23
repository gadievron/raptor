"""AFL-instrumented env build-on-demand for /fuzz.

Source-only targets get an AFL-instrumented binary built inside the
pinned AFL++ image (``core.env.build.AFL_BUILD_IMAGE``), and the SAME
image's exported rootfs becomes the campaign substrate for
``core.sandbox.run(rootfs=...)`` — compile-time and run-time AFL
versions and libc agree by construction, and the campaign keeps the
sandbox observation tier (network deny, Landlock scoping, audit dir)
the host-binary path already has.

Consent: building a repo executes repo-influenced code, so this rides
the project ``build`` trust marker (or an explicit per-run flag) via
``core.project.trust.resolve_build_execution`` — the same gate
/validate Stage E build-on-demand uses. Without it the
candidacy check declines with a hint naming the marker; nothing runs.

The exported rootfs is LARGE (the flattened AFL++ image is several GB
across >100k inodes). It lives under the run output directory (never
a tmpfs) and the orchestrator deletes it when the campaign ends unless
the operator asks to keep it.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from core.logging import get_logger

logger = get_logger()

#: afl-fuzz locations probed inside the exported image rootfs.
_AFL_FUZZ_CANDIDATES = ("usr/local/bin/afl-fuzz", "usr/bin/afl-fuzz")

#: rootfs directory name under the fuzz run output dir.
ROOTFS_DIRNAME = "afl-rootfs"

#: in-image sibling tree holding the cmplog twin build.
CMPLOG_DIRNAME = "src-cmplog"

#: provenance record written next to the campaign output.
PROVENANCE_FILENAME = "env-build.json"


@dataclass
class FuzzEnvBuild:
    """Outcome of one AFL-instrumented env build."""

    ok: bool
    reason: str = ""      # "" | not_authorized | no_build_command |
    #                       stale_rootfs | no_afl_fuzz_in_image |
    #                       broken_afl_version | unsupported_sanitizer |
    #                       (containerized_build reasons)
    detail: str = ""
    rootfs: Path | None = None
    binaries: dict[str, str] = field(default_factory=dict)
    #: repo-relative name -> absolute in-rootfs path (under /src)
    host_artifacts: dict[str, Path] = field(default_factory=dict)
    #: repo-relative name -> read-only extracted host copy (0444)
    checksums: dict[str, str] = field(default_factory=dict)
    command: str = ""
    command_source: str = ""
    guessed: bool = False
    afl_fuzz: str = ""    # absolute in-rootfs afl-fuzz path
    base_image: str = ""
    sanitizer: str = ""   # "" | "asan" — instrumentation of the build
    cmplog_binaries: dict[str, str] = field(default_factory=dict)
    #: repo-relative name -> in-rootfs cmplog twin path (may be empty
    #: even when requested: the twin build can fail independently)


def env_build_candidate(
    repo: Path, *, build: bool | None = None,
) -> tuple[bool, str]:
    """Cheap candidacy check for plan(): consent + command resolution
    + docker presence. Runs nothing; returns ``(candidate, hint)``
    where *hint* explains a decline in operator terms.
    """
    repo = Path(repo)
    if not repo.is_dir():
        return False, ""
    if build is False:
        # Explicit per-run opt-out — no hint needed.
        return False, ""
    if not shutil.which("docker"):
        return False, ("env build-on-demand needs docker for the "
                       "containerized AFL build; docker not found")
    from core.project.trust import resolve_build_execution
    if not resolve_build_execution(build, banner=False, target_path=repo):
        return False, (
            "source tree could be fuzzed via env build-on-demand: set "
            "the project 'build' trust marker (/project trust build) "
            "or pass --env-build to authorise building it"
        )
    from core.build.resolve import resolve_build_command
    resolved = resolve_build_command(repo)
    if resolved is None:
        return False, (
            "env build-on-demand authorised but no build command "
            "resolves: set one with /project set build-command"
        )
    return True, ""


def env_build_for_fuzzing(
    repo: Path,
    out_dir: Path,
    *,
    build: bool | None = None,
    timeout_seconds: int = 600,
    sanitizer: str = "",
    cmplog: bool = False,
) -> FuzzEnvBuild:
    """Build *repo* AFL-instrumented in the pinned AFL++ image and keep
    the exported rootfs under *out_dir* as the campaign substrate.

    Never raises for build-class failures; see :class:`FuzzEnvBuild`.
    """
    from core.build.resolve import resolve_build_command
    from core.env.build import (
        AFL_BUILD_IMAGE,
        AFL_TOOLCHAIN,
        containerized_build,
    )
    from core.project.trust import resolve_build_execution

    repo = Path(repo)
    out_dir = Path(out_dir)
    if sanitizer not in ("", "asan"):
        return FuzzEnvBuild(ok=False, reason="unsupported_sanitizer",
                            detail=f"sanitizer {sanitizer!r} not supported")
    if not resolve_build_execution(build, target_path=repo):
        return FuzzEnvBuild(
            ok=False, reason="not_authorized",
            detail="build trust marker absent and no explicit flag")
    resolved = resolve_build_command(repo)
    if resolved is None:
        return FuzzEnvBuild(
            ok=False, reason="no_build_command",
            detail="no operator setting and detector synthesis found "
                   "nothing")
    command, source = resolved
    guessed = not source.startswith("project-setting:")
    if guessed:
        logger.warning(
            "env build uses a GUESSED build command (%s): %s — set "
            "/project set build-command to assert the real one",
            source, command,
        )

    rootfs_dir = out_dir / ROOTFS_DIRNAME
    if rootfs_dir.exists():
        # A prior run's kept rootfs (--keep-env-rootfs) or interrupted
        # leftovers. export_rootfs would silently MERGE over it: stale
        # /src binaries from the previous build would be re-enumerated
        # and reported as products of THIS build — provenance
        # dishonesty — and a wholesale clear would destroy a tree the
        # operator explicitly asked to keep. Refuse; the operator
        # decides.
        return FuzzEnvBuild(
            ok=False, reason="stale_rootfs",
            detail=f"{rootfs_dir} already exists (kept or interrupted "
                   "earlier run) — delete it or use a fresh --out",
            command=command, command_source=source, guessed=guessed)
    # ASAN rides afl-clang-fast's own env toggle; the cmplog twin is
    # a full second build of the same tree with compare logging on.
    run_env = {"AFL_USE_ASAN": "1"} if sanitizer == "asan" else None
    aux = {CMPLOG_DIRNAME: {"AFL_LLVM_CMPLOG": "1"}} if cmplog else None
    product = containerized_build(
        repo, command,
        out_dir=out_dir / "env-built",
        toolchain=AFL_TOOLCHAIN,
        base_image=AFL_BUILD_IMAGE,
        timeout_seconds=timeout_seconds,
        keep_rootfs=rootfs_dir,
        run_env=run_env,
        aux_builds=aux,
    )
    if not product.ok:
        return FuzzEnvBuild(
            ok=False, reason=product.reason, detail=product.detail,
            command=command, command_source=source, guessed=guessed,
            base_image=AFL_BUILD_IMAGE)

    afl_fuzz = ""
    for cand in _AFL_FUZZ_CANDIDATES:
        if (rootfs_dir / cand).is_file():
            afl_fuzz = "/" + cand
            break
    if afl_fuzz:
        broken = _broken_afl_version(rootfs_dir / afl_fuzz.lstrip("/"))
        if broken:
            version, defect = broken
            shutil.rmtree(rootfs_dir, ignore_errors=True)
            logger.error(
                "REFUSING to fuzz with afl-fuzz %s: %s. Use the pinned "
                "AFL_BUILD_IMAGE (or any build without this defect).",
                version, defect)
            return FuzzEnvBuild(
                ok=False, reason="broken_afl_version",
                detail=f"afl-fuzz {version}: {defect}",
                command=command, command_source=source, guessed=guessed,
                base_image=AFL_BUILD_IMAGE)
    if not afl_fuzz:
        shutil.rmtree(rootfs_dir, ignore_errors=True)
        return FuzzEnvBuild(
            ok=False, reason="no_afl_fuzz_in_image",
            detail=f"{AFL_BUILD_IMAGE} rootfs lacks afl-fuzz",
            command=command, command_source=source, guessed=guessed,
            base_image=AFL_BUILD_IMAGE)

    cmplog_binaries = {}
    if cmplog:
        for rel in sorted(product.artifacts):
            twin = rootfs_dir / CMPLOG_DIRNAME / rel
            if twin.is_file():
                cmplog_binaries[rel] = f"/{CMPLOG_DIRNAME}/{rel}"
        if not cmplog_binaries:
            logger.warning(
                "cmplog requested but no twin binaries found under "
                "/%s — campaign proceeds without compare logging",
                CMPLOG_DIRNAME)
    result = FuzzEnvBuild(
        ok=True,
        rootfs=rootfs_dir,
        sanitizer=sanitizer,
        cmplog_binaries=cmplog_binaries,
        binaries={rel: f"/src/{rel}" for rel in sorted(product.artifacts)},
        host_artifacts=dict(product.artifacts),
        checksums=dict(product.checksums),
        command=command,
        command_source=source,
        guessed=guessed,
        afl_fuzz=afl_fuzz,
        base_image=AFL_BUILD_IMAGE,
    )
    _write_provenance(out_dir, result)
    return result


def _broken_afl_version(afl_fuzz_path: Path) -> tuple[str, str] | None:
    """Return (version, defect) when the afl-fuzz binary carries a
    blocklisted version token, else None.

    Artifact-level check: it fires regardless of WHERE the image came
    from (the pinned constant, a future operator override, a stale
    layer cache), because the failure mode it guards against is
    silently-wrong fuzzing results.
    """
    from core.env.build import AFL_BROKEN_VERSIONS

    try:
        blob = afl_fuzz_path.read_bytes()
    except OSError as exc:
        # unreadable ≠ proven-healthy, but refusing here would fail
        # campaigns on transient fs hiccups; log so a repeat pattern
        # is visible.
        logger.warning("blocklist scan could not read %s: %s",
                       afl_fuzz_path, exc)
        return None
    for version, defect in AFL_BROKEN_VERSIONS.items():
        if version.encode() in blob:
            return version, defect
    return None


def _write_provenance(out_dir: Path, result: FuzzEnvBuild) -> None:
    record = {
        "base_image": result.base_image,
        "build_command": result.command,
        "build_command_source": result.command_source,
        "guessed_build_command": result.guessed,
        "binaries": result.binaries,
        # Read-only (0444) extracted host copies — these survive the
        # rootfs cleanup at campaign end; the record is how operators
        # find them (later analysis, /project binary add).
        "host_artifacts": {rel: str(p)
                           for rel, p in result.host_artifacts.items()},
        "checksums": result.checksums,
        "afl_fuzz": result.afl_fuzz,
        "sanitizer": result.sanitizer,
        "cmplog_binaries": result.cmplog_binaries,
        "rootfs": str(result.rootfs),
    }
    try:
        (out_dir / PROVENANCE_FILENAME).write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:  # provenance is evidence, not a gate
        logger.warning("env-build provenance write failed: %s", exc)
