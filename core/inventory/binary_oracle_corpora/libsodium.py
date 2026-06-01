"""libsodium corpus driver — C precision corpus.

libsodium v1.0.20 — pure C, ~40k LOC. Autotools build with two
configurations (O0+coverage / O2+--gc-sections); ground truth from
``make check`` (60+ test binaries). Mirrors the zlib driver structure
but uses libsodium's static archive ``libsodium.a`` as both the
candidate-enumeration source and the link target for the classifier
binary.

Cache layout::

    out/binary-oracle-precision/cache/libsodium/<sha-prefix>/
        build_o0/        # autotools build, includes .gcda after make check
        build_o2/        # autotools build
        sentinel.ok      # version-stamped; absent → full rebuild
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Set

logger = logging.getLogger(__name__)

LIBSODIUM_URL = "https://github.com/jedisct1/libsodium.git"
LIBSODIUM_TAG = "1.0.20-RELEASE"
# Bumped to 2: sandbox-wrapped test-binary invocation + writable_paths
# for gcov + broader gcda reset (whole build_dir, not just src/libsodium).
# Old caches need a fresh build for the new workload semantics.
CACHE_VERSION = "2"


@dataclass
class _LibsodiumDriver:
    name: str = "libsodium"
    description: str = (
        "libsodium v1.0.20 — pure C, ~40k LOC, autotools + gcov. "
        "Ground truth from `make check` (60+ test binaries).")
    mode: Literal["gcov"] = "gcov"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        work_dir = work_dir.resolve()
        tag_dir = work_dir / LIBSODIUM_TAG.replace("-", "_")
        sentinel = tag_dir / "sentinel.ok"
        build_o0 = tag_dir / "build_o0"
        build_o2 = tag_dir / "build_o2"

        if (not sentinel.exists()
                or sentinel.read_text().strip() != CACHE_VERSION):
            _build_fresh(tag_dir, build_o0, build_o2)
            sentinel.write_text(CACHE_VERSION)

        live = _collect_gcov_liveness(build_o0)
        candidates = _enumerate_candidates(build_o0)
        from .toolchain import record_toolchain
        toolchain = record_toolchain(cc="gcc", gcov="gcov")
        return {
            # ``aead_aegis128l`` is one of the test executables — it's
            # statically linked against libsodium.a and exercises a broad
            # slice of the library, so ``--gc-sections`` produces a
            # realistic mix of absent / inlined / symbol_present.
            "o2_binary":            build_o2 / "test" / "default"
                                    / "aead_aegis128l",
            "candidate_functions":  candidates,
            "live_set":             live,
            "toolchain":            toolchain,
        }


def _build_fresh(tag_dir: Path, build_o0: Path, build_o2: Path) -> None:
    """Clone (full history so the tag can be checked out) → autogen →
    configure × 2 → build × 2 → ``make check`` on the O0 build."""
    tag_dir.mkdir(parents=True, exist_ok=True)
    src = tag_dir / "src"

    from core.git import clone_repository, get_safe_git_env
    from core.git.clone import safe_git_command

    if src.exists():
        shutil.rmtree(src)
    logger.info("libsodium: cloning %s → %s", LIBSODIUM_URL, src)
    if not clone_repository(LIBSODIUM_URL, src, depth=None):
        raise RuntimeError(f"libsodium: clone failed for {LIBSODIUM_URL}")
    subprocess.run(
        safe_git_command("-C", str(src), "checkout", LIBSODIUM_TAG),
        env=get_safe_git_env(), check=True, timeout=60,
    )

    subprocess.run(["./autogen.sh"], cwd=src, check=True, timeout=120)

    for build_dir, cflags, ldflags, target_only in [
        (build_o0, "-O0 -g --coverage", "--coverage", True),
        (build_o2,
         "-O2 -g -ffunction-sections -fdata-sections",
         "-Wl,--gc-sections", False),
    ]:
        if build_dir.exists():
            shutil.rmtree(build_dir)
        build_dir.mkdir(parents=True)
        env = {**os.environ, "CFLAGS": cflags, "LDFLAGS": ldflags}
        subprocess.run(
            [str((src / "configure").resolve()),
             "--enable-static", "--disable-shared"],
            cwd=build_dir, env=env, check=True, timeout=180,
        )
        # libsodium's test binaries (the only artifacts with realistic
        # --gc-sections DCE on a libsodium-linked executable) are only
        # produced by ``make check`` — plain ``make`` builds just the
        # static archive. Run check on BOTH configs to materialise the
        # test binaries.
        subprocess.run(["make", "-j4"], cwd=build_dir,
                       env=env, check=True, timeout=600)
        subprocess.run(["make", "check"], cwd=build_dir,
                       env=env, check=True, timeout=900)
        if target_only:
            # Reset gcov counters and run ONLY the classifier target
            # binary. This aligns ground truth (what gcov saw executed)
            # with what the classifier evaluates (a single test binary).
            # Without this, ``make check`` aggregated execution across
            # 60+ tests but the classifier sees one slice — so most
            # cross-test-active functions misclassify as absent FPs.
            #
            # Walk the WHOLE build_dir (not just src/libsodium) —
            # adversarial review E P1-5. libtool can emit .gcda under
            # ``test/*/.libs/*.gcda`` and other layouts; the prior
            # narrow reset left stale .gcda from earlier ``make check``
            # runs in those locations, contaminating the live_set.
            for gcda in build_dir.rglob("*.gcda"):
                try:
                    gcda.unlink()
                except OSError:
                    pass
            # Sandbox the libsodium test-binary invocation. Upstream
            # tag is trusted but supply-chain compromise on a pinned
            # ref is the residual risk; running an executable should
            # be contained (Landlock + namespace; no network needed).
            # writable_paths includes build_dir because gcov writes
            # .gcda files alongside .o files — without the allow,
            # the live_set would be silently empty.
            from core.sandbox import run as _sandbox_run
            target = build_dir / "test" / "default" / "aead_aegis128l"
            _sandbox_run(
                [str(target)], cwd=str(target.parent),
                target=str(target.parent),
                writable_paths=[str(build_dir)],
                block_network=True,
                check=True, timeout=60,
            )

    shutil.rmtree(src, ignore_errors=True)


# ---------------------------------------------------------------------------
# gcov parsing — reuses the zlib regex; libsodium gcov format is identical.
# ---------------------------------------------------------------------------

_GCOV_FN_RE = re.compile(r"^Function '([^']+)'")
_GCOV_LINES_RE = re.compile(r"^Lines executed:([\d.]+)% of \d+")


def _collect_gcov_liveness(build_dir: Path) -> Set[str]:
    """Walk ``src/libsodium/sodium/`` and the per-area subdirs for
    .gcda/.c pairs, run ``gcov -f``, accumulate functions with > 0%
    line execution. libsodium splits its source across many subdirs
    (codecs, runtime, version, crypto_*, etc.) so we recurse."""
    libsodium_root = build_dir / "src" / "libsodium"
    if not libsodium_root.is_dir():
        logger.warning("libsodium: %s missing", libsodium_root)
        return set()

    live: Set[str] = set()
    for gcda in libsodium_root.rglob("*.gcda"):
        gcda_dir = gcda.parent
        out = subprocess.run(
            ["gcov", "-f", gcda.name], cwd=gcda_dir,
            capture_output=True, text=True, check=False, timeout=60,
        ).stdout
        current = None
        for line in out.splitlines():
            m = _GCOV_FN_RE.match(line)
            if m:
                current = m.group(1)
                continue
            if current:
                m2 = _GCOV_LINES_RE.match(line)
                if m2:
                    if float(m2.group(1)) > 0:
                        live.add(current)
                    current = None
    return live


def _enumerate_candidates(build_o0: Path) -> List[str]:
    """Functions defined in ``libsodium.a`` — the candidate population.

    libtool prefixes symbols in archived objects with ``libsodium_la-``
    on the OBJECT FILE names, but the symbols themselves are unprefixed
    (just the C function name). Use nm directly on the archive."""
    archive = build_o0 / "src" / "libsodium" / ".libs" / "libsodium.a"
    if not archive.exists():
        logger.warning("libsodium: %s missing", archive)
        return []
    out = subprocess.run(["nm", str(archive)],
                         capture_output=True, text=True,
                         check=False, timeout=30).stdout
    fns: Set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-2] in ("T", "t", "W", "w"):
            fns.add(parts[-1])
    return sorted(fns)


driver = _LibsodiumDriver()
