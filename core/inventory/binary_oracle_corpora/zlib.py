"""zlib corpus driver — first real-world precision corpus.

Methodology:
  1. Clone zlib v1.3.1 (pinned SHA), full history (so the checkout works).
  2. Build TWICE in isolated copies of the source tree (zlib doesn't
     support out-of-tree builds, so cp the tree):

       build_o0/   ./configure --static
                   CFLAGS='-O0 -g --coverage'   LDFLAGS='--coverage'

       build_o2/   ./configure --static
                   CFLAGS='-O2 -g -ffunction-sections -fdata-sections'
                   LDFLAGS='-Wl,--gc-sections'

  3. Run ``./example`` (zlib's self-contained smoke test) against the O0
     build to populate ``.gcda``. We deliberately skip ``make test`` —
     it'd also exercise ``minigzip``, broadening ground truth past what
     the ``example`` binary actually covers.

  4. Parse ``gcov -f`` over libz's ``.c`` files → set of functions with
     non-zero line execution.

  5. Candidate set = functions defined in ``libz.a`` (the static archive
     from the O0 build). That's the population the classifier evaluates.

  6. Classifier runs against ``build_o2/example`` — a statically-linked
     executable where ``--gc-sections`` actually applies (vs ``libz.so``
     where exported symbols are linker-roots and never DCE'd, which
     would trivialise the measurement).

Cache layout::

    out/binary-oracle-precision/cache/zlib/<sha-prefix>/
        build_o0/        # built once; .gcda accumulates
        build_o2/        # built once
        sentinel.ok      # version-stamped; absent → full rebuild

Idempotent re-runs read the cached build directly. Bump ``CACHE_VERSION``
when build flags change.
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

ZLIB_URL = "https://github.com/madler/zlib.git"
ZLIB_SHA = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf"   # v1.3.1
CACHE_VERSION = "1"


@dataclass
class _ZlibDriver:
    name: str = "zlib"
    description: str = (
        "zlib v1.3.1 — pure C, ~10k LOC. gcov ground truth from "
        "self-test; classifier target = statically-linked example.")
    mode: Literal["gcov"] = "gcov"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        work_dir = work_dir.resolve()
        sha_dir = work_dir / ZLIB_SHA[:12]
        sentinel = sha_dir / "sentinel.ok"
        build_o0 = sha_dir / "build_o0"
        build_o2 = sha_dir / "build_o2"

        if (not sentinel.exists()
                or sentinel.read_text().strip() != CACHE_VERSION):
            _build_fresh(sha_dir, build_o0, build_o2)
            sentinel.write_text(CACHE_VERSION)

        live = _collect_gcov_liveness(build_o0)
        candidates = _enumerate_candidates(build_o0)
        return {
            "o2_binary": build_o2 / "example",
            "candidate_functions": candidates,
            "live_set": live,
        }


def _build_fresh(sha_dir: Path, build_o0: Path, build_o2: Path) -> None:
    """Clone → checkout pinned SHA → build twice. Source clone is deleted
    afterwards; only build artifacts persist in the cache."""
    sha_dir.mkdir(parents=True, exist_ok=True)
    src = sha_dir / "src"

    # Centralised safe-clone API (no direct ``git clone``); depth=None
    # gives us full history so the SHA checkout can resolve.
    from core.git import clone_repository, get_safe_git_env
    from core.git.clone import safe_git_command

    if src.exists():
        shutil.rmtree(src)
    logger.info("zlib: cloning %s → %s", ZLIB_URL, src)
    if not clone_repository(ZLIB_URL, src, depth=None):
        raise RuntimeError(f"zlib: clone failed for {ZLIB_URL}")
    subprocess.run(
        safe_git_command("-C", str(src), "checkout", ZLIB_SHA),
        env=get_safe_git_env(), check=True, timeout=60,
    )

    for build_dir, cflags, ldflags, run_tests in [
        (build_o0,
         "-O0 -g --coverage", "--coverage", True),
        (build_o2,
         "-O2 -g -ffunction-sections -fdata-sections",
         "-Wl,--gc-sections", False),
    ]:
        if build_dir.exists():
            shutil.rmtree(build_dir)
        shutil.copytree(src, build_dir)
        env = {**os.environ, "CFLAGS": cflags, "LDFLAGS": ldflags}
        subprocess.run(["./configure", "--static"], cwd=build_dir,
                       env=env, check=True, timeout=120)
        subprocess.run(["make", "-j4"], cwd=build_dir,
                       env=env, check=True, timeout=300)
        if run_tests:
            # Run only ``./example`` — see module docstring for why we
            # skip ``make test``. Sandbox the built-binary invocation
            # — upstream tag is trusted but supply-chain compromise on
            # a pinned ref is the residual risk. writable_paths
            # includes build_dir so gcov can write .gcda files.
            from core.sandbox import run as _sandbox_run
            _sandbox_run(
                ["./example"], cwd=str(build_dir),
                target=str(build_dir),
                writable_paths=[str(build_dir)],
                block_network=True,
                check=True, timeout=60,
            )

    shutil.rmtree(src, ignore_errors=True)


# ---------------------------------------------------------------------------
# gcov parsing
# ---------------------------------------------------------------------------

_GCOV_FN_RE = re.compile(r"^Function '([^']+)'")
_GCOV_LINES_RE = re.compile(r"^Lines executed:([\d.]+)% of \d+")


def _collect_gcov_liveness(build_dir: Path) -> Set[str]:
    """Run ``gcov -f`` over every ``.c`` file with a matching ``.gcda``
    in the build dir; return the set of functions with > 0% lines
    executed."""
    c_files = sorted(p.name for p in build_dir.glob("*.c")
                     if (build_dir / (p.stem + ".gcda")).exists())
    if not c_files:
        logger.warning("zlib: no .gcda files in %s — was the self-test run?",
                       build_dir)
        return set()

    out = subprocess.run(
        ["gcov", "-f"] + c_files, cwd=build_dir,
        capture_output=True, text=True, check=False, timeout=120,
    ).stdout

    live: Set[str] = set()
    current_fn = None
    for line in out.splitlines():
        m = _GCOV_FN_RE.match(line)
        if m:
            current_fn = m.group(1)
            continue
        if current_fn:
            m2 = _GCOV_LINES_RE.match(line)
            if m2:
                if float(m2.group(1)) > 0:
                    live.add(current_fn)
                current_fn = None
    return live


# ---------------------------------------------------------------------------
# Candidate enumeration
# ---------------------------------------------------------------------------

def _enumerate_candidates(build_o0: Path) -> List[str]:
    """Functions defined in ``libz.a`` — the population the classifier
    evaluates. ``nm`` types ``T`` (text, exported) and ``t`` (text, local)
    are functions; ``W``/``w`` are weak. Skip data symbols."""
    archive = build_o0 / "libz.a"
    if not archive.exists():
        logger.warning("zlib: %s not found; cannot enumerate candidates",
                       archive)
        return []
    out = subprocess.run(["nm", str(archive)],
                         capture_output=True, text=True,
                         check=False, timeout=30).stdout
    fns: Set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        # ``<addr> T <name>`` or ``         T <name>`` (undefined → skip).
        if len(parts) >= 3 and parts[-2] in ("T", "t", "W", "w"):
            fns.add(parts[-1])
    return sorted(fns)


driver = _ZlibDriver()
