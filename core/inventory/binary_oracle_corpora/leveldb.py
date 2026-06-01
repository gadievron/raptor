"""leveldb corpus driver — C++ precision corpus (key-value store).

leveldb master pinned at the most-recent ``Bump third_party/
dependencies`` commit — older tagged releases bundle a gtest that
fails to compile with clang-21 (uninitialized-const-pointer + missing
uintptr_t header). The leveldb tests link against the benchmark library
unnecessarily; we patch that out before configuring.

Same LLVM source-based coverage methodology as the snappy driver.
Tests virtual dispatch (leveldb's iterator hierarchies + filter
policies), heavy class-method inlining, and ICF (leveldb has many
small accessor methods that often fold).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Set, Tuple

from ..binary_oracle import (
    _demangle_linkage_names,
    _qualified_from_demangled,
)
from .snappy import (
    _LLVM_COV_CANDIDATES,
    _LLVM_PROFDATA_CANDIDATES,
    _resolve,
    _strip_llvm_file_prefix,
    _is_stdlib_or_helper,
)

logger = logging.getLogger(__name__)

LEVELDB_URL = "https://github.com/google/leveldb.git"
# Most-recent commit on main as of 2026-05-30 ("Bump third_party/
# dependencies.") — necessary because the v1.23 tag's gtest submodule
# pin doesn't compile with clang-21. Verified against the live repo:
# the prior value (7ee830d6c12f…) was never a real leveldb commit
# ("upload-pack: not our ref"), which is why the pinned checkout 128'd
# every nightly. This is the actual main HEAD SHA (same 7ee830d prefix
# — the old value was a corrupted full SHA).
LEVELDB_SHA = "7ee830d02b623e8ffe0b95d59a74db1e58da04c5"
# In case the SHA isn't reachable, fall back to whatever ``main`` HEAD
# is now — leveldb's main has been stable for years.
LEVELDB_FALLBACK_BRANCH = "main"
CACHE_VERSION = "1"


@dataclass
class _LeveldbDriver:
    name: str = "leveldb"
    description: str = (
        "leveldb master @ 2026-05 — C++ KV-store, ~30k LOC. LLVM "
        "source-based coverage. Tests virtual dispatch + heavy class "
        "inlining + ICF.")
    mode: Literal["gcov"] = "gcov"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        work_dir = work_dir.resolve()
        sha_dir = work_dir / LEVELDB_SHA[:12]
        sentinel = sha_dir / "sentinel.ok"
        build_dir = sha_dir / "build"
        profdata = sha_dir / "merged.profdata"

        if (not sentinel.exists()
                or sentinel.read_text().strip() != CACHE_VERSION):
            _build_and_run(sha_dir, build_dir, profdata)
            sentinel.write_text(CACHE_VERSION)

        binary = build_dir / "leveldb_tests"
        live, candidates = _liveness_from_llvm_cov(binary, profdata)
        return {
            "o2_binary":            binary,
            "candidate_functions":  sorted(candidates),
            "live_set":             live,
        }


def _build_and_run(sha_dir: Path, build_dir: Path, profdata: Path) -> None:
    """Clone main + bump submodules → patch CMakeLists to drop the
    benchmark dep → CMake build → run tests → merge profraw."""
    sha_dir.mkdir(parents=True, exist_ok=True)
    src = sha_dir / "src"

    from core.git import clone_repository, get_safe_git_env
    from core.git.clone import safe_git_command

    if src.exists():
        shutil.rmtree(src)
    logger.info("leveldb: cloning %s → %s", LEVELDB_URL, src)
    if not clone_repository(LEVELDB_URL, src, depth=None):
        raise RuntimeError(f"leveldb: clone failed for {LEVELDB_URL}")
    # Hard-pin: check out the pinned SHA. The clone fetches branch heads
    # + their history, but the pinned commit may not be reachable from
    # the default branch (shallow clone, or the commit sits behind a
    # later force-push / on a now-deleted branch). In that case fetch the
    # exact object explicitly, then check it out — GitHub honours fetching
    # an arbitrary reachable SHA. We still check out ``LEVELDB_SHA`` and
    # never fall back to ``main`` HEAD, so reproducibility of the precision
    # claim is preserved (Adversarial review E P2-1): an unfetchable object
    # is a hard error, never a silent revision swap. Operators wanting a
    # different revision bump ``LEVELDB_SHA`` explicitly.
    checkout = subprocess.run(
        safe_git_command("-C", str(src), "checkout", LEVELDB_SHA),
        env=get_safe_git_env(), check=False, timeout=60,
    )
    if checkout.returncode != 0:
        subprocess.run(
            safe_git_command("-C", str(src), "fetch", "--depth", "1",
                             "origin", LEVELDB_SHA),
            env=get_safe_git_env(), check=True, timeout=120,
        )
        subprocess.run(
            safe_git_command("-C", str(src), "checkout", LEVELDB_SHA),
            env=get_safe_git_env(), check=True, timeout=60,
        )

    subprocess.run(
        safe_git_command("-C", str(src), "submodule", "update",
                         "--init", "--recursive"),
        env=get_safe_git_env(), check=True, timeout=300,
    )

    # Patch the test-link line to drop the unused ``benchmark`` dep —
    # the benchmark library's CMake forces ``-Werror`` on Release
    # builds and clang-21 trips its own warning fences. Tests don't
    # actually use benchmark.
    _patch_drop_benchmark(src / "CMakeLists.txt")

    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    cxxflags = ("-O2 -g -ffunction-sections -fdata-sections "
                "-fprofile-instr-generate -fcoverage-mapping")
    ldflags = "-Wl,--gc-sections -fprofile-instr-generate"
    subprocess.run([
        "cmake", str(src),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_COMPILER=clang",
        "-DCMAKE_CXX_COMPILER=clang++",
        f"-DCMAKE_CXX_FLAGS={cxxflags}",
        f"-DCMAKE_EXE_LINKER_FLAGS={ldflags}",
        "-DLEVELDB_BUILD_TESTS=ON",
        "-DLEVELDB_BUILD_BENCHMARKS=OFF",
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
    ], cwd=build_dir, check=True, timeout=300)
    subprocess.run(["cmake", "--build", ".", "-j4"],
                   cwd=build_dir, check=True, timeout=900)

    profraw_pattern = str(sha_dir / "leveldb_%m.profraw")
    env = {**os.environ, "LLVM_PROFILE_FILE": profraw_pattern}
    subprocess.run(["ctest", "--output-on-failure"],
                   cwd=build_dir, env=env, check=True, timeout=600)

    profraw = list(sha_dir.glob("leveldb_*.profraw"))
    if not profraw:
        raise RuntimeError(
            f"leveldb: no profraw produced (LLVM_PROFILE_FILE="
            f"{profraw_pattern}); coverage instrumentation may be broken")

    profdata_tool = _resolve(_LLVM_PROFDATA_CANDIDATES)
    subprocess.run(
        [profdata_tool, "merge", "-sparse", *(str(p) for p in profraw),
         "-o", str(profdata)],
        check=True, timeout=120,
    )

    shutil.rmtree(src, ignore_errors=True)


_BENCHMARK_LINK_RE = re.compile(r"leveldb gmock gtest benchmark")
_BENCHMARK_SUBDIR_RE = re.compile(
    r'add_subdirectory\("third_party/benchmark"\)')


def _patch_drop_benchmark(cmakelists: Path) -> None:
    """Drop the ``benchmark`` test-link dep and ``add_subdirectory`` for
    the benchmark library — both unnecessary for our tests-only build
    and the benchmark lib's CMake forces -Werror which clang-21 trips.

    Idempotent: re-applying produces no change."""
    text = cmakelists.read_text()
    new_text = _BENCHMARK_LINK_RE.sub("leveldb gmock gtest", text)
    new_text = _BENCHMARK_SUBDIR_RE.sub(
        "# benchmark add_subdirectory skipped — tests-only build",
        new_text)
    if new_text != text:
        cmakelists.write_text(new_text)
        logger.info("leveldb: patched out benchmark dep in CMakeLists.txt")


def _liveness_from_llvm_cov(
    binary: Path, profdata: Path,
) -> Tuple[Set[str], Set[str]]:
    """Same approach as snappy — strip llvm-cov's ``<file>:`` prefix,
    demangle via c++filt, reduce to qualified name. Scope candidates to
    leveldb's surface only."""
    cov_tool = _resolve(_LLVM_COV_CANDIDATES)
    proc = subprocess.run(
        [cov_tool, "export", f"--instr-profile={profdata}", str(binary)],
        capture_output=True, text=True, check=False, timeout=120,
    )
    if proc.returncode != 0 or not proc.stdout:
        logger.warning("leveldb: llvm-cov export failed: %s",
                       proc.stderr[:300])
        return set(), set()
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.warning("leveldb: llvm-cov JSON parse failed: %s", e)
        return set(), set()

    blocks = data.get("data") or []
    if not blocks:
        return set(), set()

    fns = blocks[0].get("functions") or []
    bare_mangled = sorted({_strip_llvm_file_prefix(f["name"])
                           for f in fns if f.get("name")})
    demangled_map = _demangle_linkage_names(bare_mangled)

    live: Set[str] = set()
    candidates: Set[str] = set()
    for fn in fns:
        bare = _strip_llvm_file_prefix(fn.get("name") or "")
        full = demangled_map.get(bare, bare)
        qualified = _qualified_from_demangled(full)
        if not qualified or _is_stdlib_or_helper(qualified):
            continue
        # Scope to leveldb's surface — without this, gtest internals
        # and miscellaneous C runtime functions inflate the candidate
        # set with methodology noise. Anonymous-namespace helpers are
        # admitted (adversarial review E P1-4: ICF/DCE-prime category).
        is_leveldb_surface = (qualified.startswith("leveldb::")
                              or qualified.startswith("leveldb_"))
        is_anon = "(anonymous namespace)" in qualified
        if not (is_leveldb_surface or is_anon):
            continue
        candidates.add(qualified)
        if fn.get("count", 0) > 0:
            live.add(qualified)
    return live, candidates


driver = _LeveldbDriver()
