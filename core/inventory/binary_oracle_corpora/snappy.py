"""snappy corpus driver — C++ precision corpus.

snappy v1.2.1 (Google's compressor) replaces the originally-planned re2
corpus: re2 requires a system Abseil install (~100MB+), while snappy
vendors googletest as a submodule and has zero system deps.

Methodology: LLVM source-based coverage. A single -O2 build is BOTH
instrumented and classified — no O0/O2 differential. The earlier gcov
methodology shipped at 83.3% precision; the lone FP was a compile-time-
only lambda that gcov over-attributed (live in O0 ground truth, gone in
O2 binary). llvm-cov at -O2 reflects what the binary actually executes,
eliminating the confound (Inc 3c LLVM experiment).

Pipeline::

    1. clang++ -O2 -g -ffunction-sections -fdata-sections
              -fprofile-instr-generate -fcoverage-mapping ...
    2. LLVM_PROFILE_FILE=...%m.profraw ctest      # one profraw per run
    3. llvm-profdata-21 merge -sparse *.profraw -o merged.profdata
    4. llvm-cov-21 export --instr-profile=merged.profdata <binary>
       → JSON: per-function execution counts (count > 0 = live)
    5. Names in JSON are MANGLED (Itanium ABI), some prefixed with
       ``<source-file>:`` for internal-linkage. Strip prefix, demangle
       via c++filt, reduce to qualified-no-args form.

Cache layout::

    out/binary-oracle-precision/cache/snappy/<sha-prefix>/
        build/           # single instrumented -O2 build
        merged.profdata  # accumulated across ctest runs
        sentinel.ok      # version-stamped; absent → full rebuild
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Set, Tuple

# ``_qualified_from_demangled`` / ``_find_arglist_open`` /
# ``_METHOD_TRAILING_QUALS`` live in ``binary_oracle`` so the classifier
# can demangle DWARF linkage names with the same logic. Re-exported here
# for any external importer.
from ..binary_oracle import (  # noqa: F401  (re-export)
    _demangle_linkage_names,
    _find_arglist_open,
    _METHOD_TRAILING_QUALS,
    _qualified_from_demangled,
)

logger = logging.getLogger(__name__)

SNAPPY_URL = "https://github.com/google/snappy.git"
SNAPPY_SHA = "984b191f0fefdeb17050b42a90b7625999c13b8d"   # v1.2.1
CACHE_VERSION = "2"   # bumped: gcov → llvm-cov methodology

# Versioned LLVM tools. Plain ``llvm-cov`` / ``llvm-profdata`` aren't on
# the PATH on Ubuntu 24.04 LTS even with ``clang-21`` installed — only
# the versioned binaries exist. Try the versioned form first, then plain.
_LLVM_COV_CANDIDATES = ("llvm-cov-21", "llvm-cov-20", "llvm-cov-19",
                        "llvm-cov")
_LLVM_PROFDATA_CANDIDATES = ("llvm-profdata-21", "llvm-profdata-20",
                             "llvm-profdata-19", "llvm-profdata")


def _resolve(candidates: Tuple[str, ...]) -> str:
    for c in candidates:
        if shutil.which(c):
            return c
    raise RuntimeError(f"snappy: none of {candidates} found on PATH")


# Filter out llvm-cov hits on stdlib / google-test / inlined-everywhere
# helpers when populating the candidate set — they're not part of the
# snappy surface a researcher would evaluate, and including them just
# inflates n_functions with methodology noise.
_STDLIB_PREFIXES = (
    "std::",
    "__gnu_cxx::",
    "testing::",
    "decltype(",
    "operator new",
    "operator delete",
)


def _is_stdlib_or_helper(qualified: str) -> bool:
    if any(qualified.startswith(p) for p in _STDLIB_PREFIXES):
        return True
    return qualified.startswith("__")


@dataclass
class _SnappyDriver:
    name: str = "snappy"
    description: str = (
        "snappy v1.2.1 — C++17, ~3k LOC. LLVM source-based coverage "
        "(single -O2 build, no O0/O2 differential).")
    mode: Literal["gcov"] = "gcov"   # harness cross-tab is liveness-based

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        work_dir = work_dir.resolve()
        sha_dir = work_dir / SNAPPY_SHA[:12]
        sentinel = sha_dir / "sentinel.ok"
        build_dir = sha_dir / "build"
        profdata = sha_dir / "merged.profdata"

        if (not sentinel.exists()
                or sentinel.read_text().strip() != CACHE_VERSION):
            _build_and_run(sha_dir, build_dir, profdata)
            sentinel.write_text(CACHE_VERSION)

        binary = build_dir / "snappy_unittest"
        live, candidates = _liveness_from_llvm_cov(binary, profdata)
        return {
            "o2_binary":            binary,
            "candidate_functions":  sorted(candidates),
            "live_set":             live,
        }


def _build_and_run(sha_dir: Path, build_dir: Path, profdata: Path) -> None:
    """Clone (+ submodule init for googletest) → CMake build once →
    run unittest → merge profraw → profdata."""
    sha_dir.mkdir(parents=True, exist_ok=True)
    src = sha_dir / "src"

    from core.git import clone_repository, get_safe_git_env
    from core.git.clone import safe_git_command

    if src.exists():
        shutil.rmtree(src)
    logger.info("snappy: cloning %s → %s", SNAPPY_URL, src)
    if not clone_repository(SNAPPY_URL, src, depth=None):
        raise RuntimeError(f"snappy: clone failed for {SNAPPY_URL}")
    subprocess.run(
        safe_git_command("-C", str(src), "checkout", SNAPPY_SHA),
        env=get_safe_git_env(), check=True, timeout=60,
    )
    # snappy vendors googletest + benchmark as submodules.
    subprocess.run(
        safe_git_command("-C", str(src), "submodule", "update",
                         "--init", "--recursive"),
        env=get_safe_git_env(), check=True, timeout=300,
    )

    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    # ``-Wno-error=uninitialized-const-pointer``: clang-21 is stricter
    # than gcc and rejects a known-benign pattern in snappy's
    # ``snappy-test.cc`` (an intentionally-uninitialised dummy used to
    # exercise an error path). Don't fail the build over an upstream
    # warning we don't own.
    cxxflags = ("-O2 -g -ffunction-sections -fdata-sections "
                "-fprofile-instr-generate -fcoverage-mapping "
                "-Wno-error=uninitialized-const-pointer")
    ldflags = "-Wl,--gc-sections -fprofile-instr-generate"
    subprocess.run([
        "cmake", str(src),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_COMPILER=clang",
        "-DCMAKE_CXX_COMPILER=clang++",
        f"-DCMAKE_CXX_FLAGS={cxxflags}",
        f"-DCMAKE_EXE_LINKER_FLAGS={ldflags}",
        "-DSNAPPY_BUILD_TESTS=ON",
        "-DSNAPPY_BUILD_BENCHMARKS=OFF",
        # snappy's CMake declares min 3.1; newer CMake refuses without this.
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
    ], cwd=build_dir, check=True, timeout=300)
    subprocess.run(["cmake", "--build", ".", "-j4"],
                   cwd=build_dir, check=True, timeout=600)

    # Run tests with profile output. ``%m`` expands to a unique-per-image
    # ID at runtime so concurrent processes don't trample one file.
    profraw_pattern = str(sha_dir / "snappy_%m.profraw")
    env = {**os.environ, "LLVM_PROFILE_FILE": profraw_pattern}
    subprocess.run(["ctest", "--output-on-failure"],
                   cwd=build_dir, env=env, check=True, timeout=300)

    profraw = list(sha_dir.glob("snappy_*.profraw"))
    if not profraw:
        raise RuntimeError(
            f"snappy: no profraw produced (LLVM_PROFILE_FILE="
            f"{profraw_pattern}); coverage instrumentation may be broken")

    profdata_tool = _resolve(_LLVM_PROFDATA_CANDIDATES)
    subprocess.run(
        [profdata_tool, "merge", "-sparse", *(str(p) for p in profraw),
         "-o", str(profdata)],
        check=True, timeout=120,
    )

    shutil.rmtree(src, ignore_errors=True)


def _strip_llvm_file_prefix(name: str) -> str:
    """``llvm-cov export`` prefixes internal-linkage function names with
    the defining source file: ``snappy.cc:_ZN6snappy12_GLOBAL...``.
    External-linkage names start at ``_Z`` directly. Strip the prefix
    so the rest of the pipeline (c++filt → qualified extraction →
    namespace filter) sees the bare mangled symbol."""
    if name.startswith("_Z"):
        return name
    if ":_Z" in name:
        return name.split(":", 1)[1]
    return name


def _liveness_from_llvm_cov(
    binary: Path, profdata: Path,
) -> Tuple[Set[str], Set[str]]:
    """Run ``llvm-cov export`` → JSON, demangle mangled function names
    via ``c++filt``, and reduce to qualified-no-args form. Returns
    ``(live_set, candidate_set)``."""
    cov_tool = _resolve(_LLVM_COV_CANDIDATES)
    proc = subprocess.run(
        [cov_tool, "export", f"--instr-profile={profdata}", str(binary)],
        capture_output=True, text=True, check=False, timeout=120,
    )
    if proc.returncode != 0 or not proc.stdout:
        logger.warning("snappy: llvm-cov export failed: %s",
                       proc.stderr[:300])
        return set(), set()
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.warning("snappy: failed to parse llvm-cov JSON: %s", e)
        return set(), set()

    # ``llvm-cov export`` emits a top-level ``data`` array with one entry
    # per "object" — for a single binary that's a single entry.
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
        # Scope to snappy's own surface — without this, the candidate
        # set balloons with gtest internals (libsnappy.a is linked into
        # the gtest-driven unittest, so llvm-cov sees both).
        #
        # Adversarial review E P1-4: include anonymous-namespace
        # helpers ((anonymous namespace)::Foo) — they're exactly where
        # ICF / DCE is most aggressive in C++ and excluding them from
        # the candidate set was hiding the highest-risk class from
        # precision measurement. The qualified-name extractor flags
        # them by the literal ``(anonymous namespace)`` prefix; admit
        # those AND the snappy-prefixed ones.
        is_snappy_surface = (qualified.startswith("snappy::")
                             or qualified.startswith("snappy_"))
        is_anon = "(anonymous namespace)" in qualified
        if not (is_snappy_surface or is_anon):
            continue
        candidates.add(qualified)
        if fn.get("count", 0) > 0:
            live.add(qualified)
    return live, candidates


driver = _SnappyDriver()
