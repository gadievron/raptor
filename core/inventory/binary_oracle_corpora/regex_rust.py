"""regex (rust-lang/regex) corpus driver — Rust precision corpus.

First Rust integration. Validates the classifier end-to-end on Rust
mangling (predominantly v0; some legacy ``_ZN...``) and Rust release-
profile DWARF.

Methodology mirrors the snappy LLVM-cov driver: single ``cargo build``
with ``-C instrument-coverage -C debuginfo=2``, run the unit test
binary, merge ``.profraw`` → ``.profdata``, ``llvm-cov export`` for
ground truth. Same -O level (release) is both instrumented and
classified — no O0/O2 differential.

Notable Rust quirks:

  * ``cargo build`` strips DWARF by default in release; we set
    ``-C debuginfo=2`` via RUSTFLAGS to keep it.
  * llvm-cov function names are mangled (Rust v0 ``_RNv...`` for
    Rust 1.93's default, some legacy ``_ZN...``). ``c++filt --format
    =auto`` handles v0; legacy ``_ZN...`` Rust names aren't recognised
    by c++filt — we build a ``nm --demangle``-derived map first
    (nm's libiberty handles both) and fall back to c++filt only for
    names absent from the binary's symbol table (inlined-only DIEs).
  * Test binary lives at ``target/release/deps/regex-<hash>``; we
    glob for the latest.
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

from ..binary_oracle import (
    _qualified_from_demangled,
    _strip_impl_block_brackets,  # noqa: F401  (re-export for tests)
    _strip_rust_crate_hash,
)
from .snappy import (
    _LLVM_COV_CANDIDATES,
    _LLVM_PROFDATA_CANDIDATES,
    _resolve,
)

logger = logging.getLogger(__name__)

REGEX_URL = "https://github.com/rust-lang/regex.git"
REGEX_TAG = "1.10.6"
CACHE_VERSION = "1"


@dataclass
class _RegexRustDriver:
    name: str = "regex-rust"
    description: str = (
        "rust-lang/regex 1.10.6 — Rust ~30k LOC. cargo + -C "
        "instrument-coverage; first Rust corpus.")
    mode: Literal["gcov"] = "gcov"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        work_dir = work_dir.resolve()
        tag_dir = work_dir / REGEX_TAG
        sentinel = tag_dir / "sentinel.ok"
        target_dir = tag_dir / "target"
        profdata = tag_dir / "merged.profdata"

        if (not sentinel.exists()
                or sentinel.read_text().strip() != CACHE_VERSION):
            _build_and_run(tag_dir, target_dir, profdata)
            sentinel.write_text(CACHE_VERSION)

        # Test binary path (hash suffix; glob to find latest).
        candidates = sorted((target_dir / "release" / "deps").glob("regex-*"))
        candidates = [c for c in candidates if c.is_file()
                      and os.access(c, os.X_OK)
                      and "." not in c.name[6:]]  # skip regex-XXX.d / .rmeta
        if not candidates:
            raise RuntimeError(
                f"regex-rust: no test binary at {target_dir}/release/deps/")
        test_bin = candidates[-1]

        live, candidates_set = _liveness_from_llvm_cov(test_bin, profdata)
        return {
            "o2_binary":            test_bin,
            "candidate_functions":  sorted(candidates_set),
            "live_set":             live,
        }


def _build_and_run(tag_dir: Path, target_dir: Path, profdata: Path) -> None:
    """Clone → cargo build with coverage + DWARF → run test binary →
    merge profraw."""
    tag_dir.mkdir(parents=True, exist_ok=True)
    src = tag_dir / "src"

    from core.git import clone_repository, get_safe_git_env
    from core.git.clone import safe_git_command

    if src.exists():
        shutil.rmtree(src)
    logger.info("regex-rust: cloning %s → %s", REGEX_URL, src)
    if not clone_repository(REGEX_URL, src, depth=None):
        raise RuntimeError(f"regex-rust: clone failed for {REGEX_URL}")
    subprocess.run(
        safe_git_command("-C", str(src), "checkout", REGEX_TAG),
        env=get_safe_git_env(), check=True, timeout=60,
    )

    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    # Rust release profile strips DWARF + LLVM coverage instrumentation
    # by default; restore both via RUSTFLAGS. Single codegen unit so the
    # binary's DWARF references are stable across re-runs.
    env = {
        **os.environ,
        "RUSTFLAGS": ("-C instrument-coverage -C debuginfo=2 "
                      "-C codegen-units=1 -C lto=off"),
        "CARGO_TARGET_DIR": str(target_dir),
    }
    subprocess.run(
        ["cargo", "build", "--release", "--tests"],
        cwd=src, env=env, check=True, timeout=1800,
    )

    candidates = sorted((target_dir / "release" / "deps").glob("regex-*"))
    test_bin = next(
        (c for c in candidates if c.is_file() and os.access(c, os.X_OK)
         and "." not in c.name[6:]), None,
    )
    if test_bin is None:
        raise RuntimeError(
            f"regex-rust: no test binary built at {target_dir}/release/deps/")

    profraw_pattern = str(tag_dir / "cov-%p-%m.profraw")
    test_env = {**env, "LLVM_PROFILE_FILE": profraw_pattern}
    subprocess.run(
        [str(test_bin), "--test-threads=1"],
        cwd=tag_dir, env=test_env, check=True, timeout=600,
    )

    profraw = list(tag_dir.glob("cov-*.profraw"))
    if not profraw:
        raise RuntimeError(
            f"regex-rust: no profraw at {profraw_pattern}; coverage "
            f"instrumentation may be broken")

    profdata_tool = _resolve(_LLVM_PROFDATA_CANDIDATES)
    subprocess.run(
        [profdata_tool, "merge", "-sparse", *(str(p) for p in profraw),
         "-o", str(profdata)],
        check=True, timeout=120,
    )

    shutil.rmtree(src, ignore_errors=True)


# NB: ``_strip_rust_crate_hash`` was promoted to ``binary_oracle``
# (alongside ``_qualified_from_demangled`` and
# ``_strip_impl_block_brackets``) so every future Rust corpus +
# operator-supplied Rust binary gets it automatically. The local alias
# is retained for backwards compatibility with tests that still
# import ``_strip_crate_hash`` by the old name.
_strip_crate_hash = _strip_rust_crate_hash


# NB: ``_strip_impl_block_brackets`` was promoted to ``binary_oracle``
# (alongside ``_qualified_from_demangled``) so every future Rust corpus
# + operator-supplied Rust binary gets it automatically; the symbol is
# re-exported above for any external importer of this driver.


def _build_demangle_map(binary: Path) -> Dict[str, str]:
    """Return mangled → demangled for every text symbol in the binary.
    ``nm --demangle`` (libiberty) handles BOTH Rust v0 (``_RNv...``)
    and legacy (``_ZN...17h<hash>E``) — c++filt's auto mode only
    handles v0, so we prefer the nm-derived map. Returns ``{}`` if
    nm fails."""
    out_mangled = subprocess.run(
        ["nm", str(binary)],
        capture_output=True, text=True, check=False, timeout=60,
    ).stdout
    out_demangled = subprocess.run(
        ["nm", "--demangle", str(binary)],
        capture_output=True, text=True, check=False, timeout=60,
    ).stdout
    mangled = [line.split(None, 2) for line in out_mangled.splitlines()
               if line.strip()]
    demangled = [line.split(None, 2) for line in out_demangled.splitlines()
                 if line.strip()]
    mapping: Dict[str, str] = {}
    for m, d in zip(mangled, demangled):
        if len(m) >= 3 and len(d) >= 3 and m[1] == d[1] and m[1] in "tTwW":
            mapping[m[2]] = d[2]
    return mapping


def _liveness_from_llvm_cov(
    binary: Path, profdata: Path,
) -> Tuple[Set[str], Set[str]]:
    """Run ``llvm-cov export`` → JSON, demangle Rust names via nm-map
    (covers v0 + legacy) with c++filt as fallback, reduce to qualified-
    no-args form, filter to regex's surface."""
    cov_tool = _resolve(_LLVM_COV_CANDIDATES)
    proc = subprocess.run(
        [cov_tool, "export", f"--instr-profile={profdata}", str(binary)],
        capture_output=True, text=True, check=False, timeout=300,
    )
    if proc.returncode != 0 or not proc.stdout:
        logger.warning("regex-rust: llvm-cov export failed: %s",
                       proc.stderr[:300])
        return set(), set()
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.warning("regex-rust: llvm-cov JSON parse failed: %s", e)
        return set(), set()

    blocks = data.get("data") or []
    if not blocks:
        return set(), set()

    fns = blocks[0].get("functions") or []
    demangle_map = _build_demangle_map(binary)

    live: Set[str] = set()
    candidates: Set[str] = set()
    for fn in fns:
        mangled = fn.get("name") or ""
        if not mangled:
            continue
        # nm-map first; c++filt fallback (auto-mode handles v0, no-op on
        # legacy Rust which nm did catch).
        demangled = demangle_map.get(mangled)
        if demangled is None:
            try:
                proc = subprocess.run(
                    ["c++filt"], input=mangled, capture_output=True,
                    text=True, check=False, timeout=5,
                )
                demangled = proc.stdout.strip() or mangled
            except (OSError, subprocess.TimeoutExpired):
                demangled = mangled
        # ``_qualified_from_demangled`` now applies BOTH the Rust
        # impl-block bracket strip AND the crate-hash strip internally
        # (both promoted from this driver after the Inc 3g regex
        # measurement); no explicit pre-pass needed.
        qualified = _qualified_from_demangled(demangled)
        if not qualified:
            continue
        # Scope to regex's own surface (drop std::, core::, alloc::,
        # gimli::, etc. that get pulled in by the test binary).
        if not qualified.startswith("regex"):
            continue
        candidates.add(qualified)
        if fn.get("count", 0) > 0:
            live.add(qualified)
    return live, candidates


driver = _RegexRustDriver()
