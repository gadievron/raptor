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
from typing import Any, Literal, TYPE_CHECKING

from core.analysis.binary_oracle import (
    _qualified_from_demangled,
    _strip_impl_block_brackets,  # noqa: F401  (re-export for tests)
    _strip_rust_crate_hash,
)
from core.inventory.binary_oracle_corpora._sandbox_exec import (
    run_build_step,
    run_tool,
)

from .snappy import (
    _LLVM_COV_CANDIDATES,
    _LLVM_PROFDATA_CANDIDATES,
    _resolve,
)

if TYPE_CHECKING:
    from pathlib import Path

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

    def prepare(self, work_dir: Path) -> dict[str, Any]:
        work_dir = work_dir.resolve()
        tag_dir = work_dir / REGEX_TAG
        sentinel = tag_dir / "sentinel.ok"
        target_dir = tag_dir / "target"
        profdata = tag_dir / "merged.profdata"

        if (not sentinel.exists()
                or sentinel.read_text(encoding="utf-8").strip() != CACHE_VERSION):
            _build_and_run(tag_dir, target_dir, profdata)
            sentinel.write_text(CACHE_VERSION, encoding="utf-8")

        # Test binary path (hash suffix; glob to find latest).
        candidates = sorted((target_dir / "release" / "deps").glob("regex-*"))
        candidates = [c for c in candidates if c.is_file()
                      and os.access(c, os.X_OK)
                      and "." not in c.name[6:]]  # skip regex-XXX.d / .rmeta
        if not candidates:
            msg = f"regex-rust: no test binary at {target_dir}/release/deps/"
            raise RuntimeError(msg)
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
    logger.info("regex-rust: cloning %s (tag %s) → %s",
                REGEX_URL, REGEX_TAG, src)
    if not clone_repository(REGEX_URL, src, depth=1):
        msg = f"regex-rust: clone failed for {REGEX_URL}"
        raise RuntimeError(msg)
    subprocess.run(
        safe_git_command("-C", str(src), "fetch", "--depth", "1",
                         "origin", REGEX_TAG),
        # Dials origin outside the sandbox egress proxy — keep the
        # operator proxy vars (get_safe_git_env contract).
        env=get_safe_git_env(preserve_proxy=True), check=True, timeout=60,
    )
    subprocess.run(
        safe_git_command("-C", str(src), "checkout", "FETCH_HEAD"),
        env=get_safe_git_env(), check=True, timeout=60,
    )

    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    # Rust release profile strips DWARF + LLVM coverage instrumentation
    # by default; restore both via RUSTFLAGS. Single codegen unit so the
    # binary's DWARF references are stable across re-runs.
    build_env = {
        "RUSTFLAGS": ("-C instrument-coverage -C debuginfo=2 "
                      "-C codegen-units=1 -C lto=off"),
        "CARGO_TARGET_DIR": str(target_dir),
    }
    # cargo executes the fetched crate's build machinery (build.rs,
    # proc-macros) — sandboxed like every other fetched build system.
    # network=True: this is the declared package-manager fetch step
    # (crates.io); run_build_step keeps the operator proxy vars for it
    # (mandatory-egress-proxy hosts have no other route).
    # scope=tag_dir: CARGO_TARGET_DIR is a SIBLING of src/ — under
    # mount-ns isolation it is invisible unless the sandbox root spans
    # both. CARGO_HOME lives under tag_dir for the same reason (the
    # operator's ~/.cargo would be invisible in the mount-ns view);
    # the registry download re-runs per cold corpus build and the
    # sentinel cache absorbs it afterwards.
    build_env["CARGO_HOME"] = str(tag_dir / "cargo-home")
    run_build_step(
        ["cargo", "build", "--release", "--tests"],
        cwd=src, scope=tag_dir, extra_env=build_env, network=True,
        timeout=1800,
    )

    candidates = sorted((target_dir / "release" / "deps").glob("regex-*"))
    test_bin = next(
        (c for c in candidates if c.is_file() and os.access(c, os.X_OK)
         and "." not in c.name[6:]), None,
    )
    if test_bin is None:
        msg = f"regex-rust: no test binary built at {target_dir}/release/deps/"
        raise RuntimeError(msg)

    profraw_pattern = str(tag_dir / "cov-%p-%m.profraw")
    # The built test binary is untrusted-origin code — run it inside
    # the sandbox (network removed, writes confined to tag_dir).
    run_build_step(
        [str(test_bin), "--test-threads=1"],
        cwd=tag_dir,
        extra_env={**build_env, "LLVM_PROFILE_FILE": profraw_pattern},
        timeout=600,
    )

    profraw = list(tag_dir.glob("cov-*.profraw"))
    if not profraw:
        msg = (
            f"regex-rust: no profraw at {profraw_pattern}; coverage "
            f"instrumentation may be broken"
        )
        raise RuntimeError(msg)

    profdata_tool = _resolve(_LLVM_PROFDATA_CANDIDATES)
    run_tool(
        [profdata_tool, "merge", "-sparse", *(str(p) for p in profraw),
         "-o", str(profdata)],
        timeout=120,
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


def _build_demangle_map(binary: Path) -> dict[str, str]:
    """Return mangled → demangled for every text symbol in the binary.
    ``nm --demangle`` (libiberty) handles BOTH Rust v0 (``_RNv...``)
    and legacy (``_ZN...17h<hash>E``) — c++filt's auto mode only
    handles v0, so we prefer the nm-derived map. Returns ``{}`` if
    nm fails."""
    out_mangled = run_tool(
        ["nm", str(binary)], check=False, timeout=60,
    ).stdout
    out_demangled = run_tool(
        ["nm", "--demangle", str(binary)], check=False, timeout=60,
    ).stdout
    mangled = [line.split(None, 2) for line in out_mangled.splitlines()
               if line.strip()]
    demangled = [line.split(None, 2) for line in out_demangled.splitlines()
                 if line.strip()]
    mapping: dict[str, str] = {}
    for m, d in zip(mangled, demangled, strict=True):
        if len(m) >= 3 and len(d) >= 3 and m[1] == d[1] and m[1] in "tTwW":
            mapping[m[2]] = d[2]
    return mapping


def _liveness_from_llvm_cov(
    binary: Path, profdata: Path,
) -> tuple[set[str], set[str]]:
    """Run ``llvm-cov export`` → JSON, demangle Rust names via nm-map
    (covers v0 + legacy) with c++filt as fallback, reduce to qualified-
    no-args form, filter to regex's surface."""
    cov_tool = _resolve(_LLVM_COV_CANDIDATES)
    proc = run_tool(
        [cov_tool, "export", f"--instr-profile={profdata}", str(binary)],
        check=False, timeout=300,
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

    live: set[str] = set()
    candidates: set[str] = set()
    for fn in fns:
        mangled = fn.get("name") or ""
        if not mangled:
            continue
        # nm-map first; c++filt fallback (auto-mode handles v0, no-op on
        # legacy Rust which nm did catch).
        demangled = demangle_map.get(mangled)
        if demangled is None:
            try:
                proc = run_tool(
                    ["c++filt"], input_text=mangled,
                    check=False, timeout=5,
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
