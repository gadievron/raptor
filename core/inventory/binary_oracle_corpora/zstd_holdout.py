"""zstd HELD-OUT corpus driver — one-shot precision measurement.

This driver exists for ONE purpose: to measure binary_oracle absent
precision on a corpus the classifier was never tuned against.

**The contract for this driver is: do not modify the classifier based
on what it reports.** The methodology (O0/O2 differential like
libsodium) is the most rigorous of the existing drivers because the
candidate set comes from the O0 build (independent of what O2 DCE
strips) and ground truth comes from the O0 build's gcov run.

zstd v1.5.6 — pure C, ~50k LOC, two compilation modes:
    build_o0: -O0 -g --coverage     (candidate enumeration + ground truth)
    build_o2: -O2 -g -ffunction-sections -fdata-sections + --gc-sections
              (classifier target)
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

ZSTD_URL = "https://github.com/facebook/zstd.git"
ZSTD_TAG = "v1.5.6"
CACHE_VERSION = "3"   # bumped: writable_paths fix for gcda writes


@dataclass
class _ZstdHoldoutDriver:
    name: str = "zstd_holdout"
    description: str = (
        "zstd v1.5.6 — pure C, ~50k LOC, gcov O0/O2 differential. "
        "HELD OUT: classifier was never tuned against this corpus.")
    mode: Literal["gcov"] = "gcov"

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        work_dir = work_dir.resolve()
        tag_dir = work_dir / ZSTD_TAG.replace(".", "_")
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
        return {
            "o2_binary":            build_o2 / "programs" / "zstd",
            "candidate_functions":  candidates,
            "live_set":             live,
            "toolchain":            record_toolchain(cc="gcc", gcov="gcov"),
        }


def _build_fresh(tag_dir: Path, build_o0: Path, build_o2: Path) -> None:
    tag_dir.mkdir(parents=True, exist_ok=True)
    src = tag_dir / "src"

    from core.git import clone_repository, get_safe_git_env
    from core.git.clone import safe_git_command

    if src.exists():
        shutil.rmtree(src)
    logger.info("zstd_holdout: cloning %s → %s", ZSTD_URL, src)
    if not clone_repository(ZSTD_URL, src, depth=None):
        raise RuntimeError(f"zstd_holdout: clone failed for {ZSTD_URL}")
    subprocess.run(
        safe_git_command("-C", str(src), "checkout", ZSTD_TAG),
        env=get_safe_git_env(), check=True, timeout=60,
    )

    for build_dir, cflags, ldflags, run_target in [
        (build_o0, "-O0 -g --coverage", "--coverage", True),
        (build_o2,
         "-O2 -g -ffunction-sections -fdata-sections",
         "-Wl,--gc-sections", False),
    ]:
        if build_dir.exists():
            shutil.rmtree(build_dir)
        # zstd's Makefile build can't take an out-of-tree dir, so we
        # copy the source into the build dir each time. ``cp -a`` via
        # subprocess (rather than ``shutil.copytree``) — on Python 3.14
        # shutil.copytree fails on zstd's source tree
        # (NotADirectoryError on file symlinks under tests/cli-tests/);
        # cp -a is the portable Unix idiom that handles this cleanly.
        build_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["cp", "-a", f"{src}/.", str(build_dir)],
            check=True, timeout=120,
        )
        env = {**os.environ, "CFLAGS": cflags, "LDFLAGS": ldflags}
        subprocess.run(
            ["make", "-j4", "lib-mt", "zstd"],
            cwd=build_dir, env=env, check=True, timeout=600,
        )
        if run_target:
            # Exercise the CLI binary with a workload broad enough that
            # the gcov live_set is non-trivial. A previous version ran a
            # single compress+decompress on one file — the resulting
            # live_set was nearly empty, which made the precision
            # claim mathematically vacuous (classifier-absent ∩
            # live_set is forced empty when live_set is empty).
            #
            # The workload now spans: 5 input files of different sizes
            # and entropy classes; 6 compression levels (fast/normal/
            # high); long-range mode; multi-threaded mode; dictionary
            # training + use; decompression of every produced artefact.
            # Combined ground-truth coverage of zstd's hot paths is
            # genuine — the cross-tab "live" column populates with
            # hundreds of functions and the precision claim has actual
            # statistical power.
            from core.sandbox import run as _sandbox_run
            zstd_bin = build_dir / "programs" / "zstd"
            tmp = build_dir / "workload"
            tmp.mkdir(exist_ok=True)

            # Inputs: highly-redundant (compresses well), random-ish
            # (incompressible), source code (medium), small + large.
            inputs: list = []
            (tmp / "low.txt").write_bytes(b"AAAA" * 16384)
            inputs.append(tmp / "low.txt")
            import os as _os
            (tmp / "high.bin").write_bytes(_os.urandom(64 * 1024))
            inputs.append(tmp / "high.bin")
            inputs.append(build_dir / "lib" / "compress" / "zstd_compress.c")
            inputs.append(build_dir / "lib" / "decompress" / "zstd_decompress.c")
            inputs.append(build_dir / "lib" / "common" / "fse_decompress.c")

            def _z(*argv: str) -> None:
                # writable_paths includes build_dir because gcov
                # instrumentation writes .gcda files alongside the
                # .o files (under ``build_dir/obj/...``). Without
                # the explicit allow, the sandbox blocks those
                # writes and the live_set comes back empty —
                # making absent_precision mathematically vacuous.
                _sandbox_run(
                    [str(zstd_bin), *argv],
                    target=str(build_dir), output=str(tmp),
                    writable_paths=[str(build_dir)],
                    block_network=True, check=True, timeout=120,
                )

            # Compression: every level class — fast / default / high /
            # ultra; --long for long-range matching; -T2 for MT.
            # NB: deliberately NOT named ``src`` here — that's the
            # outer source-tree dir; Python's for-loop variable
            # persists after the loop and would silently shadow it,
            # breaking the second build_o2 iteration's cp command.
            for lvl in ("-1", "-3", "-9", "-19", "--ultra", "-22"):
                for input_file in inputs:
                    out = tmp / (
                        f"{input_file.name}.{lvl.lstrip('-') or 'u'}.zst"
                    )
                    _z(lvl, "-f", "-o", str(out), str(input_file))
            # Long-range mode (different code path)
            _z("--long", "-3", "-f", "-o",
               str(tmp / "long.zst"), str(inputs[0]))
            # Multi-threaded compression (MT code path)
            _z("-T2", "-3", "-f", "-o",
               str(tmp / "mt.zst"), str(inputs[1]))
            # Dictionary training + dictionary-based compression
            dict_path = tmp / "dict"
            try:
                _z("--train", "-o", str(dict_path),
                   *(str(p) for p in inputs),
                   "--maxdict", "16384")
                _z("-D", str(dict_path), "-3", "-f", "-o",
                   str(tmp / "dict.zst"), str(inputs[2]))
                _z("-D", str(dict_path), "-d", "-f", "-o",
                   str(tmp / "dict.out"), str(tmp / "dict.zst"))
            except subprocess.CalledProcessError:
                # zstd --train requires multiple samples; some envs
                # bail. Not fatal — coverage from the other branches
                # is enough.
                pass
            # Decompress everything we compressed (decompress path).
            for compressed in tmp.glob("*.zst"):
                _z("-d", "-f", "-o",
                   str(tmp / f"{compressed.stem}.out"), str(compressed))

    shutil.rmtree(src, ignore_errors=True)


_GCOV_FN_RE = re.compile(r"^Function '([^']+)'")
_GCOV_LINES_RE = re.compile(r"^Lines executed:([\d.]+)% of \d+")


def _collect_gcov_liveness(build_dir: Path) -> Set[str]:
    """Walk the build tree for .gcda files and harvest live function
    names from ``gcov -f``. zstd's Makefile statically links the lib
    sources into the CLI binary's object dir
    (``programs/obj/conf_*/*.o``), so .gcda files land THERE — not
    under ``lib/``. Walk the whole build_dir and the gcov tool
    figures out which .gcno pairs with each .gcda."""
    if not build_dir.is_dir():
        logger.warning("zstd_holdout: %s missing", build_dir)
        return set()

    live: Set[str] = set()
    for gcda in build_dir.rglob("*.gcda"):
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
    """nm on libzstd.a — candidates are every defined symbol in the
    O0 archive. The O0 build doesn't DCE, so this is the source-side
    surface (modulo macros that produce no symbol)."""
    # zstd's Makefile builds libzstd.a in lib/ root.
    archive = build_o0 / "lib" / "libzstd.a"
    if not archive.exists():
        logger.warning("zstd_holdout: %s missing", archive)
        return []
    out = subprocess.run(
        ["nm", str(archive)], capture_output=True, text=True,
        check=False, timeout=30,
    ).stdout
    fns: Set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-2] in ("T", "t", "W", "w"):
            fns.add(parts[-1])
    return sorted(fns)


driver = _ZstdHoldoutDriver()
