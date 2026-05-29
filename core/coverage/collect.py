"""Runtime-coverage collection (Phase 4): turn raw coverage *build artifacts*
into store marks by running the coverage tool, then reusing the parsers.

`import_runtime` (importer.py) imports already-produced artifacts (`.gcov` /
`.info` / coverage.json). This module runs the tool to *produce* them from a
coverage build:
- ``collect_gcov(build_dir)`` runs ``gcov`` on the ``.gcda``/``.gcno`` under a
  build dir → ``.gcov`` → :func:`parse_gcov`.
- ``collect_llvm(binary, profdata)`` runs ``llvm-cov export -format=lcov`` →
  :func:`parse_lcov`.

Subprocesses use the sanitised env (``RaptorConfig.get_safe_env``) and
list-form args (never shell-interpolate scanned-repo paths); tolerant — a tool
failure yields ``{}``, never raises.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Set

from core.coverage.store import CoverageStore

_TIMEOUT = 300


def _safe_env() -> Dict[str, str]:
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except (ImportError, AttributeError):
        return dict(os.environ)


def collect_gcov(build_dir, env: Optional[Dict[str, str]] = None) -> Dict[str, Set[int]]:
    """Run ``gcov`` on every ``.gcda`` under ``build_dir`` and parse the result.
    Returns ``{source_path: set(executed_lines)}``. Runs gcov in each artifact
    dir (so the compiled-in source path resolves), collects only the ``.gcov``
    it newly produced, parses, and cleans those up."""
    from .parsers import parse_gcov

    build = Path(build_dir)
    gcda = list(build.rglob("*.gcda"))
    if not gcda:
        return {}
    env = env or _safe_env()
    out: Dict[str, Set[int]] = {}
    by_dir: Dict[Path, list] = {}
    for f in gcda:
        by_dir.setdefault(f.parent, []).append(f.name)
    for d, names in by_dir.items():
        pre = set(d.glob("*.gcov"))
        try:
            subprocess.run(["gcov", *names], cwd=str(d), env=env,
                           capture_output=True, timeout=_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        produced = [g for g in d.glob("*.gcov") if g not in pre]
        for g in produced:
            for src, lines in parse_gcov(g).items():
                out.setdefault(src, set()).update(lines)
        for g in produced:                 # best-effort: don't pollute the build
            try:
                g.unlink()
            except OSError:
                pass
    return out


def collect_llvm(binary, profdata, env: Optional[Dict[str, str]] = None) -> Dict[str, Set[int]]:
    """Run ``llvm-cov export -format=lcov`` for an instrumented ``binary`` +
    ``.profdata`` and parse the emitted lcov. Returns
    ``{source_path: set(executed_lines)}``."""
    from .parsers import parse_lcov

    env = env or _safe_env()
    try:
        r = subprocess.run(
            ["llvm-cov", "export", "-format=lcov",
             f"-instr-profile={profdata}", str(binary)],
            capture_output=True, text=True, env=env, timeout=_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return {}
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    fd, tmp = tempfile.mkstemp(suffix=".info")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(r.stdout)
        return parse_lcov(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def collect_addr2line(binary, addresses, env: Optional[Dict[str, str]] = None) -> Dict[str, Set[int]]:
    """Resolve a set of runtime ``addresses`` to source lines via the binary's
    DWARF debug info (``addr2line``). Returns ``{source_path: set(lines)}``.

    This is the binary-coverage → source primitive (the honest "AFL→source via
    DWARF" path): a coverage *address* set — from drcov / sancov / a fuzzer /
    QEMU-mode — is mapped to source and then marked exactly like gcov/lcov, so
    it lands in the source-anchored store with no new representation. Only
    useful when the binary has DWARF *and* a source inventory exists to map
    into; stripped binaries resolve to ``??`` and yield nothing here (that's the
    function-level / r2 case — a separate binary-inventory extension)."""
    addrs = [a for a in addresses if a is not None]
    if not addrs:
        return {}
    env = env or _safe_env()
    out: Dict[str, Set[int]] = {}
    for chunk in _chunks(addrs, 1000):          # avoid arg-length limits
        args = ["addr2line", "-e", str(binary)] + [
            hex(a) if isinstance(a, int) else str(a) for a in chunk]
        try:
            r = subprocess.run(args, capture_output=True, text=True, env=env,
                               timeout=_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            # "path:line", "path:line (discriminator N)", "??:0", "path:?"
            line = line.strip()
            path, sep, rest = line.rpartition(":")
            if not sep or not path or path == "??":
                continue
            num = rest.split()[0] if rest else ""
            # addr2line emits ":0" for "no line info" — lines are 1-based, so a
            # 0 is not real coverage; drop it (avoids a junk [0,0] mark).
            if num.isdigit() and int(num) > 0:
                out.setdefault(path, set()).add(int(num))
    return out


def import_addresses(
    store: CoverageStore, binary, addresses, checklist: Dict[str, Any],
    tool: str = "bincov",
) -> int:
    """Resolve binary-coverage ``addresses`` to source (DWARF) and mark them.
    ``tool`` labels the tracer (e.g. ``drcov``/``sancov``/``afl``) — all
    runtime-category."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_addr2line(binary, addresses), checklist, tool)


def parse_drcov(path) -> Dict[str, Dict[str, Any]]:
    """Parse a drcov coverage file (DynamoRIO / Frida / AFL-QEMU / Lighthouse).

    Returns ``{module_path: {"base": int, "offsets": set(bb_start_offsets)}}`` —
    addresses, not source (resolved later by :func:`collect_drcov`). drcov is a
    text header (module table) followed by a packed-binary BB table of
    ``<IHH>`` records (module-relative start u32, size u16, module_id u16)."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return {}
    marker = b"BB Table:"
    idx = raw.find(marker)
    if idx < 0:
        return {}
    modules: Dict[int, tuple] = {}                 # id -> (base, path)
    in_mod = False
    for line in raw[:idx].decode("utf-8", "replace").splitlines():
        s = line.strip()
        if s.startswith("Module Table:"):
            in_mod = True
            continue
        if s.startswith("Columns:") or not s:
            continue
        if in_mod and s[0].isdigit():
            parts = [p.strip() for p in s.split(",")]
            try:
                mid, base = int(parts[0]), int(parts[1], 0)
            except (ValueError, IndexError):
                continue
            modules[mid] = (base, parts[-1])
    eol = raw.find(b"\n", idx)
    if eol < 0:
        return {}
    try:
        count = int(raw[idx + len(marker):eol].split(b"bbs")[0].strip())
    except ValueError:
        count = None
    blob = raw[eol + 1:]
    avail = len(blob) // 8
    n = avail if count is None else min(count, avail)
    out: Dict[str, Dict[str, Any]] = {}
    for i in range(n):
        start, _size, mid = struct.unpack_from("<IHH", blob, i * 8)
        if mid in modules:
            base, modpath = modules[mid]
            out.setdefault(modpath, {"base": base, "offsets": set()})["offsets"].add(start)
    return out


def collect_drcov(drcov_path, binary, env: Optional[Dict[str, str]] = None) -> Dict[str, Set[int]]:
    """drcov file + binary → ``{source_path: set(lines)}`` via DWARF.

    Picks the module matching ``binary`` (by basename) — or all modules if none
    match — and resolves each BB offset BOTH as a PIE file-vaddr (offset itself)
    AND as a non-PIE vaddr (module base + offset); the wrong interpretation
    lands out of range and ``addr2line`` drops it, so the union is correct
    without needing to know whether the binary is PIE."""
    mods = parse_drcov(drcov_path)
    if not mods:
        return {}
    binname = Path(binary).name
    picked = {p: v for p, v in mods.items() if Path(p).name == binname} or mods
    addrs: Set[int] = set()
    for v in picked.values():
        base = v["base"]
        for o in v["offsets"]:
            addrs.add(o)
            addrs.add(base + o)
    return collect_addr2line(binary, addrs, env)


def import_drcov(
    store: CoverageStore, drcov_path, binary, checklist: Dict[str, Any],
    tool: str = "drcov",
) -> int:
    """Resolve a drcov file against ``binary`` (DWARF) and mark it."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_drcov(drcov_path, binary, env=None), checklist, tool)


# LLVM SanitizerCoverage .sancov: 8-byte magic then a flat PC array.
_SANCOV_MAGIC64 = 0xC0BFFFFFFFFFFF64
_SANCOV_MAGIC32 = 0xC0BFFFFFFFFFFF32


def parse_sancov(path) -> Set[int]:
    """Parse an LLVM ``.sancov`` file (``-fsanitize-coverage=trace-pc-guard``
    dump) into its set of covered PCs. 8-byte magic selects 64/32-bit PC width;
    the remainder is a flat little-endian PC array."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return set()
    if len(raw) < 8:
        return set()
    magic = struct.unpack_from("<Q", raw, 0)[0]
    if magic == _SANCOV_MAGIC64:
        width, fmt = 8, "<Q"
    elif magic == _SANCOV_MAGIC32:
        width, fmt = 4, "<I"
    else:
        return set()
    pcs: Set[int] = set()
    for off in range(8, 8 + ((len(raw) - 8) // width) * width, width):
        pcs.add(struct.unpack_from(fmt, raw, off)[0])
    return pcs


def collect_sancov(sancov_path, binary, base: int = 0,
                   env: Optional[Dict[str, str]] = None) -> Dict[str, Set[int]]:
    """sancov file + binary → ``{source_path: set(lines)}`` via DWARF.

    sancov records absolute PCs. For a non-PIE binary the PC is the file vaddr
    (``base=0``); for a PIE run pass the module ``base`` so ``PC - base`` is the
    file vaddr. Both candidates are tried (the wrong one lands out of range and
    addr2line drops it)."""
    pcs = parse_sancov(sancov_path)
    if not pcs:
        return {}
    addrs: Set[int] = set()
    for p in pcs:
        addrs.add(p)
        if base and p >= base:
            addrs.add(p - base)
    return collect_addr2line(binary, addrs, env)


def import_sancov(
    store: CoverageStore, sancov_path, binary, checklist: Dict[str, Any],
    base: int = 0, tool: str = "sancov",
) -> int:
    """Resolve a .sancov file against ``binary`` (DWARF) and mark it."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_sancov(sancov_path, binary, base), checklist, tool)


def import_gcov_build(
    store: CoverageStore, build_dir, checklist: Dict[str, Any], tool: str = "gcov",
) -> int:
    """Collect gcov coverage from a build dir and mark it into the store."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_gcov(build_dir), checklist, tool)


def import_llvm(
    store: CoverageStore, binary, profdata, checklist: Dict[str, Any],
    tool: str = "llvm-cov",
) -> int:
    """Collect llvm-cov coverage for a binary + profdata and mark it."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_llvm(binary, profdata), checklist, tool)
