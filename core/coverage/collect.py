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
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, TYPE_CHECKING


if TYPE_CHECKING:
    from core.coverage.store import CoverageStore

_TIMEOUT = 300


def _safe_env() -> dict[str, str]:
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except (ImportError, AttributeError):
        return dict(os.environ)


# Per-.gcda cap on gcov report size. A legitimate report is
# proportional to the source file; anything past this is a crafted
# artifact — refuse rather than keep processing it.
_MAX_GCOV_STDOUT = 64 * 1024 * 1024

# A gcov text report starts each per-source section with the
# ``Source:`` metadata row (lineno 0).
_GCOV_SOURCE_ROW = re.compile(r"^\s*-:\s*0:Source:")


def _split_gcov_sections(text: str) -> list:
    """Split a concatenated ``gcov --stdout`` report into per-source
    sections (one ``.gcda`` covers every source that contributed to
    the object: the main file plus headers with inline functions)."""
    sections: list = []
    current: list = []
    for line in text.splitlines(keepends=True):
        if _GCOV_SOURCE_ROW.match(line) and current:
            sections.append("".join(current))
            current = []
        current.append(line)
    if current:
        sections.append("".join(current))
    return sections


def collect_gcov(build_dir, env: dict[str, str] | None = None) -> dict[str, set[int]]:
    """Run ``gcov`` on every ``.gcda`` under ``build_dir`` and parse the result.
    Returns ``{source_path: set(executed_lines)}``.

    ``build_dir`` is ATTACKER-INFLUENCED (a hostile repo's build tree,
    or artifacts it shipped), so gcov must never write into it: in
    file mode gcov creates ``<src>.gcov`` outputs named after the
    artifacts' recorded source names in its CWD, and a pre-planted
    symlink at such a name redirects the write to an arbitrary host
    path. Run gcov in stdout mode (``-t``) instead — the report goes
    to the pipe and NOTHING lands on disk — one ``.gcda`` at a time
    (absolute path, list args). The cwd stays at the artifact dir
    purely so the recorded relative source paths resolve (without
    source text gcov omits the per-line rows); with ``-t`` that cwd
    is never written to. Sections are split per ``Source:`` header
    and parsed from a private temp dir."""
    from .parsers import parse_gcov

    build = Path(build_dir)
    gcda = list(build.rglob("*.gcda"))
    if not gcda:
        return {}
    env = env or _safe_env()
    out: dict[str, set[int]] = {}
    for f in gcda:
        try:
            r = subprocess.run(
                ["gcov", "-t", "-o", str(f.parent), str(f)],
                cwd=str(f.parent), env=env,
                capture_output=True, timeout=_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode != 0 or not r.stdout:
            continue
        if len(r.stdout) > _MAX_GCOV_STDOUT:
            continue
        text = r.stdout.decode("utf-8", "replace")
        with tempfile.TemporaryDirectory(prefix="raptor-gcov-") as td:
            tdp = Path(td)
            for i, section in enumerate(_split_gcov_sections(text)):
                (tdp / f"section-{i:04d}.gcov").write_text(
                    section, encoding="utf-8")
            for src, lines in parse_gcov(tdp).items():
                out.setdefault(src, set()).update(lines)
    return out


def collect_llvm(binary, profdata, env: dict[str, str] | None = None) -> dict[str, set[int]]:
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


def collect_addr2line(binary, addresses, env: dict[str, str] | None = None) -> dict[str, set[int]]:
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
    out: dict[str, set[int]] = {}
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
    store: CoverageStore, binary, addresses, checklist: dict[str, Any],
    tool: str = "bincov",
) -> int:
    """Resolve binary-coverage ``addresses`` to source (DWARF) and mark them.
    ``tool`` labels the tracer (e.g. ``drcov``/``sancov``/``afl``) — all
    runtime-category."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_addr2line(binary, addresses), checklist, tool)


def parse_drcov(path) -> dict[str, dict[str, Any]]:
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
    modules: dict[int, tuple] = {}                 # id -> (base, path)
    in_mod = False
    for line in raw[:idx].decode("utf-8", "replace").splitlines():
        s = line.strip()
        if s.startswith("Module Table:"):
            in_mod = True
            continue
        if s.startswith("Columns:") or not s:
            continue
        if in_mod and s[0].isdigit():
            # drcov v2: id, base, end, entry, checksum, timestamp, path
            # maxsplit=6 so commas inside the path field are preserved.
            parts = [p.strip() for p in s.split(",", 6)]
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
    out: dict[str, dict[str, Any]] = {}
    for i in range(n):
        start, _size, mid = struct.unpack_from("<IHH", blob, i * 8)
        if mid in modules:
            base, modpath = modules[mid]
            out.setdefault(modpath, {"base": base, "offsets": set()})["offsets"].add(start)
    return out


def collect_drcov(drcov_path, binary, env: dict[str, str] | None = None) -> dict[str, set[int]]:
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
    addrs: set[int] = set()
    for v in picked.values():
        base = v["base"]
        for o in v["offsets"]:
            addrs.add(o)
            addrs.add(base + o)
    return collect_addr2line(binary, addrs, env)


def import_drcov(
    store: CoverageStore, drcov_path, binary, checklist: dict[str, Any],
    tool: str = "drcov",
) -> int:
    """Resolve a drcov file against ``binary`` (DWARF) and mark it."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_drcov(drcov_path, binary, env=None), checklist, tool)


# LLVM SanitizerCoverage .sancov: 8-byte magic then a flat PC array.
_SANCOV_MAGIC64 = 0xC0BFFFFFFFFFFF64
_SANCOV_MAGIC32 = 0xC0BFFFFFFFFFFF32


def parse_sancov(path) -> set[int]:
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
    pcs: set[int] = set()
    for off in range(8, 8 + ((len(raw) - 8) // width) * width, width):
        pcs.add(struct.unpack_from(fmt, raw, off)[0])
    return pcs


def collect_sancov(sancov_path, binary, base: int = 0,
                   env: dict[str, str] | None = None) -> dict[str, set[int]]:
    """sancov file + binary → ``{source_path: set(lines)}`` via DWARF.

    sancov records absolute PCs. For a non-PIE binary the PC is the file vaddr
    (``base=0``); for a PIE run pass the module ``base`` so ``PC - base`` is the
    file vaddr. Both candidates are tried (the wrong one lands out of range and
    addr2line drops it)."""
    pcs = parse_sancov(sancov_path)
    if not pcs:
        return {}
    addrs: set[int] = set()
    for p in pcs:
        addrs.add(p)
        if base and p >= base:
            addrs.add(p - base)
    return collect_addr2line(binary, addrs, env)


def import_sancov(
    store: CoverageStore, sancov_path, binary, checklist: dict[str, Any],
    base: int = 0, tool: str = "sancov",
) -> int:
    """Resolve a .sancov file against ``binary`` (DWARF) and mark it."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_sancov(sancov_path, binary, base), checklist, tool)


def import_gcov_build(
    store: CoverageStore, build_dir, checklist: dict[str, Any], tool: str = "gcov",
) -> int:
    """Collect gcov coverage from a build dir and mark it into the store."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_gcov(build_dir), checklist, tool)


def import_llvm(
    store: CoverageStore, binary, profdata, checklist: dict[str, Any],
    tool: str = "llvm-cov",
) -> int:
    """Collect llvm-cov coverage for a binary + profdata and mark it."""
    from .importer import mark_runtime
    return mark_runtime(store, collect_llvm(binary, profdata), checklist, tool)
