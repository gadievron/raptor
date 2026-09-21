"""Runtime-coverage collection (Phase 4): turn raw coverage *build artifacts*
into store marks by running the coverage tool, then reusing the parsers.

`import_runtime` (importer.py) imports already-produced artifacts (`.gcov` /
`.info` / coverage.json). This module runs the tool to *produce* them from a
coverage build:
- ``collect_gcov(build_dir)`` runs ``gcov`` on the ``.gcda``/``.gcno`` under a
  build dir → ``.gcov`` → :func:`parse_gcov`.
- ``collect_llvm(binary, profdata)`` runs ``llvm-cov export -format=lcov`` →
  :func:`parse_lcov`.

Subprocesses run under the full sandbox (``core.sandbox.run``: network
blocked, Landlock, rlimits — the same posture the binary oracle gives
binutils, and for the same reason: gcov/llvm-cov/addr2line parse
attacker-influenced build artifacts and their parsers have CVE
history), with the sanitised env and list-form args (never
shell-interpolate scanned-repo paths); tolerant — a tool failure (or a
sandbox that cannot engage: never run these tools unsandboxed over
hostile artifacts) yields ``{}``, never raises.
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


import logging
from core.security.env_sanitisation import safe_subprocess_env

logger = logging.getLogger(__name__)


# Per-.gcda cap on gcov report size. A legitimate report is
# proportional to the source file; anything past this is a crafted
# artifact — refuse rather than keep processing it. Enforced on the
# redirected output FILE before it is read, so a crafted artifact
# cannot balloon this process's memory either (the pre-fix
# capture_output shape buffered the whole report before checking).
_MAX_GCOV_STDOUT = 64 * 1024 * 1024

# Read budget for binary coverage artifacts (drcov / sancov dumps).
# They arrive from instrumented target runs — attacker-influenced by
# definition — and were read wholesale (a 4 GiB sancov materialises
# ~30 GiB of Python ints). Same 64 MiB ceiling class as the gcov
# stdout cap above; an over-budget artifact refuses (truncated PC
# tables would silently misattribute coverage).
_MAX_BINARY_COV_BYTES = 64 * 1024 * 1024


def _sandboxed_run(argv: list[str], *, target: str | None,
                   env: dict[str, str],
                   readable_paths: list[str] | None = None,
                   output: str | None = None,
                   cwd: str | None = None):
    """Run one collector tool under the full sandbox; ``None`` on any
    failure INCLUDING a sandbox that cannot engage — the artifacts the
    tool parses are attacker-influenced, so degrading to an
    unsandboxed run is never an option (fail closed to "no coverage").
    """
    from core.sandbox import run as _sandbox_run
    from core.sandbox.errors import SandboxSetupError
    try:
        return _sandbox_run(
            argv, block_network=True, target=target,
            readable_paths=readable_paths, output=output,
            env=env, strict_env=True, cwd=cwd,
            capture_output=True, timeout=_TIMEOUT)
    except SandboxSetupError as e:
        logger.warning(
            "coverage collect: sandbox could not engage for %s — "
            "refusing to run it unsandboxed over untrusted build "
            "artifacts (%s)", argv[0], e)
        return None
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug("coverage collect: %s failed: %s", argv[0], e)
        return None

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
    and parsed from a private temp dir.

    gcov runs under the full sandbox with ``build_dir`` as the read
    grant; its stdout is redirected to a file in the sandbox-writable
    temp dir (the sandbox runners capture rather than stream) and
    size-checked BEFORE being read, so a crafted artifact can balloon
    neither this process's memory nor the parse. Residual: on hosts
    where the mount-ns backend engages, sources OUTSIDE ``build_dir``
    (out-of-tree builds recording ``../``-relative paths) are not
    visible to gcov, which then omits those per-line rows — the safe
    direction (less coverage claimed, never wrong coverage)."""
    from .parsers import parse_gcov

    build = Path(build_dir)
    gcda = list(build.rglob("*.gcda"))
    if not gcda:
        return {}
    env = dict(env) if env else safe_subprocess_env()
    out: dict[str, set[int]] = {}
    for f in gcda:
        with tempfile.TemporaryDirectory(prefix="raptor-gcov-") as td:
            out_path = os.path.join(td, "stdout.txt")
            run_env = dict(env)
            run_env["RAPTOR_GCOV_OUT"] = out_path
            # The redirect happens inside bash via "$@"/env so
            # attacker-influenced paths never enter a shell string
            # (same shape as the binary oracle's stream helper).
            wrapper = ["bash", "-c", 'exec "$@" > "$RAPTOR_GCOV_OUT"',
                       "gcov-run",
                       "gcov", "-t", "-o", str(f.parent), str(f)]
            r = _sandboxed_run(wrapper, target=str(build), output=td,
                               env=run_env, cwd=str(f.parent))
            if r is None or r.returncode != 0:
                continue
            try:
                if os.stat(out_path).st_size > _MAX_GCOV_STDOUT:
                    continue
                text = Path(out_path).read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not text:
                continue
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
    ``{source_path: set(executed_lines)}``.

    Sandboxed like :func:`collect_gcov` (the binary and profdata are
    attacker-influenced artifacts): the binary's directory is the read
    grant, the profdata's directory an extra readable path."""
    from .parsers import parse_lcov

    env = dict(env) if env else safe_subprocess_env()
    try:
        target = str(Path(binary).resolve().parent)
        prof_dir = str(Path(profdata).resolve().parent)
    except OSError:
        return {}
    r = _sandboxed_run(
        ["llvm-cov", "export", "-format=lcov",
         f"-instr-profile={profdata}", str(binary)],
        target=target, readable_paths=[prof_dir], env=env)
    if r is None or r.returncode != 0:
        return {}
    r_stdout = (r.stdout or b"").decode("utf-8", "replace")
    if not r_stdout.strip():
        return {}
    fd, tmp = tempfile.mkstemp(suffix=".info")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(r_stdout)
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
    env = dict(env) if env else safe_subprocess_env()
    try:
        target = str(Path(binary).resolve().parent)
    except OSError:
        return {}
    out: dict[str, set[int]] = {}
    for chunk in _chunks(addrs, 1000):          # avoid arg-length limits
        args = ["addr2line", "-e", str(binary)] + [
            hex(a) if isinstance(a, int) else str(a) for a in chunk]
        # Sandboxed: addr2line parses the artifact's DWARF (untrusted
        # bytes) — same posture as the binary oracle's binutils calls.
        r = _sandboxed_run(args, target=target, env=env)
        if r is None or r.returncode != 0:
            continue
        for line in (r.stdout or b"").decode("utf-8", "replace").splitlines():
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


def _read_binary_cov(path) -> bytes | None:
    """Byte-budgeted read of a coverage artifact; None on refusal."""
    from core.source import read_bytes_capped
    read = read_bytes_capped(path, _MAX_BINARY_COV_BYTES)
    if read is None:
        return None
    raw, truncated = read
    if truncated:
        logger.warning(
            "coverage artifact %s exceeds %d bytes; refusing rather "
            "than importing a truncated PC table", path,
            _MAX_BINARY_COV_BYTES)
        return None
    return raw


def parse_drcov(path) -> dict[str, dict[str, Any]]:
    """Parse a drcov coverage file (DynamoRIO / Frida / AFL-QEMU / Lighthouse).

    Returns ``{module_path: {"base": int, "offsets": set(bb_start_offsets)}}`` —
    addresses, not source (resolved later by :func:`collect_drcov`). drcov is a
    text header (module table) followed by a packed-binary BB table of
    ``<IHH>`` records (module-relative start u32, size u16, module_id u16)."""
    raw = _read_binary_cov(path)
    if raw is None:
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
            # Module-table layout is versioned: v2 rows are
            # ``id, base, ...`` (what the row parser below assumes),
            # v3/v4 move ``containing_id`` into column 1 and rename
            # ``base`` to ``start`` — misreading those silently
            # resolves every non-PIE offset out of range and imports
            # ZERO coverage. Honest-refuse instead: warn with the
            # version and return nothing. Legacy tables with no
            # ``version`` marker keep the v2 row shape.
            m = re.search(r"version\s+(\d+)", s)
            if m and int(m.group(1)) != 2:
                logger.warning(
                    "drcov %s: unsupported module-table version %s "
                    "(only v2 rows are parsed); refusing rather than "
                    "misattributing coverage", path, m.group(1),
                )
                return {}
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
    raw = _read_binary_cov(path)
    if raw is None or len(raw) < 8:
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
