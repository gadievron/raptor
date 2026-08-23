"""Binary loading — the one right way to open an ELF for symex.

Wraps ``angr.Project`` with:

  * ``auto_load_libs=False`` — no libc/ld auto-load. Deterministic +
    fast; consumers that need libc-modelled behaviour can pass
    ``SimProcedure`` hooks after load.
  * Log suppression — angr's default logging is chatty; we drop
    ``angr.*``, ``cle.*``, ``pyvex.*`` to WARNING so consumer scripts
    stay readable.
  * Symbol snapshot capture — populates :class:`BinaryInfo.symbols`
    so a consumer can query names without touching the ``Project``.

Consumers should never construct ``angr.Project`` directly. Every
integration point takes a ``Path`` and produces a
:class:`BinaryInfo`.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Any

from core.symbolic._types import BinaryInfo


def _suppress_angr_logging() -> None:
    """Drop angr / cle / pyvex chatter to WARNING.

    Idempotent — called on every ``load_binary`` invocation; setting
    the same level repeatedly is a no-op. Doesn't touch the root
    logger; only the noisy sub-loggers.
    """
    for name in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(name).setLevel(logging.WARNING)


def load_binary(binary_path: Path, *, auto_load_libs: bool = False) -> BinaryInfo:
    """Load ``binary_path`` for symbolic execution.

    Returns a :class:`BinaryInfo` snapshot. The underlying
    ``angr.Project`` is created but not returned; consumers work
    through the higher-level operations
    (``find_reaching_input``, planned ``path_constraints``, etc.).

    Args:
        binary_path: Path to an ELF file. Must exist + be readable.
        auto_load_libs: Passed through to ``angr.Project``. Default
            False for speed and determinism. Set True when a
            consumer NEEDS libc-modelled behaviour beyond angr's
            SimProcedure defaults.

    Raises:
        FileNotFoundError: binary_path doesn't exist.
        ValueError: binary is not an ELF (angr's loader raises;
            re-raised as ValueError for consumer clarity).
    """
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        raise FileNotFoundError(f"binary not found: {binary_path}")

    # Fallback when angr is missing: pyelftools provides everything
    # BinaryInfo needs (arch, bits, entry, is_pie, symbols). The full
    # angr.Project isn't reachable from BinaryInfo anyway — consumers
    # that need the project handle for symex must independently gate
    # on angr_available() and see the primitive's unavailable_result.
    from core.symbolic._availability import angr_available
    if not angr_available():
        return _load_binary_pyelftools(binary_path)

    try:
        project = _open_project(binary_path, auto_load_libs=auto_load_libs)
    except Exception as exc:
        raise ValueError(
            f"angr failed to load {binary_path}: {type(exc).__name__}: {exc}"
        ) from exc

    # Capture symbol snapshot. Only include defined symbols with a
    # non-external address — imports / weak-undefined show up in the
    # loader with rebased_addr==None or an extern-region address.
    symbols: dict[str, int] = {}
    for sym in project.loader.symbols:
        if not sym.name:
            continue
        if sym.is_import:
            continue
        addr = sym.rebased_addr
        if addr is None:
            continue
        symbols[sym.name] = addr

    # PIE detection via the main ELF header type.
    is_pie = _detect_pie(project)

    return BinaryInfo(
        path=binary_path,
        arch_name=project.arch.name,
        bits=project.arch.bits,
        entry_point=project.entry,
        is_pie=is_pie,
        symbols=symbols,
    )


def _load_binary_pyelftools(binary_path: Path) -> BinaryInfo:
    """Angr-free fallback: build BinaryInfo purely from pyelftools.

    Same output shape as the angr path so consumers can't tell the
    difference. Only difference is the arch_name string — pyelftools
    uses 'x64'/'x86' while angr uses 'AMD64'/'X86'; we translate to
    the angr names for consistency.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise ValueError(
            f"pyelftools also unavailable — can't load {binary_path} "
            f"without either angr or pyelftools: {exc}"
        ) from exc

    _ARCH_MAP = {
        "x64": "AMD64",
        "x86": "X86",
        "AArch64": "AARCH64",
        "ARM": "ARMEL",
    }
    with binary_path.open("rb") as f:
        elf = ELFFile(f)
        arch = _ARCH_MAP.get(elf.get_machine_arch(), elf.get_machine_arch())
        bits = elf.elfclass
        entry = elf.header["e_entry"]
        is_pie = elf.header["e_type"] == "ET_DYN"
        symbols: dict[str, int] = {}
        for section in elf.iter_sections():
            if section.name not in (".symtab", ".dynsym"):
                continue
            for sym in section.iter_symbols():
                name = sym.name
                if not name:
                    continue
                addr = sym["st_value"]
                if addr == 0:
                    continue  # undefined / import
                # For PIE binaries, addresses in the symtab are
                # relative to the base — angr's "rebased_addr" would
                # add the load base. Without a load base at hand
                # (there's no live project), we return the file-
                # relative address; consumers should be aware.
                symbols[name] = addr
    return BinaryInfo(
        path=binary_path,
        arch_name=arch,
        bits=bits,
        entry_point=entry,
        is_pie=is_pie,
        symbols=symbols,
    )


def _detect_pie(project: "Any") -> bool:
    """Detect PIE (position-independent executable) from angr's loader.

    ``cle`` exposes the ELF header; ``Type: DYN`` is PIE, ``Type:
    EXEC`` is non-PIE. Fall back to False (conservative — treat as
    non-PIE if we can't tell) rather than raising, so a corrupt or
    unusual ELF doesn't take out the loader.
    """
    try:
        main = project.loader.main_object
        # cle.ELF has ``pic`` (position-independent-code) attribute.
        pic = getattr(main, "pic", None)
        if isinstance(pic, bool):
            return pic
    except Exception:  # noqa: BLE001 — best-effort attribute access
        pass
    return False


# Project cache: (resolved_path, mtime_ns, auto_load_libs) → Project.
# angr.Project load is 50-200ms + CFGFast (when built) is seconds; a
# multi-primitive workflow on the same binary re-uses the same load.
# Keyed on mtime so an operator rebuild invalidates cleanly. Bounded
# at _CACHE_LIMIT entries to prevent unbounded growth in long-running
# processes; LRU eviction via ordered dict.
_CACHE_LIMIT = 16
_project_cache: OrderedDict[tuple, object] = OrderedDict()
_cache_lock = Lock()


def clear_cache() -> None:
    """Drop all cached Project handles. Called by tests to isolate
    from prior loads + rarely by operators after a large-scale
    rebuild sweep."""
    with _cache_lock:
        _project_cache.clear()


# Internal — used by other core.symbolic submodules that DO need the
# raw Project handle (e.g. _reach.py). Kept underscore-prefixed so
# consumers can't accidentally couple to it.
def _open_project(binary_path: Path, *, auto_load_libs: bool = False):
    """Internal helper: return a cached ``angr.Project`` for a binary.

    Cache hit: sub-millisecond return, no angr work. Cache miss:
    full angr.Project load, entry cached for future calls. Cache
    key includes mtime, so a rebuild triggers a reload naturally.

    Only for use inside ``core.symbolic``. External callers use
    :func:`load_binary` to get a :class:`BinaryInfo` snapshot.
    """
    _suppress_angr_logging()
    resolved = binary_path.resolve()
    try:
        mtime_ns = resolved.stat().st_mtime_ns
    except OSError:
        # Race between resolve + stat, or path unreadable. Fall
        # through to fresh load; angr will raise if truly broken.
        mtime_ns = 0
    key = (resolved, mtime_ns, auto_load_libs)

    with _cache_lock:
        hit = _project_cache.get(key)
        if hit is not None:
            # LRU touch — move to end so the most-recently-used
            # entry survives the next eviction.
            _project_cache.move_to_end(key)
            return hit

    # Miss — build outside the lock (angr load is slow; other
    # threads can hit unrelated cache entries meanwhile).
    import angr
    project = angr.Project(str(resolved), auto_load_libs=auto_load_libs)

    with _cache_lock:
        # Double-check: another thread may have populated the same
        # key concurrently while we were loading. If so, drop ours
        # and reuse theirs to keep identity stable across callers.
        existing = _project_cache.get(key)
        if existing is not None:
            _project_cache.move_to_end(key)
            return existing
        _project_cache[key] = project
        if len(_project_cache) > _CACHE_LIMIT:
            # Evict oldest.
            _project_cache.popitem(last=False)
    return project
