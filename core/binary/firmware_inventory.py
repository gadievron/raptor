"""ELF inventory over an extracted firmware filesystem root.

Walks the tree, classifies every regular file through
:func:`core.binary.elf.parse_elf` (the stdlib ELF parser — handles
both endianness modes and is hardened against malformed/hostile
inputs), and returns a prioritised inventory: which binaries exist,
what architecture they target, and which look security-relevant
(network daemons, CGI handlers, credential stores).

Consumed by the firmware scan mode in
``packages/static-analysis/scanner.py`` and written to
``firmware-inventory.json`` in the run output directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from core.binary.elf import parse_elf
from core.logging import get_logger

logger = get_logger()

# (family, bits) → operator-facing architecture name. Internally
# core.binary.elf reports the radare2 family convention (arch="x86"
# bits=64); the inventory surfaces the conventional toolchain name
# because that is what operators feed to cross-compilers, QEMU and
# Ghidra language IDs.
_ARCH_NAMES: dict[tuple[str, int], str] = {
    ("x86", 32): "x86",
    ("x86", 64): "x86_64",
    ("arm", 32): "arm",
    ("arm", 64): "aarch64",
    ("mips", 32): "mips",
    ("mips", 64): "mips64",
    ("ppc", 32): "ppc",
    ("ppc", 64): "ppc64",
    ("riscv", 32): "riscv",
    ("riscv", 64): "riscv64",
    ("s390", 32): "s390",
    ("s390", 64): "s390x",
}

# Filename-substring seed for high-value targets in embedded Linux
# firmware: network-facing daemons, CGI surfaces, and config/cred
# stores. A seed heuristic only — deeper per-binary prioritisation
# belongs to the /binary investigation surface.
_HIGH_VALUE_NAMES: tuple[str, ...] = (
    "httpd", "lighttpd", "uhttpd", "nginx", "apache",
    "cgi", "telnetd", "sshd", "dropbear", "busybox",
    "upnpd", "miniupnpd", "boa", "goahead",
    "nvram", "cfgd", "ated", "wpa_supplicant",
)

HIGH_VALUE_SCORE = 10


def _arch_name(family: str, bits: int, endianness: str) -> str:
    """Operator-facing arch name for a parsed (family, bits,
    endianness) triple. MIPS and ARM are the families where firmware
    toolchains name the endianness variant explicitly."""
    if family == "unknown":
        return "unknown"
    name = _ARCH_NAMES.get((family, bits), f"{family}{bits}")
    if endianness == "little" and family == "mips":
        return name + "el"      # mipsel / mips64el
    if endianness == "big" and family == "arm":
        return "armeb" if bits == 32 else "aarch64_be"
    return name


def _interest_score(name: str) -> int:
    """Score a binary filename by security interest (higher = more
    interesting). 10 = high-value target, 5 = network-adjacent,
    1 = baseline."""
    name_lower = name.lower()
    for substr in _HIGH_VALUE_NAMES:
        if substr in name_lower:
            return HIGH_VALUE_SCORE
    if name_lower.endswith(".cgi"):
        return HIGH_VALUE_SCORE
    if any(x in name_lower for x in ("web", "http", "net", "wan", "lan")):
        return 5
    return 1


def inventory_firmware(firmware_root: Path) -> dict[str, Any]:
    """Walk ``firmware_root``, find all ELF binaries, and return an
    inventory sorted by interest score then size.

    Symlinks are skipped: extracted firmware routinely carries
    absolute symlinks (``/bin/sh`` → busybox) whose targets resolve
    on the *host* filesystem — following them would inventory host
    binaries as firmware content.

    Returns a dict with:
      - ``binaries``: list of {path, size_bytes, arch, interest_score}
        (path is relative to ``firmware_root``)
      - ``detected_arch``: most common architecture across all ELFs
        (or ``"unknown"`` when none parse)
      - ``total_elfs``: count
      - ``high_value_targets``: subset with
        ``interest_score >= HIGH_VALUE_SCORE``
    """
    binaries: list[dict[str, Any]] = []
    arch_counts: dict[str, int] = {}

    # os.walk(followlinks=False), not rglob: pathlib's ``**`` recursion
    # follows *directory* symlinks before Python 3.13, so a hostile
    # ``lnk -> /`` in the root would walk the host filesystem (same
    # fix as core.hash.sha256_tree). Sorting dirnames/filenames keeps
    # the walk deterministic without materializing the whole tree.
    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(firmware_root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            candidates.append(Path(dirpath) / name)

    for p in candidates:
        if p.is_symlink() or not p.is_file():
            continue
        meta = parse_elf(p)
        if meta is None:
            continue
        arch = _arch_name(meta.arch, meta.bits, meta.endianness)
        try:
            size = p.stat().st_size
        except OSError as e:
            logger.debug("firmware inventory: stat failed for %s: %s", p, e)
            continue
        binaries.append({
            "path": str(p.relative_to(firmware_root)),
            "size_bytes": size,
            "arch": arch,
            "endianness": meta.endianness,
            "interest_score": _interest_score(p.name),
        })
        if arch != "unknown":
            arch_counts[arch] = arch_counts.get(arch, 0) + 1

    binaries.sort(key=lambda b: (-b["interest_score"], -b["size_bytes"]))

    detected_arch = (
        max(arch_counts, key=lambda a: arch_counts[a]) if arch_counts else "unknown"
    )

    return {
        "binaries": binaries,
        "detected_arch": detected_arch,
        "total_elfs": len(binaries),
        "high_value_targets": [
            b for b in binaries if b["interest_score"] >= HIGH_VALUE_SCORE
        ],
    }
