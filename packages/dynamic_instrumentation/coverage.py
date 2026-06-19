"""Frida Stalker coverage → drcov → RAPTOR CoverageStore.

The coverage agent (``agents.coverage_agent``) emits a module table and
basic-block start/end addresses as ``send()`` events. This module turns those
into a standard **drcov** file (the format ``core.coverage.collect.parse_drcov``
already ingests - its docstring names Frida as a producer) and then resolves
it to source via the existing ``import_drcov`` path. No new resolver is
written: Frida coverage rides the same DWARF-resolution + store-marking
machinery as DynamoRIO/AFL-QEMU drcov.
"""

from __future__ import annotations

import json
import logging
import struct
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


def _load_events(events_path: str) -> Tuple[List[dict], List[Tuple[int, int]]]:
    """Return (modules, block_addrs) from the driver's JSONL event file.

    ``modules`` = [{name, base(int), size(int), path}]; ``block_addrs`` =
    list of (start_addr, end_addr) ints (absolute)."""
    modules: List[dict] = []
    blocks: List[Tuple[int, int]] = []
    try:
        text = Path(events_path).read_text()
    except OSError:
        return modules, blocks
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("type") != "send":
            continue
        payload = msg.get("payload") or {}
        kind = payload.get("kind")
        if kind == "modules":
            for m in payload.get("modules", []):
                try:
                    modules.append({
                        "name": m["name"],
                        "base": int(m["base"], 0) if isinstance(m["base"], str)
                        else int(m["base"]),
                        "size": int(m["size"]),
                        "path": m["path"],
                    })
                except (KeyError, ValueError, TypeError):
                    continue
        elif kind == "blocks":
            for pair in payload.get("blocks", []):
                try:
                    start = int(pair[0], 0) if isinstance(pair[0], str) else int(pair[0])
                    end = int(pair[1], 0) if isinstance(pair[1], str) else int(pair[1])
                    blocks.append((start, end))
                except (ValueError, TypeError, IndexError):
                    continue
    return modules, blocks


def write_drcov(events_path: str, drcov_path: str) -> int:
    """Serialise the Frida coverage events to a drcov-v2 file. Returns the
    number of basic-block records written (0 if nothing was collected)."""
    modules, blocks = _load_events(events_path)
    if not modules:
        logger.debug("frida coverage: no module table in %s", events_path)
        return 0

    # Stable module ids by load order; resolve each block to (module_id, off).
    mod_ranges = [
        (i, m["base"], m["base"] + m["size"]) for i, m in enumerate(modules)
    ]
    records: List[Tuple[int, int, int]] = []  # (offset_u32, size_u16, mid_u16)
    seen = set()
    for start, end in blocks:
        for mid, lo, hi in mod_ranges:
            if lo <= start < hi:
                off = start - lo
                size = max(0, min(end - start, 0xFFFF))
                key = (mid, off)
                if key not in seen:
                    seen.add(key)
                    records.append((off & 0xFFFFFFFF, size, mid & 0xFFFF))
                break

    lines = [
        "DRCOV VERSION: 2",
        "DRCOV FLAVOR: frida",
        f"Module Table: version 2, count {len(modules)}",
        "Columns: id, base, end, entry, path",
    ]
    for i, m in enumerate(modules):
        lines.append(
            f"{i}, {hex(m['base'])}, {hex(m['base'] + m['size'])}, 0, {m['path']}"
        )
    header = ("\n".join(lines) + "\n").encode("utf-8")
    bb_header = f"BB Table: {len(records)} bbs\n".encode("utf-8")
    blob = b"".join(struct.pack("<IHH", off, size, mid) for off, size, mid in records)

    Path(drcov_path).write_bytes(header + bb_header + blob)
    return len(records)


def import_to_store(store, drcov_path: str, binary: str,
                    checklist: Dict[str, Any], tool: str = "frida") -> int:
    """Resolve the drcov file to source and mark ``store`` - thin wrapper over
    the existing ``core.coverage.collect.import_drcov`` so Frida coverage flows
    into the same store as every other runtime source (visible in
    ``/project coverage``). Returns the number of source lines marked."""
    from core.coverage.collect import import_drcov
    return import_drcov(store, drcov_path, binary, checklist, tool=tool)
