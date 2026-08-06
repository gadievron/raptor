"""Per-function basic-block control-flow graphs from radare2.

Phase 2 of ``docs/design-path-homology-cfg.md``. Reverse-engineering's
binary path stops at function-granularity call graphs; path homology's
higher-dimensional signal needs the *intra-function* basic-block CFG —
the directed graph of basic blocks, where edges are branch targets
(``jump`` / ``fail`` / switch cases). This module turns radare2's
``afbj`` (analyse-function-basic-blocks, JSON) output into a directed
graph that satisfies the ``core.inventory.dominators.Graph`` protocol,
so it feeds both the dominator machinery (Project B) and the
path-homology core (Phase 1) unchanged.

Everything here is **r2-free and pure**: the r2 command is run by the
caller (``radare2_understand.py``, which owns the sandboxed r2 handle and
timeouts) and the JSON is handed to :func:`parse_afbj`. That keeps the
parser, the ``Graph`` adapter, and the cache unit-testable on hosts
without radare2 (e.g. macOS dev boxes).

A per-build-id on-disk cache mirrors ``core.inventory.binary_oracle_edges``:
the slow part of binary analysis is r2's ``aaa``, and re-analysing the
same build should reuse extracted CFGs. The cache is keyed by ELF
build-id (content-sha fallback), version-stamped, and guarded against
build-id collisions across different binaries.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Cache schema version — bump on any incompatible change to the on-disk
# shape so stale entries are ignored rather than mis-parsed.
_CFG_CACHE_VERSION = 1

# Cache-key shape guard (build-id hex, or "sha256:<64 hex>"). Defends the
# cache-file path against a hostile binary planting arbitrary bytes in its
# build-id note. Mirrors binary_oracle_edges._BUILD_ID_RE intent.
_CACHE_KEY_RE = re.compile(r"^(?:[0-9a-f]{8,128}|sha256:[0-9a-f]{64})$")


@dataclass(frozen=True)
class BasicBlockCFG:
    """A function's basic-block control-flow graph.

    Satisfies the ``core.inventory.dominators.Graph`` protocol
    (``entry`` / ``nodes()`` / ``successors()``), so it can be handed
    directly to ``core.inventory.path_homology.betti`` or
    ``core.inventory.dominators.build_dom_tree``.

    ``entry`` is the function's entry block address. ``adjacency`` maps
    each block address to the list of its successor block addresses
    (intra-function only — edges leaving the function are dropped).
    """

    entry: Optional[int]
    adjacency: Dict[int, List[int]] = field(default_factory=dict)

    def nodes(self) -> List[int]:
        return list(self.adjacency.keys())

    def successors(self, node: int) -> List[int]:
        return self.adjacency.get(node, [])

    @property
    def block_count(self) -> int:
        return len(self.adjacency)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self.adjacency.values())


def _block_addr(block: Dict) -> Optional[int]:
    """Basic-block address from an ``afbj`` record. r2 6.x uses ``addr``;
    some builds use ``offset``. Accept either."""
    for key in ("addr", "offset"):
        v = block.get(key)
        if isinstance(v, int):
            return v
    return None


def parse_afbj(blocks, entry_addr: Optional[int] = None) -> BasicBlockCFG:
    """Parse radare2 ``afbj`` output into a :class:`BasicBlockCFG`.

    ``blocks`` is the decoded JSON list (one record per basic block).
    Each record carries the block address plus its out-edges:

      * ``jump`` — the taken-branch / unconditional-jump target,
      * ``fail`` — the fall-through (not-taken) target,
      * ``switch_op``/``cases`` — switch-table case targets (when present;
        r2 exposes these inconsistently, so they're parsed defensively).

    Only edges that land on *another block of this function* are kept —
    tail calls and inter-function jumps are dropped, since we want the
    intra-procedural CFG. Self-edges (a block jumping to itself) are
    dropped too (path homology is loopless; a self-loop carries no
    homological signal beyond what the block already encodes).

    ``entry_addr`` is the function's entry; when absent or not among the
    blocks, the lowest block address is used.
    """
    addrs: List[int] = []
    seen_addr = set()
    for b in blocks if isinstance(blocks, list) else []:
        if not isinstance(b, dict):
            continue
        a = _block_addr(b)
        if a is not None and a not in seen_addr:
            seen_addr.add(a)
            addrs.append(a)

    adjacency: Dict[int, List[int]] = {a: [] for a in addrs}

    for b in blocks if isinstance(blocks, list) else []:
        if not isinstance(b, dict):
            continue
        a = _block_addr(b)
        if a is None or a not in adjacency:
            continue
        out_seen = set()
        targets: List[int] = []
        for key in ("jump", "fail"):
            t = b.get(key)
            if isinstance(t, int):
                targets.append(t)
        # Switch tables: r2 may attach case targets under "switch_op"
        # with a "cases" list, each carrying a "jump"/"addr".
        sw = b.get("switch_op")
        cases = sw.get("cases") if isinstance(sw, dict) else b.get("cases")
        if isinstance(cases, list):
            for c in cases:
                if isinstance(c, dict):
                    for ck in ("jump", "addr", "offset"):
                        t = c.get(ck)
                        if isinstance(t, int):
                            targets.append(t)
                            break
                elif isinstance(c, int):
                    targets.append(c)
        for t in targets:
            if t in seen_addr and t != a and t not in out_seen:
                out_seen.add(t)
                adjacency[a].append(t)

    if entry_addr is not None and entry_addr in seen_addr:
        entry: Optional[int] = entry_addr
    elif addrs:
        entry = min(addrs)
    else:
        entry = None
    return BasicBlockCFG(entry=entry, adjacency=adjacency)


# ---------------------------------------------------------------------------
# Per-build-id cache
# ---------------------------------------------------------------------------

def _cache_dir() -> Path:
    from core.config import RaptorConfig
    return Path(RaptorConfig.BASE_OUT_DIR) / "binary-cfg-cache"


def _cache_key(binary_path: Path) -> Optional[str]:
    """Build-id (preferred) or ``sha256:<hex>`` content fallback. ``None``
    when neither can be derived."""
    try:
        from core.inventory.binary_oracle import read_build_id
        bid = read_build_id(binary_path)
    except Exception:
        bid = None
    if isinstance(bid, str) and re.fullmatch(r"[0-9a-fA-F]{8,128}", bid):
        return bid.lower()
    sha = _content_sha(binary_path)
    return f"sha256:{sha}" if sha else None


def _content_sha(binary_path: Path) -> Optional[str]:
    try:
        import hashlib
        h = hashlib.sha256()
        with binary_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _cache_path(key: str) -> Optional[Path]:
    if not isinstance(key, str) or not _CACHE_KEY_RE.match(key):
        return None
    safe = key.replace(":", "_")
    return _cache_dir() / f"{safe}.json"


def load_cached_cfgs(binary_path: Path) -> Optional[Dict[int, BasicBlockCFG]]:
    """Load previously-extracted per-function CFGs for ``binary_path``.
    Returns ``None`` on cache miss (absent / malformed / version-mismatch
    / build-id collision with a different binary)."""
    key = _cache_key(binary_path)
    if not key:
        return None
    path = _cache_path(key)
    if path is None or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("version") != _CFG_CACHE_VERSION:
        return None
    # Build-id collision guard: a different binary sharing this build-id
    # (reproducible-build collision, or a poisoned cache file) must not
    # feed CFGs to the wrong target.
    cached_path = payload.get("binary_path")
    if isinstance(cached_path, str) and cached_path != str(binary_path):
        logger.warning(
            "function_cfg: cache key collision; cached path=%s wanted=%s; "
            "treating as miss", cached_path, binary_path)
        return None
    raw = payload.get("cfgs")
    if not isinstance(raw, dict):
        return None
    out: Dict[int, BasicBlockCFG] = {}
    try:
        for addr_s, rec in raw.items():
            entry = rec.get("entry")
            adj = {
                int(a): [int(t) for t in succs]
                for a, succs in (rec.get("adjacency") or {}).items()
            }
            out[int(addr_s)] = BasicBlockCFG(entry=entry, adjacency=adj)
    except (ValueError, TypeError, AttributeError):
        return None
    return out


def save_cached_cfgs(
    binary_path: Path,
    cfgs: Dict[int, BasicBlockCFG],
) -> None:
    """Persist per-function CFGs for ``binary_path``. Best-effort — IO
    errors are logged at debug and never propagate."""
    key = _cache_key(binary_path)
    if not key:
        return
    path = _cache_path(key)
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": _CFG_CACHE_VERSION,
            "binary_path": str(binary_path),
            "cfgs": {
                str(addr): {
                    "entry": cfg.entry,
                    "adjacency": {
                        str(a): list(succs)
                        for a, succs in cfg.adjacency.items()
                    },
                }
                for addr, cfg in cfgs.items()
            },
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload))
        tmp.replace(path)
    except OSError as e:
        logger.debug("function_cfg: cache write failed: %s", e)


__all__ = [
    "BasicBlockCFG",
    "parse_afbj",
    "load_cached_cfgs",
    "save_cached_cfgs",
]
