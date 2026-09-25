"""Per-function basic-block control-flow graphs from radare2.

RAPTOR's binary path stops at function-granularity call graphs; the
*intra-function* basic-block CFG — the directed graph of basic blocks,
where edges are branch targets (``jump`` / ``fail`` / switch cases) —
is what per-function structural analysis needs. This module turns
radare2's ``afbj`` (analyse-function-basic-blocks, JSON) output into a
directed graph that satisfies the ``core.analysis.dominators.Graph``
protocol, so it feeds the dominator machinery and the scalar CFG
metrics (``core.analysis.cfg_metrics``) unchanged.

Everything here is **r2-free and pure**: the r2 command is run by the
caller (``radare2_understand.py``, which owns the sandboxed r2 handle and
timeouts) and the JSON is handed to :func:`parse_afbj`. That keeps the
parser, the ``Graph`` adapter, and the cache unit-testable on hosts
without radare2 (e.g. macOS dev boxes).

A per-build-id on-disk cache mirrors ``core.analysis.binary_oracle_edges``:
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
from typing import TypeGuard

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

    Satisfies the ``core.analysis.dominators.Graph`` protocol
    (``entry`` / ``nodes()`` / ``successors()``), so it can be handed
    directly to ``core.analysis.dominators.build_dom_tree`` or
    ``core.analysis.cfg_metrics.cyclomatic_number``.

    ``entry`` is the function's entry block address. ``adjacency`` maps
    each block address to the list of its successor block addresses
    (intra-function only — edges leaving the function are dropped).
    """

    entry: int | None
    adjacency: dict[int, list[int]] = field(default_factory=dict)

    def nodes(self) -> list[int]:
        return list(self.adjacency.keys())

    def successors(self, node: int) -> list[int]:
        return self.adjacency.get(node, [])

    @property
    def block_count(self) -> int:
        return len(self.adjacency)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self.adjacency.values())


def _is_addr(v: object) -> TypeGuard[int]:
    """True for a usable address value. ``bool`` is an ``int`` subclass in
    Python, so a hostile ``"addr": true`` record would otherwise coerce to
    address 1 — reject it explicitly."""
    return isinstance(v, int) and not isinstance(v, bool)


def _block_addr(block: dict) -> int | None:
    """Basic-block address from an ``afbj`` record. r2 6.x uses ``addr``;
    some builds use ``offset``. Accept either."""
    for key in ("addr", "offset"):
        v = block.get(key)
        if _is_addr(v):
            return v
    return None


def parse_afbj(blocks: object, entry_addr: int | None = None) -> BasicBlockCFG:
    """Parse radare2 ``afbj`` output into a :class:`BasicBlockCFG`.

    ``blocks`` is the decoded JSON list (one record per basic block).
    Each record carries the block address plus its out-edges:

      * ``jump`` — the taken-branch / unconditional-jump target,
      * ``fail`` — the fall-through (not-taken) target,
      * ``switch_op``/``cases`` — switch-table case targets (when present;
        r2 exposes these inconsistently, so they're parsed defensively).

    Only edges that land on *another block of this function* are kept —
    tail calls and inter-function jumps are dropped, since we want the
    intra-procedural CFG. Self-edges (a block branching to itself — a
    single-block spin loop) are KEPT: they are real control flow and
    real cyclomatic complexity. Consumers that require a loopless
    digraph must drop them in their own normalisation.

    ``entry_addr`` is the function's entry; when absent or not among the
    blocks, the lowest block address is used.

    The whole input is untrusted r2 output: non-list input, non-dict
    records, and non-int addresses/targets are ignored rather than
    raised on.
    """
    addrs: list[int] = []
    seen_addr: set[int] = set()
    for b in blocks if isinstance(blocks, list) else []:
        if not isinstance(b, dict):
            continue
        a = _block_addr(b)
        if a is not None and a not in seen_addr:
            seen_addr.add(a)
            addrs.append(a)

    adjacency: dict[int, list[int]] = {a: [] for a in addrs}

    for b in blocks if isinstance(blocks, list) else []:
        if not isinstance(b, dict):
            continue
        a = _block_addr(b)
        if a is None or a not in adjacency:
            continue
        # Seed dedup from edges already recorded for this block — a
        # hostile listing may repeat the same block record, and per-record
        # dedup alone would duplicate the shared edges.
        out_seen: set[int] = set(adjacency[a])
        targets: list[int] = []
        for key in ("jump", "fail"):
            t = b.get(key)
            if _is_addr(t):
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
                        if _is_addr(t):
                            targets.append(t)
                            break
                elif _is_addr(c):
                    targets.append(c)
        for t in targets:
            if t in seen_addr and t not in out_seen:
                out_seen.add(t)
                adjacency[a].append(t)

    if entry_addr is not None and entry_addr in seen_addr:
        entry: int | None = entry_addr
    elif addrs:
        entry = min(addrs)
    else:
        entry = None
    return BasicBlockCFG(entry=entry, adjacency=adjacency)


# ---------------------------------------------------------------------------
# Per-build-id cache
# ---------------------------------------------------------------------------

def _is_canonical_int(s: object) -> bool:
    """True for a string that is exactly ``str(int(s))`` — the only key
    shape ``save_cached_cfgs`` writes. Rejects underscore literals
    ("1_0"), whitespace, and leading zeros that ``int()`` would silently
    coerce."""
    if not isinstance(s, str):
        return False
    try:
        return str(int(s)) == s
    except ValueError:
        return False


def _cache_dir() -> Path:
    from core.config import RaptorConfig
    return Path(RaptorConfig.BASE_OUT_DIR) / "binary-cfg-cache"


def _cache_key(binary_path: Path) -> str | None:
    """Content-identity value (build-id / LC_UUID / PE GUID+age) via
    the kind-aware front door, or ``sha256:<hex>`` for the content
    fallback. ``None`` when neither can be derived.

    The front door sniffs the format itself, so the sandboxed
    build-id probe never spawns over non-ELF bytes; ELF keys and the
    ``sha256:`` fallback keys are byte-identical to the historical
    build-id-or-hash scheme, so existing cache entries stay valid.
    """
    try:
        from core.binary.identity import KIND_SHA256, content_identity
        ident = content_identity(binary_path)
    except Exception:  # noqa: BLE001 — identity is an optimisation; fall back to content hash on any extraction failure
        ident = None
    if ident is None:
        sha = _content_sha(binary_path)
        return f"sha256:{sha}" if sha else None
    if ident.kind == KIND_SHA256:
        return f"sha256:{ident.value}"
    return ident.value


def _content_sha(binary_path: Path) -> str | None:
    """Streamed content hash via the repo's single chokepoint
    (core.hash.sha256_file); unreadable file degrades to None."""
    try:
        from core.hash import sha256_file
        return sha256_file(binary_path)
    except OSError:
        return None


def _cache_path(key: str) -> Path | None:
    if not isinstance(key, str) or not _CACHE_KEY_RE.fullmatch(key):
        return None
    safe = key.replace(":", "_")
    return _cache_dir() / f"{safe}.json"


def load_cached_cfgs(binary_path: Path) -> dict[int, BasicBlockCFG] | None:
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
    # RecursionError: json.loads raises it on deeply-nested input — a
    # tampered cache file must read as a miss, not abort the analysis.
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    version = payload.get("version")
    # type() not isinstance(): bool is an int subclass and True == 1, so a
    # tampered {"version": true} would otherwise pass the check below.
    if type(version) is not int or version != _CFG_CACHE_VERSION:
        return None
    # Build-id collision guard: a different binary sharing this build-id
    # (reproducible-build collision, or a poisoned cache file) must not
    # feed CFGs to the wrong target.
    cached_path = payload.get("binary_path")
    if not isinstance(cached_path, str) or cached_path != str(binary_path):
        logger.warning(
            "function_cfg: cache key collision; cached path=%s wanted=%s; "
            "treating as miss", cached_path, binary_path)
        return None
    raw = payload.get("cfgs")
    if not isinstance(raw, dict):
        return None
    # Load with the same type discipline the parser applies to r2 output,
    # plus the parser's structural invariants (every edge target is a
    # member block; entry is a member or None). save_cached_cfgs never
    # writes anything that fails these, so any violation means tampering
    # or corruption — fail closed to a miss.
    out: dict[int, BasicBlockCFG] = {}
    try:
        for addr_s, rec in raw.items():
            if not _is_canonical_int(addr_s) or not isinstance(rec, dict):
                return None
            entry = rec.get("entry")
            if entry is not None and not _is_addr(entry):
                return None
            adj_raw = rec.get("adjacency")
            if adj_raw is None:
                adj_raw = {}
            if not isinstance(adj_raw, dict):
                return None
            adj: dict[int, list[int]] = {}
            for a, succs in adj_raw.items():
                if not _is_canonical_int(a) or not isinstance(succs, list):
                    return None
                adj[int(a)] = succs
            for succs in adj.values():
                for t in succs:
                    if not _is_addr(t) or t not in adj:
                        return None
            if entry is not None and entry not in adj:
                return None
            out[int(addr_s)] = BasicBlockCFG(entry=entry, adjacency=adj)
    except (ValueError, TypeError, AttributeError):
        return None
    return out


def save_cached_cfgs(
    binary_path: Path,
    cfgs: dict[int, BasicBlockCFG],
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
        # core.json.save_json owns the atomic tempfile + rename dance
        # (parent dir creation included). The hand-rolled predecessor
        # used a CONSTANT `.json.tmp` sidecar per cache key, so two
        # concurrent saves raced on the same tempfile — save_json's
        # unique tempfile removes the torn-write window entirely.
        from core.json import save_json
        save_json(path, payload)
    except OSError as e:
        logger.debug("function_cfg: cache write failed: %s", e)


__all__ = [
    "BasicBlockCFG",
    "parse_afbj",
    "load_cached_cfgs",
    "save_cached_cfgs",
]
