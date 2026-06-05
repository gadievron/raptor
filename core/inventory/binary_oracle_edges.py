"""Binary-oracle call-edge extraction — Inc 2b Tier 1.

The asymmetric companion to Inc 2's ``absent``-direction suppression
witness: extract the binary's direct call graph, then for each
``(caller, callee)`` edge cross-reference back to the source inventory.
A source function with an incoming binary edge — even if the source
graph thinks no caller exists — gets a positive reachability witness
(``binary_call_edge``).

Tier scope (per design §6 + Phase 4 edge-gap measurement):
  * Tier 1 (this module) — DIRECT edges via r2 ``axffj`` per function.
    Catches ~92% of all binary call sites (the indirect-call fraction
    sat at 8.1% aggregate in the 4-corpus measurement). Misses fn-
    pointer / vtable / ESIL-needed cases.
  * Tier 2 (deferred) — vtable resolution via r2 ``avtv`` for C++.
  * Tier 3 (deferred) — ESIL emulation for constant fn-pointer
    propagation.

The witness is HEURISTIC (not corpus-earned for hard suppression) —
binary-edge ⇒ reachable is affirmative evidence that flows into the
LLM prompt + reach_witness chokepoint, but doesn't license dropping a
finding the way ``binary_oracle_absent`` does. Future corpus
measurement can promote it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .binary_oracle import read_build_id

logger = logging.getLogger(__name__)


# Edge-index cache schema version. Bump on any incompatible change to
# the serialised edge format (BinaryEdgeIndex fields, edge record
# shape). Old cache entries with a stale version are ignored and the
# extractor re-runs from scratch.
_EDGE_CACHE_VERSION = 1


@dataclass(frozen=True)
class BinaryCallEdge:
    """One direct call edge in the binary."""
    caller: str
    callee: str
    binary_path: str


@dataclass
class BinaryEdgeIndex:
    """Per-binary direct-call-edge extraction result.

    ``edges`` is the full edge set; ``callees`` is the set of source-
    function names that appear as a callee somewhere (cheap "is X
    binary-called?" check used by the reach_witness stage)."""
    binary_path: str
    edges: List[BinaryCallEdge] = field(default_factory=list)
    callees: Set[str] = field(default_factory=set)


def _content_hash(binary_path: Path) -> Optional[str]:
    """sha256 of the binary's file content — cache key fallback when
    ``.note.gnu.build-id`` is absent (stripped Go, PGO-stripped vendor
    binaries). Bounded I/O cost per extraction; cheaper than running
    r2 a second time."""
    try:
        import hashlib
        h = hashlib.sha256()
        with binary_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _fn_addr(f: Dict) -> Optional[int]:
    """Function entry address from an ``aflj`` record. r2 6.x keys this
    as ``addr``; r2 5.x (the version Ubuntu/Debian apt ships, used by the
    nightly CI corpus job) keys it as ``offset``. Accept either so the
    extractor works across the r2 versions operators actually have
    installed. Returns ``None`` when neither key holds an int — the
    caller skips that function rather than crashing on ``f['addr']``."""
    for key in ("addr", "offset"):
        v = f.get(key)
        if isinstance(v, int):
            return v
    return None


def _edge_cache_dir() -> Path:
    """Edge-index cache root: ``out/binary-oracle-precision/edge-cache/``
    (re-using the existing binary_oracle output convention). Cache
    entries keyed by binary build_id."""
    from core.config import RaptorConfig
    return Path(RaptorConfig.BASE_OUT_DIR) / "binary-oracle-precision" / "edge-cache"


_BUILD_ID_RE = re.compile(r"^[0-9a-f]{8,128}$")


def _cache_path_for(build_id: str) -> Optional[Path]:
    """Cache path for a given build_id, or ``None`` when the build_id
    isn't a safely-embeddable hex string. Belt-and-braces against any
    future regression in the upstream ``read_build_id`` helper: a
    hostile binary defining its build_id note (e.g. arbitrary bytes in
    ``.note.gnu.build-id``) could otherwise drive cache-file path
    composition. Validate at use-site, not just at production."""
    if not isinstance(build_id, str) or not _BUILD_ID_RE.match(build_id):
        return None
    return _edge_cache_dir() / f"{build_id}.json"


def _load_cached_index(
    cache_file: Path,
    binary_path: str,
) -> Optional[BinaryEdgeIndex]:
    """Load a previously-extracted edge index from cache. Returns None
    when the cache file is missing, malformed, or version-mismatched
    (caller falls back to full extraction)."""
    if not cache_file.is_file():
        return None
    try:
        payload = json.loads(cache_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("version") != _EDGE_CACHE_VERSION:
        return None
    # Cross-target collision check: two binaries with the same build_id
    # (reproducible-build collision, or a pre-poisoned cache file an
    # attacker dropped under out/) would silently mis-attribute edges
    # to the wrong target. Insist the cache's ``binary_path`` matches
    # the binary we're looking up; otherwise treat as miss and re-run
    # extraction. Defends against the cache-poisoning vector flagged by
    # adversarial review (forged edges to censor LLM scrutiny on a
    # real bug — earns_suppression=False on this witness prevents
    # finding-suppression, but censorship via misattribution is still
    # within reach without this check).
    cached_path = payload.get("binary_path")
    if isinstance(cached_path, str) and cached_path != binary_path:
        logger.warning(
            "binary_oracle_edges: cache build_id collision; cached "
            "path=%s wanted=%s; treating as cache miss",
            cached_path, binary_path,
        )
        return None
    edges_raw = payload.get("edges") or []
    idx = BinaryEdgeIndex(binary_path=binary_path)
    for r in edges_raw:
        if not isinstance(r, dict):
            continue
        caller = r.get("caller")
        callee = r.get("callee")
        bp = r.get("binary_path") or binary_path
        if isinstance(caller, str) and isinstance(callee, str):
            idx.edges.append(BinaryCallEdge(
                caller=caller, callee=callee, binary_path=bp))
            idx.callees.add(callee)
    return idx


def _save_cached_index(cache_file: Path, idx: BinaryEdgeIndex) -> None:
    """Persist the edge index. Best-effort — IO failures are logged at
    debug and don't break the extraction path."""
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version":     _EDGE_CACHE_VERSION,
            "binary_path": idx.binary_path,
            "edges": [
                {"caller": e.caller, "callee": e.callee,
                 "binary_path": e.binary_path}
                for e in idx.edges
            ],
        }
        tmp = cache_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, cache_file)
    except OSError as e:
        logger.debug("binary_oracle_edges: cache write failed: %s", e)


def extract_direct_call_edges(
    binary_path: Path,
    *,
    timeout: int = 300,
    use_cache: bool = True,
) -> BinaryEdgeIndex:
    """Run r2 ``aaa`` + ``aflj`` then per-function ``axffj`` to harvest
    direct call edges. Returns an index keyed by both edge list and
    callee set. Empty index when r2 is unavailable or fails (the
    consumer treats absence as 'no binary evidence'; never licenses
    additional suppression).

    ``use_cache`` controls the per-build_id cache (under
    ``out/binary-oracle-precision/edge-cache/<build_id>.json``).
    A cache hit returns near-instantly; a miss runs the full r2
    extraction and persists the result. Pass False to force re-extract
    (test scenarios, debugging cache staleness)."""
    if not shutil.which("r2"):
        logger.info("binary_oracle_edges: r2 not found; skipping")
        return BinaryEdgeIndex(binary_path=str(binary_path))
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        return BinaryEdgeIndex(binary_path=str(binary_path))

    # Cache lookup keyed by build_id (mechanically-derived from
    # ``.note.gnu.build-id`` — changes whenever the binary's code does).
    # Stripped binaries (Go without -trimpath, PGO-stripped vendor
    # binaries, custom-link binaries that drop .note.gnu.build-id) may
    # have no build_id; fall back to a content sha256 so the cache
    # still works (slower than a 40-char hex constant but bounded —
    # one full-file digest per extraction).
    cache_key = read_build_id(binary_path) if use_cache else None
    if use_cache and not cache_key:
        cache_key = _content_hash(binary_path)
    cache_file = _cache_path_for(cache_key) if cache_key else None
    build_id = cache_key  # alias for the log message + cache payload
    if cache_file is not None:
        cached = _load_cached_index(cache_file, str(binary_path))
        if cached is not None:
            logger.info(
                "binary_oracle_edges: cache hit for %s (build_id=%s, %d edges)",
                binary_path.name, build_id[:12], len(cached.edges))
            return cached

    # ``aaa`` is the heavy analyse-all; ~10s on a snappy_unittest-sized
    # binary, longer on larger ones. Single r2 invocation that builds
    # the function list AND iterates axffj per function. Subprocess
    # errors (timeout, segfault, r2 missing post-which-check race) must
    # NOT crash the inventory build — the module's contract is positive-
    # evidence-only that degrades gracefully to "no binary evidence".
    # r2 is a powerful binary-analysis tool with a large parser attack
    # surface (CVE history in ELF/PDB parsers); the binary it analyses
    # is operator-supplied and may be attacker-controlled. Use the full
    # sandbox (namespace + Landlock + network deny) so a malicious ELF
    # triggering an r2 bug cannot escape to operator-level code exec.
    # ``target`` = the binary's containing directory so Landlock allows
    # the necessary reads; no write paths needed (we capture stdout).
    from core.sandbox import run as _sandbox_run
    try:
        fns_proc = _sandbox_run(
            ["r2", "-q", "-c", "aaa; aflj", str(binary_path)],
            target=str(binary_path.parent), block_network=True,
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError,
            OSError) as e:
        logger.warning(
            "binary_oracle_edges: aflj aborted for %s: %s",
            binary_path, e,
        )
        return BinaryEdgeIndex(binary_path=str(binary_path))
    try:
        fns = json.loads(fns_proc.stdout)
    except json.JSONDecodeError:
        logger.warning("binary_oracle_edges: aflj parse failed for %s",
                       binary_path)
        return BinaryEdgeIndex(binary_path=str(binary_path))
    if not isinstance(fns, list):
        return BinaryEdgeIndex(binary_path=str(binary_path))

    # Build addr → name map for resolving callee addresses.
    addr_to_name: Dict[int, str] = {}
    for f in fns:
        addr = _fn_addr(f)
        name = f.get("name")
        if addr is not None and isinstance(name, str):
            addr_to_name[addr] = _clean_r2_function_name(name)

    # Only functions with a resolvable entry address are eligible — the
    # axffj script keys every batch on that address. A record missing
    # both ``addr`` and ``offset`` (malformed / partial r2 output) is
    # dropped here rather than KeyError-ing the whole extraction.
    eligible_fns = [f for f in fns
                    if not f.get("name", "").startswith("sym.imp.")
                    and f.get("size", 0) > 0
                    and _fn_addr(f) is not None]

    # Single r2 invocation for ALL axffj calls (adversarial review
    # B P2-2 perf cliff fix). The prior implementation re-ran the
    # heavy ``aaa`` analyse-all step PER BATCH — on a 5k-function
    # binary at BATCH=200 that's 25 redundant ``aaa`` runs, each
    # taking seconds. Total: minutes instead of seconds for big
    # binaries. The script-file approach drives a single r2 session
    # so ``aaa`` runs once and every axffj reuses its analysis state.
    #
    # Use a script file (``r2 -i``) rather than a giant ``-c`` string
    # — argv length limits (POSIX ARG_MAX, typically 128KB) would cap
    # the latter at ~few-thousand axffj calls, below the size of any
    # serious application.
    index = BinaryEdgeIndex(binary_path=str(binary_path))
    import tempfile
    script_lines = ["aaa"]
    for f in eligible_fns:
        addr = _fn_addr(f)
        script_lines.append(f"echo BATCH {addr}")
        script_lines.append(f"axffj @ {addr}")
    with tempfile.NamedTemporaryFile(
            mode="w", suffix=".r2", delete=False,
            dir=str(binary_path.parent),
    ) as script_file:
        script_file.write("\n".join(script_lines) + "\n")
        script_path = script_file.name
    try:
        proc = _sandbox_run(
            ["r2", "-q", "-i", script_path, str(binary_path)],
            target=str(binary_path.parent), block_network=True,
            capture_output=True, text=True, check=False, timeout=timeout,
            errors="replace",
        )
        _parse_axffj_batch(proc.stdout, addr_to_name, index)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError,
            OSError) as e:
        logger.warning(
            "binary_oracle_edges: axffj script aborted for %s: %s",
            binary_path, e,
        )
        # Do NOT cache a partial / failed result — bail out and
        # return what we have without persisting.
        try:
            os.unlink(script_path)
        except OSError:
            pass
        return index
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass

    # Tier 2: vtable resolution. C++ virtual dispatch is the dominant
    # share of source-graph "indirect" edges on real codebases (leveldb
    # 9.3% indirect, mostly vtables). r2's ``av`` walks the binary's
    # vtables and prints each slot's method; we treat every slot as a
    # potentially-dispatched callee with a synthetic ``<vtable@<addr>>``
    # caller. No-op on C binaries with no vtables.
    vtable_edges = _extract_vtable_edges(binary_path, timeout=timeout)
    for edge in vtable_edges:
        index.edges.append(edge)
        index.callees.add(edge.callee)

    if cache_file is not None:
        _save_cached_index(cache_file, index)
        logger.info(
            "binary_oracle_edges: cached %d edges for %s (build_id=%s)",
            len(index.edges), binary_path.name, build_id[:12])
    return index


# ---------------------------------------------------------------------------
# Tier 2 — vtable resolution
# ---------------------------------------------------------------------------

# r2 ``av`` text output: a sequence of vtable blocks, each beginning
# with ``Vtable Found at 0x<addr>`` followed by ``<slot_addr> :
# <method>`` lines. No JSON variant exists in r2 today (``avj`` /
# ``avrj`` return empty); we parse the text.
_VTABLE_HEADER_RE = re.compile(r"Vtable Found at 0x([0-9a-fA-F]+)")
_VTABLE_SLOT_RE = re.compile(r"^\s*0x[0-9a-fA-F]+\s*:\s*(\S+)")


def _extract_vtable_edges(
    binary_path: Path,
    *,
    timeout: int = 300,
) -> List[BinaryCallEdge]:
    """Run r2 ``av`` and emit one synthetic edge per vtable slot:
    ``<vtable@<addr>>`` → ``method``. Each method that appears in any
    vtable slot is, by construction, a candidate target for the
    binary's virtual dispatch sites — affirmative reachability evidence
    source extraction often misses.

    Returns an empty list when r2 finds no vtables (pure C binary,
    stripped binary where vtable detection fails) — over-approximating
    vtables would create false-promote, which the suppression direction
    can't tolerate."""
    if not shutil.which("r2"):
        return []
    from core.sandbox import run as _sandbox_run
    try:
        proc = _sandbox_run(
            ["r2", "-q", "-c", "aaa; av", str(binary_path)],
            target=str(binary_path.parent), block_network=True,
            capture_output=True, text=True, check=False, timeout=timeout,
            errors="replace",
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError,
            OSError) as e:
        logger.warning(
            "binary_oracle_edges: av (vtable) aborted for %s: %s",
            binary_path, e,
        )
        return []
    edges: List[BinaryCallEdge] = []
    current_vtable: Optional[str] = None
    for line in proc.stdout.splitlines():
        # Strip ANSI escapes r2 emits in interactive-style output.
        plain = re.sub(r"\x1b\[[\d;]*m", "", line)
        m_hdr = _VTABLE_HEADER_RE.search(plain)
        if m_hdr:
            current_vtable = f"<vtable@0x{m_hdr.group(1).lower()}>"
            continue
        if current_vtable is None:
            continue
        m_slot = _VTABLE_SLOT_RE.match(plain)
        if not m_slot:
            continue
        method = _clean_r2_function_name(m_slot.group(1))
        # Filter slot junk: pure-virtual placeholders (``0x00000000``),
        # bare hex addresses r2 couldn't resolve, section markers
        # (``section.text``), and r2-internal location names
        # (``loc.NNN``) — none of these are real callees.
        if not method or method.startswith(
                ("0x", "section.", "loc.", "0")):
            continue
        # Require at least one non-hex character somewhere in the
        # name to weed out raw addresses that slipped through.
        if not any(c.isalpha() or c == "_" for c in method):
            continue
        edges.append(BinaryCallEdge(
            caller=current_vtable, callee=method,
            binary_path=str(binary_path),
        ))
    return edges


_R2_PREFIXES = ("sym.", "method.", "func.", "fcn.", "dbg.", "imp.")


def _clean_r2_function_name(name: str) -> str:
    """r2 prefixes functions with one of ``sym.``, ``method.``,
    ``func.``, ``fcn.``, ``dbg.``, ``imp.`` (PLT stub) depending on
    source (symbol table, decoded vtable, recovered, DWARF debug-info,
    PLT). Strip the prefix(es) iteratively — r2 can stack prefixes
    (``sym.imp.malloc`` → ``malloc``, ``method.sym.X`` → ``X``)."""
    changed = True
    while changed:
        changed = False
        for prefix in _R2_PREFIXES:
            if name.startswith(prefix):
                name = name[len(prefix):]
                changed = True
                break
    return name


def _parse_axffj_batch(
    output: str,
    addr_to_name: Dict[int, str],
    index: BinaryEdgeIndex,
) -> None:
    """Parse the concatenated axffj output: ``BATCH <addr>`` separators
    delimit each function's refs, each refs block is a JSON array of
    ``{type, at, ref, name}``."""
    current_caller: Optional[str] = None
    buf: List[str] = []
    for line in output.splitlines():
        if line.startswith("BATCH "):
            _flush_axffj(buf, current_caller, addr_to_name, index)
            try:
                caller_addr = int(line[len("BATCH "):], 0)
                current_caller = addr_to_name.get(caller_addr)
            except ValueError:
                current_caller = None
            buf = []
        else:
            buf.append(line)
    _flush_axffj(buf, current_caller, addr_to_name, index)


def _flush_axffj(
    buf: List[str],
    caller: Optional[str],
    addr_to_name: Dict[int, str],
    index: BinaryEdgeIndex,
) -> None:
    """Parse a single function's axffj JSON output and append CALL
    edges to the index. A malformed (truncated) JSON block from a
    crashed/killed r2 emits one bad batch in the middle of the
    stream; we log + skip rather than silently swallow."""
    if not caller or not buf:
        return
    text = "\n".join(buf).strip()
    if not text or text == "[]":
        return
    try:
        refs = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning(
            "binary_oracle_edges: dropped axffj batch for %s: "
            "malformed JSON (%s)", caller, e,
        )
        return
    if not isinstance(refs, list):
        return
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("type") != "CALL":
            continue
        callee_addr = ref.get("ref")
        if not isinstance(callee_addr, int):
            continue
        callee_name = addr_to_name.get(callee_addr)
        if not callee_name:
            # Use the ref's name when r2 has it (matches sym.imp.printf
            # style for library calls).
            raw = ref.get("name")
            if isinstance(raw, str):
                callee_name = _clean_r2_function_name(raw)
        if not callee_name:
            continue
        index.edges.append(BinaryCallEdge(
            caller=caller, callee=callee_name,
            binary_path=index.binary_path,
        ))
        index.callees.add(callee_name)


def annotate_inventory_with_edges(
    inventory: Dict,
    indices: List[BinaryEdgeIndex],
) -> Dict[str, int]:
    """Walk the inventory and mark each native-language item whose
    name is a binary-edge callee in ANY of the supplied indices.
    Per-item annotation: ``metadata.binary_oracle_edges = [{caller,
    binary_path}, ...]``. Top-level summary:
    ``inventory.binary_oracle_edges = {n_callees, n_binaries}``.

    Best-effort — non-native items are skipped, missing metadata is
    silently initialised, exceptions logged at debug. Returns a small
    counts dict for caller-side logging."""
    counts = {"annotated": 0, "total_edges": 0}
    if not indices:
        return counts
    # Map: callee_name → list of (caller, binary_path)
    edges_by_callee: Dict[str, List[Tuple[str, str]]] = {}
    for idx in indices:
        for edge in idx.edges:
            edges_by_callee.setdefault(edge.callee, []).append(
                (edge.caller, edge.binary_path))
            counts["total_edges"] += 1

    from .binary_oracle import _NATIVE_LANGUAGES
    files = inventory.get("files") or []
    for f in files:
        lang = (f.get("language") or "").lower()
        if lang not in _NATIVE_LANGUAGES:
            continue
        for item in f.get("items") or []:
            if item.get("kind", "function") != "function":
                continue
            name = item.get("name")
            if not isinstance(name, str) or name not in edges_by_callee:
                continue
            meta = item.get("metadata")
            if not isinstance(meta, dict):
                meta = {}
                item["metadata"] = meta
            meta["binary_oracle_edges"] = [
                {"caller": caller, "binary_path": bp}
                for caller, bp in edges_by_callee[name]
            ]
            counts["annotated"] += 1
    if counts["annotated"]:
        inventory["binary_oracle_edges"] = {
            "n_callees_with_edges": counts["annotated"],
            "n_binaries":           len(indices),
            "total_edges":          counts["total_edges"],
        }
    return counts


__all__ = [
    "BinaryCallEdge",
    "BinaryEdgeIndex",
    "extract_direct_call_edges",
    "annotate_inventory_with_edges",
]
