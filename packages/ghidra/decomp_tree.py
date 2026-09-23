"""Materialize an REDatabase as a pseudo-source tree for /understand.

The "decomp-tree" renders decompiled functions into C-like files —
one file per call-graph community — plus a synthesized ``types.h``
from recovered type definitions and a ``decomp-map.json`` sidecar
mapping every emitted line range back to ``(function, address)``.

This is the seam that gives binaries `--study` (and, later, in-session
`--hunt`/`--trace`) parity: the existing source-tree machinery
(raptor-study-prep's extraction, the study loop, evidence file:line
citations) runs over the tree unchanged, and the sidecar resolves any
citation back to a stable binary address.

Everything here is derived from RAPTOR-owned artifacts, but the
CONTENT originates in an attacker-supplied binary — names, signatures,
and decompilation are clipped with the same prompt-budget discipline
as the context injector, and the tree carries a hard total-byte
ceiling so a hostile binary cannot inflate the run directory.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .match import _CONTROL

# Body variant of ``match._CONTROL``: the same class with \t/\n carved
# out. Decompiled C is multi-line; raw control/bidi bytes are never
# legal in it (r2's pdc/pdg reproduce string-literal bytes from the
# hostile binary verbatim), and the .c tree is catted by operators and
# fed to raptor-study-prep. Regex-level escapes (not Python-decoded
# literals), matching match._CONTROL's style: the range boundaries
# stay greppable, and range linters can see the control-char spans
# are deliberate. Exact-set parity with match._CONTROL minus \t/\n
# is asserted in tests so the two layers cannot drift.
_BODY_CONTROL = re.compile(
    "[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f"    # C0 minus \t\n; DEL + C1 (incl. ESC)
    "\\u200b-\\u200f\\u2028\\u2029"          # zero-width, marks, line/para sep
    "\\u202a-\\u202e\\u2066-\\u2069"         # bidi embedding/override/isolate
    "\\ufeff]")                              # zero-width no-break space / BOM
from .model import REDatabase, REFunction

logger = logging.getLogger(__name__)

#: Clip caps for binary-derived text (same discipline as the prompt
#: injector: hostile symbol names are a no-plant inflation vector).
_MAX_NAME_CHARS = 200
_MAX_SIG_CHARS = 512
_MAX_NEIGHBORS = 8
_MAX_TYPE_FIELDS = 64
#: Hard ceiling on total emitted bytes — a hostile binary within the
#: shared RE-database cache cap must not balloon into an unbounded
#: tree.
_MAX_TREE_BYTES = 256 * 1024 * 1024
#: Functions per emitted file: large connected components are split
#: (address order) so study batching and file reads stay bounded.
_MAX_FUNCS_PER_FILE = 50

SIDECAR_NAME = "decomp-map.json"
TYPES_HEADER = "types.h"


def _clip(text: object, limit: int) -> str:
    """Clip AND control/bidi-scrub binary-derived text for emission.

    Shares ``match._CONTROL`` so the layers cannot drift: names land
    in the decomp-map.json sidecar operators ``jq`` to a terminal, in
    the .c doc-comment headers, and in the byte-ceiling
    ``logger.warning`` — the console formatter does no scrubbing of
    its own, so a hostile ESC/bidi-laden symbol name must die here."""
    s = _CONTROL.sub(" ", str(text or ""))
    return s if len(s) <= limit else s[:limit] + "…"


_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9_.-]")


class _AddrIndex:
    """Bisect index over sized functions for containment lookups.

    Local on purpose: the REDatabase lookup methods are linear scans,
    and this module resolves containment once per xref — O(xrefs x
    functions) on a large or hostile binary without an index.
    """

    def __init__(self, db: REDatabase) -> None:
        import bisect
        self._bisect = bisect
        ordered = sorted(
            (f for f in db.functions
             if isinstance(f.address, int)
             and isinstance(f.size, int) and f.size > 0),
            key=lambda fn: fn.address,
        )
        self._starts = [f.address for f in ordered]
        self._ordered = ordered
        self._by_addr: Dict[int, REFunction] = {}
        for f in db.functions:
            if isinstance(f.address, int):
                self._by_addr.setdefault(f.address, f)

    def by_addr(self, addr: object) -> Optional[REFunction]:
        if not isinstance(addr, int) or isinstance(addr, bool):
            return None
        return self._by_addr.get(addr)

    def containing(self, addr: object) -> Optional[REFunction]:
        if not isinstance(addr, int) or isinstance(addr, bool):
            return None
        i = self._bisect.bisect_right(self._starts, addr) - 1
        for j in range(i, max(-1, i - 64), -1):
            f = self._ordered[j]
            if f.address <= addr < f.address + f.size:
                return f
        return self._by_addr.get(addr)


def _safe_stem(name: str) -> str:
    """A filesystem- and terminal-safe stem from a symbol name."""
    stem = _UNSAFE_FILENAME.sub("_", str(name or "fn"))[:60]
    return stem or "fn"


@dataclass
class DecompTree:
    """Result of a materialization: where it went and what it holds."""

    root: Path
    files: List[str] = field(default_factory=list)
    functions_total: int = 0
    functions_decompiled: int = 0
    functions_emitted: int = 0
    truncated: bool = False

    @property
    def sidecar_path(self) -> Path:
        return self.root / SIDECAR_NAME

    def coverage_line(self) -> str:
        """Honest one-line coverage summary for operator output."""
        pct = (100.0 * self.functions_decompiled / self.functions_total
               if self.functions_total else 0.0)
        line = (
            f"decomp-tree: {self.functions_decompiled}/"
            f"{self.functions_total} functions carry decompilation "
            f"({pct:.0f}%), {len(self.files)} file(s)"
        )
        if self.truncated:
            line += " — TRUNCATED at the tree byte ceiling"
        return line


def _communities(db: REDatabase) -> List[List[REFunction]]:
    """Group functions into call-graph connected components.

    Deterministic: components are discovered over an undirected view
    of the call xrefs, ordered by their lowest member address, and
    split at ``_MAX_FUNCS_PER_FILE`` in address order. Functions with
    no known edges land in shared "misc" buckets rather than one file
    each (a stripped binary with sparse xrefs would otherwise emit
    thousands of single-function files).
    """
    funcs = [f for f in db.functions
             if isinstance(f.address, int)
             and not isinstance(f.address, bool)]
    by_addr: Dict[int, REFunction] = {}
    for f in funcs:
        by_addr.setdefault(f.address, f)

    # Undirected adjacency from call xrefs, resolved via containment
    # (from_addr is an instruction address inside the caller).
    index = _AddrIndex(db)
    adj: Dict[int, set] = {f.address: set() for f in by_addr.values()}
    for x in db.xrefs:
        if getattr(x, "kind", None) != "call":
            continue
        caller = index.containing(x.from_addr)
        callee = by_addr.get(x.to_addr)
        if caller is None or callee is None:
            continue
        if caller.address == callee.address:
            continue
        adj.setdefault(caller.address, set()).add(callee.address)
        adj.setdefault(callee.address, set()).add(caller.address)

    seen: set = set()
    components: List[List[REFunction]] = []
    for f in sorted(by_addr.values(), key=lambda fn: fn.address):
        if f.address in seen:
            continue
        stack = [f.address]
        comp: List[int] = []
        while stack:
            a = stack.pop()
            if a in seen:
                continue
            seen.add(a)
            comp.append(a)
            stack.extend(n for n in adj.get(a, ()) if n not in seen)
        members = sorted((by_addr[a] for a in comp),
                         key=lambda fn: fn.address)
        components.append(members)

    # Split oversized components; pool singletons into misc buckets.
    out: List[List[REFunction]] = []
    singles: List[REFunction] = []
    for group in components:
        if len(group) == 1:
            singles.append(group[0])
            continue
        for i in range(0, len(group), _MAX_FUNCS_PER_FILE):
            out.append(group[i:i + _MAX_FUNCS_PER_FILE])
    singles.sort(key=lambda fn: fn.address)
    for i in range(0, len(singles), _MAX_FUNCS_PER_FILE):
        out.append(singles[i:i + _MAX_FUNCS_PER_FILE])
    out.sort(key=lambda grp: grp[0].address)
    return out


def _call_adjacency(
    index: "_AddrIndex", db: REDatabase,
) -> Tuple[Dict[int, List[str]], Dict[int, List[str]]]:
    """(callers_of, callees_of) by function address, one indexed pass.

    Per-function xref rescans were O(functions x call-xrefs) — the
    exact pattern _AddrIndex exists to avoid, and hours of CPU on a
    large stripped binary before a single byte is written.
    """
    callers_of: Dict[int, List[str]] = {}
    callees_of: Dict[int, List[str]] = {}
    for x in db.xrefs:
        if getattr(x, "kind", None) != "call":
            continue
        src_fn = index.containing(getattr(x, "from_addr", None))
        dst_fn = index.by_addr(getattr(x, "to_addr", None))
        if src_fn is None or dst_fn is None:
            continue
        if src_fn.address == dst_fn.address:
            continue
        cs = callers_of.setdefault(dst_fn.address, [])
        nm = _clip(src_fn.name, _MAX_NAME_CHARS)
        if len(cs) < _MAX_NEIGHBORS and nm not in cs:
            cs.append(nm)
        ce = callees_of.setdefault(src_fn.address, [])
        nm2 = _clip(dst_fn.name, _MAX_NAME_CHARS)
        if len(ce) < _MAX_NEIGHBORS and nm2 not in ce:
            ce.append(nm2)
    return callers_of, callees_of


def _render_function(
    adjacency: Tuple[Dict[int, List[str]], Dict[int, List[str]]],
    func: REFunction,
) -> str:
    """One function's block: provenance header + decompilation.

    The header is a doc comment on purpose — raptor-study-prep's
    doc-comment extractor picks it up verbatim, so callers/callees
    and the address anchor ride into study items without any prep
    change.
    """
    callers_of, callees_of = adjacency
    callers = callers_of.get(func.address, []) \
        if isinstance(func.address, int) else []
    callees = callees_of.get(func.address, []) \
        if isinstance(func.address, int) else []
    name = _clip(func.name, _MAX_NAME_CHARS)
    lines = [
        "/**",
        f" * function: {name} @ {hex(func.address) if isinstance(func.address, int) else '?'}"
        f" size {func.size if isinstance(func.size, int) else '?'}",
    ]
    if func.signature:
        lines.append(f" * signature: {_clip(func.signature, _MAX_SIG_CHARS)}")
    if callers:
        lines.append(" * callers: " + ", ".join(callers))
    if callees:
        lines.append(" * callees: " + ", ".join(callees))
    if func.is_thunk:
        lines.append(" * thunk")
    if func.is_external:
        lines.append(" * external (import)")
    lines.append(" */")
    if func.decompilation:
        # Same scrub class as the header/sidecar fields — the body is
        # the most attacker-shaped surface of the whole emission.
        lines.append(_BODY_CONTROL.sub(" ", func.decompilation).rstrip("\n"))
    else:
        sig = _clip(func.signature, _MAX_SIG_CHARS) if func.signature \
            else f"void {name}(void)"
        lines.append(f"{sig}; /* no decompilation available */")
    lines.append("")
    return "\n".join(lines)


def _render_types(db: REDatabase) -> str:
    """Synthesized types.h from recovered type definitions.

    Struct/union fields become real C declarations so the study
    prep's struct extractor finds them exactly as it would in source.
    """
    parts = [
        "/* Recovered type definitions (decompiler-derived — treat as",
        "   evidence about the binary, not ground truth). */",
        "",
    ]
    for t in db.types:
        name = _clip(getattr(t, "name", ""), _MAX_NAME_CHARS)
        kind = str(getattr(t, "kind", "") or "struct")
        if not name:
            continue
        size = getattr(t, "size", None)
        size_note = f" /* size {size} */" if isinstance(size, int) else ""
        fields = getattr(t, "fields", None) or []
        if kind in ("struct", "union") :
            parts.append(f"{kind} {name} {{{size_note}")
            for fld in fields[:_MAX_TYPE_FIELDS]:
                if not isinstance(fld, dict):
                    continue
                ftype = _clip(fld.get("type", "int"), _MAX_NAME_CHARS)
                fname = _clip(fld.get("name", "field"), _MAX_NAME_CHARS)
                off = fld.get("offset")
                off_note = (f" /* offset {hex(off)} */"
                            if isinstance(off, int) else "")
                parts.append(f"    {ftype} {fname};{off_note}")
            if len(fields) > _MAX_TYPE_FIELDS:
                parts.append(
                    f"    /* ... {len(fields) - _MAX_TYPE_FIELDS} more"
                    " field(s) ... */")
            parts.append("};")
        elif kind == "enum":
            parts.append(f"enum {name} {{{size_note}")
            for fld in fields[:_MAX_TYPE_FIELDS]:
                if isinstance(fld, dict) and fld.get("name"):
                    val = fld.get("offset")
                    if isinstance(val, int):
                        parts.append(
                            f"    {_clip(fld['name'], _MAX_NAME_CHARS)}"
                            f" = {val},")
                    else:
                        parts.append(
                            f"    {_clip(fld['name'], _MAX_NAME_CHARS)},")
            parts.append("};")
        else:
            parts.append(f"/* {kind} {name}{size_note} */")
        parts.append("")
    return "\n".join(parts)


def write_decomp_tree(db: REDatabase, root: Path) -> DecompTree:
    """Write the pseudo-source tree for *db* under *root*.

    Idempotent for a given database: file grouping and content are
    deterministic (address order). Re-running over a refreshed
    database rewrites in place — the sidecar is written LAST so a
    reader never sees a sidecar pointing at files that don't exist
    yet.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    result = DecompTree(root=root)
    result.functions_total = len(db.functions)
    result.functions_decompiled = sum(
        1 for f in db.functions if f.decompilation)

    # Remove leftovers from a previous, larger materialization FIRST:
    # a stale g*.c from an earlier tree is invisible to the sidecar
    # but raptor-study-prep would extract it — studying decompilation
    # that is no longer in the database as if it were live code.
    for old in list(root.glob("g*.c")) + [root / TYPES_HEADER]:
        try:
            if old.is_file():
                old.unlink()
        except OSError:
            logger.warning("could not remove stale tree file %s", old)

    sidecar: Dict[str, object] = {
        "binary_path": _clip(db.binary_path or "", 500),
        "source_tool": _clip(getattr(db, "source_tool", ""), 100),
        "files": {},
    }
    budget = _MAX_TREE_BYTES

    types_text = _render_types(db)
    if db.types:
        if len(types_text.encode("utf-8")) <= budget:
            (root / TYPES_HEADER).write_text(types_text,
                                             encoding="utf-8")
            result.files.append(TYPES_HEADER)
            budget -= len(types_text.encode("utf-8"))
        else:
            result.truncated = True
            logger.warning(
                "decomp-tree: types.h over the byte ceiling — "
                "recovered type definitions omitted")

    used_names: set = set()
    index = _AddrIndex(db)
    adjacency = _call_adjacency(index, db)
    for group in _communities(db):
        rep = _safe_stem(group[0].name)
        base = f"g{group[0].address:08x}_{rep}.c" \
            if isinstance(group[0].address, int) else f"g_{rep}.c"
        fname = base
        n = 1
        while fname in used_names:
            fname = f"{Path(base).stem}_{n}.c"
            n += 1
        used_names.add(fname)

        chunks: List[str] = []
        entries: List[Dict[str, object]] = []
        line_no = 1
        group_budget = budget
        for func in group:
            block = _render_function(adjacency, func)
            nbytes = len(block.encode("utf-8")) + 1
            if nbytes > group_budget:
                # Skip THIS function only — one giant decompilation
                # must not starve the rest of its group (or the tree)
                # of the remaining budget.
                result.truncated = True
                logger.warning(
                    "decomp-tree byte ceiling: function %s (%d "
                    "bytes) omitted, %d bytes of budget remain",
                    _clip(func.name, 80), nbytes, group_budget,
                )
                continue
            group_budget -= nbytes
            n_lines = block.count("\n") + 1
            entries.append({
                "function": _clip(func.name, _MAX_NAME_CHARS),
                "address": func.address
                if isinstance(func.address, int) else None,
                "start_line": line_no,
                "end_line": line_no + n_lines - 1,
                "decompiled": bool(func.decompilation),
            })
            chunks.append(block)
            line_no += n_lines
        if not chunks:
            continue
        text = "\n".join(chunks)
        (root / fname).write_text(text, encoding="utf-8")
        budget = group_budget
        result.files.append(fname)
        result.functions_emitted += len(entries)
        sidecar["files"][fname] = entries  # type: ignore[index]

    sidecar["functions_total"] = result.functions_total
    sidecar["functions_emitted"] = result.functions_emitted
    sidecar["functions_decompiled"] = result.functions_decompiled
    sidecar["truncated"] = result.truncated
    from core.json import save_json
    save_json(root / SIDECAR_NAME, sidecar)
    return result


def resolve_citation(
    tree_root: Path, file: str, line: int,
) -> Optional[Dict[str, object]]:
    """Resolve a ``file:line`` evidence citation to its function entry.

    Returns the sidecar entry (function, address, decompiled, line
    range) or None when the citation does not land in the tree.
    Bounded read: the sidecar is RAPTOR-written but sized by the
    hostile binary's function count.
    """
    from core.json import load_json
    from core.json.utils import RE_DATABASE_MAX_BYTES
    sidecar = Path(tree_root) / SIDECAR_NAME
    if not sidecar.is_file():
        return None
    try:
        data = load_json(sidecar, max_bytes=RE_DATABASE_MAX_BYTES)
    except Exception:  # noqa: BLE001 — corrupt sidecar degrades to None
        logger.debug("unreadable decomp sidecar: %s", sidecar,
                     exc_info=True)
        return None
    if not isinstance(data, dict):
        return None
    files = data.get("files")
    if not isinstance(files, dict):
        return None
    entries = files.get(Path(file).name)
    if not isinstance(entries, list):
        return None
    for e in entries:
        if not isinstance(e, dict):
            continue
        start = e.get("start_line")
        end = e.get("end_line")
        if (isinstance(start, int) and isinstance(end, int)
                and isinstance(line, int) and start <= line <= end):
            return e
    return None
