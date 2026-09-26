"""Anchor-identity join for cross-run finding correlation.

Cross-run correlation historically keyed findings by the exact
``(file, function, line)`` tuple. Real re-derivations of one defect
drift on every component of that key: one run anchors the function
signature while another anchors the sink line inside the same
function; module-scope code gets a different synthetic name from every
producer (``<module>`` / ``__module__`` / ``interstitial:N-M``); and a
record can carry an explicit lineage note naming the prior finding it
re-derives, which the exact key never read. Each miss surfaced a
known-duplicate confirmed row as a NEW finding and cost a manual
adjudication pass.

This module builds the widened join:

* **Synthetic-scope normalization** — known module-scope spellings
  collapse to one canonical name at the join; the raw name stays on
  the record and in the site's anchor list.
* **Site join** — rows sharing ``(file, normalized function,
  CWE family)`` join into one site when their anchors provably sit in
  the same scope: a checklist function span covering both anchors
  where span data exists, a bounded line window as the fallback for
  named functions when spans are absent.
* **Lineage consumption** — a record whose prose carries an explicit
  prior-finding reference ("Corpus carry: ... prior verdict FIND-N
  ... from run R") joins with that exact row as an authoritative SAME
  edge (same-file only; a cross-file reference is flagged, not
  joined).
* **Canonical-anchor election** — a joined site elects the member
  whose record demonstrably anchors the mechanism/sink line; see
  :func:`_anchor_kind` for the documented rule.

DIRECTION DISCIPLINE: over-joining merges genuinely distinct defects
and HIDES findings — the dangerous direction. Under-joining only
costs a human a look. Every rule here therefore joins only on
positive evidence (shared span, bounded window inside one named
function, explicit lineage) and different CWE families never join.
Positional joins are additionally DIAMETER-BOUNDED: union-find takes
the transitive closure, so without a bound a chain of pairwise-close
anchors could fold rows arbitrarily far apart — a span or window link
that would stretch a component's anchor-line diameter past its bound
is declined and flagged instead. Finding fields (``function``,
``line``, ``cwe_id``, prose) are run-artifact content quoting the
scanned target, so no single field may self-declare joining reach: an
``interstitial:N-M`` range is honoured only when the checklist
corroborates it, and lineage notes are read only from reasoning-tier
fields, never from target-quoting ones. When identity is plausible
but unproven (no span data for module scope, anchors beyond the
window or the diameter bound, two same-run sightings, unknown CWE
family, cross-file lineage) the rows STAY DISTINCT and the pair is
surfaced with a ``join: uncertain`` marker for manual adjudication.

Merge (``core.project.merge``) deliberately does NOT consume this
join: merge is a destructive fold (one representation survives per
key) and a wrong join there would drop a record. Correlation is a
read-only view, so a joined site keeps every member anchor visible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from core.schema_constants import VULN_TYPE_TO_CWE, normalise_vuln_type

from .findings_utils import (
    _key_line,
    _key_str,
    _load_size_gated_json,
    finding_file,
    get_finding_id,
)

# --- Synthetic scope-name normalization ---

#: Canonical spelling for module-scope / top-level code. Producers
#: disagree on the placeholder name for code outside any function;
#: the join speaks one spelling and keeps the raw name on the record.
CANONICAL_MODULE_SCOPE = "<module>"

#: Known module-scope spellings (allowlist — exact match only). A
#: name is only normalized when it is a KNOWN synthetic placeholder;
#: guessing here risks folding a real function named like a
#: placeholder into module scope (the over-join direction).
MODULE_SCOPE_SPELLINGS = frozenset({
    "<module>",
    "__module__",
    "module_scope",
})

#: Checklist-style interstitial scope names (``interstitial:N-M``,
#: module-scope code between function definitions). The embedded
#: range is also the scope's span — consumed by the span rule.
_INTERSTITIAL_RE = re.compile(r"^interstitial:(\d{1,7})-(\d{1,7})$")


def normalize_scope_name(name: Any) -> str:
    """Canonical spelling for a finding's function/scope name.

    Known module-scope placeholder spellings and ``interstitial:N-M``
    names collapse to :data:`CANONICAL_MODULE_SCOPE`; every other name
    passes through unchanged (coerced to str — hostile rows carry
    non-str values, see ``findings_utils._key_str``).
    """
    s = _key_str(name).strip()
    if s in MODULE_SCOPE_SPELLINGS or _INTERSTITIAL_RE.match(s):
        return CANONICAL_MODULE_SCOPE
    return s


def interstitial_span(name: Any) -> tuple[int, int] | None:
    """The ``(start, end)`` range embedded in an ``interstitial:N-M``
    scope name, or ``None`` for any other name."""
    m = _INTERSTITIAL_RE.match(_key_str(name).strip())
    if not m:
        return None
    start, end = int(m.group(1)), int(m.group(2))
    if start > end:
        return None
    return (start, end)


# --- CWE-family classification ---

#: CWE id → family label. Small seed grouping of ids that name the
#: same defect mechanism at different specificity — NOT a taxonomy of
#: everything (unmapped ids are their own family, which can only
#: under-join). Kept deliberately tight: a wrong family equivalence
#: joins across mechanisms (the dangerous direction).
_CWE_FAMILY: dict[int, str] = {
    # Cross-site scripting
    79: "CWE-79", 80: "CWE-79", 83: "CWE-79", 87: "CWE-79",
    # CRLF / header injection into protocol streams
    93: "CWE-93", 113: "CWE-93",
    # Command / argument injection
    77: "CWE-77", 78: "CWE-77", 88: "CWE-77",
    # Path traversal
    22: "CWE-22", 23: "CWE-22", 36: "CWE-22",
    # Out-of-bounds write / classic overflow
    120: "CWE-120", 121: "CWE-120", 122: "CWE-120", 787: "CWE-120",
    # Integer overflow / underflow
    190: "CWE-190", 191: "CWE-190",
}

_CWE_ID_RE = re.compile(r"(\d{1,6})")


def cwe_family(finding: dict[str, Any]) -> str:
    """CWE-family label for a finding, or ``""`` when unknown.

    ``cwe_id`` wins over ``vuln_type`` (it is the more specific claim;
    e.g. a ``command_injection``-typed row with ``cwe_id: CWE-93`` is
    a CRLF family member). Rows without a CWE id fall back to the
    central vuln_type taxonomy (``core.schema_constants``) — no local
    name vocabulary. An unknown family is join-inert: such rows never
    span/window-join (they can still join on exact anchors or
    lineage).
    """
    raw = _key_str(finding.get("cwe_id") or finding.get("cwe") or "")[:64]
    m = _CWE_ID_RE.search(raw)
    if m:
        n = int(m.group(1))
        return _CWE_FAMILY.get(n, f"CWE-{n}")
    vt = normalise_vuln_type(_key_str(finding.get("vuln_type", "")))
    cwe = VULN_TYPE_TO_CWE.get(vt, "")
    m = _CWE_ID_RE.search(cwe)
    if not m:
        return ""
    n = int(m.group(1))
    return _CWE_FAMILY.get(n, f"CWE-{n}")


# --- Lineage notes ---

#: Prose marker for an explicit prior-finding reference. The delta
#: validate writes e.g. "Corpus carry: mechanism-identical
#: re-derivation of prior verdict FIND-N (confirmed) from run
#: <prior-run-id>; ..." into the record's reasoning prose.
_LINEAGE_MARKER = "Corpus carry:"

#: Fields the lineage scan reads. Reasoning-tier prose only —
#: target-quoting fields (code snippets, matched source lines, tool
#: messages) carry the scanned repo's own bytes, and a repo that
#: embeds a lineage-shaped sentence in its source must not be able
#: to forge a SAME edge through a quoted excerpt. Small allowlist by
#: design; grow it only for fields whose content is analyst/LLM
#: reasoning about the target, never the target itself.
_LINEAGE_FIELDS = frozenset({
    "candidate_reasoning",
    "dataflow_summary",
    "hypothesis",
    "reasoning",
})

#: Applied to a bounded window after each marker. All quantifiers are
#: bounded and the window is a slice — findings prose is LLM-authored
#: run-artifact content, never trusted with unbounded scans.
_LINEAGE_REF_RE = re.compile(
    r"prior verdict\s{1,4}([\w-]{1,64})"
    r"(?:\s{0,4}\([^)\n]{0,64}\))?"
    r"\s{1,4}from\s{1,4}run\s{1,4}([\w.-]{1,128})",
)

#: Per-field prose budget for the lineage scan.
_LINEAGE_SCAN_BYTES = 20_000
#: Window after each marker in which the reference must appear.
_LINEAGE_WINDOW = 400
#: Markers honoured per finding — a hostile row repeating the marker
#: thousands of times must not turn the scan quadratic.
_LINEAGE_MAX_REFS = 8


def lineage_refs(finding: dict[str, Any]) -> list[tuple[str, str]]:
    """Explicit prior-finding references carried by a record.

    Returns ``[(prior_finding_id, prior_run_id), ...]`` parsed from
    the record's reasoning-tier prose fields (:data:`_LINEAGE_FIELDS`
    — target-quoting fields are never scanned). Bounded on every axis
    (field budget, per-marker window, ref cap) — see the constants
    above.
    """
    refs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name in sorted(_LINEAGE_FIELDS):
        value = finding.get(name)
        if not isinstance(value, str) or _LINEAGE_MARKER not in value:
            continue
        text = value[:_LINEAGE_SCAN_BYTES]
        pos = 0
        while len(refs) < _LINEAGE_MAX_REFS:
            pos = text.find(_LINEAGE_MARKER, pos)
            if pos < 0:
                break
            window = text[pos:pos + _LINEAGE_WINDOW]
            m = _LINEAGE_REF_RE.search(window)
            if m:
                ref = (m.group(1), m.group(2))
                if ref not in seen:
                    seen.add(ref)
                    refs.append(ref)
            pos += len(_LINEAGE_MARKER)
        if len(refs) >= _LINEAGE_MAX_REFS:
            break
    return refs


# --- Checklist span index ---

@dataclass(frozen=True)
class ScopeSpan:
    """One checklist item's extent: a function body or an
    interstitial (module-scope) region."""
    name: str
    start: int
    end: int


def load_span_index(checklist: Any) -> dict[str, list[ScopeSpan]]:
    """Build ``file → [ScopeSpan, ...]`` from a parsed checklist.

    Tolerant of malformed input (checklists live in agent-writable
    run/project dirs): non-dict shapes, missing keys, and non-int
    lines all degrade to "no span data" for the affected entry, never
    an exception. File paths are normalised like
    :func:`core.project.findings_utils.finding_file` so they key
    identically to finding paths.
    """
    index: dict[str, list[ScopeSpan]] = {}
    if not isinstance(checklist, dict):
        return index
    files = checklist.get("files")
    if not isinstance(files, list):
        return index
    for entry in files:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path") or entry.get("file") or ""
        if not isinstance(path, str) or not path:
            continue
        path = str(PurePosixPath(path))
        items = entry.get("items")
        if not isinstance(items, list):
            continue
        spans: list[ScopeSpan] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            start = _key_line(item.get("line_start"))
            end = _key_line(item.get("line_end"))
            if start <= 0 or end < start:
                continue
            spans.append(ScopeSpan(
                name=_key_str(item.get("name", "")),
                start=start, end=end,
            ))
        if spans:
            spans.sort(key=lambda s: (s.start, s.end))
            index.setdefault(path, []).extend(spans)
    return index


def load_project_span_index(
    project: Any,
    run_dirs: list[Path] | None = None,
) -> dict[str, list[ScopeSpan]]:
    """Span index for a project: the project-root ``checklist.json``
    first, else the newest run dir's copy. Missing/oversized/broken
    checklists degrade to an empty index (the join then uses the
    window fallback) — span data widens the join, it is never
    required."""
    candidates: list[Path] = []
    try:
        candidates.append(Path(project.output_path) / "checklist.json")
    except Exception:  # noqa: BLE001 — synthetic projects may lack the attr
        pass
    for d in run_dirs or []:
        try:
            candidates.append(Path(d) / "checklist.json")
        except Exception:  # noqa: BLE001 — same tolerance as above
            continue
    for path in candidates:
        try:
            data = _load_size_gated_json(path)
        except Exception:  # noqa: BLE001 — unreadable checklist = no spans
            continue
        index = load_span_index(data)
        if index:
            return index
    return {}


# --- Join machinery ---

#: Fallback join window (|line_a - line_b|, inclusive) used ONLY for
#: same-named-function, same-CWE-family rows in files with no span
#: data. Both directions matter: smaller re-splits real anchor drift
#: (observed head-to-sink drift in the motivating corpus reaches 22
#: lines: function signature at :704 vs sink at :726) and re-opens
#: the manual dedupe pass; larger starts gluing neighbouring
#: same-family defects that merely share a long function — the
#: over-join direction that HIDES findings. 30 covers the observed
#: drift shapes with margin while staying well under typical
#: function-body distances between independent sinks. The same value
#: also caps a window-joined COMPONENT's anchor-line diameter:
#: union-find chains pairwise-close links transitively, so without
#: the component cap a lattice of Δ<=30 anchors folds rows hundreds
#: of lines apart. Two-direction regression tests pin both failure
#: modes (core/project/tests/test_anchor_join.py).
LINE_FALLBACK_WINDOW = 30

#: Anchor-line diameter cap for SPAN-joined components, as a multiple
#: of the window. Both directions matter: 1x would make the span leg
#: redundant with the window and re-split genuine drift inside long
#: function bodies (checklist corroboration earns the leg extra
#: reach; real function spans routinely exceed the window); larger
#: multiples let file-wide interstitial/module spans fold independent
#: same-family defects hundreds of lines apart — the over-join
#: direction (a Δ4990 module-scope fold was demonstrated against the
#: uncapped leg). 2x keeps every adjudicated same-defect drift shape
#: (max observed Δ22) with generous margin while declining the
#: file-wide folds to uncertainty flags. Two-direction regression
#: tests pin both failure modes.
_SPAN_DIAMETER_CAP = 2 * LINE_FALLBACK_WINDOW

#: Recorded ``join: uncertain`` pairs are capped; the total is still
#: counted so a capped list never reads as complete.
_UNCERTAIN_PAIR_CAP = 100

_PROOF_SINK_SCAN_BYTES = 2000

#: ``<token>.<ext> : N`` / ``<token>.<ext> line N`` / ``<token>.<ext> N``
#: — a file-qualified line reference in sink prose. Bounded
#: quantifiers; applied to a byte-capped slice.
_QUALIFIED_REF_RE = re.compile(
    r"([\w./+~-]{1,200}\.[A-Za-z0-9_]{1,8})"
    r"(?::\s{0,4}|\s{1,4}lines?\s{1,4}|\s{1,4})"
    r"(\d{1,7})",
)

#: Unqualified ``line N`` — read as a same-file reference when it is
#: not part of a qualified match.
_UNQUALIFIED_REF_RE = re.compile(r"\blines?\s{1,4}(\d{1,7})")


def _own_file_sink_lines(finding: dict[str, Any], file: str) -> set[int]:
    """Line numbers the record's sink prose ties to the finding's own
    file. Qualified references (``path/to/x.php:26``, ``x.php line
    98``) count when the basename matches; unqualified ``line N``
    references count as same-file. Election evidence only — this
    never influences join membership."""
    prose = finding.get("proof_sink")
    if not isinstance(prose, str) or not prose:
        return set()
    prose = prose[:_PROOF_SINK_SCAN_BYTES]
    own_name = PurePosixPath(file).name if file else ""
    lines: set[int] = set()
    qualified_spans: list[tuple[int, int]] = []
    for m in _QUALIFIED_REF_RE.finditer(prose):
        qualified_spans.append(m.span())
        if own_name and PurePosixPath(m.group(1)).name == own_name:
            lines.add(int(m.group(2)))
    for m in _UNQUALIFIED_REF_RE.finditer(prose):
        if any(a <= m.start() < b for a, b in qualified_spans):
            continue
        lines.add(int(m.group(1)))
    return lines


@dataclass
class _Entry:
    run: str
    index: int
    finding: dict[str, Any]
    file: str
    raw_function: str
    norm_function: str
    line: int
    family: str
    scope: tuple[int, int] | None = None


# Anchor kinds for canonical election, best first.
_KIND_SINK = 2
_KIND_MECHANISM = 1
_KIND_HEAD = 0


def _first_proof_line(finding: dict[str, Any]) -> int:
    proof = finding.get("proof_lines")
    if isinstance(proof, list) and proof:
        return _key_line(proof[0])
    return 0


def _anchor_kind(entry: _Entry, head_line: int) -> int:
    """Classify a member's anchor for canonical election.

    Documented rule (in order):

    * **sink** — the record's own sink prose references the anchor
      line in the finding's own file: this record anchors the
      mechanism/sink, the identity the corpus wants to keep.
    * **head** — the anchor equals the function's first line (the
      checklist span start where known, else the record's own
      ``proof_lines`` start): a signature anchor, the least
      informative choice.
    * **mechanism** — everything else: an anchor inside the body.

    Election picks sink > mechanism > head; ties resolve to the
    newest run's anchor, then deterministically by (line, run,
    function).
    """
    if entry.line and entry.line in _own_file_sink_lines(
            entry.finding, entry.file):
        return _KIND_SINK
    if head_line and entry.line == head_line:
        return _KIND_HEAD
    if not head_line and entry.line == _first_proof_line(entry.finding):
        return _KIND_HEAD
    return _KIND_MECHANISM


def _merge_bounds(
    a: tuple[int, int] | None,
    b: tuple[int, int] | None,
) -> tuple[int, int] | None:
    """Union of two (min_line, max_line) bounds; ``None`` = no lines."""
    if a is None:
        return b
    if b is None:
        return a
    return (min(a[0], b[0]), max(a[1], b[1]))


class _UnionFind:
    def __init__(self, n: int) -> None:
        self._parent = list(range(n))

    def find(self, i: int) -> int:
        parent = self._parent
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[max(ra, rb)] = min(ra, rb)


@dataclass
class AnchorJoin:
    """Result of the cross-run anchor join.

    ``key_for(run, index)`` maps each input finding to its site key —
    the elected canonical anchor ``(file, function, line)``. For a
    finding that joined nothing, the key is byte-identical to the
    exact ``dedup_key`` it always had, so consumers see no change
    outside genuine joins.
    """
    _key_by_entry: dict[tuple[str, int], tuple[str, str, int]] = field(
        default_factory=dict)
    _sites: dict[tuple[str, str, int], dict[str, Any]] = field(
        default_factory=dict)
    _finding_by_key: dict[tuple[str, str, int], dict[str, Any]] = field(
        default_factory=dict)
    #: Non-joined candidate pairs flagged for manual adjudication.
    uncertain_pairs: list[dict[str, Any]] = field(default_factory=list)
    #: True count (the recorded list is capped).
    uncertain_total: int = 0

    def key_for(self, run: str, index: int) -> tuple[str, str, int]:
        return self._key_by_entry[(run, index)]

    def site(self, key: tuple[str, str, int]) -> dict[str, Any]:
        return self._sites.get(key, {})

    def finding_for(self, key: tuple[str, str, int]) -> dict[str, Any]:
        """The elected canonical member's finding record."""
        return self._finding_by_key.get(key, {})

    def site_count(self) -> int:
        return len(self._sites)

    def multi_anchor_sites(self) -> list[dict[str, Any]]:
        """Every joined site (>1 anchor): canonical anchor fields plus
        the member ``anchors`` and ``join_via`` evidence."""
        return [
            dict(info["canonical"], anchors=info["anchors"],
                 join_via=info["join_via"])
            for info in self._sites.values()
            if len(info.get("anchors", ())) > 1
        ]

    def annotate(self, row: dict[str, Any],
                 key: tuple[str, str, int]) -> dict[str, Any]:
        """Attach multi-anchor join facts to an output row (no-op for
        single-anchor sites)."""
        info = self._sites.get(key)
        if info and len(info.get("anchors", ())) > 1:
            row["anchors"] = info["anchors"]
            row["join_via"] = info["join_via"]
        return row


def _scope_for(entry: _Entry,
               span_index: dict[str, list[ScopeSpan]]) -> tuple[int, int] | None:
    """The declared scope span containing an entry's anchor.

    Named functions resolve to the checklist item of the same name
    whose span contains the anchor (smallest wins). Module-scope
    entries resolve to the interstitial range embedded in the raw
    name when the checklist corroborates it, else the smallest
    checklist span containing the anchor. No span data → ``None``
    (window fallback territory).

    A finding's ``function`` string is run-artifact content — a
    hostile row could self-declare file-wide reach with a forged
    ``interstitial:1-9999999`` name. The embedded range is therefore
    honoured ONLY when it equals or is contained by a checklist span
    for the same file; uncorroborated ranges leave the row span-less
    (module scope without spans never window-joins, so a forged name
    earns at most an uncertainty flag).
    """
    spans = span_index.get(entry.file)
    raw_span = interstitial_span(entry.raw_function)
    if raw_span is not None:
        if spans and any(s.start <= raw_span[0] and raw_span[1] <= s.end
                         for s in spans):
            return raw_span
        return None
    if not spans or entry.line <= 0:
        return None
    if entry.norm_function != CANONICAL_MODULE_SCOPE:
        candidates = [s for s in spans
                      if s.name == entry.raw_function
                      and s.start <= entry.line <= s.end]
    else:
        candidates = [s for s in spans if s.start <= entry.line <= s.end]
    if not candidates:
        return None
    best = min(candidates, key=lambda s: (s.end - s.start, s.start))
    return (best.start, best.end)


def _spans_agree(a: _Entry, b: _Entry) -> bool:
    """Both anchors sit in one shared scope: the spans overlap and
    each anchor falls inside the OTHER record's span."""
    if a.scope is None or b.scope is None:
        return False
    if a.scope[0] > b.scope[1] or b.scope[0] > a.scope[1]:
        return False
    return (a.scope[0] <= b.line <= a.scope[1]
            and b.scope[0] <= a.line <= b.scope[1])


def build_anchor_join(
    findings_by_run: dict[str, list[dict[str, Any]]],
    span_index: dict[str, list[ScopeSpan]] | None = None,
    run_recency: dict[str, int] | None = None,
) -> AnchorJoin:
    """Join findings across runs into anchor-identity sites.

    Args:
        findings_by_run: run name → findings list (the correlate
            loading shape).
        span_index: file → checklist scope spans (see
            :func:`load_span_index`); empty/None degrades to the
            window fallback.
        run_recency: run name → rank, higher = newer. Used only for
            canonical-anchor tie-breaks; defaults to sorted-name
            order.

    Returns:
        :class:`AnchorJoin`.
    """
    span_index = span_index or {}
    if run_recency is None:
        run_recency = {name: i for i, name
                       in enumerate(sorted(findings_by_run))}

    entries: list[_Entry] = []
    for run, findings in findings_by_run.items():
        for i, f in enumerate(findings):
            raw_fn = _key_str(f.get("function", ""))
            e = _Entry(
                run=run, index=i, finding=f,
                file=finding_file(f),
                raw_function=raw_fn,
                norm_function=normalize_scope_name(raw_fn),
                line=_key_line(f.get("line") or 0),
                family=cwe_family(f),
            )
            e.scope = _scope_for(e, span_index)
            entries.append(e)

    uf = _UnionFind(len(entries))
    join_via: dict[int, set[str]] = {}
    # Per-root anchor-line bounds (positive lines only), maintained
    # across EVERY union so the span/window diameter guards see the
    # whole component, not just the incoming pair.
    bounds: dict[int, tuple[int, int]] = {
        i: (e.line, e.line) for i, e in enumerate(entries) if e.line > 0}

    def _joined(a: int, b: int, via: str) -> None:
        ba = bounds.pop(uf.find(a), None)
        bb = bounds.pop(uf.find(b), None)
        uf.union(a, b)
        merged = _merge_bounds(ba, bb)
        if merged is not None:
            bounds[uf.find(a)] = merged
        join_via.setdefault(a, set()).add(via)
        join_via.setdefault(b, set()).add(via)

    def _merged_diameter(a: int, b: int) -> int:
        """Anchor-line diameter the two members' components would
        have after a union (0 when no member carries a line)."""
        merged = _merge_bounds(bounds.get(uf.find(a)),
                               bounds.get(uf.find(b)))
        return merged[1] - merged[0] if merged else 0

    uncertain: list[dict[str, Any]] = []
    uncertain_total = 0

    def _flag(a: _Entry, b: _Entry, reason: str) -> None:
        nonlocal uncertain_total
        uncertain_total += 1
        if len(uncertain) >= _UNCERTAIN_PAIR_CAP:
            return
        uncertain.append({
            "join": "uncertain",
            "reason": reason,
            "anchors": [_anchor_dict(a), _anchor_dict(b)],
        })

    # 1. Exact anchors (normalized function): the historical key,
    #    modulo synthetic-scope spelling.
    by_exact: dict[tuple[str, str, int], int] = {}
    for i, e in enumerate(entries):
        k = (e.file, e.norm_function, e.line)
        first = by_exact.setdefault(k, i)
        if first != i:
            _joined(first, i, "exact")

    # 2. Lineage notes: authoritative SAME edges to the exact prior
    #    row the record names (same-file only — a cross-file
    #    reference is flagged for a human instead of trusted, so a
    #    prose note can never fold arbitrary rows together).
    by_run_id: dict[tuple[str, str], int] = {}
    for i, e in enumerate(entries):
        fid = get_finding_id(e.finding)
        if isinstance(fid, str) and fid:
            by_run_id.setdefault((e.run, fid), i)
    for i, e in enumerate(entries):
        for fid, run_id in lineage_refs(e.finding):
            j = by_run_id.get((run_id, fid))
            if j is None or j == i:
                continue
            if entries[j].file == e.file:
                _joined(i, j, "lineage")
            else:
                _flag(e, entries[j], "cross-file lineage reference")

    # 3. Span / window widening within (file, normalized function,
    #    CWE family) buckets. Unknown family is join-inert here.
    buckets: dict[tuple[str, str, str], list[int]] = {}
    for i, e in enumerate(entries):
        if e.file and e.norm_function:
            buckets.setdefault(
                (e.file, e.norm_function, e.family), []).append(i)
    for (_file, norm_fn, family), members in buckets.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda i: entries[i].line)
        for a_i, b_i in zip(members, members[1:]):
            a, b = entries[a_i], entries[b_i]
            if uf.find(a_i) == uf.find(b_i):
                # Already one component (exact anchors, or an
                # authoritative lineage edge): nothing to widen, and
                # the guards below must not emit a contradictory
                # uncertainty flag for a pair that IS joined.
                continue
            if not family:
                # Same file+function, unknown family: never joined on
                # position alone — surfaced for a human when the
                # anchors would otherwise have joined.
                if _spans_agree(a, b) or (
                        norm_fn != CANONICAL_MODULE_SCOPE
                        and a.scope is None and b.scope is None
                        and abs(a.line - b.line) <= LINE_FALLBACK_WINDOW):
                    _flag(a, b, "CWE family unknown")
                continue
            if _spans_agree(a, b):
                # Diameter guard: a shared span proves shared SCOPE,
                # not shared identity — a file-wide module span would
                # otherwise fold every same-family row in the file.
                if _merged_diameter(a_i, b_i) <= _SPAN_DIAMETER_CAP:
                    _joined(a_i, b_i, "span")
                else:
                    _flag(a, b, "span join beyond the diameter bound")
            elif a.scope is None and b.scope is None:
                if norm_fn == CANONICAL_MODULE_SCOPE:
                    # Module scope has no meaningful extent without
                    # span data: a line window is evidence-free there
                    # (two independent module-scope defects can sit a
                    # few lines apart) — flag, never join.
                    _flag(a, b, "module scope without span data")
                elif abs(a.line - b.line) > LINE_FALLBACK_WINDOW:
                    _flag(a, b, "beyond fallback window, no span data")
                elif a.run == b.run:
                    # Anchor drift is a cross-run phenomenon; within
                    # one run the pipeline's own dedup already folded
                    # what it considers identical, so two surviving
                    # same-run rows are the producer's deliberate
                    # claim of two findings. Position alone must not
                    # overrule that — flag, never join. (Corroborated
                    # span joins stay run-agnostic: shared structural
                    # scope is stronger evidence than the window.)
                    _flag(a, b, "same-run anchors within the window")
                elif _merged_diameter(a_i, b_i) <= LINE_FALLBACK_WINDOW:
                    _joined(a_i, b_i, "window")
                else:
                    # The link itself is within the window but the
                    # transitive component would stretch past it —
                    # unbounded chaining is exactly how a drifted
                    # anchor silently swallows a genuinely new
                    # neighbouring defect.
                    _flag(a, b, "window join beyond the diameter bound")
            # else: at least one anchor has span data and the spans
            # disagree — confidently distinct scopes, no flag.

    # 4. Cluster → canonical election.
    clusters: dict[int, list[int]] = {}
    for i in range(len(entries)):
        clusters.setdefault(uf.find(i), []).append(i)

    result = AnchorJoin()
    result.uncertain_pairs = uncertain
    result.uncertain_total = uncertain_total
    for members in clusters.values():
        ranked = sorted(members, key=lambda i: _election_rank(
            entries[i], run_recency), reverse=True)
        # Two clusters cannot elect the same (file, function, line) —
        # identical anchors exact-join into ONE cluster — but a silent
        # overwrite here would merge clusters in every consumer (the
        # over-join direction), so guard defensively: walk down the
        # election order past any occupied key.
        canon = entries[ranked[0]]
        for i in ranked:
            candidate = entries[i]
            if (candidate.file, candidate.raw_function,
                    candidate.line) not in result._sites:
                canon = candidate
                break
        key = (canon.file, canon.raw_function, canon.line)
        anchors = [_anchor_dict(entries[i])
                   for i in sorted(members, key=lambda i: (
                       entries[i].run, entries[i].index))]
        vias: set[str] = set()
        for i in members:
            vias |= join_via.get(i, set())
        result._sites[key] = {
            "anchors": anchors,
            "join_via": sorted(vias) if len(members) > 1 else [],
            "canonical": _anchor_dict(canon),
        }
        result._finding_by_key[key] = canon.finding
        for i in members:
            result._key_by_entry[(entries[i].run, entries[i].index)] = key
    return result


def _anchor_dict(e: _Entry) -> dict[str, Any]:
    return {"run": e.run, "file": e.file,
            "function": e.raw_function, "line": e.line}


def _election_rank(e: _Entry,
                   run_recency: dict[str, int]) -> tuple[int, int, int, str, str]:
    head = e.scope[0] if e.scope else 0
    return (
        _anchor_kind(e, head),
        run_recency.get(e.run, -1),
        e.line,
        e.run,
        e.raw_function,
    )
