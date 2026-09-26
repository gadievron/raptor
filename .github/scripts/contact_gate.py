#!/usr/bin/env python3
"""Seal-time contact gate — 3-tier compose probe over the registry-snapshot roster.

Sealed patch series are reviewed one at a time, but they land TOGETHER.
Between "my series applies clean on main" and "the composed roster is
sound" sit three failure classes that per-series review cannot see:

* two series edit the same region (git conflict markers at compose time);
* two series apply textually clean but break each other semantically
  (a sibling renames a symbol, the consumer's new code still uses the
  old name — an undefined-name error that only exists at the composed
  tree);
* a series composed onto CURRENT main trips a repo-wide census/closure
  gate that was tightened after the series sealed (base drift — no
  sibling series involved at all).

A fourth class needs no compose at all: a seal line's compose/rehearsal
CITATION (naming a sibling series plus the FINAL/TREE sha it rehearsed
against) goes stale when that sibling is recut mid-window — the
rehearsal keeps vouching for content that no longer rides.

This tool mechanises the compose probe as tiers, run against one
scratch composition built from the SAME roster interface the kit
assembler uses — a frozen registry snapshot file — so the gate and the
assembler can never disagree about what composes:

Tier 0 — rehearsal-citation staleness (always on, string-only, runs
    first). Every rostered line's machine-checkable citation
    (``STACK=on-<x>(...,tree-<sha>)``, ``STACKED-ON=patches-<x>(...)``,
    ``BASE=<sha>(=patches-<x>-FINAL...)``) is verified against the
    SAME snapshot: the cited series' current line (rostered, or landed
    with that sha) must carry the cited sha — otherwise STALE
    REHEARSAL, flagged with both lines quoted. Unparseable /
    joint-artifact citation shapes (prose rehearsal notes,
    ``COMPOSED-TREE=<sha>(...)``) surface as notes, never silently.

Tier 1 — roster compose. Apply every rostered series in roster order
    onto the base tip via ``git am -3`` / ``git apply --3way`` (NEVER
    patch(1): patch's fuzz factor silently applies hunks git correctly
    refuses, so a patch(1)-based probe is unsound). A conflict names
    the pair (applying unit x last unit(s) that touched the conflicting
    files). A conflict whose pair is DECLARED — either seal line names
    the other series — defers the unit and keeps composing; an
    UNDECLARED conflict fails the gate.

Tier 2 — composed union ruff. Repo-config ruff over the union of ALL
    applied units' touched .py files at the composed tree (the victim
    file can belong to a sibling, so scanning only the sealing unit's
    own files misses the cross-series break). Findings already present
    at the base tree are subtracted — only composition-introduced
    findings fail.

Tier 3 — composed gate battery. The repo's standing census/closure
    gate set, DERIVED from the workflow definitions at the composed
    tree (never a hand list): every static ``.github/scripts/check_*.py``
    invocation and every static, marker-unconditioned pytest invocation
    found in ``.github/workflows/*.yml`` run blocks. Each derived gate
    runs at the composed tree; a red gate is re-run at the bare base
    (pre-existing red = base rot, warned not charged) and then bisected
    over the per-unit boundary commits to name the introducing unit.

Roster source (the assembler interface): the snapshot's SEALED,
non-superseded, non-landed series lines, in registry order, adjusted by
the declared stack markers (``STACK=on-<x>``, ``STACKED-ON=patches-<x>``,
``BASE=<sha>(=patches-<x>-FINAL...)``) and explicit order constraints
(``LAND-<X>-FIRST``). Directory globs are deliberately NOT an input.
Every non-blank snapshot line gets a categorized adjudication; a SEALED
line that cannot roster is a hard error and any other series-shaped
line matching no known arm is a LOUD note — never a silent bin. The
snapshot is taken as-is (frozen-registry contract): stale SEALED lines
whose units already landed are NOT reconciled cross-line — tier 1
detects them STRUCTURALLY (``git am -3`` exits 0 for already-applied
mails without creating commits, so no-or-fewer commits than the
payload's mails, or an apply that stages nothing on the diff route, is
an already-applied finding; an empty boundary is never committed).
Boundary: a re-addition that git resolves as a legitimately NEW change
(the same content landing again at a different anchor once the
original context drifted) is a genuine tree delta tier 1 cannot
distinguish from intended content — its consequences surface at the
composed tree instead (tier 2 flags duplicate definitions as F811;
tier 3 runs the census battery over the result).

Output contract: human-readable report on stdout; one
``CONTACT-GATE-FINDING: ...`` line per finding and a final
machine-parseable ``CONTACT-GATE: PASS|FAIL ...`` summary line for the
assembler. Exit 0 = clean, 1 = findings, 2 = usage / infrastructure
error (a gate that cannot run must not pass).

Usage:
    python3 .github/scripts/contact_gate.py --snapshot <file> \
        [--repo <path>] [--base <ref>] [--tiers 1,2,3] [--json <file>] \
        [--scratch <dir>] [--keep-scratch] [--no-attribute] \
        [--list-roster] [--list-gates] [--gate-timeout <s>]
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

# Control characters (and DEL/C1) escaped before external text reaches the
# terminal: snapshot lines, patch file names and tool output excerpts are
# external inputs and must render inert.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize(text: str, limit: int = 400) -> str:
    """Escape non-printables and bound long excerpts with an elision mark."""
    out = _CTRL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    if len(out) > limit:
        out = out[:limit] + f"...[elided {len(out) - limit} chars]"
    return out


def run(
    argv: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess, capturing output; never raises on non-zero exit."""
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def die(msg: str) -> None:
    print(f"contact-gate: ERROR: {sanitize(msg)}", file=sys.stderr)
    print(f"CONTACT-GATE: ERROR {sanitize(msg, 200)}")
    sys.exit(2)


# --------------------------------------------------------------------------
# snapshot parsing (the assembler roster interface)
# --------------------------------------------------------------------------

# A series line carries "<name> <abs dir>" where both contain "patches-";
# the name-only spelling (directory implied by the /tmp/patches-<name>
# fleet convention) is also live and must roster, never silently bin.
_SERIES_RE = re.compile(
    r"(?P<name>patches-[A-Za-z0-9._-]+)\s+(?P<dir>/[^\s]*patches-[^\s]*)"
)
_NAME_RE = re.compile(r"\bpatches-[A-Za-z0-9._-]+")
_TAG_RE = re.compile(r"\s*\[([^\]]*)\]")
# Unbracketed status heads: "SEALED patches-x: ..." is a live spelling.
_BARE_STATUS_RE = re.compile(
    r"^(SEALED|LANDED|SUPERSEDED[A-Z-]*|VERIFY[A-Z-]*|BUILT-UNREVIEWED|BACKLOG)\b"
)
# BASE= and the prose "BASE <sha>" spelling both occur in seal lines.
_BASE_RE = re.compile(r"\bBASE[= ]\s*([0-9a-fA-F]{6,40})\b(?:\(([^)]*)\))?")
_FINAL_RE = re.compile(r"\bFINAL=([0-9a-fA-F]{6,40})")
_TREE_RE = re.compile(
    r"\b(?:FINAL-TREE|COMPOSED-TREE|SOLO-TREE|TREE|tree)[= ]([0-9a-fA-F]{6,64})\b"
)
_STACK_ON_RE = re.compile(r"\bSTACK=on-([A-Za-z0-9._-]+)")
_STACKED_ON_RE = re.compile(r"\bSTACKED-ON=patches-([A-Za-z0-9._-]+)")
_BASE_STACK_RE = re.compile(r"=patches-([A-Za-z0-9._-]+?)-FINAL\b")
_RECUT_OF_RE = re.compile(r"\bRECUT-OF=patches-([A-Za-z0-9._-]+)")
_LAND_FIRST_RE = re.compile(r"\bLAND-([A-Za-z0-9-]+?)-FIRST\b")

@dataclass
class RosterUnit:
    name: str                       # "patches-foo"
    directory: Path                 # declared series dir
    line_no: int
    raw_line: str                   # full snapshot line (declaration scans)
    tags: list[str] = field(default_factory=list)
    base: str | None = None
    base_note: str = ""
    final: str | None = None
    tree: str | None = None
    stack_on: list[str] = field(default_factory=list)   # short names
    land_first: list[str] = field(default_factory=list)  # short names
    recut_of: str | None = None
    # filled during compose:
    touched: set[str] = field(default_factory=set)
    status: str = "pending"         # applied | deferred-declared | failed
    boundary: str | None = None     # composed commit sha after this unit

    @property
    def short(self) -> str:
        return self.name[len("patches-"):]


def _leading_tags(line: str) -> list[str]:
    """Collect the bracketed status tags at the start of a line."""
    tags: list[str] = []
    pos = 0
    while True:
        m = _TAG_RE.match(line, pos)
        if not m:
            break
        tags.append(m.group(1).strip())
        pos = m.end()
    return tags


@dataclass
class Roster:
    units: list[RosterUnit]
    skipped: dict[str, int]         # category -> count
    notes: list[str]
    # per-line verdicts (line_no, category, label) — every non-blank
    # snapshot line gets exactly one categorized adjudication.
    adjudications: list[tuple[int, str, str]] = field(default_factory=list)
    # every series-shaped line (line_no, category, name, text) — the
    # tier-0 citation check resolves cited series against these.
    series_lines: list[tuple[int, str, str, str]] = field(default_factory=list)


def _name_variants(name: str) -> list[str]:
    """Casefolded lookup variants for a series name or constraint target.

    Live spellings carry the ``patches-`` prefix and/or a revision
    suffix that belongs to the seal tag, not the name.
    """
    t = name.casefold()
    out = [t]
    if t.startswith("patches-"):
        out.append(t[len("patches-"):])
    for c in list(out):
        stripped = re.sub(r"-r\d+$", "", c)
        if stripped not in out:
            out.append(stripped)
    return out


_EXCLUSION_CATEGORIES = (
    ("LANDED", "landed"),
    ("SUPERSEDED", "superseded"),
    ("BUILT-UNREVIEWED", "built-unreviewed"),
    ("VERIFY", "verify"),
)


def parse_snapshot(text: str) -> Roster:
    """Parse a frozen registry snapshot into the rostered unit list.

    Roster rule (the assembler contract): every SEALED, non-superseded,
    non-landed series line, in registry order. Both the bracketed
    ``[SEALED ...]`` and the unbracketed ``SEALED patches-x ...``
    spellings roster; a SEALED line with no directory token takes
    ``/tmp/patches-<name>`` by the fleet convention (noted). VERIFY /
    BACKLOG / BUILT-UNREVIEWED lines never roster.

    No silent drops: a SEALED line that cannot be rostered (no series
    name, or a malformed non-absolute directory) is a hard error, and
    any series-shaped line — one that names a patches-* unit or
    directory — matching no known arm is surfaced as a LOUD note plus
    an ``unrecognized`` adjudication. The parser is structurally unable
    to silently bin a series-shaped line.
    """
    units: list[RosterUnit] = []
    skipped: dict[str, int] = {}
    notes: list[str] = []
    adjudications: list[tuple[int, str, str]] = []
    series_lines: list[tuple[int, str, str, str]] = []
    seen: dict[str, int] = {}
    current_line = ""

    def adjudicate(line_no: int, category: str, label: str = "") -> None:
        skipped[category] = skipped.get(category, 0) + 1
        adjudications.append((line_no, category, label))
        if label:
            series_lines.append((line_no, category, label, current_line))

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        # Registry lines are conventionally '#'-prefixed; strip the marker.
        if line.startswith("#"):
            line = line.lstrip("#").strip()
        if not line:
            continue
        current_line = line
        tags = _leading_tags(line)
        body_start = 0
        if tags:
            pos = 0
            while (tm := _TAG_RE.match(line, pos)) is not None:
                pos = tm.end()
            body_start = pos
        else:
            bare = _BARE_STATUS_RE.match(line)
            if bare:
                tags = [bare.group(1)]
                body_start = bare.end()
        tag_heads = [t.split()[0] if t.split() else "" for t in tags]
        # Identity binds to the POST-TAG text: a tag that happens to
        # name ANOTHER series (supersession notes, cross-references)
        # must never steal the line's identity.
        body = line[body_start:]
        nm = _NAME_RE.search(body)
        name_label = nm.group(0).rstrip(".") if nm else ""

        if any(h.startswith("BACKLOG") for h in tag_heads):
            adjudicate(line_no, "backlog", name_label)
            continue
        exclusion = next(
            (
                cat
                for h in tag_heads
                for prefix, cat in _EXCLUSION_CATEGORIES
                if h.startswith(prefix)
            ),
            None,
        )
        if exclusion:
            adjudicate(line_no, exclusion, name_label)
            continue
        sealed = any(h.startswith("SEALED") for h in tag_heads)
        if not sealed:
            if name_label:
                # Series-shaped but no recognized arm: NEVER a silent bin.
                notes.append(
                    f"LOUD: line {line_no} is series-shaped ({name_label}) but "
                    "matches no known arm (not SEALED, not a recognized "
                    "exclusion) — unparsed registry spelling? NOT rostered."
                )
                adjudicate(line_no, "unrecognized", name_label)
            else:
                adjudicate(line_no, "comment")
            continue
        if "do NOT roster" in line:
            adjudicate(line_no, "do-not-roster", name_label)
            continue

        # Identity: explicit "<name> <abs dir>" pair, else the first
        # patches-* token with the convention directory — both from the
        # post-tag body. A SEALED line that yields no identity must
        # refuse the snapshot, not skip.
        m = _SERIES_RE.search(body)
        if m:
            name = m.group("name")
            directory = Path(m.group("dir"))
        else:
            if not nm:
                raise ValueError(
                    f"SEALED line {line_no} cannot be rostered: no series "
                    "name found — fix the registry line or the parser, "
                    "never compose past it"
                )
            name = name_label
            following = body[nm.end():].lstrip(":,;").split()
            if following and "/" in following[0]:
                raise ValueError(
                    f"SEALED line {line_no} ({name}) carries a malformed "
                    f"(non-absolute) directory token {following[0]!r} — "
                    "fix the registry line, never compose past it"
                )
            directory = Path("/tmp") / name
            notes.append(
                f"line {line_no}: {name} has no directory token — using the "
                f"fleet convention {directory}"
            )
        unit = RosterUnit(
            name=name,
            directory=directory,
            line_no=line_no,
            raw_line=line,
            tags=tags,
        )
        bm = _BASE_RE.search(line)
        if bm:
            unit.base = bm.group(1)
            unit.base_note = bm.group(2) or ""
            sm = _BASE_STACK_RE.search(unit.base_note)
            if sm:
                unit.stack_on.append(sm.group(1))
        fm = _FINAL_RE.search(line)
        if fm:
            unit.final = fm.group(1)
        tm = _TREE_RE.search(line)
        if tm:
            unit.tree = tm.group(1)
        for sm in _STACK_ON_RE.finditer(line):
            unit.stack_on.append(sm.group(1))
        for sm in _STACKED_ON_RE.finditer(line):
            unit.stack_on.append(sm.group(1))
        rm = _RECUT_OF_RE.search(line)
        if rm:
            unit.recut_of = rm.group(1)
        for lm in _LAND_FIRST_RE.finditer(line):
            unit.land_first.append(lm.group(1).lower())

        if name in seen:
            raise ValueError(
                f"duplicate rostered series {name!r} at snapshot lines "
                f"{seen[name]} and {line_no} — registry hygiene owed "
                "(one line should carry a SUPERSEDED/LANDED tag)"
            )
        seen[name] = line_no
        adjudications.append((line_no, "rostered", name))
        series_lines.append((line_no, "rostered", name, line))
        units.append(unit)

    return Roster(
        units=units,
        skipped=skipped,
        notes=notes,
        adjudications=adjudications,
        series_lines=series_lines,
    )


def order_roster(roster: Roster) -> list[RosterUnit]:
    """Registry order adjusted by declared stack / order constraints.

    Constraint edges: a unit's STACK target and every LAND-<X>-FIRST
    target apply BEFORE it. Targets not in the roster (already landed)
    are noted and ignored. Cycles are an error.
    """
    units = roster.units
    by_short = {u.short.casefold(): i for i, u in enumerate(units)}
    n = len(units)
    edges: dict[int, set[int]] = {i: set() for i in range(n)}  # dep -> dependents
    indeg = [0] * n

    def match_target(target: str) -> int | None:
        """Resolve a constraint target to a roster index.

        Live spellings carry the ``patches-`` prefix and/or a revision
        suffix that belongs to the seal tag, not the name
        (``STACK=on-patches-foo-r3`` targeting rostered ``patches-foo``);
        try exact first, then prefix- and revision-normalized forms.
        """
        t = target.casefold()
        for cand in _name_variants(target):
            j = by_short.get(cand)
            if j is not None:
                if cand != t:
                    roster.notes.append(
                        f"constraint target {target!r} matched roster unit "
                        f"{units[j].name} via normalization"
                    )
                return j
        return None

    for i, u in enumerate(units):
        for target in u.stack_on + u.land_first:
            j = match_target(target)
            if j is None:
                roster.notes.append(
                    f"{u.name}: constraint target {target!r} not in roster "
                    "(landed or absent) — ignored"
                )
                continue
            if j == i:
                continue
            if i not in edges[j]:
                edges[j].add(i)
                indeg[i] += 1
    # Kahn with registry-index priority (stable order for the unconstrained).
    ready = [i for i in range(n) if indeg[i] == 0]
    heapq.heapify(ready)
    out: list[RosterUnit] = []
    while ready:
        i = heapq.heappop(ready)
        out.append(units[i])
        for j in sorted(edges[i]):
            indeg[j] -= 1
            if indeg[j] == 0:
                heapq.heappush(ready, j)
    if len(out) != n:
        stuck = [units[i].name for i in range(n) if indeg[i] > 0]
        raise ValueError(
            "cycle in declared stack/order constraints involving: "
            + ", ".join(stuck)
        )
    return out


# --------------------------------------------------------------------------
# declared-contact check (the fleet convention, mechanised)
# --------------------------------------------------------------------------


def mentions(line: str, short: str, all_shorts: tuple[str, ...] = ()) -> bool:
    """True when a seal line names another unit's short name.

    Word-boundary aware for hyphenated names: the char before the match
    must not be alphanumeric (a leading '-' is fine — ``patches-foo``,
    ``on-foo`` forms); the char after must not be alphanumeric, and a
    trailing '-' only ends the match when NOT followed by an
    alphanumeric (so ``census-stats`` does not match inside
    ``census-stats-r4``, while ``phphandler->igraph1a`` still matches
    ``phphandler``).

    ``all_shorts`` masks LONGER roster names that contain ``short`` as a
    substring before scanning, so a suffix-shaped name (``stats-r4``)
    cannot be "declared" by a line that merely names its longer sibling
    (``census-stats-r4``) — that would silently demote an undeclared
    conflict to a declared deferral.
    """
    for other in all_shorts:
        if other == short:
            continue
        if len(other) > len(short) and short.casefold() in other.casefold():
            line = re.sub(
                re.escape(other), "\x00" * len(other), line, flags=re.IGNORECASE
            )
    pat = re.compile(
        r"(?<![A-Za-z0-9])" + re.escape(short) + r"(?![A-Za-z0-9])(?!-[A-Za-z0-9])",
        re.IGNORECASE,
    )
    return bool(pat.search(line))


def declared_contact(
    a: RosterUnit, b: RosterUnit, all_shorts: tuple[str, ...] = ()
) -> bool:
    """Either seal line names the other series."""
    return mentions(a.raw_line, b.short, all_shorts) or mentions(
        b.raw_line, a.short, all_shorts
    )


# --------------------------------------------------------------------------
# tier 0 — rehearsal-citation staleness (string check, no compose)
# --------------------------------------------------------------------------

_STACK_CITE_RE = re.compile(r"\bSTACK=on-([A-Za-z0-9._-]+)\(([^)]*)\)")
_STACKED_CITE_RE = re.compile(r"\bSTACKED-ON=patches-([A-Za-z0-9._-]+)\(([^)]*)\)")
_PAREN_SHA_RE = re.compile(r"\b(?:tree|final|composed-tree)[-= ]([0-9a-fA-F]{6,64})\b", re.I)
_COMPOSED_CITE_RE = re.compile(r"\bCOMPOSED-TREE=([0-9a-fA-F]{6,64})\(([^)]*)\)")
_PROSE_CITE_RE = re.compile(r"rehears|compose-verified", re.I)
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{6,64}\b")


def _sha_carried(sha: str, text: str) -> bool:
    """Prefix-tolerant: registry lines abbreviate shas at varying widths."""
    s = sha.casefold()
    for token in _HEX_TOKEN_RE.findall(text):
        t = token.casefold()
        if t.startswith(s) or s.startswith(t):
            return True
    return False


def tier0(roster: Roster) -> tuple[list[Finding], int, list[str]]:
    """Rehearsal-citation staleness check over the rostered lines.

    A seal line's compose/rehearsal citation names another series plus
    a FINAL/TREE sha (``STACK=on-<x>(...,tree-<sha>)``,
    ``BASE=<sha>(=patches-<x>-FINAL...)``). The rehearsal ages when the
    cited series is later recut: the citation keeps pointing at a sha
    no CURRENT line carries. This tier verifies each citation against
    the SAME snapshot: the cited series' current line (rostered, or
    landed with that sha) must carry the cited sha — otherwise the
    rehearsal is STALE and the unit needs a re-rehearsal/recut. Cheap
    string check, runs before any compose.

    Conservative grammar: only machine-checkable (series, sha) shapes
    are verdicts. Joint-artifact citations (``COMPOSED-TREE=<sha>(...)``
    — the sha belongs to no single series) and prose-only rehearsal
    notes surface as notes, never silent skips.
    """
    findings: list[Finding] = []
    notes: list[str] = []
    checked = 0
    family: dict[str, list[tuple[int, str, str, str]]] = {}
    for entry in roster.series_lines:
        for variant in _name_variants(entry[2]):
            family.setdefault(variant, []).append(entry)

    for unit in roster.units:
        line = unit.raw_line
        cites: list[tuple[str, str]] = []
        for m in list(_STACK_CITE_RE.finditer(line)) + list(
            _STACKED_CITE_RE.finditer(line)
        ):
            sm = _PAREN_SHA_RE.search(m.group(2))
            if sm:
                cites.append((m.group(1), sm.group(1)))
        bm = _BASE_RE.search(line)
        if bm and bm.group(2):
            fm = _BASE_STACK_RE.search(bm.group(2))
            if fm:
                cites.append((fm.group(1), bm.group(1)))
        for _cm in _COMPOSED_CITE_RE.finditer(line):
            notes.append(
                f"{unit.name}: COMPOSED-TREE citation is a joint artifact — "
                "not sha-checkable against a single series line; the compose "
                "tiers cover its content"
            )
        if not cites and not _COMPOSED_CITE_RE.search(line) and _PROSE_CITE_RE.search(line):
            notes.append(
                f"{unit.name}: rehearsal/compose prose present but no "
                "machine-checkable citation (series + sha) parsed — not "
                "verified by tier 0"
            )
        for target, sha in cites:
            checked += 1
            # Union the whole family across name variants: a revision-
            # suffixed citation must see BOTH its superseded r-line and
            # the current recut line.
            merged: dict[int, tuple[int, str, str, str]] = {}
            for variant in _name_variants(target):
                for entry in family.get(variant, ()):
                    merged[entry[0]] = entry
            entries: list[tuple[int, str, str, str]] | None = (
                sorted(merged.values()) if merged else None
            )
            if entries is None:
                notes.append(
                    f"{unit.name}: citation target {target!r} has no line in "
                    f"this snapshot (landed-and-cleaned?) — sha {sha} "
                    "unverifiable"
                )
                continue
            entries = [e for e in entries if e[0] != unit.line_no]
            if not entries:
                continue  # self-citation only
            current = [e for e in entries if e[1] in ("rostered", "landed")]
            if not current:
                notes.append(
                    f"{unit.name}: citation target {target!r} has only "
                    "non-current (superseded/unrecognized) lines — sha "
                    f"{sha} unverifiable against a current line"
                )
                continue
            if any(_sha_carried(sha, text) for _ln, _cat, _nm, text in current):
                continue
            carriers = [e for e in entries if _sha_carried(sha, e[3])]
            cited_name = current[0][2]
            if carriers:
                why = (
                    f"cited sha {sha} is carried only by non-current line "
                    f"{carriers[0][0]} ({carriers[0][1]})"
                )
            else:
                why = f"no current line for {cited_name} carries cited sha {sha}"
            findings.append(
                Finding(
                    0,
                    "stale-rehearsal",
                    unit.name,
                    cited_name,
                    f'{why}; citing: "{sanitize(line, 100)}" | current: '
                    f'"{sanitize(current[0][3], 100)}"',
                )
            )
    return findings, checked, notes


# --------------------------------------------------------------------------
# patch payload discovery + touched-file parsing
# --------------------------------------------------------------------------

_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.MULTILINE)
_RENAME_TO_RE = re.compile(r"^rename to (\S+)$", re.MULTILINE)


def unit_payload(directory: Path) -> tuple[str, list[Path]]:
    """Resolve a unit's patch payload: mbox > *.patch > NN.diff."""
    mbox = directory / "series.mbox"
    if mbox.is_file():
        return "mbox", [mbox]
    patches = sorted(directory.glob("[0-9]*.patch"))
    if patches:
        return "patches", patches
    diffs = sorted(directory.glob("[0-9]*.diff"))
    if diffs:
        return "diffs", diffs
    raise FileNotFoundError(
        f"no series.mbox, *.patch or *.diff payload in {directory}"
    )


def touched_paths(payload_files: list[Path]) -> set[str]:
    """Paths touched by a unit's payload (both diff sides, minus /dev/null)."""
    out: set[str] = set()
    for pf in payload_files:
        text = pf.read_text(encoding="utf-8", errors="replace")
        for m in _DIFF_GIT_RE.finditer(text):
            for p in (m.group(1), m.group(2)):
                if p != "/dev/null":
                    out.add(p)
        for m in _RENAME_TO_RE.finditer(text):
            out.add(m.group(1))
    return out


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


@dataclass
class Finding:
    tier: int
    kind: str
    unit: str
    counterpart: str
    detail: str
    files: list[str] = field(default_factory=list)

    def line(self) -> str:
        files = ",".join(sanitize(f, 120) for f in self.files)
        return (
            f"CONTACT-GATE-FINDING: tier={self.tier} kind={self.kind} "
            f"unit={self.unit} counterpart={self.counterpart}"
            + (f" files={files}" if files else "")
            + f' detail="{sanitize(self.detail, 300)}"'
        )

    def as_dict(self) -> dict:
        return {
            "tier": self.tier,
            "kind": self.kind,
            "unit": self.unit,
            "counterpart": self.counterpart,
            "files": self.files,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# scratch composition (tier 1)
# --------------------------------------------------------------------------

_GIT_IDENT = [
    "-c", "user.name=contact-gate",
    "-c", "user.email=contact-gate@localhost",
    "-c", "commit.gpgsign=false",
]


class Compose:
    def __init__(self, source_repo: Path, base_sha: str, scratch: Path) -> None:
        self.source_repo = source_repo
        self.base_sha = base_sha
        self.scratch = scratch
        self.repo = scratch / "repo"
        self.boundaries: list[tuple[str, str]] = []  # (unit name, sha) applied order
        self.touched_by: dict[str, list[str]] = {}   # path -> unit names
        self._base_wt: Path | None = None
        self._probe_wt: Path | None = None

    def git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return run(["git", *_GIT_IDENT, *args], cwd=cwd or self.repo)

    def create(self) -> None:
        self.scratch.mkdir(parents=True, exist_ok=True)
        cp = run(
            ["git", "clone", "--shared", "--no-checkout", "--quiet",
             str(self.source_repo), str(self.repo)],
        )
        if cp.returncode != 0:
            raise RuntimeError(f"scratch clone failed: {cp.stderr.strip()}")
        cp = self.git("checkout", "--detach", "--quiet", self.base_sha)
        if cp.returncode != 0:
            raise RuntimeError(
                f"cannot check out base {self.base_sha}: {cp.stderr.strip()}"
            )

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    def tree(self) -> str:
        return self.git("rev-parse", "HEAD^{tree}").stdout.strip()

    def _unmerged(self) -> list[str]:
        cp = self.git("diff", "--name-only", "--diff-filter=U")
        return [ln for ln in cp.stdout.splitlines() if ln.strip()]

    def _mail_count(self, mbox: Path) -> int:
        """Precise mail count via git's own splitter (never a From-grep)."""
        split_dir = self.scratch / "mailsplit"
        shutil.rmtree(split_dir, ignore_errors=True)
        split_dir.mkdir(parents=True)
        cp = self.git("mailsplit", f"-o{split_dir}", str(mbox))
        try:
            return int(cp.stdout.strip()) if cp.returncode == 0 else -1
        finally:
            shutil.rmtree(split_dir, ignore_errors=True)

    def apply_unit(self, unit: RosterUnit) -> tuple[str, list[str], str]:
        """Apply one unit.

        Returns (status, conflict_files, detail) with status one of
        ``ok`` / ``conflict`` / ``already-applied``.

        Already-applied detection is STRUCTURAL, never message-text:
        ``git am -3`` exits 0 for an already-applied mail while creating
        NO commit for it (a stale seal line would otherwise sail through
        silently), so the created-commit count is compared against the
        payload's mail count — full staleness is HEAD-unchanged, partial
        staleness is a commit shortfall. The diff route refuses to mint
        an empty boundary commit: apply-success with nothing staged is
        the same staleness signal.
        """
        mode, files = unit_payload(unit.directory)
        pre = self.head()
        if mode in ("mbox", "patches"):
            expected = self._mail_count(files[0]) if mode == "mbox" else len(files)
            cp = self.git("am", "-3", "--quiet", *[str(f) for f in files])
            if cp.returncode == 0:
                created = int(
                    self.git("rev-list", "--count", f"{pre}..HEAD").stdout.strip()
                    or "0"
                )
                if created == 0:
                    self.git("reset", "--hard", "--quiet", pre)
                    return "already-applied", [], (
                        "apply succeeded with HEAD unchanged — no commit "
                        "created, the unit's content is already in the "
                        "composed tree (stale seal line / already landed)"
                    )
                if 0 <= expected != created:
                    self.git("reset", "--hard", "--quiet", pre)
                    return "already-applied", [], (
                        f"only {created} of {expected} commits materialized — "
                        "the rest are already in the composed tree (partially "
                        "stale unit; reseal against the current base)"
                    )
                return "ok", [], ""
            conflicts = self._unmerged()
            detail = (cp.stderr.strip() + " " + cp.stdout.strip()).strip()
            self.git("am", "--abort")
            self.git("reset", "--hard", "--quiet", pre)
            self.git("clean", "-fdq")
            return "conflict", conflicts, detail
        # NN.diff route: apply + commit each diff.
        for f in files:
            cp = self.git("apply", "--3way", str(f))
            if cp.returncode != 0:
                conflicts = self._unmerged()
                detail = f"{f.name}: {(cp.stderr.strip() or cp.stdout.strip())}"
                self.git("reset", "--hard", "--quiet", pre)
                self.git("clean", "-fdq")
                return "conflict", conflicts, detail
            self.git("add", "-A")
            if self.git("diff", "--cached", "--quiet").returncode == 0:
                # Nothing staged: this diff's content is already in the
                # tree. An empty boundary is a finding, never a commit.
                self.git("reset", "--hard", "--quiet", pre)
                return "already-applied", [], (
                    f"{f.name}: apply succeeded with nothing to commit — "
                    "content already present in the composed tree (stale "
                    "unit); empty boundary commit refused"
                )
            cc = self.git(
                "commit", "--quiet",
                "-m", f"contact-gate compose: {unit.name} {f.name}",
            )
            if cc.returncode != 0:
                self.git("reset", "--hard", "--quiet", pre)
                return "conflict", [], f"commit failed for {f.name}: {cc.stderr.strip()}"
        return "ok", [], ""

    # -- secondary worktrees for control / attribution runs ---------------

    def worktree_at(self, name: str, sha: str) -> Path:
        wt = self.scratch / name
        if not wt.exists():
            cp = self.git("worktree", "add", "--detach", "--quiet", str(wt), sha)
            if cp.returncode != 0:
                raise RuntimeError(f"worktree add failed: {cp.stderr.strip()}")
        else:
            cp = self.git("checkout", "--detach", "--quiet", sha, cwd=wt)
            if cp.returncode != 0:
                raise RuntimeError(f"worktree checkout failed: {cp.stderr.strip()}")
        return wt

    def base_worktree(self) -> Path:
        return self.worktree_at("base", self.base_sha)

    def probe_worktree(self, sha: str) -> Path:
        return self.worktree_at("probe", sha)


# --------------------------------------------------------------------------
# tier 2 — composed union ruff
# --------------------------------------------------------------------------


def ruff_findings(tree: Path, files: list[str]) -> tuple[set[tuple[str, str, str]], str]:
    """Run repo-config ruff over files at a tree.

    Returns (set of (path, code, message), raw output). Raises when ruff
    is unrunnable — a lint gate that cannot run must not pass.
    """
    if not files:
        return set(), ""
    if shutil.which("ruff") is None:
        raise RuntimeError("ruff not found on PATH — tier 2 cannot run")
    cp = run(
        ["ruff", "check", "--no-cache", "--output-format", "json", *files],
        cwd=tree,
    )
    if cp.returncode not in (0, 1):
        raise RuntimeError(f"ruff failed to run: {cp.stderr.strip()[:400]}")
    found: set[tuple[str, str, str]] = set()
    if cp.stdout.strip():
        try:
            records = json.loads(cp.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"unparseable ruff JSON output: {exc}") from exc
        for rec in records:
            path = os.path.relpath(rec.get("filename", ""), tree)
            found.add((path, rec.get("code") or "", rec.get("message") or ""))
    return found, cp.stdout


# --------------------------------------------------------------------------
# tier 3 — derived composed gate battery
# --------------------------------------------------------------------------

_DYNAMIC_TOKEN_RE = re.compile(r"\$\{\{|\$\(|`|\$[A-Za-z_{]")


_BLOCK_SCALARS = ("|", "|-", "|+", ">", ">-", ">+")


def _run_blocks(workflow_text: str) -> list[list[str]]:
    """Extract the logical shell lines of every ``run:`` block.

    Line-based (the repo's workflow-lint precedent). Handles the
    ``run: <cmd>`` inline form, literal (``run: |``) and folded
    (``run: >``) block scalars including their chomping variants, and
    the ``- run:`` list-item spelling. Folded blocks join into a single
    logical line (YAML folds newlines to spaces; a blank line is a
    paragraph break); backslash continuations join everywhere.
    """
    blocks: list[list[str]] = []
    lines = workflow_text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].lstrip()
        indent = len(lines[i]) - len(stripped)
        if stripped.startswith("- run:"):
            stripped = stripped[2:]
            indent += 2
        if not stripped.startswith("run:"):
            i += 1
            continue
        body = stripped[len("run:"):].strip()
        raw: list[str] = []
        folded = False
        if body and body not in _BLOCK_SCALARS:
            raw.append(body)
            i += 1
        else:
            folded = body.startswith(">")
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                raw.append(nxt.strip())
                i += 1
        if folded:
            paragraphs: list[str] = []
            para: list[str] = []
            for ln in raw:
                if not ln:
                    if para:
                        paragraphs.append(" ".join(para))
                        para = []
                    continue
                para.append(ln)
            if para:
                paragraphs.append(" ".join(para))
            raw = paragraphs
        # join backslash continuations
        joined: list[str] = []
        acc = ""
        for ln in raw:
            if ln.endswith("\\"):
                acc += ln[:-1] + " "
                continue
            acc += ln
            if acc.strip():
                joined.append(acc.strip())
            acc = ""
        if acc.strip():
            joined.append(acc.strip())
        blocks.append(joined)
    return blocks


def _static(tokens: list[str]) -> bool:
    return not any(_DYNAMIC_TOKEN_RE.search(t) for t in tokens)


def _normalize_pytest(tokens: list[str]) -> list[str] | None:
    """Normalize a pytest invocation to ``python3 -m pytest ...`` or None.

    Exclusion rules (each mechanical, each documented):
    * dynamic tokens beyond droppable options — not reproducible here;
    * ``-m <marker>`` selections — marker-conditioned tier dispatch
      (slow / integration lanes), not the repo-invariant battery;
    * report-artifact options (``--junitxml``) are dropped: they point
      at runner-local paths and do not affect the verdict.
    """
    if tokens[0] in ("pytest",):
        rest = tokens[1:]
    elif (
        tokens[0] in ("python", "python3")
        and len(tokens) >= 3
        and tokens[1] == "-m"
        and tokens[2] == "pytest"
    ):
        rest = tokens[3:]
    else:
        return None
    cleaned: list[str] = []
    skip_next = False
    for idx, tok in enumerate(rest):
        if skip_next:
            skip_next = False
            continue
        if tok == "-m" or tok.startswith("-m="):
            return None  # marker-conditioned lane
        if tok.startswith("--junitxml"):
            if "=" not in tok and idx + 1 < len(rest):
                skip_next = True
            continue
        cleaned.append(tok)
    if not _static(cleaned):
        return None
    if not any(not t.startswith("-") for t in cleaned):
        return None  # no static positional target
    return [sys.executable, "-m", "pytest", *cleaned]


def derive_gates(tree: Path) -> list[list[str]]:
    """Derive the standing gate battery from the tree's own workflows.

    Included: static ``python3 .github/scripts/check_*.py`` invocations
    and static, marker-unconditioned pytest invocations found in any
    workflow ``run:`` block. Deduplicated. Never a hand list — a gate
    added to the workflows joins the battery automatically.
    """
    wf_dir = tree / ".github" / "workflows"
    gates: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    if not wf_dir.is_dir():
        return gates
    # *.y*ml: GHA accepts both .yml and .yaml workflow files.
    for wf in sorted(wf_dir.glob("*.y*ml")):
        text = wf.read_text(encoding="utf-8", errors="replace")
        for block in _run_blocks(text):
            for line in block:
                try:
                    tokens = shlex.split(line)
                except ValueError:
                    continue
                if not tokens:
                    continue
                cmd: list[str] | None = None
                if (
                    tokens[0] in ("python", "python3")
                    and len(tokens) >= 2
                    and re.fullmatch(
                        r"\.github/scripts/check_[A-Za-z0-9_]+\.py", tokens[1]
                    )
                ):
                    if _static(tokens[1:]) and (tree / tokens[1]).is_file():
                        cmd = [sys.executable, *tokens[1:]]
                else:
                    cmd = _normalize_pytest(tokens)
                    if cmd is not None:
                        targets = [t for t in cmd[3:] if not t.startswith("-")]
                        if not all((tree / t).exists() for t in targets):
                            cmd = None
                        elif not all(
                            t.startswith(".github/")
                            or t.startswith(".github" + os.sep)
                            or (tree / t).is_file()
                            for t in targets
                        ):
                            # A whole test DIRECTORY outside .github/ is a
                            # subsystem/environment tier dispatch (canary and
                            # matrix lanes), not a pinned repo-invariant
                            # suite; only explicit file lists join the
                            # battery from outside .github/.
                            cmd = None
                if cmd is None:
                    continue
                key = tuple(cmd[1:])
                if key in seen:
                    continue
                seen.add(key)
                gates.append(cmd)
    return gates


def gate_env() -> dict[str, str]:
    env = dict(os.environ)
    env["CLAUDECODE"] = "1"
    return env


def run_gate(cmd: list[str], tree: Path, timeout: int) -> tuple[int, str]:
    extra: list[str] = []
    if cmd[1:3] == ["-m", "pytest"]:
        # -rf: print FAILED node ids in the short summary so red gates
        # can be narrowed for attribution; -p no:cacheprovider keeps the
        # scratch tree byte-stable across probe re-runs.
        extra = ["-rf", "-p", "no:cacheprovider"]
    try:
        cp = run(cmd + extra, cwd=tree, env=gate_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    return cp.returncode, (cp.stdout + "\n" + cp.stderr)


_FAILED_NODE_RE = re.compile(r"^FAILED\s+(\S+)", re.MULTILINE)


def narrow_pytest(cmd: list[str], output: str) -> list[str] | None:
    """Reduce a red pytest gate to its failing node ids (for attribution)."""
    if cmd[1:3] != ["-m", "pytest"]:
        return None
    nodes = _FAILED_NODE_RE.findall(output)
    if not nodes or len(nodes) > 50:
        return None
    return [sys.executable, "-m", "pytest", "-q", *nodes]


def gate_label(cmd: list[str]) -> str:
    shown = ["python3" if c == sys.executable else c for c in cmd]
    return " ".join(shown)


# --------------------------------------------------------------------------
# main gate driver
# --------------------------------------------------------------------------


def resolve_base(repo: Path, ref: str) -> str:
    cp = run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo)
    if cp.returncode != 0:
        raise RuntimeError(f"cannot resolve base {ref!r} in {repo}: {cp.stderr.strip()}")
    return cp.stdout.strip()


def file_intersection_census(units: list[RosterUnit]) -> list[tuple[str, str, list[str]]]:
    """Emit, don't assert: which unit pairs share touched files."""
    out: list[tuple[str, str, list[str]]] = []
    for i, a in enumerate(units):
        for b in units[i + 1:]:
            shared = sorted(a.touched & b.touched)
            if shared:
                out.append((a.name, b.name, shared))
    return out


def tier1(compose: Compose, ordered: list[RosterUnit]) -> list[Finding]:
    findings: list[Finding] = []
    for unit in ordered:
        try:
            mode, payload = unit_payload(unit.directory)
        except FileNotFoundError as exc:
            raise RuntimeError(str(exc)) from exc
        unit.touched = touched_paths(payload)
        status, conflict_files, detail = compose.apply_unit(unit)
        if status == "ok":
            unit.status = "applied"
            unit.boundary = compose.head()
            compose.boundaries.append((unit.name, unit.boundary))
            for p in unit.touched:
                compose.touched_by.setdefault(p, []).append(unit.name)
            continue
        if status == "already-applied":
            # Structural staleness (apply succeeded but produced no /
            # fewer commits): the unit's content is already in the base
            # — a stale seal line must fail LOUDLY, never sail through.
            unit.status = "failed"
            findings.append(
                Finding(
                    1, "already-applied", unit.name, "BASE", detail,
                    sorted(unit.touched)[:8],
                )
            )
            continue
        # conflict: attribute counterpart unit(s) via the touched-file map
        counterparts: list[str] = []
        for f in conflict_files:
            for owner in compose.touched_by.get(f, []):
                if owner not in counterparts:
                    counterparts.append(owner)
        if not conflict_files and not counterparts:
            # apply failure without unmerged paths (e.g. missing
            # pre-image blob) — attribute against the base.
            unit.status = "failed"
            findings.append(
                Finding(
                    1, "base-conflict", unit.name, "BASE", detail,
                    sorted(unit.touched)[:8],
                )
            )
            continue
        if not counterparts:
            unit.status = "failed"
            findings.append(
                Finding(
                    1, "base-conflict", unit.name, "BASE",
                    detail or "conflicts against the base tip — recut owed",
                    conflict_files,
                )
            )
            continue
        by_name = {u.name: u for u in ordered}
        all_shorts = tuple(u.short for u in ordered)
        undeclared = [
            c for c in counterparts
            if not declared_contact(unit, by_name[c], all_shorts)
        ]
        if undeclared:
            unit.status = "failed"
            findings.append(
                Finding(
                    1, "undeclared-conflict", unit.name, ",".join(undeclared),
                    detail or "git 3-way conflict at compose time",
                    conflict_files,
                )
            )
        else:
            unit.status = "deferred-declared"
    return findings


def tier2(compose: Compose, ordered: list[RosterUnit]) -> tuple[list[Finding], int]:
    applied = [u for u in ordered if u.status == "applied"]
    union_py = sorted(
        {
            p for u in applied for p in u.touched
            if p.endswith(".py") and (compose.repo / p).is_file()
        }
    )
    if not union_py:
        return [], 0
    base_wt = compose.base_worktree()
    base_files = [p for p in union_py if (base_wt / p).is_file()]
    base_found, _ = ruff_findings(base_wt, base_files)
    composed_found, _ = ruff_findings(compose.repo, union_py)
    findings: list[Finding] = []
    for path, code, message in sorted(composed_found):
        if (path, code, message) in base_found:
            continue  # pre-existing at base — not a composition contact
        # unit = the last unit that touched the finding file; counterpart =
        # earlier touchers of the same file (the pair), else the base.
        owners = compose.touched_by.get(path, [])
        unit = owners[-1] if owners else "BASE"
        counterpart = ",".join(owners[:-1]) if len(owners) > 1 else "BASE"
        findings.append(
            Finding(2, "composed-ruff", unit, counterpart, f"{code} {message}", [path])
        )
    return findings, len(union_py)


def tier3(
    compose: Compose,
    ordered: list[RosterUnit],
    timeout: int,
    attribute: bool,
) -> tuple[list[Finding], list[dict], int]:
    gates = derive_gates(compose.repo)
    findings: list[Finding] = []
    ledger: list[dict] = []
    base_red = 0
    for cmd in gates:
        label = gate_label(cmd)
        t0 = time.monotonic()
        rc, output = run_gate(cmd, compose.repo, timeout)
        dt = time.monotonic() - t0
        entry = {"gate": label, "rc": rc, "seconds": round(dt, 1)}
        ledger.append(entry)
        if rc == 0:
            continue
        # control: pre-existing red at the bare base is rot, not a contact
        base_wt = compose.base_worktree()
        base_rc: int | None = None
        if cmd[1:3] == ["-m", "pytest"]:
            targets = [t for t in cmd[3:] if not t.startswith("-")]
            runnable_at_base = all((base_wt / t).exists() for t in targets)
        else:
            runnable_at_base = (base_wt / cmd[1]).exists() if len(cmd) > 1 else False
        if runnable_at_base:
            base_rc, _ = run_gate(cmd, base_wt, timeout)
        entry["base_rc"] = base_rc
        if base_rc is not None and base_rc != 0:
            base_red += 1
            entry["classification"] = "base-red"
            print(
                f"contact-gate: WARNING: gate red at the BARE BASE too "
                f"(not charged to the roster): {sanitize(label, 200)}"
            )
            continue
        unit_name = "roster"
        if attribute and compose.boundaries:
            probe_cmd = narrow_pytest(cmd, output) or cmd
            unit_name = _bisect_attribution(compose, probe_cmd, timeout)
        entry["classification"] = "contact"
        entry["attributed_unit"] = unit_name
        tail = "\n".join(output.strip().splitlines()[-15:])
        findings.append(
            Finding(3, "gate-red", unit_name, f"gate:{label}", tail)
        )
    return findings, ledger, base_red


def _bisect_attribution(compose: Compose, cmd: list[str], timeout: int) -> str:
    """First boundary commit at which the (narrowed) gate goes red."""
    boundaries = compose.boundaries
    lo, hi = 0, len(boundaries) - 1  # invariant: red at hi (composed tip)
    first_red: int | None = None
    is_pytest = cmd[1:3] == ["-m", "pytest"]

    def red_at(idx: int) -> bool:
        wt = compose.probe_worktree(boundaries[idx][1])
        rc, _ = run_gate(cmd, wt, timeout)
        if is_pytest and rc in (4, 5):
            # Usage error / nothing collected: the narrowed target does
            # not EXIST at this boundary (e.g. a failing test file a
            # later unit adds) — the breakage is not present yet, so
            # this boundary is not-red. Genuine breakage stays red:
            # test failures exit 1, collection errors exit 2.
            return False
        return rc != 0

    # confirm red at the tip with the (possibly narrowed) probe command
    if not red_at(hi):
        return "roster"
    while lo <= hi:
        mid = (lo + hi) // 2
        if red_at(mid):
            first_red = mid
            hi = mid - 1
        else:
            lo = mid + 1
    if first_red is None:
        return "roster"
    return boundaries[first_red][0]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="contact_gate.py",
        description="Seal-time 3-tier compose probe over the registry-snapshot roster.",
    )
    ap.add_argument("--snapshot", required=True, help="frozen registry snapshot file")
    ap.add_argument("--repo", default=None, help="source repository (default: cwd's toplevel)")
    ap.add_argument("--base", default="origin/main", help="base tip ref (default: origin/main)")
    ap.add_argument("--tiers", default="1,2,3", help="comma list of compose tiers to run (tier 0 and tier 1 always run)")
    ap.add_argument("--json", dest="json_out", default=None, help="write full JSON report here")
    ap.add_argument("--scratch", default=None, help="scratch dir (default: mkdtemp)")
    ap.add_argument("--keep-scratch", action="store_true", help="keep the scratch composition")
    ap.add_argument("--no-attribute", action="store_true", help="skip tier-3 bisect attribution")
    ap.add_argument("--gate-timeout", type=int, default=900, help="per-gate timeout seconds")
    ap.add_argument("--list-roster", action="store_true", help="print the parsed roster and exit")
    ap.add_argument("--list-gates", action="store_true", help="print the derived gate battery at the base tree and exit")
    args = ap.parse_args(argv)

    t_start = time.monotonic()

    snapshot = Path(args.snapshot)
    if not snapshot.is_file():
        die(f"snapshot not found: {snapshot}")
    try:
        roster = parse_snapshot(snapshot.read_text(encoding="utf-8", errors="replace"))
        ordered = order_roster(roster)
    except ValueError as exc:
        die(str(exc))
        return 2

    repo = Path(args.repo).resolve() if args.repo else None
    if repo is None:
        cp = run(["git", "rev-parse", "--show-toplevel"])
        if cp.returncode != 0:
            die("not inside a git repository and no --repo given")
        repo = Path(cp.stdout.strip())

    for note in roster.notes:
        print(f"contact-gate: note: {sanitize(note)}")

    if args.list_roster:
        for u in ordered:
            extra = []
            if u.stack_on:
                extra.append(f"stack-on={','.join(u.stack_on)}")
            if u.land_first:
                extra.append(f"land-first={','.join(u.land_first)}")
            print(
                f"{u.name} dir={u.directory} base={u.base or '?'} "
                + " ".join(extra)
            )
        non_rostered = [a for a in roster.adjudications if a[1] != "rostered"]
        if non_rostered:
            print("non-rostered lines (categorized adjudications):")
            for line_no, category, label in non_rostered:
                suffix = f" ({sanitize(label, 80)})" if label else ""
                print(f"  line {line_no}: {category}{suffix}")
        skipped = " ".join(f"{k}={v}" for k, v in sorted(roster.skipped.items()))
        print(f"CONTACT-GATE: ROSTER units={len(ordered)} skipped[{skipped}]")
        return 0

    try:
        base_sha = resolve_base(repo, args.base)
    except RuntimeError as exc:
        die(str(exc))
        return 2

    tiers = {t.strip() for t in args.tiers.split(",") if t.strip()}

    scratch = Path(args.scratch) if args.scratch else Path(
        tempfile.mkdtemp(prefix="contact-gate-")
    )
    compose = Compose(repo, base_sha, scratch)

    if args.list_gates:
        try:
            compose.create()
        except RuntimeError as exc:
            die(str(exc))
        gates = derive_gates(compose.repo)
        for g in gates:
            print(gate_label(g))
        print(f"CONTACT-GATE: GATES count={len(gates)} base={base_sha[:12]}")
        if not args.keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)
        return 0

    if not ordered:
        print("contact-gate: roster is empty — nothing composes")
        print(
            f"CONTACT-GATE: PASS units=0 base={base_sha[:12]} "
            f"composed-tree={base_sha[:12]} tier0=ok(citations=0) tier1=ok "
            f"tier2=skipped tier3=skipped"
        )
        return 0

    findings: list[Finding] = []
    ledger: list[dict] = []
    base_red = 0
    union_count = 0
    # Tier 0 — rehearsal-citation staleness: pure string check over the
    # snapshot itself, always on, before any compose work.
    t0_findings, t0_citations, t0_notes = tier0(roster)
    for note in t0_notes:
        print(f"contact-gate: tier0 note: {sanitize(note)}")
    findings += t0_findings
    try:
        compose.create()
        findings += tier1(compose, ordered)
        if "2" in tiers:
            t2, union_count = tier2(compose, ordered)
            findings += t2
        if "3" in tiers:
            t3, ledger, base_red = tier3(
                compose, ordered, args.gate_timeout, attribute=not args.no_attribute
            )
            findings += t3
        composed_tree = compose.tree()
    except RuntimeError as exc:
        if not args.keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)
        die(str(exc))
        return 2
    finally:
        if args.keep_scratch:
            print(f"contact-gate: scratch kept at {scratch}")

    # ---- report ----------------------------------------------------------
    applied = [u for u in ordered if u.status == "applied"]
    deferred = [u for u in ordered if u.status == "deferred-declared"]
    census = file_intersection_census(ordered)

    print(f"contact-gate: roster {len(ordered)} unit(s), base {base_sha[:12]}")
    for u in ordered:
        print(f"contact-gate:   {u.name}: {u.status}")
    if deferred:
        print(
            "contact-gate: declared-conflict deferral(s) — composed WITHOUT: "
            + ", ".join(u.name for u in deferred)
        )
    if census:
        print("contact-gate: file-intersection census (flag, not verdict):")
        for a, b, shared in census:
            head = ", ".join(sanitize(s, 120) for s in shared[:4])
            more = f" (+{len(shared) - 4} more)" if len(shared) > 4 else ""
            print(f"contact-gate:   {a} x {b}: {head}{more}")
    for entry in ledger:
        print(
            f"contact-gate: tier3 gate rc={entry['rc']} "
            f"({entry['seconds']}s) {sanitize(entry['gate'], 200)}"
        )
    for f in findings:
        print(f.line())

    tier_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    for f in findings:
        tier_counts[f.tier] += 1
    elapsed = round(time.monotonic() - t_start, 1)

    if args.json_out:
        report = {
            "base": base_sha,
            "composed_tree": composed_tree,
            "units": [
                {
                    "name": u.name,
                    "dir": str(u.directory),
                    "status": u.status,
                    "boundary": u.boundary,
                    "touched": sorted(u.touched),
                }
                for u in ordered
            ],
            "file_intersections": [
                {"a": a, "b": b, "files": s} for a, b, s in census
            ],
            "tier0_citations": t0_citations,
            "tier2_union_files": union_count,
            "tier3_ledger": ledger,
            "tier3_base_red": base_red,
            "findings": [f.as_dict() for f in findings],
            "elapsed_seconds": elapsed,
        }
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if not args.keep_scratch:
        shutil.rmtree(scratch, ignore_errors=True)

    if findings:
        print(
            f"CONTACT-GATE: FAIL findings={len(findings)} "
            f"tier0={tier_counts[0]} tier1={tier_counts[1]} "
            f"tier2={tier_counts[2]} tier3={tier_counts[3]} "
            f"units={len(ordered)} applied={len(applied)} "
            f"deferred-declared={len(deferred)} base={base_sha[:12]} "
            f"composed-tree={composed_tree[:12]} elapsed={elapsed}s"
        )
        return 1
    t2s = f"ok(files={union_count})" if "2" in tiers else "skipped"
    t3s = (
        f"ok(gates={len(ledger)},base-red={base_red})" if "3" in tiers else "skipped"
    )
    print(
        f"CONTACT-GATE: PASS units={len(ordered)} applied={len(applied)} "
        f"deferred-declared={len(deferred)} base={base_sha[:12]} "
        f"composed-tree={composed_tree[:12]} "
        f"tier0=ok(citations={t0_citations}) tier1=ok tier2={t2s} tier3={t3s} "
        f"elapsed={elapsed}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
