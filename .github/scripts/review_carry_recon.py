#!/usr/bin/env python3
"""Review-cycle carry reconciler — mechanical closure proof for KNOWN-OPEN files.

When a review cycle ends, its open findings are carried into the next cycle's
KNOWN-OPEN file. History shows the carry step leaks when hand-built: finding
sections with no carry row, and series-NOTES deferrals never mirrored. This
tool proves closure mechanically: every item in each declared source universe
must be disposed of exactly once in the new KNOWN-OPEN file — carried, owned,
or dropped-with-note (a claim inside a "dropped/resolved" section is still a
claim; the row itself is the note). Exit is non-zero on any drop, double
claim, or unknown reference.

Source universes (each opt-in):

1. ``--findings TAG=DIR`` — prior findings directory. Every ``### [SEV]``
   heading in ``DIR/*.md`` (keyed UNIT:line, UNIT = filename stem; the
   whitespace between ``###`` and ``[`` is matched Unicode-aware AND may be
   absent entirely, so double-space, NBSP-drifted and zero-space ``###[P1]``
   headings all join the universe) must be claimed via
   ``[src: TAG:UNIT:l1,l2]`` or covered by exactly one
   ``[agg: TAG:UNIT:SEV1,SEV2]`` severity aggregate. An explicit claim takes
   a heading out of its unit's aggregate remainder. Heading-LIKE lines that
   still fail the grammar (``## [P1]``, ``#### x [P2]``) surface as a
   counted per-file warning so the next drift spelling is loud, not silent.
2. ``--prior-known-open TAG=PATH`` — the previous KNOWN-OPEN file. Every
   ``- `` row under a ``## X.`` / ``## §X.`` section (keyed ``X<ordinal>``,
   e.g. ``A3``) must be claimed via ``[src: TAG:A3]``. Rows already
   adjudicated out of the carry are skipped with ``--prior-exempt TAG:A3``.
3. ``--notes SERIES=PATH`` — a fix-series NOTES file. Every top-level ``- ``
   row matching ``--notes-pattern`` (default ``(?i)\\bdefer``, case-insensitive
   so ``Deferred:`` spellings cannot escape) must be claimed via
   ``[src: NOTES:SERIES:lineno]``. This is the deferral mirror: a NOTES row
   alone is not routing. Blind spot, made loud: deferral-shaped text OUTSIDE
   top-level ``- `` rows (markdown tables, prose, indented sub-bullets) does
   NOT join the universe — the reconciler prints a counted warning per NOTES
   file when the pattern matches such lines, so table-styled dispositions
   surface instead of vanishing.
4. ``--p1-count N`` — priority findings of record, ids 1..N. Each must be
   claimed exactly once via ``[p1: 1,4,7-9]``.
5. ``--require-ref NAME`` — free-form references (e.g. ``HF:hotfixname``)
   that must appear in at least one ``[src: ...]`` token.

Claims are read only from top-level ``- `` rows of the new KNOWN-OPEN file;
prose and code blocks never claim. ``+`` joins several sources in one token:
``[src: TAG:U01:12+NOTES:seriesx:88]``.

``--emit-stubs`` additionally prints a ready-to-paste stub row for every
undisposed item, so the carry section is generated mechanically and then
hand-pruned — never hand-built. With ``--emit-stubs`` the new KNOWN-OPEN file
may be absent (treated as empty) to bootstrap the file.

Typical invocation, from the coordinator, at prep and again after ANY edit:

    review_carry_recon.py --known-open /tmp/review-next/KNOWN-OPEN.md \\
        --findings prev=/tmp/review-prev/findings \\
        --prior-known-open KO=/tmp/review-prev/KNOWN-OPEN.md \\
        --prior-exempt KO:G1 --notes seriesx=/tmp/patches-seriesx/NOTES.md \\
        --p1-count 46 --require-ref HF:hotfixname
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

# \s* is Unicode-aware in str patterns: NBSP, double spaces, tabs — and NO
# whitespace at all — between the marker and the severity bracket keep a
# drifted heading in the universe (the zero-space ``###[P1]`` spelling is an
# equally plausible authoring slip and silently dropped under ``\s+``). The
# ``[`` anchor keeps ``####`` sub-headings out: after three ``#`` the next
# non-space char must open the severity bracket.
HEADING_RE = re.compile(r"^###\s*\[([A-Z0-9]+)\]\s*(.*)")
# Heading-LIKE lines that fail HEADING_RE (two/four hashes, stray chars
# before the bracket) are the NEXT drift spelling: not enforced, but they
# must surface as a counted advisory instead of vanishing silently.
HEADING_LIKE_RE = re.compile(r"^#{2,4}.{0,3}\[[A-Z0-9]{1,10}\]")
SECTION_RE = re.compile(r"^## §?([A-Z])[.\s]")
SRC_RE = re.compile(r"\[src:\s*([^\]]+)\]")
AGG_RE = re.compile(r"\[agg:\s*([A-Za-z0-9_.\-]+):([A-Za-z0-9_-]+):([A-Z0-9,]+)\]")
P1_RE = re.compile(r"\[p1:\s*([\d,\s-]+)\]")


class Universe:
    """The declared source universes and the claims made against them."""

    def __init__(self) -> None:
        # (tag, unit, line) -> (severity, heading text)
        self.findings: dict[tuple[str, str, int], tuple[str, str]] = {}
        # (tag, row-id) -> row text; row-id = section letter + ordinal
        self.prior_rows: dict[tuple[str, str], str] = {}
        self.prior_exempt: set[tuple[str, str]] = set()
        # (series, lineno) -> row text
        self.notes_rows: dict[tuple[str, int], str] = {}
        self.p1_count: int = 0
        self.require_refs: set[str] = set()
        # series -> count of pattern matches outside top-level '- ' rows
        self.notes_advisory: collections.Counter[str] = collections.Counter()
        # "tag:unit" -> count of heading-LIKE lines outside HEADING_RE
        self.findings_advisory: collections.Counter[str] = collections.Counter()
        self.findings_tags: set[str] = set()
        self.prior_tags: set[str] = set()
        self.notes_series: set[str] = set()


def load_findings(uni: Universe, tag: str, directory: Path) -> None:
    for path in sorted(directory.glob("*.md")):
        unit = path.stem
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            m = HEADING_RE.match(line)
            if m:
                uni.findings[(tag, unit, lineno)] = (m.group(1), m.group(2).strip())
            elif HEADING_LIKE_RE.match(line):
                uni.findings_advisory[f"{tag}:{unit}"] += 1


def load_prior_known_open(uni: Universe, tag: str, path: Path) -> None:
    section: str | None = None
    ordinal = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        m = SECTION_RE.match(line)
        if m:
            section, ordinal = m.group(1), 0
            continue
        if section and line.startswith("- "):
            ordinal += 1
            uni.prior_rows[(tag, f"{section}{ordinal}")] = line[2:].strip()


def load_notes(uni: Universe, series: str, path: Path, pattern: re.Pattern[str]) -> None:
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not pattern.search(line):
            continue
        if line.startswith("- "):
            uni.notes_rows[(series, lineno)] = line[2:].strip()
        else:
            uni.notes_advisory[series] += 1


class Claims:
    """Claims parsed from the new KNOWN-OPEN file's top-level rows."""

    def __init__(self) -> None:
        self.findings: dict[tuple[str, str, int], list[int]] = collections.defaultdict(list)
        self.aggs: dict[tuple[str, str, str], list[int]] = collections.defaultdict(list)
        self.prior: dict[tuple[str, str], list[int]] = collections.defaultdict(list)
        self.notes: dict[tuple[str, int], list[int]] = collections.defaultdict(list)
        self.p1: dict[int, list[int]] = collections.defaultdict(list)
        self.refs_seen: set[str] = set()
        self.rows_by_section: collections.Counter[str] = collections.Counter()
        self.errors: list[str] = []


def parse_src_part(uni: Universe, claims: Claims, lineno: int, part: str) -> None:
    part = part.strip()
    if not part:
        return
    if part in uni.require_refs:
        claims.refs_seen.add(part)
        return
    head, _, body = part.partition(":")
    if head == "NOTES":
        series, _, num = body.rpartition(":")
        if series not in uni.notes_series or not num.isdigit():
            claims.errors.append(f"L{lineno}: unknown NOTES src '{part}'")
            return
        key = (series, int(num))
        if key not in uni.notes_rows:
            claims.errors.append(f"L{lineno}: unknown NOTES row {series}:{num}")
        claims.notes[key].append(lineno)
        return
    if head in uni.prior_tags:
        row = body.strip()
        if (head, row) not in uni.prior_rows:
            claims.errors.append(f"L{lineno}: unknown {head} row '{row}'")
            return
        claims.prior[(head, row)].append(lineno)
        return
    if head in uni.findings_tags:
        m = re.match(r"([A-Za-z0-9_-]+):([\d,]+)$", body)
        if not m:
            claims.errors.append(f"L{lineno}: bad {head} src '{part}'")
            return
        unit = m.group(1)
        for num in m.group(2).split(","):
            key = (head, unit, int(num))
            if key not in uni.findings:
                claims.errors.append(f"L{lineno}: unknown finding {head}:{unit}:{num}")
            claims.findings[key].append(lineno)
        return
    claims.errors.append(f"L{lineno}: unparsed src '{part}'")


def parse_known_open(uni: Universe, text: str) -> Claims:
    claims = Claims()
    section: str | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = SECTION_RE.match(line)
        if m:
            section = m.group(1)
            continue
        if not line.startswith("- "):
            continue
        if section:
            claims.rows_by_section[section] += 1
        for token in SRC_RE.findall(line):
            for part in token.split("+"):
                parse_src_part(uni, claims, lineno, part)
        for tag, unit, sevs in AGG_RE.findall(line):
            if tag not in uni.findings_tags:
                claims.errors.append(f"L{lineno}: unknown agg tag '{tag}'")
                continue
            for sev in sevs.split(","):
                claims.aggs[(tag, unit, sev)].append(lineno)
        for token in P1_RE.findall(line):
            for part in token.split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    for n in range(int(lo), int(hi) + 1):
                        claims.p1[n].append(lineno)
                else:
                    claims.p1[int(part)].append(lineno)
    return claims


def reconcile(uni: Universe, claims: Claims) -> tuple[list[str], list[str], collections.Counter[str]]:
    """Return (errors, stub rows for undisposed items, disposition tally)."""
    errors = list(claims.errors)
    stubs: list[str] = []
    tally: collections.Counter[str] = collections.Counter()

    for key in sorted(uni.findings):
        tag, unit, line = key
        sev, text = uni.findings[key]
        explicit = claims.findings.get(key, [])
        agg = claims.aggs.get((tag, unit, sev), [])
        if len(explicit) > 1:
            errors.append(
                f"finding {tag}:{unit}:{line} explicitly claimed "
                f"{len(explicit)}x (lines {explicit})"
            )
        elif len(explicit) == 1:
            tally["finding-explicit"] += 1
        elif len(agg) == 1:
            tally["finding-aggregate"] += 1
        elif len(agg) > 1:
            errors.append(
                f"finding {tag}:{unit}:{line} covered by {len(agg)} aggregates (lines {agg})"
            )
        else:
            errors.append(f"DROP: finding {tag}:{unit}:{line} [{sev}] has no disposition")
            stubs.append(f"- [src: {tag}:{unit}:{line}] [{sev}] {text} — OPEN — owner TBD.")

    for key in sorted(uni.prior_rows):
        if key in uni.prior_exempt:
            tally["prior-exempt"] += 1
            continue
        tag, row = key
        got = claims.prior.get(key, [])
        if not got:
            errors.append(f"DROP: {tag} row {row} has no disposition")
            stubs.append(
                f"- [src: {tag}:{row}] {uni.prior_rows[key][:120]} — OPEN — owner TBD."
            )
        elif len(got) > 1:
            errors.append(f"{tag} row {row} claimed {len(got)}x (lines {got})")
        else:
            tally["prior-carried"] += 1

    for key in sorted(uni.notes_rows):
        series, lineno = key
        got = claims.notes.get(key, [])
        if not got:
            errors.append(f"DROP: NOTES deferral {series}:{lineno} is unmirrored")
            stubs.append(
                f"- [src: NOTES:{series}:{lineno}] {uni.notes_rows[key][:120]}"
                " — OPEN — owner TBD."
            )
        elif len(got) > 1:
            errors.append(f"NOTES deferral {series}:{lineno} claimed {len(got)}x (lines {got})")
        else:
            tally["notes-mirrored"] += 1

    for n in range(1, uni.p1_count + 1):
        got = claims.p1.get(n, [])
        if len(got) != 1:
            errors.append(f"P1 #{n} claimed {len(got)}x (lines {got})")
            if not got:
                stubs.append(f"- [p1: {n}] — OPEN — owner TBD.")
        else:
            tally["p1-owned"] += 1
    for n in sorted(claims.p1):
        if not 1 <= n <= uni.p1_count:
            errors.append(f"unknown P1 id #{n}")

    for name in sorted(uni.require_refs - claims.refs_seen):
        errors.append(f"required ref '{name}' unreferenced")
        stubs.append(f"- [src: {name}] — OPEN — owner TBD.")

    return errors, stubs, tally


def _split_pair(value: str, flag: str) -> tuple[str, str]:
    name, sep, path = value.partition("=")
    if not sep or not name or not path:
        raise SystemExit(f"error: {flag} expects NAME=PATH, got '{value}'")
    return name, path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--known-open", required=True, help="the new KNOWN-OPEN file to verify")
    parser.add_argument(
        "--findings", action="append", default=[], metavar="TAG=DIR",
        help="prior findings dir; headings claimed as [src: TAG:UNIT:line] / [agg: ...]",
    )
    parser.add_argument(
        "--prior-known-open", action="append", default=[], metavar="TAG=PATH",
        help="prior KNOWN-OPEN file; rows claimed as [src: TAG:<SectionOrdinal>]",
    )
    parser.add_argument(
        "--prior-exempt", action="append", default=[], metavar="TAG:ROW",
        help="prior row adjudicated out of the carry (repeatable)",
    )
    parser.add_argument(
        "--notes", action="append", default=[], metavar="SERIES=PATH",
        help="series NOTES file; deferral rows claimed as [src: NOTES:SERIES:lineno]",
    )
    parser.add_argument(
        "--notes-pattern", default=r"(?i)\bdefer",
        help="regex selecting NOTES rows that demand a mirror "
             "(default: %(default)s — case-insensitive)",
    )
    parser.add_argument(
        "--p1-count", type=int, default=0,
        help="priority findings of record; each of 1..N needs exactly one [p1: N]",
    )
    parser.add_argument(
        "--require-ref", action="append", default=[], metavar="NAME",
        help="reference that must appear in at least one [src: ...] (repeatable)",
    )
    parser.add_argument(
        "--emit-stubs", action="store_true",
        help="print a paste-ready stub row per undisposed item (generate, then hand-prune)",
    )
    args = parser.parse_args(argv)

    uni = Universe()
    for value in args.findings:
        tag, path = _split_pair(value, "--findings")
        uni.findings_tags.add(tag)
        load_findings(uni, tag, Path(path))
    for value in args.prior_known_open:
        tag, path = _split_pair(value, "--prior-known-open")
        uni.prior_tags.add(tag)
        load_prior_known_open(uni, tag, Path(path))
    for value in args.prior_exempt:
        tag, sep, row = value.partition(":")
        if not sep:
            raise SystemExit(f"error: --prior-exempt expects TAG:ROW, got '{value}'")
        uni.prior_exempt.add((tag, row))
    try:
        notes_pattern = re.compile(args.notes_pattern)
    except re.error as exc:
        raise SystemExit(f"error: bad --notes-pattern: {exc}") from exc
    for value in args.notes:
        series, path = _split_pair(value, "--notes")
        uni.notes_series.add(series)
        load_notes(uni, series, Path(path), notes_pattern)
    uni.p1_count = args.p1_count
    uni.require_refs = set(args.require_ref)
    if "NOTES" in (uni.findings_tags | uni.prior_tags):
        raise SystemExit("error: tag 'NOTES' is reserved for --notes claims")

    known_open = Path(args.known_open)
    if known_open.exists():
        text = known_open.read_text(encoding="utf-8")
    elif args.emit_stubs:
        text = ""
    else:
        raise SystemExit(f"error: {known_open} does not exist (bootstrap with --emit-stubs)")

    claims = parse_known_open(uni, text)
    errors, stubs, tally = reconcile(uni, claims)

    print(
        f"universes: {len(uni.findings)} finding headings, "
        f"{len(uni.prior_rows)} prior rows ({len(uni.prior_exempt)} exempt), "
        f"{len(uni.notes_rows)} NOTES deferrals, {uni.p1_count} P1s, "
        f"{len(uni.require_refs)} required refs"
    )
    print(f"dispositions: {dict(sorted(tally.items()))}")
    for unit, count in sorted(uni.findings_advisory.items()):
        print(
            f"warning: findings {unit}: {count} heading-like line(s) "
            "outside HEADING_RE — not in the universe; fix the heading "
            "spelling (### [SEV]) or these findings are invisible to "
            "the carry"
        )
    for series, count in sorted(uni.notes_advisory.items()):
        print(
            f"warning: NOTES {series}: --notes-pattern matched {count} "
            "non-bullet line(s) — not enforced; only top-level '- ' rows "
            "join the deferral universe"
        )
    if claims.rows_by_section:
        print(f"rows by section: {dict(sorted(claims.rows_by_section.items()))}")
    if args.emit_stubs and stubs:
        print(f"\n== {len(stubs)} stub row(s) for undisposed items ==")
        for stub in stubs:
            print(stub)
    if errors:
        print(f"\nRECONCILIATION FAILED — {len(errors)} problem(s):")
        for err in errors:
            print("  " + err)
        return 1
    print("\nRECONCILIATION CLEAN — zero drops, zero double-claims.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
