"""Synthetic-mutant generator for the /audit calibration corpus.

Usage:
    python3 -m core.audit.corpus.mutate \\
        --fixture out/audit-corpus-fixtures/<repo_key> \\
        --repo-key <repo_key> --ref <pinned sha/tag> \\
        --file <repo-relative path> --function <name> --lines A-B \\
        --operator drop-guard \\
        --out out/mutant-corpus/labels [--check] [--dry-run]

Takes a peer-family member in a PINNED CLEAN fixture tree, applies
ONE mechanical mutation (see the operator table in
``core.audit.corpus.mutation``), and emits a ``.label.json`` with
provenance kind ``synthetic_mutant`` under
``<out>/consistency/``.  The label pins the UNMUTATED upstream; the
mutation spec (operator, site, edits, content hash of the applied
result) is what the corpus runner applies to its per-run tree.

Site finding is deliberately narrow and mechanical: each operator
matches one simple syntactic shape inside the pinned span and
refuses (with an enumerated reason) on anything else — a refusal
means "pick another site", never "improvise a bigger edit".
``--line`` disambiguates when several sites match;
``remove-pair-release`` always requires ``--callee`` (release names
are project vocabulary, never hardcoded here).

``--check`` runs the LLM-free consistency prepass over the clean and
the mutated tree and reports, per the operator's dimension, whether
the family scored consistent pre-mutation and whether the mutant is
flagged post-mutation.  HONESTY: these outcomes are
mutation-operator regression floors conditioned on family-found — an
end-to-end plumbing harness, NOT a real-bug recall estimate (see the
corpus README).  Mutant overlays live OUTSIDE the packaged labels/
dir; run them with ``run_corpus --labels-dir <out>``.

Fixture repos are third-party trees: every source line copied into
label prose is sanitised (``core.security.log_sanitisation``) and
bounded, and the spec size is capped at validation.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

from core.json import save_json
from core.security.log_sanitisation import sanitise_for_terminal
from core.source import read_contained

from .mutation import (
    MUTATION_OPERATORS,
    OPERATOR_INFO,
    MutationError,
    build_mutation_spec,
)

# One edit is (line_start, line_end, replacement_lines).
Edit = tuple[int, int, list[str]]

# Bound on source excerpts quoted into label rationale prose.
_MAX_EXCERPT_CHARS = 120

_LABELER = "mutation-generator"

# ── site finders (one narrow syntactic shape per operator) ─────────

# `if (fn(args)) return ...;` / `if (!fn(args) < 0) goto err;` — a
# single-line guarded call with an early exit.  Dropping the check
# keeps the call and discards its return (census usage: discarded).
# Overlapping-repeat shapes are folded so matching stays linear on a
# pathological line: the optional `!` gates its own whitespace, and
# `[^;]*` subsumes the whitespace before the `;` (all of `\s` is in
# `[^;]`, so the language is identical, with no overlapping spans).
_DROP_RETURN_RE = re.compile(
    r"^(?P<ind>\s*)if\s*\(\s*(?:!\s*)?(?P<fn>[A-Za-z_]\w*)\s*"
    r"\((?P<args>[^()]*)\)\s*(?:[<>!=]=?\s*[-\w]+\s*)?\)\s*"
    r"(?:return\b[^;]*|(?:goto\s+\w+|break|continue)\s*);\s*$",
)

# Null-guard head: `if (!p)` / `if (p == NULL)` — with the early exit
# either on the same line or on the immediately following line.
# `rest` starts right after the `)` — `.*` subsumes the whitespace an
# earlier `\s*` matched (same language on the single-line inputs the
# finder feeds; the one consumer strips the group), so the pattern
# carries no overlapping adjacent repeats.
_NULL_GUARD_HEAD_RE = re.compile(
    r"^\s*if\s*\(\s*(?:!\s*[A-Za-z_]\w*"
    r"|[A-Za-z_]\w*\s*==\s*(?:NULL|nullptr|0))\s*\)(?P<rest>.*)$",
)
# Same fold as _DROP_RETURN_RE: `[^;]*` subsumes the whitespace
# before the `;`, so the trailing `\s*` rides only the branches that
# need it (identical language, no overlapping spans).
_EARLY_EXIT_RE = re.compile(
    r"^\s*(?:return\b[^;]*|(?:goto\s+\w+|break|continue)\s*);\s*$",
)

# Bare single-call statement: `fn(args);`
_CALL_STMT_RE = re.compile(
    r"^(?P<ind>\s*)(?P<fn>[A-Za-z_]\w*)\s*\(.*\)\s*;\s*$",
)

# Relational operator, excluding shifts (`<<` `>>`), arrows (`->`)
# and compound comparisons already consumed by the alternatives.
_REL_OP_RE = re.compile(r"(?<![<>=!&|-])(<=|>=|<(?![<=])|>(?![>=]))")
_FLIP = {"<": "<=", "<=": "<", ">": ">=", ">=": ">"}

# Single-line case arm: `case IDENT: return ...;` / `case IDENT:
# break;` / `case IDENT: goto err;`.  Same fold as _DROP_RETURN_RE:
# `[^;]*` subsumes the whitespace before the `;` (identical language,
# no overlapping adjacent repeats).  Multi-line arms are refused —
# a mutation is one narrow mechanical shape, never an improvised
# region delete.
_CASE_ARM_RE = re.compile(
    r"^\s*case\s+(?P<label>[A-Za-z_]\w*)\s*:\s*"
    r"(?:return\b[^;]*|(?:goto\s+\w+|break|continue)\s*);\s*$",
)


def _candidate_lines(span: tuple[int, int], line: int | None) -> range:
    if line is not None:
        return range(line, line + 1)
    return range(span[0], span[1] + 1)


def find_site(
    lines: list[str],
    span: tuple[int, int],
    operator: str,
    *,
    callee: str | None = None,
    line: int | None = None,
) -> tuple[list[Edit], int]:
    """Locate the mutation site.  Returns ``(edits, site_line)``.

    Raises :class:`MutationError` with an enumerated reason
    (``no-matching-site``, ``callee-required``, ``line-out-of-span``)
    — the generator refuses rather than improvising a larger edit.
    """
    if line is not None and not (span[0] <= line <= span[1]):
        raise MutationError(
            f"line-out-of-span: --line {line} outside the pinned "
            f"span {span[0]}..{span[1]}"
        )

    # Not "_line": that bare name is a registered sanitiser helper
    # (core.security.report_writer_audit._SANITISERS) and the
    # report-writer closure gate's name-shadow arm rejects unrelated
    # local definitions of it.
    def _line_at(i: int) -> str:
        return lines[i - 1] if 1 <= i <= len(lines) else ""

    if operator == "drop-return-check":
        for i in _candidate_lines(span, line):
            m = _DROP_RETURN_RE.match(_line_at(i))
            if not m or (callee and m.group("fn") != callee):
                continue
            repl = f"{m.group('ind')}{m.group('fn')}({m.group('args')});"
            return [(i, i, [repl])], i
        raise MutationError(
            "no-matching-site: no single-line `if (fn(...)) "
            "return/goto ...;` checked call in the span"
            + (f" for callee {callee!r}" if callee else "")
        )

    if operator == "drop-case-arm":
        for i in _candidate_lines(span, line):
            m = _CASE_ARM_RE.match(_line_at(i))
            if not m or (callee and m.group("label") != callee):
                continue
            return [(i, i, [])], i
        raise MutationError(
            "no-matching-site: no single-line `case IDENT: "
            "return/break ...;` arm in the span"
            + (f" for label {callee!r}" if callee else "")
        )

    if operator in ("drop-guard", "drop-slot-guard"):
        for i in _candidate_lines(span, line):
            m = _NULL_GUARD_HEAD_RE.match(_line_at(i))
            if not m:
                continue
            rest = m.group("rest").strip()
            if rest and _EARLY_EXIT_RE.match(rest):
                return [(i, i, [])], i
            if not rest and i < span[1] \
                    and _EARLY_EXIT_RE.match(_line_at(i + 1)):
                return [(i, i + 1, [])], i
        raise MutationError(
            "no-matching-site: no single-statement null-guard with "
            "an early exit in the span"
        )

    if operator == "flip-bound":
        for i in _candidate_lines(span, line):
            text = _line_at(i)
            head = text.strip()
            if line is None and not head.startswith(
                ("if", "for", "while"),
            ):
                continue
            m = _REL_OP_RE.search(text)
            if not m:
                continue
            flipped = text[:m.start(1)] + _FLIP[m.group(1)] \
                + text[m.end(1):]
            return [(i, i, [flipped])], i
        raise MutationError(
            "no-matching-site: no relational comparison on an "
            "if/for/while line in the span (pass --line for other "
            "shapes)"
        )

    if operator == "swap-order":
        for i in _candidate_lines(span, line):
            if i + 1 > span[1]:
                break
            m1 = _CALL_STMT_RE.match(_line_at(i))
            m2 = _CALL_STMT_RE.match(_line_at(i + 1))
            if not m1 or not m2:
                continue
            if m1.group("fn") == m2.group("fn"):
                continue
            if callee and callee not in (
                m1.group("fn"), m2.group("fn"),
            ):
                continue
            return [(i, i + 1, [_line_at(i + 1), _line_at(i)])], i
        raise MutationError(
            "no-matching-site: no adjacent pair of distinct bare "
            "call statements in the span"
        )

    if operator == "remove-pair-release":
        if not callee:
            raise MutationError(
                "callee-required: remove-pair-release needs --callee "
                "(release names are project vocabulary, never "
                "hardcoded here)"
            )
        for i in _candidate_lines(span, line):
            m = _CALL_STMT_RE.match(_line_at(i))
            if m and m.group("fn") == callee:
                return [(i, i, [])], i
        raise MutationError(
            f"no-matching-site: no bare `{callee}(...);` statement "
            f"in the span"
        )

    raise MutationError(
        f"unknown operator {operator!r}; must be one of "
        f"{sorted(MUTATION_OPERATORS)}"
    )


# ── detection harness (LLM-free prepass, clean vs mutated) ─────────

# Mechanical-record detector ids that belong to each dimension (the
# census's return-check hits carry a "dimension" field instead).
_DIMENSION_DETECTORS = {
    "guard-presence": {
        "guard_presence_deviation", "insufficient_guard_smt",
    },
    "ordering": {"ordering_deviation"},
    "cleanup": {"cleanup_deviation"},
    "return-check": set(),
    "guard-predicate": set(),
    "interface": {"interface_deviation"},
    "enum-switch": {"enum_switch_deviation"},
}


def _peer_groups_for_texts(
    texts: dict[str, str],
) -> list[Any] | None:
    """Peer groups for the detection harness's prepass runs.

    The interface dimension only votes over resolver-formed groups;
    the harness forms them the same way prep does — the L7 census
    over the fixture texts, joined to the texts' own function spans.
    Returns ``None`` when no family forms (every other operator's
    fixtures), leaving prior operators' outcomes byte-identical.
    """
    try:
        from core.analysis.interface_slots import (
            interface_slot_families,
        )
        from core.analysis.peer_groups import interface_slot_groups
        from core.audit.consistency_dimensions import function_spans
    except ImportError:  # pragma: no cover - trimmed deployment
        return None

    families = interface_slot_families(texts)
    if not families:
        return None
    functions = [
        {"name": name, "file": file_path, "line": start}
        for file_path, name, start, _lines in function_spans(texts)
    ]
    return interface_slot_groups(families, functions) or None


def _dimension_hits(
    prepass: dict[str, Any],
    *,
    dimension: str,
    file: str,
    function: str,
) -> list[dict[str, Any]]:
    detectors = _DIMENSION_DETECTORS.get(dimension, set())
    hits = []
    for rec in (
        list(prepass.get("leads") or [])
        + list(prepass.get("findings") or [])
        + list(prepass.get("mechanical") or [])
    ):
        if rec.get("file") != file:
            continue
        fn = rec.get("function") or rec.get("enclosing_function") or ""
        if fn != function:
            continue
        if rec.get("dimension") == dimension \
                or rec.get("detector") in detectors:
            hits.append(rec)
    return hits


def check_detection(
    clean_texts: dict[str, str],
    mutated_texts: dict[str, str],
    *,
    operator: str,
    file: str,
    function: str,
    domain_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the LLM-free consistency prepass on both trees and report
    the operator's dimension outcome at the mutated function.

    Returns ``{"dimension", "family_clean", "detected", "pre_hits",
    "post_hits"}``.  ``family_clean`` = the CLEAN tree produced no
    hit at the site (the family scores consistent);  ``detected`` =
    the MUTATED tree flags the deviant.  Both conditioned on
    family-found: this is the regression-floor harness, not a recall
    measurement.
    """
    from core.audit.consistency_prepass import run_consistency_prepass

    dimension = OPERATOR_INFO[operator][0]
    pre = run_consistency_prepass(
        clean_texts, domain_model=domain_model,
        peer_groups=_peer_groups_for_texts(clean_texts),
    )
    post = run_consistency_prepass(
        mutated_texts, domain_model=domain_model,
        peer_groups=_peer_groups_for_texts(mutated_texts),
    )
    pre_hits = _dimension_hits(
        pre, dimension=dimension, file=file, function=function,
    )
    post_hits = _dimension_hits(
        post, dimension=dimension, file=file, function=function,
    )
    return {
        "dimension": dimension,
        "family_clean": not pre_hits,
        "detected": bool(post_hits),
        "pre_hits": pre_hits,
        "post_hits": post_hits,
    }


# ── label assembly ─────────────────────────────────────────────────

def build_mutant_label(
    text: str,
    *,
    repo_key: str,
    ref: str,
    file: str,
    function: str,
    span: tuple[int, int],
    operator: str,
    callee: str | None = None,
    line: int | None = None,
    cwe: str = "",
) -> Any:
    """Find the site, build the verified spec, and return the
    ``FunctionLabel`` (validated by construction).  Raises
    :class:`MutationError` on refusal.
    """
    from .label import FunctionLabel, SourcePin, compute_span_sha

    edits, site_line = find_site(
        text.split("\n"), span, operator, callee=callee, line=line,  # line-model: universal-newline read_contained upstream (no \r survives the decode) and the view must be build_mutation_spec's exact raw split — split_lines drops the trailing empty element, shifting its len(lines) edit bound
    )
    spec = build_mutation_spec(
        text,
        line_start=span[0], line_end=span[1],
        operator=operator, site_line=site_line, edits=edits,
    )
    dimension, default_cwe = OPERATOR_INFO[operator]
    original = text.split("\n")[site_line - 1].strip()  # line-model: prose excerpt only (universal-newline read upstream, .strip() drops any stray \r); indexed with the spec's own raw-split line numbering
    excerpt = sanitise_for_terminal(
        original, max_len=_MAX_EXCERPT_CHARS,
    )
    rationale = (
        f"Synthetic mutant ({operator}): mechanical edit at "
        f"{file}:{site_line} of the pinned clean ref (original line: "
        f"`{excerpt}`). Expected: the {dimension} consistency "
        f"dimension flags the deviant against its peer family. "
        f"Regression floor for the mutation operator — NOT a real "
        f"defect report; the flaw is machine-introduced and exists "
        f"only in the run-private mutated tree."
    )
    return FunctionLabel(
        function_id=f"{file}:{function}",
        bug_class="consistency",
        expected_status="finding",
        rationale=rationale,
        source=SourcePin(
            repo=repo_key,
            sha=ref,
            file=file,
            line_start=span[0],
            line_end=span[1],
            span_sha=compute_span_sha(text, span[0], span[1]),
        ),
        labeler=_LABELER,
        labeled_at=date.today().isoformat(),
        cwe=cwe or default_cwe,
        expected_mechanism="consistency",
        excerpt_scope="peer_set",
        provenance_kind="synthetic_mutant",
        mutation=spec,
    )


def _slug(file: str, function: str, operator: str) -> str:
    raw = f"{Path(file).stem}-{function}-{operator}"
    return re.sub(r"[^-\w.]", "_", raw)


def _parse_lines(value: str) -> tuple[int, int]:
    m = re.fullmatch(r"(\d+)-(\d+)", value.strip())
    if not m:
        raise argparse.ArgumentTypeError(
            "expected A-B (1-indexed inclusive line range)",
        )
    a, b = int(m.group(1)), int(m.group(2))
    if not (1 <= a <= b):
        raise argparse.ArgumentTypeError("need 1 <= A <= B")
    return a, b


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m core.audit.corpus.mutate",
        description=(
            "Generate one synthetic-mutant corpus label from a "
            "pinned clean fixture tree (regression floors, never "
            "recall estimates — see the corpus README)"
        ),
    )
    parser.add_argument(
        "--fixture", type=Path, required=True,
        help="Clean fixture tree checked out at the pinned ref",
    )
    parser.add_argument("--repo-key", required=True,
                        help="sources.json repo key")
    parser.add_argument("--ref", required=True,
                        help="Pinned ref (sha/tag) of the fixture")
    parser.add_argument("--file", required=True,
                        help="Repo-relative source file")
    parser.add_argument("--function", required=True,
                        help="Enclosing function of the mutated span")
    parser.add_argument(
        "--lines", type=_parse_lines, required=True, metavar="A-B",
        help="Pinned function span (1-indexed inclusive)",
    )
    parser.add_argument(
        "--operator", required=True, choices=sorted(MUTATION_OPERATORS),
    )
    parser.add_argument(
        "--callee", default=None,
        help="Restrict the site to this callee (required for "
             "remove-pair-release; for drop-case-arm it names the "
             "case label)",
    )
    parser.add_argument(
        "--line", type=int, default=None,
        help="Exact site line (disambiguates multiple matches)",
    )
    parser.add_argument(
        "--cwe", default="",
        help="Override the operator's default CWE",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Label overlay directory (label lands under "
             "<out>/consistency/). Required unless --dry-run",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Run the LLM-free consistency prepass over the clean "
             "and mutated file and report the dimension outcome "
             "(regression-floor harness; informational)",
    )
    parser.add_argument(
        "--domain-model", type=Path, default=None,
        help="domain-model.json for --check (cleanup/ordering need "
             "learned pairs from a study pass)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the label and the mutated span; write nothing",
    )
    args = parser.parse_args(argv)

    if args.out is None and not args.dry_run:
        parser.error("--out is required unless --dry-run")

    src_path = args.fixture / args.file
    if not src_path.is_file():
        print(f"source file not found: {src_path}", file=sys.stderr)
        return 1
    # Containment-checked, capped read (core.source doctrine): --file
    # is repo-relative by contract, so a traversal or symlink escape
    # out of the fixture root refuses here; a span past the cap fails
    # closed downstream (line-range and span-sha verification).
    text = read_contained(args.fixture, args.file)
    if text is None:
        print(
            f"source file unreadable or escapes the fixture root: "
            f"{src_path}",
            file=sys.stderr,
        )
        return 1

    try:
        label = build_mutant_label(
            text,
            repo_key=args.repo_key,
            ref=args.ref,
            file=args.file,
            function=args.function,
            span=args.lines,
            operator=args.operator,
            callee=args.callee,
            line=args.line,
            cwe=args.cwe,
        )
    except (MutationError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1

    spec = label.mutation
    print(f"Operator: {args.operator} "
          f"(dimension: {OPERATOR_INFO[args.operator][0]})")
    print(f"Site: {args.file}:{spec['site_line']}")
    print(f"Edits: {len(spec['edits'])}, mutated span "
          f"{label.source.line_start}..{spec['mutated_line_end']} "
          f"(sha {spec['mutated_span_sha']})")

    if args.check:
        from core.json import load_json
        from .mutation import apply_mutation_to_text

        domain_model = None
        if args.domain_model is not None:
            domain_model = load_json(
                args.domain_model, max_bytes=64 * 1024 * 1024,
            )
        mutated = apply_mutation_to_text(text, label)
        outcome = check_detection(
            {args.file: text},
            {args.file: mutated},
            operator=args.operator,
            file=args.file,
            function=args.function,
            domain_model=domain_model,
        )
        print(
            f"Check ({outcome['dimension']}): family_clean="
            f"{outcome['family_clean']} detected={outcome['detected']}"
            f" — regression floor conditioned on family-found, not a"
            f" recall estimate"
        )

    if args.dry_run:
        print("Dry run — label not written.")
        return 0

    out_path = (
        args.out / "consistency"
        / f"{_slug(args.file, args.function, args.operator)}.label.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(out_path, label.to_dict())
    print(f"Label written to {out_path}")
    print(f"Run it with: python3 -m core.audit.corpus.run_corpus "
          f"--labels-dir {args.out} --fetch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
