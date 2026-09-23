"""Round-trip tests for the SAGE evidence-row grammar.

The writer (``core.sage.hooks.store_study_concepts`` via
``core.concepts.model.sage_evidence_row``) and the parsers (the shared
per-line iteration over ``core.concepts.study._SAGE_EVIDENCE_RE`` and
the staleness verifier / reconstruction built on it) share one
grammar; a drift silently disables the cross-run study skip (parse
fails closed to the seed path). These tests pin the round trip on the
regex level, the hash-verification level, and the composite-fold
level.
"""

from __future__ import annotations

from pathlib import Path

from core.concepts.model import (
    Evidence,
    StudyItem,
    evidence_hash_composite,
    sage_evidence_row,
)
from core.concepts.study import (
    _SAGE_EVIDENCE_RE,
    _extract_evidence_hashes,
    _iter_evidence_matches,
    _reconstruct_from_sage,
    _verify_evidence_hashes,
    stamped_evidence_composite,
)


def test_row_with_line_and_hash_round_trips():
    ev = Evidence(type="code_path", file="src/mm.c", line=42,
                  observation="alloc without size check", hash="ab12cd34ef56")
    row = sage_evidence_row(ev)
    m = _SAGE_EVIDENCE_RE.match(row.strip())
    assert m is not None
    assert m.group(1) == "code_path"
    assert m.group(2).strip() == "src/mm.c"
    assert m.group(3) == "42"
    assert m.group(4) == "ab12cd34ef56"
    assert m.group(5).strip() == "alloc without size check"


def test_row_without_hash_round_trips():
    ev = Evidence(type="api_pattern", file="src/api.c", line=7,
                  observation="callback registered")
    row = sage_evidence_row(ev)
    m = _SAGE_EVIDENCE_RE.match(row.strip())
    assert m is not None
    assert m.group(2).strip() == "src/api.c"
    assert m.group(3) == "7"
    assert m.group(4) is None
    assert m.group(5).strip() == "callback registered"


def test_row_without_line_round_trips():
    ev = Evidence(type="doc", file="README.md",
                  observation="documented ownership transfer")
    row = sage_evidence_row(ev)
    m = _SAGE_EVIDENCE_RE.match(row.strip())
    assert m is not None
    assert m.group(2).strip() == "README.md"
    assert m.group(3) is None
    assert m.group(5).strip() == "documented ownership transfer"


def test_hash_extraction_sees_written_hashes():
    ev = Evidence(type="code_path", file="a.c", line=1,
                  observation="x", hash="deadbeef1234")
    content = "Concept [c.x] in scope: d\n" + sage_evidence_row(ev)
    assert _extract_evidence_hashes(content) == {"deadbeef1234"}


def test_written_row_verifies_and_detects_drift(tmp_path: Path):
    # Writer -> staleness-verifier round trip: a row rendered by the
    # shared helper over a real source span verifies fresh, and stops
    # verifying when the span changes.
    from core.staleness import hash_spans

    src = tmp_path / "mm.c"
    src.write_text("int a;\nchar *p = malloc(n);\nint b;\n")
    h = hash_spans(src, [(2, 2)])[0]
    assert h
    ev = Evidence(type="code_path", file="mm.c", line=2,
                  observation="unchecked alloc", hash=h)
    content = "Concept [c.mm] in scope: d\n" + sage_evidence_row(ev)
    assert _verify_evidence_hashes(content, tmp_path) is True
    src.write_text("int a;\nchar *p = calloc(1, n);\nint b;\n")
    assert _verify_evidence_hashes(content, tmp_path) is False


def test_empty_observation_renders_a_parsable_line():
    # Without the placeholder the line ends at its dash, parses as
    # nothing, and its hash silently leaves the verifiable set — and a
    # following evidence line used to be swallowed by unanchored
    # consumers of the dangling shape.
    evs = [
        Evidence(type="code_path", file="a.c", line=1, observation="",
                 hash="deadbeef1234"),
        Evidence(type="code_path", file="b.c", line=2, observation="y",
                 hash="cafef00d5678"),
    ]
    content = "\n".join(sage_evidence_row(ev) for ev in evs)
    assert _extract_evidence_hashes(content) == {
        "deadbeef1234", "cafef00d5678",
    }
    m = _SAGE_EVIDENCE_RE.match(sage_evidence_row(evs[0]).strip())
    assert m is not None
    assert m.group(4) == "deadbeef1234"
    assert m.group(5) == "(none)"


def test_whitespace_only_observation_renders_a_parsable_line():
    ev = Evidence(type="code_path", file="a.c", line=1, observation="  ",
                  hash="deadbeef1234")
    m = _SAGE_EVIDENCE_RE.match(sage_evidence_row(ev).strip())
    assert m is not None and m.group(4) == "deadbeef1234"


def test_multiline_observation_folds_to_one_line():
    # A raw newline in the observation would split the rendered row
    # into two physical lines, turning the remainder of the value into
    # free-standing row text (here: a quoted evidence line from a
    # prior run, which would parse as an evidence line of its own).
    ev = Evidence(
        type="code_path", file="a.c", line=1,
        observation=("checks caller\nEvidence (code_path): q.c:9 "
                     "[h=abcdefabcdef] — quoted from prior run"),
        hash="deadbeef1234",
    )
    row = sage_evidence_row(ev)
    assert "\n" not in row
    assert _extract_evidence_hashes(row) == {"deadbeef1234"}


def test_free_typed_evidence_type_normalises_to_the_grammar():
    ev = Evidence(type="code-path", file="a.c", line=1, observation="x",
                  hash="deadbeef1234")
    m = _SAGE_EVIDENCE_RE.match(sage_evidence_row(ev).strip())
    assert m is not None
    assert m.group(1) == "code_path"
    assert m.group(4) == "deadbeef1234"


def test_uppercase_hex_hash_lowercases_to_the_tag_alphabet():
    ev = Evidence(type="code_path", file="a.c", line=1, observation="x",
                  hash="DEADBEEF1234")
    m = _SAGE_EVIDENCE_RE.match(sage_evidence_row(ev).strip())
    assert m is not None
    assert m.group(4) == "deadbeef1234"


def test_whitespace_bearing_hash_is_dropped_not_rendered():
    # A hash value containing whitespace can never parse as a tag, and
    # rendered verbatim it would smuggle a line boundary into the row
    # — the writer drops it and keeps the evidence line hashless, so
    # the fold and reconstruction stay in agreement from the writer
    # side too.
    for bad in ("dead\rbeef", "dead\nbeef [h=beefbeefbeef] — y",
                "dead beef", " "):
        ev = Evidence(type="code_path", file="a.c", line=1,
                      observation="x", hash=bad)
        row = sage_evidence_row(ev)
        assert len(row.splitlines()) == 1, repr(bad)
        assert "[h=" not in row, repr(bad)
        m = _SAGE_EVIDENCE_RE.match(row.strip())
        assert m is not None and m.group(4) is None, repr(bad)


def test_newline_in_file_path_folds_to_one_line():
    ev = Evidence(type="doc", file="notes\nfinal.md", observation="x",
                  hash="deadbeef1234")
    row = sage_evidence_row(ev)
    assert "\n" not in row
    assert _extract_evidence_hashes(row) == {"deadbeef1234"}


def test_dash_terminated_line_cannot_swallow_the_next_line():
    # A line ending at its dash has no observation and does not parse;
    # critically, it must not absorb the NEXT physical line either. An
    # unanchored multi-line scan let the dangling match's whitespace
    # cross the newline and swallow the following hashed evidence line
    # into its observation group — the extracted hash set then differed
    # from the lines the per-line reconstruction parser mints.
    content = (
        "Concept [c.x] in scope: d\n"
        "  Evidence (code_path): mm.c:7 [h=cafef00d5678] —\n"
        "Evidence (code_path): sh.c:3 [h=aaaabbbbcccc] — trailing line"
    )
    assert _extract_evidence_hashes(content) == {"aaaabbbbcccc"}
    assert [m.group(4) for m in _iter_evidence_matches(content)] == [
        "aaaabbbbcccc"
    ]


def test_extraction_and_reconstruction_agree_on_hashed_lines():
    # The load-bearing agreement: every hashed evidence line that
    # reconstruction turns into an Evidence object is visible to the
    # shared extraction (and therefore to the staleness verifier) —
    # including a line following a dash-terminated one.
    content = (
        "Concept [c.x] in scope: d\n"
        "  Evidence (code_path): a.c:1 [h=deadbeef1234] — kept\n"
        "  Evidence (code_path): mm.c:7 [h=cafef00d5678] —\n"
        "Evidence (code_path): sh.c:3 [h=aaaabbbbcccc] — trailing line"
    )
    item = StudyItem(id="i1", kind="function", name="c.x", file="a.c")
    reconstructed = _reconstruct_from_sage(item, content)
    assert reconstructed is not None
    minted = {ev.hash for c in reconstructed[0] for ev in c.evidence if ev.hash}
    assert minted == _extract_evidence_hashes(content)
    assert minted == {"deadbeef1234", "aaaabbbbcccc"}


def test_verifier_checks_every_line_reconstruction_mints(tmp_path: Path):
    # Staleness verifier on the shared discipline: a hashed line after
    # a dash-terminated line is checked (here: its file is absent, so
    # verification fails) instead of being swallowed unseen while the
    # reconstruction parser mints it.
    from core.staleness import hash_spans

    src = tmp_path / "mm.c"
    src.write_text("".join(f"mm line {i}\n" for i in range(1, 10)))
    real = hash_spans(src, [(7, 7)])[0]
    assert real
    content = (
        "Concept [c.x] in scope: d\n"
        f"  Evidence (code_path): mm.c:7 [h={real}] —\n"
        "Evidence (code_path): sh.c:3 [h=aaaabbbbcccc] — hidden claim"
    )
    assert _verify_evidence_hashes(content, tmp_path) is False


def test_line_boundary_characters_split_for_every_consumer():
    # \r, \v, \f, FS, NEL, U+2028 are line boundaries for the shared
    # iteration but ordinary ./\s characters for the regex. A consumer
    # with a private "\n" split once read such a line as ONE parsing
    # line while the fold read two non-parsing fragments — a hash the
    # fold and the freshness verifier never saw was still minted by
    # reconstruction. On the shared split the fragments parse as
    # nothing for everyone.
    item = StudyItem(id="i1", kind="function", name="c.x", file="a.c")
    boundaries = ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85",
                  "\u2028", "\u2029")
    # Separator at every position class of the forged line: inside the
    # keyword region, between fields, after the location, inside the
    # hash region, and at the tag/dash boundary — each yields
    # fragments that parse as nothing for every consumer.
    shapes = (
        "  Evidence{b}(code_path): sh.c:3 [h=aaaabbbbcccc] — hidden",
        "  Evidence (code_path):{b}sh.c:3 [h=aaaabbbbcccc] — hidden",
        "  Evidence (code_path): sh.c:3{b} [h=aaaabbbbcccc] — hidden",
        "  Evidence (code_path): sh.c:3 [h=aaaabb{b}bbcccc] — hidden",
        "  Evidence (code_path): sh.c:3 [h=aaaabbbbcccc]{b}— hidden",
    )
    for boundary in boundaries:
        for shape in shapes:
            content = (
                "Concept [c.x] in scope: d\n"
                "  Evidence (code_path): a.c:1 [h=deadbeef1234] — kept\n"
                + shape.format(b=boundary)
            )
            got = _extract_evidence_hashes(content)
            assert "aaaabbbbcccc" not in got, (repr(boundary), shape)
            reconstructed = _reconstruct_from_sage(item, content)
            assert reconstructed is not None
            minted = {
                ev.hash for c in reconstructed[0]
                for ev in c.evidence if ev.hash
            }
            assert minted == got, (repr(boundary), shape)


def test_fold_and_reconstruction_agree_under_boundary_fuzz():
    # Seeded property sweep over the full str.splitlines boundary
    # charset: whatever shape the mutated content takes, the hashes
    # reconstruction mints are EXACTLY the hashes the fold (and so the
    # composite check and the freshness verifier) sees — the two walk
    # the same (line, match) pairs.
    import random
    from collections import Counter

    rng = random.Random(20260922)
    seps = ["\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85",
            "\u2028", "\u2029", " ", "\n", "\t", ""]
    frags = ["Evidence (t): sh.c:3", "[h=aaaabbbbcccc]", "—", "-",
             "FORGED", "Evidence (u):", "x.c:9", "[h=", "]",
             "Source hash: ffff", ":", "  ",
             "Evidence (code_path): q.c:7 [h=cafef00d5678] — obs"]
    base = (
        "Concept [c.x] in scope: d\n"
        "  Evidence (code_path): a.c:1 [h=deadbeef1234] — kept\n"
        "  Study scope: s"
    )
    item = StudyItem(id="i1", kind="function", name="c.x", file="a.c")
    for _ in range(300):
        lines = base.split("\n")
        for _ in range(rng.randrange(1, 4)):
            bits = []
            for _ in range(rng.randrange(2, 7)):
                bits.append(rng.choice(frags))
                bits.append(rng.choice(seps))
            lines.insert(rng.randrange(1, len(lines)), "".join(bits))
        content = "\n".join(lines)
        folded = Counter(
            m.group(4) for m in _iter_evidence_matches(content)
            if m.group(4)
        )
        reconstructed = _reconstruct_from_sage(item, content)
        minted: Counter = Counter()
        if reconstructed is not None:
            minted = Counter(
                ev.hash for c in reconstructed[0]
                for ev in c.evidence if ev.hash
            )
        assert not (minted - folded), repr(content)
        if reconstructed is not None:
            assert minted == folded, repr(content)


def test_mid_line_evidence_text_is_not_an_evidence_line():
    # Anchored per line: evidence-shaped text that does not START a
    # line (a quoted mention inside an observation) is part of that
    # line's observation, never an extracted line of its own — the
    # same reading reconstruction has always had.
    content = (
        "Concept [c.x] in scope: d\n"
        "  Evidence (code_path): a.c:1 [h=deadbeef1234] — quotes "
        "Evidence (code_path): q.c:9 [h=abcdefabcdef] — from a prior run"
    )
    assert _extract_evidence_hashes(content) == {"deadbeef1234"}


def test_composite_formula_shape():
    # The formula the writer binds into the row MAC: sorted fold, full
    # SHA-256 hex, empty in -> empty out.
    from core.hash import sha256_string

    hashes = ["bb22", "aa11"]
    assert evidence_hash_composite(hashes) == sha256_string("aa11|bb22")
    assert evidence_hash_composite([]) == ""


def test_composite_order_independent_duplicate_sensitive():
    # Order never matters (sorted fold); multiplicity does (one entry
    # per evidence line, so a duplicated hash folds differently from a
    # single occurrence).
    assert (evidence_hash_composite(["a1", "b2"])
            == evidence_hash_composite(["b2", "a1"]))
    assert (evidence_hash_composite(["a1", "a1"])
            != evidence_hash_composite(["a1"]))


def test_stamped_composite_folds_extracted_lines():
    # Fold over rendered rows == fold over the hashes the per-line
    # extraction reads back (hashless lines contribute nothing).
    evs = [
        Evidence(type="code_path", file="a.c", line=1,
                 observation="x", hash="deadbeef1234"),
        Evidence(type="api_pattern", file="b.c", line=2,
                 observation="y", hash="cafef00d5678"),
        Evidence(type="doc", file="README.md", observation="no hash"),
    ]
    content = "Concept [c.x] in scope: d\n" + "\n".join(
        sage_evidence_row(ev) for ev in evs
    )
    assert stamped_evidence_composite(content) == evidence_hash_composite(
        ["deadbeef1234", "cafef00d5678"]
    )


def test_stamped_composite_preserves_duplicate_lines():
    # Two evidence lines sharing a hash fold as two entries — a set
    # here would let one be added or dropped without moving the value.
    ev = Evidence(type="code_path", file="a.c", line=1,
                  observation="x", hash="deadbeef1234")
    content = "\n".join([sage_evidence_row(ev), sage_evidence_row(ev)])
    assert stamped_evidence_composite(content) == evidence_hash_composite(
        ["deadbeef1234", "deadbeef1234"]
    )


def test_stamped_composite_empty_without_hashes():
    ev = Evidence(type="doc", file="README.md", observation="prose only")
    content = "Concept [c.x] in scope: d\n" + sage_evidence_row(ev)
    assert stamped_evidence_composite(content) == ""


def test_stamped_composite_ignores_hash_tokens_outside_evidence_lines():
    # Hash-shaped tokens in observation prose or on non-evidence lines
    # never fold: extraction is the per-line evidence grammar, and the
    # tag slot is the only fold source.
    ev = Evidence(type="code_path", file="a.c", line=1,
                  observation="see [h=ffffffffffff] upstream",
                  hash="deadbeef1234")
    content = "\n".join([
        "Concept [c.x] in scope: d",
        sage_evidence_row(ev),
        "  Invariant [c.x.i1]: token [h=abcdefabcdef] shape (negation: n)",
    ])
    assert stamped_evidence_composite(content) == evidence_hash_composite(
        ["deadbeef1234"]
    )


def test_writer_fold_matches_gate_fold_on_awkward_values():
    # Mint-through-parser property at the grammar level: for value
    # shapes whose rendering the parser reads differently than the
    # Evidence objects suggest (a file path containing the spaced dash
    # separator — the parse then takes the FIRST dash and the hash tag
    # lands in the observation), folding the rendered content is the
    # same computation the recall gate will run, so the two always
    # agree. What such a row loses is only the mis-rendered hash's
    # contribution to freshness — never its mechanical reach.
    ev = Evidence(type="doc", file="notes — draft.md", line=3,
                  observation="x", hash="deadbeef1234")
    content = "Concept [c.x] in scope: d\n" + sage_evidence_row(ev)
    fold = stamped_evidence_composite(content)
    assert fold == stamped_evidence_composite(content)  # deterministic
    # adjudicated parse: first spaced dash wins, hash not extracted
    assert _extract_evidence_hashes(content) == set()
    assert fold == ""


def test_hash_grammar_matches_stamped_hash_alphabet(tmp_path: Path):
    # hash_spans emits lowercase-hex prefixes; the evidence grammar's
    # tag slot ([a-f0-9]+) must accept every hash the stamper
    # produces — checked through the shared extraction, the reading
    # every consumer actually uses.
    from core.staleness import hash_spans

    src = tmp_path / "x.c"
    src.write_text("line one\n")
    h = hash_spans(src, [(1, 1)])[0]
    assert h
    row = sage_evidence_row(Evidence(type="code_path", file="x.c",
                                     line=1, observation="o", hash=h))
    assert _extract_evidence_hashes(row) == {h}


def test_line_zero_evidence_keeps_its_anchor():
    """line=0 is a real anchor (whole-file evidence): the writer must
    render it, or the parser round-trip loses the hash anchor."""
    from core.concepts.model import Evidence, sage_evidence_row

    row = sage_evidence_row(Evidence(
        type="code_path", file="a.c", observation="obs",
        line=0, hash="beef1234",
    ))
    assert "a.c:0" in row
    assert "[h=beef1234]" in row


def test_invariant_row_round_trips():
    from core.concepts.study import _SAGE_INVARIANT_RE

    row = ("Invariant [inv-1]: len is validated before copy "
           "(negation: copy with unvalidated len)")
    m = _SAGE_INVARIANT_RE.match(row)
    assert m is not None
    assert m.group(1) == "inv-1"
    assert (m.group(2) or "").strip() == "len is validated before copy"
    assert m.group(3).strip() == "copy with unvalidated len"


def test_invariant_row_whitespace_run_is_fast():
    """Hostile recall line opening 'Invariant [x]:' and ending in a
    long whitespace run with no '(negation:': the previous trim
    spelling \\s+(.*?)\\s*\\( overlapped three unbounded repeats on
    whitespace and tried every split of the run between them — cubic
    in the line length. The \\S-delimited statement spelling is
    linear."""
    from core.concepts.study import _SAGE_INVARIANT_RE
    from core.testing.wallclock import cpu_budget

    hostile = "Invariant [x]: y" + " " * (1 << 16) + "("
    with cpu_budget(1.0, what="invariant-row whitespace-run scan"):
        assert _SAGE_INVARIANT_RE.match(hostile) is None
