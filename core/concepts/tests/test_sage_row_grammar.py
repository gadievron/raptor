"""Round-trip tests for the SAGE evidence-row grammar.

The writer (``core.sage.hooks.store_study_concepts`` via
``core.concepts.model.sage_evidence_row``) and the parsers (the shared
per-line iteration over ``core.concepts.study._SAGE_EVIDENCE_RE`` and
the staleness verifier / reconstruction built on it) share one
grammar; a drift silently disables the cross-run study skip (parse
fails closed to the seed path). These tests pin the round trip on both
the regex level and the hash-verification level.
"""

from __future__ import annotations

from pathlib import Path

from core.concepts.model import Evidence, StudyItem, sage_evidence_row
from core.concepts.study import (
    _SAGE_EVIDENCE_RE,
    _extract_evidence_hashes,
    _iter_evidence_matches,
    _reconstruct_from_sage,
    _verify_evidence_hashes,
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
