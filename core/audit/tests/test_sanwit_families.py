"""Registry integrity + breakout predicates for core.audit.sanwit.

Hermetic: predicates run in Python over strings — no interpreter.
Every predicate matrix row is a KNOWN ground truth of the sink
context's parsing rules, exercised in both directions.
"""

from __future__ import annotations

from core.audit.sanwit._families import (
    FAMILY_HTML,
    FAMILY_SANITIZERS,
    FAMILY_SHELL,
    MAX_PAYLOAD_BYTES,
    SINK_CONTEXTS,
    contexts_for_family,
    scan_shell_word,
)


class TestRegistryIntegrity:
    def test_every_context_is_wellformed(self):
        assert SINK_CONTEXTS, "registry must not be empty"
        for ctx in SINK_CONTEXTS.values():
            assert ctx.family in (FAMILY_HTML, FAMILY_SHELL)
            assert ctx.corpus, f"{ctx.context_id}: empty corpus"
            ids = [pid for pid, _ in ctx.corpus]
            assert len(ids) == len(set(ids)), (
                f"{ctx.context_id}: duplicate payload ids"
            )
            for pid, payload in ctx.corpus:
                assert payload, f"{ctx.context_id}/{pid}: empty payload"
                assert len(payload.encode()) <= MAX_PAYLOAD_BYTES
                assert "\x00" not in payload
            assert callable(ctx.predicate)

    def test_both_families_ship_contexts(self):
        assert contexts_for_family(FAMILY_HTML)
        assert contexts_for_family(FAMILY_SHELL)

    def test_family_sanitizer_seeds(self):
        for family, names in FAMILY_SANITIZERS.items():
            assert names, family
            assert len(names) <= 9, "seed-set policy: <= 9 per category"

    def test_every_corpus_payload_breaks_out_raw(self):
        """Non-vacuity floor: fed through an IDENTITY chain, every
        payload must trip its own context's predicate — a corpus row
        that cannot break out even unsanitized tests nothing."""
        for ctx in SINK_CONTEXTS.values():
            for pid, payload in ctx.corpus:
                check = ctx.predicate(payload)
                assert check.breakout, (
                    f"{ctx.context_id}/{pid}: raw payload does not "
                    "trip the predicate"
                )
                assert check.detail


class TestHtmlPredicates:
    def test_squote_survival(self):
        pred = SINK_CONTEXTS["html-attr-squote"].predicate
        assert pred("x' y").breakout
        assert not pred("x&#039; y").breakout
        assert not pred('x" <b>').breakout  # other chars irrelevant here

    def test_dquote_survival(self):
        pred = SINK_CONTEXTS["html-attr-dquote"].predicate
        assert pred('x" y').breakout
        assert not pred("x&quot; y'").breakout

    def test_unquoted_attr(self):
        pred = SINK_CONTEXTS["html-attr-unquoted"].predicate
        assert pred("x y").breakout          # space terminates value
        assert pred("x\ty").breakout
        assert pred("x>y").breakout
        assert not pred("x&#032;y").breakout

    def test_html_text(self):
        pred = SINK_CONTEXTS["html-text"].predicate
        assert pred("a<b").breakout
        # Quotes and '>' are inert in text context — only '<' opens
        # markup.
        assert not pred("a&lt;b>'\"").breakout


class TestShellCommandPredicate:
    def test_field_splitting_is_breakout(self):
        pred = SINK_CONTEXTS["shell-command"].predicate
        assert pred("x --flag").breakout
        assert "argument" in pred("x --flag").detail

    def test_escaped_and_quoted_forms_are_inert(self):
        pred = SINK_CONTEXTS["shell-command"].predicate
        # escapeshellcmd-style backslash escaping
        assert not pred(r"x\;id").breakout
        assert not pred(r"x\$\(id\)").breakout
        # escapeshellarg-style whole-word quoting
        assert not pred("'x --flag'").breakout
        assert not pred("'x$(id)'").breakout

    def test_active_metachars(self):
        pred = SINK_CONTEXTS["shell-command"].predicate
        for raw in ("x;id", "x|id", "x&id", "x$(id)", "x`id`",
                    "x\nid", "x>o"):
            assert pred(raw).breakout, raw

    def test_unterminated_quote_is_breakout(self):
        pred = SINK_CONTEXTS["shell-command"].predicate
        assert pred("x'").breakout
        assert pred('x"').breakout
        assert pred("x\\").breakout

    def test_scanner_field_counts(self):
        assert scan_shell_word("a b").fields == 2
        assert scan_shell_word("'a b'").fields == 1
        assert scan_shell_word("a' 'b").fields == 1  # quote-joined
        assert scan_shell_word(r"a\ b").fields == 1
        assert scan_shell_word('"a b" c').fields == 2

    def test_scanner_dquote_actives(self):
        scan = scan_shell_word('"$x"')
        assert "$" in scan.active
        assert scan_shell_word(r'"\$x"').active == ()


class TestShellQuoteContextPredicates:
    def test_squote_backslash_does_not_escape(self):
        pred = SINK_CONTEXTS["shell-squote"].predicate
        # sh single quotes have no escape character: \' still closes.
        assert pred(r"\'").breakout
        assert pred("'").breakout
        assert not pred(r"x\;id").breakout

    def test_dquote_actives(self):
        pred = SINK_CONTEXTS["shell-dquote"].predicate
        assert pred("$x").breakout
        assert pred("`y`").breakout
        assert pred('"').breakout
        assert pred("x\\").breakout          # dangling backslash
        assert not pred(r"\$x").breakout
        assert not pred(r"\`y\`").breakout
        assert not pred("plain 'text'").breakout
