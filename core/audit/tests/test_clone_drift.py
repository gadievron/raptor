"""Cloned-block drift (§3.9): fix-anchored + generic winnowing legs.

Fixture pairs: the fix-anchored near-clone missing the fix's guard
must confirm promote-capable with ``contract_source: fix_commit``;
the low-similarity pair must form no group; identical clones must
produce no deviation.
"""

from __future__ import annotations

import json
import textwrap

from core.audit.clone_drift import (
    CLONE_SIMILARITY,
    detect_clone_drift,
    fix_anchored_drift,
    load_fix_anchors,
)
from core.audit.consistency_verify import clone_drift_verdict
from core.audit.evidence_grade import is_tool_evidence
from core.testing import requires_ts

_GUARDED = textwrap.dedent("""\
    int handle_packet(pkt_t *p, size_t n) {
        if (validate_len(p, n) != 0)
            return -1;
        for (size_t i = 0; i < n; i++) {
            acc += p->data[i] * scale_factor(p, i);
            emit_sample(acc, p->flags, i);
        }
        flush_output(p, acc);
        return finalize_packet(p, acc, n);
    }
""")

# Same body, renamed identifiers, guard missing.
_DRIFTED = textwrap.dedent("""\
    int handle_frame(frm_t *f, size_t count) {
        for (size_t j = 0; j < count; j++) {
            total += f->data[j] * scale_factor(f, j);
            emit_sample(total, f->flags, j);
        }
        flush_output(f, total);
        return finalize_packet(f, total, count);
    }
""")

_UNRELATED = textwrap.dedent("""\
    char *format_name(const char *a, const char *b) {
        char *out = malloc(64);
        snprintf(out, 64, "%s.%s", a, b);
        return out;
    }
""")


class TestGenericWinnowing:
    @requires_ts('c')
    def test_guard_divergence_between_near_clones(self):
        devs = detect_clone_drift({
            "src/pkt.c": _GUARDED,
            "src/frm.c": _DRIFTED,
        })
        guard = [d for d in devs if d.kind == "guard"]
        assert len(guard) == 1
        d = guard[0]
        assert d.token == "validate_len"
        assert d.enclosing_function == "handle_frame"
        assert d.peer_function == "handle_packet"
        assert d.similarity >= CLONE_SIMILARITY
        pe = d.peer_evidence
        assert pe.dimension == "clone-drift"
        assert pe.formation == "clone"
        assert pe.contract_source == "majority"
        assert pe.rule_id == "consistency:clone-drift-majority"

    def test_low_similarity_pair_forms_no_group(self):
        devs = detect_clone_drift({
            "src/pkt.c": _GUARDED,
            "src/name.c": _UNRELATED,
        })
        assert devs == []

    def test_identical_clones_no_divergence(self):
        devs = detect_clone_drift({
            "src/a.c": _GUARDED,
            "src/b.c": _GUARDED.replace("handle_packet", "handle_copy"),
        })
        assert devs == []

    def test_short_functions_below_token_floor_skipped(self):
        short_a = "int a(void) { if (chk()) return 1; return 0; }\n"
        short_b = "int b(void) { return 0; }\n"
        assert detect_clone_drift({
            "src/a.c": short_a, "src/b.c": short_b,
        }) == []

    def test_detection_variant_never_standalone_evidence(self):
        assert not is_tool_evidence("consistency:clone-drift-majority")
        assert is_tool_evidence("consistency:clone-drift")


def _anchor(*, guard: str = "validate_len") -> dict:
    return {
        "file": "src/frm.c",
        "name": "handle_frame",
        "sha": "a" * 40,
        "guard": guard,
        "sensitive": "finalize_packet",
        "fixed_file": "src/pkt.c",
        "fixed_line": 2,
        "fixed_region": _GUARDED,
    }


class TestFixAnchoredLeg:
    @requires_ts('c')
    def test_near_clone_missing_guard_promotes(self):
        devs = fix_anchored_drift([_anchor()], {"src/frm.c": _DRIFTED})
        assert len(devs) == 1
        d = devs[0]
        assert d.kind == "fix_anchor"
        assert d.registry_grade
        assert d.fix_sha == "a" * 40
        pe = d.peer_evidence
        assert pe.contract_source == "fix_commit"
        assert pe.registry_grade
        assert pe.rule_id == "consistency:clone-drift"
        assert pe.provenance == f"fix_commit:{'a' * 12}"

        res = clone_drift_verdict(d)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:clone-drift"
        assert res.contract["source"] == "fix_commit"
        assert res.contract["grade"] == "registry"

    def test_guard_present_refutes_the_anchor(self):
        devs = fix_anchored_drift(
            [_anchor()],
            {"src/frm.c": _DRIFTED.replace(
                "for (size_t j = 0;",
                "if (validate_len(f, count) != 0)\n"
                "        return -1;\n"
                "    for (size_t j = 0;",
            )},
        )
        assert devs == []

    def test_low_containment_no_finding(self):
        devs = fix_anchored_drift(
            [_anchor()],
            {"src/frm.c": _UNRELATED.replace(
                "format_name", "handle_frame",
            ).replace("src/name.c", "src/frm.c")},
        )
        assert devs == []

    def test_anchors_loaded_from_fix_history_artifact(self, tmp_path):
        (tmp_path / "fix-history.json").write_text(json.dumps({
            "fixes": [],
            "variant_gaps": [],
            "regression_gaps": [],
            "variant_sites": [_anchor()],
        }))
        anchors = load_fix_anchors(tmp_path)
        assert len(anchors) == 1
        assert anchors[0]["guard"] == "validate_len"
        assert load_fix_anchors(tmp_path / "missing") == []


class TestVariantSiteRecords:
    def test_apply_fix_history_persists_anchor_records(self, tmp_path):
        """The additive variant_sites field carries the clone anchor:
        sha + guard + the current-tree fixed region."""
        from core.audit.fix_history import (
            SecurityFix,
            _variant_site_records,
        )

        target = tmp_path / "repo"
        target.mkdir()
        (target / "pkt.c").write_text(_GUARDED)
        fix = SecurityFix(
            sha="b" * 40,
            subject="fix overflow: validate length",
            category="overflow",
            added={"pkt.c": [(2, "    if (validate_len(p, n) != 0)")]},
        )
        variant_gap = {
            "file": "frm.c",
            "name": "handle_frame",
            "fix_anchor": {
                "sha": "b" * 40,
                "guard": "validate_len",
                "sensitive": "finalize_packet",
            },
        }
        records = _variant_site_records([variant_gap], [fix], target)
        assert len(records) == 1
        r = records[0]
        assert r["sha"] == "b" * 40
        assert r["guard"] == "validate_len"
        assert r["fixed_file"] == "pkt.c"
        assert "validate_len" in r["fixed_region"]

    def test_no_anchor_no_record(self, tmp_path):
        from core.audit.fix_history import _variant_site_records

        assert _variant_site_records(
            [{"file": "a.c", "name": "f"}], [], tmp_path,
        ) == []


class TestPrepassWiring:
    @requires_ts('c')
    def test_fix_anchored_finding_and_generic_lead(self, tmp_path):
        from core.audit.consistency_prepass import run_consistency_prepass

        (tmp_path / "fix-history.json").write_text(json.dumps({
            "variant_sites": [_anchor()],
        }))
        res = run_consistency_prepass(
            {"src/pkt.c": _GUARDED, "src/frm.c": _DRIFTED},
            out_dir=tmp_path,
        )
        drift_findings = [
            f for f in res["findings"]
            if f["dimension"] == "clone-drift"
        ]
        assert len(drift_findings) == 1
        f = drift_findings[0]
        assert f["rule_id"] == "consistency:clone-drift"
        assert f["detection_grade"] is False
        assert res["telemetry"]["contract_sources"].get(
            "fix_commit") == 1
        # The generic leg sees the same pair and seeds a lead.
        generic_leads = [
            ld for ld in res["leads"]
            if ld["dimension"] == "clone-drift"
            and ld["rule_id"] == "consistency:clone-drift-majority"
        ]
        assert generic_leads


class TestGrammarAbsentDegradation:
    """Grammar-absent must be a LOUD degraded signal, not a silent
    zero-deviation result — the fix-anchored leg is promote-capable
    and used to drop every fix anchor unchecked."""

    @staticmethod
    def _block_grammar(monkeypatch):
        import core.audit.consistency_dimensions as cd
        monkeypatch.setattr(cd, "_TS_AVAILABLE", False)

    def test_fix_anchored_leg_signals_degraded(
        self, monkeypatch, caplog,
    ):
        from core.audit.clone_drift import fix_anchored_drift

        self._block_grammar(monkeypatch)
        telemetry: dict = {}
        with caplog.at_level("WARNING", logger="core.audit.clone_drift"):
            out = fix_anchored_drift(
                [_anchor()], {"src/frm.c": _DRIFTED},
                telemetry=telemetry,
            )
        assert out == []
        assert telemetry.get("degraded", 0) == 1
        assert any("fix-anchored" in r
                   for r in telemetry.get("degraded_reasons", []))
        assert any("dropped unchecked" in rec.getMessage()
                   for rec in caplog.records)

    def test_winnowing_leg_signals_degraded(self, monkeypatch, caplog):
        from core.audit.clone_drift import detect_clone_drift

        self._block_grammar(monkeypatch)
        telemetry: dict = {}
        with caplog.at_level("WARNING", logger="core.audit.clone_drift"):
            out = detect_clone_drift(
                {"src/frm.c": _DRIFTED}, telemetry=telemetry,
            )
        assert out == []
        assert telemetry.get("degraded", 0) == 1

    def test_no_signal_when_nothing_to_check(self, monkeypatch, caplog):
        from core.audit.clone_drift import (
            detect_clone_drift,
            fix_anchored_drift,
        )

        self._block_grammar(monkeypatch)
        telemetry: dict = {}
        assert fix_anchored_drift([], {}, telemetry=telemetry) == []
        assert detect_clone_drift({}, telemetry=telemetry) == []
        assert "degraded" not in telemetry


def _clone_body(fn: str, var: str) -> str:
    """A distinct ≥``MIN_CLONE_TOKENS``-token near-clone of the
    guarded fixture (identifier renames only — type-2 identical)."""
    return _GUARDED.replace("handle_packet", fn).replace("acc", var)


class TestCapAccounting:
    """A bitten cap must never read as full coverage: the truncation
    is warned, stamped into ``caps_hit`` with exact kept/dropped
    counts — and below the cap nothing changes and no marker
    appears (two-direction pin)."""

    _SOURCES = {
        "src/a.c": _GUARDED,
        "src/b.c": _clone_body("handle_b", "q"),
        "src/c.c": _clone_body("handle_c", "r"),
    }

    @requires_ts('c')
    def test_function_cap_bite_marked_and_bounded(self, caplog):
        from core.audit.clone_drift import detect_clone_drift

        telemetry: dict = {}
        with caplog.at_level(
                "WARNING", logger="core.audit.clone_drift"):
            detect_clone_drift(
                self._SOURCES, max_functions=2, telemetry=telemetry,
            )
        assert telemetry.get("caps_hit") == ["clone_functions"]
        assert telemetry["clone_functions_cap"] == 2
        assert telemetry["clone_functions_kept"] == 2
        assert telemetry["clone_functions_dropped"] == 1
        assert any("clone_functions cap hit" in rec.getMessage()
                   for rec in caplog.records)

    @requires_ts('c')
    def test_function_cap_bite_bounds_the_population(self):
        from core.audit.clone_drift import _function_bodies

        telemetry: dict = {}
        bodies = _function_bodies(
            self._SOURCES, max_functions=1, telemetry=telemetry,
        )
        assert len(bodies) == 1
        assert telemetry["clone_functions_dropped"] == 2

    @requires_ts('c')
    def test_pair_cap_bite_marked_and_bounded(self, caplog):
        from core.audit.clone_drift import detect_clone_drift

        telemetry: dict = {}
        with caplog.at_level(
                "WARNING", logger="core.audit.clone_drift"):
            devs = detect_clone_drift(
                self._SOURCES, max_pairs=1, telemetry=telemetry,
            )
        # Three identical clones form three candidate pairs; one is
        # reported, the other two are honest residue.
        assert telemetry.get("caps_hit") == ["clone_pairs"]
        assert telemetry["clone_pairs_cap"] == 1
        assert telemetry["clone_pairs_kept"] == 1
        assert telemetry["clone_pairs_dropped"] == 2
        assert {d.enclosing_function for d in devs} <= {
            "handle_packet", "handle_b", "handle_c",
        }
        assert any("clone_pairs cap hit" in rec.getMessage()
                   for rec in caplog.records)

    @requires_ts('c')
    def test_under_cap_no_marker_no_behaviour_change(self, caplog):
        from core.audit.clone_drift import detect_clone_drift

        telemetry: dict = {}
        with caplog.at_level(
                "WARNING", logger="core.audit.clone_drift"):
            devs = detect_clone_drift({
                "src/pkt.c": _GUARDED,
                "src/frm.c": _DRIFTED,
            }, telemetry=telemetry)
        assert "caps_hit" not in telemetry
        assert not any("cap hit" in rec.getMessage()
                       for rec in caplog.records)
        # Pre-change expectation still holds verbatim.
        guard = [d for d in devs if d.kind == "guard"]
        assert len(guard) == 1
        assert guard[0].token == "validate_len"


class TestDerivedCaps:
    """Floor-derive-ceiling, both directions: the floor is the
    historical constant (small targets unchanged), the derivation
    tracks input scale in the midband, and the ceiling clamps."""

    def test_function_cap_floor_holds(self):
        from core.audit.clone_drift import (
            MAX_CLONE_FUNCTIONS,
            _derive_function_cap,
        )
        assert _derive_function_cap(0) == MAX_CLONE_FUNCTIONS
        assert _derive_function_cap(
            2048 * MAX_CLONE_FUNCTIONS) == MAX_CLONE_FUNCTIONS

    def test_function_cap_derives_then_clamps(self):
        from core.audit.clone_drift import (
            MAX_CLONE_FUNCTIONS_CEILING,
            _derive_function_cap,
        )
        assert _derive_function_cap(2048 * 1000) == 1000
        assert _derive_function_cap(10**12) == MAX_CLONE_FUNCTIONS_CEILING

    def test_pair_cap_floor_holds(self):
        from core.audit.clone_drift import (
            MAX_CLONE_PAIRS,
            _derive_pair_cap,
        )
        assert _derive_pair_cap(0) == MAX_CLONE_PAIRS
        assert _derive_pair_cap(10 * MAX_CLONE_PAIRS) == MAX_CLONE_PAIRS

    def test_pair_cap_derives_then_clamps(self):
        from core.audit.clone_drift import (
            MAX_CLONE_PAIRS_CEILING,
            _derive_pair_cap,
        )
        assert _derive_pair_cap(1000) == 100
        assert _derive_pair_cap(10**7) == MAX_CLONE_PAIRS_CEILING


def _shared_prints(a: str, b: str) -> int:
    """Shared winnowed-fingerprint count between two bodies (the
    candidate-strength metric the pair loop sorts on)."""
    from core.audit.clone_drift import _fingerprints, _normalise_tokens
    return len(
        _fingerprints(_normalise_tokens(a))
        & _fingerprints(_normalise_tokens(b)),
    )


# Mostly-different function sharing only the small flush/finalize
# tail with the ``_GUARDED`` clones: each pair with a clone stays
# below ``MIN_SHARED_FINGERPRINTS`` — a candidate the pair loop may
# never examine (a sub-floor tail).
_MOSTLY_DIFFERENT = textwrap.dedent("""\
    int checksum_window(const buf_t *w, size_t len) {
        unsigned sum = 0;
        size_t step = 4;
        size_t pos = 0;
        while (pos + step <= len) {
            sum ^= w->bytes[pos] << 3;
            sum |= w->bytes[pos + 1] >> 2;
            sum *= 2654435761u;
            pos += step;
        }
        flush_output(w, sum);
        return finalize_packet(w, sum, len);
    }
""")


class TestPairCapSubFloorTail:
    """Sub-floor candidates cannot fake a bite, both directions:
    the dropped count excludes candidates below the shared-
    fingerprint floor, and an exact-fit cap whose only residue is
    sub-floor stamps nothing at all."""

    _SOURCES = {
        "src/a.c": _GUARDED,
        "src/b.c": _clone_body("handle_b", "q"),
        "src/c.c": _clone_body("handle_c", "r"),
        "src/d.c": _MOSTLY_DIFFERENT,
    }

    def test_fixture_has_sub_floor_tail(self):
        """Validity pin: the three clone pairs sit above the floor,
        the three pairs with src/d.c sit below it but still share
        prints (so they enter the candidate list)."""
        from core.audit.clone_drift import MIN_SHARED_FINGERPRINTS
        clones = [self._SOURCES["src/a.c"], self._SOURCES["src/b.c"],
                  self._SOURCES["src/c.c"]]
        for i, a in enumerate(clones):
            for b in clones[i + 1:]:
                assert _shared_prints(a, b) >= MIN_SHARED_FINGERPRINTS
            assert 0 < _shared_prints(
                a, _MOSTLY_DIFFERENT) < MIN_SHARED_FINGERPRINTS

    @requires_ts('c')
    def test_dropped_excludes_sub_floor_tail(self):
        from core.audit.clone_drift import detect_clone_drift

        telemetry: dict = {}
        detect_clone_drift(
            self._SOURCES, max_pairs=1, telemetry=telemetry,
        )
        # Three above-floor clone pairs: one examined, two honest
        # residue. The three sub-floor candidates with src/d.c must
        # not inflate the count.
        assert telemetry.get("caps_hit") == ["clone_pairs"]
        assert telemetry["clone_pairs_kept"] == 1
        assert telemetry["clone_pairs_dropped"] == 2

    @requires_ts('c')
    def test_exact_fit_cap_with_sub_floor_tail_stamps_no_bite(
            self, caplog):
        from core.audit.clone_drift import detect_clone_drift

        telemetry: dict = {}
        with caplog.at_level(
                "WARNING", logger="core.audit.clone_drift"):
            detect_clone_drift(
                self._SOURCES, max_pairs=3, telemetry=telemetry,
            )
        # The cap fits the above-floor population exactly; the only
        # residue is the sub-floor tail. Zero real residue = no
        # bite, no marker, no warning.
        assert "caps_hit" not in telemetry
        assert not any("cap hit" in rec.getMessage()
                       for rec in caplog.records)


# Strong pair: long near-clones, many shared prints, guard
# divergence ``validate_big``.
_BIG_GUARDED = textwrap.dedent("""\
    int process_record(rec_t *r, size_t n) {
        if (validate_big(r, n) != 0)
            return -1;
        for (size_t i = 0; i < n; i++) {
            sum += r->data[i] * weight_of(r, i);
            push_value(sum, r->flags, i);
        }
        for (size_t j = 0; j < n; j++) {
            norm += r->aux[j] + bias_of(r, j);
            push_aux(norm, r->mode, j);
        }
        commit_record(r, sum);
        commit_aux(r, norm);
        return seal_record(r, sum, n);
    }
""")
_BIG_DRIFTED = textwrap.dedent("""\
    int replay_record(rec_t *e, size_t n) {
        for (size_t i = 0; i < n; i++) {
            tot += e->data[i] * weight_of(e, i);
            push_value(tot, e->flags, i);
        }
        for (size_t j = 0; j < n; j++) {
            base += e->aux[j] + bias_of(e, j);
            push_aux(base, e->mode, j);
        }
        commit_record(e, tot);
        commit_aux(e, base);
        return seal_record(e, tot, n);
    }
""")
# Weak pair: shorter, structurally unrelated near-clones (fewer
# shared prints, still above the floor), guard divergence
# ``check_hdr``.
_SMALL_GUARDED = textwrap.dedent("""\
    int copy_label(char *dst, const char *src, int cap) {
        if (check_hdr(dst, src) != 0)
            return -1;
        int used = 0;
        while (*src != 0 && used + 1 < cap) {
            *dst = *src;
            dst = dst + 1;
            src = src + 1;
            used = used + 1;
        }
        *dst = 0;
        stamp_label(dst, used);
        return used;
    }
""")
_SMALL_DRIFTED = textwrap.dedent("""\
    int copy_tag(char *out, const char *tag, int cap) {
        int used = 0;
        while (*tag != 0 && used + 1 < cap) {
            *out = *tag;
            out = out + 1;
            tag = tag + 1;
            used = used + 1;
        }
        *out = 0;
        stamp_label(out, used);
        return used;
    }
""")

# Tied-key order fixture: fn_x lacks the guard both fn_y and fn_z
# carry; fn_z adds tail statements so (x, z) shares strictly fewer
# prints than (x, y). Both x-pairs produce the same (file, line,
# token) deviation key — only the emission order tells them apart.
_ORDER_X = textwrap.dedent("""\
    int fn_x(pkt_t *p, size_t n) {
        for (size_t i = 0; i < n; i++) {
            acc += p->data[i] * scale_factor(p, i);
            emit_sample(acc, p->flags, i);
        }
        flush_output(p, acc);
        return finalize_packet(p, acc, n);
    }
""")
_ORDER_Y = _ORDER_X.replace("fn_x", "fn_y").replace(
    "size_t n) {",
    "size_t n) {\n    if (validate_pkt(p, n) != 0)\n        return -1;",
)
_ORDER_Z = _ORDER_X.replace("fn_x", "fn_z").replace(
    "size_t n) {",
    "size_t n) {\n    if (validate_pkt(p, n) != 0)\n        return -1;",
).replace(
    "    flush_output(p, acc);",
    "    acc = acc * 3 + 7;\n    acc = acc ^ 129;\n"
    "    flush_output(p, acc);",
)


class TestCandidateOrder:
    """Candidate examination runs strongest-evidence-first (most
    shared fingerprints), both directions: a bitten cap keeps the
    strongest pair, and below the cap deviations with a tied sort
    key emit in candidate order."""

    _STRONG_WEAK = {
        "src/bg.c": _BIG_GUARDED,
        "src/bd.c": _BIG_DRIFTED,
        "src/sg.c": _SMALL_GUARDED,
        "src/sd.c": _SMALL_DRIFTED,
    }

    def test_fixture_strength_ordering(self):
        """Validity pin: strong pair shares strictly more prints
        than the weak pair, both above the floor; cross pairs stay
        below it. Same strict ordering for the tied-key fixture."""
        from core.audit.clone_drift import MIN_SHARED_FINGERPRINTS
        strong = _shared_prints(_BIG_GUARDED, _BIG_DRIFTED)
        weak = _shared_prints(_SMALL_GUARDED, _SMALL_DRIFTED)
        assert strong > weak >= MIN_SHARED_FINGERPRINTS
        for big in (_BIG_GUARDED, _BIG_DRIFTED):
            for small in (_SMALL_GUARDED, _SMALL_DRIFTED):
                assert _shared_prints(
                    big, small) < MIN_SHARED_FINGERPRINTS
        xy = _shared_prints(_ORDER_X, _ORDER_Y)
        xz = _shared_prints(_ORDER_X, _ORDER_Z)
        assert xy > xz >= MIN_SHARED_FINGERPRINTS

    @requires_ts('c')
    def test_bitten_cap_keeps_strongest_pair(self):
        from core.audit.clone_drift import detect_clone_drift

        telemetry: dict = {}
        devs = detect_clone_drift(
            self._STRONG_WEAK, max_pairs=1, telemetry=telemetry,
        )
        # Only the strongest pair fits under the cap — the reported
        # deviation must come from it, never from the weak pair.
        assert [(d.token, d.enclosing_function, d.peer_function)
                for d in devs] == [
            ("validate_big", "replay_record", "process_record"),
        ]
        assert telemetry["clone_pairs_kept"] == 1
        assert telemetry["clone_pairs_dropped"] == 1

    @requires_ts('c')
    def test_below_cap_tied_keys_emit_strongest_peer_first(self):
        from core.audit.clone_drift import detect_clone_drift

        devs = detect_clone_drift({
            "src/x.c": _ORDER_X,
            "src/y.c": _ORDER_Y,
            "src/z.c": _ORDER_Z,
        }, similarity=0.8)
        # Both deviations carry the same (file, line, token) sort
        # key; the stable final sort preserves candidate order, so
        # the stronger peer (fn_y) must come first.
        assert [(d.token, d.enclosing_function, d.peer_function)
                for d in devs] == [
            ("validate_pkt", "fn_x", "fn_y"),
            ("validate_pkt", "fn_x", "fn_z"),
        ]


def _many_spans(n: int) -> str:
    """``n`` distinct ≥``MIN_CLONE_TOKENS``-token functions in one
    translation unit."""
    fn = textwrap.dedent("""\
        int span_NAME(int a, int b) {
            a = a + b; b = b + 1;
            a = a * 2; b = b - a;
            a = a + 3; b = b * a;
            a = a - 4; b = b + a;
            return a + b;
        }
    """)
    return "\n".join(fn.replace("NAME", f"{i:03d}") for i in range(n))


class TestDerivedCapWiring:
    """The DEFAULT caps must flow through the derivations at the
    real callsites — not the fixed floor constants, not a file
    count. Wiring-level: no explicit caps passed."""

    @requires_ts('c')
    def test_default_function_cap_tracks_char_scale(self):
        from core.audit.clone_drift import (
            MAX_CLONE_FUNCTIONS,
            _function_bodies,
        )
        n_spans = MAX_CLONE_FUNCTIONS + 100
        # Comment padding lifts the char scale (and thus the derived
        # cap) above the span count without adding spans.
        source = _many_spans(n_spans) + "\n/* " \
            + ("x" * 64 + "\n") * 21000 + " */\n"
        telemetry: dict = {}
        bodies = _function_bodies(
            {"src/many.c": source}, telemetry=telemetry,
        )
        # The historical fixed cap (or a cap derived from the file
        # count) would bite at 500 and stamp the marker.
        assert len(bodies) == n_spans
        assert "caps_hit" not in telemetry

    @requires_ts('c')
    def test_default_pair_cap_wired_through_derivation(
            self, monkeypatch):
        from core.audit import clone_drift

        seen: list[int] = []

        def _fake_pair_cap(n_bodies: int) -> int:
            seen.append(n_bodies)
            return 1

        monkeypatch.setattr(
            clone_drift, "_derive_pair_cap", _fake_pair_cap)
        telemetry: dict = {}
        clone_drift.detect_clone_drift(
            TestCapAccounting._SOURCES, telemetry=telemetry,
        )
        # The derivation was consulted with the admitted body count
        # and its value (not the fixed floor) drove the cap.
        assert seen == [3]
        assert telemetry["clone_pairs_cap"] == 1
        assert telemetry["clone_pairs_kept"] == 1
