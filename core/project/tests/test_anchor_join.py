"""Tests for core.project.anchor_join — anchor-identity correlation join.

The acceptance suite reproduces (with synthetic names) the seven
adjudicated near-miss shapes that motivated the join: anchor drift
within one function, synthetic-scope name variants, head-vs-mechanism
anchoring, explicit lineage notes, and the one genuinely-distinct
same-file pair that must NOT join. Each join leg (normalization, span
widening, window fallback, lineage) carries its own pin so a mutant
disabling one leg fails independently, and the direction-discipline
negative controls pin that uncertainty flags instead of joining:
transitive chains and shared spans are diameter-bounded, same-run
pairs never window-join, forged interstitial names earn no span, and
lineage is read only from reasoning-tier fields.
"""

import json
import tempfile
from pathlib import Path
from unittest import TestCase

from core.project.anchor_join import (
    CANONICAL_MODULE_SCOPE,
    LINE_FALLBACK_WINDOW,
    _SPAN_DIAMETER_CAP,
    build_anchor_join,
    cwe_family,
    interstitial_span,
    lineage_refs,
    load_project_span_index,
    load_span_index,
    normalize_scope_name,
)

# --- Unit: scope-name normalization ---

class TestNormalizeScopeName(TestCase):
    def test_known_module_spellings(self):
        for name in ("<module>", "__module__", "module_scope"):
            self.assertEqual(normalize_scope_name(name),
                             CANONICAL_MODULE_SCOPE, name)

    def test_interstitial_names(self):
        self.assertEqual(normalize_scope_name("interstitial:23-184"),
                         CANONICAL_MODULE_SCOPE)

    def test_real_function_names_pass_through(self):
        self.assertEqual(normalize_scope_name("startFeed"), "startFeed")
        # Near-miss spellings are NOT normalized (allowlist, exact
        # match — guessing risks folding a real function into module
        # scope).
        self.assertEqual(normalize_scope_name("Module"), "Module")
        self.assertEqual(normalize_scope_name("modulescope"), "modulescope")
        self.assertEqual(normalize_scope_name("interstitial:x-y"),
                         "interstitial:x-y")

    def test_hostile_values_coerced(self):
        self.assertEqual(normalize_scope_name(None), "")
        self.assertEqual(normalize_scope_name({"a": 1}), "{'a': 1}")

    def test_interstitial_span_parse(self):
        self.assertEqual(interstitial_span("interstitial:23-184"), (23, 184))
        self.assertIsNone(interstitial_span("interstitial:9-4"))
        self.assertIsNone(interstitial_span("fn"))


# --- Unit: CWE family ---

class TestCweFamily(TestCase):
    def test_cwe_id_wins_over_vuln_type(self):
        # A command_injection-typed row with an explicit CWE-93 id is
        # a CRLF-family member (the real row-6 shape).
        f = {"cwe_id": "CWE-93", "vuln_type": "command_injection"}
        self.assertEqual(cwe_family(f), "CWE-93")

    def test_family_grouping(self):
        self.assertEqual(cwe_family({"cwe_id": "CWE-88"}),
                         cwe_family({"cwe_id": "CWE-78"}))
        self.assertNotEqual(cwe_family({"cwe_id": "CWE-79"}),
                            cwe_family({"cwe_id": "CWE-93"}))

    def test_unmapped_id_is_own_family(self):
        self.assertEqual(cwe_family({"cwe_id": "CWE-352"}), "CWE-352")

    def test_vuln_type_fallback(self):
        self.assertEqual(cwe_family({"vuln_type": "xss"}), "CWE-79")

    def test_unknown_is_empty(self):
        self.assertEqual(cwe_family({"vuln_type": "other"}), "")
        self.assertEqual(cwe_family({}), "")


# --- Unit: lineage parsing ---

_LINEAGE_PROSE = (
    "Injection via decoded field. | Corpus carry: mechanism-identical "
    "re-derivation of prior verdict FIND-R4 (confirmed) from run "
    "run-prior-1; source unchanged, verdict imported."
)


class TestLineageRefs(TestCase):
    def test_parses_reference(self):
        f = {"candidate_reasoning": _LINEAGE_PROSE}
        self.assertEqual(lineage_refs(f), [("FIND-R4", "run-prior-1")])

    def test_reasoning_tier_fields_scanned(self):
        f = {"dataflow_summary": _LINEAGE_PROSE}
        self.assertEqual(lineage_refs(f), [("FIND-R4", "run-prior-1")])

    def test_target_quoting_fields_never_scanned(self):
        """A lineage-shaped sentence in a field that quotes the
        scanned repo's own bytes (snippets, matched lines, messages)
        must never mint a SAME edge — the repo would otherwise
        control the join."""
        for name in ("code_snippet", "matched_code", "snippet",
                     "message", "evidence", "source_line"):
            self.assertEqual(lineage_refs({name: _LINEAGE_PROSE}), [],
                             name)

    def test_no_marker_no_refs(self):
        f = {"candidate_reasoning": "prior verdict FIND-R4 from run r1"}
        self.assertEqual(lineage_refs(f), [])

    def test_ref_cap_bounds_hostile_repetition(self):
        f = {"candidate_reasoning": " ".join(
            f"Corpus carry: prior verdict FIND-R{i} (x) from run r{i}"
            for i in range(50))}
        self.assertLessEqual(len(lineage_refs(f)), 8)


# --- Unit: span index ---

def _checklist(files):
    return {
        "files": [
            {"path": path, "items": [
                {"name": n, "kind": k, "line_start": a, "line_end": b}
                for (n, k, a, b) in items
            ]}
            for path, items in files.items()
        ],
    }


class TestSpanIndex(TestCase):
    def test_load(self):
        idx = load_span_index(_checklist({
            "src/one.php": [("openPipe", "function", 90, 100)],
        }))
        self.assertIn("src/one.php", idx)
        span = idx["src/one.php"][0]
        self.assertEqual((span.name, span.start, span.end),
                         ("openPipe", 90, 100))

    def test_malformed_shapes_degrade(self):
        for junk in (None, [], "x", {"files": "x"},
                     {"files": [{"path": "a", "items": [
                         {"line_start": "x", "line_end": []}]}]}):
            self.assertEqual(load_span_index(junk), {}, junk)

    def test_project_index_reads_project_checklist(self):
        import shutil
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(base), ignore_errors=True)
        (base / "checklist.json").write_text(json.dumps(_checklist({
            "src/one.php": [("openPipe", "function", 90, 100)],
        })))

        class _P:
            output_path = base
        self.assertIn("src/one.php", load_project_span_index(_P()))

    def test_project_index_falls_back_to_run_dir(self):
        import shutil
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(base), ignore_errors=True)
        run = base / "validate-001"
        run.mkdir()
        (run / "checklist.json").write_text(json.dumps(_checklist({
            "src/two.php": [("renderDiv", "function", 10, 40)],
        })))

        class _P:
            output_path = base
        self.assertIn("src/two.php",
                      load_project_span_index(_P(), [run]))

    def test_missing_everything_is_empty(self):
        class _P:
            output_path = Path("/nonexistent/nowhere")
        self.assertEqual(load_project_span_index(_P(), []), {})


# --- Acceptance: the seven adjudicated shapes, synthetic names ---
#
# Six SAME (one defect, two anchors) + one DISTINCT (same file, same
# module scope, different CWE family). Shapes mirror the adjudicated
# corpus rows: (1) signature-vs-sink drift, (2) head-vs-mechanism
# drift, (3) module-scope spelling variant, (4) drift with an
# explicit lineage note, (5) the negative control, (6) identical
# anchors under differing vuln_type spellings, (7) head-vs-mechanism
# with lineage across a long function.

_SPAN_INDEX = load_span_index(_checklist({
    "src/one.php": [("openPipe", "function", 90, 100)],
    "src/two.php": [("renderDiv", "function", 2067, 2095)],
    "mod/three.mod": [("interstitial:20-60", "interstitial", 20, 60)],
    "src/four.php": [("composeLink", "function", 704, 733)],
    "ext/five/panel.php": [
        ("interstitial:23-184", "interstitial", 23, 184)],
    "ext/six.php": [("fetchAttachment", "function", 20, 40)],
    "src/seven.php": [("notifyRead", "function", 167, 377)],
}))


def _f(file, function, line, cwe, *, fid=None, status="confirmed",
       vuln_type="other", proof_lines=None, proof_sink=None, reasoning=None):
    f = {"id": fid or f"F-{file}-{line}", "file": file,
         "function": function, "line": line, "cwe_id": cwe,
         "vuln_type": vuln_type, "final_status": status}
    if proof_lines is not None:
        f["proof_lines"] = proof_lines
    if proof_sink is not None:
        f["proof_sink"] = proof_sink
    if reasoning is not None:
        f["candidate_reasoning"] = reasoning
    return f


def _seven_rows():
    """(findings_by_run, recency) for the seven adjudicated shapes."""
    prior = [
        # 1: prior anchors the sink line, names it in its own file.
        _f("src/one.php", "openPipe", 98, "CWE-88", fid="P-1",
           proof_lines=[90, 100],
           proof_sink="command pipe opened at src/one.php line 98"),
        # 2: prior anchors the function head.
        _f("src/two.php", "renderDiv", 2067, "CWE-79", fid="P-2",
           proof_lines=[2073, 2093],
           proof_sink="style built at two.php 2083, wrapped at 2091"),
        # 3: module-scope spelling variant.
        _f("mod/three.mod", "__module__", 34, "CWE-79", fid="P-3",
           proof_lines=[23, 35],
           proof_sink="page body emission via makePage helper"),
        # 4: prior anchors the sink line.
        _f("src/four.php", "composeLink", 726, "CWE-79", fid="FIND-R4",
           proof_lines=[724, 727],
           proof_sink="src/four.php:726 onclick concatenation"),
        # 5 (negative control): module-scope branch A.
        _f("ext/five/panel.php", "__module__", 51, "CWE-79", fid="P-5",
           proof_lines=[49, 53],
           proof_sink="raw echo of stored pref at render helper"),
        # 6: identical anchor, different vuln_type spelling.
        _f("ext/six.php", "fetchAttachment", 26, "CWE-93", fid="P-6",
           proof_lines=[25, 32],
           proof_sink="protocol command at ext/six.php:26 and :31"),
        # 7: prior anchors the mechanism line inside a long function.
        _f("src/seven.php", "notifyRead", 188, "CWE-93", fid="FIND-R7",
           proof_lines=[186, 190],
           proof_sink="outgoing header assembly, lib/other.php line 673"),
    ]
    new = [
        # 1: new run anchors the signature.
        _f("src/one.php", "openPipe", 90, "CWE-88", fid="N-1",
           proof_lines=[90, 99],
           proof_sink="pipe opened at line 98 with flag at line 96"),
        # 2: new run anchors the mechanism line.
        _f("src/two.php", "renderDiv", 2075, "CWE-79", fid="N-2",
           proof_lines=[2074, 2091],
           proof_sink="style built at two.php 2083 and 2091"),
        # 3: canonical module-scope spelling.
        _f("mod/three.mod", "<module>", 34, "CWE-79", fid="N-3",
           proof_lines=[24, 34],
           proof_sink="mod/three.mod line 34: unescaped interpolation"),
        # 4: signature anchor + explicit lineage note.
        _f("src/four.php", "composeLink", 704, "CWE-79", fid="N-4",
           proof_lines=[704, 704],
           proof_sink="src/four.php:726 onclick concatenation",
           reasoning=("Injection via link text. | Corpus carry: "
                      "mechanism-identical re-derivation of prior verdict "
                      "FIND-R4 (confirmed) from run run-prior-1; source "
                      "unchanged.")),
        # 5 (negative control): module-scope branch B, DIFFERENT
        # family, nearby line.
        _f("ext/five/panel.php", "interstitial:23-184", 59, "CWE-93",
           fid="N-5", proof_lines=[53, 60],
           proof_sink="verbatim key=value line write via pref helper"),
        # 6: same anchor, vuln_type spelled differently.
        _f("ext/six.php", "fetchAttachment", 26, "CWE-93", fid="N-6",
           vuln_type="command_injection", proof_lines=[24, 33],
           proof_sink="protocol command at ext/six.php:26 and :31"),
        # 7: signature anchor + lineage note.
        _f("src/seven.php", "notifyRead", 167, "CWE-93", fid="N-7",
           proof_lines=[167, 167],
           proof_sink="outgoing header assembly, lib/other.php line 673",
           reasoning=("Header injection via decoded field. | Corpus carry: "
                      "mechanism-identical re-derivation of prior verdict "
                      "FIND-R7 (confirmed) from run run-prior-1.")),
    ]
    findings_by_run = {"run-prior-1": prior, "run-new-2": new}
    recency = {"run-prior-1": 0, "run-new-2": 1}
    return findings_by_run, recency


class TestSevenRowAcceptance(TestCase):
    def _join(self):
        findings_by_run, recency = _seven_rows()
        return build_anchor_join(findings_by_run, _SPAN_INDEX, recency)

    def test_exactly_six_same_one_distinct(self):
        join = self._join()
        multi = join.multi_anchor_sites()
        self.assertEqual(len(multi), 6)
        # 7 defects in the prior run + 1 genuinely new = 8 sites.
        self.assertEqual(join.site_count(), 8)
        # The negative-control pair stays split: different site keys.
        k_prior = join.key_for("run-prior-1", 4)
        k_new = join.key_for("run-new-2", 4)
        self.assertNotEqual(k_prior, k_new)

    def test_same_pairs_share_keys(self):
        join = self._join()
        for i in (0, 1, 2, 3, 5, 6):
            self.assertEqual(
                join.key_for("run-prior-1", i),
                join.key_for("run-new-2", i),
                f"row {i + 1} did not join",
            )

    def test_canonical_anchor_election(self):
        """The adjudicated canonical anchors, mechanically re-derived:
        sink-referencing records win regardless of run age (rows 1,
        4), mechanism anchors beat function heads (row 7), and a
        mechanism-vs-mechanism tie goes to the newest run (row 2)."""
        join = self._join()
        expected = {
            0: ("src/one.php", "openPipe", 98),          # prior's sink
            1: ("src/two.php", "renderDiv", 2075),       # newest mechanism
            2: ("mod/three.mod", "<module>", 34),
            3: ("src/four.php", "composeLink", 726),     # prior's sink
            5: ("ext/six.php", "fetchAttachment", 26),
            6: ("src/seven.php", "notifyRead", 188),     # prior mechanism
        }
        for i, key in expected.items():
            self.assertEqual(join.key_for("run-new-2", i), key,
                             f"row {i + 1} canonical anchor")

    def test_raw_names_preserved_in_anchors(self):
        join = self._join()
        k = join.key_for("run-new-2", 2)
        names = {a["function"] for a in join.site(k)["anchors"]}
        self.assertEqual(names, {"<module>", "__module__"})

    def test_negative_control_not_even_uncertain(self):
        """Row 5 is a CONFIDENT distinct (different CWE families),
        not an uncertainty flag."""
        join = self._join()
        flagged_files = {a["file"] for p in join.uncertain_pairs
                         for a in p["anchors"]}
        self.assertNotIn("ext/five/panel.php", flagged_files)

    def test_singleton_keys_match_historical_dedup_key(self):
        """A finding that joins nothing keeps its exact historical
        (file, function, line) key — consumers see no change outside
        genuine joins."""
        join = self._join()
        self.assertEqual(join.key_for("run-new-2", 4),
                         ("ext/five/panel.php", "interstitial:23-184", 59))


# --- Per-leg pins: each join leg killed independently ---

class TestNormalizationLeg(TestCase):
    def test_spelling_variants_join_at_identical_anchor(self):
        """Same file+line, `<module>` vs `__module__`: only the
        normalization leg can join these (no spans, no lineage, and
        the exact leg keys on the NORMALIZED name)."""
        fbr = {
            "r1": [_f("a/m.php", "__module__", 34, "CWE-79")],
            "r2": [_f("a/m.php", "<module>", 34, "CWE-79")],
        }
        join = build_anchor_join(fbr)
        self.assertEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.site_count(), 1)

    def test_interstitial_variant_joins_via_embedded_span(self):
        """`module_scope` vs `interstitial:N-M` at different lines:
        needs BOTH the interstitial normalization and the raw-name
        span, plus a checklist span for the bare-spelling side."""
        idx = load_span_index(_checklist({
            "a/m.php": [("interstitial:10-80", "interstitial", 10, 80)],
        }))
        fbr = {
            "r1": [_f("a/m.php", "module_scope", 40, "CWE-79")],
            "r2": [_f("a/m.php", "interstitial:10-80", 44, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        self.assertEqual(join.key_for("r1", 0), join.key_for("r2", 0))


class TestSpanLeg(TestCase):
    def test_span_joins_beyond_window(self):
        """Anchors farther apart than the window but inside one
        checklist function span join via the span leg alone (up to
        the span diameter cap — shrinking the cap to the window would
        make this leg redundant and re-split long-function drift)."""
        self.assertGreater(215 - 170, LINE_FALLBACK_WINDOW)
        self.assertLessEqual(215 - 170, _SPAN_DIAMETER_CAP)
        idx = load_span_index(_checklist({
            "s.php": [("bigFn", "function", 167, 377)],
        }))
        fbr = {
            "r1": [_f("s.php", "bigFn", 170, "CWE-79")],
            "r2": [_f("s.php", "bigFn", 215, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        k = join.key_for("r1", 0)
        self.assertEqual(k, join.key_for("r2", 0))
        self.assertIn("span", join.site(k)["join_via"])

    def test_span_join_beyond_diameter_cap_flags(self):
        """A shared span proves shared SCOPE, not shared identity:
        anchors farther apart than the diameter cap inside one span
        (a long function, or a file-wide module region) are flagged
        uncertain, never silently folded — growing the cap lets
        file-wide spans hide independent same-family defects."""
        self.assertGreater(260 - 170, _SPAN_DIAMETER_CAP)
        idx = load_span_index(_checklist({
            "s.php": [("bigFn", "function", 167, 377)],
        }))
        fbr = {
            "r1": [_f("s.php", "bigFn", 170, "CWE-79")],
            "r2": [_f("s.php", "bigFn", 260, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 1)
        self.assertEqual(join.uncertain_pairs[0]["reason"],
                         "span join beyond the diameter bound")

    def test_file_wide_module_span_never_folds_far_rows(self):
        """The demonstrated over-join: two same-family module-scope
        rows thousands of lines apart inside one file-wide
        interstitial span must stay distinct (flagged)."""
        idx = load_span_index(_checklist({
            "s.php": [("interstitial:1-6000", "interstitial", 1, 6000)],
        }))
        fbr = {
            "r1": [_f("s.php", "<module>", 10, "CWE-79")],
            "r2": [_f("s.php", "<module>", 5000, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 1)

    def test_forged_interstitial_name_earns_no_span(self):
        """A row's ``function`` string is run-artifact content: a
        forged ``interstitial:1-9999999`` name must not self-declare
        file-wide scope. Uncorroborated by the checklist, the row is
        span-less — and module scope without spans never joins."""
        idx = load_span_index(_checklist({
            "g.php": [("interstitial:4990-5010", "interstitial",
                       4990, 5010)],
        }))
        fbr = {
            "r1": [_f("g.php", "interstitial:1-9999999", 5001, "CWE-79")],
            "r2": [_f("g.php", "<module>", 5000, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))

    def test_corroborated_interstitial_span_still_honoured(self):
        """The containment check must not break the legitimate case:
        an embedded range equal to (or inside) a checklist span keeps
        working — see also
        ``test_interstitial_variant_joins_via_embedded_span``."""
        idx = load_span_index(_checklist({
            "g.php": [("interstitial:40-90", "interstitial", 40, 90)],
        }))
        fbr = {
            "r1": [_f("g.php", "interstitial:40-90", 50, "CWE-79")],
            "r2": [_f("g.php", "module_scope", 55, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        k = join.key_for("r1", 0)
        self.assertEqual(k, join.key_for("r2", 0))
        self.assertIn("span", join.site(k)["join_via"])

    def test_different_spans_stay_distinct_without_flag(self):
        """Two module-scope anchors in DIFFERENT interstitial regions
        of one file: confidently distinct scopes — no join, no
        uncertainty flag."""
        idx = load_span_index(_checklist({
            "s.php": [("interstitial:1-40", "interstitial", 1, 40),
                      ("interstitial:60-90", "interstitial", 60, 90)],
        }))
        fbr = {
            "r1": [_f("s.php", "<module>", 20, "CWE-79")],
            "r2": [_f("s.php", "<module>", 70, "CWE-79")],
        }
        join = build_anchor_join(fbr, idx)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 0)

    def test_different_cwe_family_never_span_joins(self):
        """Same span, different families: the row-5 control at the
        leg level."""
        idx = load_span_index(_checklist({
            "s.php": [("interstitial:23-184", "interstitial", 23, 184)],
        }))
        fbr = {
            "r1": [_f("s.php", "__module__", 51, "CWE-79")],
            "r2": [_f("s.php", "__module__", 59, "CWE-93")],
        }
        join = build_anchor_join(fbr, idx)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))


class TestWindowLeg(TestCase):
    def _pair(self, delta):
        fbr = {
            "r1": [_f("w.php", "fn", 700, "CWE-79")],
            "r2": [_f("w.php", "fn", 700 + delta, "CWE-79")],
        }
        return build_anchor_join(fbr), fbr

    def test_within_window_joins(self):
        """No span data, named function, drift within the window: the
        fallback leg joins (shrinking the window re-splits real
        anchor drift — the observed shapes reach 22 lines)."""
        join, _ = self._pair(LINE_FALLBACK_WINDOW)
        k = join.key_for("r1", 0)
        self.assertEqual(k, join.key_for("r2", 0))
        self.assertIn("window", join.site(k)["join_via"])

    def test_beyond_window_stays_distinct_and_flags(self):
        """One past the window: distinct + `join: uncertain` (growing
        the window glues neighbouring same-family defects — the
        over-join direction that hides findings)."""
        join, _ = self._pair(LINE_FALLBACK_WINDOW + 1)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 1)
        self.assertEqual(join.uncertain_pairs[0]["join"], "uncertain")

    def test_far_drift_never_window_joins(self):
        """Absolute grow-direction pin: Δ100 in one named function
        with no span data stays distinct (and flagged) — the window
        must never grow into span territory, because only real span
        evidence may join drift that far. Together with the
        within-window pin this bounds the constant from both sides."""
        self.assertLess(LINE_FALLBACK_WINDOW, 100)
        join, _ = self._pair(100)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 1)

    def test_same_run_pair_never_window_joins(self):
        """Two surviving rows in ONE run are the producer's
        deliberate claim of two findings (its own dedup already ran):
        position alone must not overrule that — flagged, never
        joined."""
        fbr = {
            "r1": [_f("w.php", "fn", 700, "CWE-79", fid="X-1"),
                   _f("w.php", "fn", 710, "CWE-79", fid="X-2")],
        }
        join = build_anchor_join(fbr)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r1", 1))
        self.assertEqual(join.uncertain_total, 1)
        self.assertEqual(join.uncertain_pairs[0]["reason"],
                         "same-run anchors within the window")

    def test_transitive_window_chain_is_diameter_bounded(self):
        """Union-find takes the transitive closure: a lattice of
        pairwise-close anchors (13 rows, step 25, alternating runs)
        must NOT chain into one site spanning Δ300 — every
        window-joined component stays within the diameter bound and
        the declined links are flagged."""
        fbr = {"r1": [], "r2": []}
        for i in range(13):
            run = "r1" if i % 2 == 0 else "r2"
            fbr[run].append(
                _f("t.php", "fn", 100 + 25 * i, "CWE-79", fid=f"L-{i}"))
        join = build_anchor_join(fbr)
        self.assertGreater(join.site_count(), 1)
        self.assertGreater(join.uncertain_total, 0)
        for site in join.multi_anchor_sites():
            lines = [a["line"] for a in site["anchors"]]
            self.assertLessEqual(max(lines) - min(lines),
                                 LINE_FALLBACK_WINDOW, site)

    def test_window_component_diameter_boundary(self):
        """Two-direction pin on the component diameter bound: a
        three-anchor chain whose total diameter equals the window
        still joins (shrinking the bound re-splits real multi-run
        drift); one line more and the extending link is declined and
        flagged (growing it re-opens unbounded chaining)."""
        def _chain(third_line):
            return build_anchor_join({
                "r1": [_f("w.php", "fn", 100, "CWE-79", fid="C-1")],
                "r2": [_f("w.php", "fn", 115, "CWE-79", fid="C-2")],
                "r3": [_f("w.php", "fn", third_line, "CWE-79",
                          fid="C-3")],
            })
        join = _chain(100 + LINE_FALLBACK_WINDOW)
        self.assertEqual(join.site_count(), 1)
        self.assertEqual(join.uncertain_total, 0)
        join = _chain(100 + LINE_FALLBACK_WINDOW + 1)
        self.assertEqual(join.site_count(), 2)
        self.assertEqual(join.uncertain_total, 1)
        self.assertEqual(join.uncertain_pairs[0]["reason"],
                         "window join beyond the diameter bound")

    def test_new_sink_next_to_drifted_anchor_stays_visible(self):
        """The false-suppression scenario the diameter bound exists
        for: an old anchor drifts in the delta run, and a genuinely
        NEW same-family sink sits within window range of the drifted
        anchor. The new sink must never silently read as persistent —
        it stays a distinct site and the declined link is flagged."""
        fbr = {
            "run-old": [_f("r.php", "render", 100, "CWE-79",
                           fid="OLD-A")],
            "run-new": [_f("r.php", "render", 120, "CWE-79",
                           fid="NEW-A"),
                        _f("r.php", "render", 145, "CWE-79",
                           fid="NEW-B")],
        }
        join = build_anchor_join(
            fbr, run_recency={"run-old": 0, "run-new": 1})
        drifted_key = join.key_for("run-old", 0)
        self.assertEqual(drifted_key, join.key_for("run-new", 0))
        new_sink_key = join.key_for("run-new", 1)
        self.assertNotEqual(new_sink_key, drifted_key)
        self.assertGreaterEqual(join.uncertain_total, 1)

    def test_module_scope_never_window_joins(self):
        """Module scope without span data has no meaningful extent: a
        near-anchor pair is flagged for a human, never window-joined
        (two independent module-scope defects can sit lines apart —
        the real negative-control shape)."""
        fbr = {
            "r1": [_f("m.php", "<module>", 51, "CWE-93")],
            "r2": [_f("m.php", "__module__", 59, "CWE-93")],
        }
        join = build_anchor_join(fbr)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 1)

    def test_unknown_family_flags_instead_of_joining(self):
        fbr = {
            "r1": [_f("w.php", "fn", 700, "")],
            "r2": [_f("w.php", "fn", 710, "")],
        }
        join = build_anchor_join(fbr)
        self.assertNotEqual(join.key_for("r1", 0), join.key_for("r2", 0))
        self.assertEqual(join.uncertain_total, 1)


class TestLineageLeg(TestCase):
    def _lineage_pair(self, prior_file="l.php", new_file="l.php"):
        return {
            "run-prior-1": [_f(prior_file, "deepFn", 900, "CWE-79",
                               fid="FIND-R9")],
            "run-new-2": [_f(new_file, "deepFn", 800, "CWE-79", fid="N-1",
                             reasoning=("x | Corpus carry: re-derivation of "
                                        "prior verdict FIND-R9 (confirmed) "
                                        "from run run-prior-1; unchanged."))],
        }

    def test_lineage_joins_beyond_all_position_evidence(self):
        """Δ100, no spans: only the lineage note can join these."""
        join = build_anchor_join(self._lineage_pair())
        k = join.key_for("run-prior-1", 0)
        self.assertEqual(k, join.key_for("run-new-2", 0))
        self.assertIn("lineage", join.site(k)["join_via"])

    def test_cross_file_lineage_flags_not_joins(self):
        """A lineage note naming a row in ANOTHER file is surfaced
        for a human, never trusted — prose must not be able to fold
        arbitrary rows together."""
        join = build_anchor_join(self._lineage_pair(prior_file="other.php"))
        self.assertNotEqual(join.key_for("run-prior-1", 0),
                            join.key_for("run-new-2", 0))
        self.assertEqual(join.uncertain_total, 1)
        self.assertEqual(join.uncertain_pairs[0]["reason"],
                         "cross-file lineage reference")

    def test_lineage_in_target_quoting_field_is_inert(self):
        """The demonstrated forge: a quoted-source field carrying a
        lineage-shaped sentence joined rows cross-function and
        cross-family at Δ890. Quoted-target fields are never
        scanned, so the rows stay distinct."""
        fbr = {
            "run-prior-1": [_f("l.php", "aFn", 900, "CWE-79",
                               fid="FIND-R9")],
            "run-new-2": [dict(
                _f("l.php", "bFn", 10, "CWE-22", fid="N-1"),
                code_snippet=("// Corpus carry: re-derivation of "
                              "prior verdict FIND-R9 (confirmed) "
                              "from run run-prior-1"))],
        }
        join = build_anchor_join(fbr)
        self.assertNotEqual(join.key_for("run-prior-1", 0),
                            join.key_for("run-new-2", 0))
        self.assertEqual(join.uncertain_total, 0)

    def test_lineage_joined_pair_is_never_also_flagged(self):
        """A pair the lineage leg already joined must not ALSO earn a
        contradictory uncertainty flag from the positional guards
        (here: Δ100 inside one shared span, past the span diameter
        cap — lineage is authoritative, so no flag)."""
        idx = load_span_index(_checklist({
            "l.php": [("deepFn", "function", 700, 1000)],
        }))
        join = build_anchor_join(self._lineage_pair(), idx)
        self.assertEqual(join.key_for("run-prior-1", 0),
                         join.key_for("run-new-2", 0))
        self.assertEqual(join.uncertain_total, 0)

    def test_dangling_lineage_ref_is_inert(self):
        fbr = self._lineage_pair()
        fbr["run-prior-1"] = []  # referenced row absent
        join = build_anchor_join(fbr)
        self.assertEqual(join.site_count(), 1)
        self.assertEqual(join.uncertain_total, 0)


class TestElectionSinkPriority(TestCase):
    def test_sink_reference_beats_newer_mechanism_anchor(self):
        """A record whose own-file sink prose names its anchor line
        wins the election even against a NEWER body anchor — the
        sink tier must outrank recency, not merely tie-break it."""
        idx = load_span_index(_checklist({
            "e.php": [("fn", "function", 10, 100)],
        }))
        prior = _f("e.php", "fn", 55, "CWE-79", fid="P-1",
                   proof_lines=[50, 60],
                   proof_sink="raw write at e.php:55")
        newer = _f("e.php", "fn", 40, "CWE-79", fid="N-1",
                   proof_lines=[38, 60],
                   proof_sink="flows to the write at e.php:55")
        join = build_anchor_join({"r1": [prior], "r2": [newer]}, idx,
                                 {"r1": 0, "r2": 1})
        self.assertEqual(join.key_for("r2", 0), ("e.php", "fn", 55))


class TestDirectionDiscipline(TestCase):
    def test_different_files_never_join(self):
        fbr = {
            "r1": [_f("a.php", "fn", 10, "CWE-79")],
            "r2": [_f("b.php", "fn", 10, "CWE-79")],
        }
        join = build_anchor_join(fbr)
        self.assertEqual(join.site_count(), 2)

    def test_uncertain_pair_cap_keeps_true_total(self):
        fbr = {
            "r1": [_f("c.php", f"fn{i}", 10, "") for i in range(120)],
            "r2": [_f("c.php", f"fn{i}", 20, "") for i in range(120)],
        }
        join = build_anchor_join(fbr)
        self.assertEqual(join.uncertain_total, 120)
        self.assertEqual(len(join.uncertain_pairs), 100)

