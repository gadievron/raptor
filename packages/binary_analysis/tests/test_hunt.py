"""Anchor-family hunt: clustering, bounds, escaping, artifacts."""

from __future__ import annotations

import json
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from core.json import save_json

from packages.binary_analysis.hunt import (
    MAX_ANCHOR_PATTERN_CHARS,
    MAX_ANCHOR_REGEX_QUANTIFIERS,
    MAX_ANCHORS,
    MAX_FAMILIES,
    MAX_FAMILY_MEMBERS,
    MAX_FUNCS_PER_STRING,
    HuntError,
    cluster_anchor_families,
    compile_anchor_matcher,
    run_anchor_hunt,
)

BUILD_ID = "fa1544052f2d4bfa87d3d3bfb1b7b9f4aa11c0de"
ANCHOR16 = BUILD_ID[:16]
SHA = "a" * 64


def _record(text: str, vaddr: int, funcs: list[tuple[int, str]]) -> dict[str, Any]:
    return {
        "text": text,
        "vaddr": vaddr,
        "functions": [
            {"address": addr, "name": name} for addr, name in funcs
        ],
    }


class TestAnchorMatcher(unittest.TestCase):
    def test_substring_is_case_insensitive(self):
        match = compile_anchor_matcher(["Record Blob"])
        self.assertTrue(match("bad record blob %d"))
        self.assertTrue(match("RECORD BLOB header"))
        self.assertFalse(match("rec blob"))

    def test_regex_mode(self):
        match = compile_anchor_matcher([r"rec(ord)? blob"], regex=True)
        self.assertTrue(match("bad rec blob"))
        self.assertTrue(match("bad RECORD BLOB"))
        self.assertFalse(match("recblob"))

    def test_empty_and_too_many_anchors_refused(self):
        with self.assertRaises(HuntError):
            compile_anchor_matcher([])
        with self.assertRaises(HuntError):
            compile_anchor_matcher(["  "])
        with self.assertRaises(HuntError):
            compile_anchor_matcher(["a"] * (MAX_ANCHORS + 1))

    def test_overlong_pattern_refused(self):
        with self.assertRaises(HuntError):
            compile_anchor_matcher(["x" * (MAX_ANCHOR_PATTERN_CHARS + 1)])
        with self.assertRaises(HuntError):
            compile_anchor_matcher(
                ["x" * (MAX_ANCHOR_PATTERN_CHARS + 1)], regex=True,
            )

    def test_quantifier_count_bound_refused(self):
        pattern = "a*" * (MAX_ANCHOR_REGEX_QUANTIFIERS + 1)
        with self.assertRaises(HuntError):
            compile_anchor_matcher([pattern], regex=True)

    def test_nested_repetition_refused(self):
        """The classic superlinear shapes must refuse at compile time —
        the subject strings are hostile."""
        for pattern in (r"(a+)+b", r"(a*)*b", r"(x|y+){3}z",
                        r"((a+)b)+c"):
            with self.assertRaises(HuntError, msg=pattern):
                compile_anchor_matcher([pattern], regex=True)

    def test_alternation_overlap_bombs_refused(self):
        """Alternation inside a repeated group backtracks like nested
        repetition — (a|a)+ / (a|aa)+ hang on one clipped planted
        string and must refuse at compile time."""
        for pattern in (r"(a|a)+b", r"(a|aa)+c", r"(ab|a|b){9}d"):
            with self.assertRaises(HuntError, msg=pattern):
                compile_anchor_matcher([pattern], regex=True)

    def test_optional_quantifier_counted_and_nested(self):
        """`?` is a quantifier for BOTH caps: (a?)+ is a bomb, and
        ?-chains count toward the quantifier budget."""
        with self.assertRaises(HuntError):
            compile_anchor_matcher([r"(a?)+b"], regex=True)
        pattern = "a?" * (MAX_ANCHOR_REGEX_QUANTIFIERS + 1)
        with self.assertRaises(HuntError):
            compile_anchor_matcher([pattern], regex=True)

    def test_adjacent_same_atom_stacking_refused(self):
        """a*a*…b / a?a?…a is the exponential-alternatives shape with
        no group at all — refuse on the stacked pair."""
        for pattern in (r"a*a*b", r"a?a?a", r"a+a*b", r"[ab]*[ab]*c",
                        r"a*?a*b"):
            with self.assertRaises(HuntError, msg=pattern):
                compile_anchor_matcher([pattern], regex=True)

    def test_safe_shapes_accepted(self):
        # Escaped metacharacters, quantifier-free groups, top-level
        # alternation, bounded-optional groups (0-1 repetition cannot
        # amplify), lazy suffix on a single atom, and distinct-atom
        # quantifier runs all stay accepted.
        for pattern in (r"(abc)+", r"rec(ord)? blob", r"\(a\+\)\+",
                        r"a+b*c", r"foo|bar", r"(a|b)?c",
                        r"frame [0-9]+ truncated", r"a*?b",
                        r"(?:xy)+z"):
            compile_anchor_matcher([pattern], regex=True)

    def test_invalid_regex_refused(self):
        with self.assertRaises(HuntError):
            compile_anchor_matcher(["(unclosed"], regex=True)

    def test_regex_subject_is_clipped(self):
        match = compile_anchor_matcher(["needle"], regex=True)
        haystack = "x" * 1_000_000 + "needle"
        # The needle sits beyond the clip: no match, and no unbounded
        # scan over the hostile blob.
        self.assertFalse(match(haystack))

    def test_match_budget_times_out_slow_search(self):
        """Defense-in-depth under the guard: a search overrunning the
        wall budget returns the timeout sentinel instead of hanging
        the scan."""
        from packages.binary_analysis import hunt as hunt_module

        class _Stuck:
            def search(self, _subject):
                import time
                time.sleep(30)

        started = __import__("time").monotonic()
        outcome = hunt_module._search_with_budget([_Stuck()], "x", 0.05)
        elapsed = __import__("time").monotonic() - started
        self.assertIs(outcome, hunt_module._MATCH_TIMED_OUT)
        self.assertLess(elapsed, 5.0)

    def test_match_budget_breaker_disables_regex_matching(self):
        """After the breaker count of budget overruns, regex matching
        is disabled for the rest of the scan (bounding stranded
        watchdog threads) and the stats record it."""
        from unittest.mock import patch as _patch

        from packages.binary_analysis import hunt as hunt_module
        match = compile_anchor_matcher([r"frame [0-9]+"], regex=True)
        with _patch.object(
            hunt_module, "_search_with_budget",
            return_value=hunt_module._MATCH_TIMED_OUT,
        ) as budget:
            for _ in range(10):
                self.assertFalse(match("frame 12"))
        # Breaker fired: only the first BREAKER calls hit the budget
        # path; the rest short-circuited disabled.
        from packages.binary_analysis.hunt import (
            REGEX_MATCH_TIMEOUT_BREAKER,
        )
        self.assertEqual(budget.call_count, REGEX_MATCH_TIMEOUT_BREAKER)
        stats = match.match_stats
        self.assertEqual(stats["budget_timeouts"],
                         REGEX_MATCH_TIMEOUT_BREAKER)
        self.assertTrue(stats["disabled"])


class TestClustering(unittest.TestCase):
    def _sibling_records(self) -> list[dict[str, Any]]:
        # Two families: parse_a/parse_b share two strings; lone_fn
        # references one unrelated string.
        return [
            _record("record blob magic bad", 0x5000,
                    [(0x1000, "parse_a"), (0x2000, "parse_b")]),
            _record("record blob truncated", 0x5010,
                    [(0x1000, "parse_a"), (0x2000, "parse_b")]),
            _record("zzz unrelated banner", 0x5020, [(0x9000, "lone_fn")]),
        ]

    def test_co_occurrence_joins_at_k(self):
        families, _stats = cluster_anchor_families(self._sibling_records())
        self.assertEqual(len(families), 2)
        top = families[0]
        self.assertEqual(
            [m["name"] for m in top["members"]], ["parse_a", "parse_b"],
        )

    def test_single_shared_string_does_not_join(self):
        records = [
            _record("one shared string", 0x5000,
                    [(0x1000, "fa"), (0x2000, "fb")]),
        ]
        families, _stats = cluster_anchor_families(records)
        # K=2: one shared string is not corroboration.
        self.assertEqual(len(families), 2)

    def test_rare_stem_joins_singletons(self):
        records = [
            _record("kdcc frame open failed", 0x5000, [(0x1000, "fa")]),
            _record("kdcc frame close failed", 0x5010, [(0x2000, "fb")]),
        ]
        families, _stats = cluster_anchor_families(records)
        self.assertEqual(len(families), 1)
        self.assertIn("kdcc", families[0]["shared_stems"])

    def test_common_stem_does_not_join(self):
        # The same stem across MORE than STEM_JOIN_MAX_FANOUT functions
        # is vocabulary, not family evidence.
        records = [
            _record(f"failed operation {i}", 0x5000 + i,
                    [(0x1000 + i * 0x100, f"f{i}")])
            for i in range(8)
        ]
        families, _stats = cluster_anchor_families(records)
        self.assertEqual(len(families), 8)

    def test_deterministic_under_shuffled_emission(self):
        base = [
            _record(f"kdcc item {i} bad", 0x5000 + i * 0x10,
                    [(0x1000 + (i % 5) * 0x100, f"f{i % 5}"),
                     (0x8000 + (i % 3) * 0x100, f"g{i % 3}")])
            for i in range(24)
        ]
        expected, expected_stats = cluster_anchor_families(
            [dict(r) for r in base],
        )
        for seed in range(5):
            shuffled = [dict(r) for r in base]
            for record in shuffled:
                random.Random(seed).shuffle(record["functions"])
            random.Random(seed).shuffle(shuffled)
            families, stats = cluster_anchor_families(shuffled)
            self.assertEqual(families, expected, f"seed={seed}")
            self.assertEqual(stats, expected_stats, f"seed={seed}")

    def test_member_flood_truncates_by_xref_weight(self):
        """A flood of one-string members must not displace the
        anchor-dense members — truncation keeps xref-weight order and
        says so in-band."""
        records = []
        # Two heavy members sharing many strings.
        for i in range(6):
            records.append(_record(
                f"kdcc heavy string {i}", 0x5000 + i,
                [(0x1000, "heavy_a"), (0x1100, "heavy_b")],
            ))
        # A flood of light members, each sharing exactly K strings with
        # heavy_a so they join the same family (addresses BELOW the
        # heavy members, so discovery/address order would rank them
        # first if the weight ordering regressed).
        for i in range(MAX_FAMILY_MEMBERS + 10):
            for j in range(2):
                records.append(_record(
                    f"kdcc light {i} {j}", 0x6000 + i * 4 + j,
                    [(0x100 + i * 0x10, f"light_{i:03d}"), (0x1000, "heavy_a")],
                ))
        families, _stats = cluster_anchor_families(records)
        family = families[0]
        self.assertEqual(family["member_count"],
                         2 + MAX_FAMILY_MEMBERS + 10)
        self.assertEqual(len(family["members"]), MAX_FAMILY_MEMBERS)
        names = [m["name"] for m in family["members"]]
        self.assertEqual(names[0], "heavy_a")
        self.assertIn("heavy_b", names)
        self.assertIn(
            f"capped at {MAX_FAMILY_MEMBERS} of", family["truncation"],
        )
        self.assertIn("xref-weight", family["truncation"])

    def test_family_flood_truncates_globally(self):
        records = []
        for i in range(MAX_FAMILIES + 5):
            for j in range(2):
                records.append(_record(
                    f"grp{i:03d}xx string {j}", 0x5000 + i * 0x20 + j,
                    [(0x1000 + i * 0x100, f"f{i:03d}")],
                ))
        families, stats = cluster_anchor_families(records)
        self.assertEqual(len(families), MAX_FAMILIES)
        self.assertIn(
            f"capped at {MAX_FAMILIES} of", stats["families_truncation"],
        )

    def test_per_string_fanout_capped(self):
        records = [_record(
            "planted string referenced everywhere and again", 0x5000,
            [(0x1000 + i * 0x10, f"f{i}")
             for i in range(MAX_FUNCS_PER_STRING + 40)],
        )]
        families, stats = cluster_anchor_families(records)
        self.assertEqual(stats["string_fanout_truncated"], 1)
        total_members = sum(f["member_count"] for f in families)
        self.assertLessEqual(total_members, MAX_FUNCS_PER_STRING)

    def test_duplicate_text_records_share_one_fanout_cap(self):
        """Cap-bypass shape: many RECORDS carrying the SAME string
        text, each individually under the fanout cap, whose union is
        far past it. Function sets must aggregate per TEXT and be
        capped BEFORE pairwise work — bounded members AND the in-band
        signal, instead of a quadratic pairwise blow-up over the
        uncapped union."""
        import time
        records = []
        text = "planted duplicate text with many referencing functions"
        for dup in range(40):
            records.append(_record(
                text, 0x5000 + dup,
                [(0x10000 + (dup * (MAX_FUNCS_PER_STRING - 1) + i) * 0x10,
                  f"f{dup}_{i}")
                 for i in range(MAX_FUNCS_PER_STRING - 1)],
            ))
        started = time.monotonic()
        families, stats = cluster_anchor_families(records)
        elapsed = time.monotonic() - started
        # One TEXT, one cap, one truncation signal.
        self.assertEqual(stats["string_fanout_truncated"], 1)
        total_members = sum(f["member_count"] for f in families)
        self.assertLessEqual(total_members, MAX_FUNCS_PER_STRING)
        # Bounded pairwise work: the capped set pairs in milliseconds;
        # pairing the uncapped 2520-function union is quadratically
        # slower (tens of seconds).
        self.assertLess(elapsed, 5.0)

    def test_stem_fanout_exact_boundary(self):
        """Fanout boundary: a stem across exactly STEM_JOIN_MAX_FANOUT
        functions joins; one more refuses."""
        def _records_for(count):
            return [
                _record(f"zzqx variant {i} failed", 0x5000 + i * 0x10,
                        [(0x1000 + i * 0x100, f"f{i}")])
                for i in range(count)
            ]
        from packages.binary_analysis.hunt import STEM_JOIN_MAX_FANOUT
        families, _stats = cluster_anchor_families(
            _records_for(STEM_JOIN_MAX_FANOUT),
        )
        self.assertEqual(len(families), 1)
        families, _stats = cluster_anchor_families(
            _records_for(STEM_JOIN_MAX_FANOUT + 1),
        )
        self.assertEqual(len(families), STEM_JOIN_MAX_FANOUT + 1)


class TestRunAnchorHunt(unittest.TestCase):
    def _run_dir(self, tmp: Path) -> Path:
        run_dir = tmp / "run"
        run_dir.mkdir()
        save_json(run_dir / "binary-manifest.json", {
            "schema_version": 1,
            "binary_path": str(tmp / "target.bin"),
            "binary_sha256": SHA,
            "size_bytes": 128,
            "executable": True,
            "target_kind": "binary",
            "arch": "x86",
            "bits": 64,
            "binary_format": "elf",
            "build_id": BUILD_ID,
            "image_base": 0x400000,
        })
        save_json(run_dir / "binary-context-map.json", {
            "interesting_functions": [
                {"id": "BFN-401000", "name": "parse_a",
                 "address": "0x401000", "size": 64,
                 "fid": f"{ANCHOR16}:0x1000"},
                {"id": "BFN-401100", "name": "parse_b",
                 "address": "0x401100", "size": 96,
                 "fid": f"{ANCHOR16}:0x1100"},
                {"id": "BFN-402000", "name": "common_helper",
                 "address": "0x402000", "size": 32,
                 "fid": f"{ANCHOR16}:0x2000"},
            ],
            "call_graph_edges": [
                {"source_name": "parse_a", "target_name": "common_helper"},
                {"source_name": "parse_b", "target_name": "common_helper"},
                {"source_name": "parse_a", "target_name": "parse_b"},
                {"source_name": "parse_a", "target_name": "mystery_ext"},
                {"source_name": "parse_b", "target_name": "mystery_ext"},
            ],
        })
        return run_dir

    def _scanner(self, records, stats=None, notes=None):
        def scan(_manifest, _matcher):
            # stats={} means "the scan degraded" (the collector's
            # documented contract) — only None gets the default.
            effective = stats if stats is not None else {
                "strings_total": len(records),
                "strings_scanned": len(records),
                "scan_truncated": False,
                "selected": len(records),
                "selection_truncated": False,
            }
            return records, {"stats": effective, "notes": notes or []}
        return scan

    def _records(self):
        return [
            _record("record blob magic bad", 0x5000,
                    [(0x401000, "fcn.401000"), (0x401100, "fcn.401100")]),
            _record("record blob truncated", 0x5010,
                    [(0x401000, "fcn.401000"), (0x401100, "fcn.401100")]),
        ]

    def test_members_bound_to_inventory_with_fids(self):
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            payload = run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(self._records()),
            )
            self.assertEqual(len(payload["families"]), 1)
            family = payload["families"][0]
            members = {m["name"]: m for m in family["members"]}
            # Inventory names win over the scan's fcn.* placeholders.
            self.assertIn("parse_a", members)
            self.assertEqual(members["parse_a"]["fid"],
                             f"{ANCHOR16}:0x1000")
            self.assertEqual(members["parse_a"]["size"], 64)
            self.assertEqual(members["parse_a"]["address"], "0x401000")
            # Shared callee resolved with fid; inter-member edge kept.
            shared = {c["name"]: c for c in family["shared_callees"]}
            self.assertIn("common_helper", shared)
            self.assertEqual(shared["common_helper"]["fid"],
                             f"{ANCHOR16}:0x2000")
            self.assertEqual(
                family["inter_member_edges"],
                [{"caller": "parse_a", "callee": "parse_b"}],
            )
            # Honesty lines present.
            self.assertEqual(payload["claim"], "structural_lead_only")
            self.assertIn("not findings", payload["evidence_note"])
            self.assertEqual(family["evidence_tier"], "xref_backed")

    def test_unresolvable_shared_callee_records_fid_miss(self):
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            payload = run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(self._records()),
            )
            family = payload["families"][0]
            shared = {c["name"]: c for c in family["shared_callees"]}
            self.assertIn("mystery_ext", shared)
            self.assertNotIn("fid", shared["mystery_ext"])
            misses = json.loads(
                (run_dir / "fid-misses.json").read_text(encoding="utf-8"),
            )
            ops = [op["operation"] for op in misses["operations"]]
            self.assertIn("binary-hunt-anchor", ops)

    def test_artifacts_written_and_collision_suffixed(self):
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            first = run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(self._records()),
            )
            second = run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(self._records()),
            )
            self.assertNotEqual(first["artifacts"]["json"],
                                second["artifacts"]["json"])
            for artifact in (first, second):
                self.assertTrue(Path(artifact["artifacts"]["json"]).is_file())
                self.assertTrue(
                    Path(artifact["artifacts"]["report"]).is_file(),
                )
            on_disk = json.loads(
                Path(first["artifacts"]["json"]).read_text(encoding="utf-8"),
            )
            self.assertEqual(on_disk["provenance"]["untrusted"], True)

    def test_hostile_anchor_echo_and_strings_escaped(self):
        hostile_anchor = "rec\x1b]0;pwn\x07ord"
        # Raw ESC, BEL, a bidi override (survives JSON serialisation
        # as a raw code point), and markdown structure.
        hostile_string = "record \x1b[9A ‮blob `bad` [x](http://e)"
        records = [
            _record(hostile_string, 0x5000,
                    [(0x401000, "fcn.\x1b[31mred")]),
            _record(hostile_string + " again", 0x5010,
                    [(0x401000, "fcn.\x1b[31mred")]),
        ]
        # Scanner contract: text/names arrive ESCAPED (the real
        # scanner escapes at capture) — but a lazy fake keeps raw
        # bytes, which the payload escape backstop must still catch
        # across EVERY slot (member names, sample_strings, per-member
        # anchor_strings, evidence data). Feed raw here and assert on
        # the ON-DISK ARTIFACT BYTES — a json.dumps(payload) check is
        # vacuous for anything an ensure_ascii lane would mask.
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            payload = run_anchor_hunt(
                run_dir, [hostile_anchor],
                scanner=self._scanner(records),
            )
            raw = Path(payload["artifacts"]["json"]).read_bytes()
            self.assertNotIn(b"\x1b", raw)
            self.assertNotIn(b"\x07", raw)
            self.assertNotIn("‮".encode(), raw)  # raw bidi
            self.assertIn(b"\\\\x1b", raw)  # escaped form survives
            # The family carried the hostile text into every slot —
            # prove the slots exist AND are inert.
            on_disk = json.loads(raw.decode("utf-8"))
            family = on_disk["families"][0]
            self.assertTrue(family["sample_strings"])
            self.assertTrue(family["members"][0]["anchor_strings"])
            self.assertTrue(
                any(rec["data"].get("sample_strings")
                    for rec in on_disk["evidence"]),
            )
            report_raw = Path(payload["artifacts"]["report"]).read_bytes()
            self.assertNotIn(b"\x1b", report_raw)
            self.assertNotIn("‮".encode(), report_raw)
            report = report_raw.decode("utf-8")
            # Report neutralises markdown structure in slots: the
            # hostile backtick cannot close the wrapping code span.
            self.assertNotIn("``bad``", report)
            self.assertIn("Not findings", report)

    def test_degraded_scan_surfaces_in_band(self):
        """The collector's empty-stats contract: a degraded izj must
        not present as a clean zero-family result — the payload, the
        report and the truncation lines all say so."""
        note = "WARNING: radare2 session lost mid-scan (r2 died)"
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            payload = run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner([], stats={}, notes=[note]),
            )
            self.assertEqual(payload["families"], [])
            self.assertTrue(payload["scan"]["degraded"])
            lines = "\n".join(payload["truncation_lines"])
            self.assertIn("string scan degraded", lines)
            self.assertIn("session lost mid-scan", lines)
            report = Path(payload["artifacts"]["report"]).read_text(
                encoding="utf-8",
            )
            self.assertIn("string scan degraded", report)
            self.assertIn("session lost mid-scan", report)

    def test_regex_budget_hits_surface_in_band(self):
        """Budget overruns recorded by the matcher ride into the scan
        block and the in-band lines."""
        from unittest.mock import patch as _patch

        from packages.binary_analysis import hunt as hunt_module
        matcher_holder = {}
        real_compile = hunt_module.compile_anchor_matcher

        def capture_compile(anchors, *, regex=False):
            matcher = real_compile(anchors, regex=regex)
            matcher_holder["m"] = matcher
            return matcher

        def scanner(_manifest, matcher):
            # The scan drives the matcher over planted strings; the
            # budget times out every one of them.
            for _ in range(10):
                matcher("planted subject")
            return [], {"stats": {
                "strings_total": 10, "strings_scanned": 10,
                "scan_truncated": False, "selected": 0,
                "selection_truncated": False,
            }, "notes": []}

        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            with _patch.object(
                hunt_module, "compile_anchor_matcher", capture_compile,
            ), _patch.object(
                hunt_module, "_search_with_budget",
                return_value=hunt_module._MATCH_TIMED_OUT,
            ):
                payload = hunt_module.run_anchor_hunt(
                    run_dir, [r"frame [0-9]+"], regex=True,
                    scanner=scanner,
                )
            self.assertEqual(
                payload["scan"]["regex_budget_timeouts"],
                hunt_module.REGEX_MATCH_TIMEOUT_BREAKER,
            )
            self.assertTrue(payload["scan"]["regex_matching_disabled"])
            lines = "\n".join(payload["truncation_lines"])
            self.assertIn("regex match budget", lines)
            self.assertIn("disabled", lines)

    def test_scan_truncation_surfaces_in_band(self):
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            payload = run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(
                    self._records(),
                    stats={
                        "strings_total": 5000,
                        "strings_scanned": 3000,
                        "scan_truncated": True,
                        "selected": 512,
                        "selection_truncated": True,
                    },
                ),
            )
            lines = "\n".join(payload["truncation_lines"])
            self.assertIn("3000 of 5000", lines)
            self.assertIn("xref-lookup budget", lines)
            report = Path(payload["artifacts"]["report"]).read_text(
                encoding="utf-8",
            )
            self.assertIn("3000 of 5000", report)

    def test_graph_kinds_written(self):
        from packages.binary_analysis.graph_store import (
            graph_path_for_run,
            query_edges,
        )
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(self._records()),
            )
            edges = query_edges(
                graph_path_for_run(run_dir),
                kind="HUNT_ANCHOR_FAMILY_MEMBER",
            )
            self.assertEqual(len(edges), 2)

    def test_missing_artifacts_refused(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(HuntError):
                run_anchor_hunt(
                    Path(tmp), ["x"], scanner=self._scanner([]),
                )

    def test_hunt_preserves_map_graph_and_reuses_snapshot(self):
        """The hunt attaches to the MAP's snapshot: it must neither
        REPLACE the map's function-node props (calls_dangerous,
        transitive_distance) nor mint a snapshot of its own — a
        regression to begin_snapshot on the same run dir would
        cascade-delete the map's whole graph."""
        import sqlite3

        from packages.binary_analysis.graph_store import (
            BinaryGraphStore,
            graph_path_for_run,
        )
        with TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp))
            graph_path = graph_path_for_run(run_dir)
            # Pre-populate like the map ingest: one snapshot, a
            # function node with map-owned props, and a sibling map
            # node that a snapshot wipe would delete.
            with BinaryGraphStore(graph_path) as store:
                snapshot_id = store.begin_snapshot(
                    SHA, str(Path(tmp) / "target.bin"), run_dir,
                )
                store.add_node(
                    snapshot_id, SHA, "function", "BFN-401000",
                    name="parse_a", address="0x401000",
                    props={"calls_dangerous": ["strcpy"],
                           "transitive_distance": 2},
                )
                store.add_node(
                    snapshot_id, SHA, "external_ingress", "ING-1",
                    name="openURL", props={"kind": "url_handler"},
                )
            run_anchor_hunt(
                run_dir, ["record blob"],
                scanner=self._scanner(self._records()),
            )
            conn = sqlite3.connect(graph_path)
            try:
                conn.row_factory = sqlite3.Row
                snapshots = conn.execute(
                    "SELECT COUNT(*) AS n FROM snapshots").fetchone()["n"]
                self.assertEqual(snapshots, 1)
                fn_props = json.loads(conn.execute(
                    "SELECT props_json FROM nodes WHERE kind='function' "
                    "AND stable_key='BFN-401000'").fetchone()["props_json"])
                self.assertEqual(fn_props.get("calls_dangerous"),
                                 ["strcpy"])
                self.assertEqual(fn_props.get("transitive_distance"), 2)
                ingress = conn.execute(
                    "SELECT COUNT(*) AS n FROM nodes "
                    "WHERE kind='external_ingress'").fetchone()["n"]
                self.assertEqual(ingress, 1)
                hunt_edges = conn.execute(
                    "SELECT COUNT(*) AS n FROM edges "
                    "WHERE kind='HUNT_ANCHOR_FAMILY_MEMBER'",
                ).fetchone()["n"]
                self.assertEqual(hunt_edges, 2)
            finally:
                conn.close()


class TestScanSliceBound(unittest.TestCase):
    def test_scan_and_lookup_bounds_enforced_and_reported(self):
        """The izj slice bound and the xref-lookup budget both bite
        and both surface in the stats (mutation pin: dropping either
        bound or its stats field fails here)."""
        from unittest.mock import MagicMock, patch as _patch

        from packages.binary_analysis.radare2_understand import (
            BinaryContextMap,
            BinaryUnderstand,
        )
        understand = BinaryUnderstand.__new__(BinaryUnderstand)
        ctx = BinaryContextMap(binary_path=Path("/x/bin"))
        izj = [
            {"string": f"needle {i} here", "vaddr": 0x5000 + i * 0x10}
            for i in range(10)
        ]
        r2 = MagicMock()

        def cmd(command):
            if command == "izj":
                return json.dumps(izj)
            return "[]"

        r2.cmd.side_effect = cmd
        with _patch.object(BinaryUnderstand, "_MAX_ANCHOR_STRINGS", 5), \
                _patch.object(BinaryUnderstand,
                              "_MAX_ANCHOR_XREF_LOOKUPS", 3):
            records, stats = understand._collect_selected_string_xrefs(
                r2, ctx, lambda text: "needle" in text,
            )
        self.assertEqual(stats["strings_total"], 10)
        self.assertLessEqual(stats["strings_scanned"], 5)
        self.assertTrue(stats["scan_truncated"])
        self.assertEqual(stats["selected"], 3)
        self.assertTrue(stats["selection_truncated"])
        self.assertEqual(len(records), 3)


if __name__ == "__main__":
    unittest.main()
