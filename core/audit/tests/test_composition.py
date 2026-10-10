"""Tests for the weakness composition engine."""

from __future__ import annotations

from pathlib import Path

from core.audit.composition import (
    WeaknessRecord,
    compose_hypotheses,
    find_unguarded_paths,
    build_weakness_inventory,
    run_composition,
    _caller_guards_property,
)

FuncKey = tuple[str, str]


def _w(
    func: str = "parse_input",
    file: str = "src/parse.c",
    guard_type: str = "bounds",
    prop: str = "length <= 256",
    mechanism: str = "CWE-120 buffer overflow",
) -> WeaknessRecord:
    return WeaknessRecord(
        function=func,
        file=file,
        guard_type=guard_type,
        assumed_property=prop,
        mechanism=mechanism,
        guarded_by=("validate_input",),
    )


def _reverse(
    edges: list[tuple[FuncKey, FuncKey]],
) -> dict[FuncKey, set[FuncKey]]:
    """Build reverse edges from (caller, callee) pairs."""
    result: dict[FuncKey, set[FuncKey]] = {}
    for caller, callee in edges:
        result.setdefault(callee, set()).add(caller)
    return result


class TestCallerGuardsProperty:
    def test_reviewed_no_weakness_is_guarded(self):
        w = _w()
        reviewed = {"src/main.c:handle_request"}
        assert _caller_guards_property(
            "src/main.c:handle_request", w, {}, reviewed,
        ) is True

    def test_unreviewed_is_unguarded(self):
        w = _w()
        assert _caller_guards_property(
            "src/main.c:handle_request", w, {}, set(),
        ) is False

    def test_same_guard_type_about_callee_is_unguarded(self):
        w = _w(func="parse_input")
        index = {
            "src/main.c:handle_request": [{
                "guard_type": "bounds",
                "mechanism": "CWE-120 overflow in parse_input",
                "assumed_by": "src/parse.c:parse_input",
            }],
        }
        reviewed = {"src/main.c:handle_request"}
        assert _caller_guards_property(
            "src/main.c:handle_request", w, index, reviewed,
        ) is False

    def test_different_guard_type_is_guarded(self):
        w = _w(guard_type="bounds")
        index = {
            "src/main.c:handle_request": [{
                "guard_type": "null_safety",
                "mechanism": "null dereference in parse_input",
                "assumed_by": "src/parse.c:parse_input",
            }],
        }
        reviewed = {"src/main.c:handle_request"}
        assert _caller_guards_property(
            "src/main.c:handle_request", w, index, reviewed,
        ) is True

    def test_short_name_substring_match_is_conservative(self):
        """A function named 'parse' substring-matches 'parse_input' in
        the mechanism — the engine treats this as unguarded (conservative)."""
        w = _w(func="parse")
        index = {
            "src/main.c:handle_request": [{
                "guard_type": "bounds",
                "mechanism": "CWE-120 overflow in parse_input",
                "assumed_by": "",
            }],
        }
        reviewed = {"src/main.c:handle_request"}
        assert _caller_guards_property(
            "src/main.c:handle_request", w, index, reviewed,
        ) is False


class TestFindUnguardedPaths:
    def test_one_guarded_one_unguarded(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "handle_request"), ("src/parse.c", "parse_input")),
            (("src/api.c", "api_handler"), ("src/parse.c", "parse_input")),
        ])
        entry_points = {"src/main.c:handle_request", "src/api.c:api_handler"}
        reviewed = {"src/main.c:handle_request"}
        journal_index: dict = {}

        paths = find_unguarded_paths(
            w, reverse, entry_points, journal_index, reviewed,
        )
        assert len(paths) == 1
        fids = [f"{f}:{fn}" for f, fn in paths[0].chain]
        assert "src/api.c:api_handler" in fids

    def test_all_callers_guarded(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "handle_request"), ("src/parse.c", "parse_input")),
        ])
        entry_points = {"src/main.c:handle_request"}
        reviewed = {"src/main.c:handle_request"}

        paths = find_unguarded_paths(
            w, reverse, entry_points, {}, reviewed,
        )
        assert paths == []

    def test_depth_cap(self):
        w = _w()
        chain = []
        for i in range(20):
            caller = ("src/f.c", f"f{i + 1}")
            callee = ("src/f.c", f"f{i}") if i > 0 else ("src/parse.c", "parse_input")
            chain.append((caller, callee))
        reverse = _reverse(chain)

        paths = find_unguarded_paths(
            w, reverse, set(), {}, set(), max_depth=5,
        )
        limited = [p for p in paths if p.depth_limited]
        assert len(limited) > 0

    def test_cyclic_graph_terminates(self):
        w = _w()
        reverse = _reverse([
            (("a.c", "a"), ("src/parse.c", "parse_input")),
            (("b.c", "b"), ("a.c", "a")),
            (("a.c", "a"), ("b.c", "b")),
        ])

        paths = find_unguarded_paths(
            w, reverse, set(), {}, set(),
        )
        assert isinstance(paths, list)

    def test_entry_point_reached(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "main"), ("src/mid.c", "mid")),
            (("src/mid.c", "mid"), ("src/parse.c", "parse_input")),
        ])
        entry_points = {"src/main.c:main"}

        paths = find_unguarded_paths(
            w, reverse, entry_points, {}, set(),
        )
        assert len(paths) == 1
        assert not paths[0].depth_limited
        fids = [f"{f}:{fn}" for f, fn in paths[0].chain]
        assert fids[0] == "src/main.c:main"
        assert fids[-1] == "src/parse.c:parse_input"

    def test_root_function_is_implicit_entry_when_no_entry_points(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "main"), ("src/parse.c", "parse_input")),
        ])

        paths = find_unguarded_paths(
            w, reverse, set(), {}, set(),
        )
        assert len(paths) == 1
        fids = [f"{f}:{fn}" for f, fn in paths[0].chain]
        assert fids[0] == "src/main.c:main"
        assert not paths[0].depth_limited

    def test_root_function_ignored_when_entry_points_defined(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "main"), ("src/parse.c", "parse_input")),
        ])

        paths = find_unguarded_paths(
            w, reverse, {"src/other.c:other"}, {}, set(),
        )
        assert len(paths) == 0

    def test_unreviewed_caller_is_unguarded(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "main"), ("src/parse.c", "parse_input")),
        ])
        entry_points = {"src/main.c:main"}

        paths = find_unguarded_paths(
            w, reverse, entry_points, {}, set(),
        )
        assert len(paths) == 1


class TestComposeHypotheses:
    def test_deduplication_keeps_shortest(self):
        w = _w()
        reverse = _reverse([
            (("src/main.c", "main"), ("src/parse.c", "parse_input")),
            (("src/main.c", "main"), ("src/mid.c", "mid")),
            (("src/mid.c", "mid"), ("src/parse.c", "parse_input")),
        ])
        entry_points = {"src/main.c:main"}

        results = compose_hypotheses(
            [w], reverse, entry_points, {}, set(),
        )
        assert len(results) == 1
        assert len(results[0].unguarded_path.chain) == 2

    def test_verifiable_guard_types(self):
        for gt in ("bounds", "null_safety", "validation", "sanitisation"):
            w = _w(guard_type=gt)
            reverse = _reverse([
                (("m.c", "main"), ("src/parse.c", "parse_input")),
            ])
            results = compose_hypotheses(
                [w], reverse, {"m.c:main"}, {}, set(),
            )
            assert len(results) == 1
            assert results[0].verifiable is True

    def test_non_verifiable_guard_types(self):
        for gt in ("lifetime", "ordering", "concurrency", "other"):
            w = _w(guard_type=gt)
            reverse = _reverse([
                (("m.c", "main"), ("src/parse.c", "parse_input")),
            ])
            results = compose_hypotheses(
                [w], reverse, {"m.c:main"}, {}, set(),
            )
            assert len(results) == 1
            assert results[0].verifiable is False

    def test_cap_limits_output(self):
        weaknesses = [
            _w(func=f"f{i}") for i in range(10)
        ]
        reverse: dict[FuncKey, set[FuncKey]] = {}
        for i in range(10):
            reverse.setdefault(
                ("src/parse.c", f"f{i}"), set(),
            ).add(("m.c", "main"))
        results = compose_hypotheses(
            weaknesses, reverse, {"m.c:main"}, {}, set(),
            max_hypotheses=3,
        )
        assert len(results) == 3

    def test_to_dict_shape(self):
        w = _w()
        reverse = _reverse([
            (("m.c", "main"), ("src/parse.c", "parse_input")),
        ])
        results = compose_hypotheses(
            [w], reverse, {"m.c:main"}, {}, set(),
        )
        d = results[0].to_dict()
        assert "weakness" in d
        assert "path" in d
        assert "hypothesis" in d
        assert d["weakness"]["guard_type"] == "bounds"
        assert d["weakness"]["guarded_by"] == ["validate_input"]

    def test_duplicate_weaknesses_deduplicated(self):
        w = _w()
        reverse = _reverse([
            (("m.c", "main"), ("src/parse.c", "parse_input")),
        ])
        results = compose_hypotheses(
            [w, w, w], reverse, {"m.c:main"}, {}, set(),
        )
        assert len(results) == 1


class TestBuildWeaknessInventory:
    def test_round_trips_from_journal(self, tmp_path: Path):
        from core.coverage.journal import (
            ReviewJournalEntry, append_entry, now_iso,
        )

        entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="run-1",
            file="src/parse.c",
            function="parse_input",
            verdict="clean",
            source_hash="abc",
            weaknesses=[{
                "guard_type": "bounds",
                "property": "length <= 256",
                "mechanism": "CWE-120 overflow",
                "guarded_by": ["validate_input"],
                "cwe_class": "CWE-120",
                "source": "structured_pass",
            }],
        )
        append_entry(tmp_path, entry)

        ws = build_weakness_inventory(tmp_path)
        assert len(ws) == 1
        assert ws[0].guard_type == "bounds"
        assert ws[0].assumed_property == "length <= 256"
        assert ws[0].function == "parse_input"
        assert ws[0].guarded_by == ("validate_input",)
        assert ws[0].cwe_class == "CWE-120"

    def test_skips_entries_without_guard_type(self, tmp_path: Path):
        from core.coverage.journal import (
            ReviewJournalEntry, append_entry, now_iso,
        )

        entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="run-1",
            file="src/a.c",
            function="f",
            verdict="clean",
            source_hash="abc",
            weaknesses=[{"property": "something"}],
        )
        append_entry(tmp_path, entry)

        ws = build_weakness_inventory(tmp_path)
        assert ws == []


class TestRunComposition:
    def test_end_to_end(self, tmp_path: Path):
        from core.coverage.journal import (
            ReviewJournalEntry, append_entry, now_iso,
        )
        from core.inventory.call_graph import CallSite, FileCallGraph

        # Weak function with a bounds weakness
        weak_entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="run-1",
            file="src/parse.c",
            function="parse_input",
            verdict="clean",
            source_hash="abc",
            weaknesses=[{
                "guard_type": "bounds",
                "property": "length <= 256",
                "mechanism": "CWE-120 overflow",
                "guarded_by": ["validate_input"],
                "cwe_class": "CWE-120",
                "source": "structured_pass",
            }],
        )
        # Caller that was reviewed but has no weakness about parse_input
        caller_entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="run-1",
            file="src/main.c",
            function="handle_request",
            verdict="clean",
            source_hash="def",
        )
        append_entry(tmp_path, weak_entry)
        append_entry(tmp_path, caller_entry)

        call_graphs = {
            "src/main.c": FileCallGraph(
                calls=[CallSite(
                    chain=["parse_input"], line=10,
                    caller="handle_request",
                )],
            ),
            "src/parse.c": FileCallGraph(
                calls=[CallSite(
                    chain=["memcpy"], line=5,
                    caller="parse_input",
                )],
            ),
        }
        entry_points = {"src/main.c:handle_request"}

        results = run_composition(tmp_path, call_graphs, entry_points)
        # Caller was reviewed and doesn't share the weakness → guarded
        assert len(results) == 0

    def test_unreviewed_caller_produces_hypothesis(self, tmp_path: Path):
        from core.coverage.journal import (
            ReviewJournalEntry, append_entry, now_iso,
        )
        from core.inventory.call_graph import CallSite, FileCallGraph

        weak_entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="run-1",
            file="src/parse.c",
            function="parse_input",
            verdict="clean",
            source_hash="abc",
            weaknesses=[{
                "guard_type": "bounds",
                "property": "length <= 256",
                "mechanism": "CWE-120 overflow",
                "guarded_by": [],
                "source": "structured_pass",
            }],
        )
        append_entry(tmp_path, weak_entry)

        call_graphs = {
            "src/main.c": FileCallGraph(
                calls=[CallSite(
                    chain=["parse_input"], line=10,
                    caller="handle_request",
                )],
            ),
            "src/parse.c": FileCallGraph(
                calls=[CallSite(
                    chain=["memcpy"], line=5,
                    caller="parse_input",
                )],
            ),
        }
        entry_points = {"src/main.c:handle_request"}

        results = run_composition(tmp_path, call_graphs, entry_points)
        assert len(results) == 1
        assert results[0].weakness.guard_type == "bounds"
        assert results[0].verifiable is True
        d = results[0].to_dict()
        assert "src/main.c:handle_request" in d["path"]
