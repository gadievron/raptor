"""Tests for the cross-scope discovery engine."""

from __future__ import annotations

import json
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[3])

from core.audit.discovery import (
    HandlerSite,
    SeamBundle,
    StateMachineBundle,
    _HINT_MULTI_THREADED,
    _HINT_SINGLE_THREADED,
    _build_func_index,
    _build_sm_prompt,
    _extract_call_site_snippet,
    _extract_cross_file_seams,
    _parse_findings,
    _parse_sm_findings,
    _score_field,
    _score_seam,
    build_seam_bundles,
    build_state_machine_bundles,
    detect_single_threaded,
    run_contract_discovery,
    run_state_machine_discovery,
    write_discovery_weaknesses,
)


# ── fixtures ────────────────────────────────────────────────────────

def _checklist(*file_specs: tuple[str, list[dict], list[dict]]) -> dict:
    """Build a minimal checklist.

    Each file_spec is (path, items, calls) where items are
    [{name, line_start, line_end}] and calls are
    [{line, chain, caller}].
    """
    files = []
    for path, items, calls in file_specs:
        full_items = []
        for it in items:
            entry = {
                "name": it["name"],
                "line_start": it.get("line_start", 1),
                "line_end": it.get("line_end", 50),
            }
            sig = it.get("signature", f"void {it['name']}()")
            if sig is not None:
                entry["signature"] = sig
            full_items.append(entry)
        files.append({
            "path": path,
            "items": full_items,
            "call_graph": {"calls": calls},
        })
    return {"files": files}


def _simple_checklist() -> dict:
    """Two-file checklist with one cross-file seam."""
    return _checklist(
        (
            "src/main.c",
            [{"name": "handle_request", "line_start": 10, "line_end": 60}],
            [{"line": 30, "chain": ["parse_input"], "caller": "handle_request"}],
        ),
        (
            "src/parse.c",
            [{"name": "parse_input", "line_start": 5, "line_end": 40}],
            [],
        ),
    )


def _multi_seam_checklist() -> dict:
    """Three files with multiple cross-file seams for priority testing."""
    return _checklist(
        (
            "src/main.c",
            [
                {"name": "handle_request", "line_start": 10, "line_end": 60},
                {"name": "dispatch", "line_start": 70, "line_end": 100},
            ],
            [
                {"line": 30, "chain": ["parse_input"], "caller": "handle_request"},
                {"line": 35, "chain": ["validate"], "caller": "handle_request"},
                {"line": 80, "chain": ["parse_input"], "caller": "dispatch"},
            ],
        ),
        (
            "src/parse.c",
            [{"name": "parse_input", "line_start": 5, "line_end": 40}],
            [{"line": 20, "chain": ["validate"], "caller": "parse_input"}],
        ),
        (
            "lib/validate.c",
            [{"name": "validate", "line_start": 1, "line_end": 30}],
            [],
        ),
    )


# ── seam extraction ─────────────────────────────────────────────────

class TestExtractCrossFileSeams:
    def test_basic_cross_file(self):
        cl = _simple_checklist()
        seams = _extract_cross_file_seams(cl)
        assert seams == {
            ("src/main.c:handle_request", "src/parse.c:parse_input"),
        }

    def test_same_file_excluded(self):
        cl = _checklist(
            (
                "src/main.c",
                [
                    {"name": "foo", "line_start": 1, "line_end": 10},
                    {"name": "bar", "line_start": 15, "line_end": 30},
                ],
                [{"line": 5, "chain": ["bar"], "caller": "foo"}],
            ),
        )
        seams = _extract_cross_file_seams(cl)
        assert seams == set()

    def test_external_excluded(self):
        cl = _checklist(
            (
                "src/main.c",
                [{"name": "foo", "line_start": 1, "line_end": 10}],
                [{"line": 5, "chain": ["strlen"], "caller": "foo"}],
            ),
        )
        seams = _extract_cross_file_seams(cl)
        assert seams == set()

    def test_multiple_seams(self):
        cl = _multi_seam_checklist()
        seams = _extract_cross_file_seams(cl)
        expected = {
            ("src/main.c:handle_request", "src/parse.c:parse_input"),
            ("src/main.c:dispatch", "src/parse.c:parse_input"),
            ("src/main.c:handle_request", "lib/validate.c:validate"),
            ("src/parse.c:parse_input", "lib/validate.c:validate"),
        }
        assert seams == expected


# ── func index ──────────────────────────────────────────────────────

class TestBuildFuncIndex:
    def test_basic(self):
        cl = _simple_checklist()
        idx = _build_func_index(cl)
        assert "src/main.c:handle_request" in idx
        assert "src/parse.c:parse_input" in idx
        assert idx["src/parse.c:parse_input"]["line_start"] == 5


class TestBuildDefinedFuncs:
    def test_false_extraction_filtered(self):
        """Items without a signature are dropped when the same name has
        a real definition (with signature) in another file."""
        from core.audit.discovery import _build_defined_funcs

        cl = _checklist(
            (
                "src/caller.c",
                [{"name": "target_fn", "line_start": 50, "line_end": 70,
                  "signature": None}],
                [],
            ),
            (
                "src/real.c",
                [{"name": "target_fn", "line_start": 1, "line_end": 20,
                  "signature": "int target_fn(char *buf)"}],
                [],
            ),
        )
        defined = _build_defined_funcs(cl)
        assert defined["target_fn"] == {"src/real.c"}

    def test_no_signature_unique_name_kept(self):
        """Items without a signature are kept when the name is unique."""
        from core.audit.discovery import _build_defined_funcs

        cl = _checklist(
            (
                "src/main.c",
                [{"name": "unique_fn", "line_start": 1, "line_end": 20,
                  "signature": None}],
                [],
            ),
        )
        defined = _build_defined_funcs(cl)
        assert defined["unique_fn"] == {"src/main.c"}

    def test_all_nosig_duplicates_kept(self):
        """When ALL instances of a name lack a signature, all are kept."""
        from core.audit.discovery import _build_defined_funcs

        cl = _checklist(
            (
                "src/a.c",
                [{"name": "common", "line_start": 1, "line_end": 20,
                  "signature": None}],
                [],
            ),
            (
                "src/b.c",
                [{"name": "common", "line_start": 1, "line_end": 20,
                  "signature": None}],
                [],
            ),
        )
        defined = _build_defined_funcs(cl)
        assert defined["common"] == {"src/a.c", "src/b.c"}


# ── seam scoring ────────────────────────────────────────────────────

class TestScoreSeam:
    def test_sink_score(self):
        from collections import Counter
        score, reason = _score_seam(
            "src/main.c:handle_request",
            "src/parse.c:parse_input",
            sinks={"src/parse.c:parse_input"},
            entry_reachable=set(),
            weakness_fids=set(),
            fan_in=Counter(),
        )
        assert score >= 3
        assert "sink/entry-reachable" in reason

    def test_weakness_score(self):
        from collections import Counter
        score, _ = _score_seam(
            "src/main.c:handle_request",
            "src/parse.c:parse_input",
            sinks=set(),
            entry_reachable=set(),
            weakness_fids={"src/parse.c:parse_input"},
            fan_in=Counter(),
        )
        assert score >= 2

    def test_fan_in_score(self):
        from collections import Counter
        score, reason = _score_seam(
            "src/main.c:handle_request",
            "src/parse.c:parse_input",
            sinks=set(),
            entry_reachable=set(),
            weakness_fids=set(),
            fan_in=Counter({"src/parse.c:parse_input": 7}),
        )
        assert score >= 1
        assert "fan-in" in reason

    def test_cross_directory_score(self):
        from collections import Counter
        score, reason = _score_seam(
            "src/main.c:handle_request",
            "lib/validate.c:validate",
            sinks=set(),
            entry_reachable=set(),
            weakness_fids=set(),
            fan_in=Counter(),
        )
        assert score >= 1
        assert "cross-directory" in reason

    def test_input_handler_name(self):
        from collections import Counter
        score, reason = _score_seam(
            "src/main.c:caller",
            "src/net.c:parse_request_buffer",
            sinks=set(),
            entry_reachable=set(),
            weakness_fids=set(),
            fan_in=Counter(),
        )
        assert score >= 2
        assert "input-handler-name" in reason

    def test_additive_scoring(self):
        from collections import Counter
        score, _ = _score_seam(
            "src/main.c:caller",
            "lib/parse.c:recv_packet_data",
            sinks={"lib/parse.c:recv_packet_data"},
            entry_reachable=set(),
            weakness_fids={"lib/parse.c:recv_packet_data"},
            fan_in=Counter({"lib/parse.c:recv_packet_data": 10}),
        )
        # sink(3) + weakness(2) + fan-in(1) + cross-dir(1) + input-name(2) = 9
        assert score >= 9


# ── parse findings ──────────────────────────────────────────────────

class TestParseFindings:
    def _bundle(self) -> SeamBundle:
        return SeamBundle(
            caller_fid="src/main.c:handle_request",
            callee_fid="src/parse.c:parse_input",
            caller_source="void handle_request() {}",
            callee_source="int parse_input() {}",
            call_site_snippet="parse_input(buf);",
            annotation="",
            priority_score=5.0,
            priority_reason="test",
        )

    def test_valid_json(self):
        raw = json.dumps({
            "findings": [{
                "guard_type": "bounds",
                "assumed_property": "length <= 256",
                "mechanism": "buffer overflow via unbounded copy",
                "cwe_class": "CWE-120",
                "standalone": False,
            }]
        })
        result = _parse_findings(raw, self._bundle())
        assert len(result.weaknesses) == 1
        w = result.weaknesses[0]
        assert w["guard_type"] == "bounds"
        assert w["property"] == "length <= 256"
        assert w["source"] == "contract_perspective"
        assert w["guarded_by"] == ["src/main.c:handle_request"]

    def test_standalone_finding(self):
        raw = json.dumps({
            "findings": [{
                "guard_type": "validation",
                "assumed_property": "input is validated",
                "mechanism": "missing validation",
                "cwe_class": "CWE-20",
                "standalone": True,
            }]
        })
        result = _parse_findings(raw, self._bundle())
        assert len(result.weaknesses) == 1
        assert result.weaknesses[0]["guarded_by"] == []

    def test_empty_findings(self):
        raw = json.dumps({"findings": []})
        result = _parse_findings(raw, self._bundle())
        assert result.weaknesses == []
        assert result.hypotheses == []

    def test_invalid_json(self):
        result = _parse_findings("not json", self._bundle())
        assert result.weaknesses == []

    def test_markdown_fenced_json(self):
        raw = '```json\n{"findings": [{"guard_type": "bounds", "assumed_property": "x", "mechanism": "y", "cwe_class": null, "standalone": false}]}\n```'
        result = _parse_findings(raw, self._bundle())
        assert len(result.weaknesses) == 1

    def test_fenced_json_with_preamble(self):
        raw = (
            "Here is the analysis:\n"
            "```json\n"
            '{"findings": [{"guard_type": "bounds", '
            '"assumed_property": "x", "mechanism": "y", '
            '"cwe_class": null, "standalone": false}]}\n'
            "```\n"
            "This is critical."
        )
        result = _parse_findings(raw, self._bundle())
        assert len(result.weaknesses) == 1

    def test_fenced_json_no_trailing_newline(self):
        raw = (
            '```json\n'
            '{"findings": [{"guard_type": "bounds", '
            '"assumed_property": "x", "mechanism": "y", '
            '"cwe_class": null, "standalone": false}]}```'
        )
        result = _parse_findings(raw, self._bundle())
        assert len(result.weaknesses) == 1

    def test_hypothesis_generation(self):
        raw = json.dumps({
            "findings": [{
                "guard_type": "null_safety",
                "assumed_property": "return value is non-null",
                "mechanism": "null dereference on error path",
                "cwe_class": "CWE-476",
                "standalone": False,
            }]
        })
        result = _parse_findings(raw, self._bundle())
        assert len(result.hypotheses) == 1
        h = result.hypotheses[0]
        assert h["source"] == "contract_perspective"
        assert "null_safety" in h["text"]
        assert h["caller"] == "src/main.c:handle_request"
        assert h["callee"] == "src/parse.c:parse_input"


# ── build_seam_bundles ──────────────────────────────────────────────

class TestBuildSeamBundles:
    def test_basic_bundle_creation(self, tmp_path: Path):
        cl = _simple_checklist()
        src_main = tmp_path / "src" / "main.c"
        src_main.parent.mkdir(parents=True, exist_ok=True)
        src_main.write_text(
            "\n".join(
                [f"// line {i}" for i in range(1, 10)]
                + ["void handle_request(char *buf) {"]
                + [f"    // body line {i}" for i in range(11, 30)]
                + ["    parse_input(buf);"]
                + [f"    // body line {i}" for i in range(31, 60)]
                + ["}"]
            )
        )
        src_parse = tmp_path / "src" / "parse.c"
        src_parse.write_text(
            "\n".join(
                [f"// line {i}" for i in range(1, 5)]
                + ["int parse_input(char *buf) {"]
                + [f"    // body line {i}" for i in range(6, 40)]
                + ["}"]
            )
        )

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert len(bundles) == 1
        b = bundles[0]
        assert b.caller_fid == "src/main.c:handle_request"
        assert b.callee_fid == "src/parse.c:parse_input"
        assert "parse_input" in b.callee_source
        assert b.priority_score >= 0

    def test_max_seams_cap(self, tmp_path: Path):
        # Build a checklist with many seams
        items_a = [
            {"name": f"caller_{i}", "line_start": i * 10, "line_end": i * 10 + 5}
            for i in range(20)
        ]
        calls_a = [
            {"line": i * 10 + 3, "chain": ["target"], "caller": f"caller_{i}"}
            for i in range(20)
        ]
        cl = _checklist(
            ("src/a.c", items_a, calls_a),
            ("src/b.c", [{"name": "target", "line_start": 1, "line_end": 10}], []),
        )

        # Write source files
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "a.c").write_text(
            "\n".join(f"void caller_{i}() {{ target(); }}" for i in range(20))
            + "\n"
        )
        (tmp_path / "src" / "b.c").write_text("void target() {}\n")

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path, max_seams=5,
        )
        assert len(bundles) <= 5

    def test_no_seams_returns_empty(self, tmp_path: Path):
        cl = _checklist(
            ("src/main.c", [{"name": "foo"}], []),
        )
        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert bundles == []

    def test_priority_ordering(self, tmp_path: Path):
        cl = _multi_seam_checklist()

        # Write source files with enough lines to match checklist ranges
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "lib").mkdir(parents=True, exist_ok=True)
        main_lines = [""] * 110
        main_lines[9] = "void handle_request(char *buf) {"
        main_lines[29] = "    parse_input(buf);"
        main_lines[34] = "    validate(buf);"
        main_lines[59] = "}"
        main_lines[69] = "void dispatch(char *buf) {"
        main_lines[79] = "    parse_input(buf);"
        main_lines[99] = "}"
        (tmp_path / "src" / "main.c").write_text("\n".join(main_lines) + "\n")
        parse_lines = [""] * 50
        parse_lines[4] = "int parse_input(char *buf) {"
        parse_lines[19] = "    validate(buf);"
        parse_lines[39] = "}"
        (tmp_path / "src" / "parse.c").write_text("\n".join(parse_lines) + "\n")
        val_lines = [""] * 35
        val_lines[0] = "int validate(char *x) {"
        val_lines[29] = "}"
        (tmp_path / "lib" / "validate.c").write_text("\n".join(val_lines) + "\n")

        bundles = build_seam_bundles(
            cl, None, set(),
            target_path=tmp_path,
            weakness_fids={"src/parse.c:parse_input"},
        )
        assert len(bundles) >= 1
        # parse_input has weakness + fan-in >= 2, should score higher
        fids = [(b.caller_fid, b.callee_fid) for b in bundles]
        parse_seams = [f for f in fids if "parse_input" in f[1]]
        assert len(parse_seams) >= 1


# ── run_contract_discovery ──────────────────────────────────────────

class TestRunContractDiscovery:
    def _bundle(self) -> SeamBundle:
        return SeamBundle(
            caller_fid="src/main.c:handle_request",
            callee_fid="src/parse.c:parse_input",
            caller_source="void handle_request() { parse_input(buf); }",
            callee_source="int parse_input(char *buf) { strcpy(dest, buf); }",
            call_site_snippet="parse_input(buf);",
            annotation="## Contract analysis",
            priority_score=5.0,
            priority_reason="test",
        )

    def test_basic_discovery(self):
        response = json.dumps({
            "findings": [{
                "guard_type": "bounds",
                "assumed_property": "buf fits in dest",
                "mechanism": "unbounded strcpy",
                "cwe_class": "CWE-120",
                "standalone": False,
            }]
        })

        def review_fn(system: str, prompt: str) -> tuple[str, float]:
            return response, 0.01

        results = run_contract_discovery(
            [self._bundle()], review_fn=review_fn, max_cost_usd=1.0,
        )
        assert len(results) == 1
        assert len(results[0].weaknesses) == 1
        assert results[0].cost_usd == 0.01

    def test_cost_cap(self):
        call_count = 0

        def review_fn(system: str, prompt: str) -> tuple[str, float]:
            nonlocal call_count
            call_count += 1
            return '{"findings": []}', 2.0

        bundles = [self._bundle(), self._bundle(), self._bundle()]
        run_contract_discovery(
            bundles, review_fn=review_fn, max_cost_usd=3.0,
        )
        # Should stop after 2 calls (cost 4.0 >= 3.0 after second)
        assert call_count <= 2

    def test_llm_error_skipped(self):
        def review_fn(system: str, prompt: str) -> tuple[str, float]:
            raise RuntimeError("LLM down")

        results = run_contract_discovery(
            [self._bundle()], review_fn=review_fn, max_cost_usd=1.0,
        )
        assert results == []

    def test_budget_exhaustion_breaks(self):
        call_count = 0

        def review_fn(system: str, prompt: str) -> tuple[str, float]:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("budget exceeded")

        bundles = [self._bundle() for _ in range(5)]
        run_contract_discovery(
            bundles, review_fn=review_fn, max_cost_usd=10.0,
        )
        assert call_count == 1


# ── weakness record compatibility ───────────────────────────────────

class TestWeaknessRecordCompatibility:
    def test_discovery_weakness_creates_valid_record(self):
        try:
            from core.audit.composition import WeaknessRecord
        except ImportError:
            import pytest
            pytest.skip("composition module not available on this branch")

        weakness = {
            "property": "length <= 256",
            "guard_type": "bounds",
            "mechanism": "CWE-120 buffer overflow",
            "cwe_class": "CWE-120",
            "source": "contract_perspective",
            "guarded_by": ["src/main.c:handle_request"],
        }
        record = WeaknessRecord(
            function="parse_input",
            file="src/parse.c",
            guard_type=weakness["guard_type"],
            assumed_property=weakness["property"],
            mechanism=weakness["mechanism"],
            guarded_by=tuple(weakness["guarded_by"]),
            cwe_class=weakness["cwe_class"],
            source=weakness["source"],
        )
        assert record.guard_type == "bounds"
        assert record.source == "contract_perspective"
        assert record.fid == "src/parse.c:parse_input"


# ── journal round-trip ──────────────────────────────────────────────

class TestJournalRoundTrip:
    def test_write_and_read_back(self, tmp_path: Path):
        weaknesses = [{
            "property": "length <= 256",
            "guard_type": "bounds",
            "mechanism": "unbounded copy",
            "cwe_class": "CWE-120",
            "source": "contract_perspective",
            "guarded_by": [],
        }]
        write_discovery_weaknesses(
            tmp_path,
            "src/parse.c:parse_input",
            weaknesses,
            run_id="test-run",
        )

        from core.coverage.journal import load_entries
        entries = load_entries(tmp_path)
        assert len(entries) >= 1
        entry = entries[-1]
        assert entry.file == "src/parse.c"
        assert entry.function == "parse_input"
        assert entry.verdict == "weakness"
        assert entry.weaknesses is not None
        assert len(entry.weaknesses) == 1
        assert entry.weaknesses[0]["guard_type"] == "bounds"

    def test_composition_reads_discovery_weaknesses(self, tmp_path: Path):
        try:
            from core.audit.composition import build_weakness_inventory
        except ImportError:
            import pytest
            pytest.skip("composition module not available on this branch")

        weaknesses = [{
            "property": "return value is non-null",
            "guard_type": "null_safety",
            "mechanism": "null dereference",
            "cwe_class": "CWE-476",
            "source": "contract_perspective",
            "guarded_by": [],
        }]
        write_discovery_weaknesses(
            tmp_path,
            "src/parse.c:parse_input",
            weaknesses,
            run_id="test-run",
        )

        inventory = build_weakness_inventory(tmp_path)
        assert len(inventory) == 1
        w = inventory[0]
        assert w.guard_type == "null_safety"
        assert w.source == "contract_perspective"
        assert w.function == "parse_input"
        assert w.file == "src/parse.c"

    def test_empty_weaknesses_no_write(self, tmp_path: Path):
        write_discovery_weaknesses(
            tmp_path,
            "src/parse.c:parse_input",
            [],
            run_id="test-run",
        )
        journal_files = list(tmp_path.glob("review-journal*"))
        assert journal_files == []


# ── callee body-size filter ────────────────────────────────────────

class TestCalleeSignatureRequired:
    def test_callee_without_signature_excluded(self, tmp_path: Path):
        """Callees lacking a parsed signature are excluded — they are
        likely false extractions (macro calls mistaken for definitions)."""
        cl = _checklist(
            (
                "src/main.c",
                [{"name": "caller", "line_start": 1, "line_end": 30}],
                [{"line": 15, "chain": ["macro_fn"], "caller": "caller"}],
            ),
            (
                "src/util.c",
                [{"name": "macro_fn", "line_start": 1, "line_end": 20,
                  "signature": None}],
                [],
            ),
        )
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "main.c").write_text(
            "\n".join(f"line {i}" for i in range(35)),
        )
        (tmp_path / "src" / "util.c").write_text(
            "\n".join(f"line {i}" for i in range(25)),
        )

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert bundles == []


class TestCalleeBodySizeFilter:
    def test_tiny_callee_excluded(self, tmp_path: Path):
        """Callees with < MIN_CALLEE_LINES body are excluded."""
        cl = _checklist(
            (
                "src/main.c",
                [{"name": "caller", "line_start": 1, "line_end": 30}],
                [{"line": 15, "chain": ["tiny"], "caller": "caller"}],
            ),
            (
                "src/util.c",
                [{"name": "tiny", "line_start": 1, "line_end": 3}],
                [],
            ),
        )
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "main.c").write_text(
            "\n".join(f"line {i}" for i in range(35)),
        )
        (tmp_path / "src" / "util.c").write_text("int tiny() { return 0; }\n")

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert bundles == []

    def test_adequate_callee_included(self, tmp_path: Path):
        """Callees at or above MIN_CALLEE_LINES are included."""
        from core.audit.discovery import MIN_CALLEE_LINES

        cl = _checklist(
            (
                "src/main.c",
                [{"name": "caller", "line_start": 1, "line_end": 30}],
                [{"line": 15, "chain": ["big"], "caller": "caller"}],
            ),
            (
                "src/big.c",
                [{"name": "big", "line_start": 1,
                  "line_end": 1 + MIN_CALLEE_LINES}],
                [],
            ),
        )
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "main.c").write_text(
            "\n".join(f"line {i}" for i in range(35)),
        )
        (tmp_path / "src" / "big.c").write_text(
            "\n".join(f"line {i}" for i in range(MIN_CALLEE_LINES + 5)),
        )

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert len(bundles) == 1


# ── two-pass callee diversity ──────────────────────────────────────

class TestTwoPassDiversity:
    def test_one_caller_per_callee_first(self, tmp_path: Path):
        """First pass picks one caller per unique callee."""
        # 3 callers in a.c all call the same callee in b.c
        # plus 1 caller calling a different callee in c.c
        cl = _checklist(
            (
                "src/a.c",
                [
                    {"name": "c1", "line_start": 1, "line_end": 20},
                    {"name": "c2", "line_start": 25, "line_end": 44},
                    {"name": "c3", "line_start": 50, "line_end": 69},
                ],
                [
                    {"line": 10, "chain": ["target"], "caller": "c1"},
                    {"line": 35, "chain": ["target"], "caller": "c2"},
                    {"line": 60, "chain": ["target"], "caller": "c3"},
                    {"line": 12, "chain": ["other_fn"], "caller": "c1"},
                ],
            ),
            (
                "src/b.c",
                [{"name": "target", "line_start": 1, "line_end": 20}],
                [],
            ),
            (
                "src/c.c",
                [{"name": "other_fn", "line_start": 1, "line_end": 20}],
                [],
            ),
        )
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "a.c").write_text(
            "\n".join(f"line {i}" for i in range(75)),
        )
        (tmp_path / "src" / "b.c").write_text(
            "\n".join(f"line {i}" for i in range(25)),
        )
        (tmp_path / "src" / "c.c").write_text(
            "\n".join(f"line {i}" for i in range(25)),
        )

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path, max_seams=2,
        )
        callee_fids = [b.callee_fid for b in bundles]
        # With max_seams=2 and first-pass diversity, we should get
        # one bundle for each unique callee (target + other_fn)
        assert len(set(callee_fids)) == 2

    def test_second_pass_fills_duplicates(self, tmp_path: Path):
        """Second pass fills remaining slots with duplicate callees."""
        cl = _checklist(
            (
                "src/a.c",
                [
                    {"name": "c1", "line_start": 1, "line_end": 20},
                    {"name": "c2", "line_start": 25, "line_end": 44},
                ],
                [
                    {"line": 10, "chain": ["target"], "caller": "c1"},
                    {"line": 35, "chain": ["target"], "caller": "c2"},
                ],
            ),
            (
                "src/b.c",
                [{"name": "target", "line_start": 1, "line_end": 20}],
                [],
            ),
        )
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "a.c").write_text(
            "\n".join(f"line {i}" for i in range(50)),
        )
        (tmp_path / "src" / "b.c").write_text(
            "\n".join(f"line {i}" for i in range(25)),
        )

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path, max_seams=10,
        )
        # First pass picks 1 (one per callee), second pass picks 1 more
        assert len(bundles) == 2
        assert all(b.callee_fid == "src/b.c:target" for b in bundles)


# ── call-site snippet ──────────────────────────────────────────────

class TestCallSiteSnippet:
    def test_word_boundary_avoids_substring_match(self, tmp_path: Path):
        src = tmp_path / "a.c"
        # Place fread far from read so context window doesn't overlap
        lines = (
            ["void caller() {"]
            + [f"    stmt_{i}();" for i in range(10)]
            + ["    fread(buf, 1, sz, fp);"]
            + [f"    stmt_{i}();" for i in range(10, 20)]
            + ["    read(fd, buf, sz);"]
            + ["}"]
        )
        src.write_text("\n".join(lines) + "\n")
        snippet = _extract_call_site_snippet(
            src, "read", 1, len(lines),
        )
        assert "read(fd" in snippet
        assert "fread" not in snippet


# ── orchestrator hook integration ──────────────────────────────────

class TestOrchestratorHookImport:
    def test_discovery_imports_resolve(self):
        """The orchestrator hook imports the right symbols."""
        from core.audit.discovery import (  # noqa: F401
            build_seam_bundles,
            run_contract_discovery,
            write_discovery_weaknesses,
        )

    def test_config_fields_exist(self):
        from core.audit.orchestrator import OrchestratorConfig
        cfg = OrchestratorConfig.__dataclass_fields__
        assert "open_discovery" in cfg
        assert "discovery_budget_fraction" in cfg
        assert cfg["open_discovery"].default is False
        assert cfg["discovery_budget_fraction"].default == 0.20

    def test_pipeline_opts_fields_exist(self):
        from core.audit.pipeline import AuditPipelineOpts
        fields = AuditPipelineOpts.__dataclass_fields__
        assert "open_discovery" in fields
        assert "discovery_budget_fraction" in fields


# ── CLI arg parsing ────────────────────────────────────────────────

class TestCLIArgParsing:
    def test_open_discovery_flag(self):
        import subprocess
        result = subprocess.run(
            ["python3", "libexec/raptor-audit", "run", "--help"],
            capture_output=True, text=True, cwd=_REPO_ROOT,
        )
        assert "--open-discovery" in result.stdout

    def test_discovery_budget_flag(self):
        import subprocess
        result = subprocess.run(
            ["python3", "libexec/raptor-audit", "run", "--help"],
            capture_output=True, text=True, cwd=_REPO_ROOT,
        )
        assert "--discovery-budget" in result.stdout


# ── end-to-end dry-run via CLI ─────────────────────────────────────

class TestDryRunEndToEnd:
    def test_dry_run_with_synthetic_target(self, tmp_path: Path):
        """Full dry-run pipeline: checklist + source → bundle listing."""
        # Build a synthetic target codebase
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "lib").mkdir(parents=True)

        # Main module — handles network requests
        (target / "src" / "server.c").write_text("\n".join([
            "#include <stdio.h>",
            "#include <string.h>",
            "",
            "extern int parse_packet(char *buf, int len);",
            "extern void log_event(const char *msg);",
            "",
            "void handle_connection(int fd) {",
            "    char buf[4096];",
            "    int n = read(fd, buf, sizeof(buf));",
            "    if (n <= 0) return;",
            "    int result = parse_packet(buf, n);",
            "    if (result < 0) {",
            '        log_event("parse failed");',
            "        return;",
            "    }",
            "    // process the parsed data",
            "    char response[256];",
            "    snprintf(response, sizeof(response),",
            '             "OK: %d", result);',
            "    write(fd, response, strlen(response));",
            "}",
        ]) + "\n")

        # Parser module
        (target / "src" / "parser.c").write_text("\n".join([
            "#include <string.h>",
            "#include <stdlib.h>",
            "",
            "int parse_packet(char *buf, int len) {",
            "    if (len < 4) return -1;",
            "    int msg_type = buf[0];",
            "    int msg_len = *(int *)(buf + 1);",
            "    if (msg_len > len) return -1;",
            "    char *payload = malloc(msg_len);",
            "    if (!payload) return -1;",
            "    memcpy(payload, buf + 4, msg_len - 4);",
            "    // process payload",
            "    int result = atoi(payload);",
            "    free(payload);",
            "    return result;",
            "}",
        ]) + "\n")

        # Logger module
        (target / "lib" / "logger.c").write_text("\n".join([
            "#include <stdio.h>",
            "#include <time.h>",
            "",
            "void log_event(const char *msg) {",
            "    time_t now = time(NULL);",
            "    struct tm *t = localtime(&now);",
            "    char ts[64];",
            '    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);',
            '    fprintf(stderr, "[%s] %s\\n", ts, msg);',
            "}",
        ]) + "\n")

        # Build a matching checklist
        checklist = {
            "target_path": str(target),
            "files": [
                {
                    "path": "src/server.c",
                    "items": [
                        {
                            "name": "handle_connection",
                            "line_start": 7,
                            "line_end": 21,
                            "signature": "void handle_connection(int fd)",
                        },
                    ],
                    "call_graph": {
                        "calls": [
                            {
                                "line": 11,
                                "chain": ["parse_packet"],
                                "caller": "handle_connection",
                            },
                            {
                                "line": 13,
                                "chain": ["log_event"],
                                "caller": "handle_connection",
                            },
                        ],
                    },
                },
                {
                    "path": "src/parser.c",
                    "items": [
                        {
                            "name": "parse_packet",
                            "line_start": 4,
                            "line_end": 16,
                            "signature": "int parse_packet(char *buf, int len)",
                        },
                    ],
                    "call_graph": {"calls": []},
                },
                {
                    "path": "lib/logger.c",
                    "items": [
                        {
                            "name": "log_event",
                            "line_start": 4,
                            "line_end": 10,
                            "signature": "void log_event(const char *msg)",
                        },
                    ],
                    "call_graph": {"calls": []},
                },
            ],
        }

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "checklist.json").write_text(json.dumps(checklist))

        import subprocess
        result = subprocess.run(
            [
                "python3", "-m", "core.audit.discovery",
                "--run-dir", str(run_dir),
                "--target", str(target),
                "--dry-run",
            ],
            capture_output=True, text=True,
            cwd=_REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr
        assert "Seam bundles:" in result.stdout
        # Should find at least the server→parser seam
        assert "parse_packet" in result.stdout

    def test_dry_run_no_seams(self, tmp_path: Path):
        """Dry-run with a single-file project produces no bundles."""
        target = tmp_path / "target" / "src"
        target.mkdir(parents=True)
        (target / "main.c").write_text(
            "int main() { return 0; }\n",
        )
        checklist = {
            "files": [{
                "path": "src/main.c",
                "items": [{"name": "main", "line_start": 1, "line_end": 1}],
                "call_graph": {"calls": []},
            }],
        }
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "checklist.json").write_text(json.dumps(checklist))

        import subprocess
        result = subprocess.run(
            [
                "python3", "-m", "core.audit.discovery",
                "--run-dir", str(run_dir),
                "--target", str(tmp_path / "target"),
                "--dry-run",
            ],
            capture_output=True, text=True,
            cwd=_REPO_ROOT,
        )
        assert result.returncode == 0
        assert "Seam bundles: 0" in result.stdout


# ── full pipeline mock ─────────────────────────────────────────────

class TestFullPipelineMock:
    def test_bundles_to_journal(self, tmp_path: Path):
        """Full pipeline: build bundles → mock LLM → journal write."""
        (tmp_path / "src").mkdir(parents=True)
        (tmp_path / "src" / "caller.c").write_text(
            "\n".join(f"line {i}" for i in range(65)),
        )
        (tmp_path / "src" / "callee.c").write_text(
            "\n".join(f"line {i}" for i in range(45)),
        )

        cl = _checklist(
            (
                "src/caller.c",
                [{"name": "do_request", "line_start": 1, "line_end": 30}],
                [{"line": 15, "chain": ["process_data"],
                  "caller": "do_request"}],
            ),
            (
                "src/callee.c",
                [{"name": "process_data", "line_start": 1, "line_end": 25}],
                [],
            ),
        )

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert len(bundles) == 1

        response = json.dumps({
            "findings": [{
                "guard_type": "validation",
                "assumed_property": "input is sanitised",
                "mechanism": "no sanitisation on data parameter",
                "cwe_class": "CWE-20",
                "standalone": True,
            }],
        })

        def review_fn(system: str, prompt: str) -> tuple[str, float]:
            assert "contract" in system.lower() or "contract" in prompt.lower()
            return response, 0.02

        results = run_contract_discovery(
            bundles, review_fn=review_fn, max_cost_usd=1.0,
        )
        assert len(results) == 1
        assert len(results[0].weaknesses) == 1

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        for dr in results:
            callee_fid = dr.seam_or_field.split("->")[-1].strip()
            write_discovery_weaknesses(
                out_dir, callee_fid, dr.weaknesses,
                run_id="integration-test",
            )

        from core.coverage.journal import load_entries
        entries = load_entries(out_dir)
        assert len(entries) == 1
        assert entries[0].verdict == "weakness"
        assert entries[0].function == "process_data"
        assert entries[0].file == "src/callee.c"

    def test_source_unreadable_skipped(self, tmp_path: Path):
        """Bundles with unreadable source files are silently skipped."""
        cl = _checklist(
            (
                "src/caller.c",
                [{"name": "caller", "line_start": 1, "line_end": 30}],
                [{"line": 15, "chain": ["callee"], "caller": "caller"}],
            ),
            (
                "src/callee.c",
                [{"name": "callee", "line_start": 1, "line_end": 20}],
                [],
            ),
        )
        # Don't write the source files — they don't exist

        bundles = build_seam_bundles(
            cl, None, set(), target_path=tmp_path,
        )
        assert bundles == []


# ── state machine discovery ────────────────────────────────────────

def _make_field_census(fields):
    return {"tier": "t0", "telemetry": {}, "fields": fields, "functions": {}}


class TestScoreField:
    def test_state_name_scores_higher(self):
        score_state, _ = _score_field(
            "conn_state", [], [], {"a.c", "b.c"},
        )
        score_generic, _ = _score_field(
            "count", [], [], {"a.c", "b.c"},
        )
        assert score_state > score_generic

    def test_cross_file_rw_bonus(self):
        writes = [{"file": "a.c", "line": 1}]
        reads = [{"file": "b.c", "line": 2}]
        score, reason = _score_field("x", writes, reads, {"a.c", "b.c"})
        assert "cross-file-rw" in reason


class TestBuildStateMachineBundles:
    def test_filters_by_min_files(self, tmp_path):
        (tmp_path / "a.c").write_text(
            "\n".join(f"line {i}" for i in range(30)),
        )
        fc = _make_field_census({
            "single_file_field": {
                "field": "single_file_field",
                "tier": "t0",
                "sites_capped": False,
                "writes": [
                    {"file": "a.c", "line": 5, "function": "f1", "code": "x=1;"},
                    {"file": "a.c", "line": 10, "function": "f2", "code": "x=2;"},
                    {"file": "a.c", "line": 15, "function": "f3", "code": "x=3;"},
                ],
                "reads": [],
            },
        })
        bundles = build_state_machine_bundles(
            fc, target_path=tmp_path,
        )
        assert bundles == []

    def test_cross_file_field_produces_bundle(self, tmp_path):
        for name in ["a.c", "b.c"]:
            (tmp_path / name).write_text(
                "\n".join(f"line {i}" for i in range(30)),
            )
        fc = _make_field_census({
            "state": {
                "field": "state",
                "tier": "t0",
                "sites_capped": False,
                "writes": [
                    {"file": "a.c", "line": 5, "function": "init", "code": "state=0;"},
                    {"file": "a.c", "line": 15, "function": "update", "code": "state=1;"},
                ],
                "reads": [
                    {"file": "b.c", "line": 10, "function": "check", "code": "if(state)"},
                ],
            },
        })
        bundles = build_state_machine_bundles(
            fc, target_path=tmp_path,
        )
        assert len(bundles) == 1
        b = bundles[0]
        assert b.field_name == "state"
        assert len(b.handler_sites) == 3
        writes = [s for s in b.handler_sites if s.access == "write"]
        reads = [s for s in b.handler_sites if s.access == "read"]
        assert len(writes) == 2
        assert len(reads) == 1


class TestParseSmFindings:
    def test_valid_json(self):
        bundle = StateMachineBundle(
            field_name="state",
            handler_sites=[],
            annotation="test",
            priority_score=1.0,
            priority_reason="test",
        )
        raw = json.dumps({"findings": [
            {
                "guard_type": "ordering",
                "assumed_property": "init before use",
                "mechanism": "write without lock",
                "cwe_class": "CWE-362",
                "standalone": True,
            },
        ]})
        result = _parse_sm_findings(raw, bundle)
        assert result.source == "state_machine"
        assert len(result.weaknesses) == 1
        assert result.weaknesses[0]["guard_type"] == "ordering"
        assert len(result.hypotheses) == 1

    def test_empty_findings(self):
        bundle = StateMachineBundle(
            field_name="x",
            handler_sites=[],
            annotation="test",
            priority_score=0.0,
            priority_reason="test",
        )
        result = _parse_sm_findings('{"findings": []}', bundle)
        assert result.weaknesses == []
        assert result.hypotheses == []


class TestRunStateMachineDiscovery:
    def test_mock_llm(self):
        bundle = StateMachineBundle(
            field_name="conn_state",
            handler_sites=[
                HandlerSite(
                    file="net.c", function="connect",
                    line=10, code="conn_state=1;",
                    access="write", context="conn_state=1;",
                ),
                HandlerSite(
                    file="io.c", function="on_data",
                    line=20, code="if(conn_state)",
                    access="read", context="if(conn_state)",
                ),
            ],
            annotation="test annotation",
            priority_score=3.0,
            priority_reason="state-name; cross-file-rw",
        )
        response = json.dumps({"findings": [
            {
                "guard_type": "concurrency",
                "assumed_property": "atomic state transitions",
                "mechanism": "no locking around state write",
                "cwe_class": "CWE-362",
                "standalone": True,
            },
        ]})

        def mock_review(system, prompt):
            return response, 0.01

        results = run_state_machine_discovery(
            [bundle], review_fn=mock_review, max_cost_usd=1.0,
        )
        assert len(results) == 1
        assert len(results[0].weaknesses) == 1
        assert results[0].weaknesses[0]["source"] == "state_machine"
        assert results[0].cost_usd == 0.01

    def test_concurrency_hint_flows_to_prompt(self):
        """Verify that concurrency_hint reaches the generated prompt."""
        bundle = StateMachineBundle(
            field_name="state",
            handler_sites=[
                HandlerSite(
                    file="a.c", function="set_state",
                    line=1, code="state=1;",
                    access="write", context="state=1;",
                ),
                HandlerSite(
                    file="b.c", function="get_state",
                    line=1, code="if(state)",
                    access="read", context="if(state)",
                ),
            ],
            annotation="",
            priority_score=1.0,
            priority_reason="test",
        )
        prompt = _build_sm_prompt(bundle, concurrency_hint=_HINT_SINGLE_THREADED)
        assert "single-threaded" in prompt
        assert "Do NOT report race conditions" in prompt

        prompt_mt = _build_sm_prompt(bundle, concurrency_hint=_HINT_MULTI_THREADED)
        assert "uses threads" in prompt_mt

    def test_hint_passed_through_run(self):
        """Verify run_state_machine_discovery derives the hint from the bool."""
        bundle = StateMachineBundle(
            field_name="flags",
            handler_sites=[
                HandlerSite(
                    file="x.c", function="set_flags",
                    line=1, code="flags=1;",
                    access="write", context="flags=1;",
                ),
                HandlerSite(
                    file="y.c", function="check_flags",
                    line=1, code="if(flags)",
                    access="read", context="if(flags)",
                ),
            ],
            annotation="",
            priority_score=1.0,
            priority_reason="test",
        )
        captured_prompts = []

        def mock_review(system, prompt):
            captured_prompts.append(prompt)
            return '{"findings": []}', 0.001

        run_state_machine_discovery(
            [bundle],
            review_fn=mock_review,
            max_cost_usd=1.0,
            single_threaded=True,
        )
        assert len(captured_prompts) == 1
        assert "single-threaded" in captured_prompts[0]

        captured_prompts.clear()
        run_state_machine_discovery(
            [bundle],
            review_fn=mock_review,
            max_cost_usd=1.0,
            single_threaded=False,
        )
        assert len(captured_prompts) == 1
        assert "uses threads" in captured_prompts[0]


class TestDetectSingleThreaded:
    def test_no_threading_primitives(self, tmp_path):
        src = tmp_path / "main.c"
        src.write_text("int main() { return 0; }\n")
        assert detect_single_threaded(tmp_path) is True

    def test_pthread_detected(self, tmp_path):
        src = tmp_path / "server.c"
        src.write_text("void start() { pthread_create(&t, NULL, fn, NULL); }\n")
        assert detect_single_threaded(tmp_path) is False


class TestCwe362PostFilter:
    def test_cwe362_stripped_when_single_threaded(self):
        bundle = StateMachineBundle(
            field_name="state",
            handler_sites=[
                HandlerSite(
                    file="a.c", function="f", line=1,
                    code="x", access="write", context="x",
                ),
                HandlerSite(
                    file="b.c", function="g", line=1,
                    code="y", access="read", context="y",
                ),
            ],
            annotation="", priority_score=1.0, priority_reason="test",
        )
        raw = json.dumps({"findings": [
            {"guard_type": "ordering", "assumed_property": "p",
             "mechanism": "m", "cwe_class": "CWE-362", "standalone": True},
            {"guard_type": "uninit", "assumed_property": "q",
             "mechanism": "n", "cwe_class": "CWE-908", "standalone": True},
        ]})
        result = _parse_sm_findings(raw, bundle, single_threaded=True)
        assert len(result.weaknesses) == 1
        assert result.weaknesses[0]["cwe_class"] == "CWE-908"

    def test_cwe362_with_title_suffix_stripped(self):
        """Model may emit 'CWE-362: Concurrent Modification...' — prefix match."""
        bundle = StateMachineBundle(
            field_name="state",
            handler_sites=[
                HandlerSite(
                    file="a.c", function="f", line=1,
                    code="x", access="write", context="x",
                ),
                HandlerSite(
                    file="b.c", function="g", line=1,
                    code="y", access="read", context="y",
                ),
            ],
            annotation="", priority_score=1.0, priority_reason="test",
        )
        raw = json.dumps({"findings": [
            {"guard_type": "ordering", "assumed_property": "p",
             "mechanism": "m",
             "cwe_class": "CWE-362: Concurrent Modification of Shared Resource",
             "standalone": True},
        ]})
        result = _parse_sm_findings(raw, bundle, single_threaded=True)
        assert len(result.weaknesses) == 0

    def test_cwe362_kept_when_multi_threaded(self):
        bundle = StateMachineBundle(
            field_name="state",
            handler_sites=[
                HandlerSite(
                    file="a.c", function="f", line=1,
                    code="x", access="write", context="x",
                ),
                HandlerSite(
                    file="b.c", function="g", line=1,
                    code="y", access="read", context="y",
                ),
            ],
            annotation="", priority_score=1.0, priority_reason="test",
        )
        raw = json.dumps({"findings": [
            {"guard_type": "race", "assumed_property": "p",
             "mechanism": "m", "cwe_class": "CWE-362", "standalone": True},
        ]})
        result = _parse_sm_findings(raw, bundle, single_threaded=False)
        assert len(result.weaknesses) == 1
        assert result.weaknesses[0]["cwe_class"] == "CWE-362"
