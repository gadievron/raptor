"""Pins for the verification-rigor and recall fixes.

Each test names the failure mode it prevents; see the audit
improvement analysis for the full derivations.
"""

from __future__ import annotations

from core.audit.gaps import _consume_covered_key
from core.audit.sweep import _match_in_range


class TestMatchInRange:
    def test_line_zero_is_not_in_range(self):
        # coccinelle matches without line info used to count as
        # in-function — confirming hypotheses from anywhere in the file.
        assert _match_in_range({"line": 0}, 10, 20) is False
        assert _match_in_range({}, 10, 20) is False

    def test_real_lines_behave(self):
        assert _match_in_range({"line": 15}, 10, 20) is True
        assert _match_in_range({"line": 9}, 10, 20) is False
        assert _match_in_range({"line": 21}, 10, 20) is False


class TestCoveredKeyConsumption:
    def test_covered_key_suppresses_only_first(self):
        # One record used to suppress EVERY same-named overload.
        covered = {"f.cpp:handle"}
        consumed: dict = {}
        assert _consume_covered_key(covered, consumed, "f.cpp:handle") is True
        assert _consume_covered_key(covered, consumed, "f.cpp:handle") is False
        assert _consume_covered_key(covered, consumed, "f.cpp:handle") is False

    def test_uncovered_key_never_suppresses(self):
        assert _consume_covered_key(set(), {}, "f.c:g") is False


class TestUafReassignmentRegex:
    def _freed_after(self, line):
        import re
        var = "ptr"
        return re.search(
            rf'\b{re.escape(var)}\s*(?<![!<>+\-*/&|^%=])=(?!=)\s*',
            line,
        )

    def test_comparisons_do_not_clear(self):
        # `ptr != NULL` used to clear the freed set (lookbehind saw '!').
        assert self._freed_after("if (ptr != NULL) {") is None
        assert self._freed_after("if (ptr <= end)") is None
        assert self._freed_after("count += 1; use(ptr);") is None
        assert self._freed_after("if (ptr == NULL)") is None

    def test_reassignment_clears(self):
        assert self._freed_after("ptr = malloc(10);") is not None
        assert self._freed_after("  ptr = other;") is not None


class TestMacroSpans:
    def test_multiline_define_spans_continuations(self):
        from core.inventory.extractors import _extract_macros_regex
        src = (
            "#define ONE 1\n"
            "#define BIG(x) do { \\\n"
            "    use(x); \\\n"
            "    check(x); \\\n"
            "} while (0)\n"
            "int f(void) { return 0; }\n"
        )
        macros = {m.name: m for m in _extract_macros_regex(src)}
        assert macros["ONE"].line_start == 1
        assert macros["ONE"].line_end == 1
        assert macros["BIG"].line_start == 2
        assert macros["BIG"].line_end == 5


class TestIncludeKinds:
    def _checklist(self):
        return {
            "files": [{
                "path": "m.py",
                "items": [
                    {"name": "f", "kind": "function", "line_start": 1,
                     "line_end": 2},
                    {"name": "m.py::top_level", "kind": "top_level",
                     "line_start": 4, "line_end": 9},
                ],
            }],
        }

    def test_default_includes_top_level(self):
        # Flipped default: module-level code is a reviewable unit
        # unless the operator opts out.
        from core.audit.gaps import compute_gaps
        gaps = compute_gaps(self._checklist(), [])
        assert sorted(g["name"] for g in gaps) == [
            "f", "m.py::top_level",
        ]

    def test_none_restores_functions_only(self):
        from core.audit.gaps import compute_gaps
        gaps = compute_gaps(self._checklist(), [],
                            include_kinds={"none"})
        assert [g["name"] for g in gaps] == ["f"]

    def test_opt_in_includes_top_level(self):
        from core.audit.gaps import compute_gaps
        gaps = compute_gaps(self._checklist(), [],
                            include_kinds={"top_level"})
        assert sorted(g["name"] for g in gaps) == [
            "f", "m.py::top_level",
        ]


class TestScopeSeparator:
    def test_scope_does_not_prefix_match_sibling(self):
        from core.audit.gaps import compute_gaps
        checklist = {
            "files": [
                {"path": "ipc/a.c", "items": [
                    {"name": "fa", "kind": "function", "line_start": 1,
                     "line_end": 2}]},
                {"path": "ipcz/b.c", "items": [
                    {"name": "fb", "kind": "function", "line_start": 1,
                     "line_end": 2}]},
            ],
        }
        gaps = compute_gaps(checklist, [], scope="ipc")
        assert [g["file"] for g in gaps] == ["ipc/a.c"]


class TestRootAnchoredBuildNames:
    """First-party dirs named env/bin/out survive when nested;
    build/target stay pruned anywhere (Gradle/Maven/Rust norm)."""

    def test_nested_env_and_bin_included(self, tmp_path):
        from core.inventory.builder import build_inventory
        (tmp_path / "src" / "env").mkdir(parents=True)
        (tmp_path / "src" / "env" / "config.c").write_text(
            "int env_get(void){return 1;}\n")
        (tmp_path / "src" / "bin").mkdir()
        (tmp_path / "src" / "bin" / "tool.c").write_text(
            "int tool(void){return 2;}\n")
        (tmp_path / "env").mkdir()
        (tmp_path / "env" / "root.c").write_text(
            "int r(void){return 3;}\n")
        (tmp_path / "module" / "build").mkdir(parents=True)
        (tmp_path / "module" / "build" / "gen.c").write_text(
            "int g(void){return 4;}\n")
        inv = build_inventory(
            str(tmp_path), output_dir=str(tmp_path / ".inv"),
            parallel=False,
        )
        files = {f["path"] for f in inv["files"]}
        assert "src/env/config.c" in files
        assert "src/bin/tool.c" in files
        assert "env/root.c" not in files          # root-anchored prune
        assert "module/build/gen.c" not in files  # build/ any-depth
