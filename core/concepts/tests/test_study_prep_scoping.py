"""Tests for raptor-study-prep scoping, merge precedence, doc-comment
extraction, and subprocess hygiene."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

RAPTOR_DIR = Path(__file__).resolve().parents[3]
_PREP_PATH = RAPTOR_DIR / "libexec" / "raptor-study-prep"


def _load_prep() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_prep_scoping", str(_PREP_PATH))
    spec = importlib.util.spec_from_file_location(
        "raptor_study_prep_scoping", str(_PREP_PATH), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prep = _load_prep()


# ------------------------------------------------------------------
# Doc-comment extraction
# ------------------------------------------------------------------


def _reference_doc_comment(source: str, pos: int) -> str:
    """Straightforward (O(prefix)-per-call) reference implementation
    used to pin the extraction contract."""
    before = source[:pos].rstrip()
    lines = before.split("\n")
    doc_lines: list[str] = []
    in_block = False
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.endswith("*/"):
            in_block = True
            doc_lines.append(stripped)
            if stripped.startswith("/*"):
                in_block = False
            continue
        if in_block:
            doc_lines.append(stripped)
            if stripped.startswith("/*"):
                in_block = False
            continue
        if stripped.startswith(("//", "*", "/*")):
            doc_lines.append(stripped)
        elif stripped == "":
            if doc_lines:
                break
        else:
            break
    if not doc_lines:
        return ""
    doc_lines.reverse()
    return "\n".join(doc_lines)[:1000]


class TestExtractDocComment:
    def test_block_comment(self) -> None:
        src = "/* doc line one\n * two */\nstruct foo {\n};\n"
        pos = src.index("struct")
        assert prep._extract_doc_comment(src, pos) == \
            "/* doc line one\n* two */"

    def test_line_comments(self) -> None:
        src = "// a\n// b\nint foo(void) { return 0; }\n"
        pos = src.index("int")
        assert prep._extract_doc_comment(src, pos) == "// a\n// b"

    def test_blank_line_between_doc_and_definition(self) -> None:
        src = "// a\n\nstruct foo {\n};\n"
        pos = src.index("struct")
        assert prep._extract_doc_comment(src, pos) == "// a"

    def test_code_line_stops_scan(self) -> None:
        src = "// doc\nint x;\nstruct foo {\n};\n"
        pos = src.index("struct")
        assert prep._extract_doc_comment(src, pos) == ""

    def test_blank_line_terminates_collected_doc(self) -> None:
        src = "// far\n\n// near\nstruct foo {\n};\n"
        pos = src.index("struct")
        assert prep._extract_doc_comment(src, pos) == "// near"

    def test_position_zero(self) -> None:
        src = "struct foo {\n};\n"
        assert prep._extract_doc_comment(src, 0) == ""

    @pytest.mark.parametrize("src", [
        "/* one */\nstruct foo {",
        "/*\n * multi\n * line\n */\nstruct foo {",
        "// a\n// b\n// c\nstruct foo {",
        "\n\n\nstruct foo {",
        "int x;\n\n/* doc */\nstruct foo {",
        "/* first */\nint y;\n// second\nstruct foo {",
        "   \t \n// ws above\nstruct foo {",
        "* stray continuation\nstruct foo {",
        "code(); /* trailing */\nstruct foo {",
    ])
    def test_matches_reference_implementation(self, src: str) -> None:
        pos = src.index("struct foo")
        assert prep._extract_doc_comment(src, pos) == \
            _reference_doc_comment(src, pos)


# ------------------------------------------------------------------
# Definition-over-declaration precedence
# ------------------------------------------------------------------


class TestDefinitionPrecedence:
    def test_later_declaration_keeps_call_edges(self) -> None:
        functions = [
            {"name": "foo", "body": "{ helper(); }"},
            {"name": "helper", "body": "{ return 0; }"},
            {"name": "foo", "body": ""},  # extern re-declaration
        ]
        graph = prep._build_call_graph(functions)
        assert graph["foo"] == ["helper"]

    def test_definition_after_declaration_wins(self) -> None:
        functions = [
            {"name": "foo", "body": ""},
            {"name": "helper", "body": "{ return 0; }"},
            {"name": "foo", "body": "{ helper(); }"},
        ]
        graph = prep._build_call_graph(functions)
        assert graph["foo"] == ["helper"]

    def test_pure_declaration_has_no_edges(self) -> None:
        functions = [
            {"name": "foo", "body": ""},
            {"name": "helper", "body": "{ return 0; }"},
        ]
        graph = prep._build_call_graph(functions)
        assert graph["foo"] == []

    def test_usage_classification_survives_later_declaration(self) -> None:
        fn_def = {
            "name": "foo_set",
            "signature": "void foo_set(struct foo *f)",
            "param_types": ["struct foo"],
            "return_type": "void",
            "body": "{ f->x = 1; }",
        }
        fn_decl = dict(fn_def, body="")
        idx = prep._build_type_reference_index([], [fn_def, fn_decl])
        assert ("foo_set", "writer") in idx["struct foo"]


# ------------------------------------------------------------------
# Pass-2 concept filter case handling
# ------------------------------------------------------------------


class TestConceptFilterCase:
    def _write(self, tmp_path: Path, content: str) -> Path:
        f = tmp_path / "src.c"
        f.write_text(content, encoding="utf-8")
        return f

    def test_case_mismatched_term_still_matches(self, tmp_path) -> None:
        f = self._write(tmp_path, "struct FooCtx {\n    int a;\n};\n")
        structs, _fns, _protos, _incs = prep._scan_file_result(
            f, tmp_path, False, None,
            concept_filter=frozenset({"fooctx"}),
        )
        assert [s["name"] for s in structs] == ["FooCtx"]

    def test_exact_case_still_matches(self, tmp_path) -> None:
        f = self._write(tmp_path, "struct fooctx {\n    int a;\n};\n")
        structs, _fns, _protos, _incs = prep._scan_file_result(
            f, tmp_path, False, None,
            concept_filter=frozenset({"fooctx"}),
        )
        assert [s["name"] for s in structs] == ["fooctx"]

    def test_non_matching_term_skips_file(self, tmp_path) -> None:
        f = self._write(tmp_path, "struct FooCtx {\n    int a;\n};\n")
        result = prep._scan_file_result(
            f, tmp_path, False, None,
            concept_filter=frozenset({"barctx"}),
        )
        assert result == ([], [], [], {})


# ------------------------------------------------------------------
# Reading-list definition chase: sanitised subprocess environment
# ------------------------------------------------------------------


class TestChaseSubprocessEnv:
    def test_grep_and_find_get_sanitised_env(
        self, tmp_path, monkeypatch,
    ) -> None:
        monkeypatch.setenv("LD_PRELOAD", "/nonexistent/evil.so")
        rl = tmp_path / "reading-list.json"
        rl.write_text(json.dumps({"items": [{
            "question": "What is `scatterlist_map`?",
            "context": "Unresolved type: struct scatterlist_map",
        }]}), encoding="utf-8")
        target = tmp_path / "sub"
        target.mkdir()

        captured: list[dict] = []

        def fake_run(cmd, **kwargs):
            captured.append(kwargs)
            return SimpleNamespace(stdout="")

        monkeypatch.setattr(prep.subprocess, "run", fake_run)
        prep._chase_reading_list_definitions(rl, tmp_path, target)

        assert len(captured) == 2  # one grep, one find
        for kwargs in captured:
            env = kwargs.get("env")
            assert env is not None, "subprocess must get an explicit env"
            assert "LD_PRELOAD" not in env


# ------------------------------------------------------------------
# main(): correlate merge order, include-dir warning, strict flags
# ------------------------------------------------------------------


def _run_prep(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(  # noqa: PLW1510 - callers assert on returncode
        [sys.executable, str(_PREP_PATH)] + args,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _make_correlate_tree(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "alpha.c").write_text(
        "struct alpha_ctx {\n    int a;\n};\n"
        "int alpha_ctx_new(void) { return 0; }\n",
        encoding="utf-8",
    )
    (repo / "beta.c").write_text(
        "int beta_ops_run(void) { return 1; }\n", encoding="utf-8",
    )
    (repo / "gamma.c").write_text(
        "int gamma_ops_run(void) { return 2; }\n", encoding="utf-8",
    )
    (repo / "noise.c").write_text(
        "int unrelated(void) { return 3; }\n", encoding="utf-8",
    )
    return repo


def _item_names(out_dir: Path) -> set[str]:
    data = json.loads(
        (out_dir / "study-list.json").read_text(encoding="utf-8"))
    return {it["name"] for it in data["items"]}


class TestCorrelateMergeOrder:
    def test_correlate_files_survive_pass2_filter(self, tmp_path) -> None:
        """Files defining only correlate targets must be parsed even
        when --identifier is also set."""
        repo = _make_correlate_tree(tmp_path)
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "alpha_ctx",
            "--correlate", "beta_ops+gamma_ops",
        ])
        assert result.returncode == 0, result.stderr
        names = _item_names(out)
        assert "beta_ops_run" in names
        assert "gamma_ops_run" in names
        assert "alpha_ctx" in names

    def test_identifier_only_still_filters(self, tmp_path) -> None:
        repo = _make_correlate_tree(tmp_path)
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "alpha_ctx",
        ])
        assert result.returncode == 0, result.stderr
        names = _item_names(out)
        assert "alpha_ctx" in names
        assert "beta_ops_run" not in names

    def test_correlate_survives_grep_scope(self, tmp_path) -> None:
        """On >500-file trees the grep pre-scope must keep files that
        define correlate targets."""
        repo = _make_correlate_tree(tmp_path)
        for i in range(510):
            (repo / f"filler_{i}.c").write_text(
                f"int filler_{i}(void) {{ return 0; }}\n",
                encoding="utf-8",
            )
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "alpha_ctx",
            "--correlate", "beta_ops+gamma_ops",
        ])
        assert result.returncode == 0, result.stderr
        names = _item_names(out)
        assert "beta_ops_run" in names
        assert "gamma_ops_run" in names


class TestIncludeDirWarning:
    def test_out_of_tree_include_dir_warns(self, tmp_path) -> None:
        repo = _make_correlate_tree(tmp_path)
        ext = tmp_path / "external-headers"
        ext.mkdir()
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "alpha_ctx",
            "--include-dir", str(ext),
        ])
        assert result.returncode == 0, result.stderr
        assert "outside the source root" in result.stderr

    def test_in_tree_include_dir_does_not_warn(self, tmp_path) -> None:
        repo = _make_correlate_tree(tmp_path)
        hdrs = repo / "hdrs"
        hdrs.mkdir()
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "alpha_ctx",
            "--include-dir", str(hdrs),
        ])
        assert result.returncode == 0, result.stderr
        assert "outside the source root" not in result.stderr


class TestStrictArgParsing:
    def test_unknown_flag_is_an_error(self, tmp_path) -> None:
        repo = _make_correlate_tree(tmp_path)
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out),
            "--identifer", "alpha_ctx",  # deliberate misspelling
        ])
        assert result.returncode != 0
        assert "unrecognized arguments" in result.stderr


class TestScopeFromReadingListContainment:
    """reading-list.json is an LLM-authored artifact: seed
    ``source_file`` entries must not escape the source root
    (traversal, absolute path, or symlink) — the same containment
    ``_resolve_include`` enforces for every chased include."""

    def _write_rl(self, dirpath: Path, seeds: list[str]) -> Path:
        rl = dirpath / "reading-list.json"
        rl.write_text(json.dumps(
            {"items": [{"source_file": s} for s in seeds]}))
        return rl

    def test_in_root_seed_collected(self, tmp_path) -> None:
        root = tmp_path / "src"
        root.mkdir()
        (root / "a.c").write_text("int main(void) { return 0; }\n")
        rl = self._write_rl(tmp_path, ["a.c"])
        scoped = prep._scope_from_reading_list(rl, root, [root])
        assert scoped == [(root / "a.c").resolve()]

    def test_traversal_seed_excluded(self, tmp_path) -> None:
        root = tmp_path / "src"
        root.mkdir()
        outside = tmp_path / "evil.c"
        outside.write_text("int evil;\n")
        (root / "a.c").write_text("int main(void) { return 0; }\n")
        rl = self._write_rl(tmp_path, ["../evil.c", "a.c"])
        scoped = prep._scope_from_reading_list(rl, root, [root])
        assert scoped is not None
        assert outside.resolve() not in scoped
        assert (root / "a.c").resolve() in scoped

    def test_absolute_seed_outside_root_excluded(self, tmp_path) -> None:
        root = tmp_path / "src"
        root.mkdir()
        outside = tmp_path / "evil.c"
        outside.write_text("int evil;\n")
        rl = self._write_rl(tmp_path, [str(outside)])
        # No in-root seed survives -> None (full-rglob fallback), the
        # pre-existing no-usable-seeds contract.
        assert prep._scope_from_reading_list(rl, root, [root]) is None

    def test_symlink_seed_escaping_root_excluded(self, tmp_path) -> None:
        root = tmp_path / "src"
        root.mkdir()
        outside = tmp_path / "evil.c"
        outside.write_text("int evil;\n")
        (root / "link.c").symlink_to(outside)
        rl = self._write_rl(tmp_path, ["link.c"])
        assert prep._scope_from_reading_list(rl, root, [root]) is None
