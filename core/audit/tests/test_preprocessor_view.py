"""Tests for core.audit.preprocessor_view.

The sandbox entry (``core.sandbox.context.run``) is monkeypatched in
every test that preprocesses: the spy records the sandbox kwargs (so we
can assert ``block_network=True`` etc.) and then runs the preprocessor
directly — the suite must pass on hosts where namespace isolation is
unavailable, and must never require network.

Real gcc / cpp are used where present; every preprocessing test is
guarded by a skipif so the suite degrades gracefully on hosts without
a C preprocessor.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.audit import preprocessor_view as pv
from core.audit.preprocessor_view import (
    ExpandedView,
    MacroDefinedFunction,
    _macro_flags,
    _parse_linemarked_output,
    augment_checklist_with_macro_functions,
    expand_function,
    expand_translation_unit,
    recover_macro_defined_functions,
)

FIXTURES = Path(__file__).parent / "fixtures" / "preprocessor_view"

pv._reset_probe_cache()
HAVE_CPP = pv._preprocessor_for(False) is not None

needs_cpp = pytest.mark.skipif(
    not HAVE_CPP, reason="no C preprocessor (gcc/cpp) installed",
)


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    pv._reset_probe_cache()
    yield
    pv._reset_probe_cache()


@pytest.fixture
def sandbox_spy(monkeypatch):
    """Record sandbox kwargs, then execute the preprocessor directly."""
    calls: list[dict] = []

    def fake_sandbox_run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        fwd = {
            k: kwargs[k]
            for k in ("capture_output", "text", "timeout", "cwd")
            if k in kwargs
        }
        try:
            from core.config import RaptorConfig
            env = RaptorConfig.get_safe_env()
        except ImportError:
            env = None
        return subprocess.run(cmd, check=False, env=env, **fwd)

    monkeypatch.setattr("core.sandbox.context.run", fake_sandbox_run)
    return calls


def _target_with(tmp_path: Path, *fixture_names: str) -> Path:
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    for name in fixture_names:
        shutil.copy(FIXTURES / name, target / name)
    return target


# ---------------------------------------------------------------------------
# (a) whole-TU expanded view + line map
# ---------------------------------------------------------------------------


@needs_cpp
class TestExpandedView:
    def test_tu_lines_map_to_original_coordinates(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        assert view.ok
        assert view.fidelity == 3
        lines = view.lines()
        add_idx = next(
            i for i, ln in enumerate(lines) if ln.startswith("int add(")
        )
        assert view.origin_of(add_idx + 1) == ("simple.c", 5)

    def test_macro_expanded_line_keeps_original_line(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        assert view.ok
        lines = view.lines()
        buf_idx = next(
            i for i, ln in enumerate(lines) if "char buf[16]" in ln
        )
        # `char buf[BUFSZ];` is line 10 of the fixture; the expanded
        # form must attribute back to it.
        assert view.origin_of(buf_idx + 1) == ("simple.c", 10)

    def test_system_header_expansion_is_unattributable(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        assert view.ok
        # stdio.h expansion produced substantial content whose map
        # entries are all None (system headers are noise).
        assert any(e is None for e in view.line_map)
        # Every attributable entry points at a file under the target.
        attributed_files = {e[0] for e in view.line_map if e is not None}
        assert attributed_files == {"simple.c"}

    def test_linemarkers_are_removed_from_view(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        assert view.ok
        assert not any(
            ln.startswith("# ") and '"' in ln for ln in view.lines()
        )
        assert len(view.line_map) == len(view.lines())

    def test_macro_config_object_selects_ifdef_arm(self, tmp_path, sandbox_spy):
        from core.build.macro_config import MacroConfig

        target = _target_with(tmp_path, "cfg.c")
        view = expand_translation_unit(
            target_path=target, file_path="cfg.c",
            macro_config=MacroConfig(defined={"ENABLE_FEATURE": "1"}),
            out_dir=tmp_path / "out",
        )
        assert view.ok
        assert "feature_on" in view.text
        assert "feature_off" not in view.text

    def test_macro_config_list_form(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "cfg.c")
        view = expand_translation_unit(
            target_path=target, file_path="cfg.c",
            macro_config=["-DENABLE_FEATURE"],
            out_dir=tmp_path / "out",
        )
        assert view.ok
        assert "feature_on" in view.text
        assert "feature_off" not in view.text

    def test_no_macro_config_takes_else_arm(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "cfg.c")
        view = expand_translation_unit(
            target_path=target, file_path="cfg.c", out_dir=tmp_path / "out",
        )
        assert view.ok
        assert "feature_off" in view.text


# ---------------------------------------------------------------------------
# (b) per-function expanded range
# ---------------------------------------------------------------------------


@needs_cpp
class TestExpandFunction:
    def test_function_range_selected_with_original_lines(
        self, tmp_path, sandbox_spy,
    ):
        target = _target_with(tmp_path, "simple.c")
        fx = expand_function(
            target_path=target, file_path="simple.c",
            line_start=5, line_end=7, out_dir=tmp_path / "out",
        )
        assert fx.ok
        assert "return a + b;" in fx.text
        assert "use_macro" not in fx.text
        assert all(5 <= ln <= 7 for ln, _t in fx.lines)

    def test_function_range_shows_expanded_macros(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        fx = expand_function(
            target_path=target, file_path="simple.c",
            line_start=9, line_end=14, out_dir=tmp_path / "out",
        )
        assert fx.ok
        assert "char buf[16]" in fx.text
        assert "BUFSZ" not in fx.text

    def test_degraded_view_degrades_function_expansion(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "broken.c")
        fx = expand_function(
            target_path=target, file_path="broken.c",
            line_start=3, line_end=5, out_dir=tmp_path / "out",
        )
        assert not fx.ok
        assert fx.errors
        assert fx.text == ""

    def test_reuses_prebuilt_view(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        n_calls = len(sandbox_spy)
        fx = expand_function(
            target_path=target, file_path="simple.c",
            line_start=5, line_end=7, view=view,
        )
        assert fx.ok
        assert len(sandbox_spy) == n_calls  # no re-preprocess


# ---------------------------------------------------------------------------
# (c) macro-defined function recovery
# ---------------------------------------------------------------------------


@needs_cpp
class TestMacroRecovery:
    def test_macro_defined_functions_recovered_with_attribution(
        self, tmp_path, sandbox_spy,
    ):
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h")
        recovered = recover_macro_defined_functions(
            target_path=target, file_path="macro_funcs.c",
            out_dir=tmp_path / "out",
        )
        names = {r.name for r in recovered}
        assert names == {"handler_alpha", "handler_beta"}
        by_name = {r.name: r for r in recovered}
        # Attribution: the macro-invocation site in the original file.
        assert by_name["handler_alpha"].file == "macro_funcs.c"
        assert by_name["handler_alpha"].line == 3
        assert by_name["handler_beta"].line == 9

    def test_pre_expansion_definitions_not_reported(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h")
        recovered = recover_macro_defined_functions(
            target_path=target, file_path="macro_funcs.c",
            out_dir=tmp_path / "out",
        )
        assert "plain_function" not in {r.name for r in recovered}

    def test_plain_tu_recovers_nothing(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        assert recover_macro_defined_functions(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        ) == []

    def test_degraded_view_recovers_nothing(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "broken.c")
        assert recover_macro_defined_functions(
            target_path=target, file_path="broken.c", out_dir=tmp_path / "out",
        ) == []

    def test_checklist_item_shape(self):
        rec = MacroDefinedFunction(
            name="handler_x", file="a.c", line=7, signature="int handler_x(int v) {",
        )
        item = rec.to_checklist_item()
        assert item["name"] == "handler_x"
        assert item["kind"] == "function"
        assert item["line_start"] == 7
        assert item["line_end"] == 7
        assert item["macro_defined"] is True
        assert item["checked_by"] == []


# ---------------------------------------------------------------------------
# Checklist augmentation (inventory feed)
# ---------------------------------------------------------------------------


@needs_cpp
class TestChecklistAugmentation:
    def _checklist(self):
        return {
            "files": [
                {
                    "path": "macro_funcs.c",
                    "items": [
                        {"name": "plain_function", "kind": "function",
                         "line_start": 5, "line_end": 7, "checked_by": []},
                    ],
                },
                {
                    "path": "simple.c",
                    "items": [
                        {"name": "add", "kind": "function",
                         "line_start": 5, "line_end": 7, "checked_by": []},
                    ],
                },
            ],
        }

    def test_macro_functions_added_to_checklist(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h", "simple.c")
        checklist = self._checklist()
        added = augment_checklist_with_macro_functions(
            checklist, target, out_dir=tmp_path / "out",
        )
        assert added == 2
        items = checklist["files"][0]["items"]
        names = {it["name"] for it in items}
        assert {"handler_alpha", "handler_beta"} <= names
        new = [it for it in items if it.get("macro_defined")]
        assert all(it["line_start"] > 0 for it in new)

    def test_prefilter_skips_files_without_macro_invocations(
        self, tmp_path, sandbox_spy,
    ):
        # simple.c has no ALL_CAPS invocation at column 0 — it must not
        # even reach the preprocessor.
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h", "simple.c")
        augment_checklist_with_macro_functions(
            self._checklist(), target, out_dir=tmp_path / "out",
        )
        preprocessed = {c["cmd"][-3] for c in sandbox_spy}
        assert all("macro_funcs.c" in p for p in preprocessed)

    def test_idempotent(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h", "simple.c")
        checklist = self._checklist()
        assert augment_checklist_with_macro_functions(
            checklist, target, out_dir=tmp_path / "out",
        ) == 2
        assert augment_checklist_with_macro_functions(
            checklist, target, out_dir=tmp_path / "out",
        ) == 0

    def test_max_files_budget(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h")
        checklist = self._checklist()
        added = augment_checklist_with_macro_functions(
            checklist, target, out_dir=tmp_path / "out", max_files=0,
        )
        assert added == 0
        assert sandbox_spy == []


# ---------------------------------------------------------------------------
# Degradation: failure is never an exception, never a fabricated view
# ---------------------------------------------------------------------------


class TestDegradation:
    @needs_cpp
    def test_missing_generated_header_degrades(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "broken.c")
        view = expand_translation_unit(
            target_path=target, file_path="broken.c", out_dir=tmp_path / "out",
        )
        assert not view.ok
        assert view.text == ""
        assert view.line_map == ()
        assert any("preprocess failed" in e for e in view.errors)

    def test_non_c_file_degrades(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "app.py").write_text("x = 1\n")
        view = expand_translation_unit(
            target_path=target, file_path="app.py", out_dir=tmp_path / "out",
        )
        assert not view.ok
        assert any("not a C/C++" in e for e in view.errors)

    def test_path_escape_degrades(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        view = expand_translation_unit(
            target_path=target, file_path="../evil.c", out_dir=tmp_path / "out",
        )
        assert not view.ok
        assert any("escapes target" in e for e in view.errors)

    def test_missing_file_degrades(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        view = expand_translation_unit(
            target_path=target, file_path="ghost.c", out_dir=tmp_path / "out",
        )
        assert not view.ok

    def test_no_preprocessor_degrades(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        assert not view.ok
        assert any("no C preprocessor" in e for e in view.errors)

    @needs_cpp
    def test_no_sandbox_no_preprocess(self, tmp_path, monkeypatch):
        # When core.sandbox cannot be imported, refuse to run the
        # preprocessor on untrusted source (never unsandboxed).
        import builtins
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "core.sandbox.context":
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        target = _target_with(tmp_path, "simple.c")
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        assert not view.ok
        assert any("refusing" in e for e in view.errors)


# ---------------------------------------------------------------------------
# Sandbox invocation contract
# ---------------------------------------------------------------------------


@needs_cpp
class TestSandboxInvocation:
    def test_sandbox_used_with_network_deny(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        out_dir = tmp_path / "out"
        view = expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=out_dir,
        )
        assert view.ok
        assert len(sandbox_spy) == 1
        call = sandbox_spy[0]
        assert call["block_network"] is True
        assert call["target"] == str(target)
        assert str(out_dir) in call["output"]
        assert isinstance(call["cmd"], list)
        assert all(isinstance(a, str) for a in call["cmd"])
        assert "timeout" in call

    def test_single_tu_only_no_build_system(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        expand_translation_unit(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        cmd = sandbox_spy[0]["cmd"]
        binary = Path(cmd[0]).name
        assert binary in ("gcc", "g++", "cpp", "cc")
        assert not any(b in cmd[0] for b in ("make", "cmake", "configure"))
        repo_files = [a for a in cmd if a.endswith(".c")]
        assert repo_files == [a for a in cmd if "simple.c" in a]


# ---------------------------------------------------------------------------
# Linemarker parsing (no preprocessor needed)
# ---------------------------------------------------------------------------


class TestLinemarkerParsing:
    def test_attribution_and_exclusion(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.c").write_text("int x;\n")
        work = tmp_path / "work"
        work.mkdir()
        raw = "\n".join([
            '# 1 "<built-in>"',
            "typedef int __int32_t;",
            f'# 1 "{target}/a.c"',
            "int x;",
            '# 1 "/usr/include/other.h" 1 3 4',
            "extern int puts(const char *);",
            f'# 3 "{target}/a.c" 2',
            "int y;",
        ])
        text, line_map = _parse_linemarked_output(raw, target, work)
        lines = text.split("\n")
        assert lines == [
            "typedef int __int32_t;",
            "int x;",
            "extern int puts(const char *);",
            "int y;",
        ]
        assert line_map[0] is None          # <built-in>
        assert line_map[1] == ("a.c", 1)
        assert line_map[2] is None          # system header
        assert line_map[3] == ("a.c", 3)

    def test_line_counter_advances_between_markers(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.c").write_text("\n")
        raw = "\n".join([
            f'# 5 "{target}/a.c"',
            "int a;",
            "int b;",
            "int c;",
        ])
        _text, line_map = _parse_linemarked_output(raw, target, target)
        assert line_map == (("a.c", 5), ("a.c", 6), ("a.c", 7))

    def test_escaped_marker_filename(self, tmp_path):
        assert pv._unescape_marker_path(r'a\"b\\c') == 'a"b\\c'


# ---------------------------------------------------------------------------
# Macro flag validation (no preprocessor needed)
# ---------------------------------------------------------------------------


class TestMacroFlags:
    def test_none_is_empty(self):
        assert _macro_flags(None) == []

    def test_macro_config_object(self):
        from core.build.macro_config import MacroConfig
        cfg = MacroConfig(
            defined={"FOO": "1", "BAR": "42"},
            undefined=frozenset({"BAZ"}),
        )
        flags = _macro_flags(cfg)
        assert "-DFOO" in flags
        assert "-DBAR=42" in flags
        assert "-UBAZ" in flags

    def test_list_form(self):
        assert _macro_flags(["-DA", "-DB=2", "-UC"]) == ["-DA", "-DB=2", "-UC"]

    def test_invalid_names_dropped(self):
        assert _macro_flags(["-D1BAD", "-D", "-Dbad name=1"]) == []
        assert _macro_flags(["-U-flag"]) == []

    def test_non_flag_strings_dropped(self):
        assert _macro_flags(["-I/etc", "--include=x", "rm -rf /"]) == []

    def test_control_chars_in_value_dropped(self):
        assert _macro_flags(["-DX=a\nb"]) == []

    def test_bare_define_normalised(self):
        assert _macro_flags(["-DFEATURE=1"]) == ["-DFEATURE"]


# ---------------------------------------------------------------------------
# Result-type invariants
# ---------------------------------------------------------------------------


class TestResultInvariants:
    def test_degraded_view_is_never_fabricated(self):
        view = ExpandedView(ok=False, file_path="x.c", errors=["boom"])
        assert view.text == ""
        assert view.lines() == []
        assert view.origin_of(1) is None

    def test_origin_out_of_range(self):
        view = ExpandedView(
            ok=True, file_path="x.c", text="a", line_map=(("x.c", 1),),
        )
        assert view.origin_of(0) is None
        assert view.origin_of(2) is None
        assert view.origin_of(1) == ("x.c", 1)
