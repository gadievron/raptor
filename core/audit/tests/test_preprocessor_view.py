"""Tests for core.audit.preprocessor_view.

The sandbox entry (``core.sandbox.context.run``) is monkeypatched in
every test that preprocesses: the spy records the sandbox kwargs (so we
can assert ``block_network=True`` etc.) and then runs the preprocessor
directly — the suite must pass on hosts where namespace isolation is
unavailable, and must never require network.

Real gcc / cpp are used where present; every preprocessing test is
guarded by a skipif so the suite degrades gracefully on hosts without
a C preprocessor.

The live legs additionally route through the transport/product
partition in ``core.audit.tests._live_transport`` (cpp channel):
runtime degradation under battery load — deadline, spawn OSError, a
SIGKILL'd preprocessor, the per-test probe flipping — skips with the
transport's reason, while everything the preprocessor DID (diagnostics,
positive exits, non-KILL signals such as a segfault) stays a hard
failure. Directions, minted-identity pins and structural fences live in
``test_live_transport_guards.py``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.testing.module_state import isolated_module_state

from core.audit import preprocessor_view as pv
from core.audit.preprocessor_view import (
    ExpandedView,
    FunctionExpansion,
    MacroDefinedFunction,
    _macro_flags,
    _parse_linemarked_output,
    augment_checklist_with_macro_functions,
    expand_function,
    expand_translation_unit,
    recover_macro_defined_functions,
)
from core.audit.tests._live_transport import (
    expand_function_guarded,
    expand_translation_unit_guarded,
    skip_unless_cpp_carries_probe,
)

import core.audit.preprocessor_view as _tool_lookup_consumer
from core.testing.module_bindings import patch_module_attribute

FIXTURES = Path(__file__).parent / "fixtures" / "preprocessor_view"

with isolated_module_state(pv, {"_PROBE_CACHE": {}}, lock=pv._PROBE_LOCK):
    HAVE_CPP = pv._preprocessor_for(False) is not None

needs_cpp = pytest.mark.skipif(
    not HAVE_CPP, reason="no C preprocessor (gcc/cpp) installed",
)


def _expand_tu_guarded(**kwargs: Any) -> ExpandedView:
    """Live preprocessor runs route through the transport guard:
    runtime degradation (deadline, spawn OSError, a SIGKILL'd
    preprocessor, the per-test probe lost under load) skips with the
    transport's reason; every product degradation — including a
    segfaulting preprocessor, a rejected TU, and every diagnostic —
    passes through untouched for the caller's own hard assertions."""
    return expand_translation_unit_guarded(cpp_probed=HAVE_CPP, **kwargs)


def _expand_function_guarded(**kwargs: Any) -> FunctionExpansion:
    """``expand_function`` live legs, same transport guard (a degraded
    expansion carries the underlying view's errors)."""
    return expand_function_guarded(cpp_probed=HAVE_CPP, **kwargs)


def _probe_cpp(tmp_path: Path, spy_calls: list, *, context: str) -> None:
    """Transport probe for the identity-collapsed surfaces (macro
    recovery returns [] for a degraded view and for a genuinely
    macro-free TU; checklist augmentation swallows per-file failures):
    skip unless the preprocessor carries a trivial TU right now. Probe
    sandbox calls are scrubbed from ``spy_calls`` so call-counting
    assertions see only the test's own runs."""
    skip_unless_cpp_carries_probe(
        tmp_path, cpp_probed=HAVE_CPP, context=context, spy_calls=spy_calls,
    )


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    with isolated_module_state(pv, {"_PROBE_CACHE": {}}, lock=pv._PROBE_LOCK):
        yield


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
        view = _expand_tu_guarded(
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
        view = _expand_tu_guarded(
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
        view = _expand_tu_guarded(
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
        view = _expand_tu_guarded(
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
        view = _expand_tu_guarded(
            target_path=target, file_path="cfg.c",
            macro_config=MacroConfig(defined={"ENABLE_FEATURE": "1"}),
            out_dir=tmp_path / "out",
        )
        assert view.ok
        assert "feature_on" in view.text
        assert "feature_off" not in view.text

    def test_macro_config_list_form(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "cfg.c")
        view = _expand_tu_guarded(
            target_path=target, file_path="cfg.c",
            macro_config=["-DENABLE_FEATURE"],
            out_dir=tmp_path / "out",
        )
        assert view.ok
        assert "feature_on" in view.text
        assert "feature_off" not in view.text

    def test_no_macro_config_takes_else_arm(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "cfg.c")
        view = _expand_tu_guarded(
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
        fx = _expand_function_guarded(
            target_path=target, file_path="simple.c",
            line_start=5, line_end=7, out_dir=tmp_path / "out",
        )
        assert fx.ok
        assert "return a + b;" in fx.text
        assert "use_macro" not in fx.text
        assert all(5 <= ln <= 7 for ln, _t in fx.lines)

    def test_function_range_shows_expanded_macros(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        fx = _expand_function_guarded(
            target_path=target, file_path="simple.c",
            line_start=9, line_end=14, out_dir=tmp_path / "out",
        )
        assert fx.ok
        assert "char buf[16]" in fx.text
        assert "BUFSZ" not in fx.text

    def test_degraded_view_degrades_function_expansion(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "broken.c")
        fx = _expand_function_guarded(
            target_path=target, file_path="broken.c",
            line_start=3, line_end=5, out_dir=tmp_path / "out",
        )
        assert not fx.ok
        assert fx.errors
        assert fx.text == ""

    def test_reuses_prebuilt_view(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "simple.c")
        view = _expand_tu_guarded(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        )
        # Raw runner is deliberate: with a prebuilt healthy view no
        # subprocess runs, so there is no transport surface (and the
        # no-re-preprocess count below proves exactly that).
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
        _probe_cpp(tmp_path, sandbox_spy, context="macro recovery")
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
        _probe_cpp(tmp_path, sandbox_spy, context="pre-expansion filter")
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h")
        recovered = recover_macro_defined_functions(
            target_path=target, file_path="macro_funcs.c",
            out_dir=tmp_path / "out",
        )
        assert "plain_function" not in {r.name for r in recovered}

    def test_plain_tu_recovers_nothing(self, tmp_path, sandbox_spy):
        # [] must mean "expanded fine, nothing macro-defined" — a dead
        # transport also yields [] and would pass vacuously.
        _probe_cpp(tmp_path, sandbox_spy, context="plain-TU negative")
        target = _target_with(tmp_path, "simple.c")
        assert recover_macro_defined_functions(
            target_path=target, file_path="simple.c", out_dir=tmp_path / "out",
        ) == []

    def test_degraded_view_recovers_nothing(self, tmp_path, sandbox_spy):
        # The probe proves the toolchain is alive, so [] here is the
        # product's verdict on broken.c, not a transport artefact.
        _probe_cpp(tmp_path, sandbox_spy, context="degraded-view negative")
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
        _probe_cpp(tmp_path, sandbox_spy, context="checklist augmentation")
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
        # even reach the preprocessor. The probe's own sandbox call is
        # scrubbed from the spy before the assertion below reads it.
        _probe_cpp(tmp_path, sandbox_spy, context="prefilter")
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h", "simple.c")
        augment_checklist_with_macro_functions(
            self._checklist(), target, out_dir=tmp_path / "out",
        )
        preprocessed = {c["cmd"][-3] for c in sandbox_spy}
        assert all("macro_funcs.c" in p for p in preprocessed)

    def test_idempotent(self, tmp_path, sandbox_spy):
        _probe_cpp(tmp_path, sandbox_spy, context="idempotence")
        target = _target_with(tmp_path, "macro_funcs.c", "handlers.h", "simple.c")
        checklist = self._checklist()
        assert augment_checklist_with_macro_functions(
            checklist, target, out_dir=tmp_path / "out",
        ) == 2
        assert augment_checklist_with_macro_functions(
            checklist, target, out_dir=tmp_path / "out",
        ) == 0

    def test_max_files_budget(self, tmp_path, sandbox_spy):
        # No probe: with max_files=0 the preprocessor is never spawned
        # (the empty-spy assertion proves it), so there is no transport
        # surface on this leg.
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
        view = _expand_tu_guarded(
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
        # Deliberately MINTS the availability shape (the guard's
        # transport arm on cpp-probed hosts), so it must bypass the
        # guard — the sole reason this leg calls the raw runner.
        patch_module_attribute(monkeypatch, _tool_lookup_consumer, 'shutil', 'which', lambda *a, **k: None)
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
        view = _expand_tu_guarded(
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
        view = _expand_tu_guarded(
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
        _expand_tu_guarded(
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


def test_pinned_preprocessor_uses_remaining_budget_without_tool_discovery(tmp_path, monkeypatch):
    import core.audit.preprocessor_view as view_module
    target = tmp_path / 'repo'
    target.mkdir()
    (target / 'input.c').write_text('void f(void) {}\n')
    calls = []
    monkeypatch.setattr(view_module, '_preprocessor_for', lambda *a: pytest.fail('must use pinned executable'))
    monkeypatch.setattr(view_module, '_derive_include_dirs', lambda *a: [])

    def run(cmd, **kw):
        calls.append((cmd, kw))
        Path(cmd[cmd.index('-o') + 1]).write_text(f'# 1 "{target / "input.c"}"\nvoid f(void) {{}}\n')
        return subprocess.CompletedProcess(cmd, 0, '', '')

    monkeypatch.setattr('core.sandbox.context.run', run)
    view = expand_translation_unit(target_path=target, file_path='input.c', timeout=3,
                                   preprocessor=('/pinned/gcc', '-E', '-x', 'c'))
    assert view.ok and calls[0][0][0] == '/pinned/gcc'
    kw = calls[0][1]
    assert 0 < kw['timeout'] <= 3 and kw['block_network']
    assert kw['target'] == str(target) and kw['cwd'] == kw['output']
    assert not Path(kw['output']).exists()


def test_preprocessor_deadline_exhausted_during_preparation_does_not_launch(tmp_path, monkeypatch):
    import core.audit.preprocessor_view as view_module
    target = tmp_path / 'repo'
    target.mkdir()
    (target / 'input.c').write_text('void f(void) {}\n')
    ticks = iter([0.0, 5.0])
    monkeypatch.setattr(view_module, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(view_module, '_derive_include_dirs', lambda *a: [])
    monkeypatch.setattr('core.sandbox.context.run', lambda *a, **kw: pytest.fail('deadline already exhausted'))
    view = expand_translation_unit(target_path=target, file_path='input.c', timeout=1,
                                   preprocessor=('/pinned/gcc', '-E', '-x', 'c'))
    assert not view.ok and 'budget exhausted' in view.errors[0]


@needs_cpp
def test_shared_include_memo_does_not_share_preprocessor_macro_context(tmp_path, sandbox_spy, monkeypatch):
    from core.audit import compiler_sweep
    from core.audit.run_memo import BoundedMemo
    (tmp_path / 'include').mkdir()
    (tmp_path / 'include' / 'value.h').write_text('int value = VALUE;\n')
    (tmp_path / 'a.c').write_text('#include "value.h"\n')
    walks = []
    derive = compiler_sweep._derive_include_dirs
    def count(target, directory):
        walks.append((target, directory))
        return derive(target, directory)
    monkeypatch.setattr(compiler_sweep, '_derive_include_dirs', count)
    memo = BoundedMemo(2)
    one = _expand_tu_guarded(target_path=tmp_path, file_path='a.c',
                             macro_config=['-DVALUE=1'], include_dirs_memo=memo)
    two = _expand_tu_guarded(target_path=tmp_path, file_path='a.c',
                             macro_config=['-DVALUE=2'], include_dirs_memo=memo)
    assert one.ok and two.ok
    assert 'int value = 1;' in one.text and 'int value = 2;' in two.text
    assert one.line_map == two.line_map
    assert len(walks) == 1 and memo.hit_count == 1


@pytest.fixture
def prepared_reuse(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace
    from core.detectors.setup import AnalysisSetup, PreparedViews
    source = tmp_path / 'reuse.c'
    source.write_text('int value = VALUE;\n')
    calls = []
    prefix = [sys.executable, '-E', '-x', 'c']
    monkeypatch.setattr(pv, '_preprocessor_for', lambda _: prefix)
    def run(command, **kwargs):
        calls.append(command)
        value = next((a.partition('=')[2] if '=' in a else '1' for a in command
                      if a == '-DVALUE' or a.startswith('-DVALUE=')), '0')
        output = Path(command[command.index('-o')+1])
        output.write_text(f'# 1 "{source}"\n'+source.read_text().replace('VALUE', value))
        return SimpleNamespace(returncode=0, stderr='')
    monkeypatch.setattr('core.sandbox.context.run', run)
    setup = AnalysisSetup(preprocessed_views=PreparedViews())
    def expand(**kwargs):
        return pv.expand_translation_unit(target_path=tmp_path, file_path=source.name,
                                          setup=kwargs.pop('setup', setup), **kwargs)
    return source, setup, calls, prefix, expand


def test_prepared_view_reuse_preserves_mapping_and_isolates_mutable_view(prepared_reuse):
    source, setup, calls, _, expand = prepared_reuse
    first = expand(macro_config=['-DVALUE=1'])
    text, mapping = first.text, first.line_map
    first.text = 'consumer edit'
    first.errors.append('consumer error')
    second = expand(macro_config=['-DVALUE=1'])
    assert first.ok and second.ok and len(calls) == 1
    assert second.text == text and second.line_map == mapping and not second.errors
    assert second.origin_of(1) == (source.name, 1)
    assert setup.preprocessed_views.hit_count == 1


def test_prepared_views_separate_macro_environment_source_and_run(prepared_reuse, monkeypatch):
    from core.detectors.setup import AnalysisSetup
    source, _, calls, _, expand = prepared_reuse
    one = expand(macro_config=['-DVALUE=1'])
    two = expand(macro_config=['-DVALUE=2'])
    monkeypatch.setenv('RAPTOR_PREPARED_VIEW_TEST', 'different environment')
    expand(macro_config=['-DVALUE=2'])
    source.write_text('int changed = VALUE;\n')
    changed = expand(macro_config=['-DVALUE=2'])
    expand(setup=AnalysisSetup(), macro_config=['-DVALUE=2'])
    assert len(calls) == 5
    assert 'value = 1' in one.text and 'value = 2' in two.text and 'changed = 2' in changed.text


def test_analyzer_prefix_remains_independent_of_ordinary_view(prepared_reuse):
    _, _, calls, prefix, expand = prepared_reuse
    expand()
    analyzer = (prefix[0], '-fanalyzer', *prefix[1:])
    expand(preprocessor=analyzer)
    expand(preprocessor=analyzer)
    expand()
    assert len(calls) == 3  # only the ordinary view is reused


def test_prepared_view_byte_budget_bypasses_cache_without_losing_results(prepared_reuse):
    from core.detectors.setup import PreparedViews
    _, setup, calls, _, expand = prepared_reuse
    setup.preprocessed_views = PreparedViews(max_bytes=1)
    one, two = expand(), expand()
    assert one.ok and two.ok and one.text == two.text and len(calls) == 2
    assert setup.preprocessed_views.retained_bytes == 0


def test_failed_preparation_is_retried_and_not_replayed(prepared_reuse, monkeypatch):
    from types import SimpleNamespace
    from core.sandbox import context
    _, _, calls, _, expand = prepared_reuse
    original = context.run
    attempts = []
    def fail_once(command, **kwargs):
        attempts.append(command)
        if len(attempts) == 1:
            return SimpleNamespace(returncode=1, stderr='missing generated header')
        return original(command, **kwargs)
    monkeypatch.setattr(context, 'run', fail_once)
    failed, success, reused = expand(), expand(), expand()
    assert not failed.ok and success.ok and reused.ok
    assert len(attempts) == 2 and len(calls) == 1


def test_tool_identity_and_include_order_separate_prepared_views(prepared_reuse, monkeypatch):
    source, _, calls, prefix, expand = prepared_reuse
    tool = source.parent / 'compiler'
    tool.write_text('first executable identity')
    prefix[0] = str(tool)
    expand()
    tool.write_text('a replacement executable with another size')
    expand()
    monkeypatch.setattr(pv, '_cached_include_dirs', lambda *a: [str(source.parent), '/first'])
    expand()
    monkeypatch.setattr(pv, '_cached_include_dirs', lambda *a: ['/first', str(source.parent)])
    expand()
    assert len(calls) == 4


def test_expired_request_does_not_serve_a_cached_success(prepared_reuse):
    _, _, calls, _, expand = prepared_reuse
    assert expand().ok
    assert not expand(timeout=0).ok
    assert len(calls) == 1


def test_relative_compiler_search_path_bypasses_reuse(prepared_reuse, monkeypatch):
    _, _, calls, _, expand = prepared_reuse
    monkeypatch.setenv('CPATH', '..')
    assert expand().ok and expand().ok
    assert len(calls) == 2


def test_oversized_source_and_view_are_not_retained(prepared_reuse):
    from core.detectors.setup import PreparedViews
    source, _, calls, _, expand = prepared_reuse
    source.write_text('/*' + 'x' * (1024 * 1024) + '*/\n')
    assert expand().ok and expand().ok and len(calls) == 2
    cache = PreparedViews()
    assert not cache.put(('large',), ExpandedView(ok=True, file_path='a.c', text='x' * (3 * 1024 * 1024)))
    assert cache.retained_bytes == 0


def test_concurrent_miss_does_not_wait_past_its_deadline(prepared_reuse, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from core.sandbox import context
    _, _, _, _, expand = prepared_reuse
    original = context.run
    started, release = Event(), Event()
    def held(command, **kwargs):
        started.set()
        assert release.wait(8)
        return original(command, **kwargs)
    monkeypatch.setattr(context, 'run', held)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(expand)
        try:
            assert started.wait(5)
            second = pool.submit(expand, timeout=0)
            assert not second.result(timeout=5).ok
        finally:
            release.set()
        assert first.result(timeout=5).ok


def test_single_consumer_does_not_hash_or_retain_prepared_views(prepared_reuse, monkeypatch):
    from core.detectors.setup import AnalysisSetup
    _, _, calls, _, expand = prepared_reuse
    def unexpected(*args):
        raise AssertionError('unnecessary preparation hash for a single consumer')
    monkeypatch.setattr(pv, '_prepared_view_key', unexpected)
    setup = AnalysisSetup()
    assert expand(setup=setup).ok and expand(setup=setup).ok
    assert len(calls) == 2 and setup.preprocessed_views is None


@pytest.mark.parametrize("payload, expected", [
    (b"int one;\r\nint two;\rint three;\n", "int one;\nint two;\nint three;\n"),
    (b"int bad; // \xff\n", "int bad; // \ufffd\n"),
])
def test_output_read_preserves_decoding_and_newlines(prepared_reuse, monkeypatch, payload, expected):
    from types import SimpleNamespace
    source, _, _, _, expand = prepared_reuse

    def run(command, **kwargs):
        output = Path(command[command.index('-o') + 1])
        output.write_bytes(f'# 1 "{source}"\n'.encode() + payload)
        return SimpleNamespace(returncode=0, stderr='')

    monkeypatch.setattr('core.sandbox.context.run', run)
    view = expand()
    assert view.ok, view.errors
    assert view.text == expected
    assert view.origin_of(2) == (source.name, 2)


def test_output_growth_over_byte_budget_is_refused_and_retried(prepared_reuse, monkeypatch):
    from core.source import gated
    _, setup, calls, _, expand = prepared_reuse
    original = gated._open_gated
    monkeypatch.setattr(pv, '_MAX_EXPANDED_BYTES', 512)

    def grow(path, **kwargs):
        handle, snapshot = original(path, **kwargs)
        if Path(path).name == 'expanded.i':
            try:
                with Path(path).open('ab') as output:
                    output.write(b'x' * 513)
            except BaseException:
                handle.close()
                raise
        return handle, snapshot

    monkeypatch.setattr(gated, '_open_gated', grow)
    rejected = expand()
    assert not rejected.ok
    assert any('exceeds 512 bytes' in error for error in rejected.errors)
    assert setup.preprocessed_views.retained_bytes == 0
    monkeypatch.setattr(gated, '_open_gated', original)
    assert expand().ok
    assert len(calls) == 2


def test_nonregular_preprocessor_output_is_refused(prepared_reuse, monkeypatch):
    import os
    from types import SimpleNamespace
    _, setup, _, _, expand = prepared_reuse

    def run(command, **kwargs):
        output = Path(command[command.index('-o') + 1])
        output.unlink(missing_ok=True)
        os.mkfifo(output)
        return SimpleNamespace(returncode=0, stderr='')

    def unbounded_read(*args, **kwargs):
        pytest.fail('preprocessor output must use a nonblocking bounded reader')

    monkeypatch.setattr('core.sandbox.context.run', run)
    monkeypatch.setattr(Path, 'read_text', unbounded_read)
    view = expand()
    assert not view.ok
    assert any('not a regular file' in error for error in view.errors)
    assert setup.preprocessed_views.retained_bytes == 0


def test_output_growth_within_budget_is_read_completely(prepared_reuse, monkeypatch):
    from core.source import gated
    source, _, _, _, expand = prepared_reuse
    original = gated._open_gated
    monkeypatch.setattr(pv, '_MAX_EXPANDED_BYTES', 512)

    def grow(path, **kwargs):
        handle, snapshot = original(path, **kwargs)
        if Path(path).name == 'expanded.i':
            try:
                with Path(path).open('ab') as output:
                    output.write(b'int appended;\n')
            except BaseException:
                handle.close()
                raise
        return handle, snapshot

    monkeypatch.setattr(gated, '_open_gated', grow)
    view = expand()
    assert view.ok, view.errors
    assert view.text.endswith('int appended;\n')
    assert view.origin_of(2) == (source.name, 2)


@pytest.mark.parametrize("trailing_newline", [False, True])
def test_macro_recovery_without_whole_view_line_lists(tmp_path, trailing_newline):
    class UnsplitText(str):
        def split(self, *args, **kwargs):
            pytest.fail("macro recovery must not split the entire expanded view")

    (tmp_path / 'macros.c').write_text('DEFINE(first)\nDEFINE(second)\n')
    text = (
        'int system_function(void) {\nreturn 0;\n}\n'
        'int first(\nvoid) {\nreturn 1;\n}\n'
        'int existing(void) { return 0; }\n'
        'int second(void) { return 2; }'
    ) + ('\n' if trailing_newline else '')
    (tmp_path / 'other.c').write_text('int existing(void) { return 0; }\n')
    origins = (
        None, None, None,
        ('macros.c', 1), ('macros.c', 1), ('macros.c', 1), ('macros.c', 1),
        ('other.c', 1), ('macros.c', 2),
    ) + ((('macros.c', 3),) if trailing_newline else ())
    view = ExpandedView(ok=True, file_path='macros.c', text=UnsplitText(text),
                        line_map=origins)
    recovered = recover_macro_defined_functions(
        target_path=tmp_path, file_path='macros.c', view=view,
    )
    assert [(item.name, item.file, item.line, item.signature) for item in recovered] == [
        ('first', 'macros.c', 1, 'int first('),
        ('second', 'macros.c', 2, 'int second(void) { return 2; }'),
    ]


@pytest.mark.parametrize('source, expected', [
    ('DEFINE_HANDLER/**/(alpha)\n', True),
    ('DEFINE_HAND\\\nLER(alpha)\n', True),
    ('DEFINE_HAND\\\r\nLER/**/(alpha)\r\n', True),
    ('DEFINE_HANDLER // comment\n(alpha)\n', True),
    ('    DEFINE_HANDLER/**/(alpha)\n', False),
    ('void f(void) { DEFINE_HANDLER/**/(alpha); }\n', False),
    ('void ordinary(void) {}\n', False),
])
def test_checklist_macro_gate_uses_shared_normalization_with_column_zero_policy(tmp_path, monkeypatch, source, expected):
    (tmp_path / 'a.c').write_text(source)
    checklist = {'files': [{'path': 'a.c', 'items': []}]}
    calls = []

    def recover(**kwargs):
        calls.append(kwargs['file_path'])
        return [MacroDefinedFunction('handler_alpha', 'a.c', 1)]

    monkeypatch.setattr(pv, 'recover_macro_defined_functions', recover)
    added = augment_checklist_with_macro_functions(checklist, tmp_path)
    assert added == int(expected)
    assert calls == (['a.c'] if expected else [])


@needs_cpp
def test_native_checklist_recovers_spliced_definition_macro(tmp_path, sandbox_spy):
    _probe_cpp(tmp_path, sandbox_spy, context='spliced definition macro')
    target = _target_with(tmp_path, 'handlers.h')
    (target / 'generated.c').write_text('#include "handlers.h"\nDEFINE_HAND\\\nLER/**/(alpha)\n')
    checklist = {'files': [{'path': 'generated.c', 'items': []}]}
    assert augment_checklist_with_macro_functions(checklist, target, out_dir=tmp_path / 'out') == 1
    assert [item['name'] for item in checklist['files'][0]['items']] == ['handler_alpha']


def test_macro_recovery_counts_only_newline_for_attribution(tmp_path):
    (tmp_path / 'macros.c').write_text('DEFINE(real)\n')
    view = ExpandedView(
        ok=True, file_path='macros.c',
        text='// \u2028 \x0c \r\nint real(void) { return 1; }',
        line_map=(None, ('macros.c', 1)),
    )
    recovered = recover_macro_defined_functions(
        target_path=tmp_path, file_path='macros.c', view=view,
    )
    assert [(item.name, item.line) for item in recovered] == [('real', 1)]


def test_checklist_recovery_reuses_normalized_macro_configuration(tmp_path, monkeypatch):
    for name in ('a.c', 'b.c'):
        (tmp_path / name).write_text('DEFINE_HANDLER(value)\n')
    checklist = {'files': [{'path': name, 'items': []} for name in ('a.c', 'b.c')]}
    calls = []

    def recover(**kwargs):
        flags = tuple(kwargs['macro_config'])
        calls.append(flags)
        return [MacroDefinedFunction('generated', kwargs['file_path'], 1)]

    monkeypatch.setattr(pv, 'recover_macro_defined_functions', recover)
    assert augment_checklist_with_macro_functions(checklist, tmp_path,
        macro_config=iter(['-DVALUE=2', '-UOTHER'])) == 2
    assert calls == [('-DVALUE=2', '-UOTHER')] * 2


def test_truncated_checklist_input_does_not_spend_expansion_budget(tmp_path, monkeypatch):
    for name in ('bad.c', 'good.c'):
        (tmp_path / name).write_text('DEFINE_HANDLER(value)\n')
    checklist = {'files': [{'path': name, 'items': []} for name in ('bad.c', 'good.c')]}
    original = pv.read_text_capped
    calls = []

    def read(path, **kwargs):
        return ('DEFINE_HANDLER(value)', True) if Path(path).name == 'bad.c' else original(path, **kwargs)

    def recover(**kwargs):
        calls.append(kwargs['file_path'])
        return [MacroDefinedFunction('generated', kwargs['file_path'], 1)]

    monkeypatch.setattr(pv, 'read_text_capped', read)
    monkeypatch.setattr(pv, 'recover_macro_defined_functions', recover)
    assert augment_checklist_with_macro_functions(checklist, tmp_path, max_files=1) == 1
    assert calls == ['good.c']
    assert checklist['files'][0]['items'] == []


def test_checklist_recovery_indexes_names_once_and_deduplicates_across_tus(tmp_path, monkeypatch):
    visits = []

    class ExistingItem(dict):
        def get(self, key, *args):
            if key == 'name':
                visits.append(key)
            return super().get(key, *args)

    for name in ('a.c', 'b.c'):
        (tmp_path / name).write_text('DEFINE_HANDLER(value)\n')
    existing = ExistingItem(name='existing', human_note='retain')
    header = {'path': 'shared.h', 'items': [existing]}
    checklist = {'files': [{'path': name, 'items': []} for name in ('a.c', 'b.c')] + [header]}
    recovered = [MacroDefinedFunction('existing', 'shared.h', 1)] + [
        MacroDefinedFunction(f'generated_{index}', 'shared.h', index + 2) for index in range(1000)]
    monkeypatch.setattr(pv, 'recover_macro_defined_functions', lambda **kw: recovered)
    assert augment_checklist_with_macro_functions(checklist, tmp_path) == 1000
    assert visits == ['name']
    assert header['items'][0] is existing and existing['human_note'] == 'retain'
    assert [item['name'] for item in header['items'][1:]] == [f'generated_{index}' for index in range(1000)]
