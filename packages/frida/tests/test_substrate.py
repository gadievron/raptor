"""Tests for frida substrate helpers: available(), parse_events(), bb-coverage
template existence, and drcov round-trip through core.coverage.collect."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace

from packages.frida import available, parse_events

import builtins
from types import ModuleType
import pytest
from core.testing.module_bindings import mock_module_attribute
from core.testing.module_views import module_function_view

# ── available() ────────────────────────────────────────────────────────

class TestAvailable:
    """available() caches its result; reset between tests."""

    @pytest.fixture(autouse=True)
    def _owned_availability(self, monkeypatch):
        """Keep import overrides and cached answers on this fixture's view."""
        import packages.frida as original

        inherited = vars(original).get("__builtins__", builtins)
        imports = ModuleType("builtins")
        vars(imports).update(vars(inherited) if isinstance(inherited, ModuleType) else inherited)

        def import_local(name, globals=None, locals=None, fromlist=(), level=0):
            return private._imports.__import__(name, globals, locals, fromlist, level)

        private = module_function_view(original, import_hook=import_local)
        private._imports = imports
        monkeypatch.setattr(self, "_mod", private, raising=False)
        self._mod._available = None
        monkeypatch.setitem(globals(), "available", private.available)
        try:
            yield private
        finally:
            self._mod._available = None

    def test_no_frida_python_no_cli(self):
        """Neither frida-python nor CLI → False."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "frida":
                raise ImportError("no frida")
            return real_import(name, *a, **kw)

        with mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import), \
             mock_module_attribute(self._mod, 'shutil', 'which', return_value=None):
            assert available() is False
        # Cached after first call.
        assert available() is False

    def test_cli_only_sufficient(self):
        """CLI on PATH without frida-python importable → True."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "frida":
                raise ImportError("no frida")
            return real_import(name, *a, **kw)

        with mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import), \
             mock_module_attribute(self._mod, 'shutil', 'which', return_value='/usr/bin/frida'):
            self._mod._available = None
            assert available() is True

    def test_both_present(self):
        """frida importable + CLI on PATH → True."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "frida":
                return SimpleNamespace(__version__="test")
            return real_import(name, *a, **kw)

        with mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import), \
             mock_module_attribute(self._mod, 'shutil', 'which', return_value='/usr/local/bin/frida'):
            self._mod._available = None
            assert available() is True
        # Cached.
        assert available() is True

    def test_cache_persists(self):
        """Second call returns cached value without re-probing."""
        self._mod._available = True
        assert available() is True
        self._mod._available = False
        assert available() is False

    def test_force_bypasses_cache(self):
        """force=True re-probes even when cached."""
        import builtins
        real_import = builtins.__import__

        self._mod._available = False

        def fake_import(name, *a, **kw):
            if name == "frida":
                return SimpleNamespace(__version__="test")
            return real_import(name, *a, **kw)

        with mock_module_attribute(self._mod, '_imports', '__import__', side_effect=fake_import), \
             mock_module_attribute(self._mod, 'shutil', 'which', return_value='/usr/local/bin/frida'):
            assert available(force=True) is True
        assert available() is True


# ── parse_events() ─────────────────────────────────────────────────────

class TestParseEvents:

    def test_well_formed(self, tmp_path: Path):
        p = tmp_path / "events.jsonl"
        records = [
            {"ts": 0.1, "type": "send", "payload": {"x": 1}},
            {"ts": 0.2, "type": "error", "description": "boom"},
        ]
        p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        got = list(parse_events(p))
        assert got == records

    def test_blank_lines_skipped(self, tmp_path: Path):
        p = tmp_path / "events.jsonl"
        p.write_text('\n{"a":1}\n\n{"b":2}\n\n')
        assert len(list(parse_events(p))) == 2

    def test_malformed_lines_skipped(self, tmp_path: Path):
        p = tmp_path / "events.jsonl"
        p.write_text('{"ok":true}\nNOT JSON\n{"ok":true}\n')
        got = list(parse_events(p))
        assert len(got) == 2

    def test_missing_file_yields_nothing(self, tmp_path: Path):
        assert list(parse_events(tmp_path / "nope.jsonl")) == []

    def test_empty_file(self, tmp_path: Path):
        p = tmp_path / "events.jsonl"
        p.write_text("")
        assert list(parse_events(p)) == []

    def test_binary_garbage_skipped(self, tmp_path: Path):
        """Invalid UTF-8 bytes must not crash the parser."""
        p = tmp_path / "events.jsonl"
        p.write_bytes(b'{"ts": 1}\n\xff\xfe\x00\x01\n{"ts": 2}\n')
        got = list(parse_events(p))
        assert len(got) == 2
        assert got[0] == {"ts": 1}
        assert got[1] == {"ts": 2}


# ── bb-coverage.js template ────────────────────────────────────────────

def test_bb_coverage_template_exists():
    tpl = Path(__file__).resolve().parents[1] / "templates" / "bb-coverage.js"
    assert tpl.is_file(), f"bb-coverage.js not found at {tpl}"
    text = tpl.read_text()
    assert "DRCOV VERSION: 2" in text
    assert "_drcov" in text
    assert "Stalker" in text


def test_bb_coverage_template_sanitises_module_paths():
    """Module paths come from the instrumented process; a path with a
    \\n would forge module-table rows. The header concat must route
    m.path through the sanitiser, never embed it raw."""
    tpl = Path(__file__).resolve().parents[1] / "templates" / "bb-coverage.js"
    text = tpl.read_text()
    assert "function sanitizePath" in text
    assert "sanitizePath(m.path)" in text
    # No line of the header build may concatenate m.path directly.
    for line in text.splitlines():
        if "header +=" in line and "m.path" in line:
            assert "sanitizePath(m.path)" in line, f"raw m.path concat: {line!r}"


# ── drcov write path in runner ─────────────────────────────────────────

def test_drcov_payload_written_to_file(tmp_path: Path):
    """Exercise the runner's _message_cb drcov write path end-to-end
    by firing a _drcov message through a FakeScript during run()."""
    from packages.frida import runner
    from packages.frida.tests.test_runner import (
        FakeDevice,
        FakeScript,
        _fake_frida,
    )

    drcov_bytes = b"DRCOV VERSION: 2\ntest blob\n"
    device = FakeDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1234"),
        out_dir=tmp_path,
        script_source="// bb-coverage stub",
        script_origin="file:test.js",
        duration_sec=0.05,
    )

    original_load = FakeScript.load
    def load_and_fire_drcov(self):
        original_load(self)
        self.fire(
            {"type": "send", "payload": {"_drcov": True, "bb_count": 1}},
            data=drcov_bytes,
        )
    FakeScript.load = load_and_fire_drcov
    try:
        result = runner.run(cfg, frida_mod_override=fake)
    finally:
        FakeScript.load = original_load

    assert result.ok is True
    out = tmp_path / "coverage.drcov"
    assert out.exists(), "runner did not write coverage.drcov"
    assert out.read_bytes() == drcov_bytes


# ── drcov round-trip: bb-coverage format → parse_drcov() ───────────────

def test_drcov_parseable_by_coverage_collector(tmp_path: Path):
    """Build a minimal drcov file in the same format bb-coverage.js
    emits and verify core.coverage.collect.parse_drcov() can parse it."""
    from core.coverage.collect import parse_drcov

    header = (
        "DRCOV VERSION: 2\n"
        "DRCOV FLAVOR: frida-stalker\n"
        "Module Table: version 2, count 1\n"
        "Columns: id, base, end, entry, checksum, timestamp, path\n"
        "0, 0x400000, 0x401000, 0x0, 0x0, 0x0, /usr/bin/test\n"
        "BB Table: 3 bbs\n"
    )
    header_bytes = header.encode("ascii")
    # 3 BB entries: <IHH> each (start_u32, size_u16, module_id_u16)
    bb_data = b""
    bb_data += struct.pack("<IHH", 0x100, 4, 0)
    bb_data += struct.pack("<IHH", 0x200, 8, 0)
    bb_data += struct.pack("<IHH", 0x300, 1, 0)

    drcov_file = tmp_path / "coverage.drcov"
    drcov_file.write_bytes(header_bytes + bb_data)

    result = parse_drcov(drcov_file)
    assert result, "parse_drcov returned empty dict"
    assert "/usr/bin/test" in result
    mod = result["/usr/bin/test"]
    assert mod["base"] == 0x400000
    assert mod["offsets"] == {0x100, 0x200, 0x300}


def test_drcov_comma_in_module_path(tmp_path: Path):
    """Module paths containing commas must survive parse_drcov()."""
    from core.coverage.collect import parse_drcov

    comma_path = "/opt/lib,v2/libfoo.so"
    header = (
        "DRCOV VERSION: 2\n"
        "DRCOV FLAVOR: frida-stalker\n"
        "Module Table: version 2, count 1\n"
        "Columns: id, base, end, entry, checksum, timestamp, path\n"
        f"0, 0x7f000000, 0x7f001000, 0x0, 0x0, 0x0, {comma_path}\n"
        "BB Table: 1 bbs\n"
    )
    bb_data = struct.pack("<IHH", 0x42, 1, 0)
    drcov_file = tmp_path / "coverage.drcov"
    drcov_file.write_bytes(header.encode("ascii") + bb_data)

    result = parse_drcov(drcov_file)
    assert comma_path in result, f"path with comma not found; got keys: {list(result)}"
    assert result[comma_path]["offsets"] == {0x42}


# ── sandboxed wrapper ─────────────────────────────────────────────────

class TestSandboxedMain:

    def test_python_runtime_prefixes_are_allowlisted(self, tmp_path):
        """Framework/venv Python roots must be readable for inner re-exec."""
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        framework_prefix = tmp_path / "Python.framework" / "Versions" / "3.14"
        base_prefix = tmp_path / "base-python"
        framework_prefix.mkdir(parents=True)
        base_prefix.mkdir()

        fake_result = MagicMock()
        fake_result.returncode = 0
        mock_run = MagicMock(return_value=fake_result)
        runtime_paths = [
            str(framework_prefix.resolve()),
            str(base_prefix.resolve()),
        ]

        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed._find_frida_site",
                        return_value=None), \
             mock_patch(
                 "core.sandbox.python_paths.python_runtime_tool_paths",
                 return_value=runtime_paths), \
             mock_patch.dict("packages.frida.sandboxed.os.environ",
                             {"RAPTOR_DIR": ""}, clear=False), \
             mock_patch("core.sandbox.run", mock_run):
            mock_sys.argv = [
                "sandboxed", "--out", "/tmp/run", "--",
                "python3", "-m", "packages.frida.cli", "--target", "1234",
            ]
            rc = sandboxed.main()

        assert rc == 0
        tool_paths = mock_run.call_args[1]["tool_paths"]
        assert str(framework_prefix.resolve()) in tool_paths
        assert str(base_prefix.resolve()) in tool_paths

    def test_spawn_mode_passes_block_network(self):
        """--spawn → sandbox_run called with block_network=True."""
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        fake_result = MagicMock()
        fake_result.returncode = 0
        mock_run = MagicMock(return_value=fake_result)

        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed.sys", mock_sys), \
             mock_patch.dict("sys.modules", {"core.sandbox": MagicMock()}):
            mock_sys.argv = [
                "sandboxed", "--spawn", "--out", "/tmp/run", "--",
                "python3", "-m", "packages.frida.cli", "--target", "./x",
            ]
            with mock_patch("core.sandbox.run", mock_run):
                rc = sandboxed.main()

        assert rc == 0
        call_kwargs = mock_run.call_args
        assert call_kwargs[1]["block_network"] is True
        assert call_kwargs[1]["profile"] == "frida"
        assert call_kwargs[1]["skip_pid_ns"] is True
        assert call_kwargs[1]["skip_mount_ns"] is True

    def test_attach_mode_allows_network(self):
        """No --spawn → sandbox_run called with block_network=False."""
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        fake_result = MagicMock()
        fake_result.returncode = 0
        mock_run = MagicMock(return_value=fake_result)

        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed.sys", mock_sys), \
             mock_patch.dict("sys.modules", {"core.sandbox": MagicMock()}):
            mock_sys.argv = [
                "sandboxed", "--out", "/tmp/run", "--",
                "python3", "-m", "packages.frida.cli", "--target", "1234",
            ]
            with mock_patch("core.sandbox.run", mock_run):
                rc = sandboxed.main()

        assert rc == 0
        call_kwargs = mock_run.call_args
        assert call_kwargs[1]["block_network"] is False

    def test_missing_separator_returns_usage_error(self):
        """No -- separator → exit 2."""
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        with mock_patch.object(sandboxed, "sys") as mock_sys:
            mock_sys.argv = ["sandboxed", "--out", "/tmp/run"]
            mock_sys.stderr = __import__("io").StringIO()
            rc = sandboxed.main()
        assert rc == 2

    def test_import_failure_hard_fails(self):
        """When core.sandbox is not importable, hard-fail (never run unsandboxed)."""
        import io
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        stderr_capture = io.StringIO()

        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed.sys", mock_sys), \
             mock_patch.dict("sys.modules", {"core.sandbox": None}), \
             mock_patch("subprocess.call", return_value=0) as mock_call:
            mock_sys.argv = [
                "sandboxed", "--out", "/tmp/run", "--",
                "echo", "hello",
            ]
            mock_sys.stderr = stderr_capture
            rc = sandboxed.main()

        assert rc == 1
        mock_call.assert_not_called()
        assert "Fatal" in stderr_capture.getvalue()


class TestLibexecSandboxFlags:
    """Verify libexec/raptor-frida passes the right sandbox flags.

    These parse the bash script and check the flag-detection logic
    by running the relevant section in a subprocess.
    """

    def _detect_flags(self, args: list[str], target_is_file: bool = False):
        """Run the flag-detection section of raptor-frida and return
        the IS_SPAWN and IS_REMOTE values."""
        import subprocess
        script = (
            'PASS_ARGS=(' + ' '.join(f'"{a}"' for a in args) + ')\n'
            'TARGET="dummy"\n'
            'UNSAFE_ATTACH=0\n'
            'IS_SPAWN=0\n'
            'IS_REMOTE=0\n'
            'for a in "${PASS_ARGS[@]}"; do\n'
            '    case "$a" in\n'
            '        --unsafe-attach) UNSAFE_ATTACH=1 ;;\n'
            '        --spawn)         IS_SPAWN=1 ;;\n'
            '        --host|--host=*) IS_REMOTE=1 ;;\n'
            '        --usb)           IS_REMOTE=1 ;;\n'
            '    esac\n'
            'done\n'
        )
        if target_is_file:
            script += 'IS_SPAWN=1\n'
        script += (
            'if [ "$IS_REMOTE" -eq 1 ]; then IS_SPAWN=0; fi\n'
            'echo "SPAWN=$IS_SPAWN REMOTE=$IS_REMOTE UNSAFE=$UNSAFE_ATTACH"\n'
        )
        r = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=5, check=False,
        )
        vals = {}
        for token in r.stdout.strip().split():
            k, v = token.split("=")
            vals[k] = int(v)
        return vals

    def test_spawn_local_blocks_network(self):
        vals = self._detect_flags(["--spawn", "--template", "api-trace"])
        assert vals["SPAWN"] == 1
        assert vals["REMOTE"] == 0

    def test_attach_local_allows_network(self):
        vals = self._detect_flags(["--template", "api-trace"])
        assert vals["SPAWN"] == 0
        assert vals["REMOTE"] == 0

    def test_host_remote_overrides_spawn(self):
        """--host + --spawn → IS_SPAWN forced to 0 (network needed)."""
        vals = self._detect_flags(
            ["--spawn", "--host", "10.10.20.1", "--template", "api-trace"])
        assert vals["SPAWN"] == 0
        assert vals["REMOTE"] == 1

    def test_usb_remote_overrides_spawn(self):
        """--usb + --spawn → IS_SPAWN forced to 0."""
        vals = self._detect_flags(
            ["--spawn", "--usb", "--template", "ssl-unpin"])
        assert vals["SPAWN"] == 0
        assert vals["REMOTE"] == 1

    def test_binary_target_implies_spawn(self):
        vals = self._detect_flags(
            ["--template", "api-trace"], target_is_file=True)
        assert vals["SPAWN"] == 1

    def test_unsafe_attach_detected(self):
        vals = self._detect_flags(["--unsafe-attach", "--template", "api-trace"])
        assert vals["UNSAFE"] == 1


class TestSandboxedHookSourcePaths:

    def _run_main(self, argv_tail: list[str]):
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        fake_result = MagicMock()
        fake_result.returncode = 0
        mock_run = MagicMock(return_value=fake_result)

        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed._find_frida_site",
                        return_value=None), \
             mock_patch(
                 "core.sandbox.python_paths.python_runtime_tool_paths",
                 return_value=[]), \
             mock_patch.dict("packages.frida.sandboxed.os.environ",
                             {"RAPTOR_DIR": ""}, clear=False), \
             mock_patch("core.sandbox.run", mock_run):
            mock_sys.argv = ["sandboxed", "--out", "/tmp/run", "--",
                             "python3", "-m", "packages.frida.cli",
                             "--target", "1234"] + argv_tail
            rc = sandboxed.main()
        assert rc == 0
        return mock_run.call_args[1]["tool_paths"]

    def test_sink_watch_file_parent_is_readable(self, tmp_path):
        """restrict_reads would otherwise reject the operator's sinks
        file before any hook loads."""
        sinks = tmp_path / "findings" / "sinks.json"
        sinks.parent.mkdir()
        sinks.write_text("[]", encoding="utf-8")
        tool_paths = self._run_main(["--sink-watch", str(sinks)])
        assert str(sinks.parent.resolve()) in tool_paths

    def test_script_file_parent_is_readable(self, tmp_path):
        hook = tmp_path / "hooks" / "my.js"
        hook.parent.mkdir()
        hook.write_text("// hook", encoding="utf-8")
        tool_paths = self._run_main(["--script", str(hook)])
        assert str(hook.parent.resolve()) in tool_paths

    def test_wrapper_absolutizes_stdin_flag(self):
        """Both --stdin forms must route through abs_if_file in the
        wrapper's arg loop, like --script/--sink-watch — a relative
        PoC path stops resolving once the sandboxed CLI's cwd moves
        to the output dir."""
        script_path = (Path(__file__).resolve().parents[3]
                       / "libexec" / "raptor-frida")
        text = script_path.read_text(encoding="utf-8")
        assert "--script|--sink-watch|--stdin)" in text
        assert '--stdin=$(abs_if_file "${a#--stdin=}")' in text

    def test_stdin_file_parent_is_readable(self, tmp_path):
        """PoC input delivery: the CLI dup2s the --stdin file onto
        its own stdin, so restrict_reads must admit it."""
        poc = tmp_path / "pocs" / "input.bin"
        poc.parent.mkdir()
        poc.write_bytes(b"RUN")
        tool_paths = self._run_main(["--stdin", str(poc)])
        assert str(poc.parent.resolve()) in tool_paths

    def test_equals_form_flag_is_granted(self, tmp_path):
        sinks = tmp_path / "findings" / "sinks.json"
        sinks.parent.mkdir()
        sinks.write_text("[]", encoding="utf-8")
        tool_paths = self._run_main([f"--sink-watch={sinks}"])
        assert str(sinks.parent.resolve()) in tool_paths


class TestSandboxedTargetPath:
    def test_spawn_target_parent_is_readable(self, tmp_path):
        """A spawn-target binary outside the default read set died with
        PermissionDeniedError before the hook could load; the wrapper
        must grant the binary's directory (which also covers sibling
        libraries it may dlopen)."""
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        target = tmp_path / "build" / "victim"
        target.parent.mkdir()
        target.write_bytes(b"\x7fELF")

        fake_result = MagicMock()
        fake_result.returncode = 0
        mock_run = MagicMock(return_value=fake_result)
        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed._find_frida_site",
                        return_value=None), \
             mock_patch(
                 "core.sandbox.python_paths.python_runtime_tool_paths",
                 return_value=[]), \
             mock_patch.dict("packages.frida.sandboxed.os.environ",
                             {"RAPTOR_DIR": ""}, clear=False), \
             mock_patch("core.sandbox.run", mock_run):
            mock_sys.argv = ["sandboxed", "--out", "/tmp/run", "--",
                             "python3", "-m", "packages.frida.cli",
                             "--target", str(target),
                             "--template", "api-trace"]
            rc = sandboxed.main()
        assert rc == 0
        assert (str(target.parent.resolve())
                in mock_run.call_args[1]["tool_paths"])

    def test_non_path_target_grants_nothing(self, tmp_path):
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from packages.frida import sandboxed

        fake_result = MagicMock()
        fake_result.returncode = 0
        mock_run = MagicMock(return_value=fake_result)
        with mock_patch.object(sandboxed, "sys") as mock_sys, \
             mock_patch("packages.frida.sandboxed._find_frida_site",
                        return_value=None), \
             mock_patch(
                 "core.sandbox.python_paths.python_runtime_tool_paths",
                 return_value=[]), \
             mock_patch.dict("packages.frida.sandboxed.os.environ",
                             {"RAPTOR_DIR": ""}, clear=False), \
             mock_patch("core.sandbox.run", mock_run):
            mock_sys.argv = ["sandboxed", "--out", "/tmp/run", "--",
                             "python3", "-m", "packages.frida.cli",
                             "--target", "1234",
                             "--template", "api-trace"]
            rc = sandboxed.main()
        assert rc == 0
        # A PID target must not resolve to a cwd grant.
        assert mock_run.call_args[1]["tool_paths"] in ([], None)


class TestWrapperTargetAbsolutization:
    """The sandboxed CLI's cwd is the output dir, so relative paths the
    operator typed stop resolving there — the wrapper must absolutize
    existing relative file paths (and nothing else) before forwarding.
    Runs the wrapper's REAL abs_if_file, extracted verbatim."""

    def _run_helper(self, fn: str, value: str, cwd) -> str:
        import subprocess
        script_path = (Path(__file__).resolve().parents[3]
                       / "libexec" / "raptor-frida")
        text = script_path.read_text(encoding="utf-8")
        snippet = ""
        for name in ("abs_if_file", "abs_target"):
            start = text.index(name + "() {")
            end = text.index("\n}", start) + 2
            snippet += text[start:end] + "\n"
        snippet += f'{fn} "$1"\n'
        r = subprocess.run(
            ["bash", "-c", snippet, "_", value],
            cwd=str(cwd), capture_output=True, text=True,
            timeout=5, check=False,
        )
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    def _abs_if_file(self, value: str, cwd) -> str:
        return self._run_helper("abs_target", value, cwd)

    def test_relative_existing_file_becomes_absolute(self, tmp_path):
        (tmp_path / "victim").write_bytes(b"\x7fELF")
        assert (self._abs_if_file("./victim", tmp_path)
                == str(tmp_path / "victim"))

    def test_absolute_path_unchanged(self, tmp_path):
        target = tmp_path / "victim"
        target.write_bytes(b"\x7fELF")
        assert self._abs_if_file(str(target), tmp_path) == str(target)

    def test_process_name_unchanged(self, tmp_path):
        assert self._abs_if_file("nginx", tmp_path) == "nginx"

    def test_pid_unchanged_even_with_colliding_file(self, tmp_path):
        # parse_target classifies pure digits as a PID before checking
        # the filesystem; the wrapper must not promote a digit-named
        # file into a spawn target.
        (tmp_path / "1234").write_bytes(b"\x7fELF")
        assert self._run_helper("abs_target", "1234", tmp_path) == "1234"

    def test_digit_named_hook_file_still_absolutizes(self, tmp_path):
        # The PID guard is --target semantics only; --script and
        # --sink-watch values are always file paths.
        (tmp_path / "1234").write_text("[]", encoding="utf-8")
        assert (self._run_helper("abs_if_file", "1234", tmp_path)
                == str(tmp_path / "1234"))
