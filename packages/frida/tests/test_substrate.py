"""Tests for frida substrate helpers: available(), parse_events(), bb-coverage
template existence, and drcov round-trip through core.coverage.collect."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packages.frida import available, parse_events


# ── available() ────────────────────────────────────────────────────────

class TestAvailable:
    """available() caches its result; reset between tests."""

    def setup_method(self):
        import packages.frida as _mod
        self._mod = _mod
        _mod._available = None   # reset cache

    def teardown_method(self):
        self._mod._available = None

    def test_no_frida_python_no_cli(self):
        """Neither frida-python nor CLI → False."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "frida":
                raise ImportError("no frida")
            return real_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=fake_import), \
             patch("shutil.which", return_value=None):
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

        with patch("builtins.__import__", side_effect=fake_import), \
             patch("shutil.which", return_value="/usr/bin/frida"):
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

        with patch("builtins.__import__", side_effect=fake_import), \
             patch("shutil.which", return_value="/usr/local/bin/frida"):
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

        with patch("builtins.__import__", side_effect=fake_import), \
             patch("shutil.which", return_value="/usr/local/bin/frida"):
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


# ── drcov write path in runner ─────────────────────────────────────────

def test_drcov_payload_written_to_file(tmp_path: Path):
    """Exercise the runner's _message_cb drcov write path end-to-end
    by firing a _drcov message through a FakeScript during run()."""
    from packages.frida import runner
    from packages.frida.tests.test_runner import (
        FakeDevice, FakeScript, _fake_frida,
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
        from unittest.mock import MagicMock, patch as mock_patch
        import packages.frida.sandboxed as sandboxed

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
        from unittest.mock import MagicMock, patch as mock_patch
        import packages.frida.sandboxed as sandboxed

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
        from unittest.mock import MagicMock, patch as mock_patch
        import packages.frida.sandboxed as sandboxed

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
        import packages.frida.sandboxed as sandboxed
        from unittest.mock import patch as mock_patch

        with mock_patch.object(sandboxed, "sys") as mock_sys:
            mock_sys.argv = ["sandboxed", "--out", "/tmp/run"]
            mock_sys.stderr = __import__("io").StringIO()
            rc = sandboxed.main()
        assert rc == 2

    def test_import_failure_hard_fails(self):
        """When core.sandbox is not importable, hard-fail (never run unsandboxed)."""
        import io
        from unittest.mock import patch as mock_patch
        import packages.frida.sandboxed as sandboxed

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
        assert "FATAL" in stderr_capture.getvalue()


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
            capture_output=True, text=True, timeout=5,
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
