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

    def test_no_frida_python(self):
        """ImportError on frida-python → False."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "frida":
                raise ImportError("no frida")
            return real_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=fake_import):
            assert available() is False
        # Cached after first call.
        assert available() is False

    def test_frida_python_but_no_cli(self):
        """frida importable but CLI missing → False."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "frida":
                return SimpleNamespace(__version__="test")
            return real_import(name, *a, **kw)

        with patch("builtins.__import__", side_effect=fake_import), \
             patch("shutil.which", return_value=None):
            self._mod._available = None
            assert available() is False

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
    import threading
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
        threading.Timer(0.01, lambda: self.fire(
            {"type": "send", "payload": {"_drcov": True, "bb_count": 1}},
            data=drcov_bytes,
        )).start()
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
