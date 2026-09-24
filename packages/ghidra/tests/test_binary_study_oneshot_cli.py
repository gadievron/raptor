"""raptor-binary-study-oneshot: sequencing over the existing tools.

The stub is GLUE only — these tests pin that it refuses non-binary
input, reuses a cached database instead of re-importing, propagates
a terminal import failure without starting the study, and hands the
study the exact database + .gpr the import produced.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_cli(monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_binary_study_oneshot_test",
        str(REPO_ROOT / "libexec" / "raptor-binary-study-oneshot"),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _capture_runs(mod, monkeypatch, *, rcs: dict[str, int] | None = None):
    """Record child invocations; fake per-tool exit codes.

    On a faked import success, materialize the artifacts the real
    import child would leave (re-database.json + the onramp's .gpr)
    so the stub's hand-off logic sees a truthful filesystem.
    """
    calls: list[list[str]] = []
    rcs = rcs or {}

    def fake_run(cmd: list[str]) -> int:
        calls.append([str(c) for c in cmd])
        tool = Path(cmd[1]).name
        rc = rcs.get(tool, 0)
        if tool == "raptor-ghidra" and rc == 0:
            out = Path(cmd[cmd.index("--out") + 1])
            binary = Path(cmd[3])
            out.mkdir(parents=True, exist_ok=True)
            (out / "re-database.json").write_text(
                json.dumps({"functions": []}), encoding="utf-8")
            gpr_dir = out / "ghidra-project" / binary.stem
            gpr_dir.mkdir(parents=True, exist_ok=True)
            (gpr_dir / "raptor.gpr").write_text("", encoding="utf-8")
        return rc

    monkeypatch.setattr(mod, "_run", fake_run)
    return calls


class TestInputRefusals:
    def test_missing_binary(self, monkeypatch, tmp_path, capsys):
        mod = _load_cli(monkeypatch)
        monkeypatch.setattr(
            "sys.argv",
            ["x", str(tmp_path / "nope"), str(tmp_path / "out")])
        assert mod.main() == 1
        assert "binary not found" in capsys.readouterr().err

    def test_gpr_and_json_refused(self, monkeypatch, tmp_path, capsys):
        mod = _load_cli(monkeypatch)
        for name in ("p.gpr", "re-database.json"):
            path = tmp_path / name
            path.write_text("", encoding="utf-8")
            monkeypatch.setattr(
                "sys.argv", ["x", str(path), str(tmp_path / "out")])
            assert mod.main() == 1
            assert "not a raw binary" in capsys.readouterr().err


class TestSequencing:
    def test_import_then_study_with_gpr_handoff(
            self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        import packages.ghidra.roundtrip as roundtrip
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda _p: [])
        binary = tmp_path / "demo"
        binary.write_bytes(b"\x7fELF")
        out = tmp_path / "out"
        calls = _capture_runs(mod, monkeypatch)
        monkeypatch.setattr(
            "sys.argv",
            ["x", str(binary), str(out), "--identifier", "a,b",
             "--max-cost", "2.5", "--no-bridge-seeds"])
        assert mod.main() == 0
        assert [Path(c[1]).name for c in calls] == [
            "raptor-ghidra", "raptor-binary-study"]
        ghidra_cmd, study_cmd = calls
        assert ghidra_cmd[2:4] == ["import", str(binary)]
        assert "--decompile-all" in ghidra_cmd
        # Study gets the produced database, the run's output dir,
        # the created .gpr, and the passthrough flags.
        assert study_cmd[2] == str(out / "ghidra-import"
                                   / "re-database.json")
        assert study_cmd[3] == str(out)
        assert "--gpr" in study_cmd
        gpr = Path(study_cmd[study_cmd.index("--gpr") + 1])
        assert gpr.name == "raptor.gpr" and gpr.is_file()
        assert study_cmd[study_cmd.index("--identifier") + 1] == "a,b"
        assert study_cmd[study_cmd.index("--max-cost") + 1] == "2.5"
        assert "--no-bridge-seeds" in study_cmd

    def test_cached_database_skips_import(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        cached = tmp_path / "cache" / "re-database.json"
        cached.parent.mkdir()
        cached.write_text(json.dumps({"functions": []}),
                          encoding="utf-8")
        import packages.ghidra.roundtrip as roundtrip
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda _p: [cached])
        binary = tmp_path / "demo"
        binary.write_bytes(b"\x7fELF")
        calls = _capture_runs(mod, monkeypatch)
        monkeypatch.setattr(
            "sys.argv", ["x", str(binary), str(tmp_path / "out")])
        assert mod.main() == 0
        assert [Path(c[1]).name for c in calls] == [
            "raptor-binary-study"]
        assert calls[0][2] == str(cached)
        # The cache dir has no onramp .gpr — the flag must be absent
        # rather than pointing at nothing.
        assert "--gpr" not in calls[0]

    def test_wrong_anchor_cache_falls_through_to_import(
            self, monkeypatch, tmp_path, capsys):
        """A stem-keyed cache for a DIFFERENT build (or a rebuilt
        binary) must not silently redirect the study — the content
        anchor is the identity check the fid keystone provides."""
        mod = _load_cli(monkeypatch)
        binary = tmp_path / "demo"
        binary.write_bytes(b"\x7fELF-stale-check")
        stale = tmp_path / "cache" / "re-database.json"
        stale.parent.mkdir()
        stale.write_text(json.dumps({"functions": [
            {"name": "a", "address": 0x1010, "size": 1,
             "fid": "1111222233334444:0x10"},
        ]}), encoding="utf-8")
        import packages.ghidra.roundtrip as roundtrip
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda _p: [stale])
        calls = _capture_runs(mod, monkeypatch)
        monkeypatch.setattr(
            "sys.argv", ["x", str(binary), str(tmp_path / "out")])
        assert mod.main() == 0
        # Import ran (cache rejected), then the study.
        assert [Path(c[1]).name for c in calls] == [
            "raptor-ghidra", "raptor-binary-study"]
        assert "content-anchor mismatch" in capsys.readouterr().err

    def test_matching_anchor_cache_is_reused(self, monkeypatch,
                                             tmp_path):
        mod = _load_cli(monkeypatch)
        binary = tmp_path / "demo"
        binary.write_bytes(b"\x7fELF-match-check")
        from core.binary.addrmap import content_anchor
        anchor = content_anchor(binary)
        assert anchor  # sha256-derived for a non-build-id file
        cached = tmp_path / "cache" / "re-database.json"
        cached.parent.mkdir()
        cached.write_text(json.dumps({"functions": [
            {"name": "a", "address": 0x1010, "size": 1,
             "fid": f"{anchor}:0x10"},
        ]}), encoding="utf-8")
        import packages.ghidra.roundtrip as roundtrip
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda _p: [cached])
        calls = _capture_runs(mod, monkeypatch)
        monkeypatch.setattr(
            "sys.argv", ["x", str(binary), str(tmp_path / "out")])
        assert mod.main() == 0
        assert [Path(c[1]).name for c in calls] == [
            "raptor-binary-study"]
        assert calls[0][2] == str(cached)

    def test_import_failure_is_terminal(self, monkeypatch, tmp_path,
                                        capsys):
        # Covers the occupied-destination refusal too: raptor-ghidra
        # exits nonzero and the stub must NOT degrade or start the
        # study.
        mod = _load_cli(monkeypatch)
        import packages.ghidra.roundtrip as roundtrip
        monkeypatch.setattr(
            roundtrip, "redb_cache_candidates", lambda _p: [])
        binary = tmp_path / "demo"
        binary.write_bytes(b"\x7fELF")
        calls = _capture_runs(mod, monkeypatch,
                              rcs={"raptor-ghidra": 1})
        monkeypatch.setattr(
            "sys.argv", ["x", str(binary), str(tmp_path / "out")])
        assert mod.main() == 1
        assert [Path(c[1]).name for c in calls] == ["raptor-ghidra"]
        assert "not starting the study" in capsys.readouterr().err
