"""compile_commands.json → sanitized c2cpg frontend args.

The database ships with the scanned repo, so every test that exercises
extraction is really testing the untrusted-input surface: charset
allowlists, root containment, conflict-drop, caps.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import packages.joern.runner as runner_mod
from packages.joern.runner import (
    FrontendArgs,
    build_cpg,
    build_cpg_cached,
    discover_frontend_args,
    find_compile_commands,
    load_cached_cpg,
)


def _write_db(root: Path, entries, subdir: str = "") -> Path:
    d = root / subdir if subdir else root
    d.mkdir(parents=True, exist_ok=True)
    db = d / "compile_commands.json"
    db.write_text(json.dumps(entries) if not isinstance(entries, str)
                  else entries)
    return db


def _entry(root: Path, args: list) -> dict:
    return {
        "directory": str(root),
        "file": str(root / "a.c"),
        "arguments": ["cc", *args, "a.c"],
    }


class TestFindCompileCommands:
    def test_absent(self, tmp_path):
        assert find_compile_commands(tmp_path) is None

    def test_root(self, tmp_path):
        db = _write_db(tmp_path, [])
        assert find_compile_commands(tmp_path) == db

    def test_build_subdir(self, tmp_path):
        db = _write_db(tmp_path, [], subdir="build")
        assert find_compile_commands(tmp_path) == db

    def test_cmake_build_glob(self, tmp_path):
        db = _write_db(tmp_path, [], subdir="cmake-build-debug")
        assert find_compile_commands(tmp_path) == db

    def test_root_wins_over_build(self, tmp_path):
        root_db = _write_db(tmp_path, [])
        _write_db(tmp_path, [], subdir="build")
        assert find_compile_commands(tmp_path) == root_db


class TestDiscoverFrontendArgs:
    def test_absent_gives_empty(self, tmp_path):
        fa = discover_frontend_args(tmp_path)
        assert not fa
        assert fa.to_argv() == []
        assert fa.fingerprint() == ""

    def test_defines_and_includes(self, tmp_path):
        inc = tmp_path / "include"
        inc.mkdir()
        _write_db(tmp_path, [_entry(tmp_path, [
            "-DFOO=1", "-DBAR", "-Iinclude", "-D", "BAZ=2",
        ])])
        fa = discover_frontend_args(tmp_path)
        assert fa.defines == ("BAR", "BAZ=2", "FOO=1")
        assert fa.includes == (str(inc.resolve()),)

    def test_command_string_entry(self, tmp_path):
        inc = tmp_path / "hdrs"
        inc.mkdir()
        _write_db(tmp_path, [{
            "directory": str(tmp_path),
            "file": str(tmp_path / "a.c"),
            "command": f"cc -DX=y -I {inc} -c a.c",
        }])
        fa = discover_frontend_args(tmp_path)
        assert fa.defines == ("X=y",)
        assert fa.includes == (str(inc.resolve()),)

    def test_isystem(self, tmp_path):
        inc = tmp_path / "sys"
        inc.mkdir()
        _write_db(tmp_path, [_entry(tmp_path, [f"-isystem{inc}"])])
        assert discover_frontend_args(tmp_path).includes == (
            str(inc.resolve()),)

    def test_malformed_json_gives_empty(self, tmp_path):
        _write_db(tmp_path, "{not json")
        assert not discover_frontend_args(tmp_path)

    def test_non_list_gives_empty(self, tmp_path):
        _write_db(tmp_path, "{}")
        assert not discover_frontend_args(tmp_path)

    def test_oversized_gives_empty(self, tmp_path, monkeypatch):
        _write_db(tmp_path, [_entry(tmp_path, ["-DFOO"])])
        monkeypatch.setattr(runner_mod, "_CC_MAX_BYTES", 4)
        assert not discover_frontend_args(tmp_path)

    def test_hostile_define_values_rejected(self, tmp_path):
        _write_db(tmp_path, [_entry(tmp_path, [
            '-DQUOTED="v"',
            "-DSPACED=a b",
            "-DSEMI=x;rm",
            "-DBACKTICK=`id`",
            "-DDOLLAR=$(id)",
            "-DOK=safe.value-1",
        ])])
        assert discover_frontend_args(tmp_path).defines == ("OK=safe.value-1",)

    def test_hostile_define_names_rejected(self, tmp_path):
        _write_db(tmp_path, [_entry(tmp_path, ["-Dbad-name=1", "-D=1"])])
        assert not discover_frontend_args(tmp_path)

    def test_include_escaping_root_rejected(self, tmp_path):
        outside = tmp_path.parent / "outside-hdrs"
        outside.mkdir(exist_ok=True)
        target = tmp_path / "repo"
        target.mkdir()
        _write_db(target, [_entry(target, [
            f"-I{outside}", "-I../outside-hdrs", "-I/etc",
        ])])
        assert discover_frontend_args(target).includes == ()

    def test_include_symlink_escape_rejected(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        target = tmp_path / "repo"
        target.mkdir()
        os.symlink(outside, target / "sneaky")
        _write_db(target, [_entry(target, ["-Isneaky"])])
        assert discover_frontend_args(target).includes == ()

    def test_missing_include_dir_rejected(self, tmp_path):
        _write_db(tmp_path, [_entry(tmp_path, ["-Ino-such-dir"])])
        assert discover_frontend_args(tmp_path).includes == ()

    def test_define_undef_conflict_dropped(self, tmp_path):
        _write_db(tmp_path, [
            _entry(tmp_path, ["-DFLAG=1", "-DKEEP=1"]),
            _entry(tmp_path, ["-UFLAG"]),
        ])
        assert discover_frontend_args(tmp_path).defines == ("KEEP=1",)

    def test_caps_applied_and_logged(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(runner_mod, "_CC_MAX_DEFINES", 2)
        _write_db(tmp_path, [_entry(tmp_path, ["-DA", "-DB", "-DC"])])
        with caplog.at_level("INFO"):
            fa = discover_frontend_args(tmp_path)
        assert len(fa.defines) == 2
        assert "capping defines" in caplog.text

    def test_fingerprint_tracks_content(self, tmp_path):
        _write_db(tmp_path, [_entry(tmp_path, ["-DA=1"])])
        fp1 = discover_frontend_args(tmp_path).fingerprint()
        _write_db(tmp_path, [_entry(tmp_path, ["-DA=2"])])
        fp2 = discover_frontend_args(tmp_path).fingerprint()
        assert fp1 and fp2 and fp1 != fp2


class TestFrontendArgsArgv:
    def test_argv_shape(self):
        fa = FrontendArgs(defines=("A=1", "B"), includes=("/t/inc",))
        assert fa.to_argv() == [
            "--frontend-args",
            "--define", "A=1", "--define", "B",
            "--include", "/t/inc",
        ]

    def test_empty_argv(self):
        assert FrontendArgs().to_argv() == []


class TestBuildCpgWiring:
    def _capture_runner(self, calls):
        def fake_runner(cmd, **kw):
            calls.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return fake_runner

    def test_c_language_appends_frontend_tail(self, tmp_path):
        inc = tmp_path / "include"
        inc.mkdir()
        _write_db(tmp_path, [_entry(tmp_path, ["-DFOO=1", "-Iinclude"])])
        calls = []
        build_cpg(tmp_path, languages={"c"},
                  subprocess_runner=self._capture_runner(calls))
        cmd = calls[0]
        sep = cmd.index("--frontend-args")
        tail = cmd[sep + 1:]
        assert tail == ["--define", "FOO=1",
                        "--include", str(inc.resolve())]

    def test_non_c_language_skips_discovery(self, tmp_path):
        _write_db(tmp_path, [_entry(tmp_path, ["-DFOO=1"])])
        calls = []
        build_cpg(tmp_path, languages={"pythonsrc"},
                  subprocess_runner=self._capture_runner(calls))
        assert "--frontend-args" not in calls[0]

    def test_explicit_empty_disables(self, tmp_path):
        _write_db(tmp_path, [_entry(tmp_path, ["-DFOO=1"])])
        calls = []
        build_cpg(tmp_path, languages={"c"}, frontend_args=FrontendArgs(),
                  subprocess_runner=self._capture_runner(calls))
        assert "--frontend-args" not in calls[0]

    def test_no_database_no_tail(self, tmp_path):
        calls = []
        build_cpg(tmp_path, languages={"c"},
                  subprocess_runner=self._capture_runner(calls))
        assert "--frontend-args" not in calls[0]


class TestCacheKey:
    def _build_runner(self, cache_dir, calls):
        # Fake joern-parse: records argv and materializes cpg.bin so the
        # cached-build path writes its manifest.
        def fake_runner(cmd, **kw):
            calls.append(cmd)
            out = cmd[cmd.index("--output") + 1]
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            Path(out).write_bytes(b"cpg")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return fake_runner

    def test_flags_change_invalidates_cache(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.c").write_text("int main(){}")
        cache = tmp_path / "cache"
        cache.mkdir()
        _write_db(target, [_entry(target, ["-DA=1"])])
        calls = []
        build_cpg_cached(target, cache, languages={"c"},
                         subprocess_runner=self._build_runner(cache, calls))
        assert len(calls) == 1
        # Unchanged → cache hit, no second build.
        build_cpg_cached(target, cache, languages={"c"},
                         subprocess_runner=self._build_runner(cache, calls))
        assert len(calls) == 1
        # Flags change → rebuild even though sources are unchanged.
        _write_db(target, [_entry(target, ["-DA=2"])])
        build_cpg_cached(target, cache, languages={"c"},
                         subprocess_runner=self._build_runner(cache, calls))
        assert len(calls) == 2

    def test_readonly_load_skips_fingerprint_check(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.c").write_text("int main(){}")
        cache = tmp_path / "cache"
        cache.mkdir()
        _write_db(target, [_entry(target, ["-DA=1"])])
        calls = []
        build_cpg_cached(target, cache, languages={"c"},
                         subprocess_runner=self._build_runner(cache, calls))
        _write_db(target, [_entry(target, ["-DA=2"])])
        # None → read-only consumer contract: content hash only.
        assert load_cached_cpg(target, cache) is not None
        assert load_cached_cpg(
            target, cache,
            expected_frontend_fingerprint="different",
        ) is None
