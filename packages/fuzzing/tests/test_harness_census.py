"""Tests for the multi-engine fuzz-harness census."""

import os
import subprocess

import pytest

from packages.fuzzing.harness_census import (
    ENGINE_AFL,
    ENGINE_ATHERIS,
    ENGINE_CARGO_FUZZ,
    ENGINE_LIBFUZZER,
    EngineCensus,
    FuzzHarnessCensus,
    census_fuzz_harnesses,
)
from packages.fuzzing import harness_census as census_mod


# ── fixture builders ─────────────────────────────────────────────────

def _cargo_fuzz_repo(root, names=("parse_header",)):
    (root / "Cargo.toml").write_text("[package]\nname = \"demo\"\n")
    fuzz = root / "fuzz"
    (fuzz / "fuzz_targets").mkdir(parents=True, exist_ok=True)
    (fuzz / "Cargo.toml").write_text("[package]\nname = \"demo-fuzz\"\n")
    for name in names:
        (fuzz / "fuzz_targets" / f"{name}.rs").write_text(
            "fuzz_target!(|data: &[u8]| {});\n")
    return root


def _libfuzzer_repo(root, names=("fuzz_decode",)):
    d = root / "tests" / "fuzz"
    d.mkdir(parents=True)
    for name in names:
        (d / f"{name}.c").write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n)"
            " { return 0; }\n")
    return root


def _afl_repo(root):
    d = root / "fuzzing"
    d.mkdir(parents=True)
    (d / "afl_harness.c").write_text(
        "int main(void) { while (__AFL_LOOP(1000)) {} return 0; }\n")
    return root


def _atheris_repo(root):
    d = root / "fuzz"
    d.mkdir(parents=True, exist_ok=True)
    (d / "fuzz_json.py").write_text(
        "import atheris\n\ndef TestOneInput(data):\n    pass\n")
    return root


def _by_engine(census: FuzzHarnessCensus) -> dict[str, EngineCensus]:
    return {e.engine: e for e in census.engines}


# ── per-engine fixtures ──────────────────────────────────────────────

class TestEngines:
    def test_cargo_fuzz_layout(self, tmp_path):
        _cargo_fuzz_repo(tmp_path, names=("parse_header", "decode"))
        census = census_fuzz_harnesses(tmp_path)
        eng = _by_engine(census)
        assert set(eng) == {ENGINE_CARGO_FUZZ}
        assert eng[ENGINE_CARGO_FUZZ].count == 2
        assert sorted(eng[ENGINE_CARGO_FUZZ].examples) == \
            ["decode", "parse_header"]
        assert str(tmp_path) in eng[ENGINE_CARGO_FUZZ].invocation_hint
        assert census.total_harnesses == 2
        assert not census.truncated

    def test_cargo_fuzz_requires_manifest(self, tmp_path):
        # fuzz_targets/*.rs WITHOUT a sibling-crate Cargo.toml is not
        # the cargo-fuzz layout.
        d = tmp_path / "fuzz" / "fuzz_targets"
        d.mkdir(parents=True)
        (d / "orphan.rs").write_text("fn main() {}\n")
        census = census_fuzz_harnesses(tmp_path)
        assert census.engines == []

    def test_libfuzzer_c_harness(self, tmp_path):
        _libfuzzer_repo(tmp_path)
        eng = _by_engine(census_fuzz_harnesses(tmp_path))
        assert set(eng) == {ENGINE_LIBFUZZER}
        assert eng[ENGINE_LIBFUZZER].count == 1
        assert eng[ENGINE_LIBFUZZER].examples == ["fuzz_decode"]

    def test_afl_harness_and_precedence(self, tmp_path):
        # A file with BOTH AFL markers and a libFuzzer entry counts
        # once, as AFL (AFL markers are the more specific signal).
        d = tmp_path / "fuzz"
        d.mkdir()
        (d / "both.c").write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);\n"
            "int main(void) { while (__AFL_LOOP(1000)) {} }\n")
        eng = _by_engine(census_fuzz_harnesses(tmp_path))
        assert set(eng) == {ENGINE_AFL}
        assert eng[ENGINE_AFL].count == 1

    def test_afl_repo(self, tmp_path):
        _afl_repo(tmp_path)
        eng = _by_engine(census_fuzz_harnesses(tmp_path))
        assert set(eng) == {ENGINE_AFL}

    def test_atheris_python_harness(self, tmp_path):
        _atheris_repo(tmp_path)
        eng = _by_engine(census_fuzz_harnesses(tmp_path))
        assert set(eng) == {ENGINE_ATHERIS}
        assert eng[ENGINE_ATHERIS].examples == ["fuzz_json"]
        assert "--py-harness" in eng[ENGINE_ATHERIS].invocation_hint

    def test_polyglot_combo(self, tmp_path):
        _cargo_fuzz_repo(tmp_path)
        _libfuzzer_repo(tmp_path)
        _atheris_repo(tmp_path)
        census = census_fuzz_harnesses(tmp_path)
        eng = _by_engine(census)
        assert set(eng) == {
            ENGINE_CARGO_FUZZ, ENGINE_LIBFUZZER, ENGINE_ATHERIS,
        }
        assert census.total_harnesses == 3

    def test_empty_repo(self, tmp_path):
        census = census_fuzz_harnesses(tmp_path)
        assert census.engines == []
        assert census.total_harnesses == 0
        assert ENGINE_CARGO_FUZZ in census.engines_checked
        assert ENGINE_ATHERIS in census.engines_checked
        assert not census.truncated

    def test_nonexistent_path_yields_empty_census(self, tmp_path):
        census = census_fuzz_harnesses(tmp_path / "missing")
        assert census.engines == []
        assert census.engines_checked  # still enumerates the vocabulary

    def test_non_fuzz_hinted_files_not_sniffed(self, tmp_path):
        # A libFuzzer entry point outside any fuzz-hinted location is
        # invisible by design (content sniffs stay proportional to
        # the fuzzing surface).
        d = tmp_path / "src"
        d.mkdir()
        (d / "decoder.c").write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);\n")
        assert census_fuzz_harnesses(tmp_path).engines == []


# ── hostile-name discipline ──────────────────────────────────────────

class TestHostileNames:
    def test_hostile_names_counted_never_exemplified(self, tmp_path):
        _cargo_fuzz_repo(tmp_path, names=("ok_target",))
        evil = tmp_path / "fuzz" / "fuzz_targets" / "e\x1b]0;pwn\x07vil.rs"
        evil.write_text("fn main() {}\n")
        census = census_fuzz_harnesses(tmp_path)
        eng = _by_engine(census)
        assert eng[ENGINE_CARGO_FUZZ].count == 2
        assert eng[ENGINE_CARGO_FUZZ].examples == ["ok_target"]
        for example in eng[ENGINE_CARGO_FUZZ].examples:
            assert all(31 < ord(c) < 127 for c in example)

    def test_overlong_names_withheld(self, tmp_path):
        long_name = "a" * 200
        _cargo_fuzz_repo(tmp_path, names=(long_name,))
        eng = _by_engine(census_fuzz_harnesses(tmp_path))
        assert eng[ENGINE_CARGO_FUZZ].count == 1
        assert eng[ENGINE_CARGO_FUZZ].examples == []

    def test_examples_capped_at_three(self, tmp_path):
        _cargo_fuzz_repo(
            tmp_path, names=tuple(f"target_{i}" for i in range(7)))
        eng = _by_engine(census_fuzz_harnesses(tmp_path))
        assert eng[ENGINE_CARGO_FUZZ].count == 7
        assert len(eng[ENGINE_CARGO_FUZZ].examples) == 3

    def test_symlinked_harness_never_read(self, tmp_path):
        secret = tmp_path / "outside.txt"
        secret.write_text("import atheris\n")
        d = tmp_path / "repo" / "fuzz"
        d.mkdir(parents=True)
        os.symlink(secret, d / "fuzz_link.py")
        assert census_fuzz_harnesses(tmp_path / "repo").engines == []

    def test_fifo_planted_as_harness_never_blocks(self, tmp_path):
        # A FIFO named like a harness must not block the census (a
        # plain open(2) on a writer-less FIFO hangs forever).
        d = tmp_path / "fuzz"
        d.mkdir()
        os.mkfifo(d / "fuzz_trap.c")
        assert census_fuzz_harnesses(tmp_path).engines == []

    def test_post_open_fstat_is_the_toctou_belt(self, tmp_path,
                                                monkeypatch):
        # Force the lstat pre-check to lie (simulating a regular-
        # file → FIFO swap between lstat and open): the post-open
        # fstat re-check must still refuse the FIFO, and the
        # O_NONBLOCK open must not hang on it.
        fifo = tmp_path / "swapped.c"
        os.mkfifo(fifo)
        monkeypatch.setattr(
            census_mod, "_lstat_is_regular", lambda _path: True)
        assert census_mod._sniff(fifo) is None


# ── bounds ───────────────────────────────────────────────────────────

class TestBounds:
    def test_sniff_cap_sets_truncated(self, tmp_path, monkeypatch):
        monkeypatch.setattr(census_mod, "_MAX_SNIFF_FILES", 2)
        d = tmp_path / "fuzz"
        d.mkdir()
        for i in range(5):
            (d / f"fuzz_{i}.c").write_text(
                "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);\n")
        census = census_fuzz_harnesses(tmp_path)
        assert census.truncated
        assert _by_engine(census)[ENGINE_LIBFUZZER].count == 2

    def test_walk_cap_sets_truncated(self, tmp_path, monkeypatch):
        monkeypatch.setattr(census_mod, "_MAX_WALK_ENTRIES", 3)
        _cargo_fuzz_repo(
            tmp_path, names=tuple(f"target_{i}" for i in range(10)))
        assert census_fuzz_harnesses(tmp_path).truncated

    def test_dir_heavy_tree_counts_against_walk_cap(
            self, tmp_path, monkeypatch):
        # Directories tick the walk budget too: a tree of MANY empty
        # dirs and few files must still truncate rather than walk
        # unbounded with truncated=False.
        monkeypatch.setattr(census_mod, "_MAX_WALK_ENTRIES", 10)
        for i in range(25):
            (tmp_path / f"d{i:03d}").mkdir()
        census = census_fuzz_harnesses(tmp_path)
        assert census.truncated
        assert census.engines == []

    def test_skip_dirs_pruned(self, tmp_path):
        d = tmp_path / "vendor" / "fuzz"
        d.mkdir(parents=True)
        (d / "fuzz_x.c").write_text(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);\n")
        assert census_fuzz_harnesses(tmp_path).engines == []

    def test_to_dict_shape(self, tmp_path):
        _cargo_fuzz_repo(tmp_path)
        doc = census_fuzz_harnesses(tmp_path).to_dict()
        assert doc["total_harnesses"] == 1
        assert doc["engines"][0]["engine"] == ENGINE_CARGO_FUZZ
        assert doc["engines_checked"]
        assert doc["truncated"] is False


# ── read-only pin ────────────────────────────────────────────────────

class TestReadOnlyPin:
    def test_census_spawns_nothing_and_writes_nothing(
            self, tmp_path, monkeypatch):
        _cargo_fuzz_repo(tmp_path)
        _libfuzzer_repo(tmp_path)
        _atheris_repo(tmp_path)
        _afl_repo(tmp_path)

        def _explode(*a, **k):  # pragma: no cover - trap
            raise AssertionError("census must not spawn processes")

        monkeypatch.setattr(subprocess.Popen, "__init__", _explode)
        monkeypatch.setattr(os, "system", _explode)
        for name in ("spawnv", "spawnve", "posix_spawn", "fork"):
            if hasattr(os, name):
                monkeypatch.setattr(os, name, _explode)

        real_os_open = os.open
        write_flags = (
            os.O_WRONLY | os.O_RDWR | getattr(os, "O_CREAT", 0)
            | getattr(os, "O_TRUNC", 0) | getattr(os, "O_APPEND", 0)
        )

        def _guarded_open(path, flags, *a, **k):
            assert not (flags & write_flags), \
                f"census opened {path!r} with write flags"
            return real_os_open(path, flags, *a, **k)

        monkeypatch.setattr(os, "open", _guarded_open)

        real_open = open

        def _guarded_builtin_open(file, mode="r", *a, **k):
            assert not any(c in str(mode) for c in "wax+"), \
                f"census opened {file!r} for writing"
            return real_open(file, mode, *a, **k)

        import builtins
        monkeypatch.setattr(builtins, "open", _guarded_builtin_open)

        census = census_fuzz_harnesses(tmp_path)
        assert census.total_harnesses == 4

    def test_extra_engine_sweep_failure_isolated(
            self, tmp_path, monkeypatch):
        def _boom(_root):
            raise RuntimeError("engine arm exploded")

        monkeypatch.setattr(
            census_mod, "_EXTRA_ENGINE_SWEEPS",
            (("exploding-engine", "/fuzz --binary {path}", _boom),),
        )
        _cargo_fuzz_repo(tmp_path)
        census = census_fuzz_harnesses(tmp_path)
        assert "exploding-engine" in census.engines_checked
        assert _by_engine(census)[ENGINE_CARGO_FUZZ].count == 1

    def test_extra_engine_sweep_names_vetted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            census_mod, "_EXTRA_ENGINE_SWEEPS",
            (("stub-engine", "/fuzz --binary {path}",
              lambda _root: ["GoodTarget", "bad\x1bname", "x" * 200]),),
        )
        census = census_fuzz_harnesses(tmp_path)
        eng = _by_engine(census)
        assert eng["stub-engine"].count == 3
        assert eng["stub-engine"].examples == ["GoodTarget"]

    def test_extra_sweep_reusing_builtin_name_merges(
            self, tmp_path, monkeypatch):
        # A seam entry reusing a built-in engine name never double-
        # lists the vocabulary; its targets merge into that tally.
        monkeypatch.setattr(
            census_mod, "_EXTRA_ENGINE_SWEEPS",
            ((ENGINE_CARGO_FUZZ, "/fuzz --binary {path}",
              lambda _root: ["extra_target"]),),
        )
        _cargo_fuzz_repo(tmp_path)
        census = census_fuzz_harnesses(tmp_path)
        assert census.engines_checked.count(ENGINE_CARGO_FUZZ) == 1
        assert _by_engine(census)[ENGINE_CARGO_FUZZ].count == 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
