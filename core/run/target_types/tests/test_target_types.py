"""Tests for ``core.run.target_types`` — the catalog substrate
(QoL #17): YAML loading, schema parsing, detection, fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.run.target_types import (
    CatalogEntry,
    _reset_cache_for_tests,
    all_entries,
    binary_dominant,
    detect,
    load,
    load_by_name,
)


@pytest.fixture(autouse=True)
def _reset_catalog_cache():
    """Ensure each test sees a fresh catalog load — module-level
    cache means tests would otherwise interfere via leftover
    state."""
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


# ---------------------------------------------------------------------------
# Schema parsing
# ---------------------------------------------------------------------------


class TestCatalogEntryFromDict:
    def test_minimal_required_fields(self):
        e = CatalogEntry.from_dict({"name": "minimal"})
        assert e.name == "minimal"
        assert e.description == ""
        assert e.file_globs == ()
        assert e.version == 1

    def test_full_schema(self):
        e = CatalogEntry.from_dict({
            "name": "c.userspace-daemon",
            "description": "C/C++ daemons",
            "detection": {
                "file_globs": ["configure.ac", "Makefile.am"],
                "file_extensions": [".c", ".h"],
                "function_names": ["main_loop"],
                "negative_globs": ["kernel/**"],
            },
            "semgrep_packs": {
                "default": ["security-audit"],
                "optional": ["secrets"],
            },
            "attack_surface": {
                "high_priority_dirs": ["src/http"],
                "low_priority_dirs": ["tests"],
            },
            "pipeline": {
                "recommended": ["scan", "agentic"],
            },
            "budget_defaults": {
                "typical_findings_count": 20,
                "typical_cost_per_run_usd": 15.5,
            },
            "version": 2,
        })
        assert e.name == "c.userspace-daemon"
        assert e.description == "C/C++ daemons"
        assert e.file_globs == ("configure.ac", "Makefile.am")
        assert e.file_extensions == (".c", ".h")
        assert e.function_names == ("main_loop",)
        assert e.negative_globs == ("kernel/**",)
        assert e.semgrep_packs_default == ("security-audit",)
        assert e.semgrep_packs_optional == ("secrets",)
        assert e.attack_surface_high == ("src/http",)
        assert e.attack_surface_low == ("tests",)
        assert e.pipeline_recommended == ("scan", "agentic")
        assert e.typical_findings_count == 20
        assert e.typical_cost_per_run_usd == 15.5
        assert e.version == 2

    def test_missing_name_raises(self):
        with pytest.raises(ValueError) as exc:
            CatalogEntry.from_dict({"description": "no name"})
        assert "name" in str(exc.value)

    def test_partial_sections_default_to_empty(self):
        e = CatalogEntry.from_dict({
            "name": "partial",
            "detection": {"file_globs": ["foo"]},
            # no semgrep_packs, no attack_surface, etc.
        })
        assert e.file_globs == ("foo",)
        assert e.semgrep_packs_default == ()
        assert e.attack_surface_high == ()


# ---------------------------------------------------------------------------
# Loader — uses real YAML files in the catalog dir
# ---------------------------------------------------------------------------


class TestLoader:
    def test_all_entries_loads_seed_yamls(self):
        entries = all_entries()
        names = {e.name for e in entries}
        assert "c.userspace-daemon" in names
        assert "c.generic" in names
        assert "go.generic" in names
        assert "python.web-app" in names
        assert "python.generic" in names
        assert "generic" in names

    def test_load_by_name_returns_match(self):
        e = load_by_name("c.userspace-daemon")
        assert e is not None
        assert e.name == "c.userspace-daemon"
        # Spot-check the schema parsed.
        assert "security-audit" in e.semgrep_packs_default

    def test_load_by_name_unknown_returns_none(self):
        assert load_by_name("does-not-exist") is None


# ---------------------------------------------------------------------------
# Detection — synthetic target trees in tmp_path
# ---------------------------------------------------------------------------


def _build_tree(tmp_path: Path, files: dict) -> Path:
    """Helper: create a fake target tree under tmp_path with the
    given relative paths. Values are file contents (default empty
    string is fine — detection is filename-based in v1)."""
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else "")
    return tmp_path


class TestDetect:
    def test_autotools_daemon_tree_matches_c_userspace_daemon(self, tmp_path):
        # The Monit shape: autotools at top, src/ with .c files.
        _build_tree(tmp_path, {
            "configure.ac": "",
            "Makefile.am": "",
            "src/main.c": "",
            "src/http/server.c": "",
        })
        ranked = detect(tmp_path)
        assert ranked
        winner = ranked[0][0]
        assert winner.name == "c.userspace-daemon"

    def test_django_tree_matches_python_web_app(self, tmp_path):
        _build_tree(tmp_path, {
            "manage.py": "",
            "settings.py": "",
            "urls.py": "",
            "app/views.py": "",
            "requirements.txt": "Django==4.0\n",
        })
        ranked = detect(tmp_path)
        assert ranked
        assert ranked[0][0].name == "python.web-app"

    def test_specificity_gate_extensions_alone_dont_score(self, tmp_path):
        # Regression: a Python codebase with .py + .html files but
        # NO framework markers (no manage.py / wsgi.py / urls.py /
        # settings.py / templates/) must NOT match python.web-app.
        # Pre-fix the catalog scorer counted file_extension hits
        # even when no specific file_glob matched; RAPTOR-itself
        # got false-classified as python.web-app for this reason.
        _build_tree(tmp_path, {
            "lib/util.py": "",
            "lib/core.py": "",
            "lib/tests.py": "",
            "docs/index.html": "",
            "README.md": "# Just a Python library",
        })
        winner = load(tmp_path)
        assert winner is not None
        # Must NOT match python.web-app — no framework signals
        # validate the specificity claim. python.generic (extension-
        # only match) is the correct winner for a plain library.
        assert winner.name in ("generic", "python.generic"), (
            f"expected generic or python.generic for Python-library-shaped tree; "
            f"got {winner.name!r} — specificity gate regression"
        )

    def test_specificity_gate_still_matches_real_django(self, tmp_path):
        # Counter-check: a tree WITH framework markers still
        # matches python.web-app via the gate.
        _build_tree(tmp_path, {
            "manage.py": "",
            "settings.py": "",
            "urls.py": "",
            "app/views.py": "",
        })
        winner = load(tmp_path)
        assert winner.name == "python.web-app"

    def test_specificity_gate_boundary_single_framework_file_wins(self, tmp_path):
        # Boundary case: a tree with EXACTLY ONE framework file
        # match (the minimum the gate requires) should still
        # match the catalog entry. Pins the gate semantic at
        # the lowest passing edge — a future refactor that
        # raised the threshold (e.g. "require ≥2 file_globs")
        # would silently drop borderline real web apps. This
        # test fails loudly when that happens.
        _build_tree(tmp_path, {
            # Only manage.py — a minimal Django-shaped tree.
            "manage.py": "",
            "app/handler.py": "",
        })
        winner = load(tmp_path)
        assert winner.name == "python.web-app", (
            f"single-framework-file match should still win "
            f"the specificity gate; got {winner.name}. The "
            f"gate is 'at least one file_glob match', not "
            f"'multiple file_glob matches'."
        )

    def test_negative_signal_disqualifies(self, tmp_path):
        # Tree LOOKS like an autotools daemon but has a Kconfig at
        # top — that's a Linux-kernel-module shape, c.userspace-daemon
        # must NOT match.
        _build_tree(tmp_path, {
            "configure.ac": "",
            "Makefile.am": "",
            "Kconfig": "",
            "src/main.c": "",
        })
        ranked = detect(tmp_path)
        # c.userspace-daemon disqualified by negative_glob; no other
        # entry's positive signals match either (no python files,
        # generic has no detection signals).
        names = [e.name for e, _ in ranked]
        assert "c.userspace-daemon" not in names

    def test_empty_target_returns_empty_ranking(self, tmp_path):
        # Empty dir → no signals to match → no entries ranked.
        assert detect(tmp_path) == []

    def test_nonexistent_path_returns_empty(self, tmp_path):
        assert detect(tmp_path / "does-not-exist") == []


class TestLoadFallback:
    def test_load_returns_generic_when_nothing_matches(self, tmp_path):
        # Empty target → no positive signals → load() falls back
        # to the ``generic`` catalog entry rather than None. Caller
        # gets a usable default.
        e = load(tmp_path)
        assert e is not None
        assert e.name == "generic"

    def test_load_returns_best_match_when_signals_present(self, tmp_path):
        _build_tree(tmp_path, {
            "configure.ac": "",
            "src/main.c": "",
        })
        e = load(tmp_path)
        assert e.name == "c.userspace-daemon"


# ---------------------------------------------------------------------------
# Seed-entry sanity checks — fail loudly when a seed YAML drifts
# from the schema (e.g. typo in a field name) so contributors who
# add entries get an immediate signal.
# ---------------------------------------------------------------------------


class TestSeedEntrySanity:
    @pytest.mark.parametrize("name,expected_has_packs", [
        ("c.userspace-daemon", True),
        ("c.generic", True),
        ("go.generic", True),
        ("python.web-app", True),
        ("python.generic", True),
        ("generic", True),
    ])
    def test_seed_has_default_packs(self, name, expected_has_packs):
        e = load_by_name(name)
        assert e is not None, f"seed entry missing: {name}"
        if expected_has_packs:
            assert e.semgrep_packs_default, (
                f"{name}: missing semgrep_packs.default — operator "
                f"would get an empty pack set"
            )

    def test_seed_versions_set(self):
        for e in all_entries():
            assert e.version >= 1, f"{e.name}: missing version field"

    def test_generic_has_no_detection_signals(self):
        # ``generic`` is fallback-only; it must NOT match any real
        # target via score-ranking. Having empty detection signals
        # is what enforces that.
        e = load_by_name("generic")
        assert e.file_globs == ()
        assert e.file_extensions == ()


class TestTierAGenericEntries:
    """rust/java/javascript generic catalog entries (wave-b4 tier A)."""

    def test_new_entries_load(self):
        names = {e.name for e in all_entries()}
        for n in ("rust.generic", "java.generic", "javascript.generic"):
            assert n in names

    def test_cargo_tree_matches_rust_generic(self, tmp_path):
        _build_tree(tmp_path, {
            "Cargo.toml": "[package]\nname = \"x\"\n",
            "src/main.rs": "fn main() {}\n",
            "src/lib.rs": "",
        })
        ranked = detect(tmp_path)
        assert ranked and ranked[0][0].name == "rust.generic"

    def test_maven_tree_matches_java_generic(self, tmp_path):
        _build_tree(tmp_path, {
            "pom.xml": "<project/>",
            "src/main/java/App.java": "class App {}\n",
        })
        ranked = detect(tmp_path)
        assert ranked and ranked[0][0].name == "java.generic"

    def test_node_tree_matches_javascript_generic(self, tmp_path):
        _build_tree(tmp_path, {
            "package.json": "{}",
            "src/index.ts": "",
            "src/app.js": "",
        })
        ranked = detect(tmp_path)
        assert ranked and ranked[0][0].name == "javascript.generic"

    def test_pack_ids_resolve_to_registry_convention(self):
        # Every pack the new entries name must resolve through the
        # p/<id> naming convention (known baseline/policy pair or the
        # synthesised-name fallback) — i.e. be a plain pack-id suffix.
        for n in ("rust.generic", "java.generic", "javascript.generic"):
            e = load_by_name(n)
            for pack in (*e.semgrep_packs_default, *e.semgrep_packs_optional):
                assert pack and "/" not in pack and not pack.startswith("p/")


# ---------------------------------------------------------------------------
# Binary-dominance detection (magic bytes)
# ---------------------------------------------------------------------------


_ELF_HEAD = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
_MACHO_HEAD = b"\xcf\xfa\xed\xfe" + b"\x00" * 12
_PE_HEAD = b"MZ\x90\x00" + b"\x00" * 12


class TestBinaryDominant:
    def test_elf_tree_is_binary_dominant(self, tmp_path):
        for i in range(6):
            (tmp_path / f"tool{i}").write_bytes(_ELF_HEAD)
        assert binary_dominant(tmp_path) is True

    def test_mixed_artifact_magics_count(self, tmp_path):
        (tmp_path / "a").write_bytes(_ELF_HEAD)
        (tmp_path / "b").write_bytes(_MACHO_HEAD)
        (tmp_path / "c.exe").write_bytes(_PE_HEAD)
        assert binary_dominant(tmp_path) is True

    def test_source_tree_is_not_binary_dominant(self, tmp_path):
        for i in range(6):
            (tmp_path / f"mod{i}.c").write_text("int x;\n")
        assert binary_dominant(tmp_path) is False

    def test_artifacts_beside_source_tree_veto(self, tmp_path):
        # Built artifacts INSIDE a source repo (a build/ dir of .o
        # files): the substantial-source veto keeps the source
        # pipeline whatever the magic sample says.
        (tmp_path / "src").mkdir()
        for i in range(8):
            (tmp_path / "src" / f"mod{i}.c").write_text("int x;\n")
        (tmp_path / "build").mkdir()
        for i in range(4):
            (tmp_path / "build" / f"mod{i}.o").write_bytes(_ELF_HEAD)
        assert binary_dominant(tmp_path) is False

    def test_empty_dir_is_not_binary_dominant(self, tmp_path):
        assert binary_dominant(tmp_path) is False

    def test_text_tree_is_not_binary_dominant(self, tmp_path):
        (tmp_path / "README.md").write_text("hello\n")
        (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02\x03")
        assert binary_dominant(tmp_path) is False

    def test_unreadable_and_special_files_tolerated(self, tmp_path):
        import os as _os
        for i in range(5):
            (tmp_path / f"tool{i}").write_bytes(_ELF_HEAD)
        # Dangling symlink — open fails, skipped.
        (tmp_path / "dangling").symlink_to(tmp_path / "nope")
        # FIFO — must neither block nor count (S_ISREG refusal).
        _os.mkfifo(tmp_path / "pipe")
        # chmod-000 file — unreadable for non-root (skipped); a
        # root runner reads 4 non-magic bytes instead, which is
        # equally non-evidence. Either way the verdict holds.
        locked = tmp_path / "locked"
        locked.write_bytes(b"data")
        locked.chmod(0)
        try:
            assert binary_dominant(tmp_path) is True
        finally:
            locked.chmod(0o600)

    def test_sample_cap_bounds_magic_reads(self, tmp_path, monkeypatch):
        import core.run.target_types as tt
        for i in range(40):
            (tmp_path / f"tool{i:02d}").write_bytes(_ELF_HEAD)
        calls: list = []
        real = tt._read_magic

        def counting(path):
            calls.append(path)
            return real(path)

        monkeypatch.setattr(tt, "_read_magic", counting)
        assert binary_dominant(tmp_path, sample_cap=10) is True
        assert len(calls) <= 10

    def test_zero_sample_cap_refuses(self, tmp_path):
        (tmp_path / "tool").write_bytes(_ELF_HEAD)
        assert binary_dominant(tmp_path, sample_cap=0) is False

    def test_default_sample_cap_pinned(self):
        import core.run.target_types as tt
        assert tt._BINARY_SAMPLE_CAP == 200
        assert tt._BINARY_MIN_EXAMINED == 3

    def test_exact_tie_is_not_dominant(self, tmp_path):
        # STRICT majority: 2 compiled / 4 examined is a tie, not
        # dominance.
        (tmp_path / "a").write_bytes(_ELF_HEAD)
        (tmp_path / "b").write_bytes(_PE_HEAD)
        (tmp_path / "notes.txt").write_text("x\n")
        (tmp_path / "README.md").write_text("y\n")
        assert binary_dominant(tmp_path) is False

    def test_minimum_examined_floor(self, tmp_path):
        # One planted magic file plus one text file: fewer than 3
        # examined files is not evidence.
        (tmp_path / "planted").write_bytes(_PE_HEAD)
        (tmp_path / "notes.txt").write_text("x\n")
        assert binary_dominant(tmp_path) is False

    def test_minimum_examined_floor_decisive(self, tmp_path):
        # Two compiled files ALONE satisfy the strict majority
        # (2/2) — ONLY the minimum-examined floor refuses here.
        (tmp_path / "a").write_bytes(_ELF_HEAD)
        (tmp_path / "b").write_bytes(_PE_HEAD)
        assert binary_dominant(tmp_path) is False

    def test_source_veto_decisive_at_floor(self, tmp_path):
        # 10 compiled / 13 examined is a strict majority — ONLY the
        # 3-source-file veto refuses here.
        for i in range(10):
            (tmp_path / f"tool{i}").write_bytes(_ELF_HEAD)
        for i in range(3):
            (tmp_path / f"mod{i}.c").write_text("int x;\n")
        assert binary_dominant(tmp_path) is False

    def test_source_veto_ten_percent_scaling_boundary(self, tmp_path):
        # 40 walked files scale the veto threshold to 4: exactly 4
        # source files veto, 3 do not (and the tree then classifies
        # on its strict compiled majority).
        for i in range(36):
            (tmp_path / f"tool{i:02d}").write_bytes(_ELF_HEAD)
        for i in range(4):
            (tmp_path / f"mod{i}.c").write_text("int x;\n")
        assert binary_dominant(tmp_path) is False
        (tmp_path / "mod3.c").unlink()
        (tmp_path / "tool36").write_bytes(_ELF_HEAD)
        assert binary_dominant(tmp_path) is True

    def test_walk_cap_truncation_refuses(self, tmp_path, monkeypatch):
        # When the walk hits its file cap the census is truncated —
        # a hostile tree can front-load binary-magic names so no
        # real source is ever walked. Truncation must refuse the
        # binary verdict.
        import core.run.target_types as tt
        monkeypatch.setattr(tt, "_MAX_DETECT_FILES", 10)
        for i in range(12):
            (tmp_path / f"tool{i:02d}").write_bytes(_ELF_HEAD)
        assert binary_dominant(tmp_path) is False

    def test_pe_only_tree(self, tmp_path):
        for i in range(4):
            (tmp_path / f"tool{i}.exe").write_bytes(_PE_HEAD)
        assert binary_dominant(tmp_path) is True

    def test_macho_only_tree(self, tmp_path):
        (tmp_path / "a").write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 12)
        (tmp_path / "b").write_bytes(b"\xce\xfa\xed\xfe" + b"\x00" * 12)
        (tmp_path / "c").write_bytes(_MACHO_HEAD)
        (tmp_path / "d").write_bytes(b"\xca\xfe\xba\xbf" + b"\x00" * 12)
        (tmp_path / "e").write_bytes(b"\xbf\xba\xfe\xca" + b"\x00" * 12)
        assert binary_dominant(tmp_path) is True

    def test_static_archive_tree(self, tmp_path):
        # A drop of ar static libraries is a compiled-artifact tree.
        for i in range(4):
            (tmp_path / f"lib{i}.a").write_bytes(b"!<arch>\n" + b"x" * 8)
        assert binary_dominant(tmp_path) is True

    def test_live_out_of_tree_symlinks_not_counted(self, tmp_path):
        # LIVE symlinks to an out-of-tree ELF: if they were followed
        # (5 compiled / 8 examined) the tree would classify binary —
        # the symlink refusal must keep them out of the census.
        outside = tmp_path / "outside.elf"
        outside.write_bytes(_ELF_HEAD)
        tree = tmp_path / "tree"
        tree.mkdir()
        for i in range(3):
            (tree / f"notes{i}.txt").write_text("x\n")
        for i in range(5):
            (tree / f"lnk{i}").symlink_to(outside)
        assert binary_dominant(tree) is False

    def test_fifo_refused_before_open(self, tmp_path, monkeypatch):
        # The non-regular refusal must happen at the pre-open lstat:
        # opening a hostile special file can itself have side
        # effects, so _read_magic must never open(2) one at all.
        import os as _os

        import core.run.target_types as tt
        fifo = tmp_path / "pipe"
        _os.mkfifo(fifo)
        opened: list = []
        real_open = _os.open

        def spy(path, flags, *args, **kwargs):
            opened.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(tt.os, "open", spy)
        assert tt._read_magic(fifo) is None
        assert str(fifo) not in opened

    def test_only_unreadable_tree_is_not_dominant(self, tmp_path):
        # Nothing examinable — no evidence, never dominance.
        import os as _os
        for i in range(3):
            _os.mkfifo(tmp_path / f"pipe{i}")
        (tmp_path / "dangling").symlink_to(tmp_path / "nope")
        assert binary_dominant(tmp_path) is False

    def test_strided_sample_properties(self, tmp_path, monkeypatch):
        # The sample is exactly the cap, duplicate-free, in walk
        # order, and drawn from the walked tree.
        import core.run.target_types as tt
        for i in range(50):
            (tmp_path / f"tool{i:02d}").write_bytes(_ELF_HEAD)
        calls: list = []
        real = tt._read_magic

        def recording(path):
            calls.append(path)
            return real(path)

        monkeypatch.setattr(tt, "_read_magic", recording)
        assert binary_dominant(tmp_path, sample_cap=10) is True
        rels = tt._walk_target(tmp_path)
        resolved = tmp_path.resolve()
        recorded = [p.relative_to(resolved).as_posix() for p in calls]
        assert len(recorded) == 10
        assert len(set(recorded)) == 10
        positions = [rels.index(r) for r in recorded]
        assert positions == sorted(positions)
        assert all(0 <= pos < len(rels) for pos in positions)

    def test_single_file_elf_target(self, tmp_path):
        fw = tmp_path / "firmware.elf"
        fw.write_bytes(_ELF_HEAD)
        assert binary_dominant(fw) is True

    def test_single_file_text_target(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text("hello\n")
        assert binary_dominant(f) is False

    def test_binary_entry_loads_but_is_never_score_ranked(self, tmp_path):
        # binary.yml resolves by name with the binary-lane pipeline,
        # but declares no positive signals — the score-ranked
        # detect() must never surface it (selection is the
        # magic-byte sampler's job).
        e = load_by_name("binary")
        assert e is not None
        assert e.pipeline_recommended == ("binary", "understand-study")
        for i in range(4):
            (tmp_path / f"tool{i}").write_bytes(_ELF_HEAD)
        assert all(entry.name != "binary" for entry, _ in detect(tmp_path))
