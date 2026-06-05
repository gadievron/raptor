"""Tests for ``packages/describe/target_shape.py`` — target-shape
inference for the /describe command."""

from __future__ import annotations

from packages.describe.target_shape import (
    TargetShape,
    _compute_breakdown,
    _pick_primary,
    infer_target_shape,
)


class TestComputeBreakdown:
    """Normalisation of per-language file counts to percentages."""

    def test_single_language(self):
        result = _compute_breakdown({"c": 10})
        assert result == {"c": 100.0}

    def test_two_languages_share_correctly(self):
        result = _compute_breakdown({"c": 95, "python": 5})
        assert result == {"c": 95.0, "python": 5.0}

    def test_rounds_to_one_decimal(self):
        # 7/3 should round to one decimal.
        result = _compute_breakdown({"c": 7, "python": 3})
        assert result == {"c": 70.0, "python": 30.0}

    def test_empty_input_returns_empty(self):
        assert _compute_breakdown({}) == {}

    def test_zero_total_returns_empty(self):
        # All-zero counts (pathological) → empty rather than
        # ZeroDivisionError.
        assert _compute_breakdown({"c": 0, "python": 0}) == {}


class TestPickPrimary:
    """Picks the language with the largest share. None on empty.
    Deterministic on ties."""

    def test_largest_wins(self):
        assert _pick_primary({"c": 95.0, "python": 5.0}) == "c"

    def test_empty_returns_none(self):
        assert _pick_primary({}) is None

    def test_single_language_returned(self):
        assert _pick_primary({"rust": 100.0}) == "rust"


class TestInferTargetShape:
    """End-to-end inference on synthetic target trees."""

    def test_c_userspace_daemon_shape(self, tmp_path):
        # Build a tree the codeql detector + catalog both recognise.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        src = tmp_path / "src"
        src.mkdir()
        for i in range(10):
            (src / f"file{i}.c").write_text(
                f"// file {i}\nint main() {{ return 0; }}\n"
            )
        (src / "header.h").write_text("// hdr\nvoid f();\n")

        shape = infer_target_shape(tmp_path)

        assert shape.target_path == tmp_path.resolve()
        # codeql language detector merges C + C++ into "cpp"
        # (single CodeQL database). The .c/.h files land under
        # this id; ``file_extensions`` keeps the raw extension
        # breakdown for renderers that want strict-C numbers.
        assert "cpp" in shape.languages
        assert shape.primary_language == "cpp"
        # 100% C/C++ since no other language.
        assert shape.language_breakdown["cpp"] == 100.0
        # Catalog matched c.userspace-daemon (autotools markers).
        assert shape.target_type == "c.userspace-daemon"
        # File count + lines populated.
        assert shape.total_files >= 11  # 10 .c + 1 .h
        assert shape.total_lines > 0
        # Per-extension counts preserve the C/C++ split.
        assert shape.file_extensions.get(".c", 0) == 10
        assert shape.file_extensions.get(".h", 0) == 1
        # Per-language LOC populated + sums to total_lines (.c
        # and .h both roll up under "cpp", matching the codeql /
        # catalog merge convention).
        assert shape.language_lines.get("cpp", 0) > 0
        assert sum(shape.language_lines.values()) == shape.total_lines

    def test_python_target_shape(self, tmp_path):
        # python web app shape.
        (tmp_path / "manage.py").write_text("# django manage")
        (tmp_path / "settings.py").write_text("# settings")
        (tmp_path / "urls.py").write_text("# urls")
        for i in range(5):
            (tmp_path / f"view{i}.py").write_text(f"def view{i}(): pass\n")

        shape = infer_target_shape(tmp_path)
        assert shape.primary_language == "python"
        assert "python" in shape.languages
        assert shape.target_type == "python.web-app"

    def test_empty_target_returns_minimal_shape(self, tmp_path):
        # Empty tree → no languages detected → renderer can still
        # show "Languages: unknown" without crashing.
        shape = infer_target_shape(tmp_path)
        assert shape.languages == {}
        assert shape.primary_language is None
        assert shape.language_breakdown == {}
        assert shape.total_files == 0
        # Catalog falls back to "generic" rather than None.
        assert shape.target_type == "generic"

    def test_symlinked_source_file_is_skipped(self, tmp_path):
        # Adversarial fixture: a symlinked "source file" points at
        # /etc/shadow (or any host path). Pre-fix the LOC walk
        # opened it and read line count → leak primitive into
        # the JSON output. Post-fix lstat + S_ISLNK guard skips
        # symlinks entirely.
        (tmp_path / "real.c").write_text("int main(){return 0;}\n")
        # Symlink target doesn't have to exist for lstat to
        # detect the symlink itself; use a definitely-not-here
        # path so the test doesn't depend on host /etc state.
        (tmp_path / "evil.c").symlink_to("/nonexistent/sensitive-data")
        shape = infer_target_shape(tmp_path)
        # real.c is the only counted file; evil.c is skipped.
        assert shape.total_files == 1
        # Single counted .c → ≥1 LOC; the symlink contributes 0.
        assert shape.total_lines >= 1
        assert shape.file_extensions.get(".c", 0) == 1

    def test_symlinked_dir_inside_tree_not_followed(self, tmp_path):
        # os.walk(followlinks=False) — a symlinked dir within
        # the target shouldn't be descended into. Otherwise an
        # attacker could plant ``vendor`` -> ``/`` and we'd
        # try to walk the whole host filesystem.
        (tmp_path / "real.c").write_text("int x;\n")
        (tmp_path / "evil_dir").symlink_to("/etc")
        shape = infer_target_shape(tmp_path)
        # Just the one legitimate file — the symlinked dir is
        # listed as a "file" by os.walk (because followlinks
        # defaults False; symlinked dirs surface as entries but
        # aren't recursed), and our file path is lstat-guarded
        # so the symlink isn't opened either.
        assert shape.total_files == 1

    def test_license_detected_when_license_file_present(self, tmp_path):
        # MIT LICENSE at repo root → license.spdx_id="MIT".
        # Pins the reuse contract with core.license: /describe
        # gets the same detector the run-lifecycle license
        # warning uses, no parallel implementation.
        (tmp_path / "LICENSE").write_text(
            "MIT License\n\n"
            "Permission is hereby granted, free of charge, to any "
            "person obtaining a copy of this software\n"
        )
        (tmp_path / "f.py").write_text("pass\n")
        shape = infer_target_shape(tmp_path)
        assert shape.license is not None
        assert shape.license.spdx_id == "MIT"
        assert shape.license.classification == "oss"

    def test_license_missing_when_no_license_file(self, tmp_path):
        (tmp_path / "f.py").write_text("pass\n")
        shape = infer_target_shape(tmp_path)
        assert shape.license is not None
        assert shape.license.classification == "missing"
        assert shape.license.spdx_id is None

    def test_small_language_surface_not_dropped(self, tmp_path):
        # /describe walks LANGUAGE_MAP extensions directly — NO
        # ``min_files`` floor. Pins the contrast with codeql's
        # LanguageDetector (which would drop these 2-file
        # languages under its DB-build min_files=3 threshold).
        # Mixed corpus: 3 C, 2 Python, 2 Java, 2 JS — Java + JS
        # below codeql's floor; /describe MUST report all four.
        for i in range(3):
            (tmp_path / f"c{i}.c").write_text("int main(){return 0;}")
        for i in range(2):
            (tmp_path / f"p{i}.py").write_text("pass\n")
        for i in range(2):
            (tmp_path / f"J{i}.java").write_text(
                f"class J{i} {{}}\n"
            )
        for i in range(2):
            (tmp_path / f"j{i}.js").write_text("var x;\n")

        shape = infer_target_shape(tmp_path)
        # Every language present in the tree appears, regardless
        # of how few files it has — this is the bug the
        # codeql-based detector caused on /tmp/vulns.
        assert "cpp" in shape.languages
        assert "python" in shape.languages
        assert "java" in shape.languages
        assert "javascript" in shape.languages

    def test_catalog_failure_returns_none(self, monkeypatch, tmp_path):
        # Catalog load raises → target_type is None
        # (defensive against future catalog substrate bugs).
        import core.run.target_types as tt
        monkeypatch.setattr(
            tt, "load",
            lambda _p: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        shape = infer_target_shape(tmp_path)
        assert shape.target_type is None

    def test_build_system_detected_for_cpp_autotools(self, tmp_path):
        # autotools markers should yield a build_system entry.
        # Indexed under "cpp" because the language detector merges
        # C/C++ into that single language id.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        src = tmp_path / "src"
        src.mkdir()
        for i in range(5):
            (src / f"f{i}.c").write_text("int main(){return 0;}")

        shape = infer_target_shape(tmp_path)
        assert "cpp" in shape.build_systems
        assert shape.build_systems["cpp"] == "autotools"

    def test_returns_frozen_dataclass(self, tmp_path):
        # TargetShape is frozen — caller can't mutate.
        shape = infer_target_shape(tmp_path)
        import pytest
        with pytest.raises(Exception):  # FrozenInstanceError
            shape.total_files = 999  # type: ignore[misc]


class TestTargetShapeDataclass:
    """Direct dataclass construction shape — used by JSON
    serialisation / consumer tests."""

    def test_minimal_construction(self, tmp_path):
        shape = TargetShape(
            target_path=tmp_path,
            languages={},
            language_breakdown={},
            primary_language=None,
            build_systems={},
            target_type=None,
            total_files=0,
            total_lines=0,
        )
        # file_extensions has a default factory; constructible
        # without specifying it.
        assert shape.file_extensions == {}
