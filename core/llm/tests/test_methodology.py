"""Tests for core.llm.methodology — persona file loading and frontmatter stripping."""

from __future__ import annotations

import textwrap

import pytest

from core.llm.methodology import _strip_frontmatter, clear_cache, load_methodology


class TestStripFrontmatter:
    def test_strips_yaml_frontmatter(self):
        text = textwrap.dedent("""\
            ---
            name: test
            type: persona
            ---
            # Title
            Body content here.
        """)
        assert _strip_frontmatter(text) == "Body content here."

    def test_strips_h1_without_frontmatter(self):
        text = "# Title\nBody content."
        assert _strip_frontmatter(text) == "Body content."

    def test_preserves_h2_headings(self):
        text = "# Title\n## Section\nContent."
        assert _strip_frontmatter(text) == "## Section\nContent."

    def test_preserves_mid_document_h1(self):
        text = "# Title\nBody.\n# Another H1\nMore."
        assert _strip_frontmatter(text) == "Body.\n# Another H1\nMore."

    def test_empty_input(self):
        assert _strip_frontmatter("") == ""

    def test_frontmatter_only(self):
        text = "---\nname: x\n---\n# Title"
        assert _strip_frontmatter(text) == ""

    def test_no_frontmatter_no_h1(self):
        text = "Just plain content.\nMore lines."
        assert _strip_frontmatter(text) == "Just plain content.\nMore lines."

    def test_h2_before_body(self):
        text = "---\nk: v\n---\n# Title\n## Sub\nContent."
        assert _strip_frontmatter(text) == "## Sub\nContent."

    def test_blank_lines_before_h1(self):
        text = "\n\n# Title\nBody."
        result = _strip_frontmatter(text)
        assert "Body." in result


class TestLoadMethodology:
    @pytest.fixture(autouse=True)
    def _clear(self):
        clear_cache()
        yield
        clear_cache()

    def test_loads_existing_file(self, tmp_path, monkeypatch):
        persona = tmp_path / "personas"
        persona.mkdir()
        (persona / "test.md").write_text("# Test\nContent here.", encoding="utf-8")
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path.parent))
        tiers = tmp_path.parent / "tiers"
        tiers.mkdir(exist_ok=True)
        (tiers / "personas").mkdir(exist_ok=True)
        (tiers / "personas" / "test.md").write_text(
            "# Test\nContent here.", encoding="utf-8"
        )
        result = load_methodology("personas/test.md")
        assert result == "Content here."

    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        tiers = tmp_path / "tiers"
        tiers.mkdir()
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        result = load_methodology("nonexistent.md")
        assert result == ""

    def test_caches_by_mtime(self, tmp_path, monkeypatch):
        tiers = tmp_path / "tiers"
        tiers.mkdir()
        f = tiers / "cached.md"
        f.write_text("# T\nFirst.", encoding="utf-8")
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        assert load_methodology("cached.md") == "First."
        f.write_text("# T\nSecond.", encoding="utf-8")
        import os
        os.utime(f, (f.stat().st_mtime + 10, f.stat().st_mtime + 10))
        assert load_methodology("cached.md") == "Second."

    def test_cache_hit_same_mtime(self, tmp_path, monkeypatch):
        tiers = tmp_path / "tiers"
        tiers.mkdir()
        f = tiers / "stable.md"
        f.write_text("# T\nStable.", encoding="utf-8")
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        assert load_methodology("stable.md") == "Stable."
        assert load_methodology("stable.md") == "Stable."

    def test_clear_cache(self, tmp_path, monkeypatch):
        tiers = tmp_path / "tiers"
        tiers.mkdir()
        f = tiers / "clear.md"
        f.write_text("# T\nBefore.", encoding="utf-8")
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        load_methodology("clear.md")
        clear_cache()
        f.write_text("# T\nAfter.", encoding="utf-8")
        assert load_methodology("clear.md") == "After."
