"""Tests for ``core.run.target_types`` — the catalog substrate
(QoL #17): YAML loading, schema parsing, detection, fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.run.target_types import (
    CatalogEntry,
    _reset_cache_for_tests,
    all_entries,
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
                "estimated_cost_usd": [10, 30],
                "estimated_time_min": [20, 60],
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
        assert e.estimated_cost_usd == (10.0, 30.0)
        assert e.estimated_time_min == (20, 60)
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
        # Three seed entries shipped with the substrate.
        assert "c.userspace-daemon" in names
        assert "python.web-app" in names
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
        # Must fall through to generic — no framework signals
        # validate the python.web-app specificity claim.
        assert winner.name == "generic", (
            f"expected generic for Python-library-shaped tree; "
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
        ("python.web-app", True),
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
