"""Tests for the npm + PyPI envelope strip helpers.

The 30-45 MB envelopes registries return are mostly security-irrelevant
data (devDependencies on npm; redundant timestamps + cosmetic info on
PyPI). Strip at cache-write time so subsequent ``json.load`` reads are
fast on first-cache-of-the-session paths.

These tests pin:
  1. Fields RAPTOR uses are preserved.
  2. Fields RAPTOR doesn't use are dropped.
  3. Non-dict inputs (404 sentinel ``None``) pass through unchanged.
  4. Nested per-version / per-release-file structures are walked.
"""

from __future__ import annotations

from packages.sca.registries.npm import _strip_npm_metadata
from packages.sca.registries.pypi import _strip_pypi_metadata


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def test_npm_strip_drops_devdependencies() -> None:
    """devDependencies is the single biggest win (52% of a 31 MB
    envelope on next.js) — must be removed."""
    raw = {
        "name": "x",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "dependencies": {"runtime-dep": "^1"},
                "devDependencies": {"test-dep": "^1"},
                "license": "MIT",
            },
        },
    }
    out = _strip_npm_metadata(raw)
    assert "devDependencies" not in out["versions"]["1.0.0"]
    # Runtime deps + license must be preserved — RAPTOR reads these.
    assert out["versions"]["1.0.0"]["dependencies"] == {"runtime-dep": "^1"}
    assert out["versions"]["1.0.0"]["license"] == "MIT"


def test_npm_strip_drops_npm_internals_and_metadata() -> None:
    raw = {
        "name": "x",
        "dist-tags": {"latest": "1.0.0"},
        "time": {"1.0.0": "2025-01-01"},
        "_id": "x",
        "_rev": "1-abc",
        "readme": "huge readme text",
        "maintainers": [{"name": "alice"}],
        "license": "MIT",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "_id": "x@1.0.0",
                "_nodeVersion": "18",
                "_npmVersion": "10",
                "_npmOperationalInternal": {"host": "s3://..."},
                "description": "blah",
                "keywords": ["x"],
                "author": {"name": "alice"},
                "bugs": {"url": "..."},
                "repository": {"url": "git+..."},
                "main": "index.js",
                "dist": {"shasum": "abc", "tarball": "https://..."},
                "license": "MIT",
            },
        },
    }
    out = _strip_npm_metadata(raw)
    # Top-level survivors RAPTOR uses.
    assert out["dist-tags"] == {"latest": "1.0.0"}
    assert out["time"] == {"1.0.0": "2025-01-01"}
    assert out["license"] == "MIT"
    assert out["versions"]["1.0.0"]["version"] == "1.0.0"
    assert out["versions"]["1.0.0"]["dist"]["shasum"] == "abc"
    assert out["versions"]["1.0.0"]["license"] == "MIT"
    # Internals + metadata stripped.
    for k in ("_id", "_rev", "readme", "maintainers"):
        assert k not in out, f"top-level {k} should be stripped"
    v = out["versions"]["1.0.0"]
    for k in ("_id", "_nodeVersion", "_npmVersion",
              "_npmOperationalInternal", "description", "keywords",
              "author", "bugs", "repository", "main"):
        assert k not in v, f"per-version {k} should be stripped"


def test_npm_strip_passes_through_none() -> None:
    """The 404 negative-cache sentinel is ``None``. Must round-trip."""
    assert _strip_npm_metadata(None) is None


def test_npm_strip_passes_through_non_dict() -> None:
    """Defensive: upstream schema drift could yield a list / string.
    Don't crash — pass through unchanged."""
    assert _strip_npm_metadata([]) == []
    assert _strip_npm_metadata("bogus") == "bogus"


def test_npm_strip_does_not_mutate_input() -> None:
    """Outer-dict shallow copy means the caller's reference survives,
    but nested per-version dicts ARE mutated in place (callers don't
    retain references to them in production)."""
    raw = {"name": "x", "_id": "keep-in-input"}
    out = _strip_npm_metadata(raw)
    assert raw["_id"] == "keep-in-input"
    assert "_id" not in out


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def test_pypi_strip_drops_top_level_irrelevant() -> None:
    raw = {
        "info": {"name": "x", "version": "1.0.0"},
        "releases": {"1.0.0": []},
        "ownership": [{"user": "alice"}],
        "urls": [{"filename": "x-1.0.0.whl"}],
        "vulnerabilities": [{"id": "PYSEC-..."}],
        "last_serial": 12345,
    }
    out = _strip_pypi_metadata(raw)
    assert out["info"]["name"] == "x"
    assert out["releases"] == {"1.0.0": []}
    for k in ("ownership", "urls", "vulnerabilities", "last_serial"):
        assert k not in out


def test_pypi_strip_drops_per_release_file_redundant() -> None:
    raw = {
        "info": {},
        "releases": {
            "1.0.0": [
                {
                    "filename": "x-1.0.0-py3-none-any.whl",
                    "url": "https://...",
                    "digests": {"sha256": "abc", "md5": "def"},
                    "md5_digest": "def",
                    "has_sig": False,
                    "comment_text": "",
                    "upload_time": "2025-01-01T00:00:00",
                    "upload_time_iso_8601": "2025-01-01T00:00:00.000Z",
                    "downloads": -1,
                    "size": 1234,
                    "packagetype": "bdist_wheel",
                    "python_version": "py3",
                    "requires_python": ">=3.8",
                    "yanked": False,
                },
            ],
        },
    }
    out = _strip_pypi_metadata(raw)
    f = out["releases"]["1.0.0"][0]
    # Fields RAPTOR uses (wheel_compat, yanked_versions, supply-chain).
    for keep in ("filename", "url", "digests", "size", "packagetype",
                 "python_version", "requires_python", "yanked",
                 "upload_time_iso_8601"):
        assert keep in f, f"{keep} must be preserved"
    for drop in ("md5_digest", "has_sig", "comment_text", "upload_time",
                 "downloads"):
        assert drop not in f, f"{drop} should be stripped"


def test_pypi_strip_drops_cosmetic_info_fields() -> None:
    raw = {
        "info": {
            "name": "x",
            "version": "1.0.0",
            "license": "MIT",
            "license_expression": "MIT",
            "requires_python": ">=3.8",
            "requires_dist": ["dep1", "dep2"],
            "yanked": False,
            # Cosmetic — should be stripped.
            "description": "long readme...",
            "description_content_type": "text/markdown",
            "summary": "short blurb",
            "author": "alice",
            "author_email": "alice@example.com",
            "maintainer": "bob",
            "maintainer_email": "bob@example.com",
            "keywords": "foo,bar",
            "platform": ["any"],
            "home_page": "https://...",
            "project_url": "https://...",
            "project_urls": {"Homepage": "..."},
            "classifiers": ["Development Status :: 5 - Production/Stable"],
        },
        "releases": {},
    }
    out = _strip_pypi_metadata(raw)
    info = out["info"]
    # Fields RAPTOR reads: license, license_expression, requires_dist,
    # requires_python, yanked, version, name.
    for keep in ("name", "version", "license", "license_expression",
                 "requires_dist", "requires_python", "yanked"):
        assert keep in info, f"{keep} must be preserved"
    # Cosmetic fields stripped.
    for drop in ("description", "description_content_type", "summary",
                 "author", "author_email", "maintainer",
                 "maintainer_email", "keywords", "platform",
                 "home_page", "project_url", "project_urls"):
        assert drop not in info, f"{drop} should be stripped"
    # ``classifiers`` is deliberately PRESERVED — older PyPI packages
    # encode license only via the trove classifier ``License :: OSI
    # Approved :: <name>``, and ``_spdx_from_pypi`` falls back to
    # scanning classifiers. Stripping it (as the original 2026-05-20
    # implementation did) regressed license detection for mainstream
    # packages including jinja2, markdown-it-py, annotated-types,
    # mdurl, playwright. Surfaced 2026-05-21 by dogfood scan.
    assert "classifiers" in info, (
        "classifiers must be preserved — license-extraction fallback"
    )


def test_pypi_strip_passes_through_none() -> None:
    assert _strip_pypi_metadata(None) is None


def test_pypi_strip_handles_missing_releases_and_info() -> None:
    """Defensive: minimal envelope missing one or both nested blocks
    must not crash."""
    assert _strip_pypi_metadata({"info": {}}) == {"info": {}}
    assert _strip_pypi_metadata({"releases": {}}) == {"releases": {}}
    assert _strip_pypi_metadata({}) == {}
