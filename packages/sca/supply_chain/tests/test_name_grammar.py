"""Tests for the typosquat feed name grammar — fetch-time and
load-time gates plus a lint of every shipped popular-list bundle."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.supply_chain import typosquat
from packages.sca.supply_chain._name_grammar import valid_feed_name
from packages.sca.supply_chain.typosquat_audit import (
    Candidate,
    render_markdown,
)

_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "popular"

# The package conftest's autouse fixture replaces
# ``typosquat._load_popular`` with a curated stub for determinism;
# capture the real function at import time (before fixtures run) so
# the load-time grammar gate can be tested against real file IO.
_REAL_LOAD_POPULAR = typosquat._load_popular


def test_grammar_accepts_canonical_shapes() -> None:
    assert valid_feed_name("npm", "lodash")
    assert valid_feed_name("npm", "@types/node")
    assert valid_feed_name("PyPI", "django-rest-framework")
    assert valid_feed_name("Cargo", "serde_json")
    assert valid_feed_name("Packagist", "symfony/console")
    assert valid_feed_name("Go", "github.com/gin-gonic/gin")
    assert valid_feed_name("Maven", "com.google.guava:guava")
    assert valid_feed_name("NuGet", "Microsoft.AspNetCore.Mvc")
    assert valid_feed_name("RubyGems", "aws-sdk-core")


def test_grammar_rejects_garbage_rows() -> None:
    # The row that actually shipped in the npm bundle.
    assert not valid_feed_name("npm", "equire('express'")
    assert not valid_feed_name("npm", "")
    assert not valid_feed_name("npm", "a" * 215)
    assert not valid_feed_name("npm", "<script>alert(1)</script>")
    assert not valid_feed_name("PyPI", "requests==2.0")
    assert not valid_feed_name("npm", None)
    assert not valid_feed_name("npm", 42)
    # Trailing newline: ``$`` under ``match`` would accept this —
    # a poisoned row distinct from the real package name.
    assert not valid_feed_name("npm", "express\n")
    assert not valid_feed_name("PyPI", "requests\n")


def test_grammar_unknown_ecosystem_fails_closed() -> None:
    assert not valid_feed_name("Homebrew", "wget")


def test_all_shipped_bundles_pass_the_grammar() -> None:
    """Feed lint: every row of every bundled popular list must pass
    its ecosystem's grammar — a failing row means either feed garbage
    got committed or the grammar regressed against real names."""
    bundles = sorted(_DATA_DIR.glob("*.json"))
    assert bundles, "no popular-list bundles found"
    offenders: list[str] = []
    for bundle in bundles:
        eco = bundle.stem
        rows = json.loads(bundle.read_text(encoding="utf-8"))
        offenders.extend(
            f"{bundle.name}: {row!r}"
            for row in rows if not valid_feed_name(eco, row)
        )
    assert offenders == [], offenders


def test_load_popular_drops_grammar_failing_rows(tmp_path, monkeypatch) -> None:
    """Load-time gate: garbage in an already-shipped bundle must not
    become a trusted exact-match."""
    data_dir = tmp_path
    (data_dir / "npm.json").write_text(json.dumps(
        ["lodash", "equire('express'", "@types/node"],
    ), encoding="utf-8")
    monkeypatch.setattr(typosquat, "_DATA_DIR", data_dir)
    monkeypatch.setattr(typosquat, "_POPULAR_BY_ECO", {})
    loaded = _REAL_LOAD_POPULAR("npm")
    assert "lodash" in loaded
    assert "@types/node" in loaded
    assert "equire('express'" not in loaded


def test_render_markdown_escapes_hostile_names() -> None:
    hostile = Candidate(
        name="evil`|payload", near_twin="evil", rank=1, twin_rank=2,
        distance=1,
    )
    md = render_markdown({"npm": [hostile]})
    assert "evil\\`\\|payload" in md
    assert "evil`|payload" not in md
