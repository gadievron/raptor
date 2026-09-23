"""Contract tests for the registry-document → renderer-key seam.

The fixtures below are FAITHFUL raw registry documents — the exact
top-level shapes ``PyPIClient.get_metadata`` ("raw PyPI JSON":
``info``/``releases``/``urls``) and ``NpmClient.get_metadata`` (raw
packument: ``maintainers``/``time``/``repository``/``readme``/
``versions``) return. Tests that hand the renderers their own
invented keys are exactly what masked the evidence-blind prompts.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.llm import maintainer_trust, slopsquat_verdict
from packages.sca.llm.registry_view import (
    RENDERED_KEYS,
    build_registry_view,
    iter_maintainers,
)
from packages.sca.models import Confidence, Dependency, PinStyle

# A faithful (trimmed) npm packument — the raw shape the npm client
# returns, NOT the renderer's key vocabulary.
RAW_PACKUMENT = {
    "_id": "left-pod",
    "name": "left-pod",
    "dist-tags": {"latest": "1.1.0"},
    "maintainers": [
        {"name": "alice", "email": "alice@example.org"},
        {"name": "mallory", "email": "mallory@attacker.example"},
    ],
    "time": {
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2026-02-02T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.1.0": "2026-02-01T12:00:00.000Z",
    },
    "repository": {"type": "git", "url": "git+https://github.com/e/x.git"},
    "readme": "# left-pod\nPads things. New in 1.1.0: postinstall step.",
    "versions": {
        "1.0.0": {
            "name": "left-pod",
            "version": "1.0.0",
            "maintainers": [{"name": "alice", "email": "alice@example.org"}],
            "dist": {"unpackedSize": 2048},
        },
        "1.1.0": {
            "name": "left-pod",
            "version": "1.1.0",
            "maintainers": [
                {"name": "alice", "email": "alice@example.org"},
                {"name": "mallory", "email": "mallory@attacker.example"},
            ],
            "dist": {"unpackedSize": 900000},
            "deprecated": "use right-pod instead",
        },
    },
}

# A faithful (trimmed) PyPI JSON document.
RAW_PYPI_JSON = {
    "info": {
        "name": "example-pkg",
        "version": "2.0.0",
        "author": "Alice Author",
        "author_email": "alice@example.org",
        "maintainer": "",
        "maintainer_email": "",
        "home_page": "",
        "project_urls": {
            "Homepage": "https://example.org",
            "Repository": "https://github.com/e/example-pkg",
        },
        "description": "# example-pkg\nDoes examples.",
        "yanked": False,
    },
    "releases": {
        "1.0.0": [
            {"upload_time_iso_8601": "2021-03-01T00:00:00.000000Z"},
        ],
        "2.0.0": [
            {"upload_time_iso_8601": "2026-01-15T00:00:00.000000Z"},
        ],
    },
    "urls": [],
}


def _dep(ecosystem: str, name: str) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.1.0",
        declared_in=Path("/fake/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@1.1.0",
        parser_confidence=Confidence(level="high"),
    )


class TestBuildRegistryView:
    def test_npm_view_keys_match_renderer_contract(self):
        view = build_registry_view("npm", RAW_PACKUMENT)
        assert set(view) <= RENDERED_KEYS
        assert [m["name"] for m in view["maintainers"]] == [
            "alice", "mallory",
        ]
        assert view["repository_url"] == "git+https://github.com/e/x.git"
        assert view["publish_dates"]  # per-version times, not created/modified
        assert view["deprecated"] == "use right-pod instead"
        assert "postinstall" in view["readme_preview"]

    def test_pypi_view_keys_match_renderer_contract(self):
        view = build_registry_view("PyPI", RAW_PYPI_JSON)
        assert set(view) <= RENDERED_KEYS
        assert view["maintainers"][0]["name"] == "Alice Author"
        assert view["repository_url"] == "https://github.com/e/example-pkg"
        assert len(view["publish_dates"]) == 2
        assert view["first_publish"].startswith("2021-03-01")
        assert view["latest_publish"].startswith("2026-01-15")

    def test_unrendered_keys_are_stripped_not_asserted(
        self, monkeypatch,
    ):
        """The renderer-keys contract is enforced by stripping (with
        a warning), not by a bare assert that ``-O`` removes — an
        unknown key from a buggy projection must never ride into the
        prompt in any interpreter mode."""
        from packages.sca.llm import registry_view

        def bad_view(raw):
            return {"maintainers": ["a"], "not_a_rendered_key": "x"}

        monkeypatch.setattr(registry_view, "_view_pypi", bad_view)
        view = build_registry_view("PyPI", {"info": {}})
        assert "not_a_rendered_key" not in view
        assert view["maintainers"] == ["a"]
        assert set(view) <= RENDERED_KEYS

    def test_unwired_ecosystem_and_junk_docs_yield_empty(self):
        assert build_registry_view("Cargo", RAW_PACKUMENT) == {}
        assert build_registry_view("npm", None) == {}
        assert build_registry_view("npm", ["not", "a", "dict"]) == {}

    def test_hostile_document_degrades_never_raises(self):
        hostile = {
            "info": "not-a-dict",
            "releases": {"1.0": "junk"},
            "maintainers": ["string-entry", 42, None, {"name": 7}],
            "time": {"1.0.0": {"nested": "junk"}},
            "repository": 13,
            "readme": ["list"],
            "versions": "junk",
            "dist-tags": None,
        }
        for eco in ("npm", "PyPI"):
            view = build_registry_view(eco, hostile)
            assert isinstance(view, dict)
            assert set(view) <= RENDERED_KEYS


class TestRenderersConsumeRealProducerOutput:
    """End-to-end through the seam: raw document → view → prompt block."""

    def test_maintainer_trust_prompt_carries_npm_evidence(self):
        view = build_registry_view("npm", RAW_PACKUMENT)
        block = maintainer_trust._format_metadata(_dep("npm", "left-pod"), view)
        assert "alice <alice@example.org>" in block
        assert "mallory" in block
        assert "Recent publishes:" in block
        assert "Repository: git+https://github.com/e/x.git" in block
        assert "Deprecated: use right-pod instead" in block

    def test_maintainer_trust_prompt_carries_pypi_evidence(self):
        view = build_registry_view("PyPI", RAW_PYPI_JSON)
        block = maintainer_trust._format_metadata(
            _dep("PyPI", "example-pkg"), view,
        )
        assert "Alice Author" in block
        assert "Recent publishes:" in block
        assert "Repository: https://github.com/e/example-pkg" in block

    def test_slopsquat_prompt_carries_evidence(self):
        view = build_registry_view("npm", RAW_PACKUMENT)
        block = slopsquat_verdict._format_metadata(
            _dep("npm", "left-pod"), view,
        )
        assert "First published:" in block
        assert "alice" in block
        assert "README preview" in block

    def test_renderers_skip_hostile_maintainer_rows(self):
        # The packument is hostile input: non-dict entries and
        # non-string fields must render as skipped rows, not raise
        # AttributeError out of the review stage.
        meta = {
            "maintainers": [
                "string-entry",
                42,
                None,
                {"name": 7, "email": ["x"]},
                {"name": "alice", "email": "alice@example.org"},
            ],
        }
        for renderer in (
            maintainer_trust._format_metadata,
            slopsquat_verdict._format_metadata,
        ):
            block = renderer(_dep("npm", "left-pod"), meta)
            assert "alice" in block


class TestIterMaintainers:
    def test_limit_and_junk_skipping(self):
        meta = {
            "maintainers": [
                {"name": "a"},
                "junk",
                {"name": "b", "email": "b@example.org"},
                {"name": "c"},
            ],
        }
        rows = list(iter_maintainers(meta, 2))
        assert [r[0] for r in rows] == ["a", "b"]

    def test_non_list_maintainers(self):
        assert list(iter_maintainers({"maintainers": "junk"}, 5)) == []
        assert list(iter_maintainers({}, 5)) == []
