"""Tests for ``packages.sca.models``.

``Dependency.__post_init__`` derives ``source_kind="lockfile"`` for
lockfile-parsed rows that don't set an explicit ``source_kind``, so
they don't inherit the ``"manifest"`` default and misreport their
provenance. Explicitly-set source_kind values are always preserved.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle


def _dep(**overrides) -> Dependency:
    kwargs = dict(
        ecosystem="PyPI", name="requests", version="2.31.0",
        declared_in=Path("/repo/Pipfile.lock"), scope="main",
        is_lockfile=True, pin_style=PinStyle.EXACT, direct=False,
        purl="pkg:pypi/requests@2.31.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    kwargs.update(overrides)
    return Dependency(**kwargs)


def test_lockfile_row_defaults_to_lockfile_source_kind() -> None:
    assert _dep(is_lockfile=True).source_kind == "lockfile"


def test_manifest_row_keeps_manifest_default() -> None:
    assert _dep(is_lockfile=False).source_kind == "manifest"


def test_explicit_source_kind_preserved_on_lockfile_row() -> None:
    d = _dep(is_lockfile=True, source_kind="cascade_resolver")
    assert d.source_kind == "cascade_resolver"


def test_explicit_manifest_on_non_lockfile_row_preserved() -> None:
    d = _dep(is_lockfile=False, source_kind="manifest")
    assert d.source_kind == "manifest"


def test_lockfile_parser_emits_lockfile_source_kind(tmp_path: Path) -> None:
    """End-to-end through one of the lockfile parsers that omits
    source_kind (Pipfile.lock)."""
    from packages.sca.parsers import pipfile_lock

    lock = tmp_path / "Pipfile.lock"
    lock.write_text(json.dumps({
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {},
    }), encoding="utf-8")
    deps = pipfile_lock.parse(lock)
    assert deps, "fixture should parse"
    assert all(d.is_lockfile for d in deps)
    assert all(d.source_kind == "lockfile" for d in deps)
