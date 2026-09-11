"""The ``.validated`` skip-cache of ``libexec/raptor-validate-schema``
must be keyed by schema type, not just filename + content hash.

A file validated as one type must not short-circuit a later validation
request under a different type — that would claim a pass for a check
that never ran.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-validate-schema"


@pytest.fixture(scope="module")
def validator():
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_validate_schema", str(SCRIPT),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        yield mod
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class TestTypeAwareCache:
    def test_same_type_hits_cache(self, validator, tmp_path: Path):
        p = tmp_path / "foo.json"
        p.write_text("{}", encoding="utf-8")
        validator._write_validated(
            tmp_path, p.name, validator._hash_file(p), "findings",
        )
        assert validator.is_already_validated(p, "findings")

    def test_different_type_misses_cache(self, validator, tmp_path: Path):
        p = tmp_path / "foo.json"
        p.write_text("{}", encoding="utf-8")
        validator._write_validated(
            tmp_path, p.name, validator._hash_file(p), "findings",
        )
        assert not validator.is_already_validated(p, "attack-tree")

    def test_content_change_misses_cache(self, validator, tmp_path: Path):
        p = tmp_path / "foo.json"
        p.write_text("{}", encoding="utf-8")
        validator._write_validated(
            tmp_path, p.name, validator._hash_file(p), "findings",
        )
        p.write_text('{"changed": true}', encoding="utf-8")
        assert not validator.is_already_validated(p, "findings")

    def test_legacy_typeless_record_not_claimed_for_type(
        self, validator, tmp_path: Path,
    ):
        # A pre-existing type-less record must trigger one
        # re-validation under the typed lookup rather than being
        # claimed for an arbitrary type.
        p = tmp_path / "foo.json"
        p.write_text("{}", encoding="utf-8")
        validator._write_validated(tmp_path, p.name, validator._hash_file(p))
        assert validator.is_already_validated(p)
        assert not validator.is_already_validated(p, "findings")

    def test_typed_records_roundtrip_through_index(
        self, validator, tmp_path: Path,
    ):
        # Two files with different types coexist in one .validated.
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text("{}", encoding="utf-8")
        b.write_text("[]", encoding="utf-8")
        validator._write_validated(
            tmp_path, a.name, validator._hash_file(a), "findings",
        )
        validator._write_validated(
            tmp_path, b.name, validator._hash_file(b), "attack-paths",
        )
        assert validator.is_already_validated(a, "findings")
        assert validator.is_already_validated(b, "attack-paths")
        assert not validator.is_already_validated(a, "attack-paths")
