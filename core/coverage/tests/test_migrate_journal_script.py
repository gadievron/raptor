"""migrate-journal script: annotation metadata must actually migrate.

Loads the dispatch script by path (it has no importable module name)
with the trusted-env bypass so the trust-marker preamble doesn't
``sys.exit`` the test process.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "migrate-journal"
)


@pytest.fixture(scope="module")
def migrate_mod():
    import os

    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    spec = importlib.util.spec_from_loader(
        "migrate_journal_script",
        importlib.machinery.SourceFileLoader(
            "migrate_journal_script", str(_SCRIPT)),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_annotation(project_dir: Path) -> None:
    ann = project_dir / "annotations" / "src" / "a.c.md"
    ann.parent.mkdir(parents=True)
    ann.write_text(
        "## parse_header\n"
        "<!-- meta: status=clean source=llm hash=abc123def456 "
        "lines=10-42 -->\n"
        "Reviewed, no taint.\n"
    )


def test_annotation_hash_and_lines_extracted(migrate_mod, tmp_path):
    """Pre-fix the meta parse extracted only status/source — every
    migrated entry carried hash=None / line 0 and the migration's
    staleness anchoring was silently inert."""
    _write_annotation(tmp_path)
    entries = list(migrate_mod._iter_annotation_entries(tmp_path))
    assert len(entries) == 1
    e = entries[0]
    assert e["status"] == "clean"
    assert e["hash"] == "abc123def456"
    assert e["line_start"] == 10
    assert e["line_end"] == 42


def test_annotation_entry_projects_into_journal_entry(migrate_mod, tmp_path):
    _write_annotation(tmp_path)
    (rec,) = migrate_mod._iter_annotation_entries(tmp_path)
    entry = migrate_mod._to_journal_entry(rec, run_id="legacy-migration")
    assert entry.source_hash == "abc123def456"
    assert entry.line_start == 10
    assert entry.line_end == 42


def test_annotation_without_hash_or_lines_still_migrates(migrate_mod, tmp_path):
    ann = tmp_path / "annotations" / "b.c.md"
    ann.parent.mkdir(parents=True)
    ann.write_text(
        "## f\n"
        "<!-- meta: status=suspicious source=llm -->\n"
        "note\n"
    )
    (rec,) = migrate_mod._iter_annotation_entries(tmp_path)
    assert rec["hash"] is None
    assert "line_start" not in rec
    entry = migrate_mod._to_journal_entry(rec)
    assert entry.line_start == 0


def test_migrate_refuses_hostile_index_container(migrate_mod, tmp_path):
    """_migrate unconditionally REWRITES the index, so it is a writer:
    a non-object "entries" container must refuse (IndexUnreadable),
    never load-as-empty + rewrite — pre-fix the reader-degrade default
    silently destroyed the unknown container content."""
    from core.coverage.journal import IndexUnreadable

    _write_annotation(tmp_path)
    index_path = tmp_path / "review-journal-index.json"
    planted = '{"entries": [1, 2]}'
    index_path.write_text(planted, encoding="utf-8")

    with pytest.raises(IndexUnreadable):
        migrate_mod._migrate(tmp_path)
    assert index_path.read_text(encoding="utf-8") == planted


def test_migrate_survives_non_dict_occupant_at_target_key(
    migrate_mod, tmp_path,
):
    """A preserved non-dict row at the exact key a legacy entry
    migrates to crashed the ts compare (no .get on an int) pre-fix;
    the garbage occupant loses to the genuine migrated entry."""
    import json

    _write_annotation(tmp_path)
    (rec,) = migrate_mod._iter_annotation_entries(tmp_path)
    key = migrate_mod._to_journal_entry(rec, run_id="annotation").key
    index_path = tmp_path / "review-journal-index.json"
    index_path.write_text(
        json.dumps({"entries": {key: 7}}), encoding="utf-8",
    )

    added = migrate_mod._migrate(tmp_path)

    assert added == 1
    entries = json.loads(index_path.read_text(encoding="utf-8"))["entries"]
    assert entries[key]["function"] == "parse_header"
    assert entries[key]["legacy"] is True
