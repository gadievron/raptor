"""Containment of LLM-writable path fields at raw-source read sites.

Checklist ``files[].path`` values, gap ``file`` fields and call-graph
keys are all LLM-writable run artefacts. Joining them onto the target
root with bare ``/`` semantics let an absolute value discard the root
entirely and a ``../`` value walk out of it (CWE-22) — host files
outside the scanned tree were read into LLM prompts, fuzz-dictionary
extraction and the ConceptIndex. Every site now goes through
``core.paths.confine`` (symlink-aware), mirroring the
``diagnostics.read_function_source`` reference fix.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


@pytest.fixture
def tree(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "src").mkdir()
    (target / "src" / "a.c").write_text(
        "int f(void) {\n    return 1;\n}\n",
    )
    secret = tmp_path / "secret.txt"
    secret.write_text("HOST-SECRET\n")
    return target, secret


class TestReadRawSource:
    def _read(self, target, rel):
        from core.audit.orchestrator import _read_raw_source

        return _read_raw_source(target, rel, 1, 3)

    def test_in_tree_read_works(self, tree):
        target, _ = tree
        assert "int f(void)" in self._read(target, "src/a.c")

    def test_absolute_path_refused(self, tree):
        target, secret = tree
        assert self._read(target, str(secret)) == ""

    def test_traversal_refused(self, tree):
        target, _ = tree
        assert self._read(target, "../secret.txt") == ""

    def test_symlink_out_refused(self, tree):
        target, secret = tree
        os.symlink(secret, target / "src" / "link.c")
        assert self._read(target, "src/link.c") == ""


class TestLlmSummariesReadSource:
    def _read(self, target, rel):
        from core.audit.llm_summaries import _read_source

        return _read_source(target, rel, "f", 1, 3)

    def test_in_tree_read_works(self, tree):
        target, _ = tree
        assert "int f(void)" in (self._read(target, "src/a.c") or "")

    def test_absolute_and_traversal_refused(self, tree):
        target, secret = tree
        assert self._read(target, str(secret)) is None
        assert self._read(target, "../secret.txt") is None


class TestFuzzHandoffChecklistSources:
    def test_escaping_checklist_path_skipped(self, tree, monkeypatch):
        target, _ = tree
        import core.audit.gaps as gaps_mod
        from core.audit.fuzz_handoff import _checklist_sources

        checklist = {
            "files": [
                {"path": "src/a.c"},
                {"path": "../secret.txt"},
            ],
        }
        monkeypatch.setattr(
            gaps_mod, "load_checklist", lambda _out: checklist,
        )
        sources = _checklist_sources(target, target)
        assert "src/a.c" in sources
        assert "../secret.txt" not in sources
        assert not any("HOST-SECRET" in v for v in sources.values())


class TestDispatchCompletenessGetSource:
    def test_symlink_out_refused_with_root(self, tree):
        target, secret = tree
        from core.audit.dispatch_completeness import _get_source

        os.symlink(secret, target / "src" / "link.py")
        assert _get_source("src/link.py", None, target) is None
        # In-tree read still works through the confined join.
        assert "int f(void)" in (_get_source("src/a.c", None, target) or "")


class TestFlattenChecklistWithSource:
    def _checklist(self, rel):
        return {
            "files": [{
                "path": rel,
                "items": [
                    {"name": "f", "line_start": 1, "line_end": 3},
                ],
            }],
        }

    def test_in_tree_path_enriched(self, tree):
        target, _ = tree
        from core.audit.orchestrator import _flatten_checklist_with_source

        out = _flatten_checklist_with_source(
            self._checklist("src/a.c"), str(target),
        )
        assert out and "int f(void)" in out[0]["source"]

    def test_escaping_path_gets_no_source(self, tree):
        target, _ = tree
        from core.audit.orchestrator import _flatten_checklist_with_source

        out = _flatten_checklist_with_source(
            self._checklist("../secret.txt"), str(target),
        )
        assert out and out[0]["source"] == ""


class TestConceptIndexJoinRoot:
    def test_checklist_target_path_field_is_not_the_join_root(
        self, tree, tmp_path,
    ):
        """The LLM-writable checklist must not choose the base
        directory for its own ``files[].path`` reads — only the
        caller-supplied run root enriches sources."""
        target, _ = tree
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "cred.c").write_text("SecretType token;\n")

        from core.audit.orchestrator import _build_concept_index_from_prep

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "study-list.json").write_text(json.dumps({
            "items": [{"name": "SecretType"}],
        }))
        checklist = {
            # Hostile artifact steering the join root off-target.
            "target_path": str(secrets_dir),
            "files": [{
                "path": "cred.c",
                "items": [
                    {"name": "g", "line_start": 1, "line_end": 1},
                ],
            }],
        }
        ref: list = [None]
        _build_concept_index_from_prep(ref, checklist, Path(out_dir))
        idx = ref[0]
        # Without a caller-supplied root nothing is read: the secrets
        # file's content must not have bound the concept.
        assert idx is None or not idx._fn_to_concepts
