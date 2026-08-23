"""Sibling joern-flows staleness gate for core.audit.joern_backend.

import_sibling_joern_flows must skip a sibling run whose manifest
content_hash differs from the current run's hash, import it when the
hashes match, and preserve the legacy import behaviour when either
hash is unavailable.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.joern_backend import (
    _current_content_hash,
    import_sibling_joern_flows,
)

_FLOWS = {"src/a.c": [{"source_method": "read_input", "sink": "memcpy"}]}


def _make_sibling(
    project_dir: Path,
    name: str,
    target: Path,
    content_hash: str | None,
    flows: dict | None = None,
) -> Path:
    sib = project_dir / name
    sib.mkdir()
    (sib / "joern-flows.json").write_text(json.dumps(flows or _FLOWS))
    manifest: dict = {"target_path": str(target)}
    if content_hash is not None:
        manifest["content_hash"] = content_hash
    (sib / ".raptor-run.json").write_text(json.dumps(manifest))
    return sib


def _make_out_dir(
    project_dir: Path, target: Path, content_hash: str | None,
) -> Path:
    out_dir = project_dir / "run_current"
    out_dir.mkdir()
    manifest: dict = {"target_path": str(target)}
    if content_hash is not None:
        manifest["content_hash"] = content_hash
    (out_dir / ".raptor-run.json").write_text(json.dumps(manifest))
    return out_dir


class TestStalenessGate:
    def test_hash_mismatch_skips_sibling(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "b" * 16)
        _make_sibling(project, "run_old", target, "a" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported is None

    def test_hash_match_imports_sibling(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "c" * 16)
        _make_sibling(project, "run_same", target, "c" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported == _FLOWS

    def test_sibling_without_hash_skipped(self, tmp_path):
        # A sibling with no content hash cannot prove freshness:
        # unverifiable flows are stale/untrusted, never imported.
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "d" * 16)
        _make_sibling(project, "run_legacy", target, None)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported is None

    def test_current_hash_unavailable_skips(self, tmp_path):
        # Sibling carries a hash but the current run's hash is neither
        # recorded nor derivable (no manifest, no target_path): the
        # gate cannot establish freshness, so nothing imports.
        project = tmp_path / "project"
        project.mkdir()
        out_dir = project / "run_current"
        out_dir.mkdir()
        sib = project / "run_old"
        sib.mkdir()
        (sib / "joern-flows.json").write_text(json.dumps(_FLOWS))
        (sib / ".raptor-run.json").write_text(
            json.dumps({"content_hash": "e" * 16}),
        )

        imported = import_sibling_joern_flows(out_dir, target_path=None)
        assert imported is None

    def test_mixed_siblings_merge_only_fresh(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "f" * 16)
        _make_sibling(project, "run_stale", target, "0" * 16,
                      flows={"src/stale.c": [{"source_method": "old"}]})
        _make_sibling(project, "run_fresh", target, "f" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported == _FLOWS
        assert "src/stale.c" not in imported


class TestCurrentContentHash:
    def test_prefers_own_manifest(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "1" * 16)
        assert _current_content_hash(out_dir, target) == "1" * 16

    def test_derives_from_target_tree(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        out_dir = tmp_path / "run"
        out_dir.mkdir()

        from packages.joern.runner import _target_content_hash
        derived = _current_content_hash(out_dir, target)
        assert derived == _target_content_hash(target)

    def test_none_when_unavailable(self, tmp_path):
        out_dir = tmp_path / "run"
        out_dir.mkdir()
        assert _current_content_hash(out_dir, None) is None

    def test_derived_hash_gates_sibling(self, tmp_path):
        # No writer sets content_hash on the current run yet — the
        # derived-hash path must gate a mismatched sibling on its own.
        target = tmp_path / "target"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        project = tmp_path / "project"
        project.mkdir()
        out_dir = project / "run_current"
        out_dir.mkdir()
        _make_sibling(project, "run_old", target, "0" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported is None

    def test_derived_hash_admits_matching_sibling(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        project = tmp_path / "project"
        project.mkdir()
        out_dir = project / "run_current"
        out_dir.mkdir()

        from packages.joern.runner import _target_content_hash
        _make_sibling(
            project, "run_same", target, _target_content_hash(target),
        )

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported == _FLOWS
