"""Staleness gate for the sibling joern-flow import."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.joern_backend import import_sibling_joern_flows


def _mk_run(
    project: Path,
    name: str,
    *,
    flows: dict | None = None,
    content_hash: str | None = None,
    target: str | None = None,
) -> Path:
    run = project / name
    run.mkdir(parents=True)
    manifest: dict = {"status": "completed"}
    if content_hash is not None:
        manifest["content_hash"] = content_hash
    if target is not None:
        manifest["target_path"] = target
    (run / ".raptor-run.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    if flows is not None:
        (run / "joern-flows.json").write_text(
            json.dumps(flows), encoding="utf-8",
        )
    return run


class TestSiblingStalenessGate:
    def test_matching_hash_imports(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="aaaa1111",
        )
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}

    def test_mismatched_hash_skipped(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="bbbb2222",
        )
        assert import_sibling_joern_flows(out_dir) is None

    def test_sibling_without_hash_skipped(
        self, tmp_path: Path,
    ) -> None:
        """A sibling whose manifest carries no content hash cannot
        prove freshness — unverifiable flows read as stale, not fresh
        (the missing-hash bypass let arbitrary sibling flows in)."""
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(project, "older", flows={"a.c:f": [{"sink": "system"}]})
        assert import_sibling_joern_flows(out_dir) is None

    def test_unknown_current_hash_skipped(self, tmp_path: Path) -> None:
        """When the current run's hash is unavailable the gate cannot
        establish freshness — skip rather than trust."""
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current")
        _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="bbbb2222",
        )
        assert import_sibling_joern_flows(out_dir) is None

    def test_mixed_siblings_only_fresh_imported(
        self, tmp_path: Path,
    ) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        _mk_run(
            project, "fresh",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="aaaa1111",
        )
        _mk_run(
            project, "stale",
            flows={"b.c:g": [{"sink": "exec"}]},
            content_hash="cccc3333",
        )
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}


class TestMalformedSiblingArtifacts:
    """Sibling run dirs are shared-directory neighbours — malformed
    metadata or flow files must be skipped, not crash the import."""

    def test_non_dict_manifest_skipped(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        bad = project / "weird"
        bad.mkdir()
        (bad / ".raptor-run.json").write_text("[1, 2, 3]", encoding="utf-8")
        ok = _mk_run(
            project, "older",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="aaaa1111",
        )
        assert ok is not None
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}

    def test_non_dict_manifest_skipped_with_target_filter(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.joern_backend import sibling_run_dirs

        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", target=str(tmp_path))
        bad = project / "weird"
        bad.mkdir()
        (bad / ".raptor-run.json").write_text("[1, 2, 3]", encoding="utf-8")
        _mk_run(project, "older", target=str(tmp_path))
        dirs = sibling_run_dirs(out_dir, target_path=tmp_path)
        assert [d.name for d in dirs] == ["older"]

    def test_non_dict_flows_file_skipped(self, tmp_path: Path) -> None:
        import json as _json

        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        bad = _mk_run(project, "older", content_hash="aaaa1111")
        (bad / "joern-flows.json").write_text(
            _json.dumps([1, 2, 3]), encoding="utf-8",
        )
        assert import_sibling_joern_flows(out_dir) is None

    def test_oversize_flows_file_skipped(
        self, tmp_path: Path, caplog,
    ) -> None:
        """A joern-flows.json past the byte budget must be skipped via
        the loader's stat-gate refusal — not by reading the file and
        failing to parse it — while fresh siblings under the budget
        still import."""
        import logging
        import os

        project = tmp_path / "proj"
        out_dir = _mk_run(project, "current", content_hash="aaaa1111")
        oversize = _mk_run(project, "older", content_hash="aaaa1111")
        # Sparse file: st_size past the cap without materialising it.
        flows_path = oversize / "joern-flows.json"
        with flows_path.open("wb") as fh:
            os.truncate(fh.fileno(), 256 * 1024 * 1024 + 1)
        with caplog.at_level(logging.WARNING, logger="core.json.utils"):
            assert import_sibling_joern_flows(out_dir) is None
        # The skip must come from the size gate, not a failed parse of
        # a fully-buffered file.
        assert "refusing oversize" in caplog.text

        good = _mk_run(
            project, "newer",
            flows={"a.c:f": [{"sink": "system"}]},
            content_hash="aaaa1111",
        )
        assert good.is_dir()
        imported = import_sibling_joern_flows(out_dir)
        assert imported == {"a.c:f": [{"sink": "system"}]}
