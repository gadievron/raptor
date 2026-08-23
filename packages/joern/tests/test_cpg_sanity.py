"""Empty-CPG sanity check: joern-parse can exit 0 while writing a CPG
with zero METHOD nodes (observed live: rubysrc's embedded parser gem
failing to load — exit code 0, 13 KB cpg.bin, 0 methods). The probe
reads flatgraph's trailing JSON manifest, so it costs a file tail read
instead of a JVM boot.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import packages.joern.runner as runner_mod
from packages.joern.runner import (
    build_cpg,
    build_cpg_cached,
    cpg_method_count,
    load_cached_cpg,
)


def _flatgraph_bytes(method_count: int | None, *, anchor: bool = True,
                     corrupt: bool = False) -> bytes:
    """Minimal byte-shape of a flatgraph file: opaque body followed by
    the trailing JSON manifest (which opens with {"version")."""
    body = b"\x00FLATGRAPH-OPAQUE-BODY\x01" * 8
    if not anchor:
        return body
    nodes = [{"nodeLabel": "TYPE_DECL", "nnodes": 3}]
    if method_count is not None:
        nodes.append({"nodeLabel": "METHOD", "nnodes": method_count})
    # json.dumps with "version" first already opens with the {"version"
    # anchor bytes the probe searches for.
    manifest = json.dumps({"version": 1, "nodes": nodes, "edges": []})
    assert manifest.startswith('{"version"')
    raw = manifest.encode()
    if corrupt:
        raw = raw[:-4]
    return body + raw


def _write_cpg(path: Path, method_count: int | None, **kw) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_flatgraph_bytes(method_count, **kw))
    return path


class TestCpgMethodCount:
    def test_populated(self, tmp_path: Path):
        p = _write_cpg(tmp_path / "cpg.bin", 5)
        assert cpg_method_count(p) == 5

    def test_empty(self, tmp_path: Path):
        p = _write_cpg(tmp_path / "cpg.bin", 0)
        assert cpg_method_count(p) == 0

    def test_missing_file_is_unknown(self, tmp_path: Path):
        assert cpg_method_count(tmp_path / "nope.bin") is None

    def test_no_anchor_is_unknown(self, tmp_path: Path):
        p = _write_cpg(tmp_path / "cpg.bin", 5, anchor=False)
        assert cpg_method_count(p) is None

    def test_corrupt_manifest_is_unknown(self, tmp_path: Path):
        p = _write_cpg(tmp_path / "cpg.bin", 5, corrupt=True)
        assert cpg_method_count(p) is None

    def test_missing_method_row_is_unknown(self, tmp_path: Path):
        # A parsed manifest without a METHOD row is an unexpected
        # schema shape — unknown, never "empty".
        p = _write_cpg(tmp_path / "cpg.bin", None)
        assert cpg_method_count(p) is None

    def test_tail_window_seek_path(self, tmp_path: Path, monkeypatch):
        # File larger than the tail window: the probe must still find
        # the manifest at EOF via the seek branch.
        monkeypatch.setattr(runner_mod, "_CPG_MANIFEST_TAIL_BYTES", 256)
        body = b"\x00" * 4096
        manifest = json.dumps(
            {"version": 1,
             "nodes": [{"nodeLabel": "METHOD", "nnodes": 7}]},
        ).encode()
        p = tmp_path / "cpg.bin"
        p.write_bytes(body + manifest)
        assert cpg_method_count(p) == 7

    def test_anchor_in_body_does_not_shadow_manifest(self, tmp_path: Path):
        # A source string pool containing the literal anchor sits
        # BEFORE the manifest; rfind must land on the real one.
        decoy = json.dumps(
            {"version": 9,
             "nodes": [{"nodeLabel": "METHOD", "nnodes": 999}]},
        ).encode()
        real = json.dumps(
            {"version": 1,
             "nodes": [{"nodeLabel": "METHOD", "nnodes": 2}]},
        ).encode()
        p = tmp_path / "cpg.bin"
        p.write_bytes(decoy + b"\x00pad\x00" + real)
        assert cpg_method_count(p) == 2


def _writing_runner(method_count: int | None, returncode: int = 0):
    """Fake subprocess runner that writes a cpg.bin like joern-parse."""
    def runner(cmd, **kwargs):
        out_idx = cmd.index("--output") + 1
        _write_cpg(Path(cmd[out_idx]), method_count)
        return SimpleNamespace(stdout="", stderr="", returncode=returncode)
    return runner


class TestBuildCpgEmptyRejection:
    def test_empty_cpg_rejected_as_parse_failure(self, tmp_path: Path, caplog):
        target = tmp_path / "src"
        target.mkdir()
        (target / "x.rb").write_text("def f; end\n")
        with caplog.at_level("ERROR", logger="packages.joern.runner"):
            cpg = build_cpg(
                target,
                languages={"rubysrc"},
                subprocess_runner=_writing_runner(0),
                output_dir=tmp_path / "out",
            )
        assert not cpg.exists()
        assert any(
            "zero METHOD nodes" in r.message and "rubysrc" in r.message
            for r in caplog.records
        )

    def test_populated_cpg_kept(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        cpg = build_cpg(
            target,
            languages={"c"},
            subprocess_runner=_writing_runner(4),
            output_dir=tmp_path / "out",
        )
        assert cpg.exists()

    def test_unreadable_manifest_passes_through(self, tmp_path: Path):
        # Probe limits must never fail a build: unknown ≠ empty.
        def raw_runner(cmd, **kwargs):
            out_idx = cmd.index("--output") + 1
            Path(cmd[out_idx]).write_bytes(b"\x00opaque, no manifest")
            return SimpleNamespace(stdout="", stderr="", returncode=0)

        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        cpg = build_cpg(
            target,
            languages={"c"},
            subprocess_runner=raw_runner,
            output_dir=tmp_path / "out",
        )
        assert cpg.exists()


class TestCachePathEmptyRejection:
    def test_cached_empty_refused_on_load(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        cache = tmp_path / "cache"
        cpg_dir = cache / "joern-cpg"
        _write_cpg(cpg_dir / "cpg.bin", 0)
        # Legacy manifest (pre-fix: no method_count field) with a
        # matching content hash — only the probe can refuse it.
        runner_mod._write_cpg_manifest(
            cpg_dir, target, runner_mod._target_content_hash(target),
        )
        assert load_cached_cpg(target, cache) is None

    def test_cached_populated_loads(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        cache = tmp_path / "cache"
        cpg_dir = cache / "joern-cpg"
        _write_cpg(cpg_dir / "cpg.bin", 3)
        runner_mod._write_cpg_manifest(
            cpg_dir, target, runner_mod._target_content_hash(target),
        )
        cached = load_cached_cpg(target, cache)
        assert cached is not None and cached.exists()

    def test_build_cached_records_method_count(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }\n")
        cache = tmp_path / "cache"
        build_cpg_cached(
            target, cache,
            languages={"c"},
            subprocess_runner=_writing_runner(6),
        )
        manifest = json.loads((cache / "joern-cpg" / "manifest.json").read_text())
        assert manifest["method_count"] == 6

    def test_build_cached_empty_writes_no_manifest(self, tmp_path: Path):
        # build_cpg deletes the empty CPG, so the cache never persists
        # it (exists() gate on the manifest write).
        target = tmp_path / "src"
        target.mkdir()
        (target / "x.rb").write_text("def f; end\n")
        cache = tmp_path / "cache"
        cpg = build_cpg_cached(
            target, cache,
            languages={"rubysrc"},
            subprocess_runner=_writing_runner(0),
        )
        assert not cpg.exists()
        assert not (cache / "joern-cpg" / "manifest.json").exists()
