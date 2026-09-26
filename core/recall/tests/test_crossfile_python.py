"""Synthetic cross-file Python fixtures: ground truth + determinism."""

from __future__ import annotations

import json

import pytest

from core.recall.crossfile_python import (
    CrossfileFixtureError,
    SINK_CLASSES,
    emit_channel_labels,
    generate_fixtures,
    main as crossfile_main,
)
from core.recall.manifest import parse_manifest


def _gen(tmp_path, name="a", **kw):
    return generate_fixtures(tmp_path / name, seed=kw.pop("seed", 7),
                             cases_per_class=kw.pop("cases", 1), **kw)


class TestGroundTruth:
    def test_manifest_is_schema_valid_synthetic(self, tmp_path):
        manifest, cases, sha = _gen(tmp_path)
        parsed = parse_manifest(json.loads(json.dumps(manifest)))
        assert parsed.language == "python"
        assert parsed.profile == "agentic"
        assert parsed.pinned_sha == sha
        for e in parsed.expected + parsed.clean_regions:
            assert e.provenance.kind == "synthetic"
            assert e.provenance.generator == "crossfile-python"
            assert e.provenance.seed == 7

    def test_every_class_yields_vuln_and_sanitized_twin(self, tmp_path):
        manifest, cases, _ = _gen(tmp_path)
        assert len(manifest["expected"]) == len(SINK_CLASSES)
        assert len(manifest["clean_regions"]) == len(SINK_CLASSES)
        assert {e["cwe"] for e in manifest["expected"]} == {
            sc.cwe for sc in SINK_CLASSES.values()}
        for e in manifest["clean_regions"]:
            assert e["id"].endswith("_safe")

    def test_flow_actually_crosses_files(self, tmp_path):
        _, cases, _ = _gen(tmp_path)
        repo = tmp_path / "a" / "repo"
        for c in cases:
            pkg = repo / c.package_dir
            route = (pkg / "app.py").read_text(encoding="utf-8")
            helper = (pkg / "helpers.py").read_text(encoding="utf-8")
            sinks = (pkg / "sinks.py").read_text(encoding="utf-8")
            marker = SINK_CLASSES[c.sink_class].sink_marker
            # sink lives ONLY in the sink file; the source only in the
            # route file — the flow has no single-file shortcut.
            assert marker in sinks
            assert marker not in route and marker not in helper
            assert "request.args" in route
            assert "request.args" not in helper
            assert "request.args" not in sinks
            assert f"def {c.sink_fn}(" in sinks
            assert c.sink_fn in helper  # helper forwards to the sink

    def test_sink_line_points_at_the_dangerous_call(self, tmp_path):
        _, cases, _ = _gen(tmp_path)
        repo = tmp_path / "a" / "repo"
        for c in cases:
            lines = (repo / c.sink_file).read_text(
                encoding="utf-8").splitlines()
            marker = SINK_CLASSES[c.sink_class].sink_marker
            assert marker in lines[c.sink_line - 1]
            assert c.sink_fn_start <= c.sink_line <= c.sink_fn_end

    def test_sanitized_twin_sanitizes_in_helper_only(self, tmp_path):
        _, cases, _ = _gen(tmp_path)
        repo = tmp_path / "a" / "repo"
        by_id = {c.case_id: c for c in cases}
        for c in cases:
            if c.sanitized:
                continue
            twin = by_id[c.case_id + "_safe"]
            sc = SINK_CLASSES[c.sink_class]
            vuln_helper = (repo / c.package_dir / "helpers.py").read_text(
                encoding="utf-8")
            safe_helper = (repo / twin.package_dir
                           / "helpers.py").read_text(encoding="utf-8")
            sanitizer_head = sc.sanitizer_expr.split("(", 1)[0]
            assert sanitizer_head in safe_helper
            assert sanitizer_head not in vuln_helper
            # The sink body itself is IDENTICAL modulo identifiers —
            # the FP test is sanitizer awareness, not a changed sink.
            assert sc.sink_marker in (
                repo / twin.sink_file).read_text(encoding="utf-8")

    def test_generated_files_are_valid_python(self, tmp_path):
        # Producers parse the fixture tree; a syntax error would be a
        # silent zero-findings run, not a measurement.
        _gen(tmp_path, cases=2)
        repo = tmp_path / "a" / "repo"
        for path in repo.rglob("*.py"):
            compile(path.read_text(encoding="utf-8"), str(path), "exec")

    def test_expected_and_clean_ids_disjoint_and_unique(self, tmp_path):
        manifest, _, _ = _gen(tmp_path, cases=2)
        exp = [e["id"] for e in manifest["expected"]]
        cln = [e["id"] for e in manifest["clean_regions"]]
        assert len(set(exp)) == len(exp)
        assert len(set(cln)) == len(cln)
        assert not set(exp) & set(cln)


class TestDeterminism:
    def test_same_seed_reproduces_pin_and_labels(self, tmp_path):
        m1, _, sha1 = _gen(tmp_path, "a", seed=11)
        m2, _, sha2 = _gen(tmp_path, "b", seed=11)
        assert sha1 == sha2
        m1["target"]["local_path"] = m2["target"]["local_path"]
        assert m1 == m2

    def test_different_seed_moves_the_pin(self, tmp_path):
        _, _, sha1 = _gen(tmp_path, "a", seed=11)
        _, _, sha2 = _gen(tmp_path, "b", seed=12)
        assert sha1 != sha2


class TestRefusals:
    def test_unknown_class_refused(self, tmp_path):
        with pytest.raises(CrossfileFixtureError, match="unknown"):
            generate_fixtures(tmp_path / "x", classes=["bogus"])

    def test_existing_repo_dir_refused(self, tmp_path):
        (tmp_path / "x" / "repo").mkdir(parents=True)
        with pytest.raises(CrossfileFixtureError, match="create-only"):
            generate_fixtures(tmp_path / "x")

    def test_zero_cases_refused(self, tmp_path):
        with pytest.raises(CrossfileFixtureError, match=">= 1"):
            generate_fixtures(tmp_path / "x", cases_per_class=0)


class TestChannelLabels:
    def test_labels_validate_and_group_by_channel(self, tmp_path):
        _, cases, sha = _gen(tmp_path, classes=["command_injection"])
        labels_dir = tmp_path / "labels"
        written = emit_channel_labels(
            cases, repo=tmp_path / "a" / "repo", sha=sha, seed=7,
            channel="taint_crossfile", bug_class="variant",
            repo_key="crossfile-python-seed7", labels_dir=labels_dir,
            labeled_at="2026-01-01")
        assert len(written) == 2  # vuln + sanitized twin
        # The channels loader (the production consumer) accepts them.
        from core.audit.corpus.channels import load_channel_labels
        loaded = load_channel_labels("taint_crossfile", base=labels_dir)
        assert {(x.expected_status, x.bug_class) for x in loaded} == {
            ("finding", "variant"), ("clean", "clean")}
        for x in loaded:
            assert x.channel == "taint_crossfile"
            assert x.source.sha == sha
            assert x.source.span_sha  # content-addressed pin
            assert x.cwe == "CWE-78"

    def test_span_sha_matches_the_pinned_content(self, tmp_path):
        _, cases, sha = _gen(tmp_path, classes=["sql_injection"])
        repo = tmp_path / "a" / "repo"
        written = emit_channel_labels(
            cases, repo=repo, sha=sha, seed=7, channel="taint_crossfile",
            bug_class="variant", repo_key="k", labels_dir=tmp_path / "l",
            labeled_at="2026-01-01")
        from core.audit.corpus.label import compute_span_sha, load_label
        for path in written:
            label = load_label(path)
            text = (repo / label.source.file).read_text(encoding="utf-8")
            assert label.source.span_sha == compute_span_sha(
                text, label.source.line_start, label.source.line_end)

    def test_invalid_channel_refused(self, tmp_path):
        _, cases, sha = _gen(tmp_path, classes=["code_injection"])
        from core.audit.corpus.channels import ChannelCorpusError
        with pytest.raises(ChannelCorpusError, match="channel"):
            emit_channel_labels(
                cases, repo=tmp_path / "a" / "repo", sha=sha, seed=7,
                channel="Taint-Crossfile", bug_class="variant",
                repo_key="k", labels_dir=tmp_path / "l")

    def test_invalid_bug_class_refused(self, tmp_path):
        _, cases, sha = _gen(tmp_path, classes=["code_injection"])
        with pytest.raises(ValueError, match="bug_class"):
            emit_channel_labels(
                cases, repo=tmp_path / "a" / "repo", sha=sha, seed=7,
                channel="taint_crossfile", bug_class="injectionz",
                repo_key="k", labels_dir=tmp_path / "l")


class TestCli:
    def test_end_to_end_with_labels(self, tmp_path, capsys):
        out = tmp_path / "fx"
        rc = crossfile_main([
            "--out-dir", str(out), "--seed", "3",
            "--cases-per-class", "1", "--class", "command_injection",
            "--channel", "taint_crossfile", "--bug-class", "variant",
            "--repo-key", "crossfile-python-seed3"])
        assert rc == 0
        printed = capsys.readouterr().out
        assert "manifest:" in printed
        manifest = json.loads((out / "manifest.json").read_text())
        assert parse_manifest(manifest).name == "crossfile-python-seed3"
        assert list((out / "channel-labels").rglob("*.label.json"))

    def test_channel_requires_bug_class_and_repo_key(self, tmp_path):
        with pytest.raises(SystemExit):
            crossfile_main(["--out-dir", str(tmp_path / "x"),
                            "--channel", "taint_crossfile"])
