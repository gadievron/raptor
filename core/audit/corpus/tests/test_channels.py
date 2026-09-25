"""Per-channel micro-corpus layout, loader, and grouping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.corpus.channels import (
    ChannelCorpusError,
    channel_labels_dir,
    group_labels_by_channel,
    list_channels,
    load_channel_labels,
    validate_channel_name,
)
from core.audit.corpus.label import FunctionLabel, SourcePin


def _label_dict(function_id: str, channel: str = "") -> dict:
    # SYNTHETIC example label (demo repo, invented function) — the
    # micro-corpus fixture convention: structure only, never a
    # real-vulnerability label.
    d = {
        "schema_version": 1,
        "function_id": function_id,
        "bug_class": "lifecycle",
        "expected_status": "clean",
        "rationale": "Synthetic structure-example label.",
        "source": {
            "repo": "demo-repo",
            "sha": "abc123",
            "file": "src/demo.c",
            "line_start": 1,
            "line_end": 10,
        },
        "labeler": "test",
        "labeled_at": "2026-01-01",
    }
    if channel:
        d["channel"] = channel
    return d


def _write_label(base: Path, channel: str, name: str,
                 label: dict) -> Path:
    d = base / channel / "lifecycle"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{name}.label.json"
    path.write_text(json.dumps(label), encoding="utf-8")
    return path


class TestNames:
    def test_valid_names(self):
        assert validate_channel_name("api_boundary") == "api_boundary"
        assert validate_channel_name("smt") == "smt"

    @pytest.mark.parametrize("bad", ["", "Api-Boundary", "a b", "..",
                                     "UPPER", "x/y"])
    def test_invalid_names_refused(self, bad):
        with pytest.raises(ChannelCorpusError, match="invalid channel"):
            validate_channel_name(bad)

    @pytest.mark.parametrize("bad", ["smt\n", "smt\napi", "\nsmt"])
    def test_newline_carrying_names_refused(self, bad):
        # fullmatch regression: a $-anchored re.match accepts a
        # trailing newline
        with pytest.raises(ChannelCorpusError, match="invalid channel"):
            validate_channel_name(bad)


class TestListChannels:
    def test_absent_dir_is_empty(self, tmp_path):
        assert list_channels(tmp_path / "nope") == []

    def test_lists_sorted_dirs_only(self, tmp_path):
        (tmp_path / "smt").mkdir()
        (tmp_path / "api_boundary").mkdir()
        (tmp_path / "stray.txt").write_text("x", encoding="utf-8")
        assert list_channels(tmp_path) == ["api_boundary", "smt"]

    def test_malformed_dir_name_is_an_error(self, tmp_path):
        (tmp_path / "Bad-Name").mkdir()
        with pytest.raises(ChannelCorpusError, match="invalid channel"):
            list_channels(tmp_path)


class TestLoadChannelLabels:
    def test_loads_channel_dir(self, tmp_path):
        _write_label(tmp_path, "smt", "a",
                     _label_dict("src/demo.c:fn_a"))
        labels = load_channel_labels("smt", base=tmp_path)
        assert [lb.function_id for lb in labels] == ["src/demo.c:fn_a"]

    def test_missing_channel_fails_closed_listing_available(
            self, tmp_path):
        _write_label(tmp_path, "smt", "a",
                     _label_dict("src/demo.c:fn_a"))
        with pytest.raises(ChannelCorpusError, match="available"):
            load_channel_labels("api_boundary", base=tmp_path)

    def test_missing_channel_error_survives_malformed_sibling(
            self, tmp_path):
        # a malformed sibling dir must not mask the missing-channel
        # message with the listing's own validation error
        (tmp_path / "Bad-Name").mkdir()
        with pytest.raises(ChannelCorpusError,
                           match="no micro-corpus dir"):
            load_channel_labels("api_boundary", base=tmp_path)

    def test_field_dir_mismatch_refused(self, tmp_path):
        _write_label(tmp_path, "smt", "a",
                     _label_dict("src/demo.c:fn_a",
                                 channel="api_boundary"))
        with pytest.raises(ChannelCorpusError, match="refusing"):
            load_channel_labels("smt", base=tmp_path)

    def test_matching_field_accepted(self, tmp_path):
        _write_label(tmp_path, "smt", "a",
                     _label_dict("src/demo.c:fn_a", channel="smt"))
        labels = load_channel_labels("smt", base=tmp_path)
        assert labels[0].channel == "smt"

    def test_channel_dirs_isolated_from_each_other(self, tmp_path):
        # the same function_id in two channels' micro-corpora is fine:
        # per-channel loads never see each other
        _write_label(tmp_path, "smt", "a",
                     _label_dict("src/demo.c:fn_a"))
        _write_label(tmp_path, "api_boundary", "a",
                     _label_dict("src/demo.c:fn_a"))
        assert len(load_channel_labels("smt", base=tmp_path)) == 1
        assert len(load_channel_labels("api_boundary",
                                       base=tmp_path)) == 1

    def test_bug_class_filter(self, tmp_path):
        _write_label(tmp_path, "smt", "a",
                     _label_dict("src/demo.c:fn_a"))
        assert load_channel_labels("smt", base=tmp_path,
                                   bug_class="integer") == []

    def test_dir_path_helper(self, tmp_path):
        assert channel_labels_dir("smt", base=tmp_path) == \
            tmp_path / "smt"


class TestGrouping:
    def test_groups_by_field_with_unchanneled_bucket(self):
        def mk(fid, channel=""):
            return FunctionLabel(
                function_id=fid, bug_class="lifecycle",
                expected_status="clean", rationale="r",
                source=SourcePin(repo="demo-repo", sha="abc123",
                                 file="src/demo.c", line_start=1,
                                 line_end=10),
                labeler="test", labeled_at="2026-01-01",
                channel=channel)
        groups = group_labels_by_channel([
            mk("a:f", "smt"), mk("b:g", "smt"), mk("c:h")])
        assert sorted(groups) == ["", "smt"]
        assert len(groups["smt"]) == 2
        assert len(groups[""]) == 1
