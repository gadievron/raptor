"""Bounded sink reads and existing verdict records; extraction is inert."""

import ast
import io
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.inventory.call_graph import FileCallGraph
from core.inventory.sink_discovery import SinkDiscoveryResult, UnreachableVerdict
from core.source import read_bytes_capped


@pytest.fixture
def discovery():
    source = Path(__file__).parents[1] / "sink_discovery.py"
    node = next(n for n in ast.parse(source.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == "discover_sinks_for_target")
    seen = []

    def extract(text):
        seen.append(text)
        return FileCallGraph()

    namespace = {
        "__package__": "core.inventory", "io": io, "Path": Path,
        "logger": logging.getLogger("owned-sink-read-admission"),
        "read_bytes_capped": read_bytes_capped,
        "_get_call_graph_extractors": lambda: {"c": extract},
        "SinkDiscoveryResult": SinkDiscoveryResult, "UnreachableVerdict": UnreachableVerdict,
    }
    module = ast.Module(body=ast.parse("from __future__ import annotations").body + [node], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)

    def run(root, paths, *, per_file=16, aggregate=16, truncated=False, unknown=False):
        namespace["_PER_FILE_CAP"] = per_file
        namespace["_AGGREGATE_CAP"] = aggregate
        metadata = {"admitted_files": len(paths), "admitted_bytes": 5,
                    "skipped_files": 1 if truncated else 0, "skipped_bytes": 9 if truncated else 0,
                    "budget_bytes": aggregate, "truncated": truncated}

        def candidates(target, **kwargs):
            for path in paths:
                yield path, path.name, "c"
            kwargs["stats"].update(metadata)

        namespace["iter_discovery_source_files"] = candidates
        verdicts = None if unknown else {
            ("owned.c", "candidate"): UnreachableVerdict("owned.c", "candidate", True, "owned positive"),
            ("owned.c", "refused"): UnreachableVerdict("owned.c", "refused", False, "owned refusal"),
        }
        namespace["discover_sinks"] = lambda graphs, **kwargs: SinkDiscoveryResult(
            [], [], [], {}, unreachable_eligible=verdicts)
        return namespace["discover_sinks_for_target"](root)

    return SimpleNamespace(run=run, seen=seen)


def test_postadmission_oversize_withholds_and_roundtrips_existing_verdicts(tmp_path, discovery, caplog):
    path = tmp_path / "owned.c"
    path.write_bytes(b"x" * 17)
    with caplog.at_level(logging.WARNING, logger="owned-sink-read-admission"):
        result = discovery.run(tmp_path, [path])
    assert discovery.seen == []
    assert result.truncation is None
    assert result.unreachable_eligible is not None
    assert not result.unreachable_eligible[("owned.c", "candidate")].eligible
    assert result.unreachable_eligible[("owned.c", "refused")].reason == "owned refusal"
    restored = SinkDiscoveryResult.from_full_dict(result.to_full_dict())
    assert restored.unreachable_eligible == result.unreachable_eligible
    assert "unreachable_eligible" not in result.as_dict()
    assert "not read in full" in caplog.text


def test_refused_prefixes_consume_budget_before_later_extraction(tmp_path, discovery):
    paths = [tmp_path / name for name in ("large.c", "fits.c", "later.c")]
    for path, data in zip(paths, [b"x" * 9, b"y" * 4, b"z"], strict=True):
        path.write_bytes(data)
    result = discovery.run(tmp_path, paths, per_file=8, aggregate=12)
    assert discovery.seen == ["yyyy"]
    assert not result.unreachable_eligible[("owned.c", "candidate")].eligible


@pytest.mark.parametrize("data", [b"x" * 16, b"owned\r\ntext\r", b"bad\xfftext"])
def test_complete_reads_preserve_text_and_eligibility(tmp_path, discovery, data):
    path = tmp_path / "owned.c"
    path.write_bytes(data)
    result = discovery.run(tmp_path, [path])
    assert discovery.seen == [path.read_text(encoding="utf-8", errors="replace")]
    assert result.unreachable_eligible[("owned.c", "candidate")].eligible
    assert result.truncation is None


def test_refused_read_keeps_unknown_map_explicit(tmp_path, discovery):
    result = discovery.run(tmp_path, [tmp_path / "missing.c"], unknown=True)
    assert discovery.seen == []
    assert result.unreachable_eligible == {}
    assert SinkDiscoveryResult.from_full_dict(result.to_full_dict()).unreachable_eligible == {}


def test_metadata_aggregate_truncation_shape_is_preserved(tmp_path, discovery):
    path = tmp_path / "owned.c"
    path.write_text("owned")
    result = discovery.run(tmp_path, [path], truncated=True)
    assert result.truncation == {"reason": "aggregate_byte_budget", "budget_bytes": 16,
                                 "admitted_files": 1, "admitted_bytes": 5,
                                 "skipped_files": 1, "skipped_bytes": 9}
    assert not result.unreachable_eligible[("owned.c", "candidate")].eligible
