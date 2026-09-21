"""Generative containment oracle for the run-dir JSON intake boundary.

Every file this suite plants lives inside the sandbox write grant
(run dirs) or a re-importable project dir, so its bytes are
attacker-writable in full. The invariant — the reason shape
enumeration is banned on these paths — is mechanical:

* ANY byte sequence / JSON shape, per row, quarantines to that row
  (or that record / run / file, at the natural granularity);
* NO exception ever propagates out of a consumer;
* never-drop holds: rows the reader refuses stay on disk;
* valid rows planted among hostile ones keep flowing.

The generator is seeded (deterministic in CI) and runs on both JSON
backends — orjson and stdlib diverge on depth limits and non-finite
handling, and several historical crashes were single-backend.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import core.json.utils as json_utils
from core.coverage.journal import (
    INDEX_FILENAME,
    JOURNAL_FILENAME,
    latest_entries,
    latest_function_grade_index,
    load_entries,
    load_index,
    load_index_full,
    merge_run_into_index,
    now_iso,
    reviewed_set,
)

_TRIALS_PER_BACKEND = 25
_ROWS_PER_TRIAL = 8


def _valid_entry(i: int = 0) -> dict:
    return {
        "ts": now_iso(),
        "run_id": f"run-{i}",
        "file": f"src/f{i}.c",
        "function": f"fn{i}",
        "verdict": "clean",
        "source_hash": "abc123",
        "line_start": 1,
        "line_end": 20,
        "schema_version": 1,
    }


def _rand_scalar(rng: random.Random):
    return rng.choice([
        None, True, False, 0, -1, 42, 2**70, -(2**70), 1.5, 1e308,
        -1e308, "", "x", "42", "\x1b[2J\x1b[1;1H", "café", "a" * 300,
        "line_start", {"nested": 1}, [1, "two"], 3.14,
    ])


def _rand_json_value(rng: random.Random, depth: int = 0):
    if depth >= 3 or rng.random() < 0.5:
        return _rand_scalar(rng)
    if rng.random() < 0.5:
        return [_rand_json_value(rng, depth + 1)
                for _ in range(rng.randint(0, 3))]
    return {
        str(_rand_scalar(rng)): _rand_json_value(rng, depth + 1)
        for _ in range(rng.randint(0, 3))
    }


_FIXED_HOSTILE_LINES = [
    b"\x80",                                    # undecodable byte
    b"\xff\xfe\x00",                            # more undecodable bytes
    b"[" * 150_000 + b"]" * 150_000,            # nesting bomb
    b'{"a": ' + b"[" * 150_000 + b"]" * 150_000 + b"}",
    b'{"ts": NaN}',                             # non-finite constants
    b'{"cost_usd": Infinity}',
    b'{"confidence": 1e400}',                   # parses to inf
    b'"\\ud800"',                               # lone surrogate escape
    b'{"body": "\\udfff"}',
    b"null", b"[]", b'"str"', b"5", b"true",    # valid non-dict JSON
    b"not json at all",
    b'{"schema_version": 99, "ts": "t"}',       # unknown version
    b"{" * 500,                                 # truncated nesting
]


def _hostile_line(rng: random.Random) -> bytes:
    kind = rng.randrange(4)
    if kind == 0:
        return bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))
    if kind == 1:
        return rng.choice(_FIXED_HOSTILE_LINES)
    if kind == 2:
        # A structurally valid entry with randomly mutated fields.
        entry = _valid_entry(rng.randint(0, 5))
        for _ in range(rng.randint(1, 4)):
            entry[rng.choice(list(entry))] = _rand_json_value(rng)
        return json.dumps(entry).encode()
    return json.dumps(_rand_json_value(rng)).encode()


def _write_hostile_journal(run_dir: Path, rng: random.Random) -> None:
    lines = [_hostile_line(rng) for _ in range(_ROWS_PER_TRIAL)]
    lines.insert(rng.randrange(len(lines) + 1),
                 json.dumps(_valid_entry(0)).encode())
    (run_dir / JOURNAL_FILENAME).write_bytes(b"\n".join(lines) + b"\n")


def _write_hostile_index(project_dir: Path, rng: random.Random) -> set:
    """Plant an index; return the hostile row keys (empty when the
    whole container is hostile)."""
    kind = rng.randrange(4)
    path = project_dir / INDEX_FILENAME
    if kind == 0:
        path.write_bytes(_hostile_line(rng))
        return set()
    if kind == 1:
        path.write_text(json.dumps(
            {"schema_version": 1, "entries": _rand_json_value(rng)}))
        return set()
    hostile_keys = set()
    entries: dict = {"valid:key": _valid_entry(9)}
    for i in range(rng.randint(1, 4)):
        key = f"hostile-{i}:key"
        entries[key] = _rand_json_value(rng)
        hostile_keys.add(key)
    path.write_text(json.dumps({"schema_version": 1, "entries": entries}))
    return hostile_keys


def _drive_journal_consumers(run_dir: Path, project_dir: Path,
                             hostile_keys: set) -> None:
    entries = load_entries(run_dir)
    assert any(e.function == "fn0" for e in entries), \
        "valid row lost among hostile rows"
    assert "src/f0.c:fn0" in reviewed_set(run_dir)
    latest_entries(run_dir)

    index_path = project_dir / INDEX_FILENAME
    before = index_path.read_bytes() if index_path.exists() else b""
    merged = merge_run_into_index(project_dir, run_dir)
    load_index(project_dir)
    load_index_full(project_dir)
    latest_function_grade_index(project_dir)

    # Never-drop: either the writer refused (file untouched) or every
    # hostile row key survived the rewrite under its original key
    # (unparseable rows are never re-homed, never dropped).
    if merged == 0:
        assert index_path.read_bytes() == before
    elif hostile_keys:
        persisted = json.loads(index_path.read_text())["entries"]
        assert hostile_keys <= set(persisted)


def _drive_coverage_consumers(run_dir: Path, project_dir: Path,
                              rng: random.Random) -> None:
    from core.coverage.store import CoverageStore
    from core.coverage.store_summary import (
        format_progress_trend,
        render_coverage,
    )

    # Hostile companion artifacts around the store rebuild path.
    (run_dir / "findings.json").write_bytes(_hostile_line(rng))
    (run_dir / "coverage-semgrep.json").write_text(json.dumps({
        "tool": "semgrep",
        "files_examined": _rand_json_value(rng),
        "rules_applied": _rand_json_value(rng),
        "packs": _rand_json_value(rng),
        "files_failed": _rand_json_value(rng),
        "version": _rand_json_value(rng),
        "functions_analysed": _rand_json_value(rng),
    }))
    (run_dir / "coverage-evil.json").write_bytes(_hostile_line(rng))
    (run_dir / "coverage-good.json").write_text(json.dumps({
        "tool": "goodtool", "files_examined": ["ok.c"],
    }))
    (run_dir / "context-map.json").write_bytes(_hostile_line(rng))
    checklist = {"files": [
        _rand_json_value(rng),
        {"path": "src/f0.c", "lines": _rand_json_value(rng), "items": [
            {"name": "fn0", "line_start": _rand_json_value(rng),
             "line_end": _rand_json_value(rng)},
            {"name": "b", "address": _rand_json_value(rng),
             "size": _rand_json_value(rng)},
            _rand_json_value(rng),
        ]},
        {"path": "ok.c", "lines": 10, "items": [
            {"name": "good", "line_start": 1, "line_end": 10,
             "checked_by": ["audit"]},
        ]},
    ]}
    store_path = project_dir / "coverage.json"
    report = render_coverage([run_dir], checklist, store_path)
    assert report is not None
    # The genuine rows keep flowing through the hostile neighbourhood:
    # a real record's whole-file mark, and (via the legacy
    # project_dir=None path) the checklist's checked_by mark.
    store = CoverageStore(store_path)
    from core.coverage.importer import backfill
    backfill(store, [run_dir], checklist, project_dir=None)
    assert store.function_covered("ok.c", 1, 10) is True
    assert "goodtool" in store.who_checked("ok.c", 5)
    assert [v for *_, v in store.function_verdicts(checklist)]

    trail = project_dir / "coverage-progress.jsonl"
    trail.write_bytes(b"\n".join(
        _hostile_line(rng) for _ in range(4)) + b"\n")
    format_progress_trend(store_path)

    # `/project clean` consumers walk the same hostile run dir
    # (records + findings) and the hostile checklist — classify,
    # dedup, and the confirmed-deletion snapshot must all survive.
    from core.coverage.clean import (
        apply_removal,
        classify_removal,
        dedup_runs,
    )
    consequence = classify_removal(run_dir, [run_dir])
    dedup_runs([run_dir, run_dir.parent / "no-such-run", run_dir])
    apply_removal(store, run_dir, checklist, consequence)


def test_intake_containment_generative(tmp_path: Path):
    """THE closure oracle: arbitrary bytes / JSON shapes per row across
    every run-dir JSON intake — journal, index, findings, checklist,
    coverage records, progress trail — and every consumer survives,
    with never-drop and valid-row survival asserted per trial."""
    backends = [("stdlib", None)]
    if json_utils._orjson is not None:
        backends.append(("orjson", json_utils._orjson))
    for backend_name, override in backends:
        saved = json_utils._orjson
        try:
            json_utils._orjson = override
            for trial in range(_TRIALS_PER_BACKEND):
                rng = random.Random(f"{backend_name}-{trial}")
                run_dir = tmp_path / backend_name / f"t{trial}" / "run"
                project_dir = run_dir.parent / "project"
                run_dir.mkdir(parents=True)
                project_dir.mkdir()
                _write_hostile_journal(run_dir, rng)
                hostile_keys = _write_hostile_index(project_dir, rng)
                _drive_journal_consumers(run_dir, project_dir, hostile_keys)
                _drive_coverage_consumers(run_dir, project_dir, rng)
        finally:
            json_utils._orjson = saved


def test_intake_containment_fixed_hostile_corpus(tmp_path: Path):
    """Every fixed hostile line, alone in a journal next to one valid
    row, on both backends — the deterministic core of the oracle."""
    backends = [None]
    if json_utils._orjson is not None:
        backends.append(json_utils._orjson)
    for n, hostile in enumerate(_FIXED_HOSTILE_LINES):
        for override in backends:
            saved = json_utils._orjson
            try:
                json_utils._orjson = override
                d = tmp_path / f"c{n}-{override is not None}"
                d.mkdir()
                (d / JOURNAL_FILENAME).write_bytes(
                    hostile + b"\n" + json.dumps(_valid_entry(0)).encode()
                    + b"\n")
                entries = load_entries(d)
                assert [e.function for e in entries] == ["fn0"]
            finally:
                json_utils._orjson = saved
