"""drcov serialisation round-trip: the file written by coverage.write_drcov
must be readable by core.coverage.collect.parse_drcov (the existing,
Frida-aware ingest path). No Frida required."""

import json

from core.coverage.collect import parse_drcov
from packages.dynamic_instrumentation import coverage


def _write_events(path, modules, blocks):
    with open(path, "w") as fh:
        fh.write(json.dumps({"type": "send",
                             "payload": {"kind": "modules", "modules": modules}}) + "\n")
        fh.write(json.dumps({"type": "send",
                             "payload": {"kind": "blocks", "blocks": blocks}}) + "\n")


def test_drcov_round_trip(tmp_path):
    events = tmp_path / "events.jsonl"
    drcov = tmp_path / "out.drcov"
    base = 0x400000
    modules = [{"name": "target", "base": hex(base), "size": 0x2000,
                "path": "/tmp/target"}]
    # three blocks inside the module
    blocks = [[hex(base + 0x100), hex(base + 0x110)],
              [hex(base + 0x200), hex(base + 0x208)],
              [hex(base + 0x300), hex(base + 0x320)]]
    _write_events(str(events), modules, blocks)

    n = coverage.write_drcov(str(events), str(drcov))
    assert n == 3

    parsed = parse_drcov(str(drcov))
    assert "/tmp/target" in parsed
    entry = parsed["/tmp/target"]
    assert entry["base"] == base
    assert entry["offsets"] == {0x100, 0x200, 0x300}


def test_blocks_outside_modules_are_dropped(tmp_path):
    events = tmp_path / "e.jsonl"
    drcov = tmp_path / "o.drcov"
    base = 0x400000
    modules = [{"name": "t", "base": hex(base), "size": 0x1000, "path": "/t"}]
    blocks = [[hex(base + 0x10), hex(base + 0x20)],   # in
              [hex(0x900000), hex(0x900010)]]          # out of range
    _write_events(str(events), modules, blocks)
    n = coverage.write_drcov(str(events), str(drcov))
    assert n == 1
    assert parse_drcov(str(drcov))["/t"]["offsets"] == {0x10}


def test_no_modules_writes_nothing(tmp_path):
    events = tmp_path / "e.jsonl"
    events.write_text(json.dumps({"type": "send",
                                  "payload": {"kind": "blocks", "blocks": []}}) + "\n")
    assert coverage.write_drcov(str(events), str(tmp_path / "o.drcov")) == 0


def test_duplicate_blocks_deduplicated(tmp_path):
    events = tmp_path / "e.jsonl"
    drcov = tmp_path / "o.drcov"
    base = 0x400000
    modules = [{"name": "t", "base": hex(base), "size": 0x1000, "path": "/t"}]
    blocks = [[hex(base + 0x10), hex(base + 0x20)]] * 5
    _write_events(str(events), modules, blocks)
    assert coverage.write_drcov(str(events), str(drcov)) == 1
