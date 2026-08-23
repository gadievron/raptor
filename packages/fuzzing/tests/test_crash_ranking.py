"""Tests for the opt-in LLM crash-queue ranking stage."""

from __future__ import annotations

import re
from types import SimpleNamespace

from packages.fuzzing.crash_ranking import (
    _render_crash,
    _signal_name,
    rank_crash_queue,
)

_DOC_RE = re.compile(
    r"id: (\w+)\nBEGIN_DOC_\w+\n(.*?)\nEND_DOC_\w+", re.S,
)
_SIZE_RE = re.compile(r"input_size: (\d+)")


class _Response:
    def __init__(self, result):
        self.result = result
        self.cost = 0.001


class FakeRankClient:
    """Ranks crash documents by input_size descending."""

    def generate_structured(self, prompt, schema, **kwargs):
        docs = _DOC_RE.findall(prompt)
        scored = sorted(
            ((int(_SIZE_RE.search(text).group(1)), bid)
             for bid, text in docs),
            reverse=True,
        )
        return _Response({"ranked_ids": [bid for _v, bid in scored]})


class NoSignalClient:
    def generate_structured(self, prompt, schema, **kwargs):
        return _Response({"ranked_ids": []})


def _crash(tmp_path, i, size, signal="11"):
    input_file = tmp_path / f"id:{i:06d},sig:{signal},src:0,op:havoc,rep:4"
    input_file.write_bytes(b"\x41" * min(size, 64))
    return SimpleNamespace(
        crash_id=f"c{i}", input_file=input_file, signal=signal,
        stack_hash=None, size=size, timestamp=None,
    )


def test_signal_names():
    assert _signal_name("11") == "SIGSEGV"
    assert _signal_name("06") == "SIGABRT"
    assert _signal_name(None) == "?"
    assert "42" in _signal_name("42")


def test_render_includes_pretriage_fields(tmp_path):
    text = _render_crash(_crash(tmp_path, 1, 84))
    assert "SIGSEGV" in text
    assert "84 bytes" in text
    assert "op:havoc" in text
    assert "41 41" in text  # hexdump head of the input


def test_render_tolerates_missing_input(tmp_path):
    crash = _crash(tmp_path, 1, 10)
    crash.input_file.unlink()
    assert "(unreadable)" in _render_crash(crash)


def test_skips_without_config_or_client(tmp_path):
    crashes = [_crash(tmp_path, i, i * 10) for i in range(4)]
    out, note = rank_crash_queue(crashes)
    assert out is crashes
    assert "needs an external analysis model" in note


def test_skips_tiny_queue(tmp_path):
    crashes = [_crash(tmp_path, i, i * 10) for i in range(2)]
    out, note = rank_crash_queue(crashes, client=FakeRankClient())
    assert out is crashes
    assert "too few" in note


def test_reorders_by_ranking(tmp_path):
    crashes = [_crash(tmp_path, i, size)
               for i, size in enumerate([40, 400, 4, 4000])]
    out, note = rank_crash_queue(
        crashes, client=FakeRankClient(), seed=1, max_workers=1,
    )
    assert [c.size for c in out] == [4000, 400, 40, 4]
    assert "ranked 4 crashes" in note


def test_no_signal_keeps_heuristic_order(tmp_path):
    crashes = [_crash(tmp_path, i, i * 10) for i in range(4)]
    out, note = rank_crash_queue(
        crashes, client=NoSignalClient(), seed=1, max_workers=1,
    )
    assert out is crashes
    assert "no signal" in note


def test_client_failure_keeps_heuristic_order(tmp_path):
    class Boom:
        def generate_structured(self, *a, **k):
            raise RuntimeError("down")

    crashes = [_crash(tmp_path, i, i * 10) for i in range(4)]
    out, note = rank_crash_queue(
        crashes, client=Boom(), seed=1, max_workers=1,
    )
    assert out is crashes
    assert "no signal" in note or "failed" in note
