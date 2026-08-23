"""Byte ceilings on ``run_cc_streaming`` output retention.

Pre-fix the drain loop appended every stdout line / stderr chunk to
unbounded lists — the only memory bound was endpoint bandwidth x the
call deadline, so a hostile or compromised endpoint could stream
gigabytes into parent memory. The capture must stay byte-bounded while
preserving protocol correctness (the stream-json ``result`` line
arrives last and must still be found) and diagnostics (head and tail
kept, truncation logged loudly).

No real ``claude`` calls — children are tiny ``python -c`` scripts.
"""

from __future__ import annotations

import json
import logging
import os
import sys

from core.llm.cc_adapter import _CappedCapture, run_cc_streaming


def _env() -> dict[str, str]:
    return dict(os.environ)


class TestCappedCapture:

    def test_retention_is_byte_bounded_head_and_tail_kept(self):
        cap = _CappedCapture(10_000)
        lines = [f"line-{i:04d}" + "x" * 90 + "\n" for i in range(1000)]
        for line in lines:
            cap.append(line)
        kept = cap.items()
        retained = sum(len(item) for item in kept)
        # ~100 KiB in, retention stays around the 10 KB ceiling.
        assert retained <= 10_000 + len(lines[0])
        assert cap.truncated
        assert cap.dropped_bytes > 0
        assert kept[0] == lines[0]      # head preserved
        assert kept[-1] == lines[-1]    # newest tail preserved

    def test_no_truncation_under_cap(self):
        cap = _CappedCapture(10_000)
        lines = ["a\n", "b\n", "c\n"]
        for line in lines:
            cap.append(line)
        assert cap.items() == lines
        assert not cap.truncated


class TestRunCCStreamingCaps:

    def test_stdout_flood_is_bounded_and_result_line_still_found(
        self, monkeypatch, caplog,
    ):
        """Child emits an early assistant event, floods ~1 MiB of
        junk, then the result event. With a 64 KiB ceiling the middle
        is dropped loudly while the head (assistant) and tail
        (result) both survive parsing."""
        monkeypatch.setenv("RAPTOR_CC_STREAM_STDOUT_CAP", str(64 * 1024))
        assistant_line = json.dumps({
            "type": "assistant",
            "message": {
                "content": [{"type": "text", "text": "early-marker"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        })
        result_line = json.dumps({
            "type": "result",
            "session_id": "sess-flood",
            "is_error": False,
        })
        script = (
            "import sys\n"
            f"sys.stdout.write({assistant_line!r} + '\\n')\n"
            "for i in range(16384):\n"
            "    sys.stdout.write('junk ' + 'y' * 60 + '\\n')\n"
            f"sys.stdout.write({result_line!r} + '\\n')\n"
        )
        with caplog.at_level(logging.WARNING, logger="core.llm.cc_adapter"):
            sr = run_cc_streaming(
                [sys.executable, "-c", script],
                prompt="",
                env=_env(),
                timeout_s=60,
            )
        assert sr.error is None
        assert sr.session_id == "sess-flood"          # result line found
        assert "early-marker" in (sr.content or "")   # head preserved
        assert any(
            "retention ceiling" in rec.getMessage()
            for rec in caplog.records
        )

    def test_stderr_flood_is_bounded_and_diagnostics_survive(
        self, monkeypatch, caplog,
    ):
        """A failing child that floods stderr past the ceiling still
        surfaces its exit code and (truncated) stderr in the error."""
        monkeypatch.setenv("RAPTOR_CC_STREAM_STDERR_CAP", str(64 * 1024))
        script = (
            "import sys\n"
            f"sys.stderr.write('E' * {1024 * 1024})\n"
            "sys.stderr.flush()\n"
            "sys.exit(2)\n"
        )
        with caplog.at_level(logging.WARNING, logger="core.llm.cc_adapter"):
            sr = run_cc_streaming(
                [sys.executable, "-c", script],
                prompt="",
                env=_env(),
                timeout_s=60,
            )
        assert sr.error is not None
        assert "exited 2" in sr.error
        assert "E" in sr.error
        assert any(
            "retention ceiling" in (rec.getMessage())
            for rec in caplog.records
        )
