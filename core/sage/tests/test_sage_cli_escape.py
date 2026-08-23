#!/usr/bin/env python3
"""Terminal-escape sanitisation tests for the raptor-sage operator CLI.

Stored memory content, tags, domains, and statuses are attacker-
influenceable (SARIF-derived names from scanned repos, LLM hypothesis
text). The CLI's display paths must render them as inert, escaped text
— a raw ESC byte reaching the operator's terminal lets a poisoned row
erase/redraw the listing that would have exposed it, or fire OSC 52
clipboard writes.
"""

import contextlib
import importlib.util
import io
import os
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parents[3]

# CSI sequence that erases the current line and moves the cursor up —
# the primitive for overwriting a previously printed row — and an OSC
# 52 clipboard write.
CSI_PAYLOAD = "\x1b[2K\x1b[A"
OSC_PAYLOAD = "\x1b]52;c;aGk=\x07"
HOSTILE = f"evil {CSI_PAYLOAD} row {OSC_PAYLOAD} end"

_cli = None


def setUpModule():
    global _cli
    # The CLI refuses to run without the launcher trust marker; tests
    # are the documented bypass.
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_sage_cli", str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader("raptor_sage_cli", loader)
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


def _run(fn, client, args) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(client, args)
    assert rc == 0, f"{fn.__name__} returned {rc}"
    return buf.getvalue()


def _assert_inert(test, output):
    test.assertNotIn("\x1b", output)
    test.assertNotIn("\x07", output)
    test.assertIn("\\x1b", output)


class TestEscapeSanitisation(unittest.TestCase):
    def test_recall_escapes_content_and_domain(self):
        client = MagicMock()
        client.embed.return_value = [0.1]
        client.query.return_value = SimpleNamespace(results=[
            SimpleNamespace(
                confidence_score=0.9,
                domain_tag=f"raptor-{CSI_PAYLOAD}",
                content=HOSTILE,
            ),
        ])
        args = SimpleNamespace(
            query=["q"], domain=None, top=None, min_confidence=None,
        )
        out = _run(_cli.cmd_recall, client, args)
        _assert_inert(self, out)

    def test_list_escapes_all_columns(self):
        client = MagicMock()
        client.list_memories.return_value = SimpleNamespace(
            memories=[
                SimpleNamespace(
                    memory_id="abc123def456",
                    domain_tag=f"raptor-{OSC_PAYLOAD}",
                    status=f"committed{CSI_PAYLOAD}",
                    confidence_score=0.8,
                    content=HOSTILE,
                ),
            ],
            total=1,
        )
        args = SimpleNamespace(
            domain=None, tag=None, status=None, sort=None, limit=None,
        )
        out = _run(_cli.cmd_list, client, args)
        _assert_inert(self, out)

    def test_backlog_escapes_status_domain_content(self):
        client = MagicMock()
        client.list_tasks.return_value = SimpleNamespace(tasks=[
            SimpleNamespace(
                task_status=f"planned{CSI_PAYLOAD}",
                domain_tag=f"raptor-{CSI_PAYLOAD}",
                content=HOSTILE,
            ),
        ])
        args = SimpleNamespace(domain=None)
        out = _run(_cli.cmd_backlog, client, args)
        _assert_inert(self, out)

    def test_get_escapes_every_field(self):
        client = MagicMock()
        client.get_memory.return_value = SimpleNamespace(
            memory_id=f"id{CSI_PAYLOAD}",
            domain_tag=f"raptor-{OSC_PAYLOAD}",
            status=f"committed{CSI_PAYLOAD}",
            confidence_score=0.9,
            memory_type=f"fact{CSI_PAYLOAD}",
            content=HOSTILE,
            created_at=f"2026-01-01T00:00:00Z{CSI_PAYLOAD}",
            tags=[f"tag{OSC_PAYLOAD}", "clean-tag"],
        )
        # full-length id: short ids now take the prefix-resolution walk
        # (test_sage_cli_id_prefix.py), which this stub does not serve
        args = SimpleNamespace(memory_id="12345678-1234-1234-1234-123456789abc")
        out = _run(_cli.cmd_get, client, args)
        _assert_inert(self, out)
        self.assertIn("clean-tag", out)

    def test_get_preserves_newlines_in_content(self):
        client = MagicMock()
        client.get_memory.return_value = SimpleNamespace(
            memory_id="id", domain_tag="raptor-x", status="committed",
            confidence_score=0.9, memory_type="fact",
            content=f"line one\nline two {CSI_PAYLOAD}",
            created_at="", tags=[],
        )
        # full-length id — see test_get_escapes_every_field
        args = SimpleNamespace(memory_id="12345678-1234-1234-1234-123456789abc")
        out = _run(_cli.cmd_get, client, args)
        _assert_inert(self, out)
        self.assertIn("line one\nline two", out)

    def test_status_escapes_status_and_domain(self):
        client = MagicMock()
        client.list_memories.return_value = SimpleNamespace(
            memories=[
                SimpleNamespace(
                    domain_tag=f"raptor-{CSI_PAYLOAD}",
                    status=f"committed{OSC_PAYLOAD}",
                    created_at="2026-01-01T00:00:00Z",
                ),
            ],
            total=1,
        )
        out = _run(_cli.cmd_status, client, SimpleNamespace())
        _assert_inert(self, out)

    def test_print_table_escapes_cells(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _cli._print_table(["A", "B"], [(HOSTILE, "ok")])
        _assert_inert(self, buf.getvalue())

    def test_trunc_escapes_before_measuring(self):
        out = _cli._trunc(HOSTILE, width=200)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_clean_text_unchanged(self):
        self.assertEqual(_cli._trunc("plain text"), "plain text")


if __name__ == "__main__":
    unittest.main()
