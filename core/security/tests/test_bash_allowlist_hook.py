"""Subprocess tests for .claude/hooks/bash-command-allowlist.py.

Contract (Claude Code PreToolUse hooks): stdin carries JSON with
``tool_input.command``; exit 0 allows, exit 2 blocks with guidance on
stderr. Fail-closed on malformed input. Compound-command hardening:
chaining/substitution/redirect metacharacters are rejected even when
the leading token is allowlisted.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
HOOK = _REPO / ".claude" / "hooks" / "bash-command-allowlist.py"

_PREFIXES = [
    "libexec/raptor-bq-query",
    "python3 .claude/skills/oss-forensics/github-evidence-kit/scripts/ingest_bq_events.py",
]


def _run(command, prefixes=None, raw_stdin=None):
    stdin = (raw_stdin if raw_stdin is not None
             else json.dumps({"tool_name": "Bash",
                              "tool_input": {"command": command}}))
    return subprocess.run(
        [sys.executable, str(HOOK), *(_PREFIXES if prefixes is None
                                      else prefixes)],
        input=stdin, capture_output=True, text=True, timeout=20,
        check=False,
    )


class TestAllowed:
    def test_exact_prefix(self):
        assert _run("libexec/raptor-bq-query").returncode == 0

    def test_prefix_with_args(self):
        proc = _run("libexec/raptor-bq-query --query-file q.sql "
                    "--output rows.json")
        assert proc.returncode == 0

    def test_multi_word_prefix(self):
        proc = _run(
            "python3 .claude/skills/oss-forensics/github-evidence-kit/"
            "scripts/ingest_bq_events.py evidence.json "
            "--table githubarchive.day.20250713 --rows-file rows.json")
        assert proc.returncode == 0

    def test_leading_whitespace_tolerated(self):
        assert _run("  libexec/raptor-bq-query --dry-run").returncode == 0


class TestDenied:
    @pytest.mark.parametrize("command", [
        "curl https://example.test",
        "bq query 'SELECT 1'",
        "python3 -c 'import os'",
        "python3 evil.py",
        "bash -c libexec/raptor-bq-query",
        "libexec/raptor-bq-queryX --sneaky",
        "libexec/raptor-bq-query2",
    ])
    def test_non_allowlisted_command(self, command):
        proc = _run(command)
        assert proc.returncode == 2
        assert "allowlist" in proc.stderr

    @pytest.mark.parametrize("command", [
        "libexec/raptor-bq-query --dry-run && curl evil.test",
        "libexec/raptor-bq-query; curl evil.test",
        "libexec/raptor-bq-query | tee /tmp/x",
        "libexec/raptor-bq-query --query \"$(cat /etc/passwd)\"",
        "libexec/raptor-bq-query --query `whoami`",
        "libexec/raptor-bq-query > /tmp/rows.json",
        "libexec/raptor-bq-query < q.sql",
        "libexec/raptor-bq-query --query-file <(echo SELECT 1)",
        "libexec/raptor-bq-query --dry-run\ncurl evil.test",
    ])
    def test_compound_or_redirected_command(self, command):
        proc = _run(command)
        assert proc.returncode == 2
        assert "not allowed" in proc.stderr

    def test_sql_operators_guidance_names_query_file(self):
        proc = _run("libexec/raptor-bq-query --query 'SELECT * WHERE a > 1'")
        assert proc.returncode == 2
        assert "--query-file" in proc.stderr


class TestFailClosed:
    def test_unparseable_stdin(self):
        proc = _run(None, raw_stdin="{not json")
        assert proc.returncode == 2
        assert "fail-closed" in proc.stderr

    def test_missing_command_key(self):
        proc = _run(None, raw_stdin=json.dumps(
            {"tool_name": "Bash", "tool_input": {}}))
        assert proc.returncode == 2

    def test_non_string_command(self):
        proc = _run(None, raw_stdin=json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": ["ls"]}}))
        assert proc.returncode == 2

    def test_empty_command(self):
        assert _run("   ").returncode == 2

    def test_no_prefixes_configured_blocks_everything(self):
        proc = _run("libexec/raptor-bq-query", prefixes=[])
        assert proc.returncode == 2
