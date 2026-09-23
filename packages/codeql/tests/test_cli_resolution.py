"""packages.codeql._resolve_cli: invalid operator override is loud."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql import _resolve_cli


def test_invalid_codeql_cli_override_warns(tmp_path, monkeypatch, caplog):
    """A typo'd CODEQL_CLI silently fell through to PATH here while
    DatabaseManager._detect_codeql_cli warned on the same condition —
    the QueryRunner path masked exactly the mistake the DM surfaced."""
    monkeypatch.setenv("CODEQL_CLI", str(tmp_path / "nope" / "codeql"))
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/codeql")
    with caplog.at_level(logging.WARNING):
        resolved = _resolve_cli()
    assert resolved == "/usr/bin/codeql"
    assert any(
        "CODEQL_CLI" in r.getMessage() and "ignoring" in r.getMessage()
        for r in caplog.records
    )


def test_valid_override_wins_silently(tmp_path, monkeypatch, caplog):
    cli = tmp_path / "codeql"
    cli.write_text("#!/bin/sh\n")
    cli.chmod(0o755)
    monkeypatch.setenv("CODEQL_CLI", str(cli))
    with caplog.at_level(logging.WARNING):
        assert _resolve_cli() == str(cli)
    assert not caplog.records
