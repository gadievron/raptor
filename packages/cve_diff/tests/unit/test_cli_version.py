from __future__ import annotations

from typer.testing import CliRunner

from cve_diff import __version__
from cve_diff.cli.main import app


def test_version_flag_prints_version_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
