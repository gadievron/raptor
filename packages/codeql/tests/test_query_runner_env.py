import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from packages.codeql.query_runner import QueryRunner


def test_run_suite_passes_trusted_strict_env_to_sandbox(tmp_path):
    captured = {}

    def fake_sandbox_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        output_arg = next(arg for arg in cmd if str(arg).startswith("--output="))
        sarif_path = Path(str(output_arg).split("=", 1)[1])
        sarif_path.write_text(json.dumps({"version": "2.1.0", "runs": []}))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    runner = QueryRunner(codeql_cli="/usr/bin/codeql")

    with patch("core.sandbox.run", side_effect=fake_sandbox_run):
        result = runner.run_suite(
            database_path=tmp_path / "db",
            language="cpp",
            out_dir=tmp_path / "out",
        )

    assert result.success is True
    assert captured["cmd"][:3] == ["/usr/bin/codeql", "database", "analyze"]
    assert captured["kwargs"]["env"]["_RAPTOR_TRUSTED"] == "1"
    assert captured["kwargs"]["strict_env"] is True
