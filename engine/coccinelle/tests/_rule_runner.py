"""Shared native runner for Coccinelle rule fixtures."""

import json
from pathlib import Path
import subprocess
import textwrap


def run_rule(
    tmp_path: Path, source: str, rule: Path, *, include_stderr: bool = True,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"spatch exited {proc.returncode} for {rule}:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    results = []
    streams = (proc.stdout, proc.stderr) if include_stderr else (proc.stdout,)
    for stream in streams:
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results
