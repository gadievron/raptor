"""CC dispatch stderr/stdout redaction.

The CC child's env carries minted AWS session credentials
(cc_subprocess_env(mint_aws_credentials=True)); SDK verbose/error
output can echo them on stderr. Both the per-finding error excerpt and
write_debug's persisted dump must pass through redact_secrets +
escape_nonprintable before leaving the process boundary.
"""

from __future__ import annotations

from pathlib import Path

from packages.llm_analysis.cc_dispatch import write_debug

_AWS_KEY = "AKIA" + "A" * 16
_ANSI = "\x1b[2K\x1b[1Aforged-log-line"


def test_write_debug_redacts_and_defangs(tmp_path: Path):
    result: dict = {}
    write_debug(
        tmp_path,
        "finding-1",
        f"model output {_AWS_KEY}",
        f"boto3 error for key {_AWS_KEY}\n{_ANSI}\n",
        result,
    )
    debug_file = tmp_path / "debug" / "cc_finding-1.txt"
    content = debug_file.read_text(encoding="utf-8")
    assert _AWS_KEY not in content
    assert "\x1b" not in content
    # Newlines preserved for operator readability.
    assert "STDOUT:\n" in content and "STDERR:\n" in content
    assert result["cc_debug_file"] == "debug/cc_finding-1.txt"


def test_write_debug_empty_streams(tmp_path: Path):
    result: dict = {}
    write_debug(tmp_path, "finding-2", "", "", result)
    content = (tmp_path / "debug" / "cc_finding-2.txt").read_text(encoding="utf-8")
    assert "(empty)" in content
