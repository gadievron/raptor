"""PoC artifact generation for oracle-proven findings."""

from __future__ import annotations

from pathlib import Path

from packages.web.models import WebFinding
from packages.web.poc import (
    build_nuclei_template,
    build_reproducer,
    write_web_pocs,
)


def _proven(**overrides) -> WebFinding:
    kwargs = dict(
        id="WEB-0001",
        title="SQL Injection -- 1 parameter(s) affected",
        severity="high",
        confidence="medium",
        status="needs_review",
        url="https://example.test/search",
        evidence="e",
        description="d",
        recommendation="r",
        vuln_type="sqli",
        asvs_category="V5",
        check_id="V5.2.1",
        cwe_id="CWE-89",
        confirmed=True,
        target_url="https://example.test/search?lang=en",
        confirmation_payload="' OR 1=1--",
        response_evidence="SQL syntax",
        oracle_signal="sqli_error:sql syntax",
        method="GET",
        affected_parameters=["q"],
    )
    kwargs.update(overrides)
    return WebFinding(**kwargs)


def test_reproducer_replays_confirmation_request():
    script = build_reproducer(_proven())

    assert script is not None
    assert script.startswith("#!/bin/sh")
    assert "curl -sk -X GET" in script
    # Payload lands in the affected parameter, replacing, not appending.
    assert "q=%27+OR+1%3D1--" in script
    assert "lang=en" in script
    assert "sqli_error:sql syntax" in script
    assert "operator authorisation" in script


def test_reproducer_post_body_variant():
    script = build_reproducer(
        _proven(method="POST", target_url="https://example.test/login")
    )

    assert script is not None
    assert "-X POST" in script
    assert "--data" in script
    assert "q=%27+OR+1%3D1--" in script


def test_unproven_finding_gets_no_artifacts(tmp_path: Path):
    unproven = _proven(oracle_signal=None)

    assert build_reproducer(unproven) is None
    assert build_nuclei_template(unproven) is None
    assert write_web_pocs([unproven], tmp_path) == []
    assert not (tmp_path / "pocs").exists()


def test_nuclei_template_mirrors_marker_regex():
    import re

    from packages.web.markers import MARKER_RES

    template = build_nuclei_template(_proven())

    assert template is not None
    assert "id: raptor-replay-web-0001" in template
    assert "tags: sqli,raptor-replay" in template
    # Single source: the matcher regex is generated from markers.py.
    assert MARKER_RES["sqli"].pattern.replace("\\", "\\\\") in template
    assert re.search(r'regex:\n\s+- "\(\?i\)', template)


def test_nuclei_template_xss_uses_payload_word_matcher():
    template = build_nuclei_template(
        _proven(
            vuln_type="xss",
            cwe_id="CWE-79",
            confirmation_payload="<script>alert(1)</script>",
            oracle_signal="xss_reflected_unescaped",
        )
    )

    assert template is not None
    assert "type: word" in template
    assert '"<script>alert(1)</script>"' in template


def test_write_web_pocs_writes_private_files(tmp_path: Path):
    written = write_web_pocs([_proven()], tmp_path)

    assert len(written) == 2
    for path in written:
        assert path.stat().st_mode & 0o777 == 0o600
    names = {p.name for p in written}
    assert names == {"web-0001-reproducer.sh", "web-0001-replay.yaml"}


def test_reproducer_shell_quotes_hostile_values():
    """URLs come from crawling the hostile target and the operator is
    invited to RUN the script: $(…), backticks, and quotes must be
    inert (json.dumps-as-shell-quoting left $() live inside double
    quotes), and newlines in comment-interpolated fields must not
    terminate the comment."""
    import shlex
    import subprocess

    marker = "/tmp/raptor-poc-quote-marker"
    Path(marker).unlink(missing_ok=True)
    hostile = _proven(
        target_url=(
            f"https://example.test/x$(touch {marker})/`id`/p?lang=en"
        ),
        title="line one\nrm -rf /\nline two",
        oracle_signal="sig\r\ncurl evil",
        diff_summary="diff`id`",
    )

    script = build_reproducer(hostile)

    assert script is not None
    # The command line round-trips through shlex with the URL intact.
    command_line = script.rstrip("\n").rsplit("\n", 1)[-1]
    words = shlex.split(command_line)
    assert words[0] == "curl"
    assert any("$(touch" in word for word in words)
    # Comment fields are single lines: total line count is fixed.
    lines = script.split("\n")
    assert all(
        line.startswith("#") or line.startswith("curl") or line == ""
        for line in lines
    ), lines
    # Empirical: running the script cannot execute the injected command
    # (curl fails against the fake host; the marker must not appear).
    # Runners without curl still exercise the quoting assertions above.
    import shutil
    if shutil.which("curl") and shutil.which("sh"):
        subprocess.run(
            ["sh", "-c", script], capture_output=True, timeout=30,
            check=False,
        )
        assert not Path(marker).exists()
