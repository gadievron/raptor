"""Live nuclei verification against a loopback fixture server.

These tests exercise the REAL nuclei binary through the hardened
runner: batch -l invocation, pinned unsigned templates (no -dut),
tags-from-findings selection, header delivery via the 0600 file, and
JSONL match attribution. They skip when nuclei is not on PATH.

The sandbox layer is bypassed (direct subprocess with a from-nothing
env): its plumbing has its own E2E coverage, and the egress proxy
rejects loopback CONNECTs by design.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from packages.web.execution_policy import WebExecutionPolicy
from packages.web.external_validators import (
    ExternalValidatorRunner,
    NucleiConfig,
)
from packages.web.models import WebFinding

pytestmark = pytest.mark.skipif(
    shutil.which("nuclei") is None, reason="nuclei binary not on PATH"
)

_SQLI_TEMPLATE = """\
id: raptor-live-sqli-error

info:
  name: RAPTOR live SQLi error marker
  author: raptor
  severity: high
  tags: sqli

http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=%27"
    matchers:
      - type: word
        part: body
        words:
          - "You have an error in your SQL syntax"
"""

_XSS_TEMPLATE = """\
id: raptor-live-xss-marker

info:
  name: RAPTOR live XSS marker
  author: raptor
  severity: high
  tags: xss

http:
  - method: GET
    path:
      - "{{BaseURL}}/reflect"
    matchers:
      - type: word
        part: body
        words:
          - "raptor-xss-canary"
"""


class _RecordingHandler(BaseHTTPRequestHandler):
    records: list[dict[str, Any]] = []

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        type(self).records.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
        })
        if self.path.startswith("/search"):
            body = b"You have an error in your SQL syntax near q"
        elif self.path.startswith("/reflect"):
            body = b"raptor-xss-canary"
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture()
def fixture_server():
    _RecordingHandler.records = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _RecordingHandler.records
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def templates_dir(tmp_path: Path) -> Path:
    d = tmp_path / "pinned-templates"
    d.mkdir()
    (d / "raptor-sqli.yaml").write_text(_SQLI_TEMPLATE, encoding="utf-8")
    (d / "raptor-xss.yaml").write_text(_XSS_TEMPLATE, encoding="utf-8")
    return d


@pytest.fixture()
def direct_nuclei(monkeypatch: pytest.MonkeyPatch):
    """Route the runner through a direct subprocess with a minimal env."""
    import tempfile

    captured: dict[str, Any] = {}
    home = tempfile.mkdtemp(prefix="raptor-nuclei-live-home-")

    def _run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": home,
            "NO_PROXY": "127.0.0.1,localhost",
        }
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=kwargs.get("timeout"),
            env=env,
        )

    monkeypatch.setattr(
        "packages.web.external_validators.run_untrusted_networked", _run
    )
    try:
        yield captured
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _finding(url: str, vuln_type: str = "sqli") -> WebFinding:
    return WebFinding(
        id="WEB-0001",
        title="t",
        severity="high",
        confidence="medium",
        status="needs_review",
        url=url,
        evidence="e",
        description="d",
        recommendation="r",
        vuln_type=vuln_type,
        asvs_category="V5",
        check_id="V5.2.1",
        target_url=url,
    )


def _runner(base_url: str, out_dir: Path, templates: Path, **config_kwargs):
    return ExternalValidatorRunner(
        base_url=base_url,
        out_dir=out_dir,
        policy=WebExecutionPolicy.for_target(base_url),
        nuclei_config=NucleiConfig(
            templates_dir=templates,
            max_runtime=120,
            **config_kwargs,
        ),
    )


def test_live_unsigned_pinned_template_matches(
    tmp_path: Path, fixture_server, templates_dir, direct_nuclei
):
    """The pinned-dir provenance model works on the wire: our UNSIGNED
    template loads (no -dut) and its matcher fires against the fixture."""
    base_url, _records = fixture_server

    results = _runner(base_url, tmp_path, templates_dir).run(
        [_finding(f"{base_url}/search")], ["nuclei"]
    )

    assert len(results) == 1, results
    assert results[0]["status"] == "matched", results[0]
    templates = {m["template_id"] for m in results[0]["matches"]}
    assert "raptor-live-sqli-error" in templates
    # Tags derived from the finding's class: the xss-tagged template
    # must not have produced a match record.
    assert "raptor-live-xss-marker" not in templates
    assert results[0]["run"]["returncode"] == 0
    assert results[0]["run"]["timed_out"] is False


def test_live_header_file_reaches_the_wire(
    tmp_path: Path, fixture_server, templates_dir, direct_nuclei
):
    """-H accepts a file path: the credential header delivered via the
    0600 file must arrive on the wire, never on the argv."""
    base_url, records = fixture_server
    secret = "Authorization: Bearer nuclei-live-tok-42"

    _runner(base_url, tmp_path, templates_dir, headers=(secret,)).run(
        [_finding(f"{base_url}/search")], ["nuclei"]
    )

    cmd = direct_nuclei["cmd"]
    assert secret not in " ".join(cmd)
    assert any(
        record["authorization"] == "Bearer nuclei-live-tok-42"
        for record in records
    ), records


def test_live_store_responses_writes_transcripts(
    tmp_path: Path, fixture_server, templates_dir, direct_nuclei
):
    base_url, _records = fixture_server

    _runner(base_url, tmp_path, templates_dir).run(
        [_finding(f"{base_url}/search")], ["nuclei"]
    )

    responses_dir = tmp_path / "external-validators" / "nuclei-responses"
    stored = list(responses_dir.rglob("*")) if responses_dir.exists() else []
    assert any(p.is_file() for p in stored), (
        "expected -sresp/-srd request/response transcripts"
    )


def test_live_no_match_is_reported_not_silent(
    tmp_path: Path, fixture_server, templates_dir, direct_nuclei
):
    base_url, _records = fixture_server

    # An xss finding selects only the xss-tagged template, whose /reflect
    # matcher fires — while a path_traversal finding selects lfi tags
    # with no matching template at all: explicit no_match.
    results = _runner(base_url, tmp_path, templates_dir).run(
        [_finding(f"{base_url}/nothing-here", vuln_type="path_traversal")],
        ["nuclei"],
    )

    assert len(results) == 1
    assert results[0]["status"] == "no_match"
    assert "not a refutation" in results[0]["note"]
