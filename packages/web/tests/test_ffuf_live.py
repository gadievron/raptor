"""Live ffuf verification against a loopback fixture server.

These tests exercise the REAL ffuf binary: argv acceptance, -config
TOML consumption, request shaping on the wire, and JSON report shape.
They skip when ffuf is not on PATH, so CI without ffuf degrades to the
mocked unit suite in test_ffuf.py.

The sandbox layer is bypassed here (direct subprocess with a
proxy-scrubbed env): its plumbing has its own E2E coverage, and the
egress proxy deliberately rejects loopback CONNECTs, so a sandboxed
loopback fixture cannot work by design.
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

from packages.web.ffuf import FfufConfig, FfufRunner

pytestmark = pytest.mark.skipif(
    shutil.which("ffuf") is None, reason="ffuf binary not on PATH"
)


class _RecordingHandler(BaseHTTPRequestHandler):
    """Serves a tiny deterministic site and records every request."""

    records: list[dict[str, Any]] = []

    def _record(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        record = {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "authorization": self.headers.get("Authorization", ""),
            "cookie": self.headers.get("Cookie", ""),
            "body": body,
        }
        type(self).records.append(record)
        return record

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve(self) -> None:
        record = self._record()
        if record["host"].startswith("dev."):
            self._respond(200, b"vhost dev backend")
            return
        path = record["path"].split("?", 1)[0]
        if path == "/admin":
            self._respond(200, b"admin panel, quite boring honestly")
            return
        if path == "/backup":
            self._respond(200, b"backup archive index")
            return
        if path == "/login":
            self._respond(200, b"login ok")
            return
        if path == "/v1/users":
            # Simulated injectable JSON endpoint for the API sweep: a
            # quote in the body breaks the imaginary SQL statement.
            if "'" in record["body"]:
                self._respond(500, b"You have an error in your SQL syntax")
            else:
                self._respond(200, b"created")
            return
        self._respond(404, b"nope")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve()

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
def direct_ffuf(monkeypatch: pytest.MonkeyPatch):
    """Route run() through a direct subprocess with a minimal env."""
    import shutil as _shutil
    import tempfile

    captured: dict[str, Any] = {}
    # ffuf needs a WRITABLE home (it creates ~/.config/ffuf at startup —
    # the same reason the production path runs with fake_home=True). A
    # randomized mkdtemp dir avoids collisions across concurrent or
    # repeated runs, and an empty home guarantees no ffufrc autoload.
    home = tempfile.mkdtemp(prefix="raptor-ffuf-live-home-")

    def _run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        # Built UP from nothing, not filtered down from os.environ: the
        # child gets no API keys or tokens and no proxy vars. PATH is
        # irrelevant (cmd[0] is the resolved binary path) but harmless.
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

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", _run)
    try:
        yield captured
    finally:
        _shutil.rmtree(home, ignore_errors=True)


def _wordlist(tmp_path: Path, name: str, words: list[str]) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


def test_live_basic_discovery_finds_planted_paths(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "backup", "nosuchpath"])

    runner = FfufRunner(base_url, tmp_path)
    # Deliberately the one live test that leaves -ac (the dataclass
    # default) enabled: its assertions are calibration-proof on this
    # fixture (planted bodies differ from the 404 baseline in size,
    # words, and lines), and it smokes the -ac code path.
    result = runner.run(
        FfufConfig(wordlist=wordlist, threads=2, timeout=5, max_runtime=30)
    )

    assert result["returncode"] == 0, result["stderr"]
    assert result["timed_out"] is False
    hits = {entry["url"].rsplit("/", 1)[-1] for entry in result["results"]}
    assert {"admin", "backup"} <= hits
    assert "nosuchpath" not in hits


def test_live_config_file_credentials_reach_the_wire(
    tmp_path: Path, fixture_server, direct_ffuf
):
    """The -config TOML (which replaced argv -H/-b/-d) must actually be
    parsed and applied by real ffuf: header, cookie, and body arrive on
    the wire while the argv stays credential-free."""
    base_url, records = fixture_server
    wordlist = _wordlist(tmp_path, "params.txt", ["user"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            path_template="login",
            method="POST",
            data="name=FUZZ&api_key=live-cred-42",
            headers=("Authorization: Bearer live-tok-42",),
            cookies=("session=live-sess-42",),
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    cmd = direct_ffuf["cmd"]
    assert "-config" in cmd
    assert "-H" not in cmd and "-b" not in cmd and "-d" not in cmd
    posts = [record for record in records if record["method"] == "POST"]
    assert posts, records
    assert any(record["authorization"] == "Bearer live-tok-42" for record in posts)
    assert any("session=live-sess-42" in record["cookie"] for record in posts)
    assert any(
        "name=user" in record["body"] and "api_key=live-cred-42" in record["body"]
        for record in posts
    )


def test_live_clusterbomb_sends_full_product(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, records = fixture_server
    words = _wordlist(tmp_path, "w1.txt", ["alpha", "beta"])
    values = _wordlist(tmp_path, "w2.txt", ["one", "two"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=words,
            path_template="search?FUZZ=W2",
            extra_wordlists=((values, "W2"),),
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    queries = {
        record["path"].split("?", 1)[1]
        for record in records
        if "?" in record["path"]
    }
    assert queries == {"alpha=one", "alpha=two", "beta=one", "beta=two"}


def test_live_recursion_argv_is_accepted(tmp_path: Path, fixture_server, direct_ffuf):
    """The strict FUZZ-terminated template rule mirrors upstream; the
    emitted -recursion/-maxtime-job/-rate combination must be accepted
    by real ffuf without a config error."""
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "nosuchpath"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            recursion=True,
            recursion_depth=1,
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]


def test_live_vhost_reports_matched_host(tmp_path: Path, fixture_server, direct_ffuf):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "subs.txt", ["dev", "nosuchsub"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            vhost=True,
            auto_calibration=False,
            match_status="200",
            filter_status=None,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    hosts = {entry.get("host", "") for entry in result["results"]}
    assert any(host.startswith("dev.") for host in hosts), result["results"]


def test_live_filter_regex_subtracts_matching_bodies(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "backup"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            filter_regex="quite boring",
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    hits = {entry["url"].rsplit("/", 1)[-1] for entry in result["results"]}
    assert "backup" in hits
    assert "admin" not in hits  # its body matches the filter regex


def test_live_raw_request_mode_fuzzes_body(
    tmp_path: Path, fixture_server, direct_ffuf
):
    """-request mode on the wire: the raw request file's body keyword is
    substituted and the requests reach the fixture."""
    from urllib.parse import urlparse

    base_url, records = fixture_server
    host = urlparse(base_url).netloc
    wordlist = _wordlist(tmp_path, "params.txt", ["alpha", "beta"])
    request = tmp_path / "req.txt"
    request.write_text(
        "POST /login HTTP/1.1\n"
        f"Host: {host}\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "Content-Length: 9\n"
        "\n"
        "name=FUZZ",
        encoding="utf-8",
    )

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            request_file=request,
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    posts = [r for r in records if r["method"] == "POST"]
    bodies = {r["body"] for r in posts}
    assert {"name=alpha", "name=beta"} <= bodies, bodies
    # Body-positioned fuzzing: the report URL is constant, so the input
    # map is the only record of which entry matched.
    matched_inputs = {
        entry["input"]["FUZZ"]
        for entry in result["results"]
        if "input" in entry
    }
    assert matched_inputs, result["results"]
    assert matched_inputs <= {"alpha", "beta"}


def test_live_encoder_chain_applies(tmp_path: Path, fixture_server, direct_ffuf):
    base_url, records = fixture_server
    wordlist = _wordlist(tmp_path, "vals.txt", ["a b"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            path_template="search?q=FUZZ",
            encoders=("FUZZ:urlencode",),
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    paths = {r["path"] for r in records}
    # The space was urlencoded by ffuf's -enc, then once more as query
    # text: the raw 'a b' never appears.
    assert any("q=a" in p and " " not in p for p in paths), paths


def test_live_calibration_strategy_accepted(
    tmp_path: Path, fixture_server, direct_ffuf
):
    base_url, _records = fixture_server
    wordlist = _wordlist(tmp_path, "dirs.txt", ["admin", "nosuch"])

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            calibration_strategy="advanced",
            calibration_per_host=True,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]


def test_live_api_sweep_funnel_recovers_matched_payload(
    tmp_path: Path, fixture_server, direct_ffuf
):
    """The whole pre-filter funnel on the wire: a generated raw request
    file is accepted by real ffuf, the sweep marker regex is valid Go
    regexp, and the matched payload comes back through the input map."""
    from packages.web.api_testing import (
        ApiOperation,
        build_raw_request,
        sweep_match_regex,
    )

    base_url, _records = fixture_server
    op = ApiOperation(
        method="POST",
        url=f"{base_url}/v1/users",
        body_template={"name": "raptor-baseline"},
        string_body_fields=[("name",)],
    )
    request_file = tmp_path / "api-sweep-00.request"
    request_file.write_text(
        build_raw_request(op, base_url, ("name",)), encoding="utf-8",
    )
    wordlist = _wordlist(
        tmp_path, "payloads.txt", ["benign-value", "x' OR 'a'='a"],
    )

    runner = FfufRunner(base_url, tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            request_file=request_file,
            match_status=None,
            match_regex=sweep_match_regex(),
            auto_calibration=False,
            threads=1,
            timeout=5,
            max_runtime=30,
        )
    )

    assert result["returncode"] == 0, result["stderr"]
    matched = {
        entry["input"]["FUZZ"]
        for entry in result["results"]
        if "input" in entry
    }
    assert matched == {"x' OR 'a'='a"}, result["results"]
