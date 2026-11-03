"""Opt-in pytest LLM tripwire: ``pytest -p core.testing.llm_tripwire``.

Each process owns a loopback HTTP listener and private models.json. Children
inherit that config, so swallowed SDK errors still leave a failing journal.
Explicit fake-server/config overrides remain usable; this is a default-route
tripwire, not a firewall against hardcoded alternate providers.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import mkdtemp

import pytest

_KEY = pytest.StashKey()
_CREDENTIALS = (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "GOOGLE_APPLICATION_CREDENTIALS",
)


class Listener:
    """Bounded, non-forwarding HTTP sink with an owned server thread."""

    def __init__(self, journal: Path, worker: str):
        self.journal = journal
        self.worker = worker
        self.active = "<collection or between tests>"
        self.previous = None
        self.count = 0
        self.worker_requests = 0
        self.journal_errors = []
        self.host_dir = None
        self.context_path = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(0.5)

            def log_message(self, *args):
                pass

            def do_POST(self):
                self.trip()

            do_GET = do_POST
            do_PUT = do_POST
            do_DELETE = do_POST
            do_PATCH = do_POST
            do_HEAD = do_POST
            do_OPTIONS = do_POST

            def trip(self):
                owner.count += 1
                # Snapshot BEFORE reading: an old child can overlap the next test.
                active, previous = owner.active, owner.previous
                body = b""
                try:
                    length = max(0, int(self.headers.get("Content-Length", "0")))
                    body = self.rfile.read(min(length, 65536))
                except (ValueError, OSError):
                    pass
                row = {
                    "time_ns": time.time_ns(), "worker": owner.worker,
                    "active_test": active, "previous_test": previous,
                    "method": self.command, "path": self.path[:512],
                    # No authorization headers; bounded test prompt for diagnosis.
                    "body_excerpt": body.decode("utf-8", errors="replace")[:4096],
                }
                try:
                    with journal.open("a", encoding="utf-8") as out:
                        out.write(json.dumps(row) + "\n")
                except OSError as error:
                    owner.journal_errors.append(str(error))
                payload = json.dumps({"error": {
                    "message": "CI LLM tripwire: unexpected request from " + active,
                    "type": "invalid_request_error", "code": "llm_leak",
                }}).encode()
                try:
                    self.send_response(400)  # Non-retryable SDK status.
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    pass  # Disconnects cannot erase the recorded request.

        journal.parent.mkdir(parents=True, exist_ok=True)
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1"
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05),
            name="raptor-llm-tripwire", daemon=True,
        )
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("LLM tripwire listener did not stop")


def pytest_addoption(parser):
    parser.addoption(
        "--llm-tripwire-dir", default=None,
        help="Retain LLM request journals/configs here (unique subdir per session).",
    )
    parser.addoption(
        "--llm-tripwire-host-dir", default=None,
        help="Linux hostname sink directory: publish active tests and fail on connections.",
    )


def _publish(listener):
    if listener.context_path is None:
        return
    row = {"pid": os.getpid(), "worker": listener.worker,
           "active_test": listener.active, "previous_test": listener.previous,
           "updated_ns": time.time_ns()}
    temporary = listener.context_path.with_suffix(".next")
    temporary.write_text(json.dumps(row))
    temporary.replace(listener.context_path)


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if os.environ.get("RAPTOR_TEST_LIVE_LLM") == "1":
        raise pytest.UsageError("LLM tripwire cannot run with RAPTOR_TEST_LIVE_LLM=1")
    workerinput = getattr(config, "workerinput", None)
    if workerinput is not None:
        directory = Path(workerinput["llm_tripwire_dir"])
        worker = workerinput["workerid"]
    else:
        parent = config.getoption("--llm-tripwire-dir")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        directory = Path(mkdtemp(prefix="raptor-llm-tripwire-", dir=parent)).resolve()
        worker = "controller"
    listener = Listener(directory / f"{worker}.jsonl", worker)
    previous = {}
    config.stash[_KEY] = (listener, directory, previous)
    host_dir = config.getoption("--llm-tripwire-host-dir")
    listener.host_dir = Path(host_dir).resolve() if host_dir else None
    listener.context_path = (listener.host_dir / f"{worker}-{os.getpid()}.active.json"
                             if host_dir else None)
    if host_dir and not (listener.host_dir / "ready.json").exists():
        listener.close()
        raise pytest.UsageError("LLM hostname tripwire is not ready")
    _publish(listener)
    model_file = directory / f"{worker}-models.json"
    model_file.write_text(json.dumps({"models": [{
        "provider": "openai", "model": "gpt-5.2", "api_key": "ci-tripwire",
        "api_base": listener.url, "timeout": 2,
    }]}), encoding="utf-8")
    model_file.chmod(0o600)
    changes = {"RAPTOR_CONFIG": str(model_file),
               "OPENAI_BASE_URL": listener.url,
               "RAPTOR_CC_TRANSPORT_DISABLED": "1"}
    changes.update(dict.fromkeys(_CREDENTIALS))
    # Broker credentials belong to the catalog, not Python declarations.
    # Literal broker keys here would disable the registry's ownership check.
    from core.llm.model_brokers import MODEL_BROKERS
    changes.update(dict.fromkeys(broker.api_key_env for broker in MODEL_BROKERS))
    previous.update({name: os.environ.get(name) for name in changes})
    for name, value in changes.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    config.stash[_KEY] = (listener, directory, previous)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
    node.workerinput["llm_tripwire_dir"] = str(node.config.stash[_KEY][1])


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    listener = node.config.stash[_KEY][0]
    output = getattr(node, "workeroutput", {})
    listener.worker_requests += output.get("llm_tripwire_count", 0)
    listener.journal_errors.extend(output.get("llm_tripwire_journal_errors", []))


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    listener = item.config.stash[_KEY][0]
    listener.active = item.nodeid
    _publish(listener)
    try:
        return (yield)
    finally:
        listener.previous = item.nodeid
        listener.active = "<collection or between tests>"
        _publish(listener)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    listener, directory, _ = session.config.stash[_KEY]
    listener.close()
    if hasattr(session.config, "workeroutput"):
        session.config.workeroutput["llm_tripwire_count"] = listener.count
        session.config.workeroutput["llm_tripwire_journal_errors"] = listener.journal_errors
    host_log = listener.host_dir / "connections.jsonl" if listener.host_dir else None
    if (listener.count or listener.worker_requests
            or any(p.stat().st_size for p in directory.glob("*.jsonl"))
            or (host_log and host_log.exists() and host_log.stat().st_size)
            or (listener.host_dir and not (listener.host_dir / "ready.json").exists())):
        if session.exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter):
    listener, directory, _ = terminalreporter.config.stash[_KEY]
    rows = []
    for path in sorted(directory.glob("*.jsonl")):
        rows.extend(json.loads(line) for line in path.read_text().splitlines())
    if rows or listener.count or listener.worker_requests:
        terminalreporter.section("LLM tripwire FAILED", red=True, bold=True)
        for row in rows[:20]:
            terminalreporter.write_line(
                f"[{row['worker']}] {row['active_test']}: "
                f"{row['method']} {row['path']}", red=True,
            )
        terminalreporter.write_line(
            f"{max(len(rows), listener.count + listener.worker_requests)} unexpected "
            f"request(s); bounded prompt excerpts: {directory}",
        )
        for error in listener.journal_errors[:5]:
            terminalreporter.write_line(f"Request journal error: {error}", red=True)
    if listener.host_dir:
        path = listener.host_dir / "connections.jsonl"
        if path.exists() and path.stat().st_size:
            terminalreporter.section("LLM hostname tripwire FAILED", red=True, bold=True)
            for line in path.read_text().splitlines()[:20]:
                row = json.loads(line)
                terminalreporter.write_line(
                    f"pid={row['owner_pid']} worker={row['worker']} "
                    f"origin={row['origin_test']} active={row['active_test']} "
                    f"host={row.get('hostname', '<unknown>')}", red=True,
                )
            terminalreporter.write_line(f"Connection evidence: {path}")


def pytest_unconfigure(config):
    state = config.stash.get(_KEY, None)
    if state is None:
        return
    listener, _, previous = state
    if listener.thread.is_alive():
        listener.close()
    if listener.context_path:
        listener.context_path.unlink(missing_ok=True)
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
