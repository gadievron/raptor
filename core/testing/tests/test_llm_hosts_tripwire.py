"""Real Linux TLS/socket ownership checks without modifying /etc/hosts."""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core.testing.llm_hosts_tripwire import endpoint_hosts, serve

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux /proc ownership")


def test_manifest_uses_native_broker_and_configured_endpoints(tmp_path):
    native = tmp_path / "core/llm/model_data.py"
    native.parent.mkdir(parents=True)
    native.write_text("PROVIDER_ENDPOINTS = {'cloud': 'https://native.invalid/v1', "
                      "'local': 'http://localhost:11434/v1'}\n")
    registry = tmp_path / "core/llm/model_brokers/registry.json"
    registry.parent.mkdir()
    registry.write_text('// Registry comments must not truncate HTTPS URLs.\n'
                        '{"brokers":[{"upstream_base_url":"https://broker.invalid"}]}')
    models = tmp_path / "models.json"
    models.write_text(json.dumps({"models": [{
        "api_base": "https://custom.invalid:8443/v1", "region": "eu-west-1",
    }]}))
    manifest = endpoint_hosts(tmp_path, [models])
    assert {"native.invalid", "broker.invalid", "custom.invalid",
            "api.anthropic.com", "bedrock-mantle.eu-west-1.api.aws"} <= set(manifest["hosts"])
    assert "localhost" not in manifest["hosts"]
    assert 8443 in manifest["ports"]
    assert 11434 not in manifest["ports"]


@pytest.fixture
def sink(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl required for untrusted test certificate")
    directory = tmp_path / "sink"
    directory.mkdir()
    (directory / "endpoints.json").write_text(json.dumps({
        "hosts": ["api.openai.com"], "ports": [0],
    }))
    hosts = tmp_path / "hosts"
    original = "127.0.0.1 localhost\n198.51.100.1 api.openai.com kept.invalid # existing\n"
    hosts.write_text(original)
    stop = threading.Event()
    failures = []

    def run():
        try:
            serve(directory, hosts, stop.is_set)
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not (directory / "ready.json").exists():
            assert not failures, failures
            assert time.monotonic() < deadline, "TLS sink did not start"
            time.sleep(0.01)
        assert "::1 api.openai.com" in hosts.read_text()
        assert "198.51.100.1 kept.invalid # existing" in hosts.read_text()
        assert "198.51.100.1 api.openai.com" not in hosts.read_text()
        yield directory
    finally:
        stop.set()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert not failures, failures
        assert hosts.read_text() == original


@pytest.mark.parametrize("family", [0, 1])
def test_invalid_certificate_still_records_child_origin_and_worker(sink, family):
    ready = json.loads((sink / "ready.json").read_text())
    address = ready["addresses"][family][:2]
    (sink / "parent.active.json").write_text(json.dumps({
        "pid": os.getpid(), "worker": "gw-owner",
        "active_test": "test_new_active", "previous_test": "test_previous",
    }))
    code = '''
import os, socket, ssl, sys
print(os.getpid(), flush=True)
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname='api.openai.com'):
            raise AssertionError('untrusted certificate was accepted')
except ssl.SSLCertVerificationError:
    pass
'''
    child = subprocess.run(
        [sys.executable, "-I", "-c", code, str(address[0]), str(address[1])],
        env=dict(os.environ, PYTEST_CURRENT_TEST="test_original (call)"),
        capture_output=True, text=True, timeout=5,
    )
    assert child.returncode == 0, child.stderr
    path = sink / "connections.jsonl"
    deadline = time.monotonic() + 2
    while not path.exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)
    row = json.loads(path.read_text())
    assert row["owner_pid"] == int(child.stdout)
    assert row["worker"] == "gw-owner"
    assert row["active_test"] == "test_new_active"
    assert row["origin_test"] == "test_original (call)"
    assert row["hostname"] == "api.openai.com"


def test_no_connections_leave_no_failure_journal(sink):
    assert not (sink / "connections.jsonl").exists()


@pytest.mark.wall_budget(30)  # Exercises the real nested xdist controller.
def test_swallowed_tls_failure_still_fails_xdist(sink, tmp_path):
    pytest.importorskip("xdist")
    root = Path(__file__).resolve().parents[3]
    address = json.loads((sink / "ready.json").read_text())["addresses"][0][:2]
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    test_file = tmp_path / "test_tls_leak.py"
    test_file.write_text('''
import os, socket, ssl
def attempt():
    try:
        with socket.create_connection(('127.0.0.1', int(os.environ['TLS_PORT'])), timeout=3) as conn:
            with ssl.create_default_context().wrap_socket(conn, server_hostname='api.openai.com'):
                pass
    except ssl.SSLCertVerificationError:
        pass
def test_first(): attempt()
def test_second(): attempt()
''')
    env = dict(os.environ, TLS_PORT=str(address[1]), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    for name in ("PYTEST_ADDOPTS", "PYTEST_XDIST_WORKER", "PYTEST_XDIST_WORKER_COUNT",
                 "PYTEST_XDIST_TESTRUNUID", "RAPTOR_TEST_LIVE_LLM"):
        env.pop(name, None)
    result = subprocess.run(
        [sys.executable, "-c", "import sys;sys.path.insert(0,sys.argv.pop(1));"
         "import pytest;raise SystemExit(pytest.main(sys.argv[1:]))", str(root),
         "-q", "-p", "core.testing.llm_tripwire", "-p", "xdist.plugin", "-n", "2",
         "--llm-tripwire-host-dir", str(sink), str(test_file)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "2 passed" in result.stdout
    assert "LLM hostname tripwire FAILED" in result.stdout
    rows = [json.loads(line) for line in (sink / "connections.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    assert {r["active_test"].split("::")[-1] for r in rows} == {"test_first", "test_second"}
    assert {r["worker"] for r in rows} == {"gw0", "gw1"}
    assert all(r["owner_pid"] is not None for r in rows)
