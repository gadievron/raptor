"""Real parser and JVM behind the native worker filesystem policy."""

import json
import os
import shutil
import time
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

from packages.joern.models import JoernCPG
from packages.joern.services import GraphServices
from packages.joern.tunables import JoernTunables


@pytest.mark.integration
@pytest.mark.slow  # real parser/JVM boot, imports and recovery; opt-in native acceptance
@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="Linux or macOS worker check")
def test_real_joern_same_graph_leases_and_installation_protection(tmp_path, monkeypatch):
    from core.config import RaptorConfig
    from core.sandbox.landlock import _get_landlock_abi, check_landlock_available
    from core.sandbox.seccomp import check_seccomp_available
    from packages.joern.prereqs import is_available, joern_tool_paths
    from packages.joern.runner import build_cpg, cleanup_cpg
    if not is_available():
        pytest.skip("Joern required")
    if sys.platform == "linux" and (not check_landlock_available() or _get_landlock_abi() < 4 or not check_seccomp_available()):
        pytest.skip("Landlock ABI 4+ and seccomp required")
    if sys.platform == "darwin" and not Path("/usr/bin/sandbox-exec").exists():
        pytest.skip("Seatbelt required")
    from packages.joern.heap_ledger import _host_budget_mb
    budget = _host_budget_mb()
    if budget is not None and budget < 4096:
        pytest.skip("two-worker native acceptance requires a 4 GiB budget")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator-state"))
    target = tmp_path / "source"
    target.mkdir()
    (target / "main.c").write_text(
        "char *strcpy(char *, const char *);\n"
        "int fixture(void) { return 42; }\n"
        "void flow_fixture(char *input) { char output[16]; strcpy(output, input); }\n")
    if sys.platform == "darwin":
        private_base = os.confstr(65537)
        assert private_base, "macOS private temporary directory unavailable"
        scratch = Path(tempfile.mkdtemp(prefix="j", dir=private_base))
    else:
        scratch = tmp_path / "scratch"
        scratch.mkdir()
    from packages.joern import client as client_module
    monkeypatch.setattr(client_module, "_INITIAL_BASE", str(scratch))
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    guard = Path(__file__).resolve().parents[1] / "worker_guard.py"

    def parse(command, **kwargs):
        prefix = [sys.executable, "-I", str(guard), "--write", kwargs["output"]]
        for descriptor in kwargs.get("pass_fds", ()):
            prefix.extend(["--keep-fd", str(descriptor)])
        for path in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys",
                     str(target), *joern_tool_paths()]:
            if Path(path).exists():
                prefix.extend(["--read", path])
        import signal
        with (tmp_path / "parse.stdout").open("w+") as stdout, (tmp_path / "parse.stderr").open("w+") as stderr:
            process = subprocess.Popen([*prefix, "--", *command], stdout=stdout, stderr=stderr,
                                       start_new_session=True, cwd=kwargs["output"],
                                       pass_fds=kwargs.get("pass_fds", ()) ,
                                       env=RaptorConfig.strip_target_exec_markers(RaptorConfig.get_safe_env()))
            try:
                process.wait(timeout=kwargs["timeout"])
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            stdout.seek(0)
            stderr.seek(0)
            result = subprocess.CompletedProcess(command, process.returncode, stdout.read(), stderr.read())
        (tmp_path / "parse.stderr").write_text(result.stderr)
        assert result.returncode == 0, result.stderr
        return result

    graph = build_cpg(target, languages={"c"}, heap_mb=512, timeout=120,
                      subprocess_runner=parse)
    assert graph.exists() and not graph.build_failed
    other_target = target / "other"
    other_target.mkdir()
    (other_target / "other.c").write_text("int other_marker(void) { return 7; }\n")
    other_graph = build_cpg(other_target, languages={"c"}, heap_mb=512, timeout=120,
                            subprocess_runner=parse)
    assert other_graph.exists() and not other_graph.build_failed
    pool = GraphServices(tmp_path / "controller")
    try:
        tunables = JoernTunables(heap_mb=512, import_timeout_s=120, query_timeout_s=30)
        first = pool.acquire(graph, tunables)
        second = pool.acquire(JoernCPG(graph.path, target), tunables)
        assert len(pool.workers) == 1
        unrelated = pool.acquire(other_graph, tunables)
        assert len(pool.workers) == 2
        other_result = pool.execute(unrelated, "cpg.method.name.l", timeout=30)
        assert other_result.ok and "other_marker" in other_result.raw_output
        first_result = pool.execute(first, "cpg.method.name.l", timeout=30)
        assert first_result.ok and "fixture" in first_result.raw_output
        assert "other_marker" not in first_result.raw_output
        pool.release(unrelated)
        worker = next(iter(pool.workers.values())).server
        if sys.platform == "linux" and worker._member_pid is not None:
            command_line = Path(f"/proc/{worker._member_pid}/cmdline").read_bytes()
            assert worker._auth_password.encode() not in command_line
            for descriptor in worker._heap_reservation.pass_fds:
                target_fd = Path(f"/proc/{worker._member_pid}/fd/{descriptor}")
                assert ".leases/" in str(target_fd.readlink()), "JVM lost its kernel-held reservation"
        assert pool.execute(first, 'val raptorPrivateScopeProof = 7; "defined"', timeout=30).ok
        isolation = pool.execute(second, "raptorPrivateScopeProof", timeout=30)
        assert isolation.errors, "another caller inherited a previous query's definitions"
        result = pool.execute(second, "cpg.method.name.l", timeout=30)
        assert result.ok, result.errors
        assert "fixture" in result.raw_output, result.raw_output
        pool.release(first)
        assert pool.execute(second, "cpg.method.name.l", timeout=30).ok
        sentinel = tmp_path / "installation-source.py"
        sentinel.write_text("original")
        attack = f'java.nio.file.Files.writeString(java.nio.file.Paths.get({json.dumps(str(sentinel))}), "changed")'
        result = pool.execute(second, attack, timeout=30, validate=False)
        assert result.errors, result.raw_output
        assert sentinel.read_text() == "original"
        if sys.platform == "linux":
            proc_read = f'java.nio.file.Files.readString(java.nio.file.Paths.get("/proc/{os.getpid()}/environ"))'
            result = pool.execute(second, proc_read, timeout=30, validate=False)
            assert result.errors, "worker exposed another process environment"
        pool.release(second)
        assert not pool.workers
        # The same graph-bound API also crosses a real controller process.
        from packages.joern.broker import discover
        from packages.joern.client import GraphClient
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator-state"))
        endpoint = discover(scratch)
        first_client = GraphClient(tunables=tunables, endpoint=endpoint)
        second_client = GraphClient(tunables=tunables, endpoint=endpoint)
        try:
            assert first_client.bind_graph(graph)
            assert second_client.bind_graph(graph)
            errors = []
            flows = first_client.run_taint_query("flow_fixture", "strcpy", source_param="input",
                                                 timeout=60, errors_out=errors)
            assert not errors and flows, (errors, flows)
            errors = []
            batch = second_client.run_taint_queries_batch([("flow_fixture", "strcpy")],
                                                          timeout=60, errors_out=errors)
            assert not errors and batch, (errors, batch)
            from packages.joern.lang_config import C_CPP
            sweep = first_client.run_tiered_sweep(timeout=60, lang_profile=C_CPP)
            assert sweep.ok, sweep.errors
            first_client.stop()
            reply = second_client.query("cpg.method.name.l", timeout=30)
            assert reply.ok and "fixture" in reply.raw_output, reply.errors
            # Cancellation kills only the active generation. Another borrower
            # can recover from its immutable artifact after cache eviction.
            import threading
            from concurrent.futures import ThreadPoolExecutor
            cancel = threading.Event()
            timer = threading.Timer(1, cancel.set)
            timer.start()
            old_generation = second_client.cpg_load_epoch
            try:
                with ThreadPoolExecutor() as executor:
                    reply = executor.submit(second_client.query_cancellable,
                        "Thread.sleep(30000)", timeout=40, cancel_check=cancel.is_set).result(timeout=60)
                assert reply.errors and "cancel" in reply.errors[0].lower(), reply.errors
            finally:
                timer.cancel()
                timer.join()
            size = second_client.cpg_size_bytes()
            graph.path.unlink()
            assert second_client.cpg_size_bytes() == size and size > 0
            reply = second_client.query("cpg.method.name.l", timeout=30)
            assert reply.ok and "fixture" in reply.raw_output, reply.errors
            assert second_client.cpg_load_epoch > old_generation
        finally:
            first_client.stop()
            second_client.stop()
    finally:
        pool.close()
        cleanup_cpg(graph)
        cleanup_cpg(other_graph)
        if sys.platform == "darwin":
            # Leases acknowledge worker teardown; the empty controller has a
            # short independent idle grace before removing its endpoint.
            deadline = time.monotonic() + 10
            while list(scratch.glob("rj*/*/*/rpc.sock")) and time.monotonic() < deadline:
                time.sleep(0.1)
            assert not list(scratch.glob("rj*/*/*/rpc.sock"))
            shutil.rmtree(scratch)


@pytest.mark.integration
@pytest.mark.slow  # real parser/JVM boot, imports and recovery; opt-in native acceptance
def test_real_default_parser_and_public_client_share_controller(tmp_path, monkeypatch):
    from packages.joern.prereqs import is_available
    from packages.joern.runner import build_cpg, cleanup_cpg
    if not is_available():
        pytest.skip("Joern required")
    if sys.platform == "linux":
        from core.sandbox.landlock import _get_landlock_abi, check_landlock_available
        from core.sandbox.seccomp import check_seccomp_available
        if not check_landlock_available() or _get_landlock_abi() < 4 or not check_seccomp_available():
            pytest.skip("public worker requires Landlock ABI 4+ and seccomp")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "operator-state"))
    target = tmp_path / "source"
    target.mkdir()
    (target / "fixture.c").write_text("int default_parser_fixture(void) { return 42; }\n")
    graph = build_cpg(target, languages={"c"}, heap_mb=512, timeout=120)
    from packages.joern import JoernServer
    from packages.joern import client as client_module
    if sys.platform == "darwin":
        base = Path(tempfile.mkdtemp(prefix="j", dir=os.confstr(65537)))
    else:
        base = tmp_path / "service-runtime"
        base.mkdir()
    monkeypatch.setattr(client_module, "_INITIAL_BASE", str(base))
    tunables = JoernTunables(heap_mb=512, import_timeout_s=120, query_timeout_s=30)
    first = JoernServer(tunables=tunables)
    second = JoernServer(tunables=tunables)
    try:
        assert graph.exists() and not graph.build_failed
        assert first.bind_graph(graph)
        assert second.bind_graph(graph)
        assert first._lease.root == second._lease.root
        assert first._lease.lease != second._lease.lease
        result = first.query("cpg.method.name.l")
        assert result.ok and "default_parser_fixture" in result.raw_output, result.errors
        first.stop()
        graph.path.unlink()
        result = second.query("cpg.method.name.l")
        assert result.ok and "default_parser_fixture" in result.raw_output, result.errors
    finally:
        first.stop()
        second.stop()
        cleanup_cpg(graph)


@pytest.mark.integration
@pytest.mark.slow  # real parser/JVM boot, imports and recovery; opt-in native acceptance
@pytest.mark.skipif(sys.platform != "linux", reason="Linux namespace parser acceptance")
def test_real_parser_through_native_namespace_sandbox(tmp_path, monkeypatch):
    from core.sandbox import run
    from core.sandbox.probes import check_net_available, check_mount_available
    from packages.joern.prereqs import is_available
    from packages.joern import runner
    if not check_net_available() or not check_mount_available():
        pytest.skip("native user/mount namespace sandbox unavailable")
    if not is_available():
        pytest.skip("Joern required")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "state"))
    target = tmp_path / "source"
    target.mkdir()
    (target / "fixture.c").write_text("int native_parser_fixture(void) { return 42; }\n")
    results = []
    def strict(command, **kwargs):
        result = run(command, profile="strict", **kwargs)
        assert result.sandbox_info["mount_ns_active"], result.sandbox_info
        results.append(result)
        return result
    monkeypatch.setattr(runner, "_default_sandbox_runner", lambda: strict)
    graph = runner.build_cpg(target, languages={"c"}, heap_mb=512, timeout=120)
    try:
        assert graph.exists() and not graph.build_failed
        assert len(results) == 1
    finally:
        runner.cleanup_cpg(graph)
