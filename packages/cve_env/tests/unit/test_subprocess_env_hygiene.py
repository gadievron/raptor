"""REC-2: subprocess env-hygiene integration tests.

Each test asserts that a specific bare-subprocess site in cve-env tools
passes ``env=safe_subprocess_env()`` (or equivalent) so dangerous env
vars (HTTPS_PROXY / LD_PRELOAD / GIT_SSH_COMMAND / PYTHONPATH / ...)
do NOT leak from the parent shell into git/docker/gh subprocesses.

Test pattern: monkey-patch ``subprocess.run`` (or ``run_with_timeout``)
with a recorder, set HTTPS_PROXY in os.environ, invoke the function,
assert the recorded ``env=`` kwarg is a dict AND does NOT contain the
dangerous var.

At HEAD (pre-fix): ``env=`` kwarg is missing/None → recorder sees
``env=None`` (subprocess inherits parent) → assertion fails → RED.
After fix: ``env=safe_subprocess_env()`` → recorder sees a dict with
HTTPS_PROXY stripped → GREEN.

Sites covered (REC-2, 2026-05-10):

Direct (env= wired explicitly at site):
  - tools/docker_run.py:205 (port-poll docker inspect loop)
  - tools/docker_run.py:238 (docker logs on error path)

Transitive (covered by run_with_timeout's safe default, REC-2 prong 2):
  - tools/docker_run.py main `docker run --pull always` (Phase B,
    docker-pull hang: migrated from a bare subprocess.run to
    run_with_timeout so the pull is timeout-bounded; its env safety is
    now the run_with_timeout safe default, asserted in
    test_run_with_timeout_default_strips_dangerous_env)
  - tools/docker_run.py:345 (post-failure docker logs probe)
  - tools/docker_run.py:443, 444 (docker stop / docker rm -f cleanup)
  - tools/run_in_container.py:126 (docker exec sh -c)
  - tools/arch.py:84 (docker manifest inspect)
  - infra/service_health.py:213 (docker manifest inspect probe)
  - infra/service_health.py:153 (gh auth token probe)
  - plus 11 more run_with_timeout sites across image_resolve, source_build,
    docker_build, docker_compose_up, verify, github_fetch (17 transitive total)

Helper used: ``cve_env.utils.safe_env.safe_subprocess_env()`` —
returns ``os.environ`` minus 19 dangerous vars (raptor parity).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Sentinel value we set in HTTPS_PROXY; if it leaks into the env= kwarg
# passed to subprocess.run, the test fails.
_LEAK_SENTINEL = "http://leak-detect.invalid:9999"


@pytest.fixture
def proxy_set(monkeypatch: pytest.MonkeyPatch) -> str:
    """Set HTTPS_PROXY in os.environ for the duration of the test.

    Returns the sentinel value the test will look for in subprocess kwargs.
    """
    monkeypatch.setenv("HTTPS_PROXY", _LEAK_SENTINEL)
    monkeypatch.setenv("LD_PRELOAD", "/tmp/leak-preload.so")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /tmp/leak-key")
    return _LEAK_SENTINEL


def _assert_env_safe(call_kwargs: dict[str, Any]) -> None:
    """Assert ``env=`` kwarg passed to subprocess.run is a dict that
    has stripped the dangerous vars set by ``proxy_set`` fixture.

    RED at HEAD: env kwarg is None (default) → fails first assertion.
    GREEN after fix: env kwarg is dict from safe_subprocess_env() →
    HTTPS_PROXY/LD_PRELOAD/GIT_SSH_COMMAND all popped.
    """
    env = call_kwargs.get("env")
    assert env is not None, (
        f"subprocess called WITHOUT env= kwarg → child inherits parent env "
        f"including HTTPS_PROXY={_LEAK_SENTINEL}. Fix: pass "
        f"env=safe_subprocess_env() at this call site."
    )
    assert isinstance(env, dict), f"env must be dict, got {type(env).__name__}"
    assert "HTTPS_PROXY" not in env, (
        f"HTTPS_PROXY leaked into subprocess child env: {env.get('HTTPS_PROXY')!r}"
    )
    assert "LD_PRELOAD" not in env, (
        f"LD_PRELOAD leaked into subprocess child env: {env.get('LD_PRELOAD')!r}"
    )
    assert "GIT_SSH_COMMAND" not in env, (
        f"GIT_SSH_COMMAND leaked into subprocess child env: "
        f"{env.get('GIT_SSH_COMMAND')!r}"
    )


# ─── docker_run inspect/logs + main `docker run --pull always` ────────
# The main `docker run --pull always` call is the CRITICAL user-facing run
# for CVE container exec. Phase B (docker-pull hang) migrated it from a bare
# subprocess.run to run_with_timeout (timeout-bounded). Its env safety is now
# the run_with_timeout safe default (env=None → safe_subprocess_env()), so
# this test asserts the main run is invoked WITHOUT an explicit env= kwarg
# (i.e. it takes the safe default) and that the direct inspect/logs
# subprocess.run sites still pass env=safe_subprocess_env().


def test_docker_run_strips_dangerous_env(proxy_set: str) -> None:
    """REC-2 site: tools/docker_run.py `docker run --pull always` for CVE container.

    The agent runs CVE binaries inside Docker. If HTTPS_PROXY leaks to the
    docker daemon, the container's network traffic may be re-routed through
    a debugger / MITM. If LD_PRELOAD leaks, every native binary inside the
    container loads a hijack library.
    """
    from cve_env.tools import docker_run as dr
    from cve_env.utils.run import RunOutcome

    rwt_kwargs: list[dict[str, Any]] = []

    def mock_rwt(cmd: list[str], **kwargs: Any) -> RunOutcome:
        rwt_kwargs.append(kwargs)
        # The port-poll `docker inspect` needs a valid Ports JSON so the loop
        # resolves immediately (no spin); the main `docker run` needs a hex id.
        if "inspect" in cmd:
            stdout = '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"49000"}]}'
        else:
            stdout = (
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
            )
        return RunOutcome(returncode=0, stdout=stdout, stderr="", timed_out=False)

    # Stage 3E-b (2026-05-27): the inspect/logs sites migrated from bare
    # subprocess.run to run_with_timeout (bounded), joining the main docker-run
    # call. ALL external docker calls now flow through run_with_timeout, which
    # applies safe_subprocess_env() by default when no env= is passed — so the
    # REC-2 env-stripping holds for every site via that single-point default.
    with (
        patch.object(dr, "run_with_timeout", side_effect=mock_rwt),
        patch.object(dr.time, "sleep"),
    ):
        dr.docker_run(
            image="busybox:latest",
            container_port=80,
            cve_id="CVE-TEST-0001",
        )

    # Every docker call (main run + inspect poll + any logs tail) must take
    # run_with_timeout's safe env DEFAULT — i.e. no explicit env= — so REC-2
    # dangerous-var stripping (HTTPS_PROXY / LD_PRELOAD / ...) holds at all sites.
    assert rwt_kwargs, "docker_run did not invoke run_with_timeout"
    for kw in rwt_kwargs:
        assert "env" not in kw, (
            "a docker call passed an explicit env= to run_with_timeout, bypassing "
            f"the safe default; REC-2 stripping would not apply. got: {kw}"
        )


# ─── run_with_timeout default ────────────────────────────────────────────
# REC-2 (2026-05-10): run_with_timeout defaults to safe_subprocess_env()
# when caller passes env=None (the default). This single-point fix covers
# the 13 migrated subprocess sites that were Stage-2-consolidated through
# this helper.


def test_run_with_timeout_default_strips_dangerous_env(
    proxy_set: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REC-2: run_with_timeout's default behavior strips dangerous env vars.

    When called without an explicit ``env=``, the helper builds
    ``safe_subprocess_env()`` and passes it to subprocess.run. So callers
    who migrated to run_with_timeout (Cleanup-Item-3 Stage 2) automatically
    get env hygiene without needing per-site boilerplate.
    """
    from cve_env.utils import run as run_mod

    captured: list[dict[str, Any]] = []

    def mock_subprocess_run(*args: Any, **kwargs: Any) -> MagicMock:
        captured.append(kwargs)
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        return m

    monkeypatch.setattr(run_mod.subprocess, "run", mock_subprocess_run)

    # Call run_with_timeout with no env= → should default to safe.
    outcome = run_mod.run_with_timeout(["echo", "hi"], timeout=2.0)
    assert outcome.returncode == 0
    assert captured, "run_with_timeout did not invoke subprocess.run"
    _assert_env_safe(captured[0])


def test_run_with_timeout_keep_env_opt_in(
    proxy_set: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REC-2: ``keep_env`` opt-in retains specific dangerous vars.

    Use case: a caller legitimately needs HTTPS_PROXY (e.g., behind a
    corporate proxy). Pass ``keep_env=frozenset({"HTTPS_PROXY"})`` and
    that single var stays; the rest of the dangerous list is still stripped.
    """
    from cve_env.utils import run as run_mod

    captured: list[dict[str, Any]] = []

    def mock_subprocess_run(*args: Any, **kwargs: Any) -> MagicMock:
        captured.append(kwargs)
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        return m

    monkeypatch.setattr(run_mod.subprocess, "run", mock_subprocess_run)

    run_mod.run_with_timeout(
        ["echo", "hi"],
        timeout=2.0,
        keep_env=frozenset({"HTTPS_PROXY"}),
    )
    assert captured
    env = captured[0].get("env")
    assert env is not None
    assert env.get("HTTPS_PROXY") == _LEAK_SENTINEL  # opt-in retained
    assert "LD_PRELOAD" not in env  # other dangerous vars still stripped
    assert "GIT_SSH_COMMAND" not in env
