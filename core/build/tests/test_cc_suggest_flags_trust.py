"""_cc_suggest_flags holds its cc-trust verdict across dispatch staging.

The trust verdict is computed against the target SPELLING; config
assembly, proxy-host resolution and prompt staging all run before the
sandboxed ``claude`` spawn. The held-handle recheck immediately before
the spawn must refuse a target swapped at a fresh inode inside that
window — the CLI child must never be invoked against the swapped tree.
"""

from __future__ import annotations

import contextlib
import logging
import os
import subprocess
from pathlib import Path
from unittest import mock

import core.security.cc_trust as cc_trust
from core.build.build_detector import BuildDetector

_FAILURES = [{"file": "a.c", "error": "missing header"}]


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text("int main(void){return 0;}\n")
    return target


@contextlib.contextmanager
def _staged_dispatch(swap=None):
    """Stub the dispatch collaborators so the real method runs up to
    the spawn seam without touching credentials, proxies or tempfiles.

    ``swap`` (if given) runs at the readable-paths step — inside the
    verdict-to-spawn window: after the trust check released its
    verdict, before the pre-spawn recheck. The collaborators are
    patched on their source modules because the method imports them
    function-locally at call time.
    """

    def _readable(_claude_bin):
        if swap is not None:
            swap()
        return []

    with mock.patch("shutil.which", return_value="/usr/bin/claude"), \
         mock.patch("core.llm.cc_adapter.cc_subprocess_env",
                    return_value={}), \
         mock.patch("core.llm.cc_adapter.build_cc_command",
                    return_value=["claude", "-p"]), \
         mock.patch("core.llm.cc_adapter.system_prompt_file_for",
                    return_value=contextlib.nullcontext(None)), \
         mock.patch("core.llm.cc_proxy_hosts.proxy_hosts_for_cc_dispatch",
                    return_value=["example.invalid"]), \
         mock.patch("core.llm.cc_proxy_hosts.readable_paths_for_cc_dispatch",
                    side_effect=_readable), \
         mock.patch.object(cc_trust, "_trust_override_set", False):
        yield


def test_post_verdict_swap_refused_before_spawn(tmp_path, caplog):
    target = _target(tmp_path)

    def _swap():
        os.rename(target, tmp_path / "swapped-aside")
        target.mkdir()

    detector = BuildDetector(target)
    with _staged_dispatch(swap=_swap), \
         mock.patch("core.build.build_detector._sandbox_run",
                    side_effect=AssertionError(
                        "claude spawned against a swapped target"),
                    ) as spy, \
         caplog.at_level(logging.INFO):
        result = detector._cc_suggest_flags(list(_FAILURES), "cpp")
    assert result is None
    assert not spy.called
    assert "changed during the Claude Code config trust check" in caplog.text


def test_stable_target_passes_recheck_and_spawns(tmp_path):
    # Stable-direction companion: an unswapped target must still reach
    # the spawn (the recheck is refuse-only hardening, not a new gate).
    target = _target(tmp_path)
    detector = BuildDetector(target)
    with _staged_dispatch(), \
         mock.patch("core.build.build_detector._sandbox_run",
                    side_effect=subprocess.TimeoutExpired(
                        cmd="claude", timeout=1),
                    ) as spy:
        result = detector._cc_suggest_flags(list(_FAILURES), "cpp")
    assert result is None
    assert spy.called


def test_dirty_config_refused_before_staging(tmp_path, caplog):
    # Pre-existing refusal direction, now via the held handle: blocking
    # Claude Code config in the target skips flag inference before any
    # dispatch staging runs.
    target = _target(tmp_path)
    (target / ".mcp.json").write_text(
        '{"mcpServers": {"x": {"command": "evil"}}}')
    detector = BuildDetector(target)
    with _staged_dispatch(), \
         mock.patch("core.build.build_detector._sandbox_run") as spy, \
         caplog.at_level(logging.INFO):
        result = detector._cc_suggest_flags(list(_FAILURES), "cpp")
    assert result is None
    assert not spy.called
    assert "dangerous" in caplog.text
