"""start_lifecycle must inject the trust marker so the libexec guard passes
on the login-free `python3 raptor.py` path.

The lifecycle helper's inline trust guard needs _RAPTOR_TRUSTED or CLAUDECODE
in its env. get_safe_env() only copies those if already in os.environ — absent
on a direct (non-bin/raptor, non-Claude-Code) invocation, which silently
skipped the /understand pre-pass. start_lifecycle now asserts the marker.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from core.orchestration.skill_dispatch import start_lifecycle


def _fake_completed(stdout: str = "OUTPUT_DIR=/tmp/run\n"):
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=stdout, stderr="",
    )


def test_lifecycle_env_carries_trust_marker_when_parent_lacks_it():
    recorded = {}

    def _fake_run(argv, **kwargs):
        recorded["env"] = kwargs.get("env")
        return _fake_completed()

    # Parent env WITHOUT the marker (the direct python3 raptor.py case) and a
    # get_safe_env that returns a bare dict (no marker copied in).
    with patch("core.orchestration.skill_dispatch.subprocess.run",
               side_effect=_fake_run), \
         patch("core.config.RaptorConfig.get_safe_env",
               return_value={"PATH": "/usr/bin"}), \
         patch.dict("os.environ", {}, clear=True):
        start_lifecycle("understand", Path("/tmp/target"))

    assert recorded["env"].get("_RAPTOR_TRUSTED") == "1"


def test_lifecycle_does_not_fabricate_claudecode():
    # _RAPTOR_TRUSTED is the honest marker for a non-CC transport; CLAUDECODE
    # must NOT be invented (it would misrepresent the transport).
    recorded = {}

    def _fake_run(argv, **kwargs):
        recorded["env"] = kwargs.get("env")
        return _fake_completed()

    with patch("core.orchestration.skill_dispatch.subprocess.run",
               side_effect=_fake_run), \
         patch("core.config.RaptorConfig.get_safe_env",
               return_value={"PATH": "/usr/bin"}), \
         patch.dict("os.environ", {}, clear=True):
        start_lifecycle("understand", Path("/tmp/target"))

    assert "CLAUDECODE" not in recorded["env"]


def test_lifecycle_preserves_existing_marker_value():
    # setdefault must not clobber a real parent marker (bin/raptor / CC).
    recorded = {}

    def _fake_run(argv, **kwargs):
        recorded["env"] = kwargs.get("env")
        return _fake_completed()

    with patch("core.orchestration.skill_dispatch.subprocess.run",
               side_effect=_fake_run), \
         patch("core.config.RaptorConfig.get_safe_env",
               return_value={"PATH": "/usr/bin", "_RAPTOR_TRUSTED": "preset"}):
        start_lifecycle("understand", Path("/tmp/target"))

    assert recorded["env"]["_RAPTOR_TRUSTED"] == "preset"
