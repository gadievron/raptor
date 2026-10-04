"""SCA's sandboxed child is RAPTOR's OWN agent (a trusted dispatch), so it must
keep its trust markers / RAPTOR_DIR.

Without keep_trust_markers_for_dispatch the sandbox's TARGET_ENV_STRIP_SET
strips RAPTOR_DIR (correct for untrusted targets), and the child's
`sys.path.insert(0, os.environ["RAPTOR_DIR"])` KeyErrors at import — the
observed `SCA stderr: KeyError: 'RAPTOR_DIR'` on the direct run.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from packages.sca.agent import run_sca_subprocess


def test_sca_subprocess_opts_into_keep_trust_markers(tmp_path):
    recorded = {}

    def _fake_run(cmd, **kwargs):
        recorded.update(kwargs)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("core.sandbox.run", side_effect=_fake_run):
        run_sca_subprocess(
            agent_path=tmp_path / "agent.py",
            target=tmp_path / "repo",
            output_dir=tmp_path / "out",
        )

    assert recorded.get("keep_trust_markers_for_dispatch") is True
