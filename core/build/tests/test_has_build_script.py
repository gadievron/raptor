"""Pre-parse gating of package.json in ``BuildDetector._has_build_script``.

The manifest comes from the SCANNED (untrusted) repo and the check
runs in the unsandboxed parent process, so the bytes must be gated
before any JSON parse:

  * a symlinked package.json must be refused (a link at /dev/zero
    would otherwise be slurped until OOM);
  * a FIFO must not block the open (an un-written pipe would
    otherwise hang the detector forever);
  * an oversized manifest must be refused before parsing.

Every refusal degrades to "no build script" — the same answer a
malformed manifest already produced.
"""

from __future__ import annotations

import json
import os
import threading

import pytest

from core.build.build_detector import BuildDetector

_BUILD_MANIFEST = json.dumps({"scripts": {"build": "tsc"}})


def _detector(tmp_path):
    return BuildDetector(tmp_path)


class TestHasBuildScriptGate:
    def test_regular_manifest_with_build_script(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(_BUILD_MANIFEST)
        assert _detector(tmp_path)._has_build_script(pkg) is True

    def test_regular_manifest_without_build_script(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"scripts": {"test": "jest"}}))
        assert _detector(tmp_path)._has_build_script(pkg) is False

    def test_symlinked_manifest_refused(self, tmp_path):
        """A symlink at package.json is never followed — the target
        may be /dev/zero or any host file the repo shouldn't reach."""
        real = tmp_path / "real.json"
        real.write_text(_BUILD_MANIFEST)
        pkg = tmp_path / "package.json"
        pkg.symlink_to(real)
        assert _detector(tmp_path)._has_build_script(pkg) is False

    def test_oversized_manifest_refused(self, tmp_path):
        """A manifest past the size cap is refused before parsing."""
        cap = BuildDetector._PACKAGE_JSON_MAX_BYTES
        pkg = tmp_path / "package.json"
        filler = " " * (cap + 1)
        pkg.write_text(
            '{"scripts": {"build": "tsc"}, "pad": "' + filler + '"}',
        )
        assert _detector(tmp_path)._has_build_script(pkg) is False

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="platform lacks mkfifo",
    )
    def test_fifo_manifest_does_not_block(self, tmp_path):
        """A FIFO at package.json must not hang the detector: the
        gate opens O_NONBLOCK and refuses non-regular files."""
        pkg = tmp_path / "package.json"
        os.mkfifo(pkg)
        result: list = []
        t = threading.Thread(
            target=lambda: result.append(
                _detector(tmp_path)._has_build_script(pkg),
            ),
            daemon=True,
        )
        t.start()
        t.join(timeout=10)
        assert not t.is_alive(), "_has_build_script blocked on a FIFO"
        assert result == [False]
