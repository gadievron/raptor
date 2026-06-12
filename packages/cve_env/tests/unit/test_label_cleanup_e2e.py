"""Real-docker end-to-end guard for the #6 label→cleanup chain (2026-05-24).

The unit tests for #6 mock the docker boundary (argv construction, wiring). This
test is the NON-FAKE counterpart the user asked for: with a live Docker daemon
it actually builds a tiny image through ``docker_build``, asserts the
``cve-env.cve-id`` label landed on the real image, runs the real
``cleanup_result_images``, and asserts the image is gone. Skips cleanly when no
Docker daemon is reachable (e.g. Colima down) so the normal suite stays green.

Run explicitly with a live daemon:  uv run pytest refactor/tests/unit/test_label_cleanup_e2e.py -q
"""
from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest


def _docker_reachable() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return (
            subprocess.run(
                ["docker", "info"], capture_output=True, timeout=20
            ).returncode
            == 0
        )
    except (subprocess.SubprocessError, OSError):
        return False


pytestmark = [
    # @slow → excluded from the default/pre-commit suite (addopts `-m 'not slow'`).
    # This is a real-docker build test: slow (~seconds), registry-dependent, and
    # under xdist its heavy build starves neighbors. Run explicitly: pytest -m slow.
    pytest.mark.slow,
    pytest.mark.skipif(
        not _docker_reachable(), reason="real Docker daemon required (Colima up)"
    ),
]


def test_label_lands_on_real_image_and_cleanup_removes_it(tmp_path: Path) -> None:
    from cve_env.config import CVE_LABEL
    from cve_env.tools.docker_build import docker_build
    from cve_env.utils.lifecycle import cleanup_result_images

    cve_id = f"CVE-TEST-{uuid.uuid4().hex[:8]}"
    tag = f"cve-env-local:{cve_id.lower()}"
    # Dockerfile in the context dir (not dockerfile_text → skips the P14 digest
    # gate). Use alpine:latest — typically already cached, so the build doesn't
    # depend on Docker Hub reachability (the daemon may be up but the registry
    # rate-limited/flaky, esp. right after a bench).
    (tmp_path / "Dockerfile").write_text("FROM alpine:latest\nRUN true\n")

    res = docker_build(context_dir=str(tmp_path), image_tag=tag, cve_id=cve_id)
    if not res.ok:
        st = res.stderr_tail or ""
        # BuildKit loads base-image metadata from the registry even for a cached
        # image; if Docker Hub is unreachable the build can't run. That's an
        # environment outage, not a #6-chain regression — skip, don't fail.
        if any(sig in st for sig in (
            "i/o timeout", "dial tcp", "registry-1.docker.io",
            "failed to do request", "Deadline", "deadline exceeded",
        )):
            pytest.skip(f"docker registry unreachable, cannot build base: {st[:120]}")
        assert res.ok, f"build failed: reason={res.reason} stderr={st}"

    # the label actually landed on the built image
    label_val = subprocess.run(
        ["docker", "inspect", "-f", f'{{{{index .Config.Labels "{CVE_LABEL}"}}}}', tag],
        capture_output=True, text=True,
    ).stdout.strip()
    assert label_val == cve_id, f"label not on image: got {label_val!r}"

    # cleanup_result_images finds it by label and removes it
    removed = cleanup_result_images(cve_id)
    assert removed >= 1, "cleanup_result_images reported nothing removed"
    still_there = subprocess.run(
        ["docker", "images", "-q", tag], capture_output=True, text=True
    ).stdout.strip()
    assert still_there == "", "image still present after cleanup_result_images"
