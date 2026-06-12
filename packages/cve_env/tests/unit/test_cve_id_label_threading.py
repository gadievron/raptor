"""#6 (2026-05-24): the `set_cve_id_context` → docker_build-wrapper threading
that labels built images `cve-env.cve-id=<id>` (so `lifecycle.cleanup_result_images`
can remove THIS CVE's result images — the fix for the disk-floor stop in
bench50-20260524-121602).

Closes a work-audit F-gap: the threading was verified end-to-end on a real
image but had NO unit test, so a future refactor could silently drop the
`cve_id=_CURRENT_CVE_ID` kwarg from either docker_build call site without any
test going red. Both call sites are covered here:
  - the async `docker_build` agent tool wrapper (tools.py)
  - the sync `_maybe_fuse_build` render→build fuse (tools.py)

Teeth: each asserts the EXACT cve_id kwarg the wiring sets; removing
`cve_id=_CURRENT_CVE_ID` from either wrapper turns the matching test red
(verified by mutation at authoring time).
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

from cve_env.agent import tools
from cve_env.tools.docker_build import BuildResult


def _fake_build_result() -> BuildResult:
    # Real BuildResult → JSON-serializable (the async wrapper serializes its return).
    return BuildResult(ok=True, image_tag="cve-env-local:t")


def test_cve_label_single_source_of_truth() -> None:
    """GAP-3 (2026-05-24): the ``cve-env.cve-id`` label is defined ONCE in
    config and shared by every writer (docker_build / docker_run /
    docker_compose_up) and reader (lifecycle filters). Guards against a rename
    desyncing a writer from the cleanup reader — which would silently break
    per-CVE container/image cleanup (the #6 disk fix)."""
    import pathlib
    import subprocess

    from cve_env import config
    from cve_env.tools import docker_build, docker_run

    assert config.CVE_LABEL == "cve-env.cve-id"
    # writers re-export the SAME object (identity), not a parallel literal
    assert docker_build.CVE_LABEL is config.CVE_LABEL
    assert docker_run.CVE_LABEL is config.CVE_LABEL
    # exactly one functional literal of the label survives in src/cve_env
    src = pathlib.Path(config.__file__).parent
    hits = subprocess.run(
        ["grep", "-rn", '"cve-env.cve-id"', str(src), "--include=*.py"],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()
    assert len(hits) == 1, f"stray label literal(s): {hits}"
    assert "config.py" in hits[0], f"label literal not in config.py: {hits}"


def test_set_cve_id_context_sets_and_clears_global() -> None:
    """The setter stores the id; empty/None clears it (no spurious label)."""
    tools.set_cve_id_context("CVE-2018-7600")
    assert tools._CURRENT_CVE_ID == "CVE-2018-7600"
    tools.set_cve_id_context("")
    assert tools._CURRENT_CVE_ID == ""


def test_async_docker_build_wrapper_threads_cve_id() -> None:
    """The async docker_build tool wrapper passes _CURRENT_CVE_ID → docker_build.cve_id."""
    tools.set_cve_id_context("CVE-2018-7600")
    try:
        with patch.object(
            tools._docker_build, "docker_build", return_value=_fake_build_result(),
        ) as m:
            # tools.docker_build is an SdkMcpTool; the coroutine is .handler
            asyncio.run(
                tools.docker_build.handler(
                    {"context_dir": "/tmp/x", "image_tag": "cve-env-local:t"}
                )
            )
        assert m.call_args.kwargs.get("cve_id") == "CVE-2018-7600", (
            f"async wrapper did not thread cve_id: {m.call_args}"
        )
    finally:
        tools.set_cve_id_context("")


def test_fuse_build_wrapper_threads_cve_id() -> None:
    """The render→build fuse (_maybe_fuse_build) also threads _CURRENT_CVE_ID."""
    tools.set_cve_id_context("CVE-2021-44228")
    try:
        with patch.object(
            tools._docker_build, "docker_build", return_value=_fake_build_result(),
        ) as m:
            # ok render + no copy_ops → auto-build fires (the b1 fuse default)
            tools._maybe_fuse_build(
                {"ok": True, "dockerfile_text": "FROM alpine\nRUN true\n"}, {},
            )
        assert m.called, "fuse did not call docker_build"
        assert m.call_args.kwargs.get("cve_id") == "CVE-2021-44228", (
            f"fuse wrapper did not thread cve_id: {m.call_args}"
        )
    finally:
        tools.set_cve_id_context("")
