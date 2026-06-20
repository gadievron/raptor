"""Tests for :mod:`cve_env.tools.docker_build`.

S23.3 (2026-05-03): added --pull-when-FROM-is-external coverage at end of
file. Cache-bypass cascade-leak fix; see cascade-test/out/cascade-bug-report.md.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_env.tools.docker_build import (
    DEPENDENCY_PACKAGE_MAP,
    classify_build_error,
    docker_build,
    reset_docker_build_state,
)


def _find_docker_build_cmd(mock_run: object) -> list[str]:
    """Among all subprocess.run calls, find the `docker build ...` invocation."""
    for call in mock_run.call_args_list:  # type: ignore[attr-defined]
        cmd = call[0][0]
        if (
            isinstance(cmd, list)
            and len(cmd) >= 3
            and cmd[0] == "docker"
            and cmd[1] == "build"
        ):
            return cmd
    raise AssertionError(
        f"no `docker build ...` call found; calls: {mock_run.call_args_list}"  # type: ignore[attr-defined]
    )


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_appends_pull_for_external_from_image(mock_run: MagicMock) -> None:
    """Dockerfile FROM debian:11 → docker build --pull (force-pull base)."""
    reset_docker_build_state()
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    dockerfile_text = "FROM debian:11\nRUN echo hi\n"
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        docker_build(
            context_dir=tmp, dockerfile_text=dockerfile_text, image_tag="cve-test:1"
        )
    cmd = _find_docker_build_cmd(mock_run)
    assert "--pull" in cmd, f"missing --pull for external FROM: {cmd}"


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_skips_pull_for_local_from_image(mock_run: MagicMock) -> None:
    """Dockerfile FROM cve-X:build → no --pull (no upstream)."""
    reset_docker_build_state()
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    dockerfile_text = "FROM cve-2015-10010-base:build\nRUN echo hi\n"
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        docker_build(
            context_dir=tmp, dockerfile_text=dockerfile_text, image_tag="cve-test:2"
        )
    cmd = _find_docker_build_cmd(mock_run)
    assert "--pull" not in cmd, f"--pull should not appear for local FROM: {cmd}"


# -- #6 (2026-05-24): label built images with cve-env.cve-id so the per-CVE
# cleanup (lifecycle.cleanup_result_images) can label-scope the rmi exactly like
# cleanup_containers, avoiding the result-image accumulation that filled the
# Colima VM and stopped bench50-20260524-121602 at 181/253.
@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_labels_image_with_cve_id(mock_run: MagicMock) -> None:
    """When cve_id is passed, `docker build` argv carries --label cve-env.cve-id=<id>."""
    reset_docker_build_state()
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        docker_build(
            context_dir=tmp,
            dockerfile_text="FROM debian:11\nRUN echo hi\n",
            image_tag="cve-env-local:CVE-2018-7600",
            cve_id="CVE-2018-7600",
        )
    cmd = _find_docker_build_cmd(mock_run)
    assert "--label" in cmd, f"missing --label: {cmd}"
    assert "cve-env.cve-id=CVE-2018-7600" in cmd, f"missing cve-id label value: {cmd}"


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_no_cve_label_when_cve_id_empty(mock_run: MagicMock) -> None:
    """No cve_id (default) → no cve-env.cve-id label (back-compat / no spurious label)."""
    reset_docker_build_state()
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        docker_build(
            context_dir=tmp,
            dockerfile_text="FROM debian:11\nRUN echo hi\n",
            image_tag="cve-test:3",
        )
    cmd = _find_docker_build_cmd(mock_run)
    assert not any("cve-env.cve-id" in str(a) for a in cmd), (
        f"unexpected cve-id label when cve_id empty: {cmd}"
    )


def test_dependency_map_is_nonempty() -> None:
    assert DEPENDENCY_PACKAGE_MAP["openssl/ssl.h"] == "libssl-dev"
    assert DEPENDENCY_PACKAGE_MAP["-lpcre"] == "libpcre3-dev"


def test_classify_build_error_matches_missing_header() -> None:
    stderr = "config.c:10:23: fatal error: openssl/ssl.h: No such file or directory\n"
    assert classify_build_error(stderr) == ["libssl-dev"]


def test_classify_build_error_matches_missing_library() -> None:
    stderr = (
        "/usr/bin/ld: cannot find -lpcre\ncollect2: error: ld returned 1 exit status\n"
    )
    assert classify_build_error(stderr) == ["libpcre3-dev"]


def test_classify_build_error_matches_autotools_not_found() -> None:
    stderr = "checking for OpenSSL... not found\nconfigure: error: no usable OpenSSL\n"
    assert classify_build_error(stderr) == ["libssl-dev"]


def test_classify_build_error_deduplicates_order_preserved() -> None:
    stderr = (
        "fatal error: openssl/ssl.h: No such file or directory\n"
        "cannot find -lssl\n"
        "fatal error: pcre.h: No such file\n"
    )
    assert classify_build_error(stderr) == ["libssl-dev", "libpcre3-dev"]


def test_classify_build_error_falls_through_on_unknown() -> None:
    stderr = "something completely unrelated\n"
    assert classify_build_error(stderr) == []


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_autocreates_missing_context(
    mock_run: MagicMock, tmp_path: object
) -> None:
    """R1 (2026-05-23): a missing context dir is auto-created (mkdir -p) and
    the build proceeds, instead of erroring bad_context. Forensic: the agent
    often calls docker_build before mkdir-ing the context (CVE-2022-44542
    build t20 / mkdir t22). FROM+RUN Dockerfiles need no COPY context."""
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Successfully built abc123\n", stderr=""
    )
    newctx = Path(str(tmp_path)) / "ctx-not-yet-created"
    assert not newctx.exists()
    r = docker_build(context_dir=str(newctx), image_tag="cve-env-local:r1")
    assert r.reason != "bad_context", (
        "missing context must be auto-created, not rejected"
    )
    assert newctx.is_dir(), "docker_build must mkdir -p the missing context"


def test_docker_build_rejects_file_as_context(tmp_path: object) -> None:
    """R1: a context_dir that exists but is a FILE (not a dir) is still rejected
    — auto-create only applies to genuinely-missing paths."""
    f = Path(str(tmp_path)) / "afile"
    f.write_text("x")
    r = docker_build(context_dir=str(f))
    assert r.ok is False
    assert r.reason == "bad_context"


def test_docker_build_rejects_empty_context() -> None:
    """R1: an empty context_dir is rejected (must not silently build in cwd)."""
    r = docker_build(context_dir="")
    assert r.ok is False
    assert r.reason == "bad_context"


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_success(mock_run: MagicMock, tmp_path: object) -> None:
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Successfully built abc123\n", stderr=""
    )
    r = docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:test")
    assert r.ok is True
    assert r.image_tag == "cve-env-local:test"
    assert r.exit_code == 0


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_default_tag_embeds_cve_id(
    mock_run: MagicMock, tmp_path: object
) -> None:
    """When image_tag is omitted but cve_id is set, the auto-generated default tag
    embeds the cve_id (``cve-env-local:<cve_id>-<uuid>``) so that a SIGKILL'd build's
    orphan image — which may miss the cve-env.cve-id LABEL — is still reclaimable by
    a cve-id-scoped TAG sweep on the kill path. Regression-locks the wall-kill leak
    (bench50-20260609: cve-env-local:CVE-2022-4547 survived, unlabeled)."""
    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Successfully built abc\n", stderr=""
    )
    r = docker_build(context_dir=str(tmp_path), cve_id="CVE-2022-4547")
    assert r.image_tag.startswith("cve-env-local:CVE-2022-4547"), (
        f"default tag must embed cve_id for kill-path tag-sweep, got: {r.image_tag}"
    )


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_default_tag_uuid_when_no_cve_id(
    mock_run: MagicMock, tmp_path: object
) -> None:
    """No cve_id → fall back to the uuid-only default tag (back-compat)."""
    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Successfully built abc\n", stderr=""
    )
    r = docker_build(context_dir=str(tmp_path))
    assert r.image_tag.startswith("cve-env-local:"), (
        f"unexpected default tag: {r.image_tag}"
    )
    assert "CVE-" not in r.image_tag, f"no cve_id → no CVE in tag: {r.image_tag}"


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_returns_suggested_patch_on_missing_dep(
    mock_run: MagicMock, tmp_path: object
) -> None:
    stderr = "fatal error: openssl/ssl.h: No such file or directory\n"
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=stderr)
    r = docker_build(context_dir=str(tmp_path))
    assert r.ok is False
    assert r.reason == "missing_dependency"
    assert r.suggested_patch == {"apt_packages": ["libssl-dev"]}


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_no_hint_on_generic_failure(
    mock_run: MagicMock, tmp_path: object
) -> None:
    mock_run.return_value = MagicMock(
        returncode=1, stdout="", stderr="unrelated failure\n"
    )
    r = docker_build(context_dir=str(tmp_path))
    assert r.ok is False
    assert r.reason == "build_failed"
    assert r.suggested_patch is None


@patch("cve_env.utils.run.subprocess.run")
def test_docker_build_writes_dockerfile_text_tempfile(
    mock_run: MagicMock, tmp_path: object
) -> None:
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Successfully built\n", stderr=""
    )
    r = docker_build(
        context_dir=str(tmp_path),
        dockerfile_text="FROM scratch\n",
        image_tag="tmp:1",
    )
    assert r.ok is True
    # The subprocess call should include -f <tmpfile>
    call_args = mock_run.call_args
    cmd = call_args.args[0] if call_args.args else call_args.kwargs.get("args", [])
    assert "-f" in cmd
    # And the tempfile should be cleaned up after the build.
    from pathlib import Path

    f_idx = cmd.index("-f")
    tmpfile = Path(cmd[f_idx + 1])
    assert not tmpfile.exists(), "tempfile should be cleaned up on return"


# Phase 9.5: docker_build next_step_hint --------------------------------


def test_docker_build_next_step_hint_for_apt_packages_suggested() -> None:
    from cve_env.tools.docker_build import _docker_build_next_step_hint

    h = _docker_build_next_step_hint(
        reason="missing_dependency",
        reason_class="unknown",
        suggested_patch={"apt_packages": ["libssl-dev", "libpcre3-dev"]},
        stderr="",
    )
    assert "libssl-dev" in h
    assert "dockerfile_gen" in h


def test_docker_build_next_step_hint_for_disk_full() -> None:
    from cve_env.tools.docker_build import _docker_build_next_step_hint

    h = _docker_build_next_step_hint("build_failed", "disk_full", None, "")
    assert "disk" in h.lower()


def test_docker_build_next_step_hint_for_manifest_unknown_base_image() -> None:
    from cve_env.tools.docker_build import _docker_build_next_step_hint

    h = _docker_build_next_step_hint("build_failed", "manifest_unknown", None, "")
    assert "FROM" in h or "base" in h.lower()


def test_docker_build_next_step_hint_for_timeout() -> None:
    from cve_env.tools.docker_build import _docker_build_next_step_hint

    h = _docker_build_next_step_hint("timeout", "transport", None, "")
    assert "timeout" in h.lower() or "slow" in h.lower()


def test_docker_build_next_step_hint_for_copy_missing_path() -> None:
    from cve_env.tools.docker_build import _docker_build_next_step_hint

    h = _docker_build_next_step_hint(
        "build_failed",
        "unknown",
        None,
        "COPY plugin/ /app/: no such file or directory",
    )
    assert "COPY" in h or "copy_ops" in h


def test_docker_build_failure_result_includes_next_step_hint() -> None:
    """Phase 9.5: BuildResult.next_step_hint defaults to empty on success and
    is populated on failure (verified via the bad_context branch which doesn't
    invoke subprocess and so is hermetic).
    """
    from cve_env.tools.docker_build import docker_build

    result = docker_build(context_dir="/nonexistent/path/for/test")
    assert result.ok is False
    assert result.reason == "bad_context"
    assert result.next_step_hint != ""
    assert "context_dir" in result.next_step_hint or "absolute" in result.next_step_hint


# Phase 37.3: build-loop closure guard tests --------------------------------


@patch("cve_env.utils.run.subprocess.run")
def test_phase37_3_first_build_with_suggested_patch_records_state(
    mock_run: MagicMock,
    tmp_path: object,
) -> None:
    """Phase 37.3: when docker_build fails with a suggested_patch (apt deps
    detected from stderr), the (image_tag → patch) pairing is recorded for
    the next docker_build call to enforce.
    """
    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="config.c:10:23: fatal error: openssl/ssl.h: No such file\n",
    )
    r = docker_build(
        context_dir=str(tmp_path),
        image_tag="cve-env-local:test",
    )
    assert r.ok is False
    assert r.suggested_patch == {"apt_packages": ["libssl-dev"]}
    assert r.blocked is False  # first call isn't blocked
    # State recorded — proven by the next test.


@patch("cve_env.utils.run.subprocess.run")
def test_phase37_3_second_build_same_tag_is_blocked(
    mock_run: MagicMock,
    tmp_path: object,
) -> None:
    """Phase 37.3: second docker_build with the SAME image_tag, after the
    first returned a suggested_patch, is BLOCKED. Agent should call
    dockerfile_gen with the suggested apt_packages first.
    """
    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="config.c:10:23: fatal error: openssl/ssl.h: No such file\n",
    )
    # First call burns the patch.
    docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:test")
    mock_run.reset_mock()
    # Second call with same tag should short-circuit.
    r = docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:test")
    assert r.ok is False
    assert r.blocked is True
    assert r.reason == "blocked_by_build_loop_guard"
    assert r.suggested_patch == {"apt_packages": ["libssl-dev"]}
    assert "Phase 37.3" in r.next_step_hint
    assert "dockerfile_gen" in r.next_step_hint
    # Subprocess NOT called — short-circuited.
    mock_run.assert_not_called()


@patch("cve_env.utils.run.subprocess.run")
def test_phase37_3_different_tag_not_blocked(
    mock_run: MagicMock,
    tmp_path: object,
) -> None:
    """Phase 37.3: a new image_tag (e.g., a fresh dockerfile_gen render)
    is NOT blocked even if a previous tag had a pending suggested_patch.
    """
    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="config.c:10:23: fatal error: openssl/ssl.h: No such file\n",
    )
    docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:old")
    mock_run.reset_mock()
    r = docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:new")
    # New tag → not blocked, subprocess invoked.
    assert r.blocked is False
    mock_run.assert_called()


def test_phase37_3_reset_clears_state() -> None:
    """Phase 37.3: reset_docker_build_state() clears the pending-patch
    map (called per-CVE by the agent loop)."""
    from cve_env.tools import docker_build as db

    reset_docker_build_state()
    db._PENDING_SUGGESTED_PATCH["cve-env-local:test"] = {"apt_packages": ["x"]}
    assert "cve-env-local:test" in db._PENDING_SUGGESTED_PATCH
    reset_docker_build_state()
    assert db._PENDING_SUGGESTED_PATCH == {}


# Phase 38.2: gpg_signature recovery guard tests ---------------------------


@patch("cve_env.utils.run.subprocess.run")
def test_phase38_2_gpg_signature_records_tag_for_recovery_guard(
    mock_run: MagicMock,
    tmp_path: object,
) -> None:
    """Phase 38.2: when docker_build fails with reason_class=gpg_signature
    (stale apt keyring on Debian bullseye), the image_tag is recorded so
    the next docker_build call against the same tag is blocked.
    """
    from cve_env.tools import docker_build as db

    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr=(
            "W: GPG error: http://deb.debian.org/debian bullseye InRelease: "
            "At least one invalid signature was encountered.\n"
        ),
    )
    r = docker_build(
        context_dir=str(tmp_path),
        image_tag="cve-env-local:gpgtest",
    )
    assert r.ok is False
    assert r.reason_class == "gpg_signature"
    assert r.blocked is False  # first call isn't blocked
    assert "cve-env-local:gpgtest" in db._PENDING_GPG_RECOVERY


@patch("cve_env.utils.run.subprocess.run")
def test_phase38_2_second_build_after_gpg_signature_is_blocked(
    mock_run: MagicMock,
    tmp_path: object,
) -> None:
    """Phase 38.2: second docker_build with same image_tag, after the
    first returned reason_class=gpg_signature, is BLOCKED. Agent must
    call dockerfile_gen with apt_unsafe=True or pivot the base image.
    """
    reset_docker_build_state()
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr=(
            "W: GPG error: invalid signature was encountered\n"
            "E: The repository is not signed.\n"
        ),
    )
    # First call records the failure.
    docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:gpgtest")
    mock_run.reset_mock()
    # Second call with same tag short-circuits.
    r = docker_build(context_dir=str(tmp_path), image_tag="cve-env-local:gpgtest")
    assert r.ok is False
    assert r.blocked is True
    assert r.reason == "blocked_by_gpg_recovery_guard"
    assert r.reason_class == "gpg_signature"
    assert "Phase 38.2" in r.next_step_hint
    assert "apt_unsafe" in r.next_step_hint
    # Subprocess NOT called — short-circuited.
    mock_run.assert_not_called()


def test_phase38_2_reset_clears_gpg_recovery_state() -> None:
    """Phase 38.2: reset_docker_build_state() also clears the gpg_recovery
    set (called per-CVE by the agent loop).
    """
    from cve_env.tools import docker_build as db

    reset_docker_build_state()
    db._PENDING_GPG_RECOVERY.add("cve-env-local:dirty")
    assert "cve-env-local:dirty" in db._PENDING_GPG_RECOVERY
    reset_docker_build_state()
    assert not db._PENDING_GPG_RECOVERY


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Phase 67 audit issue #10 (severity 8): docker_build accepts raw
# ``dockerfile_text`` and writes it to disk WITHOUT running validators
# (validate_image_ref P14 / validate_dockerfile_semantics P14/P17). An
# agent that constructs a Dockerfile with ``FROM nginx:latest`` (no digest)
# bypasses the policy that the structured ``dockerfile_gen`` tool enforces.
# Phase 67.2 will run the same validators on raw text before invoking
# subprocess.run.


@patch("cve_env.utils.run.subprocess.run")
def test_phase67_docker_build_revalidates_raw_text_against_p14(
    mock_run: MagicMock, tmp_path: object
) -> None:
    """Phase 67.2 contract: raw ``dockerfile_text`` containing a forbidden
    tag (``:latest``, no digest pin) must be rejected BEFORE invoking docker.

    Today subprocess.run is invoked unconditionally; a successful exit
    yields ok=True. Forensic risk: an agent bypasses dockerfile_gen's
    validation by constructing the raw text directly and feeding it here.
    """
    # Mock subprocess to return success — if the validator runs, we still
    # get ok=False (validator rejects); if it doesn't, ok=True (current bug).
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Successfully built abc123\n", stderr=""
    )
    raw_dockerfile = "FROM nginx:latest\nRUN apt-get install -y curl\n"
    r = docker_build(
        context_dir=str(tmp_path),
        image_tag="cve-env-local:test67",
        dockerfile_text=raw_dockerfile,
    )
    assert r.ok is False, (
        "docker_build must reject raw dockerfile_text containing forbidden "
        ":latest tag (P14 invariant) BEFORE running subprocess"
    )
    # The reason should mention P14 or validation so the agent knows what
    # invariant was violated.
    assert "P14" in r.reason or "validation" in r.reason.lower(), (
        f"reason should cite P14/validation; got reason={r.reason!r}"
    )
