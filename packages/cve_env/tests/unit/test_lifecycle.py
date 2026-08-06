"""Phase 4 (2026-05-11): unit tests for opt-in lifecycle helpers.

Coverage:
  - acquire_lock + release_lock round-trip
  - count_other_active_builds: empty / with-others-alive / with-stale-cleaned
  - cleanup_containers: empty cve_id no-ops; non-empty filters by cve-id label
    (Phase 20A.1: changed from run-id; see lifecycle.cleanup_containers docstring)
  - prune_images: calls docker image prune -f
  - stop_colima_if_idle: fires when count_other==0; skipped when count_other>0

No real docker / colima / signals are invoked — every external call is
monkeypatched.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cve_env.utils import lifecycle as lf
from cve_env.utils.run import RunOutcome


def _mock_run_factory(
    captured: list[list[str]],
    stdout: str = "",
    returncode: int = 0,
):
    """Return a fake run_with_timeout that records calls and returns canned outcome."""

    def _fake(cmd, **_kwargs):
        captured.append(list(cmd))
        return RunOutcome(
            returncode=returncode,
            stdout=stdout,
            stderr="",
            timed_out=False,
        )

    return _fake


# ─── lock round-trip ─────────────────────────────────────────────────


def test_acquire_release_lock_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """acquire_lock creates a file with own PID; release_lock removes it."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    path = lf.acquire_lock()
    assert path.exists()
    assert path.read_text() == str(os.getpid())
    assert path.parent == tmp_path
    lf.release_lock(path)
    assert not path.exists()


# ─── count_other_active_builds ───────────────────────────────────────


def test_count_other_active_builds_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No lock files → count is 0."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    assert lf.count_other_active_builds() == 0


def test_count_other_active_builds_excludes_own(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Own PID lock present → not counted."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    own_lock = lf.acquire_lock()
    assert lf.count_other_active_builds() == 0
    lf.release_lock(own_lock)


def test_count_other_active_builds_stale_lock_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lock pointing at a dead PID is removed and not counted."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    # PID 1 is init on Unix — but use a deliberately unreachable PID instead
    # to avoid platform assumptions about kill(init, 0) permissions.
    dead_pid = 99999999  # well above any real PID
    stale = tmp_path / f"{lf.LOCK_PREFIX}{dead_pid}{lf.LOCK_SUFFIX}"
    stale.write_text(str(dead_pid))
    assert stale.exists()
    assert lf.count_other_active_builds() == 0
    assert not stale.exists(), "stale lock should have been removed by the count sweep"


def test_count_other_active_builds_with_alive_other(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lock pointing at an alive PID (parent always alive in test) is counted."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    parent_pid = os.getppid()
    if parent_pid == os.getpid():
        pytest.skip("parent pid equals own pid (shouldn't happen)")
    other = tmp_path / f"{lf.LOCK_PREFIX}{parent_pid}{lf.LOCK_SUFFIX}"
    other.write_text(str(parent_pid))
    assert lf.count_other_active_builds() == 1
    # Lock should still exist (alive PID, not stale).
    assert other.exists()


# ─── cleanup_containers ──────────────────────────────────────────────


def test_cleanup_containers_empty_cve_id_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty cve_id → no subprocess fires."""
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured))
    removed = lf.cleanup_containers("")
    assert removed == 0
    assert captured == []


def test_cleanup_containers_no_match_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """cve_id given but `docker ps` returns no IDs → no rm call."""
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured, stdout=""))
    removed = lf.cleanup_containers("CVE-2014-0160")
    assert removed == 0
    # Only the docker ps call fired, not docker rm.
    assert len(captured) == 1
    assert captured[0][:3] == ["docker", "ps", "-aq"]
    assert any("cve-env.cve-id=CVE-2014-0160" in arg for arg in captured[0])


def test_cleanup_containers_removes_matching_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two matching containers → docker rm -f called with both IDs."""
    captured: list[list[str]] = []
    monkeypatch.setattr(
        lf,
        "run_with_timeout",
        _mock_run_factory(captured, stdout="abc123\ndef456\n"),
    )
    removed = lf.cleanup_containers("CVE-2014-0160")
    assert removed == 2
    # Two calls: docker ps, then docker rm -f abc123 def456
    assert len(captured) == 2
    assert captured[1][:3] == ["docker", "rm", "-f"]
    assert "abc123" in captured[1]
    assert "def456" in captured[1]


def test_cleanup_containers_filters_by_cve_id_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 20A.1 regression: filter argument must be cve-env.cve-id, not run-id.

    Pre-Phase-20A the filter was ``cve-env.run-id={cli_run_id}`` but the agent
    labeled containers with its own run_id choice — filter never matched.
    """
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured, stdout=""))
    lf.cleanup_containers("CVE-2024-12345")
    assert captured, "docker ps must have been invoked"
    ps_args = captured[0]
    assert any("cve-env.cve-id=CVE-2024-12345" in arg for arg in ps_args), (
        f"filter must use cve-env.cve-id, got: {ps_args}"
    )
    # Must NOT use the old run-id filter.
    assert not any("cve-env.run-id=" in arg for arg in ps_args), (
        f"filter must NOT use cve-env.run-id (Phase 20A.1 fix); got: {ps_args}"
    )


# ─── prune_images ────────────────────────────────────────────────────


def test_prune_images_calls_docker_image_prune(monkeypatch: pytest.MonkeyPatch) -> None:
    """prune_images runs `docker image prune -f` exactly once."""
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured))
    lf.prune_images()
    assert captured == [["docker", "image", "prune", "-f"]]


# ─── stop_colima_if_idle ─────────────────────────────────────────────


def test_stop_colima_if_idle_fires_when_idle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty lock dir → colima stop fires, returns True."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured))
    assert lf.stop_colima_if_idle() is True
    assert captured == [["colima", "stop"]]


def test_stop_colima_if_idle_skipped_when_busy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Other active build present → no colima stop, returns False."""
    monkeypatch.setattr(lf, "LOCK_DIR", tmp_path)
    parent_pid = os.getppid()
    other = tmp_path / f"{lf.LOCK_PREFIX}{parent_pid}{lf.LOCK_SUFFIX}"
    other.write_text(str(parent_pid))
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured))
    assert lf.stop_colima_if_idle() is False
    assert captured == []


# ─── cleanup_result_images (#6, 2026-05-24) ──────────────────────────
# Mirrors cleanup_containers but for IMAGES: removes THIS CVE's tagged result
# images by label (docker_build now labels them cve-env.cve-id=<id>), fixing the
# tagged-image accumulation that filled the Colima VM and stopped
# bench50-20260524-121602 at 181/253. Removes by TAG (not -f by ID) so multi-tag
# images delete cleanly as their last tag goes.


def test_cleanup_result_images_rmi_by_label_tags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lists this CVE's images by label, then `docker rmi` each tag."""
    captured: list[list[str]] = []
    monkeypatch.setattr(
        lf,
        "run_with_timeout",
        _mock_run_factory(
            captured,
            stdout="cve-env-local:CVE-2018-7600\ncve-env-local:CVE-2018-7600-v2\n",
        ),
    )
    n = lf.cleanup_result_images("CVE-2018-7600")
    assert n == 2
    assert captured[0] == [
        "docker",
        "images",
        "--filter",
        "label=cve-env.cve-id=CVE-2018-7600",
        "--format",
        "{{.Repository}}:{{.Tag}}",
    ], f"images query not label-scoped: {captured[0]}"
    # 2026-06-09: a second cve-id TAG sweep now runs (kill-path orphan fallback).
    assert captured[1] == [
        "docker",
        "images",
        "cve-env-local",
        "--format",
        "{{.Repository}}:{{.Tag}}",
    ], f"cve-id tag sweep query missing/wrong: {captured[1]}"
    # both queries return the same two (label) tags here; deduped before rmi.
    assert captured[2] == [
        "docker",
        "rmi",
        "cve-env-local:CVE-2018-7600",
        "cve-env-local:CVE-2018-7600-v2",
    ], f"rmi not by tag: {captured[2]}"


def test_cleanup_result_images_sweeps_unlabeled_cve_id_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kill-path leak fix (2026-06-09): a SIGKILL'd build can leave a tagged
    ``cve-env-local:<cve_id>`` image WITHOUT the ``cve-env.cve-id`` label (cli.py's
    in-process finally is bypassed). The label query returns nothing, but the cve-id
    TAG sweep still finds + rmi's it — and leaves a *different* concurrent CVE's image
    untouched. Regression-locks bench50-20260609's surviving
    ``cve-env-local:CVE-2022-4547`` (empty label, 811 MB)."""
    captured: list[list[str]] = []
    # query 1 (label) → empty; query 2 (tag list) → the unlabeled orphan + an
    # unrelated concurrent CVE's image (must NOT be swept).
    responses = ["", "cve-env-local:CVE-2022-4547\ncve-env-local:CVE-2018-7600-v2\n"]

    def _fake(cmd: list[str], **_k: object) -> RunOutcome:
        captured.append(list(cmd))
        if cmd[:2] == ["docker", "images"]:
            idx = sum(1 for c in captured if c[:2] == ["docker", "images"]) - 1
            out = responses[idx] if idx < len(responses) else ""
        else:
            out = ""
        return RunOutcome(returncode=0, stdout=out, stderr="", timed_out=False)

    monkeypatch.setattr(lf, "run_with_timeout", _fake)
    n = lf.cleanup_result_images("CVE-2022-4547")
    assert n == 1, (
        f"must sweep ONLY the cve-id-tagged orphan, not the other CVE: {captured}"
    )
    rmi = [c for c in captured if c[:2] == ["docker", "rmi"]]
    assert rmi and rmi[0] == ["docker", "rmi", "cve-env-local:CVE-2022-4547"], (
        f"rmi must target exactly the cve-id orphan: {rmi}"
    )


def test_cleanup_result_images_empty_cve_id_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty cve_id is a no-op (no docker calls, returns 0)."""
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured))
    assert lf.cleanup_result_images("") == 0
    assert captured == []


def test_cleanup_result_images_skips_none_and_dedupes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`<none>:<none>` rows are skipped and duplicate tags deduped before rmi."""
    captured: list[list[str]] = []
    monkeypatch.setattr(
        lf,
        "run_with_timeout",
        _mock_run_factory(
            captured,
            stdout="cve-env-local:CVE-1\n<none>:<none>\ncve-env-local:CVE-1\n",
        ),
    )
    n = lf.cleanup_result_images("CVE-1")
    assert n == 1, "should skip <none> and dedupe to one tag (across label + tag sweep)"
    rmi = [c for c in captured if c[:2] == ["docker", "rmi"]]
    assert rmi and rmi[0] == ["docker", "rmi", "cve-env-local:CVE-1"], f"rmi: {rmi}"


def test_cleanup_result_images_no_match_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """No matching images → only the list query, no rmi."""
    captured: list[list[str]] = []
    monkeypatch.setattr(lf, "run_with_timeout", _mock_run_factory(captured, stdout=""))
    assert lf.cleanup_result_images("CVE-9999-0000") == 0
    # two list queries now (label + cve-id tag sweep), no rmi.
    assert len(captured) == 2 and all(c[:2] == ["docker", "images"] for c in captured)
