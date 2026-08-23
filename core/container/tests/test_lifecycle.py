"""Contract tests for core.container.lifecycle — label-scoped cleanup."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from core.container import lifecycle as lc
from core.container.proc import RunOutcome


def _fake(captured: list[list[str]], stdout: str = ""):
    def run(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        return RunOutcome(returncode=0, stdout=stdout, stderr="",
                          timed_out=False)
    return run


def test_remove_containers_filters_by_label_and_rms() -> None:
    captured: list[list[str]] = []
    with patch.object(lc, "run_cli", side_effect=_fake(captured,
                                                       "a1\nb2\n")):
        n = lc.remove_labeled_containers("k", "v")
    assert n == 2
    assert "--filter" in captured[0] and "label=k=v" in captured[0]
    assert captured[1] == ["docker", "rm", "-f", "a1", "b2"]


def test_remove_containers_empty_value_is_noop() -> None:
    captured: list[list[str]] = []
    with patch.object(lc, "run_cli", side_effect=_fake(captured)):
        assert lc.remove_labeled_containers("k", "") == 0
    assert captured == []


def test_remove_images_dedupes_and_skips_none_rows() -> None:
    captured: list[list[str]] = []
    with patch.object(lc, "run_cli", side_effect=_fake(
            captured, "repo:CVE-1\n<none>:<none>\nrepo:CVE-1\n")):
        n = lc.remove_labeled_images("k", "CVE-1", tag_repo="repo",
                                     tag_value="CVE-1")
    assert n == 1
    rmi = [c for c in captured if c[:2] == ["docker", "rmi"]]
    assert rmi == [["docker", "rmi", "repo:CVE-1"]]


def test_remove_images_tag_sweep_scoped_to_value() -> None:
    """The kill-path tag sweep keeps CVE-1 and CVE-1-v2 tags but never a
    concurrent neighbour's CVE-10 (prefix must be value or value + '-')."""
    def run(cmd: list[str], **_kw: Any) -> RunOutcome:
        if "--filter" in cmd:
            return RunOutcome(returncode=0, stdout="", stderr="",
                              timed_out=False)
        if cmd[:2] == ["docker", "images"]:
            return RunOutcome(
                returncode=0,
                stdout="repo:CVE-1\nrepo:CVE-1-v2\nrepo:CVE-10\n",
                stderr="", timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    with patch.object(lc, "run_cli", side_effect=run):
        n = lc.remove_labeled_images("k", "CVE-1", tag_repo="repo",
                                     tag_value="CVE-1")
    assert n == 2


def test_prune_targets_dangling_only() -> None:
    captured: list[list[str]] = []
    with patch.object(lc, "run_cli", side_effect=_fake(captured)):
        lc.prune_dangling_images()
    assert captured == [["docker", "image", "prune", "-f"]]


def test_remove_labeled_networks_scopes_by_label() -> None:
    captured: list[list[str]] = []

    def run(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        if cmd[:4] == ["docker", "network", "ls", "-q"]:
            return RunOutcome(returncode=0, stdout="n1\nn2\n", stderr="",
                              timed_out=False)
        return RunOutcome(returncode=0, stdout="", stderr="",
                          timed_out=False)

    with patch.object(lc, "run_cli", side_effect=run):
        n = lc.remove_labeled_networks("raptor-env.id", "abc123")
    assert n == 2
    assert captured[0] == ["docker", "network", "ls", "-q",
                           "--filter", "label=raptor-env.id=abc123"]
    assert captured[1] == ["docker", "network", "rm", "n1", "n2"]
    assert lc.remove_labeled_networks("raptor-env.id", "") == 0
