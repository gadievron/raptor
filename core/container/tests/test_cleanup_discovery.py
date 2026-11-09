"""Cleanup acts only on complete discovery, with unchanged removal accounting."""

import pytest

from core.container import lifecycle
from core.container.proc import RunOutcome


def outcome(stdout="", *, code=0, truncated=False):
    return RunOutcome(code, stdout, "", False, truncated=truncated)


def invoke(kind):
    if kind == "containers":
        return lifecycle.remove_labeled_containers("owned", "value", timeout=7)
    if kind == "networks":
        return lifecycle.remove_labeled_networks("owned", "value", timeout=7)
    return lifecycle.remove_labeled_images(
        "owned", "value", timeout=7,
        **({"tag_repo": "repo", "tag_value": "value"} if kind == "fallback" else {}),
    )


@pytest.mark.parametrize("kind", ["containers", "networks", "images", "fallback"])
@pytest.mark.parametrize("failure", ["truncated", "nonzero"])
def test_incomplete_discovery_cannot_drive_removal(monkeypatch, caplog, kind, failure):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["timeout"] == 7
        return outcome("repo:value\nrepo:value-two\n", code=1 if failure == "nonzero" else 0,
                       truncated=failure == "truncated")

    monkeypatch.setattr(lifecycle, "run_cli", run)
    assert invoke(kind) == 0
    assert len(calls) == (2 if kind == "fallback" else 1)
    assert all("--filter" in call or call[:3] == ["docker", "images", "repo"] for call in calls)
    if failure == "truncated":
        assert "truncated" in caplog.text


@pytest.mark.parametrize("label_truncated", [False, True])
@pytest.mark.parametrize("tag_truncated", [False, True])
def test_independent_complete_image_query_still_drives_cleanup(
    monkeypatch, label_truncated, tag_truncated,
):
    removals = []

    def run(argv, **kwargs):
        if "--filter" in argv:
            return outcome("repo:label-owned\n", truncated=label_truncated)
        if argv[:2] == ["docker", "images"]:
            return outcome("repo:value\nrepo:value-two\nrepo:value-neighbourly\nrepo:other\n",
                           truncated=tag_truncated)
        removals.append(argv)
        return outcome()

    monkeypatch.setattr(lifecycle, "run_cli", run)
    expected = ([] if label_truncated else ["repo:label-owned"]) + (
        [] if tag_truncated else ["repo:value", "repo:value-two", "repo:value-neighbourly"]
    )
    assert invoke("fallback") == len(expected)
    assert removals == ([["docker", "rmi", *expected]] if expected else [])


@pytest.mark.parametrize("kind", ["containers", "networks"])
@pytest.mark.parametrize("removal_code", [0, 1])
def test_duplicate_discovery_counts_each_removed_object_once(monkeypatch, kind, removal_code):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            return outcome("first\nfirst\nsecond\n")
        return outcome("first\n", code=removal_code)

    monkeypatch.setattr(lifecycle, "run_cli", run)
    assert invoke(kind) == (2 if removal_code == 0 else 1)
    assert calls[-1][-2:] == ["first", "second"]
    assert calls[-1].count("first") == 1


@pytest.mark.parametrize("kind", ["containers", "networks", "images"])
def test_successful_removal_keeps_count_when_only_its_output_is_truncated(monkeypatch, kind):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            return outcome("repo:first\nrepo:second\n")
        return outcome("partial output", truncated=True)

    monkeypatch.setattr(lifecycle, "run_cli", run)
    assert invoke(kind) == 2
    assert len(calls) == 2
