"""The shared launcher case owns its scratch state and borrowed class binding."""
from __future__ import annotations

import subprocess

import pytest

import core.project.tests.test_sessions as owner


def _probe(calls, outcome="normal"):
    # Keep the subclass local: pytest discovers imported unittest classes
    # regardless of their names, which would duplicate the real launcher cases.
    class Probe(owner.LauncherSeedV2Test):
        __test__ = False

        def _launch(self, home, tmpdir):
            calls.append((home, tmpdir))
            assert home.is_dir() and tmpdir.is_dir()
            if outcome.startswith("launch-"):
                error = KeyboardInterrupt if outcome.endswith("interrupt") else RuntimeError
                raise error("launcher fixture probe")
            return subprocess.CompletedProcess(["fixture"], 0, "STUB_CLAUDE_RAN\n", "")

    return Probe


@pytest.mark.parametrize("borrowed", ["missing", "none", "object"])
@pytest.mark.parametrize("outcome", ["normal", "body-error", "body-interrupt",
                                     "launch-error", "launch-interrupt"])
def test_shared_case_cleanup_and_binding_restore(monkeypatch, borrowed, outcome):
    calls = []
    probe = _probe(calls, outcome)
    missing = object()
    if borrowed != "missing":
        monkeypatch.setattr(probe, "_projectless_cases", None if borrowed == "none" else object())
    before = probe.__dict__.get("_projectless_cases", missing)
    case = probe("test_empty_bookmark_seeds_projectless_sentinel")
    sibling = probe("test_startup_check_sentinel_never_reaches_terminal_stdout")
    caught = None
    try:
        probe.setUpClass()
        assert calls == [], "class setup started an unrequested launcher"
        first = case._projectless_launch()
        assert sibling._projectless_launch() is first
        assert len(calls) == 1
        if outcome.startswith("body-"):
            error = KeyboardInterrupt if outcome.endswith("interrupt") else RuntimeError
            raise error("launcher fixture probe")
    except BaseException as error:
        caught = error
    finally:
        case.doCleanups()
        sibling.doCleanups()
        probe.doClassCleanups()
    expected = (KeyboardInterrupt if outcome.endswith("interrupt") else RuntimeError)
    assert caught is None if outcome == "normal" else isinstance(caught, expected), repr(caught)
    if caught is not None:
        assert str(caught) == "launcher fixture probe"
    assert len(calls) == 1
    assert all(not home.parent.exists() for home, _ in calls)
    assert probe.__dict__.get("_projectless_cases", missing) is before
    assert probe._class_cleanups == []


def test_new_class_lifetime_gets_a_fresh_case():
    calls = []
    probe = _probe(calls)
    results = []
    for _ in range(2):
        case = probe("test_empty_bookmark_seeds_projectless_sentinel")
        try:
            probe.setUpClass()
            results.append(case._projectless_launch())
        finally:
            case.doCleanups()
            probe.doClassCleanups()
    assert len(calls) == 2
    assert results[0] is not results[1]
    assert calls[0][0] != calls[1][0]
    assert all(not home.parent.exists() for home, _ in calls)


@pytest.mark.parametrize("failure", [False, True])
def test_direct_method_call_owns_its_temporary_directories(monkeypatch, failure):
    calls = []
    probe = _probe(calls, "launch-error" if failure else "normal")
    monkeypatch.setattr(probe, "_projectless_cases", None)
    case = probe("test_empty_bookmark_seeds_projectless_sentinel")
    try:
        if failure:
            with pytest.raises(RuntimeError, match="launcher fixture probe"):
                case._projectless_launch()
        else:
            assert case._projectless_launch() is not case._projectless_launch()
        assert all(home.parent.exists() for home, _ in calls)
    finally:
        case.doCleanups()
    assert len(calls) == (1 if failure else 2)
    assert all(not home.parent.exists() for home, _ in calls)


@pytest.mark.parametrize("status", [0, 2])
def test_sentinel_case_rejects_a_launcher_that_never_reached_frontend(status):
    class Probe(owner.LauncherSeedV2Test):
        __test__ = False

        def _launch(self, home, tmpdir):
            return subprocess.CompletedProcess(["fixture"], status, "", "")

    case = Probe("test_startup_check_sentinel_never_reaches_terminal_stdout")
    try:
        Probe.setUpClass()
        with pytest.raises(AssertionError):
            case.test_startup_check_sentinel_never_reaches_terminal_stdout()
    finally:
        case.doCleanups()
        Probe.doClassCleanups()
