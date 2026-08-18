"""_fetch_source must run git with the per-invocation safety pins.

The corpus fixture trees are cloned from external repos — a hostile
``.git/config`` in one (core.fsmonitor, core.hooksPath, ...) would
execute attacker commands on every git invocation. The fetch path
therefore has to build its argv through core.git's safe wrappers, not
bare ``["git", ...]`` lists.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from core.audit.corpus import run_corpus

_SHA = "a" * 40
_OTHER = "b" * 40


class _Recorder:
    def __init__(self, head_sha: str):
        self.calls: list[list[str]] = []
        self.head_sha = head_sha

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout=self.head_sha + "\n",
                               stderr="")


def _make_repo_dir(tmp_path, key):
    d = tmp_path / key
    (d / ".git").mkdir(parents=True)
    return d


def test_rev_parse_uses_strict_readonly_pins(tmp_path, monkeypatch):
    _make_repo_dir(tmp_path, "proj")
    monkeypatch.setattr(run_corpus, "FIXTURES_DIR", tmp_path)
    rec = _Recorder(head_sha=_SHA)
    monkeypatch.setattr(subprocess, "run", rec)

    dest = run_corpus._fetch_source("proj", _SHA)

    assert dest == tmp_path / "proj"
    assert len(rec.calls) == 1  # SHA matches → rev-parse only
    argv = rec.calls[0]
    assert argv[0] == "git"
    assert "rev-parse" in argv
    # base pins
    assert "core.hooksPath=/dev/null" in argv
    assert "core.fsmonitor=" in argv
    assert "credential.helper=" in argv
    # strict read-only pins — rev-parse never needs a transport
    assert "protocol.allow=never" in argv
    assert "core.sshCommand=false" in argv


def test_fetch_and_checkout_use_safe_pins(tmp_path, monkeypatch):
    _make_repo_dir(tmp_path, "proj")
    monkeypatch.setattr(run_corpus, "FIXTURES_DIR", tmp_path)
    rec = _Recorder(head_sha=_OTHER)  # mismatch → re-fetch + checkout
    monkeypatch.setattr(subprocess, "run", rec)

    run_corpus._fetch_source("proj", _SHA)

    flat = ["fetch" if "fetch" in c else ("checkout" if "checkout" in c
            else "other") for c in rec.calls]
    assert "fetch" in flat and "checkout" in flat
    for argv in rec.calls:
        assert argv[0] == "git"
        assert "core.hooksPath=/dev/null" in argv
        assert "core.fsmonitor=" in argv
        if "fetch" in argv:
            # fetch needs a transport — base pins, not the strict
            # protocol.allow=never which would break it
            assert "protocol.allow=never" not in argv
            assert "protocol.ext.allow=never" in argv
