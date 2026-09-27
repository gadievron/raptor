"""Filesystem-confinement fence for the c++filt demangle batch.

The mangled names fed to c++filt are attacker-derived bytes from the
analysed binary's DWARF; the tool itself reads and writes nothing on
disk, so its sandbox run must carry an ``output=`` scratch dir AND
``restrict_reads=True`` — without them the sandbox applies no
filesystem confinement and a c++filt parser bug would execute with
the whole filesystem readable and writable.

Hermetic: ``core.sandbox.run`` is a stand-in; no c++filt, no live
sandbox, no network.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any

import pytest


@pytest.fixture
def sandbox_calls(monkeypatch) -> list[dict[str, Any]]:
    import shutil

    import core.sandbox as _sb

    calls: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **kwargs: Any):
        record = dict(kwargs)
        record["cmd"] = list(cmd)
        out = kwargs.get("output")
        # Existence is a call-time property (the scratch dir is
        # deleted on exit) — capture it now, not at assert time.
        record["output_existed"] = bool(out) and os.path.isdir(out)
        calls.append(record)
        return SimpleNamespace(returncode=0, stdout="foo()\n", stderr="")

    monkeypatch.setattr(_sb, "run", fake_run)
    monkeypatch.setattr(
        shutil, "which",
        lambda name, *a, **k: "/usr/bin/c++filt" if name == "c++filt"
        else None,
    )
    return calls


def test_demangle_confines_filesystem(sandbox_calls: list[dict[str, Any]]):
    from core.analysis.binary_oracle import _demangle_linkage_names

    result = _demangle_linkage_names(["_Z3foov"])

    assert result == {"_Z3foov": "foo()"}
    [call] = sandbox_calls
    assert call["cmd"] == ["c++filt"]
    assert call["block_network"] is True
    assert call["output"]  # write-side confinement engaged
    assert call["output_existed"] is True
    # Read side confined to the system allowlist — c++filt needs
    # nothing beyond the toolchain + libc.
    assert call["restrict_reads"] is True
    assert call["input"] == "_Z3foov"


def test_demangle_missing_tool_never_reaches_sandbox(
    sandbox_calls: list[dict[str, Any]], monkeypatch,
):
    import shutil

    from core.analysis.binary_oracle import _demangle_linkage_names

    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

    assert _demangle_linkage_names(["_Z3foov"]) == {}
    assert sandbox_calls == []
