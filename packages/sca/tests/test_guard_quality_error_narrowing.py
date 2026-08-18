"""Narrowed error handling in ``packages.sca.reachability.guard_quality``.

Representative fails-before test for the suppress-narrowing sweep: the
IRIS sanitiser load in ``analyze_call_site_guards`` used to sit under a
bare ``except Exception: pass``, which ate miswiring-class exceptions
(a ``TypeError`` from a wrong call shape) alongside the legitimate
OSError loss mode. After narrowing, only OSError is suppressed (with a
warning); everything else propagates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import core.iris.api as iris_api
from packages.sca.reachability.guard_quality import analyze_call_site_guards


def _call(tmp_path: Path) -> dict:
    # Non-empty gates so the IRIS block is reached; empty reachability
    # so nothing beyond it runs.
    return analyze_call_site_guards(
        reachability={},
        target=tmp_path,
        cve_dep_keys={"npm:leftpad"},
        affected_functions={"npm:leftpad": ["pad"]},
        out_dir=tmp_path,
    )


def test_miswiring_class_exception_propagates(tmp_path, monkeypatch):
    """A TypeError from the IRIS loader is a wiring bug — must raise."""
    def _broken(*args, **kwargs):
        raise TypeError("miswired call shape")

    monkeypatch.setattr(iris_api, "get_project_sanitisers", _broken)
    with pytest.raises(TypeError, match="miswired call shape"):
        _call(tmp_path)


def test_legitimate_oserror_still_suppressed(tmp_path, monkeypatch, caplog):
    """OSError (store-path resolution) stays non-fatal and is logged."""
    def _io_fail(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(iris_api, "get_project_sanitisers", _io_fail)
    with caplog.at_level("WARNING"):
        result = _call(tmp_path)
    assert result == {}
    assert any(
        "IRIS sanitiser load failed" in r.message for r in caplog.records
    )
