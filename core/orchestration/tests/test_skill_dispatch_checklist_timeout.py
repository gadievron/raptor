"""The orchestration pre-pass builder shares the work-scaled bound.

Sibling of the raptor-audit call sites (pinned by
core/audit/tests/test_checklist_build_timeout.py):
``skill_dispatch.build_checklist`` — ridden by
``agentic_passes._provision_understand_checklist`` — spawned the same
raptor-build-checklist child under its own flat 300s constant, so the
large-binary shape that live-failed the audit surface would silently
kill the /understand pre-pass builder too. The bound now comes from
the ONE shared sizing rule (``core.audit.checklist_timeout``), env
override included; this surface keeps its warn-and-degrade shape (an
invalid override logs a warning and the scaled bound applies — a
pre-pass builder failure is already a warn-and-continue path, never a
refusal).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.orchestration.skill_dispatch import build_checklist

_MIB = 1024 * 1024

ENV = "RAPTOR_CHECKLIST_BUILD_TIMEOUT_S"


def _sparse(path: Path, size: int, head: bytes = b"") -> Path:
    """A file whose st_size is ``size`` without touching the disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        if head:
            f.write(head)
        f.truncate(size)
    return path


@pytest.fixture(autouse=True)
def _no_override(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)


def _spawn_timeout(target: Path, out_dir: Path) -> object:
    """The timeout kwarg build_checklist hands its child."""
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["timeout"] = kwargs.get("timeout")

        class _CP:
            returncode = 0
            stdout = ""
            stderr = ""
        return _CP()

    with patch("core.orchestration.skill_dispatch.subprocess.run",
               side_effect=fake_run):
        assert build_checklist(target, out_dir) is True
    return captured["timeout"]


def test_large_target_gets_the_scaled_bound(tmp_path: Path):
    # The audit surface's live-hit shape: a 41 MiB binary must get
    # more than the flat 300s this surface hardcoded.
    target = _sparse(tmp_path / "big.bin", 41 * _MIB, head=b"\x7fELF")
    out = tmp_path / "out"
    out.mkdir()
    assert _spawn_timeout(target, out) == 41 * 30


def test_small_target_keeps_the_floor(tmp_path: Path):
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.c").write_text("int main(void) { return 0; }\n")
    out = tmp_path / "out"
    out.mkdir()
    # Never tighter than the historical 300s.
    assert _spawn_timeout(target, out) == 300


def test_override_reaches_the_child_verbatim(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(ENV, "7200")
    target = tmp_path / "src"
    target.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    assert _spawn_timeout(target, out) == 7200


def test_invalid_override_degrades_to_the_scaled_bound(
        tmp_path: Path, monkeypatch, caplog):
    # This surface's shape: warn-and-continue, never refuse — but with
    # the SCALED value, not the old flat constant.
    monkeypatch.setenv(ENV, "banana")
    target = _sparse(tmp_path / "big.bin", 41 * _MIB, head=b"\x7fELF")
    out = tmp_path / "out"
    out.mkdir()
    with caplog.at_level("WARNING"):
        assert _spawn_timeout(target, out) == 41 * 30
    assert any(ENV in r.getMessage() for r in caplog.records)


def test_oversized_override_degrades_not_overflows(
        tmp_path: Path, monkeypatch, caplog):
    # A 400-digit override must neither reach subprocess.run (where
    # float conversion raises OverflowError) nor kill the pre-pass.
    monkeypatch.setenv(ENV, "9" * 400)
    target = tmp_path / "src"
    target.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    with caplog.at_level("WARNING"):
        assert _spawn_timeout(target, out) == 300
    assert any("at most" in r.getMessage() for r in caplog.records)
