"""Operator disable (`--sandbox none` / profile "none") sheds ALL
per-call Landlock policy.

The documented contract is "none: rlimits only, no isolation". Pre-fix
only target/output/allowed_tcp_ports were nulled: a surviving
writable_paths= re-engaged Landlock with output nulled (the run got a
write-nowhere-except-/tmp+extras policy — MORE denials than --sandbox
full), restrict_reads=True survived with the target no longer in the
read allowlist, and fake_home=True materialised `.home` — all while
the delivered-tier stamp said "none". The stamp lied in both
directions: the operator believed no isolation; enforcement existed
with nulled grants. Directly relevant on userns-restricted hosts,
where `--sandbox none` is the bisect tool operators reach for.
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox import context as _ctx
from core.sandbox.tests.capability import requires_landlock

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux sandbox lanes")


def _spy_preexec_kwargs(monkeypatch):
    """Capture the kwargs the plain-lane preexec builder receives."""
    captured: dict = {}
    real = _ctx._make_preexec_fn

    def spy(limits, **kw):
        captured.update(kw)
        return real(limits, **kw)

    monkeypatch.setattr(_ctx, "_make_preexec_fn", spy)
    return captured


def test_disabled_sheds_every_landlock_engaging_kwarg(
        tmp_path, monkeypatch):
    """disabled=True must null writable_paths / readable_paths /
    restrict_reads exactly like target/output — no surviving kwarg
    may hand the preexec builder a Landlock-engaging policy."""
    captured = _spy_preexec_kwargs(monkeypatch)
    grant = tmp_path / "grant"
    grant.mkdir()
    with _ctx.sandbox(disabled=True,
                      target=str(tmp_path),
                      output=str(grant),
                      writable_paths=[str(grant)],
                      restrict_reads=True,
                      readable_paths=[str(tmp_path)]):
        pass
    assert captured, "preexec builder never consulted"
    assert not captured.get("writable_paths"), (
        "writable_paths survived operator disable — Landlock engages "
        "with output nulled (write-nowhere policy under a BARE stamp)")
    assert captured.get("readable_paths") is None, (
        "read allowlist survived operator disable")
    assert not captured.get("allowed_tcp_ports")
    assert not captured.get("deny_all_tcp_connect")


def test_profile_none_kwarg_sheds_policy_too(tmp_path, monkeypatch):
    """Caller-supplied profile=\"none\" takes the same shed path as
    the CLI/disabled spellings."""
    captured = _spy_preexec_kwargs(monkeypatch)
    with _ctx.sandbox(profile="none",
                      writable_paths=[str(tmp_path)],
                      restrict_reads=True):
        pass
    assert captured, "preexec builder never consulted"
    assert not captured.get("writable_paths")
    assert captured.get("readable_paths") is None


def test_disabled_sheds_fake_home_before_materialisation(
        tmp_path, caplog):
    """fake_home=True under an operator disable must not materialise
    `.home` (it is consumed before the authoritative profile block,
    so it needs its own shed). The discard is SILENT under explicit
    operator disable — production callers pass fake_home=True
    unconditionally, and a --sandbox none bisect session must not
    warn once per call (same suppression as the target/output
    discards)."""
    out = tmp_path / "out"
    out.mkdir()
    with caplog.at_level("WARNING"):
        with _ctx.sandbox(disabled=True, fake_home=True,
                          output=str(out)):
            pass
    assert not (out / ".home").exists(), (
        "fake HOME materialised under profile none")
    assert "fake_home" not in caplog.text


def test_network_only_warns_fake_home_discard(tmp_path, caplog):
    """The non-disabled Landlock-off profile tells the caller the
    fake HOME was shed."""
    out = tmp_path / "out"
    out.mkdir()
    with caplog.at_level("WARNING"):
        with _ctx.sandbox(profile="network-only", fake_home=True,
                          output=str(out)):
            pass
    assert not (out / ".home").exists()
    assert "fake_home" in caplog.text


def test_network_only_profile_warns_about_discards(
        tmp_path, monkeypatch, caplog):
    """The non-disabled Landlock-off profile keeps warning about each
    discarded kwarg, now including the ones the shed gained."""
    _spy_preexec_kwargs(monkeypatch)
    with caplog.at_level("WARNING"):
        with _ctx.sandbox(profile="network-only",
                          writable_paths=[str(tmp_path)],
                          restrict_reads=True):
            pass
    text = caplog.text
    assert "writable_paths" in text
    assert "restrict_reads" in text


@requires_landlock
def test_disabled_run_is_actually_unrestricted(tmp_path):
    """Live enforcement probe: pre-fix, disabled + writable_paths +
    exclude_tmp_baseline delivered a write-NOWHERE Landlock policy, so
    a write outside the grant failed EACCES while the run stamped
    "none". Post-fix the child writes anywhere DAC permits and the
    stamp is truthful."""
    grant = tmp_path / "grant"
    grant.mkdir()
    probe = tmp_path / "probe.txt"
    with _ctx.sandbox(disabled=True,
                      writable_paths=[str(grant)],
                      exclude_tmp_baseline=True) as run_fn:
        result = run_fn(
            ["/bin/sh", "-c", f"echo unrestricted > {probe}"],
            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert probe.exists(), (
        "write outside the surviving grant set was denied — Landlock "
        "enforced under an operator disable")
    assert result.sandbox_info["containment_tier"] == "none"
