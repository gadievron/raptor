"""Robustness tests: trust markers do not reach untrusted sandbox children.

``CLAUDECODE`` / ``_RAPTOR_TRUSTED`` are in ``SAFE_ENV_ALLOWLIST`` so
the sandbox setup chain (pid1 shim) can run — but a target-influenced
child holding either marker could invoke ``libexec/`` scripts as a
"trusted caller". ``run_untrusted()`` / ``run_untrusted_networked()``
therefore pass ``strip_trust_markers=True`` so the env handed to the
target has both removed on every backend path.

Unit tests verify the wrapper contract; integration tests verify the
end-to-end property (marker absent in the child, libexec refusal path
hit) on hosts with working namespaces.

Run integration tests: pytest -m integration core/sandbox/tests/test_untrusted_trust_marker_strip.py
"""

import shutil
import sys
from pathlib import Path

import pytest

from core.sandbox import context as _ctx

_REPO_ROOT = Path(__file__).resolve().parents[3]


# ─── wrapper contract (no subprocess spawned) ───────────────────────


def _capture_run(captured):
    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        class _Stub:
            returncode = 0
        return _Stub()
    return fake_run


def test_run_untrusted_forwards_strip_trust_markers(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(_ctx, "run", _capture_run(captured))
    _ctx.run_untrusted(
        ["echo", "ok"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "output"),
    )
    assert captured["kwargs"].get("strip_trust_markers") is True, (
        "run_untrusted must forward strip_trust_markers=True to run(); "
        f"saw {captured['kwargs'].get('strip_trust_markers')!r}"
    )


def test_run_untrusted_networked_forwards_strip_trust_markers(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(_ctx, "run", _capture_run(captured))
    _ctx.run_untrusted_networked(
        ["echo", "ok"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "output"),
        proxy_hosts=["api.example.com"],
    )
    assert captured["kwargs"].get("strip_trust_markers") is True, (
        "run_untrusted_networked must forward strip_trust_markers=True "
        f"to run(); saw {captured['kwargs'].get('strip_trust_markers')!r}"
    )


def test_run_untrusted_rejects_caller_strip_trust_markers(tmp_path):
    """The flag is wrapper policy, not caller policy — parity with the
    strict_env guard: a caller trying to disable it gets the clean
    forbidden-kwarg TypeError, not a silent bypass."""
    with pytest.raises(TypeError, match="strip_trust_markers"):
        _ctx.run_untrusted(
            ["echo", "ok"],
            target=str(tmp_path / "target"),
            output=str(tmp_path / "output"),
            strip_trust_markers=False,
        )


def test_run_untrusted_networked_rejects_caller_strip_trust_markers(tmp_path):
    with pytest.raises(TypeError, match="strip_trust_markers"):
        _ctx.run_untrusted_networked(
            ["echo", "ok"],
            target=str(tmp_path / "target"),
            output=str(tmp_path / "output"),
            proxy_hosts=["api.example.com"],
            strip_trust_markers=False,
        )


# ─── end-to-end (real sandbox) ──────────────────────────────────────


def _require_sandbox():
    if sys.platform != "linux":
        pytest.skip("Linux-only sandbox internals")
    from core.sandbox import check_net_available
    if not check_net_available():
        pytest.skip("User namespaces not available")


@pytest.mark.integration
def test_markers_absent_in_untrusted_child_env(monkeypatch, tmp_path):
    """/usr/bin/env inside run_untrusted() must not see either marker,
    regardless of which backend (fork / unshare+shim / Landlock-only)
    handled the spawn."""
    _require_sandbox()
    env_bin = shutil.which("env") or "/usr/bin/env"
    # Guarantee the markers exist in the parent env so their absence in
    # the child is the strip working, not an unset parent.
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = _ctx.run_untrusted(
        [env_bin],
        output=str(out_dir),
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"env exited {result.returncode}: {result.stderr!r}"
    )
    assert "PATH=" in result.stdout, "child env output looks empty"
    for marker in ("CLAUDECODE=", "_RAPTOR_TRUSTED=", "_RAPTOR_DEATH_FD="):
        assert marker not in result.stdout, (
            f"trust marker {marker!r} leaked into the untrusted child env"
        )


@pytest.mark.integration
def test_sandboxed_child_hits_libexec_refusal(monkeypatch, tmp_path):
    """A sandboxed untrusted child invoking a libexec script must hit
    the inline trust-marker refusal (exit 2, 'internal dispatch
    script') because neither marker survives into its env."""
    _require_sandbox()
    python3 = "/usr/bin/python3"
    if not Path(python3).is_file():
        pytest.skip("/usr/bin/python3 not present")
    script = _REPO_ROOT / "libexec" / "raptor-run-lifecycle"
    assert script.is_file(), f"missing {script}"
    monkeypatch.setenv("CLAUDECODE", "1")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = _ctx.run_untrusted(
        [python3, str(script), "start", "scan"],
        # readable_paths= makes the script readable inside
        # restrict_reads so the refusal comes from the trust gate,
        # not from Landlock hiding the file. (Passing the whole repo
        # as target= would nest the pid1-shim's own read bind inside
        # the target bind and abort mount setup.)
        readable_paths=[str(script)],
        output=str(out_dir),
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 2, (
        f"expected trust-gate refusal (exit 2), got "
        f"{result.returncode}: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    assert "internal dispatch script" in (result.stderr or ""), (
        f"refusal message missing from stderr: {result.stderr!r}"
    )


# ─── CC skill-dispatch opt-out (keep_trust_markers) ─────────────────


def test_networked_keep_trust_markers_disables_strip(monkeypatch, tmp_path):
    """RAPTOR's own CC skill dispatch opts out of the marker strip:
    run() receives strip_trust_markers=False and the shim keep flag."""
    captured = {}
    monkeypatch.setattr(_ctx, "run", _capture_run(captured))
    _ctx.run_untrusted_networked(
        ["claude", "-p"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "output"),
        proxy_hosts=["api.example.com"],
        env={"PATH": "/usr/bin", "CLAUDECODE": "1"},
        keep_trust_markers=True,
    )
    kwargs = captured["kwargs"]
    assert kwargs.get("strip_trust_markers") is False
    env = kwargs.get("env")
    assert env["CLAUDECODE"] == "1"
    assert env["_RAPTOR_KEEP_TRUST_MARKERS"] == "1"


def test_networked_keep_from_untrusted_parent_propagates_nothing(
    monkeypatch, tmp_path,
):
    """keep_trust_markers only PASSES THROUGH markers the parent
    holds — an untrusted parent (no marker in its env) propagates
    nothing, so the child still hits the libexec refusal path."""
    captured = {}
    monkeypatch.setattr(_ctx, "run", _capture_run(captured))
    _ctx.run_untrusted_networked(
        ["claude", "-p"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "output"),
        proxy_hosts=["api.example.com"],
        env={"PATH": "/usr/bin"},  # untrusted parent: no markers
        keep_trust_markers=True,
    )
    env = captured["kwargs"].get("env")
    assert "CLAUDECODE" not in env
    assert "_RAPTOR_TRUSTED" not in env


def test_networked_default_keeps_strip_and_no_keep_flag(
    monkeypatch, tmp_path,
):
    captured = {}
    monkeypatch.setattr(_ctx, "run", _capture_run(captured))
    _ctx.run_untrusted_networked(
        ["echo", "ok"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "output"),
        proxy_hosts=["api.example.com"],
        env={"PATH": "/usr/bin", "CLAUDECODE": "1"},
    )
    kwargs = captured["kwargs"]
    assert kwargs.get("strip_trust_markers") is True
    assert "_RAPTOR_KEEP_TRUST_MARKERS" not in kwargs.get("env", {})


def test_run_untrusted_has_no_keep_opt_out(tmp_path):
    """run_untrusted() (target-derived code) deliberately offers no
    keep_trust_markers escape hatch."""
    with pytest.raises(TypeError, match="keep_trust_markers"):
        _ctx.run_untrusted(
            ["echo", "ok"],
            target=str(tmp_path / "target"),
            output=str(tmp_path / "output"),
            keep_trust_markers=True,
        )
