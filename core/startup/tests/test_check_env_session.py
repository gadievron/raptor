"""Tests for the session-context-aware additions to
``core.startup.init.check_env``:

  * Python version floor (3.10+, enforced by
    PEP 604 syntax in schemas.py without
    ``from __future__ import annotations``).
  * RAPTOR_DIR defensive check.

Both are visible to the banner AND the doctor (single source of
truth — banner picks them up automatically).
"""

from __future__ import annotations

from unittest import mock

import pytest

from core.startup import init as startup_init


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """Build a minimal fake repo at tmp_path and re-point
    ``startup_init.REPO_ROOT`` at it for the duration of the test."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / "core").mkdir()
    (tmp_path / "packages").mkdir()
    (tmp_path / "libexec").mkdir()
    (tmp_path / "bin").mkdir()
    monkeypatch.setattr(startup_init, "REPO_ROOT", tmp_path)
    return tmp_path


def _run_check_env(monkeypatch):
    """Invoke check_env with the noisy sandbox / disk side checks
    stubbed out. We're testing only the new session-context branch.
    """
    # Sandbox probes shell out; disk reads statvfs. Both are
    # noisy and orthogonal to the env-file check — patch them
    # away so the test stays focused.
    monkeypatch.setattr("os.statvfs", lambda _: type(
        "S", (), {"f_bavail": 10**9, "f_frsize": 4096}
    )())
    return startup_init.check_env(set())


# ---------------------------------------------------------------------------
# RAPTOR_DIR check
# ---------------------------------------------------------------------------


class TestRaptorDirCheck:
    def test_unset_warns_with_computed_value(
        self, fake_repo, monkeypatch,
    ):
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        _, warnings = _run_check_env(monkeypatch)
        match = [w for w in warnings if "RAPTOR_DIR not set" in w]
        assert match, f"no RAPTOR_DIR warning in: {warnings}"
        assert str(fake_repo) in match[0]

    def test_set_to_non_directory_warns(
        self, fake_repo, monkeypatch, tmp_path,
    ):
        bogus = tmp_path / "does-not-exist"
        monkeypatch.setenv("RAPTOR_DIR", str(bogus))
        _, warnings = _run_check_env(monkeypatch)
        match = [w for w in warnings if "does not resolve" in w]
        assert match, f"no path-resolution warning in: {warnings}"

    def test_set_to_non_raptor_dir_warns(
        self, fake_repo, monkeypatch, tmp_path,
    ):
        # tmp_path lacks the layout.
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setenv("RAPTOR_DIR", str(empty))
        _, warnings = _run_check_env(monkeypatch)
        match = [w for w in warnings if "missing expected directories" in w]
        assert match, f"no layout warning in: {warnings}"

    def test_set_correctly_no_warning(self, fake_repo, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(fake_repo))
        _, warnings = _run_check_env(monkeypatch)
        assert not any(
            "RAPTOR_DIR" in w and "not set" in w for w in warnings
        )


# ---------------------------------------------------------------------------
# No .claude/raptor.env or .claude/settings.json checks
# ---------------------------------------------------------------------------


class TestPythonVersionCheck:
    """The check pings a real failure mode: ``packages/
    exploitability_validation/schemas.py`` uses ``str | None``
    at function-definition time without ``__future__``, so
    importing the module on 3.9 raises ``TypeError``. We want
    the operator to see the version mismatch BEFORE that import
    trace."""

    def test_runs_on_current_python_records_version(
        self, fake_repo, monkeypatch,
    ):
        # No version mock — we're running on a real Python.
        # Whatever version it is, the version should appear as a
        # part with the appropriate glyph.
        parts, _warnings = _run_check_env(monkeypatch)
        version_parts = [p for p in parts if p.startswith("Python ")]
        assert version_parts, f"no python version in parts: {parts}"

    def test_old_python_emits_failure_glyph_and_warning(
        self, fake_repo, monkeypatch,
    ):
        # Force version_info < 3.10. NamedTuple-style replacement
        # so sys.version_info comparisons still work.
        from collections import namedtuple
        VI = namedtuple(
            "VI", "major minor micro releaselevel serial",
        )
        monkeypatch.setattr("sys.version_info", VI(3, 9, 18, "final", 0))
        # platform.python_version() reads from sys.version, not
        # version_info — patch its return so the message is
        # internally consistent.
        monkeypatch.setattr(
            "platform.python_version", lambda: "3.9.18",
        )
        parts, warnings = _run_check_env(monkeypatch)
        version_parts = [p for p in parts if p.startswith("Python ")]
        # Failure glyph ⇒ doctor classifies as failure.
        assert any("✗" in p for p in version_parts), version_parts
        # Warning carries the reason (PEP 604 / schemas.py) so
        # operator knows WHY 3.10 is required.
        match = [
            w for w in warnings
            if "Python 3.9.18" in w and "3.10+" in w
        ]
        assert match, warnings
        assert "PEP 604" in match[0]
        assert "schemas.py" in match[0]

    def test_current_python_emits_pass_glyph(
        self, fake_repo, monkeypatch,
    ):
        parts, warnings = _run_check_env(monkeypatch)
        version_parts = [p for p in parts if p.startswith("Python ")]
        assert version_parts
        # On any 3.10+ host (which CI is), the part carries ✓.
        assert any("✓" in p for p in version_parts), version_parts
        # No Python-related warning.
        assert not any(
            "Python" in w and "3.10+" in w for w in warnings
        )


class TestSandboxCapabilityTier:
    """Linux sandbox line surfaces the host's Landlock ABI tier once
    at startup — the per-run warnings (egress allowlist advisory on
    ABI < 4) otherwise repeat per run with no single summary."""

    def _run(self, monkeypatch, *, net=True, mount=True, landlock=True,
             seccomp=True, abi=5):
        monkeypatch.setattr("sys.platform", "linux")
        with mock.patch("core.sandbox.check_net_available", return_value=net), \
             mock.patch("core.sandbox.check_mount_available", return_value=mount), \
             mock.patch("core.sandbox.check_landlock_available", return_value=landlock), \
             mock.patch("core.sandbox.check_seccomp_available", return_value=seccomp), \
             mock.patch("core.sandbox._get_landlock_abi", return_value=abi), \
             mock.patch("core.startup.init._check_analyzer_capabilities",
                        return_value=([], [])):
            return _run_check_env(monkeypatch)

    def test_abi_tier_shown_in_sandbox_part(self, fake_repo, monkeypatch):
        parts, warnings = self._run(monkeypatch, abi=5)
        sandbox = [p for p in parts if p.startswith("sandbox")]
        assert sandbox and "landlock:abi5" in sandbox[0]
        assert not any("Landlock ABI" in w for w in warnings)

    def test_abi_below_4_warns_about_advisory_egress(
        self, fake_repo, monkeypatch,
    ):
        parts, warnings = self._run(monkeypatch, abi=3)
        sandbox = [p for p in parts if p.startswith("sandbox")]
        assert sandbox and "landlock:abi3" in sandbox[0]
        match = [w for w in warnings if "Landlock ABI 3 < 4" in w]
        assert match, warnings
        assert "advisory" in match[0]

    def test_landlock_unavailable_no_abi_or_warning(
        self, fake_repo, monkeypatch,
    ):
        parts, warnings = self._run(monkeypatch, landlock=False, abi=0)
        sandbox = [p for p in parts if p.startswith("sandbox")]
        assert sandbox and "landlock" not in sandbox[0]
        # The pre-existing "Landlock filesystem restriction missing"
        # warning covers total absence; no ABI-tier warning on top.
        assert not any("Landlock ABI" in w for w in warnings)

    def test_abi_probe_returning_zero_degrades_to_plain_feature(
        self, fake_repo, monkeypatch,
    ):
        parts, warnings = self._run(monkeypatch, abi=0)
        sandbox = [p for p in parts if p.startswith("sandbox")]
        assert sandbox and "landlock" in sandbox[0]
        assert "abi" not in sandbox[0]
        assert not any("Landlock ABI" in w for w in warnings)


class TestNoClaudeFileChecks:
    """Pin that ``check_env`` does NOT warn about ``.claude/raptor.env``
    or ``.claude/settings.json`` either inside or outside a claude
    session. Both checks were considered and dropped — failure
    modes for either file missing are not actionable via doctor
    advice (operator damage / RAPTOR ship-side bug / claude
    misconfig)."""

    def test_no_raptor_env_warning_inside_claude_session(
        self, fake_repo, monkeypatch,
    ):
        monkeypatch.setenv("CLAUDECODE", "1")
        _, warnings = _run_check_env(monkeypatch)
        assert not any("raptor.env" in w for w in warnings), warnings

    def test_no_raptor_env_warning_outside_claude_session(
        self, fake_repo, monkeypatch,
    ):
        monkeypatch.delenv("CLAUDECODE", raising=False)
        _, warnings = _run_check_env(monkeypatch)
        assert not any("raptor.env" in w for w in warnings), warnings

    def test_no_settings_json_warning(self, fake_repo, monkeypatch):
        # No .claude/settings.json. CLAUDECODE both set and unset.
        for v in ("1", None):
            if v is None:
                monkeypatch.delenv("CLAUDECODE", raising=False)
            else:
                monkeypatch.setenv("CLAUDECODE", v)
            _, warnings = _run_check_env(monkeypatch)
            assert not any(
                "settings.json" in w for w in warnings
            ), f"with CLAUDECODE={v}: {warnings}"
