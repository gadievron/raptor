"""safe_subprocess_env — fail-closed contract + family closure.

The one shared wrapper for "get_safe_env, but survive a broken
core.config". The per-module ``_safe_env`` copies it replaced drifted
on the failure branch (one returned ``None`` — subprocess inherit);
these tests pin the contract: config path is get_safe_env parity,
failure path is a minimal allowlist, NEVER the parent environment.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from core.security.env_sanitisation import (  # noqa: E402
    MINIMAL_ENV_KEEP,
    safe_subprocess_env,
)


def _poison_core_config(monkeypatch):
    """Make ``from core.config import RaptorConfig`` raise inside the
    helper's lazy import (None in sys.modules halts the import)."""
    monkeypatch.setitem(sys.modules, "core.config", None)


class TestConfigPath:

    def test_matches_get_safe_env(self):
        from core.config import RaptorConfig
        assert safe_subprocess_env() == RaptorConfig.get_safe_env()

    def test_strip_target_markers_removes_marker_names(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_PROBE_MARKER", "1")
        env = safe_subprocess_env(strip_target_markers=True)
        assert not any(
            k.startswith(("RAPTOR_", "_RAPTOR")) for k in env
        )

    def test_no_strip_keeps_tooling_markers(self):
        # Two-direction: RAPTOR's own tool children keep their
        # allowlisted RAPTOR_* contract vars by default; only the
        # strip_target_markers mode removes them.
        from unittest.mock import patch

        from core.config import RaptorConfig
        fake = {"PATH": "/p", "RAPTOR_DIR": "/opt/raptor"}
        with patch.object(RaptorConfig, "get_safe_env",
                          return_value=dict(fake)):
            assert safe_subprocess_env()["RAPTOR_DIR"] == "/opt/raptor"
            stripped = safe_subprocess_env(strip_target_markers=True)
            assert "RAPTOR_DIR" not in stripped
            assert stripped["PATH"] == "/p"


class TestFailClosedFallback:

    def test_fallback_is_minimal_allowlist_not_inherit(self, monkeypatch):
        monkeypatch.setenv("SUPER_SECRET_API_KEY", "hunter2")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        monkeypatch.setenv("LC_ALL", "C.UTF-8")
        _poison_core_config(monkeypatch)
        env = safe_subprocess_env()
        assert env is not None  # never the inherit sentinel
        assert "SUPER_SECRET_API_KEY" not in env
        assert "LD_PRELOAD" not in env
        assert env.get("LC_ALL") == "C.UTF-8"
        assert "PATH" in env
        allowed = set(MINIMAL_ENV_KEEP)
        assert all(k in allowed or k.startswith("LC_") for k in env)

    def test_fallback_defaults_path(self, monkeypatch):
        _poison_core_config(monkeypatch)
        monkeypatch.delenv("PATH", raising=False)
        env = safe_subprocess_env()
        assert env["PATH"] == "/usr/bin:/bin"

    def test_fallback_carries_no_target_markers(self, monkeypatch):
        # The marker-strip contract holds on the fallback branch for
        # free: the allowlist contains no RAPTOR-identifying names.
        monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "tok")
        _poison_core_config(monkeypatch)
        env = safe_subprocess_env(strip_target_markers=True)
        assert not any(
            k.startswith(("RAPTOR_", "_RAPTOR")) for k in env
        )


class TestFamilyClosure:
    """No module may re-roll the get_safe_env-or-fallback ladder.

    A ``def _safe_env`` is allowed only as a thin module-specific
    consumer that builds ON the shared helper (ghidra adds MAXMEM,
    frida re-adds its runtime vars); a copy that lazily imports
    RaptorConfig itself re-opens the drifted-failure-branch class.
    """

    def _runtime_files_defining_safe_env(self):
        hits = []
        for root in ("core", "packages", "plugins"):
            for p in (REPO_ROOT / root).rglob("*.py"):
                parts = set(p.parts)
                if "tests" in parts or "scripts" in parts:
                    continue
                if p.name.startswith("test_") or p.name == "conftest.py":
                    continue
                try:
                    text = p.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                if "def _safe_env" in text:
                    hits.append((p, text))
        return hits

    def test_every_remaining_safe_env_consumes_the_shared_helper(self):
        offenders = []
        for p, text in self._runtime_files_defining_safe_env():
            if "safe_subprocess_env(" not in text:
                offenders.append(str(p.relative_to(REPO_ROOT)))
        assert offenders == [], (
            "_safe_env re-roll(s) not built on "
            "core.security.env_sanitisation.safe_subprocess_env: "
            f"{offenders}"
        )

    def test_no_get_safe_env_ladder_inside_safe_env_defs(self):
        # The drifted idiom: a _safe_env that itself calls
        # RaptorConfig.get_safe_env() behind a try (its failure
        # branch is where the copies diverged). The shared helper is
        # the only home for that ladder; module wrappers may still
        # import RaptorConfig for OTHER vocab (e.g. the target strip
        # set), which this check deliberately permits.
        offenders = []
        for p, text in self._runtime_files_defining_safe_env():
            body = text.split("def _safe_env", 1)[1]
            # Bound the check to this def (next top-level def/class).
            for stop in ("\ndef ", "\nclass "):
                idx = body.find(stop)
                if idx != -1:
                    body = body[:idx]
            if ".get_safe_env(" in body:
                offenders.append(str(p.relative_to(REPO_ROOT)))
        assert offenders == [], (
            f"_safe_env defs re-rolling the config ladder: {offenders}"
        )
