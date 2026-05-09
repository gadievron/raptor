"""Tests for ``libexec/raptor-pick-strategies``.

Drives the shim as a subprocess. Used by /validate stage skills,
/audit's driver, and operators wanting bug-class context for a
function. Each test sets ``_RAPTOR_TRUSTED=1`` to bypass the
trust-marker guard.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[4]
SHIM = REPO_ROOT / "libexec" / "raptor-pick-strategies"


def _run(*args, env_extra=None):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(SHIM), *args],
        env=env, capture_output=True, text=True,
    )


# ---------------------------------------------------------------------------
# Trust marker
# ---------------------------------------------------------------------------


class TestTrustMarker:
    def test_refuses_without_marker(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("_RAPTOR_TRUSTED", "CLAUDECODE")}
        r = subprocess.run(
            [sys.executable, str(SHIM), "--cwe", "CWE-78"],
            env=env, capture_output=True, text=True,
        )
        assert r.returncode == 2
        assert "internal dispatch" in r.stderr


# ---------------------------------------------------------------------------
# Signal dimensions
# ---------------------------------------------------------------------------


class TestCweSignal:
    def test_cwe_78_picks_input_handling(self):
        r = _run("--cwe", "CWE-78")
        assert r.returncode == 0, r.stderr
        assert "## Strategy: input_handling" in r.stdout
        assert "CVE-2023-0179" in r.stdout

    def test_cwe_416_picks_memory_management(self):
        r = _run("--cwe", "CWE-416")
        assert r.returncode == 0
        assert "## Strategy: memory_management" in r.stdout

    def test_cwe_362_picks_concurrency(self):
        r = _run("--cwe", "CWE-362")
        assert r.returncode == 0
        assert "## Strategy: concurrency" in r.stdout


class TestPathSignal:
    def test_kernel_locking_picks_concurrency(self):
        r = _run("--file", "kernel/locking/rwsem.c")
        assert r.returncode == 0
        assert "## Strategy: concurrency" in r.stdout

    def test_crypto_path_picks_cryptography(self):
        r = _run("--file", "crypto/aes.c")
        assert r.returncode == 0
        assert "## Strategy: cryptography" in r.stdout


class TestKeywordSignal:
    def test_parse_function_picks_input_handling(self):
        r = _run("--function", "parse_request")
        assert r.returncode == 0
        assert "## Strategy: input_handling" in r.stdout


class TestCallsSignal:
    def test_mutex_lock_callee_picks_concurrency(self):
        r = _run("--calls", "mutex_lock,mutex_unlock")
        assert r.returncode == 0
        assert "## Strategy: concurrency" in r.stdout


class TestIncludesSignal:
    def test_skbuff_include_picks_input_handling(self):
        r = _run("--includes", "linux/skbuff.h")
        assert r.returncode == 0
        assert "## Strategy: input_handling" in r.stdout


# ---------------------------------------------------------------------------
# Combined signals — realistic /validate stage usage
# ---------------------------------------------------------------------------


class TestCombined:
    def test_full_stage_b_call(self):
        """Realistic Stage B: finding with CWE-id + file + function."""
        r = _run(
            "--cwe", "CWE-89",
            "--file", "src/auth/login.py",
            "--function", "check_credentials",
        )
        assert r.returncode == 0
        assert "## Strategy: input_handling" in r.stdout
        assert "## Strategy: general" in r.stdout
        # general always pinned first.
        assert r.stdout.find("## Strategy: general") < r.stdout.find(
            "## Strategy: input_handling"
        )

    def test_stage_a_no_cwe_yet(self):
        """Stage A doesn't have a CWE yet — picker fires on path /
        function alone."""
        r = _run(
            "--file", "net/parser.c",
            "--function", "parse_packet",
        )
        assert r.returncode == 0
        assert "## Strategy: input_handling" in r.stdout

    def test_full_signal_stack(self):
        r = _run(
            "--cwe", "CWE-119",
            "--file", "net/foo/parser.c",
            "--function", "parse_request",
            "--includes", "linux/skbuff.h,linux/spinlock.h",
            "--calls", "mutex_lock,skb_pull",
        )
        assert r.returncode == 0
        # input_handling pinned by CWE + path + include + keyword
        # + call (the skb_pull callee).
        assert "## Strategy: input_handling" in r.stdout


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_no_args_returns_general_only(self):
        r = _run()
        assert r.returncode == 0
        assert "## Strategy: general" in r.stdout

    def test_unknown_cwe_falls_back_to_general(self):
        r = _run("--cwe", "CWE-99999")
        assert r.returncode == 0
        # general always there as fallback.
        assert "## Strategy: general" in r.stdout

    def test_max_strategies_cap(self):
        r = _run(
            "--cwe", "CWE-119",  # several strategies pin on this
            "--file", "kernel/mm/foo.c",  # path matches multiple
            "--max-strategies", "2",
        )
        assert r.returncode == 0
        # max=2 → general + 1 specialised.
        count = r.stdout.count("## Strategy:")
        assert count == 2

    def test_no_general_flag(self):
        r = _run(
            "--cwe", "CWE-78",
            "--no-general",
        )
        assert r.returncode == 0
        # No general; only the CWE-pinned strategy.
        assert "## Strategy: general" not in r.stdout
        assert "## Strategy: input_handling" in r.stdout

    def test_no_general_no_signal_returns_no_match_marker(self):
        """No specialised match + general excluded = explicit
        no-match marker so the caller knows the helper ran."""
        r = _run("--no-general", "--file", "totally_unknown.xyz")
        assert r.returncode == 0
        assert "no matching strategies" in r.stdout

    def test_csv_strips_empty_members(self):
        """Trailing comma / empty members in csv args don't crash."""
        r = _run("--calls", "mutex_lock,,,kfree")
        assert r.returncode == 0
        # Both signals fire — concurrency for mutex_lock,
        # memory_management for kfree.
        assert "## Strategy:" in r.stdout
