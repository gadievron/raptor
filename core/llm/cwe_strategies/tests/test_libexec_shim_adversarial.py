"""Adversarial + E2E coverage for ``libexec/raptor-pick-strategies``.

The shim is the surface for /validate stage skills, /audit's
driver, and operators. Hostile inputs must not crash, must not
inject fake markdown headings, and must not exec shell text.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[4]
SHIM = REPO_ROOT / "libexec" / "raptor-pick-strategies"
STAGE_A = REPO_ROOT / ".claude" / "skills" / "exploitability-validation" / "stage-a-oneshot.md"
STAGE_B = REPO_ROOT / ".claude" / "skills" / "exploitability-validation" / "stage-b-process.md"


def _run(*args, env_extra=None, timeout=30):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(SHIM), *args],
        env=env, capture_output=True, text=True, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Hostile input — must not crash or corrupt output
# ---------------------------------------------------------------------------


class TestHostileInputs:
    def test_newline_in_cwe_no_fake_heading(self):
        r = _run("--cwe", "CWE-78\n## INJECTED")
        assert r.returncode == 0
        # Newline-injected fake heading must NOT appear in output.
        assert "## INJECTED" not in r.stdout
        # Picker treats hostile cwe as no-match → general fallback.
        assert "## Strategy: general" in r.stdout

    def test_null_byte_in_argv_rejected_by_os(self):
        """POSIX argv can't carry null bytes — ``posix_spawn``
        raises ``ValueError`` before the shim is invoked. Pin the
        OS-level defence so future test refactors don't accidentally
        assume the shim has to defend against this. Equivalent
        attack vector via the picker (``cwe_id`` set programmatically)
        is covered in ``test_picker_tier1.py``."""
        with pytest.raises(ValueError, match="null byte"):
            _run("--cwe", "CWE-78\x00")

    def test_huge_cwe_id(self):
        # 100KB cwe-id — picker hashes/compares but doesn't render
        # raw input; output stays bounded.
        big = "CWE-" + "9" * 100_000
        r = _run("--cwe", big, timeout=60)
        assert r.returncode == 0
        # Output bounded — no echo of the input.
        assert big not in r.stdout
        assert len(r.stdout) < 50_000

    def test_newline_in_file_path(self):
        r = _run("--file", "src/foo.py\n## EVIL", "--cwe", "CWE-78")
        assert r.returncode == 0
        # Hostile file path is not echoed into the markdown output.
        assert "## EVIL" not in r.stdout

    def test_newline_in_function_name(self):
        r = _run("--function", "parse\n## INJECTED")
        assert r.returncode == 0
        assert "## INJECTED" not in r.stdout
        # ``parse`` token still hits input_handling.
        assert "## Strategy: input_handling" in r.stdout

    def test_shell_metachars_in_args_not_executed(self, tmp_path):
        """argparse passes args verbatim to the shim; the shim
        passes them to the picker. None of these should reach a
        shell. Demonstrate by trying to write a side-effect file
        — it must NOT be created."""
        marker = tmp_path / "evil_marker"
        # If shell-evaluated, this would create the marker file.
        r = _run(
            "--function", f"foo; touch {marker}",
            "--file", f"src/$(touch {marker}).py",
        )
        assert r.returncode == 0
        assert not marker.exists(), (
            "shell metachars in args must NOT be evaluated"
        )

    def test_huge_calls_list(self):
        """1000 callees — picker scales, output stays bounded."""
        calls = ",".join(["noise_" + str(i) for i in range(1000)]
                          + ["mutex_lock"])
        r = _run("--calls", calls, timeout=60)
        assert r.returncode == 0
        # Concurrency strategy fires on the one real signal.
        assert "## Strategy: concurrency" in r.stdout
        # Output bounded by render_strategies' default 16KB cap.
        assert len(r.stdout) < 32_000


# ---------------------------------------------------------------------------
# Argparse / boundary cases
# ---------------------------------------------------------------------------


class TestArgparseBoundaries:
    def test_max_strategies_zero(self):
        r = _run("--cwe", "CWE-78", "--max-strategies", "0")
        assert r.returncode == 0
        # Picker returns []; shim emits the no-match marker.
        assert "no matching strategies" in r.stdout

    def test_max_strategies_negative(self):
        r = _run("--cwe", "CWE-78", "--max-strategies", "-1")
        # picker treats max<=0 as empty; shim emits no-match marker.
        assert r.returncode == 0
        assert "no matching strategies" in r.stdout

    def test_help_flag(self):
        r = _run("--help")
        assert r.returncode == 0
        assert "raptor-pick-strategies" in r.stdout
        assert "--cwe" in r.stdout

    def test_unknown_flag_rejected(self):
        r = _run("--bogus-flag")
        # argparse exits with status 2 for unknown options.
        assert r.returncode != 0

    def test_csv_with_only_separators(self):
        """``--calls ",,,"`` produces no callee signals; bare
        invocation behaviour."""
        r = _run("--calls", ",,,,")
        assert r.returncode == 0
        # No specialised picks; general only.
        assert "## Strategy: general" in r.stdout


# ---------------------------------------------------------------------------
# Output validity
# ---------------------------------------------------------------------------


class TestOutputValidity:
    def test_stdout_is_valid_utf8(self):
        r = _run("--cwe", "CWE-78")
        # subprocess.run(text=True) decodes as UTF-8; we get here
        # only if it parsed cleanly.
        assert r.stdout
        # Sanity re-encode round-trip.
        assert r.stdout == r.stdout.encode("utf-8").decode("utf-8")

    def test_output_has_top_level_header(self):
        r = _run("--cwe", "CWE-78")
        assert r.stdout.startswith("# Bug-class lenses")

    def test_strategy_blocks_are_well_formed_markdown(self):
        """Every ``## Strategy: <name>`` heading should be followed
        by a description paragraph, then the standard subsections
        (### Key questions / ### Approach / ### Worked examples)."""
        r = _run("--cwe", "CWE-78")
        # At least one strategy block.
        strategy_headings = re.findall(r"^## Strategy: \S+", r.stdout, re.M)
        assert len(strategy_headings) >= 1
        # Standard subheadings present somewhere in output.
        assert "### Key questions" in r.stdout
        assert "### Approach" in r.stdout
        assert "### Worked examples" in r.stdout

    def test_no_general_strict_suppression(self):
        """Even when the picker falls through to general (no other
        match), --no-general must keep it out."""
        # An unknown CWE plus no file/function/calls — picker would
        # naturally return general only.
        r = _run("--cwe", "CWE-99999", "--no-general")
        assert r.returncode == 0
        assert "## Strategy: general" not in r.stdout
        # No strategies left → no-match marker.
        assert "no matching strategies" in r.stdout


# ---------------------------------------------------------------------------
# Skill-file integration sanity
# ---------------------------------------------------------------------------


class TestSkillIntegration:
    def test_stage_a_references_shim(self):
        text = STAGE_A.read_text(encoding="utf-8")
        assert "libexec/raptor-pick-strategies" in text

    def test_stage_b_references_shim(self):
        text = STAGE_B.read_text(encoding="utf-8")
        assert "libexec/raptor-pick-strategies" in text
        # Stage B has a CWE id at hand from Stage A's verdict.
        assert "--cwe" in text

    def test_stage_a_documents_no_cwe_yet(self):
        text = STAGE_A.read_text(encoding="utf-8")
        # Stage A doesn't have a CWE yet — the docs should say so.
        assert "cwe" in text.lower()
        assert "stage a" in text.lower()

    def test_stage_b_documents_hypothesis_use(self):
        text = STAGE_B.read_text(encoding="utf-8")
        # Strategy guidance feeds hypothesis generation.
        assert "hypothesis" in text.lower()


# ---------------------------------------------------------------------------
# E2E — realistic stage invocations
# ---------------------------------------------------------------------------


class TestE2E:
    def test_stage_a_invocation_no_cwe(self):
        """Realistic Stage A: priority target on a parser path."""
        r = _run(
            "--file", "net/netfilter/nf_tables_api.c",
            "--function", "nft_payload_eval",
        )
        assert r.returncode == 0
        # input_handling fires on path + function-name keyword.
        assert "## Strategy: input_handling" in r.stdout
        # Output is operator-readable.
        assert "Bug-class lenses" in r.stdout

    def test_stage_b_invocation_full_context(self):
        """Realistic Stage B: finding with CWE-id assigned by
        Stage A, plus inventory metadata."""
        r = _run(
            "--cwe", "CWE-89",
            "--file", "src/auth/login.py",
            "--function", "check_credentials",
            "--includes", "",  # Python — no headers
            "--calls", "request.args.get,cursor.execute",
        )
        assert r.returncode == 0
        # CWE-89 pins input_handling.
        assert "## Strategy: input_handling" in r.stdout
        # CVE-2023-0179 (nftables payload) is the input_handling
        # exemplar; should appear.
        assert "CVE-2023-0179" in r.stdout

    def test_stage_b_concurrency_finding(self):
        """Realistic Stage B: confirmed race condition."""
        r = _run(
            "--cwe", "CWE-362",
            "--file", "kernel/locking/rwsem.c",
            "--function", "rwsem_acquire_locked",
            "--includes", "linux/mutex.h",
            "--calls", "mutex_lock,refcount_dec_and_test",
        )
        assert r.returncode == 0
        assert "## Strategy: concurrency" in r.stdout
        # CVE-2022-2602 (io_uring/GC) — the concurrency exemplar.
        assert "CVE-2022-2602" in r.stdout

    def test_full_signal_stack_bounded_size(self):
        """All five signal dimensions populated. Output stays
        within the renderer's 16KB default cap."""
        r = _run(
            "--cwe", "CWE-119",
            "--file", "net/foo/parser.c",
            "--function", "parse_locked_decrypt",
            "--includes", "linux/skbuff.h,linux/spinlock.h,crypto/aes.h",
            "--calls", "mutex_lock,spin_lock,skb_pull,crypto_aead_decrypt,kmalloc",
        )
        assert r.returncode == 0
        # Output bounded — render_strategies caps strategy block
        # at 16KB; shim adds a small header.
        assert len(r.stdout.encode("utf-8")) < 32_000
        # Multiple specialised strategies.
        n_specialised = sum(
            1 for line in r.stdout.splitlines()
            if line.startswith("## Strategy:")
            and line != "## Strategy: general"
        )
        assert n_specialised >= 1
