"""
core/security/tests/test_held_trust_verdict.py

Pins for the HELD trust-verdict handle (``HeldTrustVerdict``) and the
two gate entry points that produce it (``open_cc_trust_check``,
``open_codeql_trust_check``).

The bool checks (``check_repo_claude_trust`` /
``check_repo_codeql_trust``) release their verdict and close their
observation fd, leaving a documented post-return window: the verdict
is keyed to the target SPELLING, and a swap landing between the
check's final bracket and the consumer's dispatch re-aims that
spelling at an unexamined tree. The handle closes that gap by keeping
the fd open so the CONSUMER can re-bracket (``recheck()``) immediately
before spawning. These pins fix the handle's contract:

  * wrapper equivalence — the bool checks ARE the handle's verdict;
  * recheck is refuse-only and catches a post-verdict swap;
  * the trust override downgrades the recheck to warn-and-proceed;
  * recheck after close fails CLOSED (fd numbers are reused);
  * a handle that never held an fd keeps its original verdict;
  * close is idempotent, the CM closes, and a leaked handle's fd is
    released by the GC finalizer belt.
"""

from __future__ import annotations

import gc
import os
from pathlib import Path

import pytest

from core.security.cc_trust import (
    check_repo_claude_trust,
    open_cc_trust_check,
)
from core.security.codeql_trust import (
    check_repo_codeql_trust,
    open_codeql_trust_check,
)

# (open function, bool wrapper, subject string, dangerous-config plant)
_GATES = [
    pytest.param(
        open_cc_trust_check, check_repo_claude_trust,
        "Claude Code config",
        lambda t: (t / ".mcp.json").write_text(
            '{"mcpServers": {"x": {"command": "evil"}}}'),
        id="cc_trust",
    ),
    pytest.param(
        open_codeql_trust_check, check_repo_codeql_trust,
        "CodeQL pack config",
        lambda t: (t / "qlpack.yml").write_text(
            "name: attacker/evil\nextractor: ./evil\n"),
        id="codeql_trust",
    ),
]


def _clean_target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    return target


def _swap_spelling(target: Path, tmp_path: Path) -> None:
    """Move the examined tree aside and plant a FRESH directory at the
    same spelling — the post-verdict TOCTOU the recheck exists for."""
    os.rename(target, tmp_path / "swapped-aside")
    target.mkdir()


class TestWrapperEquivalence:

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_verdicts_match_probe_by_probe(self, open_check, bool_check,
                                           subject, plant, tmp_path):
        clean = _clean_target(tmp_path)
        dirty = tmp_path / "dirty"
        dirty.mkdir()
        plant(dirty)
        probes = [str(clean), str(dirty),
                  str(tmp_path / "gone"), ""]
        for probe in probes:
            with open_check(probe, trust_override=False) as held:
                held_verdict = held.refused
            assert held_verdict == bool_check(
                probe, trust_override=False), (
                f"handle and bool verdicts disagree on {probe!r}")

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_override_downgrade_matches(self, open_check, bool_check,
                                        subject, plant, tmp_path):
        dirty = _clean_target(tmp_path)
        plant(dirty)
        with open_check(str(dirty), trust_override=True) as held:
            assert held.refused is False
        assert bool_check(str(dirty), trust_override=True) is False


class TestRecheck:

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_stable_target_rechecks_clean(self, open_check, bool_check,
                                          subject, plant, tmp_path,
                                          capsys):
        target = _clean_target(tmp_path)
        with open_check(str(target), trust_override=False) as held:
            assert held.refused is False
            assert held.recheck() is False
            # Refuse-only: a repeat against the unchanged inode stays
            # clean too.
            assert held.recheck() is False
        assert "treating as dangerous" not in capsys.readouterr().out

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_post_verdict_swap_refused(self, open_check, bool_check,
                                       subject, plant, tmp_path, capsys):
        target = _clean_target(tmp_path)
        with open_check(str(target), trust_override=False) as held:
            assert held.refused is False
            _swap_spelling(target, tmp_path)
            assert held.recheck() is True
        out = capsys.readouterr().out
        assert "changed during" in out
        assert subject in out
        assert "treating as dangerous" in out

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_swap_recheck_downgrades_under_override(
            self, open_check, bool_check, subject, plant, tmp_path,
            capsys):
        target = _clean_target(tmp_path)
        with open_check(str(target), trust_override=True) as held:
            assert held.refused is False
            _swap_spelling(target, tmp_path)
            assert held.recheck() is False
        out = capsys.readouterr().out
        assert "changed during" in out
        assert "trust override active" in out

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_refused_handle_rechecks_refused(self, open_check,
                                             bool_check, subject, plant,
                                             tmp_path):
        with open_check(str(tmp_path / "gone"),
                        trust_override=False) as held:
            assert held.refused is True
            assert held.recheck() is True

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_recheck_after_close_fails_closed(self, open_check,
                                              bool_check, subject, plant,
                                              tmp_path, capsys):
        target = _clean_target(tmp_path)
        held = open_check(str(target), trust_override=False)
        assert held.refused is False
        held.close()
        # The fd number may already denote an unrelated object —
        # rechecking a closed handle is a caller bug and must refuse,
        # loudly, even though the target itself never moved.
        assert held.recheck() is True
        out = capsys.readouterr().out
        assert "after the held observation fd was closed" in out
        assert "treating as dangerous" in out

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_no_fd_handle_keeps_verdict_across_close(
            self, open_check, bool_check, subject, plant, capsys):
        # Empty path: documented no-op contract — nothing supplied,
        # nothing held. There never was an identity to re-compare, so
        # close must NOT flip the stored verdict to a refusal.
        held = open_check("", trust_override=False)
        assert held.refused is False
        assert held.recheck() is False
        held.close()
        assert held.recheck() is False
        assert capsys.readouterr().out == ""


class TestLifetime:

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_close_is_idempotent(self, open_check, bool_check, subject,
                                 plant, tmp_path):
        target = _clean_target(tmp_path)
        held = open_check(str(target), trust_override=False)
        held.close()
        held.close()  # second close must be a no-op, not EBADF

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_context_manager_closes(self, open_check, bool_check,
                                    subject, plant, tmp_path):
        target = _clean_target(tmp_path)
        with open_check(str(target), trust_override=False) as held:
            fd = held._fd
            assert fd is not None
            os.fstat(fd)  # live inside the CM
        assert held._fd is None
        with pytest.raises(OSError):
            os.fstat(fd)

    @pytest.mark.parametrize(("open_check", "bool_check", "subject",
                              "plant"), _GATES)
    def test_leaked_handle_fd_released_by_finalizer(
            self, open_check, bool_check, subject, plant, tmp_path):
        target = _clean_target(tmp_path)
        held = open_check(str(target), trust_override=False)
        fd = held._fd
        assert fd is not None
        del held
        gc.collect()
        with pytest.raises(OSError):
            os.fstat(fd)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
