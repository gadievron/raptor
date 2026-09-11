"""Shared sha-verification for pinned recall-corpus clones.

Every recall corpus is an INTERNET-SOURCED clone the operator acquired
with ``git clone``, so its ``.git/config`` is untrusted: hostile
entries (``core.fsmonitor``, ``core.hooksPath``, pager/diff drivers)
execute attacker commands on ordinary git operations — and the
sha-verify runs BEFORE the pin check, i.e. on wholly-unverified
content. The rev-parse therefore goes through the strict read-only
argv (:func:`core.git.safe_git_readonly_command`) with the sanitised
git env (:func:`core.git.get_safe_git_env`), the same posture as the
cvefix bridge's git plumbing.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from core.git import get_safe_git_env, safe_git_readonly_command

if TYPE_CHECKING:
    from pathlib import Path

_FULL_SHA_LEN = 40


def verify_pinned_clone(clone_dir: Path, pinned_sha: str, *,
                        error_cls: type[Exception],
                        hint: str = "") -> str:
    """Require *clone_dir*'s HEAD to match *pinned_sha*; return HEAD.

    A full 40-hex pin requires exact equality; a shorter pin (the
    manifest schema accepts >= 7 hex) is accepted as a prefix of HEAD.
    Every failure raises *error_cls* so each caller keeps its own
    exception surface. *hint* (re-acquire instructions) is appended to
    the mismatch message.
    """
    pinned = pinned_sha.lower()
    try:
        proc = subprocess.run(
            safe_git_readonly_command("-C", str(clone_dir),
                                      "rev-parse", "HEAD"),
            capture_output=True, text=True, timeout=60, check=False,
            env=get_safe_git_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"cannot sha-verify {clone_dir}: {exc}"
        raise error_cls(msg) from exc
    head = proc.stdout.strip().lower()
    if proc.returncode != 0 or not head:
        msg = f"cannot sha-verify {clone_dir}: {proc.stderr.strip()}"
        raise error_cls(msg)
    matched = (head == pinned if len(pinned) == _FULL_SHA_LEN
               else head.startswith(pinned))
    if not matched:
        msg = (
            f"{clone_dir} is at {head[:12]}, labels are pinned to "
            f"{pinned[:12]} — labels are invalid against this tree; "
            "re-checkout the pinned sha"
        )
        if hint:
            msg += f" ({hint})"
        raise error_cls(msg)
    return head


__all__ = ["verify_pinned_clone"]
