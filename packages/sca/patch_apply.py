"""Apply a generated upgrade patch to the operator's tree.

Shared by ``raptor-sca fix --harden --apply`` and ``raptor-sca fix --cve-only --apply``. Both
emit a git-flavoured unified diff during their respective plan
phases; this module is the small "actually run ``git apply``" step
that comes after.

Refusal policy: target MUST be a git checkout. Without ``.git`` we
can't roll back, and applying changes to a non-versioned tree is a
foot-gun (operator can't easily diff what changed). The error
message points the operator at the patch file so they can apply
manually if they understand the trade-off.

Sandbox posture: the target's ``.git/config`` is attacker-
controllable on an untrusted clone — git evaluates
``core.fsmonitor`` / ``core.sshCommand`` / ``core.gitProxy`` etc.
at startup and will exec arbitrary commands per their value. The
``git apply`` therefore routes through
``core.sandbox.context.run_untrusted`` — same containment posture
as harden's ``--self-test`` git calls (network blocked at the
namespace level, reads restricted, no $HOME, strict env with the
trust markers stripped, writes limited to the target checkout) —
so a malicious ``.git/config`` can only escalate to "code exec
inside the sandbox".
"""

from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def apply_patch_to_target(
    target: Path,
    patch_path: Path | None,
    *,
    caller_label: str = "sca",
    timeout: int = 60,
) -> int:
    """Run ``git apply`` against ``target`` for ``patch_path``.

    Args:
        target: project root the patch was generated against. Must
            be a git checkout (we look for ``.git``).
        patch_path: path to the unified diff. ``None`` is a graceful
            no-op (some plan paths produce nothing patchable, which
            isn't an error).
        caller_label: subcommand prefix for log lines (``"raptor-sca fix --harden"``
            or ``"raptor-sca fix --cve-only"``); helps operators read CI output.
        timeout: ``git apply`` timeout in seconds.

    Returns:
        0 on clean apply (or a no-op no-patch case).
        4 if target isn't a git checkout (refused before invocation).
        5 if the subprocess itself failed to start.
        Otherwise the non-zero exit code from ``git apply``.
    """
    if patch_path is None or not patch_path.exists():
        print(f"{caller_label} --apply: no patch generated; nothing to apply.")
        return 0
    if not (target / ".git").exists():
        print(
            f"{caller_label} --apply: target {target} is not a git checkout; "
            f"refusing to apply (no rollback path). The patch is at "
            f"{patch_path}; apply manually if you understand the risk.",
            file=sys.stderr,
        )
        return 4

    try:
        from core.sandbox.context import run_untrusted

        # The patch lives in the run's out_dir, which is outside the
        # sandbox's readable set — read it here and feed via stdin
        # (``git apply -``) so the sandbox never needs read access to
        # out_dir. Same technique as harden's ``--self-test`` apply.
        patch_text = patch_path.read_text(encoding="utf-8")
        # Scratch dir for the sandbox's fake $HOME / temp files —
        # keeping ``output=`` off the target means no ``.home/``
        # litter lands in the operator's tree. Writes are scoped to
        # the target checkout (worktree + ``.git``) via
        # ``writable_paths``; run_untrusted pins the network off and
        # supplies the strict, trust-marker-stripped environment
        # itself. The default ('full') profile keeps the caller-
        # visible failure contract identical: a spawn failure is
        # still an OSError/SubprocessError mapping to rc 5 below,
        # never an abort that skips the exit-code translation.
        with tempfile.TemporaryDirectory(
                prefix="raptor-sca-apply-") as sandbox_out:
            proc = run_untrusted(
                ["git", "apply", "-"],
                target=str(target),
                output=sandbox_out,
                writable_paths=[str(target)],
                cwd=str(target),
                input=patch_text,
                capture_output=True, text=True, timeout=timeout,
                caller_label="sca-patch-apply/git-apply",
            )
    except (subprocess.SubprocessError, OSError) as e:
        print(f"{caller_label} --apply: git apply failed: {e}",
              file=sys.stderr)
        return 5

    if proc.returncode != 0:
        print(f"{caller_label} --apply: git apply rejected the patch:",
              file=sys.stderr)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        return proc.returncode

    print(f"{caller_label} --apply: patch applied to {target}")
    return 0


__all__ = ["apply_patch_to_target"]
