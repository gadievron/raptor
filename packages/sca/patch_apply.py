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
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def apply_patch_to_target(
    target: Path,
    patch_path: Optional[Path],
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
        proc = subprocess.run(
            ["git", "apply", str(patch_path)],
            cwd=str(target),
            capture_output=True, text=True, timeout=timeout,
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
