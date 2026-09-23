"""In-place patcher for ``risk.py``'s tunable multiplier constants.

When the refitter (``packages.sca.calibration.refit``) emits a
``RefitReport`` with status ``"proposed"``, this module rewrites
the matching constant lines in ``packages/sca/risk.py`` to the
new values. Used by the ``refit-sca-calibration.yml`` workflow
to apply the refit before opening the auto-PR.

## Format invariants

The substitution targets lines of the form:

    _NAME = <number>[<optional rest-of-line>]

where ``<optional rest-of-line>`` is typically a unit comment.
Substitution preserves leading whitespace + comments. Numbers
are formatted with at most 4 decimal places to keep the diff
readable.

## Idempotency

Applying the same proposed values twice produces identical
source — the substitution is value-driven, not history-aware.
A second apply for an already-applied refit is a no-op.

## Defensive

Failures (constant not found, line malformed, file unreadable)
raise :class:`RefitApplyError`. The CLI surfaces the error;
operators inspect the source manually.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from core.atomic_fs import write_text_atomically

if TYPE_CHECKING:
    from pathlib import Path


class RefitApplyError(RuntimeError):
    """Raised when a refit can't be applied cleanly."""


# Anchored to column 0: module-level constant assignments only. An
# indented lookalike (a doc example, a nested assignment) must never
# absorb the update meant for the real constant.
_CONSTANT_LINE_RE = re.compile(
    r"^(?P<name>_[A-Z][A-Z0-9_]*)"
    r"\s*=\s*"
    r"(?P<value>[+-]?\d+(?:\.\d+)?)"
    r"(?P<rest>.*)$"
)


def apply_refit_to_risk_py(
    proposed_values: dict[str, float],
    risk_py_path: Path,
) -> int:
    """Rewrite each constant in ``proposed_values`` to its new
    value in ``risk_py_path``. Returns the count of lines
    modified.

    Idempotent: applying the same dict twice produces identical
    source. Constants in the dict but not present in the source
    raise :class:`RefitApplyError` rather than silently no-op
    (an operator would expect every entry to land).
    """
    if not proposed_values:
        return 0
    # Membership gate: the refit report is this function's INPUT
    # (a corrupted or hand-edited report reaches here unchecked in
    # the auto-PR workflow) — without it, any _SHOUTY name in the
    # dict turns the patcher into an arbitrary-constant rewriter of
    # production scoring source.
    from packages.sca.risk import TUNABLE_CONSTANTS
    strays = set(proposed_values) - set(TUNABLE_CONSTANTS)
    if strays:
        msg = (
            f"proposed constants not in TUNABLE_CONSTANTS: "
            f"{sorted(strays)}"
        )
        raise RefitApplyError(msg)
    if not risk_py_path.is_file():
        msg = f"risk.py not found at {risk_py_path}"
        raise RefitApplyError(msg)
    text = risk_py_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    found: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = _CONSTANT_LINE_RE.match(line)
        if m and m.group("name") in proposed_values:
            name = m.group("name")
            if name in found:
                # Refuse rather than guess: patching the LAST match
                # silently left the real constant unchanged when a
                # duplicate-named line appeared later in the file.
                msg = (
                    f"duplicate assignment lines for {name} in "
                    f"{risk_py_path} (lines {found[name] + 1} and "
                    f"{i + 1}) — refusing to guess which to patch"
                )
                raise RefitApplyError(msg)
            found[name] = i

    missing = set(proposed_values) - set(found)
    if missing:
        msg = (
            f"constants not found in {risk_py_path}: "
            f"{sorted(missing)}"
        )
        raise RefitApplyError(msg)

    modified = 0
    for name, line_idx in found.items():
        new_value = proposed_values[name]
        m = _CONSTANT_LINE_RE.match(lines[line_idx])
        assert m is not None
        old_value = float(m.group("value"))
        if old_value == round(new_value, 4):
            continue
        formatted = _format_value(new_value)
        new_line = (
            f"{m.group('name')} = "
            f"{formatted}{m.group('rest')}"
        )
        # Preserve trailing newline shape.
        if lines[line_idx].endswith("\n"):
            new_line = new_line + "\n"
        lines[line_idx] = new_line
        modified += 1

    if modified:
        # Atomic: this rewrites PRODUCTION source in the auto-PR
        # workflow — an interrupt mid-write must not leave a truncated
        # risk.py for a blind commit step to ship.
        write_text_atomically(risk_py_path, "".join(lines))
    return modified


def _format_value(v: float) -> str:
    """Render a float with at most 4 decimal places, always in
    fixed-point notation. Integer values stay integer-shaped;
    ``1.20`` formats as ``1.2``.

    ``%g`` is deliberately avoided: it switches large non-integers
    to scientific notation (``1234567.5`` → ``1.23457e+06``), which
    the constant-line regex then SILENTLY mis-splits into
    value=``1.23457`` / rest=``e+06`` on a later re-apply —
    corrupting the constant instead of erroring.
    """
    # Round to 4 decimals so refits don't introduce float-noise
    # like 1.0800000000000001.
    rounded = round(v, 4)
    if rounded == int(rounded):
        return f"{int(rounded)}.0"
    return f"{rounded:.4f}".rstrip("0")


__all__ = ["RefitApplyError", "apply_refit_to_risk_py"]
