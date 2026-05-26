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
from pathlib import Path
from typing import Dict


class RefitApplyError(RuntimeError):
    """Raised when a refit can't be applied cleanly."""


_CONSTANT_LINE_RE = re.compile(
    r"^(?P<indent>\s*)"
    r"(?P<name>_[A-Z][A-Z0-9_]*)"
    r"\s*=\s*"
    r"(?P<value>[+-]?\d+(?:\.\d+)?)"
    r"(?P<rest>.*)$"
)


def apply_refit_to_risk_py(
    proposed_values: Dict[str, float],
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
    if not risk_py_path.is_file():
        raise RefitApplyError(
            f"risk.py not found at {risk_py_path}",
        )
    text = risk_py_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    found: Dict[str, int] = {}
    for i, line in enumerate(lines):
        m = _CONSTANT_LINE_RE.match(line)
        if m and m.group("name") in proposed_values:
            found[m.group("name")] = i

    missing = set(proposed_values) - set(found)
    if missing:
        raise RefitApplyError(
            f"constants not found in {risk_py_path}: "
            f"{sorted(missing)}"
        )

    modified = 0
    for name, line_idx in found.items():
        new_value = proposed_values[name]
        m = _CONSTANT_LINE_RE.match(lines[line_idx])
        assert m is not None
        old_value = float(m.group("value"))
        if old_value == new_value:
            continue
        formatted = _format_value(new_value)
        new_line = (
            f"{m.group('indent')}{m.group('name')} = "
            f"{formatted}{m.group('rest')}"
        )
        # Preserve trailing newline shape.
        if lines[line_idx].endswith("\n"):
            new_line = new_line + "\n"
        lines[line_idx] = new_line
        modified += 1

    if modified:
        risk_py_path.write_text("".join(lines), encoding="utf-8")
    return modified


def _format_value(v: float) -> str:
    """Render a float with at most 4 decimal places. Integer
    values stay integer-shaped; ``1.20`` formats as ``1.2``."""
    # Round to 4 decimals so refits don't introduce float-noise
    # like 1.0800000000000001.
    rounded = round(v, 4)
    if rounded == int(rounded):
        return f"{int(rounded)}.0"
    return f"{rounded:g}"


__all__ = ["RefitApplyError", "apply_refit_to_risk_py"]
