"""Java compatibility entry for the shared negative control-scope check."""
from __future__ import annotations

from core.analysis.validator_control_scope import validator_control_scope_unverified


def java_guard_scope_unverified(source: str, validator_line: int, sink_line: int,
                                *, guard_shaped: bool) -> bool:
    """Refuse unsupported Java source control; False is not dominance proof."""
    return validator_control_scope_unverified(
        source, validator_line, sink_line, guard_shaped=guard_shaped, language="java",
    )
