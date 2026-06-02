"""Shared SPDX-expression primitives.

SPDX-2.0 license expressions take one of two forms:

  * a single identifier — ``MIT``, ``Apache-2.0``, ``GPL-3.0-or-later``
  * a compound expression — ``MIT OR Apache-2.0``,
    ``GPL-3.0 WITH Classpath-exception-2.0``, etc.

Two consumers today:

  * ``packages/sca/license.py`` — validates compound expressions
    returned by registry-metadata enrichment (PyPI / npm / crates),
    so the policy engine can detect ''MIT OR Apache-2.0''-style
    multi-license declarations rather than dropping them as
    free-text.
  * ``core/license/detector.py`` — handles compound SPDX-Identifier
    headers in LICENSE files (e.g. the Rust-ecosystem
    ``SPDX-License-Identifier: MIT OR Apache-2.0`` convention).
    Without compound handling, the detector would either drop the
    file's classification entirely or misread one operand.

The validator is permissive on operand identifiers — it checks
*shape*, not membership in the canonical SPDX list — so the
caller's classification step (operator policy in SCA's case;
OSS / proprietary allowlist in the detector's case) stays
authoritative.
"""

from __future__ import annotations

import re
from typing import List


# Grammar: ``<id> (AND|OR|WITH) <id> ...``. Operand characters per
# SPDX-2.0 §A.1 (license-id-char): alphanumerics + ``.``, ``+``,
# ``-``. No parentheses (simple grammar — nested expressions like
# ``(MIT OR Apache-2.0) AND BSD-3-Clause`` aren't supported by
# either consumer today).
_SPDX_EXPR_RE = re.compile(
    r"^[A-Za-z0-9.+\-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+\-]+)+$"
)

# Operands are split on whitespace-surrounded AND/OR/WITH so we can
# walk each license id individually. WITH attaches an *exception*
# to the preceding id (e.g. ``GPL-3.0 WITH Classpath-exception-2.0``
# means GPL-3.0 + the Classpath exception clause); callers
# typically want the principal license id, which is the FIRST
# operand of a ``X WITH Y`` form.
_OPERATOR_SPLIT_RE = re.compile(r"\s+(?:AND|OR|WITH)\s+")


def looks_like_spdx_expression(text: str) -> bool:
    """True when ``text`` matches the SPDX-2.0 compound expression
    grammar: ``<id> (AND|OR|WITH) <id> ...``.

    Permissive: doesn't validate that the ids are real SPDX
    identifiers, just that the *shape* is right. Aim is to accept
    forms like ``"Apache-2.0 AND MIT"`` while still rejecting
    free-text descriptions like ``"see LICENSE file"``.
    """
    return bool(_SPDX_EXPR_RE.match(text.strip()))


def split_compound_expression(text: str) -> List[str]:
    """Split a compound SPDX expression into operand identifiers.

    Returns an empty list when ``text`` isn't a recognised compound
    expression (so callers can fall back to single-id handling).
    Operand order is preserved; whitespace is stripped.
    Examples::

        >>> split_compound_expression("MIT OR Apache-2.0")
        ['MIT', 'Apache-2.0']
        >>> split_compound_expression("GPL-3.0 WITH Classpath-exception-2.0")
        ['GPL-3.0', 'Classpath-exception-2.0']
        >>> split_compound_expression("MIT")  # not compound
        []
        >>> split_compound_expression("see LICENSE file")  # not SPDX
        []
    """
    text = text.strip()
    if not looks_like_spdx_expression(text):
        return []
    return [tok.strip() for tok in _OPERATOR_SPLIT_RE.split(text) if tok.strip()]


__all__ = [
    "looks_like_spdx_expression",
    "split_compound_expression",
]
