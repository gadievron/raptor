"""PEP 440 version comparator (Python).

Delegates to the `packaging` library when available — it's the reference
implementation used by pip itself and is the only sensible source of
truth for PEP 440 ordering.

Falls back to a minimal comparator for the common subset (X.Y.Z[aN|bN|rcN])
when `packaging` isn't installed, so /sca isn't blocked at import time
in stripped-down environments. The fallback is documented as best-effort
and emits a warning.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from packaging.version import InvalidVersion, Version
    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False
    logger.warning(
        "sca.versions.pep440: 'packaging' library not available; "
        "falling back to minimal PEP 440 comparator. Install 'packaging' "
        "for canonical behaviour."
    )

from . import VersionError                                # noqa: E402


def compare(a: str, b: str) -> int:
    """Return -1, 0, 1 per PEP 440 ordering.

    Raises ``VersionError`` (a ``ValueError`` subclass) when either input
    is unparseable — mirrors the contract documented on
    ``versions.compare`` so callers can catch the package-wide error
    rather than the underlying library's exception.
    """
    if a == b:
        return 0
    if _HAS_PACKAGING:
        try:
            va = Version(a)
            vb = Version(b)
        except InvalidVersion as e:
            raise VersionError(f"invalid PEP 440 version: {e}") from e
        if va == vb:
            return 0
        return -1 if va < vb else 1
    try:
        return _fallback_compare(a, b)
    except ValueError as e:
        raise VersionError(str(e)) from e


# ---------------------------------------------------------------------------
# Fallback comparator — covers X.Y.Z[aN|bN|rcN][.postN][.devN] adequately.
# Operators with weird versions (epochs, local versions, post-pre) should
# install `packaging` for correct results.
# ---------------------------------------------------------------------------

_FALLBACK_RE = re.compile(
    r"""
    ^
    (?P<release>\d+(?:\.\d+)*)
    (?:(?P<pre_l>a|b|c|rc|alpha|beta|pre)(?P<pre_n>\d+))?
    (?:\.post(?P<post>\d+))?
    (?:\.dev(?P<dev>\d+))?
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Pre-release label normalisation.
_PRE_NORMALISE = {
    "a": "a", "alpha": "a",
    "b": "b", "beta": "b",
    "c": "rc", "rc": "rc", "pre": "rc",
}


def _fallback_compare(a: str, b: str) -> int:
    pa = _fallback_parse(a)
    pb = _fallback_parse(b)
    # release tuple
    ra, rb = pa[0], pb[0]
    # Pad shorter with zeros for component-wise compare.
    longest = max(len(ra), len(rb))
    ra = ra + (0,) * (longest - len(ra))
    rb = rb + (0,) * (longest - len(rb))
    if ra != rb:
        return -1 if ra < rb else 1
    # Dev release < pre-release < release < post-release.
    # Ordering tuple: (has_dev_n_or_max, pre_or_none, post_or_none).
    # Build a comparable key.
    def keyof(p):
        release, pre, post, dev = p
        # dev makes a version "lower" than the same release with no pre.
        # pre similar.
        # Convention: assign small integers to release/pre/post categories.
        # cat: 0 = .devN, 1 = preN.devN, 2 = preN, 3 = release, 4 = postN
        if dev is not None and pre is None:
            cat = 0
        elif pre is not None and dev is not None:
            cat = 1
        elif pre is not None:
            cat = 2
        elif post is not None:
            cat = 4
        else:
            cat = 3
        # within-category subkey
        pre_label_order = {"a": 0, "b": 1, "rc": 2}
        sub = (
            pre_label_order.get(pre[0]) if pre else None,
            pre[1] if pre else None,
            post or 0,
            dev or 0,
        )
        return (cat, sub)
    ka = keyof(pa)
    kb = keyof(pb)
    if ka == kb:
        return 0
    # Tuple compare: handles None safely if all positions match shape.
    # We need a total order; simple approach: stringify None as -1.
    def tup_safe(t):
        return tuple(-1 if v is None else v for v in t[1])
    if ka[0] != kb[0]:
        return -1 if ka[0] < kb[0] else 1
    return -1 if tup_safe(ka) < tup_safe(kb) else 1


def _fallback_parse(v: str) -> Tuple[Tuple[int, ...],
                                      Optional[Tuple[str, int]],
                                      Optional[int],
                                      Optional[int]]:
    """Best-effort parse for the X.Y.Z[aN|bN|rcN][.postN][.devN] subset."""
    m = _FALLBACK_RE.match(v.strip())
    if not m:
        raise ValueError(f"unparseable PEP 440 (fallback): {v!r}")
    release = tuple(int(x) for x in m.group("release").split("."))
    pre = None
    if m.group("pre_l") is not None:
        label = _PRE_NORMALISE[m.group("pre_l").lower()]
        pre = (label, int(m.group("pre_n")))
    post = int(m.group("post")) if m.group("post") else None
    dev = int(m.group("dev")) if m.group("dev") else None
    return release, pre, post, dev
