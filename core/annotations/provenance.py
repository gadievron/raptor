"""Invocation-context provenance for annotations.

``metadata.source`` is caller-asserted and always has been: any
process that can run the annotate CLI can claim ``source=human``.
RAPTOR deliberately does not attempt cryptographic proof-of-human —
rejected as overkill for an operator CLI. Instead, every add / edit
records the *invocation context*: which of stdin / stdout / stderr
were TTYs at write time. That makes a laundered "human" annotation
structurally **detectable, not impossible**: an agent-spawned
process has every fd piped, and the stamp it cannot avoid recording
contradicts the source it asserts.

On-disk keys (written into the meta comment by the CLI):

  * ``tty`` — comma-joined names of the standard fds that were TTYs
    (``stdin,stderr``), or ``none`` when no fd was a TTY.
  * ``provenance`` — the derived context tag:
    ``interactive-tty`` when ANY of the three fds was a TTY,
    ``non-tty`` when none was.

The any-fd predicate keeps legitimate terminal workflows
interactive: ``raptor-annotate add ... < notes.txt`` (stdin is a
file, stdout/stderr still TTYs) and ``... | tee`` both stamp
``interactive-tty``; an agent-spawned subprocess with all three fds
piped stamps ``non-tty``.

Grading (what readers do with the stamp):

  * **human-grade** — ``source=human`` AND the stamp is
    ``interactive-tty``. Elevated-weight readers (Reflexion veto,
    FP primers, coverage evidence, IRIS spec promotion) require
    this grade.
  * **legacy** — no stamp at all: written before provenance was
    recorded. Treated as human-grade when ``source=human``: the
    write-path audit found zero mechanical writers at HEAD, so the
    pre-stamp corpus is operator-authored, and demoting it would
    erase real operator review. New CLI writes always carry the
    stamp, so "legacy" also identifies notes that bypassed the CLI.
  * everything else — machine / hint tier. ``source=agent``,
    ``source=llm``, and human-claimed-but-non-tty all demote; the
    annotation stays useful at the reader's lower tier, it just
    doesn't carry operator authority.

Rare legitimate demotion: a human running the CLI fully detached
(cron, all three fds redirected) stamps ``non-tty`` even with an
explicit ``--source human``. Remedy: re-run the add interactively,
or accept hint-tier weight.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping

# Context tags carried in ``metadata.provenance``.
INTERACTIVE_TTY = "interactive-tty"
NON_TTY = "non-tty"
# Classification (never written to disk) for annotations that predate
# the stamp.
LEGACY = "legacy"

# Metadata keys the CLI records. Reserved: callers may not set them
# via ``--meta`` (the CLI computes them from the live fds).
TTY_KEY = "tty"
PROVENANCE_KEY = "provenance"
PROVENANCE_KEYS = (TTY_KEY, PROVENANCE_KEY)

_STD_FDS = ("stdin", "stdout", "stderr")
_TTY_NONE = "none"


def _isatty(stream) -> bool:
    """True when *stream* exists and reports a TTY. Detached or
    closed streams (``sys.stdin is None`` under pythonw, closed fds)
    count as non-TTY."""
    try:
        return stream is not None and stream.isatty()
    except (OSError, ValueError):
        return False


def detect_invocation_context() -> dict[str, str]:
    """Record the current process's invocation context.

    Returns the two provenance metadata keys: ``tty`` (which of
    stdin/stdout/stderr are TTYs, ``none`` when zero) and
    ``provenance`` (``interactive-tty`` when any fd is a TTY,
    ``non-tty`` otherwise).
    """
    ttys = [
        name
        for name, stream in (
            ("stdin", sys.stdin),
            ("stdout", sys.stdout),
            ("stderr", sys.stderr),
        )
        if _isatty(stream)
    ]
    return {
        TTY_KEY: ",".join(ttys) if ttys else _TTY_NONE,
        PROVENANCE_KEY: INTERACTIVE_TTY if ttys else NON_TTY,
    }


def valid_tty_value(value: str) -> bool:
    """Whether *value* is a well-formed ``tty`` metadata value:
    ``none`` or a comma-joined non-empty subset of
    ``stdin,stdout,stderr`` (no duplicates)."""
    if value == _TTY_NONE:
        return True
    parts = value.split(",")
    return (
        len(parts) > 0
        and len(set(parts)) == len(parts)
        and all(p in _STD_FDS for p in parts)
    )


def classify_provenance(metadata: Mapping[str, str] | None) -> str:
    """Classify a stored annotation's invocation context.

    Returns ``interactive-tty``, ``non-tty``, or ``legacy``:

      * a recognised ``provenance`` tag wins;
      * otherwise a well-formed ``tty`` key is interpreted directly
        (any fd listed → interactive);
      * an unrecognised value in either key is *not* trusted and
        classifies as ``non-tty`` (fail toward the lower tier);
      * no stamp at all → ``legacy`` (pre-stamp annotation).
    """
    if not metadata:
        return LEGACY
    tag = metadata.get(PROVENANCE_KEY)
    if tag in (INTERACTIVE_TTY, NON_TTY):
        return tag
    tty = metadata.get(TTY_KEY)
    if tty is not None and valid_tty_value(tty):
        return NON_TTY if tty == _TTY_NONE else INTERACTIVE_TTY
    if tag is not None or tty is not None:
        # A stamp key exists but carries garbage — someone tampered
        # or a producer is broken. Never grant the elevated tier.
        return NON_TTY
    return LEGACY


def is_human_grade(metadata: Mapping[str, str] | None) -> bool:
    """Whether an annotation earns human-grade weight.

    Requires ``source=human`` AND an interactive-TTY stamp — or no
    stamp at all (legacy benefit-of-doubt, see the module docstring).
    ``source=agent`` / ``source=llm``, and ``source=human`` with a
    ``non-tty`` stamp (the laundering shape), do not qualify.
    """
    if not metadata or metadata.get("source") != "human":
        return False
    return classify_provenance(metadata) in (INTERACTIVE_TTY, LEGACY)
