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
    recorded. Treated as human-grade when ``source=human`` AND the
    note demonstrably predates the stamp era (the caller passes the
    annotation file's mtime and it is older than
    :data:`STAMP_ERA_START`). The write-path audit found zero
    mechanical writers at the stamp-era cut, so the pre-stamp corpus
    is operator-authored, and demoting it would erase real operator
    review. New CLI writes always carry the stamp, so a stamp-less
    note in a file modified AFTER the era began identifies a writer
    that bypassed the CLI — it demotes to hint tier instead of
    inheriting the grandfather clause. Without a caller-supplied
    mtime the fence cannot be established, so stamp-less notes
    demote (fail toward the lower tier).

    The fence is an mtime check, not proof: an attacker who can run
    ``utime`` can backdate a planted file. That is accepted — the
    module's guarantee has always been *detectable, not impossible*
    (see above), and the fence closes the trivial bypass-by-omission
    channel (writing a bare markdown file), forcing forgery through
    a deliberate extra timestamp-tampering step.
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
# Written by the zip-import path onto restored notes that arrived
# stamp-less: the archive severed any provenance the note ever had,
# so the import stamps the channel it came through. Classifies as
# its own tag; never human-grade (hint tier).
IMPORTED = "imported"
# Classification (never written to disk) for annotations that predate
# the stamp.
LEGACY = "legacy"

# When the invocation-context stamp began being recorded (the commit
# that introduced this module landed 2026-08-17T23:55:36Z). The
# LEGACY grandfather clause in :func:`is_human_grade` only applies to
# notes whose annotation file predates this instant — everything
# stamp-less written after it is a CLI bypass, not a pre-stamp note.
# Unix epoch seconds, UTC.
STAMP_ERA_START = 1787010936.0

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

    Returns ``interactive-tty``, ``non-tty``, ``imported``, or
    ``legacy``:

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
    if tag in (INTERACTIVE_TTY, NON_TTY, IMPORTED):
        return tag
    tty = metadata.get(TTY_KEY)
    if tty is not None and valid_tty_value(tty):
        return NON_TTY if tty == _TTY_NONE else INTERACTIVE_TTY
    if tag is not None or tty is not None:
        # A stamp key exists but carries garbage — someone tampered
        # or a producer is broken. Never grant the elevated tier.
        return NON_TTY
    return LEGACY


def is_human_grade(
    metadata: Mapping[str, str] | None,
    *,
    note_mtime: float | None = None,
) -> bool:
    """Whether an annotation earns human-grade weight.

    Requires ``source=human`` AND an interactive-TTY stamp — or no
    stamp at all on a note that demonstrably predates the stamp era
    (legacy benefit-of-doubt, date-fenced: callers pass the
    annotation file's mtime as ``note_mtime``, and the grandfather
    clause applies only when it is older than
    :data:`STAMP_ERA_START`; see the module docstring). Use
    :func:`core.annotations.storage.annotation_file_mtime` to obtain
    it. Without ``note_mtime`` a stamp-less note demotes — the fence
    cannot be established, so fail toward the lower tier.

    ``source=agent`` / ``source=llm``, ``source=human`` with a
    ``non-tty`` stamp (the laundering shape), and ``provenance=
    imported`` (zip-restored, provenance severed) do not qualify.
    """
    if not metadata or metadata.get("source") != "human":
        return False
    tag = classify_provenance(metadata)
    if tag == INTERACTIVE_TTY:
        return True
    return (
        tag == LEGACY
        and note_mtime is not None
        and note_mtime < STAMP_ERA_START
    )
