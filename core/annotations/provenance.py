"""Invocation-context provenance for annotations.

``metadata.source`` is caller-asserted and always has been: any
process that can run the annotate CLI can claim ``source=human``.
RAPTOR deliberately does not attempt cryptographic proof-of-human —
rejected as overkill for an operator CLI. Instead, every add / edit
records the *invocation context* alongside the claim. The fd stamp
alone defeats only the ACCIDENTAL non-interactive claim (an
agent-spawned process with every fd piped): ``isatty`` cannot
distinguish a real terminal from a pseudo-terminal, so a one-line
``script(1)`` / pty wrapper makes the fd stamp genuinely
interactive by design. The stamp is therefore layered with
corroborating context the wrapper does not control as easily —
session-leader shape, agent-session environment markers, a
parent-process chain summary — recorded in full so a laundered
stamp carries auditable inconsistencies instead of silence.

The guarantee remains **no silent forgery, not impossibility**: a
determined local attacker with full user privileges can always fake
a terminal, rename wrapper binaries, and curate the environment.
What the layered stamp buys is (a) the stock laundering routes
either demote (``script -c``, an agent session's own pty) or at
minimum leave their names / a truncation token in the recorded
context, and (b) every human-grade grant rests on a recorded,
operator-auditable context instead of a bare ``isatty`` bit.

On-disk keys (written into the meta comment by the CLI):

  * ``tty`` — comma-joined names of the standard fds that were TTYs
    (``stdin,stderr``), or ``none`` when no fd was a TTY.
  * ``provenance`` — the derived context tag:
    ``interactive-tty`` when ANY of the three fds was a TTY,
    ``non-tty`` when none was.
  * ``sid`` — session-leader shape: ``inherited`` when the process
    runs inside a pre-existing session (every shell-launched
    command), ``self`` when the process IS its own session leader —
    the ``script -qec 'cmd'`` / setsid-wrapper shape, since a shell
    never execs a command as the session leader.
  * ``envm`` — agent-session environment markers present at write
    time (``claudecode`` / ``trusted`` / ``ssh``, or ``none``). An
    in-session agent invocation carries the launcher's marker; a
    bare-shell operator run carries the trusted-dispatch marker.
  * ``parents`` — comma-joined comm names of up to 4 ancestor
    processes (audit trail; ``unknown`` where unavailable; ends with
    the ``ancestry-truncated`` token when the bounded ancestor scan
    exhausted its window before reaching the session root). Readers
    demote on the stock ``script`` wrapper appearing in the chain;
    truncation and the rest of the chain are recorded for the
    operator's audit, not pattern-matched — process names are
    attacker-renameable, and deep-but-legitimate shell stacks exist,
    so truncation alone never demotes (fail-open, visible).
  * ``corroboration`` — ``pre-era`` only: a durable marker a
    rewrite stamps onto sections whose interactive stamp predates
    corroboration recording (see ``CORROBORATION_ERA_START``).

The any-fd predicate keeps legitimate terminal workflows
interactive: ``raptor-annotate add ... < notes.txt`` (stdin is a
file, stdout/stderr still TTYs) and ``... | tee`` both stamp
``interactive-tty``; an agent-spawned subprocess with all three fds
piped stamps ``non-tty``.

Grading (what readers do with the stamp):

  * **human-grade** — ``source=human`` AND the stamp is
    ``interactive-tty`` AND the corroborating context does not
    contradict it (see :func:`is_human_grade`): the process was not
    its own session leader, no agent-session environment marker was
    present, and the recorded parent chain does not show the stock
    ``script`` wrapper. Stamps written before corroboration
    recording began are grandfathered behind
    :data:`CORROBORATION_ERA_START` (mtime-fenced, like the legacy
    clause below; a ``corroboration=pre-era`` marker makes the
    fence outcome durable). Elevated-weight readers (Reflexion
    veto, FP primers, coverage evidence, IRIS spec promotion)
    require this grade.
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

import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path

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
# Durable on-disk form of a PASSING legacy fence: the whole-file
# mtime the fence keys on is destroyed by any sibling rewrite (every
# write path re-renders the whole file) and by a fresh checkout, so a
# rewrite that carries over a stamp-less source=human section whose
# file still predates STAMP_ERA_START materialises the fence outcome
# as an explicit tag readers honour without an mtime. Written only by
# the storage layer's era materialisation (CLI-reserved like the rest
# of the stamp); a hand-written tag is the same acknowledged
# direct-file-write channel as a hand-written interactive stamp.
LEGACY_PRE_ERA = "legacy-pre-era"

# When the invocation-context stamp began being recorded (the commit
# that introduced this module landed 2026-08-17T23:55:36Z). The
# LEGACY grandfather clause in :func:`is_human_grade` only applies to
# notes whose annotation file predates this instant — everything
# stamp-less written after it is a CLI bypass, not a pre-stamp note.
# Unix epoch seconds, UTC.
STAMP_ERA_START = 1787010936.0

# When corroboration recording (sid / envm / parents) began.
# Interactive-tty stamps without corroboration keys are grandfathered
# only when the annotation file predates this instant (same mtime
# fence + acknowledged utime residual as STAMP_ERA_START); everything
# key-less after it is a hand-written stamp, not a CLI write, and
# demotes. Fence direction trade-off: a fence later than the landing
# instant widens the grandfather window a backdater can use; earlier
# would demote legitimate pre-landing notes — legitimate notes are
# unrecoverable, so err late. Unix epoch seconds, UTC.
CORROBORATION_ERA_START = 1790640000.0  # 2026-09-29T00:00:00Z

# Metadata keys the CLI records. Reserved: callers may not set them
# via ``--meta`` (the CLI computes them from the live process
# context; the corroboration marker is written only by the storage
# layer's era materialisation).
TTY_KEY = "tty"
PROVENANCE_KEY = "provenance"
SID_KEY = "sid"
ENV_MARKERS_KEY = "envm"
PARENTS_KEY = "parents"
CORROBORATION_KEY = "corroboration"
PROVENANCE_KEYS = (
    TTY_KEY, PROVENANCE_KEY, SID_KEY, ENV_MARKERS_KEY, PARENTS_KEY,
    CORROBORATION_KEY,
)

# ``sid`` values.
SID_SELF = "self"
SID_INHERITED = "inherited"
SID_UNKNOWN = "unknown"
SID_VALUES = (SID_SELF, SID_INHERITED, SID_UNKNOWN)

# ``envm`` marker names (fixed recording order) + the empty value.
ENV_MARKER_CLAUDECODE = "claudecode"
ENV_MARKER_TRUSTED = "trusted"
ENV_MARKER_SSH = "ssh"
ENV_MARKERS = (ENV_MARKER_CLAUDECODE, ENV_MARKER_TRUSTED, ENV_MARKER_SSH)
_ENV_MARKERS_NONE = "none"

# ``corroboration`` marker: the only recognised value. Written by the
# storage layer when a rewrite carries over a section whose
# interactive stamp verifiably predates CORROBORATION_ERA_START.
CORROBORATION_PRE_ERA = "pre-era"

# ``parents`` value grammar: comma-joined sanitised comm names (or
# the literal ``unknown``). Bounded so a hostile comm can't bloat
# the metadata line.
_PARENTS_VALUE_RE = re.compile(r"[A-Za-z0-9_.,-]{1,128}")
_PARENTS_UNKNOWN = "unknown"
_PARENT_CHAIN_DEPTH = 4
# The walk itself goes deeper than the recorded window: a wrapper
# that stacks fork intermediaries would otherwise push the
# verdict-bearing ``script`` name off the recorded chain. Bounded so
# a pathological process tree can't stall the stamp. The bound is
# FAIL-OPEN by design: a walk that exhausts its window without
# reaching the session root does not demote (deep-but-legitimate
# shell stacks exist) — but it must not be SILENT either, so an
# incomplete walk appends the truncation token below and the
# auditor sees the exhausted window instead of a clean-looking
# four-name chain.
_PARENT_SCAN_DEPTH = 32
# Appended to the recorded chain when the ancestor walk ends before
# reaching the session root (depth exhausted, or an ancestor became
# unreadable mid-walk). Lives inside the parents value grammar and is
# collision-free by construction: kernel comm names are at most 15
# characters (and ``_comm`` truncates to 15), so no real process can
# occupy this 18-character token.
PARENTS_TRUNCATED = "ancestry-truncated"

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


def _detect_sid() -> str:
    """Session-leader shape of the current process.

    A command launched from any shell (bash, sshd's shell, a tmux
    pane) runs inside that shell's session — ``inherited``. The
    ``script -qec 'cmd'`` / setsid-wrapper laundering shape execs
    the command AS the new session's leader — ``self``. Kernel fact,
    not environment: a wrapper cannot unset it without forking an
    intermediate (which then shows in the parent chain)."""
    try:
        return SID_SELF if os.getsid(0) == os.getpid() else SID_INHERITED
    except (OSError, AttributeError):  # pragma: no cover — non-POSIX
        return SID_UNKNOWN


def _detect_env_markers(environ: Mapping[str, str] | None = None) -> str:
    """Agent-session / dispatch environment markers present at write
    time. Recorded in a fixed order for stable output. Spoofable by
    construction (it is the caller's own environment) — the launcher
    marker is load-bearing because the dispatch trust gate requires
    one of the two dispatch markers to run the CLI at all, so an
    in-session agent that scrubs ``claudecode`` must still present
    ``trusted``, and the scrub itself is a deliberate forgery step,
    not an accident."""
    env = os.environ if environ is None else environ
    markers = []
    if env.get("CLAUDECODE"):
        markers.append(ENV_MARKER_CLAUDECODE)
    if env.get("_RAPTOR_TRUSTED"):
        markers.append(ENV_MARKER_TRUSTED)
    if env.get("SSH_TTY") or env.get("SSH_CONNECTION"):
        markers.append(ENV_MARKER_SSH)
    return ",".join(markers) if markers else _ENV_MARKERS_NONE


def _comm(pid: int) -> str | None:
    """Sanitised comm name for *pid*, or None when unreadable."""
    try:
        raw = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8",
                                                  errors="replace")
    except OSError:
        return None
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", raw.strip())[:15]
    return name or "-"


def _detect_parent_chain() -> str:
    """Comma-joined comm names of up to ``_PARENT_CHAIN_DEPTH``
    ancestors (nearest first), or ``unknown`` where /proc is
    unavailable. Audit-trail first: names are attacker-renameable,
    so readers only key on the stock ``script`` wrapper; the rest
    exists so a forged stamp records the chain that produced it.

    The scan continues past the recorded window (to
    ``_PARENT_SCAN_DEPTH``) looking for ``script``: stacking fork
    intermediaries under ``script -qec`` pushed the verdict-bearing
    name off a fixed-depth record, so a deeper occurrence is
    appended to the recorded chain. A walk that ends WITHOUT
    reaching the session root — scan window exhausted, or an
    ancestor unreadable mid-walk — appends ``PARENTS_TRUNCATED``:
    grading stays fail-open on truncation (a deep stack alone
    proves nothing), but the exhausted window is recorded rather
    than silent, so a fork stack deep enough to outrun the scan
    still leaves a visible trace in the stamp it produces."""
    if not Path("/proc/self/stat").exists():
        return _PARENTS_UNKNOWN
    names: list[str] = []
    deep_script = False
    pid = os.getppid()
    depth = 0
    while pid > 1 and depth < _PARENT_SCAN_DEPTH:
        name = _comm(pid)
        if name is None:
            break
        if len(names) < _PARENT_CHAIN_DEPTH:
            names.append(name)
        elif name == "script":
            deep_script = True
        depth += 1
        try:
            stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            # ppid is the 4th field, after the parenthesised comm
            # (comm itself may contain spaces / parens).
            pid = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    if deep_script and "script" not in names:
        names.append("script")
    if names and pid > 1:
        # Walk ended before the session root: record the truncation.
        names.append(PARENTS_TRUNCATED)
    return ",".join(names) if names else _PARENTS_UNKNOWN


def detect_invocation_context() -> dict[str, str]:
    """Record the current process's invocation context.

    Returns the provenance metadata keys: ``tty`` (which of
    stdin/stdout/stderr are TTYs, ``none`` when zero),
    ``provenance`` (``interactive-tty`` when any fd is a TTY,
    ``non-tty`` otherwise), and the corroboration facts ``sid`` /
    ``envm`` / ``parents`` (see the module docstring) that let
    readers distinguish a genuine terminal session from a pty
    wrapper that makes ``isatty`` true by design.
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
        SID_KEY: _detect_sid(),
        ENV_MARKERS_KEY: _detect_env_markers(),
        PARENTS_KEY: _detect_parent_chain(),
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


def valid_env_markers_value(value: str) -> bool:
    """Whether *value* is a well-formed ``envm`` metadata value:
    ``none`` or a comma-joined non-empty subset of the known marker
    names in recording order (no duplicates)."""
    if value == _ENV_MARKERS_NONE:
        return True
    parts = value.split(",")
    return (
        len(parts) > 0
        and len(set(parts)) == len(parts)
        and all(p in ENV_MARKERS for p in parts)
    )


def valid_parents_value(value: str) -> bool:
    """Whether *value* is a well-formed ``parents`` metadata value."""
    return bool(_PARENTS_VALUE_RE.fullmatch(value))


def _corroboration_ok(
    metadata: Mapping[str, str],
    note_mtime: float | None,
) -> bool:
    """Whether an interactive-tty stamp's corroborating context
    supports granting human grade.

    Fail-low doctrine throughout: partial or malformed corroboration
    is tamper evidence (the CLI always records the full key set), so
    anything short of a coherent, non-contradicting record demotes.

    Demotes on: the process having been its own session leader (the
    ``script -qec`` shape — a shell never execs a command as session
    leader), an agent-session environment marker, or the stock
    ``script`` wrapper anywhere in the recorded parent chain. The
    ``ancestry-truncated`` token (bounded ancestor scan exhausted
    before the session root) deliberately does NOT demote —
    deep-but-legitimate shell stacks exist — the truncation is
    recorded for the auditor instead of silently absent.

    Key-less stamps predate corroboration recording: grandfathered
    behind ``CORROBORATION_ERA_START`` via the caller-supplied file
    mtime (same fence + acknowledged utime residual as the legacy
    clause), or via the durable ``corroboration=pre-era`` marker a
    rewrite materialises from a passing fence.
    """
    sid = metadata.get(SID_KEY)
    envm = metadata.get(ENV_MARKERS_KEY)
    parents = metadata.get(PARENTS_KEY)
    if sid is None and envm is None and parents is None:
        # No corroboration facts recorded — pre-era stamp (or a
        # hand-written one). Durable marker first, mtime fence next.
        marker = metadata.get(CORROBORATION_KEY)
        if marker is not None:
            return marker == CORROBORATION_PRE_ERA
        return note_mtime is not None and note_mtime < CORROBORATION_ERA_START
    # Facts present: all three must be present and well-formed
    # (the CLI records them together; a partial set is tampered or
    # producer-broken) and none may contradict the interactive claim.
    if sid != SID_INHERITED:
        return False
    if envm is None or not valid_env_markers_value(envm):
        return False
    if ENV_MARKER_CLAUDECODE in envm.split(","):
        return False
    if parents is None or not valid_parents_value(parents):
        return False
    return "script" not in parents.split(",")


def classify_provenance(metadata: Mapping[str, str] | None) -> str:
    """Classify a stored annotation's invocation context.

    Returns ``interactive-tty``, ``non-tty``, ``imported``,
    ``legacy-pre-era`` (the durable form of a passing legacy fence),
    or ``legacy``:

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
    if tag in (INTERACTIVE_TTY, NON_TTY, IMPORTED, LEGACY_PRE_ERA):
        return tag
    if tag is not None:
        # A ``provenance`` key exists but carries an unrecognised
        # value — someone tampered or a producer is broken. Never
        # grant the elevated tier, and never fall through to the
        # ``tty`` key: a partially-tampered stamp (garbage tag
        # beside a well-formed tty value) must demote, not elevate.
        return NON_TTY
    tty = metadata.get(TTY_KEY)
    if tty is not None and valid_tty_value(tty):
        return NON_TTY if tty == _TTY_NONE else INTERACTIVE_TTY
    if tty is not None:
        # Garbage ``tty`` value with no tag: same never-grant rule.
        return NON_TTY
    return LEGACY


def is_human_grade(
    metadata: Mapping[str, str] | None,
    *,
    note_mtime: float | None = None,
) -> bool:
    """Whether an annotation earns human-grade weight.

    Requires ``source=human`` AND an interactive-TTY stamp whose
    corroborating context does not contradict it (see
    :func:`_corroboration_ok` — a pty wrapper makes ``isatty`` true
    by design, so the fd stamp alone is not sufficient) — or no
    stamp at all on a note that demonstrably predates the stamp era
    (legacy benefit-of-doubt, date-fenced: callers pass the
    annotation file's mtime as ``note_mtime``, and the grandfather
    clause applies only when it is older than
    :data:`STAMP_ERA_START`; see the module docstring). Use
    :func:`core.annotations.storage.annotation_file_mtime` to obtain
    it. Without ``note_mtime`` a stamp-less note demotes — the fence
    cannot be established, so fail toward the lower tier. A rewrite
    that carries over a fence-passing stamp-less section
    materialises ``provenance=legacy-pre-era`` so the grade survives
    the mtime churn every whole-file rewrite (or fresh checkout)
    causes; that durable tag grades without an mtime.

    ``source=agent`` / ``source=llm``, ``source=human`` with a
    ``non-tty`` stamp (the all-fds-piped laundering shape),
    ``source=human`` with an uncorroborated or contradicted
    interactive stamp (the pty-wrapper laundering shape), and
    ``provenance=imported`` (zip-restored, provenance severed) do
    not qualify.
    """
    if not metadata or metadata.get("source") != "human":
        return False
    tag = classify_provenance(metadata)
    if tag == INTERACTIVE_TTY:
        return _corroboration_ok(metadata, note_mtime)
    if tag == LEGACY_PRE_ERA:
        # Durable form of a passing legacy fence: materialised by a
        # rewrite that verified the file mtime while it still held.
        return True
    return (
        tag == LEGACY
        and note_mtime is not None
        and note_mtime < STAMP_ERA_START
    )
