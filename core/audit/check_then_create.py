"""Check-then-create race detector (compound keyed registration).

The shape (CWE-362, registry flavour): a function does a keyed
existence CHECK that returns early when the entry is present, then
builds the entry and REGISTERS it with a keyed map write under a lock
that is acquired only AFTER the check — the lock covers the write but
not the check→create compound, so two concurrent callers for the same
key both observe "absent", both create, and the second registration
clobbers the first (duplicate creation, lost refcounts, resource
leaks). The safe spellings hold one lock (or a per-key
single-flight) across the whole compound, or re-check under the
write lock (double-checked registration) — both are recognised and
suppress the match.

Reviews on this shape reliably see the pieces (the check, the racy
window, sometimes even a TODO comment) and then talk themselves into
an adjacent hypothesis; the compound itself had no mechanical
witness. This is that witness: single-function, structural,
detection-grade (@role detection — seeds the hypothesis and
corroborates a matching claim; never promotes on its own).

Scope: Go sources (sync.Mutex ``.Lock()``/``.Unlock()``/``.RLock()``
method spellings and ``m[k] = v`` map writes are Go-stdlib ABI, not
learned project vocabulary). Other languages spell the registry
compound differently and get their own legs when a corpus shape
demands them.

Safety contract: boost-only. Adds findings; never suppresses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DETECTOR_NAME = "check_then_create"

# Keyed map write: `receiver.field[key] = value` (or bare map[key]=v).
_MAP_WRITE_RE = re.compile(
    r"^\s*(?P<map>[\w.]+)\[(?P<key>\w+)\]\s*=\s*\S",
)

# Lock acquisition / release (Go stdlib mutex ABI).
_LOCK_RE = re.compile(r"^\s*(?P<lk>[\w.]+)\.Lock\(\)")
_UNLOCK_RE = re.compile(r"^\s*(?:defer\s+)?(?P<lk>[\w.]+)\.Unlock\(\)")
_DEFER_UNLOCK_RE = re.compile(r"^\s*defer\s+(?P<lk>[\w.]+)\.Unlock\(\)")
_RLOCK_RE = re.compile(r"^\s*(?P<lk>[\w.]+)\.RLock\(\)")

# Early-return existence check: a keyed call or keyed map read whose
# result short-circuits the function when present.
#   if v, ok := m[key]; ok { return ... }
#   x, err := recv.GetFoo(ctx, key) ... else if x != nil { return x... }
_KEYED_MAP_READ_RE = re.compile(
    r"(?P<map>[\w.]+)\[(?P<key>\w+)\]",
)
_RETURN_RE = re.compile(r"^\s*return\b")


@dataclass
class CheckThenCreate:
    """One check-then-create compound without a spanning lock."""

    file: str
    function: str
    check_line: int
    lock_line: int
    write_line: int
    key: str
    map_name: str

    def description(self) -> str:
        return (
            f"check-then-create race lead: keyed existence check at "
            f"line {self.check_line} returns early when present, but "
            f"the keyed registration '{self.map_name}[{self.key}] = "
            f"...' at line {self.write_line} is guarded only by a "
            f"lock acquired at line {self.lock_line} (after the "
            f"check) with no re-check under it — two concurrent "
            f"callers for the same key both observe absent and both "
            f"create (duplicate registration / lost update)"
        )


def _keyed_check_line(
    lines: list[str], key: str, before: int,
) -> int | None:
    """Line (1-based) of an early-return existence check using *key*.

    Two spellings: a keyed call / map read whose surrounding ``if``
    arm returns, or a call taking the key whose result is
    early-returned within the next few lines.
    """
    key_use = re.compile(
        r"(?:\(|,\s*)" + re.escape(key) + r"\s*(?:\)|,)"
        r"|\[" + re.escape(key) + r"\]",
    )
    for i in range(before):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith(("//", "/*", "*")):
            continue
        if not key_use.search(line):
            continue
        # A return within the check's arm (next handful of lines,
        # brace-local) marks it as an early-out existence check.
        for j in range(i, min(i + 8, before)):
            if _RETURN_RE.match(lines[j]):
                return i + 1
        # Only the FIRST keyed use is the check candidate; later uses
        # are the create path itself.
        return None
    return None


def scan_function(
    file_path: str, function: str, source: str,
) -> list[CheckThenCreate]:
    """Scan one Go function body for the compound."""
    lines = source.split("\n")
    findings: list[CheckThenCreate] = []

    for w_idx, line in enumerate(lines):
        mw = _MAP_WRITE_RE.match(line)
        if mw is None:
            continue
        key = mw.group("key")
        map_name = mw.group("map")

        # Find the lock guarding this write: nearest .Lock() above.
        lock_idx = None
        lock_name = None
        for i in range(w_idx - 1, -1, -1):
            ml = _LOCK_RE.match(lines[i])
            if ml is not None:
                lock_idx = i
                lock_name = ml.group("lk")
                break
        if lock_idx is None:
            # Unlocked write is a different (data-race) shape — out of
            # scope for the compound lead.
            continue

        # Deferred unlock right after a lock at the function head
        # means the lock spans everything from there on; if the lock
        # sits above the check, the compound IS covered.
        # (The check scan below only looks before the lock.)

        # Re-check under the lock (double-checked registration)?
        rechecked = False
        for i in range(lock_idx + 1, w_idx):
            mr = _KEYED_MAP_READ_RE.search(lines[i])
            if mr and mr.group("key") == key and not _MAP_WRITE_RE.match(
                lines[i],
            ):
                rechecked = True
                break
        if rechecked:
            continue

        # Unlock between lock and write with the same lock would be
        # odd; unlock AFTER the write is the narrow-guard signature we
        # key on. An unlock (incl. deferred) of the same lock BEFORE
        # the check region doesn't matter — we only require the
        # check to happen before the lock acquisition.
        check_line = _keyed_check_line(lines, key, lock_idx)
        if check_line is None:
            continue

        # If the same lock is also held across the check (a .Lock()
        # of the same name above the check with no .Unlock() before
        # it), the compound is covered — suppress.
        held_across = False
        for i in range(check_line - 1):
            ml = _LOCK_RE.match(lines[i])
            if ml is not None and ml.group("lk") == lock_name:
                held_across = True
            mu = _UNLOCK_RE.match(lines[i])
            if (
                mu is not None
                and mu.group("lk") == lock_name
                and not _DEFER_UNLOCK_RE.match(lines[i])
            ):
                held_across = False
        if held_across:
            continue

        findings.append(CheckThenCreate(
            file=file_path,
            function=function,
            check_line=check_line,
            lock_line=lock_idx + 1,
            write_line=w_idx + 1,
            key=key,
            map_name=map_name,
        ))
    return findings


def scan_gaps(
    gaps: list[dict],
    source_texts: dict[str, str],
) -> list[CheckThenCreate]:
    """Scan Go checklist gaps (the mechanical-detector phase input).

    Line numbers in the results are file-absolute.
    """
    findings: list[CheckThenCreate] = []
    for gap in gaps:
        fp = gap.get("file", "")
        if not fp.endswith(".go"):
            continue
        text = source_texts.get(fp)
        if text is None:
            continue
        ls = gap.get("line_start", 0)
        le = gap.get("line_end") or ls
        if not ls:
            continue
        body = "\n".join(text.split("\n")[ls - 1:le])
        try:
            for f in scan_function(fp, gap.get("name", ""), body):
                f.check_line += ls - 1
                f.lock_line += ls - 1
                f.write_line += ls - 1
                findings.append(f)
        except Exception:  # noqa: BLE001 — one gap must not sink the phase
            logger.debug(
                "check_then_create scan failed for %s:%s",
                fp, gap.get("name", ""), exc_info=True,
            )
    return findings
