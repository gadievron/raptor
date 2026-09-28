"""Work-scaled wall-clock bound for a raptor-build-checklist child.

Shared by every surface that spawns ``libexec/raptor-build-checklist``
with a timeout: ``libexec/raptor-audit`` (the ``run`` and ``gaps``
call sites) and ``core.orchestration.skill_dispatch.build_checklist``
(the /understand pre-pass builder). One sizing rule, one override
variable — a flat per-surface constant is exactly the defect this
module replaces (a 300s bound live-failed twice in one day on 41 MiB
and 55 MiB re-databased binaries whose identical untimed builds
succeeded).

The builder's wall-clock cost tracks its inputs: a source tree is
parsed file by file; a binary target is imported (r2 analysis runs
minutes on a large .text) and joined with any cached re-database.json
(a --decompile-all database for a 12.5k-function binary is tens of
MiB of JSON to load and inventory). Sizing uses cheap stats only —
never a content read.

Constants and their both-direction rationale
(churn-prone-limit doctrine):

* Floor 300s — never tighter than the historical flat bound, so small
  targets keep today's fail-fast on a wedged builder; a flat 300s is
  NOT enough, it live-failed on the binaries above.
* Rate 30s/MiB — generous headroom over observed import+inventory
  throughput so a slow-but-healthy build (cold storage, big .text) is
  not misreported as hung; not higher because the audit run path
  spawns this child AFTER lifecycle start, and a genuinely wedged
  builder (deadlocked r2, unkillable IO) pins the CLI and the run for
  the full bound.
* Ceiling 3600s — matches the Ghidra --decompile-all import bound,
  the heaviest sibling step, which produces the very re-database this
  build consumes; beyond that the operator is better served by the
  fail-fast plus the explicit raptor-build-checklist workaround the
  timeout message names.

Operator override: RAPTOR_CHECKLIST_BUILD_TIMEOUT_S, taken verbatim
between 1 and :data:`CHECKLIST_BUILD_MAX_OVERRIDE_S` (no
floor/ceiling clamp — the Ghidra --timeout operator-value-verbatim
precedent). Values above the max are REFUSED, not clamped — see the
constant's rationale.
"""

from __future__ import annotations

import os
from pathlib import Path

# Imported at module scope on purpose: the audit run path calls
# checklist_build_timeout_s AFTER lifecycle start, where any exception
# class the call site did not anticipate (an ImportError from a lazy
# import, say) escapes the TimeoutExpired handler and wedges the run
# in status=running. Importing here moves that failure to the caller's
# own import time, before any run exists.
from core.audit.binary_context import find_redb
from core.security.log_sanitisation import escape_nonprintable

CHECKLIST_BUILD_FLOOR_S = 300
CHECKLIST_BUILD_CEILING_S = 3600
CHECKLIST_BUILD_S_PER_MIB = 30
CHECKLIST_BUILD_TIMEOUT_ENV = "RAPTOR_CHECKLIST_BUILD_TIMEOUT_S"
# Upper bound on the OVERRIDE (7 days), not on the computed scale
# (which the ceiling already bounds). Not lower: a deliberate
# overnight override for a monster target must never be refused — a
# week dwarfs every real build (the computed ceiling is one hour).
# Not unbounded: the override is taken verbatim into
# subprocess.run(timeout=...), which converts to float — an int wider
# than a C double (309+ digits) passes an isdigit()/>0 check and then
# raises OverflowError INSIDE subprocess.run, an exception class the
# call sites' except TimeoutExpired does not catch; on the audit run
# path that escape fires after lifecycle start and wedges the run in
# status=running, the exact class the scaled bound exists to prevent.
# Values above the max are refused loudly, never clamped, so the
# operator-value-verbatim contract stays true for every sane value.
CHECKLIST_BUILD_MAX_OVERRIDE_S = 7 * 24 * 3600  # 604800

_MIB = 1024 * 1024


def _bounded_repr(raw: str) -> str:
    """A refusal-message-safe rendering of an override value.

    Escaped (env values are operator-side but the refusal can end up
    in logs) and length-bounded with an explicit elision marker — a
    400-digit value must not paste whole into the message.
    """
    if len(raw) > 32:
        return (
            f"{escape_nonprintable(raw[:32])!r}... "
            f"({len(raw)} characters elided to 32)"
        )
    return repr(escape_nonprintable(raw))


def _tree_bytes(root: Path, budget: int) -> int:
    """Regular-file bytes under ``root``, stopping at ``budget``.

    ``.git`` is skipped: the builder never parses it, and a multi-GiB
    object store would otherwise drive every small repo's bound
    straight to the ceiling. Symlinks are never followed (a link out
    of the tree must not inflate the sum).
    """
    total = 0
    stack = [root]
    while stack and total < budget:
        d = stack.pop()
        try:
            with os.scandir(d) as entries:
                for entry in entries:
                    if entry.name == ".git":
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(
                                follow_symlinks=False).st_size
                    except OSError:
                        continue
                    if total >= budget:
                        break
        except OSError:
            continue
    return total


def scaled_checklist_build_timeout_s(
    target_path: Path, out_dir: Path,
) -> int:
    """The computed work-scaled bound — no env override consulted.

    Sized from cheap stats only (never a content read): the target
    file size or a bounded source-tree walk, a Ghidra project's
    ``.rep`` payload, and any cached re-database.json the binary
    route would load. Never raises on stat trouble — an unreadable
    input degrades to the floor, exactly what the historical flat
    bound gave.
    """
    # Bytes at which the scaled value reaches the ceiling: walking
    # further cannot change the answer, so tree walks stop here.
    ceiling_bytes = (
        CHECKLIST_BUILD_CEILING_S * _MIB // CHECKLIST_BUILD_S_PER_MIB
    )

    work_bytes = 0
    try:
        if target_path.is_dir():
            work_bytes += _tree_bytes(target_path, ceiling_bytes)
        elif target_path.is_file():
            work_bytes += target_path.stat().st_size
            if target_path.suffix == ".gpr":
                # The .gpr is a small pointer file; the import work
                # scales with the project payload directory.
                rep = target_path.with_suffix(".rep")
                if rep.is_dir():
                    work_bytes += _tree_bytes(rep, ceiling_bytes)
            # A cached re-database.json is builder input too (the
            # binary route loads and inventories it before writing
            # the checklist). validate=False: existence probes only,
            # no content reads — this is a size estimate, never a
            # cache-use authorization, and if validation later
            # rejects the candidate the builder re-imports (MORE
            # work), so the unvalidated size stays a sound lower
            # bound.
            redb = find_redb(out_dir, target_path, validate=False)
            if redb is not None:
                work_bytes += redb.stat().st_size
    except OSError:
        # Stat failures never abort the build — scale with whatever
        # was summed (worst case: the historical floor).
        pass

    scaled = (work_bytes // _MIB) * CHECKLIST_BUILD_S_PER_MIB
    return max(CHECKLIST_BUILD_FLOOR_S,
               min(scaled, CHECKLIST_BUILD_CEILING_S))


def checklist_build_timeout_s(target_path: Path, out_dir: Path) -> int:
    """Wall-clock bound for one raptor-build-checklist child.

    RAPTOR_CHECKLIST_BUILD_TIMEOUT_S, when set, wins verbatim (never
    floor/ceiling-clamped); unset, the work-scaled computation
    (:func:`scaled_checklist_build_timeout_s`) decides. Raises
    ValueError on an invalid or oversized override so each call site
    can fail its own run loudly (the audit run path must
    lifecycle-fail, never wedge; the orchestration pre-pass degrades
    to the scaled value with a warning).
    """
    raw = os.environ.get(CHECKLIST_BUILD_TIMEOUT_ENV, "").strip()
    if raw:
        over_cap = ValueError(
            f"{CHECKLIST_BUILD_TIMEOUT_ENV} must be at most "
            f"{CHECKLIST_BUILD_MAX_OVERRIDE_S} seconds (7 days) — "
            f"got {_bounded_repr(raw)}; an oversized value "
            f"overflows the subprocess timeout instead of bounding "
            f"anything"
        )
        # isascii() guards the isdigit() check: non-ASCII digit-class
        # characters (superscripts, Eastern Arabic digits) pass
        # str.isdigit() but fail int(), which would refuse with
        # Python's raw message (the character embedded unescaped)
        # instead of this bounded one.
        if not (raw.isascii() and raw.isdigit()):
            raise ValueError(
                f"{CHECKLIST_BUILD_TIMEOUT_ENV} must be a positive "
                f"integer number of seconds "
                f"(got {_bounded_repr(raw)})"
            )
        # Compare by digit count before int(): a 4300+-digit string
        # would trip CPython's integer-string conversion limit inside
        # int() and refuse with the raw limit message instead of this
        # one. More digits than the cap has (after leading zeros) is
        # over the cap by inspection.
        digits = raw.lstrip("0")
        if len(digits) > len(str(CHECKLIST_BUILD_MAX_OVERRIDE_S)):
            raise over_cap
        value = int(digits or "0")
        if value <= 0:
            raise ValueError(
                f"{CHECKLIST_BUILD_TIMEOUT_ENV} must be a positive "
                f"integer number of seconds "
                f"(got {_bounded_repr(raw)})"
            )
        if value > CHECKLIST_BUILD_MAX_OVERRIDE_S:
            raise over_cap
        # Operator value verbatim — never floor/ceiling-clamped.
        return value
    return scaled_checklist_build_timeout_s(target_path, out_dir)
