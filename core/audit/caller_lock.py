"""TU-local caller-held-lock witness for the anti-self-refutation gate.

Corroborates a reviewer's SELF-REFUTATION of a race/TOCTOU hypothesis
on a **static C function** by proving, mechanically, that every
execution of the function is serialised by a lock its callers hold
across the call:

1.  The caller set is TU-complete: the function is ``static`` in its
    defining ``.c`` file, its name is never visible outside that file
    (no cross-file reference of any kind, no ``#include`` of the
    defining file, no preprocessor alias), and its address is never
    taken — so a textual enumeration of the defining file's call
    sites IS the whole caller set.
2.  Every call site holds one consistently-identified lock across the
    call: the acquire is an unconditional function-scope statement
    that textually dominates the call (no label a ``goto`` could
    enter between them), no release of that lock class occurs between
    the acquire and the call, and the callee itself never touches the
    lock class (a caller cannot release while blocked in the callee,
    so the lock is held for the callee's whole execution).
3.  The lock object is passed to the callee as (part of) an argument,
    so concurrent executions on the same claimed state hold the same
    runtime lock — a per-object lock covering an unrelated object
    cannot certify anything.

When the witness holds, the ENTIRE callee body executes inside one
held lock region.  That is what licenses discharging CWE-367 here
even though the in-function race witness deliberately excludes it
(a TOCTOU can span lock scopes — but not when check and use both run
under a single region the caller holds around the whole callee).

Failure direction is uniformly conservative: every unresolvable
construct — non-static linkage, an address-taken escape, a name
visible in another file, a capped/oversized scan, a macro that names
the function, a conditional or statement-embedded acquire, a label
between acquire and call, a release in between, an unparseable lock
object, differing lock identities across call sites, recursion, a
callee that touches the lock class, local static state in the callee
— degrades to ``held=False`` ("no witness") with the refusing
construct named in ``reasoning``.  Boost-only: a positive result may
only ever ACCEPT a reviewer's dismissal, never create or suppress a
finding.

Known soundness bounds (documented, deliberate — consumers gate the
discharge on an operator repo-trust assertion for exactly these):

* Lock identity is textual (the acquire's first argument), reusing
  the same-lock-object discipline of
  :func:`core.audit.condition_smt.check_race_protection`; whether
  OTHER functions that touch the claimed state take the same lock is
  not analysed — the witness proves the callee's executions are
  serialised against each other, which is the caller-held-
  serialization claim it adjudicates, not a whole-program race proof.
* The lock-object-reaches-the-callee rule ties the serialisation
  domain to the callee's state HANDLE, not to the state itself: with
  pointer indirection (lock ``&o->m`` while passing ``o->sh``, where
  distinct owners can share one ``sh``) two callers can hold
  different locks around the same underlying state.  Not decidable
  textually; the argument-tie narrows the gap, the trust gate covers
  the rest.
* The CALLEE's transitive callees are not analysed: a helper called
  BY THE CALLEE that releases the caller's lock through a wrapper
  name is out of view (the direct-name refusal covers the callee
  itself; caller-side interval calls ARE checked — a TU body naming
  the lock class or any non-TU call receiving the lock object's base
  refuses).
* Token-pasted (``##``) identifiers are invisible to any textual
  scan; the preprocessor refusals cover the shapes that NAME the
  function, and computed ``#include`` operands refuse tree-wide.
* Custom conditional-acquire primitives whose names carry neither
  ``try`` nor ``_interruptible``/``_killable`` markers are
  indistinguishable from unconditional acquires (the suffix-pair
  discovery trusts that ``*_lock``/``*_unlock`` pairs lock
  unconditionally).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Scan bounds shared with the api_boundary enumeration machinery so
# the two TU-completeness arguments stay aligned.
from .api_boundary import (
    _MAX_FILE_BYTES,
    _MAX_SCAN_FILES,
    _MAX_WINDOW_LINE_CHARS,
    _walk_tree_entries,
    _SOURCE_SUFFIXES,
    _balanced_span,
    _scan_file_for_calls,
)

logger = logging.getLogger(__name__)

#: Per-caller pre-call region is char-capped upstream; call-site count
#: is capped by the enumerator.  This caps how many call sites the
#: per-site lock analysis will accept at all.
_MAX_CALL_SITES = 16

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

#: Named label anywhere a statement can start (a ``goto`` target):
#: line start or right after ``;``/``{``/``}`` — ``if (x) { y(); } l:``
#: hides a label mid-line.  ``default`` is not enterable by ``goto``
#: and ``case X:`` never matches (the value intervenes), so only real
#: label definitions refuse.
_STMT_LABEL_RE = re.compile(r"(?:^|[;{}])\s*(\w+)\s*:(?!:)")

#: A pure label line (``retry:``) — the one non-terminator shape a
#: candidate acquire may directly follow (jumping to the label passes
#: the acquire again).  ``case X:`` deliberately fails this.
_PURE_LABEL_LINE_RE = re.compile(r"^\s*\w+\s*:\s*$")

#: Constructs that defeat the textual dominance argument outright.
_NONLINEAR_FLOW_RE = re.compile(r"goto\s*\*|\bsetjmp\b|\blongjmp\b")

#: Loop keywords between an acquire and the call defeat the linear
#: between-region argument: a loop enclosing the call carries a
#: backward edge, so a release AFTER the call (inside the loop body)
#: still precedes the call on the next iteration — the textual
#: between-scan cannot see it.  Any loop keyword in the interval
#: refuses the candidate (conservative: loops that do not enclose the
#: call refuse too).
_LOOP_KEYWORD_RE = re.compile(r"\b(?:while|for|do)\b")

#: Digraph/trigraph brace spellings are invisible to brace counting;
#: their presence anywhere in the defining file refuses the witness
#: (checked on the sanitized view — string/comment uses do not count).
_DIGRAPH_RE = re.compile(r"<%|%>|\?\?[<>()='!/-]")

#: Call-shaped identifier (for the between-region wrapper check).
_CALL_IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

#: Scope-exit release machinery: ``__attribute__((cleanup(fn)))`` /
#: ``__cleanup__`` and the linux/cleanup.h ``guard()`` /
#: ``scoped_guard()`` / ``__free()`` idioms run a release at a brace
#: the textual unlock scan never sees.  Presence anywhere in the
#: defining file refuses (digraph-refusal style; view-checked —
#: string/comment uses do not count).
_SCOPED_RELEASE_RE = re.compile(
    r"(?:\bguard|\bscoped_guard|\bcleanup|__cleanup__|__free)\s*\(",
)

#: Conditional-acquire variants: their bare-statement form silently
#: proceeds UNLOCKED on failure (signal, contention), so they can
#: never serve as an unconditional caller-held acquire.
_CONDITIONAL_ACQUIRE_RE = re.compile(
    r"(?:_interruptible|_killable|_?trylock|try_lock)\b",
)

#: ``static`` at a statement start (line start or after ``;``/``{``/
#: ``}``) — local static state in the callee body.  The gap after the
#: statement boundary is HORIZONTAL-only ([^\S\n]): with a ``\s*``
#: gap the MULTILINE ``^`` branch re-scans a run of blank lines from
#: every line start inside it — quadratic on attacker-shaped function
#: source.  A ``static`` on a later line is still matched by the
#: ``^`` branch anchoring its own line.
_LOCAL_STATIC_RE = re.compile(
    r"(?:^|[;{}])[^\S\n]*static\b", re.MULTILINE,
)

#: C keywords that look call-shaped to _CALL_IDENT_RE.
_C_CALL_KEYWORDS = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "typeof",
    "__typeof__", "do", "else", "case", "defined",
})

#: Stable kernel APIs asserted to neither acquire nor release any
#: lock passed to them (directly or through the object they receive).
#: Consulted ONLY for an interval call the out-of-TU rule would
#: otherwise refuse — the same name-trust the acquire side already
#: extends to mutex_lock/spin_lock, kept symmetric and auditable.
#: Deliberately tiny; grows exclusively through the learned-vocab
#: route (study/IRIS-discovered contracts ride in with their
#: rationale), never by ad-hoc addition.
_NON_LOCK_TOUCHING_CALLEES = frozenset({
    # Waits for i_dio_count (inflight direct IO) to drain via
    # inode_dio_end wakeups; a pure waiter that takes no lock and
    # cannot release one it never holds.
    "inode_dio_wait",
    # Kicks writeback and waits on per-page/folio writeback bits of
    # the mapping; acquires no inode/rwsem-class lock and releases
    # nothing the caller holds.
    "filemap_write_and_wait",
    "filemap_write_and_wait_range",
})


@dataclass
class CallerLockResult:
    """Verdict of the TU-local caller-held-lock witness.

    ``held=True`` means the witness HOLDS: the function is static with
    a TU-complete caller set and every call site holds ``lock_class``
    on ``lock_object`` across the call.  Everything else — including
    every parse/scan/resolution failure — is ``held=False`` with the
    refusing construct named in ``reasoning``.
    """

    held: bool = False
    lock_class: str = ""
    lock_object: str = ""
    call_sites: int = 0
    callers: tuple[str, ...] = ()
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "held": self.held,
            "lock_class": self.lock_class,
            "lock_object": self.lock_object,
            "call_sites": self.call_sites,
            "callers": list(self.callers),
            "reasoning": self.reasoning,
        }


def _refuse(reason: str) -> CallerLockResult:
    return CallerLockResult(reasoning=reason)


# ---------------------------------------------------------------------------
# TU-locality: static linkage, no cross-file visibility, no escapes
# ---------------------------------------------------------------------------


def _static_in_head(
    view_lines: list[str],
    def_line_no: int,
    pp_lines: set[int],
) -> bool:
    """Does the definition head carry ``static`` storage class?

    The head may start above the name line (return type on its own
    line); take a small window ending at the definition line and keep
    only the segment after the last statement/definition terminator.
    Preprocessor lines (including continuations, via *pp_lines*) are
    terminators too — a ``#define`` body just above the head must not
    leak its tokens (e.g. the word ``static``) into the segment.
    """
    lo = max(0, def_line_no - 2)
    # Keep only the contiguous non-preprocessor run ending at the head.
    run: list[int] = []
    for i in range(def_line_no, lo - 1, -1):
        if i in pp_lines:
            break
        run.append(i)
    window = "\n".join(view_lines[i] for i in sorted(run))
    cut = max(window.rfind(";"), window.rfind("}"))
    segment = window[cut + 1:]
    return bool(re.search(r"\bstatic\b", segment))


def _preprocessor_lines(view_lines: list[str]) -> set[int]:
    """0-based indices of preprocessor-directive lines, including
    backslash-continuation lines of multi-line directives."""
    out: set[int] = set()
    in_directive = False
    for i, line in enumerate(view_lines):
        if in_directive:
            out.add(i)
            in_directive = line.rstrip().endswith("\\")
            continue
        if line.lstrip().startswith("#"):
            out.add(i)
            in_directive = line.rstrip().endswith("\\")
    return out


def _name_on_preprocessor_line(
    view_lines: list[str],
    name_re: re.Pattern,
    pp_lines: set[int],
) -> int | None:
    """1-based line of the first preprocessor directive that names the
    function (``#define`` wrapper/alias, conditional games), or None."""
    for i in sorted(pp_lines):
        if name_re.search(view_lines[i]):
            return i + 1
    return None


def _first_non_call_use(view: str, name_re: re.Pattern) -> int | None:
    """Offset of the first occurrence of the name NOT followed by
    ``(`` — an address-taken escape, function-pointer table entry,
    or macro-argument use (``EXPORT_SYMBOL(fn)`` ends up here too:
    the inner name is followed by ``)``).  Whitespace including
    newlines may separate a call's name from its paren."""
    for m in name_re.finditer(view):
        rest = view[m.end():m.end() + 200].lstrip()
        if not rest.startswith("("):
            return m.start()
    return None


def _scan_tree_for_visibility(
    target_path: Path,
    rel_file: str,
    function_name: str,
) -> str | None:
    """Why the name is (or may be) visible outside the defining file,
    or None when the uncapped-within-bounds scan proves it is not.

    Any occurrence of the name in another file — call, prototype,
    address-taken, macro, an ``.inc``/``.def`` textual include, an
    assembly reference, anything — refuses, as does any ``#include``
    whose final path component matches the defining file's basename
    (the include-the-.c trick that clones the static into another
    TU).  Files with the standard C suffixes get the sanitized view
    (a comment mention is not a reference); every OTHER file is
    matched raw — non-source carriers have no trustworthy comment
    grammar, so a raw hit refuses conservatively.  A capped walk or
    an unreadable/oversized file also refuses: completeness is
    earned, never assumed.
    """
    from .source_view import sanitized_view

    name_re = re.compile(rf"(?<![\w.>]){re.escape(function_name)}\b")
    basename = Path(rel_file).name
    include_re = re.compile(
        rf"#\s*(?:include|define)\b[^\n]*[\"<][^\">]*?"
        rf"{re.escape(basename)}\s*[\">]",
        re.IGNORECASE,
    )
    scanned = 0
    for path in _walk_tree_entries(target_path):
        if scanned >= _MAX_SCAN_FILES:
            return f"tree scan hit its {_MAX_SCAN_FILES}-file cap"
        if ".git" in path.parts:
            continue
        if path.is_symlink() and path.is_dir():
            # rglob does not descend into symlinked directories, so
            # their contents are invisible to this walk — the tree's
            # true extent cannot be verified.
            try:
                rel = str(path.relative_to(target_path))
            except ValueError:
                rel = str(path)
            return (
                f"symlinked directory {rel} — tree completeness "
                f"unverifiable"
            )
        if not path.is_file():
            continue
        scanned += 1
        try:
            rel = str(path.relative_to(target_path))
        except ValueError:
            continue
        is_source = path.suffix.lower() in _SOURCE_SUFFIXES
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                return f"{rel} exceeds the byte cap — unscannable"
            text = path.read_text(errors="replace")
        except OSError:
            return f"{rel} unreadable — visibility unverifiable"
        if is_source and include_re.search(text):
            # Matches the basename in an #include operand OR in a
            # #define'd quoted path (the computed-include shape
            # ``#define BODY "../x.c"`` + ``#include BODY``).  A
            # computed operand assembled where no quoted path names
            # the basename is the documented token-pasting bound.
            return (
                f"{rel} names {basename} in an include/define path — "
                f"the static may be cloned into another TU"
            )
        if rel == rel_file:
            continue
        if function_name not in text:
            continue
        if not is_source:
            return (
                f"{function_name} appears in non-source file {rel} — "
                f"visibility unverifiable"
            )
        view = sanitized_view(text, str(path))
        m = name_re.search(view)
        if m:
            line = view.count("\n", 0, m.start()) + 1
            return f"{function_name} referenced outside the TU at {rel}:{line}"
    return None


# ---------------------------------------------------------------------------
# Per-call-site lock analysis
# ---------------------------------------------------------------------------


def _line_depths_before(lines: list[str]) -> list[int]:
    """Absolute brace depth BEFORE each line (definition head = 0)."""
    depths: list[int] = []
    d = 0
    for line in lines:
        depths.append(d)
        d += line.count("{") - line.count("}")
    return depths


def _caller_name_from_head(head_line: str) -> str | None:
    """Function name from a definition's first line (the last
    identifier directly followed by ``(``), or None."""
    matches = list(re.finditer(r"([A-Za-z_]\w*)\s*\(", head_line))
    if not matches:
        return None
    return matches[-1].group(1)


def _has_goto_label(lines: list[str]) -> bool:
    """Any named label definition (a ``goto`` entry point) in *lines*,
    at line start OR after ``;``/``{``/``}`` on the same line.
    ``default`` is not enterable by ``goto`` and is exempt."""
    for ln in lines:
        for m in _STMT_LABEL_RE.finditer(ln):
            if m.group(1) != "default":
                return True
    return False


def _conditional_brace_skew(lines: list[str]) -> bool:
    """Braces that can decouple the count from compiled control
    structure: any ``{``/``}`` on a preprocessor directive (or its
    continuation), inside an ``#if``..``#endif`` region, or an
    ``#endif`` without a visible opener (the region may extend past
    the visible slice)."""
    depth = 0
    in_directive = False
    for ln in lines:
        stripped = ln.lstrip()
        is_directive = in_directive or stripped.startswith("#")
        if is_directive:
            if "{" in ln or "}" in ln:
                return True
            if re.match(r"#\s*(?:if|ifdef|ifndef)\b", stripped):
                depth += 1
            elif re.match(r"#\s*endif\b", stripped):
                if depth == 0:
                    return True
                depth -= 1
            in_directive = ln.rstrip().endswith("\\")
            continue
        if depth > 0 and ("{" in ln or "}" in ln):
            return True
    return False


def _acquire_follows_statement_boundary(
    pre_lines: list[str], acq_idx: int,
) -> bool:
    """The acquire must directly follow a COMPLETED statement or block
    boundary — the previous non-blank, non-preprocessor line must end
    with ``;``/``{``/``}`` or be a pure label line.  A braceless
    control header (``if (cond)`` / ``else`` / a wrapped condition
    line) fails this, so a brace-free conditional acquire can never
    read as unconditional."""
    i = acq_idx - 1
    while i >= 0:
        ln = pre_lines[i]
        stripped = ln.strip()
        if not stripped:
            i -= 1
            continue
        if stripped.startswith("#"):
            # Directive lines are control-neutral; keep walking.  (A
            # directive CONTINUATION line does not start with ``#``
            # and fails the terminator test below — conservative.)
            i -= 1
            continue
        if stripped.endswith((";", "{", "}")):
            return True
        return bool(_PURE_LABEL_LINE_RE.match(ln))
    return False


#: Bounds for the header-inline half of the TU body map: quoted
#: includes are followed to this depth from the defining file, at
#: most this many header files join, each under the shared byte cap.
_TU_INCLUDE_DEPTH = 2
_TU_INCLUDE_MAX_FILES = 32

_QUOTED_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"')

_POISONED = "\x00conflicting-definitions"


def _file_definition_bodies(view_lines: list[str]) -> dict[str, str]:
    """Name → body text for every top-level definition the extent
    scan can attribute in one file (sanitized view)."""
    from .api_boundary import _definition_extents, _line_depths

    depths, anomaly = _line_depths(view_lines)
    if anomaly:
        return {}
    bodies: dict[str, str] = {}
    for start, end in _definition_extents(view_lines, depths):
        name = None
        for ln in view_lines[start:min(start + 3, end + 1)]:
            got = _caller_name_from_head(ln)
            if got is not None:
                name = got
                break
        if name:
            bodies[name] = "\n".join(view_lines[start:end + 1])
    return bodies


def _tu_function_bodies(
    view_lines: list[str],
    def_path: Path | None = None,
    root: Path | None = None,
) -> dict[str, str]:
    """Name → body text for every definition that is PART OF THE TU:
    the defining ``.c`` file plus the headers its quoted ``#include``s
    pull in (a ``static inline`` in ``"f2fs.h"`` is TU code after
    preprocessing, exactly like a function in the ``.c`` itself).

    Literal quoted includes only, resolved against the including
    file's directory, path-contained to the target root, followed to
    depth :data:`_TU_INCLUDE_DEPTH` with a file count and the shared
    byte cap; angle includes are never resolved (system headers do
    not define TU-local static state this witness reasons about).
    An unresolvable header is simply absent — absence only ever means
    fewer cleared interval calls (the conservative direction).  A
    name defined more than once across the TU is POISONED (removed
    from the map): an ambiguous body must not clear anything.

    Used for the one-hop wrapper check (a TU body naming the lock
    class refuses) and for clearing interval calls that receive the
    lock object's base.
    """
    from .source_view import sanitized_view

    bodies = _file_definition_bodies(view_lines)
    if def_path is None or root is None:
        return bodies
    try:
        root_resolved = Path(root).resolve()
    except OSError:
        return bodies
    # Include scanning runs on RAW text (the sanitized view blanks
    # quoted include paths as string literals); body extraction runs
    # on each header's sanitized view.
    seen_files: set[Path] = set()
    frontier: list[tuple[Path, int]] = [(Path(def_path), 0)]
    poisoned: set[str] = set()
    while frontier and len(seen_files) < _TU_INCLUDE_MAX_FILES:
        cur_path, depth = frontier.pop(0)
        if depth >= _TU_INCLUDE_DEPTH:
            continue
        try:
            cur_raw = cur_path.read_text(errors="replace")
        except OSError:
            continue
        for ln in cur_raw.splitlines():
            m = _QUOTED_INCLUDE_RE.match(ln)
            if m is None:
                continue
            if len(seen_files) >= _TU_INCLUDE_MAX_FILES:
                break
            try:
                hdr = (cur_path.parent / m.group(1)).resolve()
                if not hdr.is_relative_to(root_resolved):
                    continue  # escapes the tree — not TU material
                if hdr in seen_files or not hdr.is_file():
                    continue
                if hdr.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = hdr.read_text(errors="replace")
            except (OSError, ValueError):
                continue
            seen_files.add(hdr)
            hlines = sanitized_view(text, str(hdr)).splitlines()
            for name, body in _file_definition_bodies(hlines).items():
                if name in bodies:
                    poisoned.add(name)
                else:
                    bodies[name] = body
            frontier.append((hdr, depth + 1))
    for name in poisoned:
        bodies.pop(name, None)
    return bodies


@dataclass
class _SiteLock:
    acquire_fn: str
    unlock_name: str
    lock_obj: str


def _locks_held_at_call(
    before_body: str,
    after_window: str,
    tu_bodies: dict[str, str],
) -> tuple[list[_SiteLock], str]:
    """Lock classes provably held at the call site, plus a refusal
    reason when the pre-call region defeats the dominance argument
    globally (non-linear flow, preprocessor-skewed braces).

    A candidate acquire qualifies only when it is an unconditional
    statement of its own at function scope (brace depth 1, directly
    following a completed statement/block boundary — never a
    braceless control header) before the call, with a parseable lock
    object, and the between-region carries no release of the class
    (including through a one-hop TU-local wrapper), no loop keyword
    (backward edges), no named label (``goto`` entry points), and no
    rebinding, arithmetic bump, or address-taking of the lock
    object's base identifier.
    """
    from .condition_smt import _EMPTY_VOCAB, _extract_lock_acquires

    if _NONLINEAR_FLOW_RE.search(before_body):
        return [], "non-linear control flow (goto*/setjmp) in the caller"

    pre_lines = before_body.splitlines()
    if _conditional_brace_skew(pre_lines):
        return [], (
            "preprocessor-conditional braces in the caller — brace "
            "depth is not trustworthy"
        )
    n_before = len(pre_lines)
    # The paired-release discovery needs the caller's whole text (the
    # release usually sits after the call), but only acquires strictly
    # in the pre-call region can serialise the call.
    full_lines = pre_lines + after_window.splitlines()
    acquires = _extract_lock_acquires(full_lines, _EMPTY_VOCAB)
    depths = _line_depths_before(pre_lines)

    held: list[_SiteLock] = []
    for acq_idx, lock_fn, unlock_name, lock_obj in acquires:
        if acq_idx >= n_before:
            continue  # at/after the call — cannot serialise it
        if _CONDITIONAL_ACQUIRE_RE.search(lock_fn):
            continue  # interruptible/killable/trylock variants
            # silently proceed unlocked on failure — never an
            # unconditional acquire, even as a bare statement
        line = pre_lines[acq_idx]
        if not re.fullmatch(
            rf"\s*{re.escape(lock_fn)}\s*\([^;{{}}]*\)\s*;\s*",
            line,
        ):
            continue  # conditional / embedded / multi-line acquire
        if depths[acq_idx] != 1:
            continue  # not at function scope — may not dominate
        if not _acquire_follows_statement_boundary(pre_lines, acq_idx):
            continue  # braceless control header — acquire conditional
        if not lock_obj:
            continue  # unparseable lock object — identity unknown
        base_m = _IDENT_RE.match(lock_obj)
        if base_m is None:
            continue
        base = base_m.group(0)
        prefix_pats = _lock_obj_prefix_patterns(lock_obj)
        if prefix_pats is None:
            continue  # not a plain member path — identity unguardable
        between = pre_lines[acq_idx + 1:n_before]
        unlock_re = re.compile(
            rf"\b{re.escape(unlock_name)}(?:_irq(?:restore)?|_bh)?\s*\(",
        )
        if any(unlock_re.search(ln) for ln in between):
            continue  # a release may run before the call
        if any(_LOOP_KEYWORD_RE.search(ln) for ln in between):
            continue  # a backward edge could re-reach the call after
            # a release the between-scan cannot see
        if _has_goto_label(between):
            continue  # a goto could enter after the acquire
        b = re.escape(base)
        decl_re = re.compile(rf"\bstruct\b[^;]*\b{b}\s*[;=]")
        rebound = any(decl_re.search(ln) for ln in between)
        if not rebound:
            for pat in prefix_pats:
                pre_re = _rebind_re_for_path(pat)
                if any(pre_re.search(ln) for ln in between):
                    rebound = True  # the lock identity (or any prefix
                    break  # of its path) may have changed or escaped
        if rebound:
            continue
        # Interval-call escape: a TU-local wrapper touching the lock
        # class, or ANY call that receives the lock object's base
        # without resolving to a clean TU body, could release the
        # lock where the literal unlock scan never looks.
        lockop_re = _lock_class_re(lock_fn, unlock_name)
        if _interval_call_escape(
            "\n".join(between), base, tu_bodies, lockop_re,
        ) is not None:
            continue
        held.append(_SiteLock(lock_fn, unlock_name, lock_obj))
    return held, ""


def _lock_obj_prefix_patterns(lock_obj: str) -> list[str] | None:
    """Regex sources matching each prefix path of *lock_obj*
    (``o->lockp`` → ``o``, ``o\\s*->\\s*lockp``), whitespace-tolerant
    around the accessors.  ``None`` when the object is not a plain
    member-access path — the identity is then too complex to guard.
    """
    parts = re.split(r"(->|\.)", lock_obj.replace(" ", ""))
    if not parts or not re.fullmatch(r"[A-Za-z_]\w*", parts[0]):
        return None
    pats: list[str] = [re.escape(parts[0])]
    cur = re.escape(parts[0])
    for i in range(1, len(parts) - 1, 2):
        sep, seg = parts[i], parts[i + 1]
        if not re.fullmatch(r"[A-Za-z_]\w*", seg):
            return None
        cur += rf"\s*{re.escape(sep)}\s*{re.escape(seg)}"
        pats.append(cur)
    return pats


def _rebind_re_for_path(path_pat: str) -> re.Pattern:
    """Assignment / compound-assignment / increment / address-taking
    of one lock-object prefix path."""
    return re.compile(
        rf"(?:^|[^\w.>&]){path_pat}\s*(?:\+\+|--|(?:<<|>>|[+\-*/%&|^])="
        rf"|(?<![=!<>])=(?!=))"
        rf"|(?:\+\+|--)\s*{path_pat}(?![\w.]|\s*->)"
        rf"|&\s*{path_pat}\b(?!\s*(?:->|\.|\[))",
    )


def _interval_call_escape(
    between_text: str,
    base: str,
    tu_bodies: dict[str, str],
    lockop_re: re.Pattern,
) -> str | None:
    """A call in the acquire→call interval that could release the
    lock, or None.

    Two shapes refuse: a call to a TU-defined function whose body
    names the lock class (one-hop wrapper release), and a call that
    RECEIVES the lock object's base but does not resolve to a clean
    TU body — an out-of-TU helper holding the object can release its
    lock, and the textual unlock scan never sees it.  Unbalanced
    argument lists refuse too (the call cannot be attributed).
    """
    base_re = re.compile(rf"\b{re.escape(base)}\b")
    for m in _CALL_IDENT_RE.finditer(between_text):
        name = m.group(1)
        if name in _C_CALL_KEYWORDS:
            continue
        body = tu_bodies.get(name)
        if body is not None and lockop_re.search(body):
            return (
                f"TU-local helper {name} called in the interval "
                f"touches the lock class"
            )
        open_pos = between_text.index("(", m.end() - 1)
        args, _end = _balanced_span(between_text, open_pos)
        if args is None:
            return (
                f"unterminated call to {name} in the acquire-to-call "
                f"interval"
            )
        if not base_re.search(args):
            continue
        if body is None:
            if name in _NON_LOCK_TOUCHING_CALLEES:
                # Operator-adjudicated contract: this API touches no
                # caller lock.  Only THIS call is cleared — every
                # other interval obligation still applies.
                continue
            return (
                f"{name} receives the lock object in the interval "
                f"and is not defined in this TU — it could release "
                f"the lock out of view"
            )
    return None


def _lock_class_re(acquire_fn: str, unlock_name: str) -> re.Pattern:
    """Call-shaped mention of either side of the lock class, with the
    irq/bh/interruptible suffix variants stripped to their base."""
    unlock_base = re.sub(r"_irq(?:save|restore)?$|_bh$", "", unlock_name)
    acquire_base = re.sub(
        r"_irq(?:save)?$|_bh$|_interruptible$|_killable$", "", acquire_fn,
    )
    return re.compile(
        rf"\b(?:{re.escape(unlock_base)}|{re.escape(acquire_base)})"
        rf"\w*\s*\(",
    )


def _lock_obj_in_args(lock_obj: str, args: list[str]) -> bool:
    """The lock object's base identifier must reach the callee as
    (part of) an argument — that ties the serialisation domain to the
    callee's state handle."""
    base_m = _IDENT_RE.match(lock_obj)
    if base_m is None:
        return False
    base = base_m.group(0)
    return any(
        re.search(rf"\b{re.escape(base)}\b", arg) for arg in args
    )


# ---------------------------------------------------------------------------
# Witness
# ---------------------------------------------------------------------------


def check_caller_lock_serialization(
    func_source: str,
    function_name: str,
    *,
    rel_file: str,
    target_path: str | Path,
) -> CallerLockResult:
    """Mechanical witness: every execution of static *function_name*
    is serialised by a lock its TU-local callers hold across the call.

    See the module docstring for the full mechanism, the conservative-
    failure contract, and the documented soundness bounds.  Boost-only:
    a positive result may only ever be used to ACCEPT a reviewer's
    dismissal.
    """
    from .safety_contract import assert_boost_only
    from .source_view import sanitized_view

    assert_boost_only("caller_lock")

    if not func_source or not func_source.strip():
        return _refuse("empty source")
    if not function_name or not re.fullmatch(r"[A-Za-z_]\w*", function_name):
        return _refuse(f"not a plain C function name: {function_name!r}")
    if not rel_file.endswith(".c"):
        return _refuse(f"not a C translation unit: {rel_file}")
    # Content half of the language check (mirrors check_race_protection).
    if any(kw in func_source for kw in ("func ", "package ", "import (")):
        return _refuse("Go source, not applicable")
    if any(kw in func_source for kw in ("def ", "import os", "class ")):
        return _refuse("Python source, not applicable")

    try:
        root = Path(target_path)
        def_path = root / rel_file
        if not def_path.is_file():
            return _refuse(f"defining file {rel_file} not found")
        if def_path.stat().st_size > _MAX_FILE_BYTES:
            return _refuse(f"defining file {rel_file} exceeds the byte cap")
        def_text = def_path.read_text(errors="replace")
    except OSError:
        return _refuse(f"defining file {rel_file} unreadable")

    view = sanitized_view(def_text, str(def_path))
    view_lines = view.splitlines()
    name_re = re.compile(rf"(?<![\w.>]){re.escape(function_name)}\b")

    if _DIGRAPH_RE.search(view):
        return _refuse(
            f"digraph/trigraph token in {rel_file} — brace counting "
            f"untrustworthy"
        )
    if _SCOPED_RELEASE_RE.search(view):
        return _refuse(
            f"scope-exit release machinery (cleanup attribute / "
            f"guard / __free) in {rel_file} — releases fire at brace "
            f"exits the textual unlock scan never sees"
        )
    # A static's symbol is TU-local, so an assembly caller can only
    # live in this file — and it must spell the name inside a string
    # the sanitized view blanks.  More raw occurrences of the name
    # than sanitized-view occurrences means a string/comment in the
    # DEFINING file carries the name: an inline-asm call site (or any
    # string-borne indirection) the enumeration cannot attribute.
    if len(name_re.findall(def_text)) > len(name_re.findall(view)):
        return _refuse(
            f"{function_name} appears inside a string or comment of "
            f"{rel_file} — an assembly/string-borne reference cannot "
            f"be attributed"
        )
    pp_lines = _preprocessor_lines(view_lines)
    raw_lines = def_text.splitlines()
    for i, raw in enumerate(raw_lines):
        if i not in pp_lines and raw.rstrip().endswith("\\"):
            return _refuse(
                f"backslash line-splice outside a preprocessor "
                f"directive at {rel_file}:{i + 1} — token boundaries "
                f"untrustworthy"
            )
    # Every #include in the TU must be a literal header path: a
    # textual include of a .c/.inc/.def fragment splices callers into
    # the TU that neither the call-site enumeration nor the
    # suffix-filtered parts of the tree scan attribute here.  Checked
    # on RAW lines — the sanitized view blanks the quoted path.
    for i, raw in enumerate(raw_lines):
        stripped = raw.lstrip()
        if not re.match(r"#\s*include\b", stripped):
            continue
        m = re.search(r'[<"]([^">]+)[">]', raw)
        if m is None or not m.group(1).strip().lower().endswith(
            (".h", ".hpp", ".hxx"),
        ):
            return _refuse(
                f"non-header #include at {rel_file}:{i + 1} — the TU "
                f"may splice in callers the enumeration cannot see"
            )
    pp_line = _name_on_preprocessor_line(view_lines, name_re, pp_lines)
    if pp_line is not None:
        return _refuse(
            f"preprocessor directive names {function_name} at "
            f"{rel_file}:{pp_line} — macro-wrapped call sites possible"
        )
    esc = _first_non_call_use(view, name_re)
    if esc is not None:
        line = view.count("\n", 0, esc) + 1
        return _refuse(
            f"address-taken/non-call use of {function_name} at "
            f"{rel_file}:{line} — indirect callers possible"
        )

    # Call-site enumeration in the defining file (the TU).  The def
    # head is excluded by the enumerator's definition detection; the
    # honesty flags refuse rather than degrade.
    sites, freport = _scan_file_for_calls(
        def_path, rel_file, function_name,
    )
    if freport.get("size_skipped"):
        return _refuse(f"defining file {rel_file} exceeds the byte cap")
    if freport.get("site_capped"):
        return _refuse("call-site enumeration capped — incomplete")
    if freport.get("span_capped"):
        return _refuse(
            f"call-shaped match of {function_name} with an argument "
            f"list unbalanced within the span bound in {rel_file} — "
            f"the caller set is not verifiably TU-complete"
        )
    if freport.get("alias_attr"):
        return _refuse(
            f'alias("{function_name}") attribute — an indirect entry '
            f"point exists"
        )
    definitions = freport.get("definitions") or []
    if len(definitions) != 1:
        return _refuse(
            f"{len(definitions)} definition head(s) of {function_name} "
            f"in {rel_file} — need exactly one"
        )
    if not _static_in_head(view_lines, definitions[0] - 1, pp_lines):
        return _refuse(
            f"{function_name} is not verifiably static — the caller "
            f"set is not TU-complete"
        )
    if not sites:
        return _refuse(f"no TU-local call sites of {function_name}")
    if len(sites) > _MAX_CALL_SITES:
        return _refuse(
            f"{len(sites)} call sites exceed the analysis cap "
            f"({_MAX_CALL_SITES})"
        )

    vis = _scan_tree_for_visibility(root, rel_file, function_name)
    if vis is not None:
        return _refuse(vis)

    tu_bodies = _tu_function_bodies(view_lines, def_path, root)

    # Per-site: the caller must hold at least one common lock class on
    # one common object across ALL sites.
    common: set[tuple[str, str, str]] | None = None
    callers: list[str] = []
    for site in sites:
        line_no = int(site.get("line") or 0)
        if (
            1 <= line_no <= len(view_lines)
            and len(view_lines[line_no - 1]) > _MAX_WINDOW_LINE_CHARS
        ):
            # The pre-call fragment of an over-long call line is
            # silently left-truncated upstream — a release could hide
            # in the invisible part.
            return _refuse(
                f"call line exceeds the line cap at "
                f"{rel_file}:{line_no}"
            )
        before = site.get("before_body") or ""
        if not before or site.get("before_truncated"):
            return _refuse(
                f"pre-call region unavailable/truncated at "
                f"{rel_file}:{site.get('line')}"
            )
        head = before.splitlines()[0] if before else ""
        caller = _caller_name_from_head(head)
        if caller is None:
            return _refuse(
                f"cannot identify the calling function at "
                f"{rel_file}:{site.get('line')}"
            )
        if caller == function_name:
            return _refuse(
                f"recursive call at {rel_file}:{site.get('line')}"
            )
        callers.append(caller)
        held, why = _locks_held_at_call(
            before, site.get("after_window") or "", tu_bodies,
        )
        if why:
            return _refuse(f"{why} at {rel_file}:{site.get('line')}")
        args = site.get("args") or []
        keyed = {
            (sl.acquire_fn, sl.unlock_name, sl.lock_obj)
            for sl in held
            if _lock_obj_in_args(sl.lock_obj, args)
        }
        if not keyed:
            return _refuse(
                f"no dominating caller-held lock covering the call at "
                f"{rel_file}:{site.get('line')} (caller {caller})"
            )
        common = keyed if common is None else common & keyed
        if not common:
            return _refuse(
                "call sites hold different locks — lock identity "
                "ambiguous across callers"
            )

    if not common:  # unreachable (sites is non-empty) — refuse anyway
        return _refuse("no common caller-held lock across call sites")

    # Local static state outlives the serialised region's object and
    # is shared across ALL lock objects — out of the witness's scope.
    # Matched at every statement start, not just line starts.
    body_start = func_source.find("{")
    if body_start >= 0 and _LOCAL_STATIC_RE.search(
        func_source[body_start:],
    ):
        return _refuse(
            f"{function_name} declares local static state — a "
            f"per-object caller lock cannot serialise it"
        )

    # Final per-class obligations: the callee must never touch the
    # lock class (a release inside it would end the held region
    # mid-execution), and no preprocessor directive in the TU may name
    # the class (a drop-the-lock-around-expression macro releases out
    # of the between-scan's view).  Pick the first surviving class.
    pp_text = [view_lines[i] for i in sorted(pp_lines)]
    chosen: tuple[str, str, str] | None = None
    first_reason = ""
    for acquire_fn, unlock_name, lock_obj in sorted(common):
        lockop_re = _lock_class_re(acquire_fn, unlock_name)
        if lockop_re.search(func_source):
            first_reason = first_reason or (
                f"{function_name} itself touches the "
                f"{acquire_fn} lock class — the caller-held region "
                f"is not callee-invariant"
            )
            continue
        if any(lockop_re.search(t) for t in pp_text):
            first_reason = first_reason or (
                f"a preprocessor directive in {rel_file} names the "
                f"{acquire_fn} lock class — releases may hide in "
                f"macro bodies"
            )
            continue
        chosen = (acquire_fn, unlock_name, lock_obj)
        break
    if chosen is None:
        return _refuse(
            first_reason or "no caller-held lock class survives the "
            "callee/macro obligations",
        )
    acquire_fn, unlock_name, lock_obj = chosen

    uniq_callers = tuple(dict.fromkeys(callers))
    return CallerLockResult(
        held=True,
        lock_class=acquire_fn,
        lock_object=lock_obj,
        call_sites=len(sites),
        callers=uniq_callers,
        reasoning=(
            f"static {function_name} has {len(sites)} TU-local call "
            f"site(s) in {rel_file} (caller(s): "
            f"{', '.join(uniq_callers)}), each under a dominating "
            f"function-scope {acquire_fn}({lock_obj}) with no release "
            f"or goto label before the call; the name never escapes "
            f"the TU and the callee never touches the lock class — "
            f"the whole callee executes inside one caller-held "
            f"{lock_obj} region"
        ),
    )
