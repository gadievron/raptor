"""Per-sink-API guard adequacy assessment.

Answers: "Is this guard *sufficient* for this specific sink?" Not merely
"does a guard exist?" (Layer 1/2) but "does it actually prevent the bug class?"

Also provides within-function sink comparison — when the same sink API
appears multiple times with different guard sets, the asymmetry is a signal.

Design from Yamaguchi et al. (IEEE S&P 2014): vulnerability descriptions
require sink-specific sanitizer specs. A bounds check that doesn't reference
the buffer size is insufficient for memcpy; an auth check is irrelevant for
integer overflow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .condition_extraction import GuardCondition, SinkGuard

# ---------------------------------------------------------------------------
# Adequacy verdict
# ---------------------------------------------------------------------------


class Adequacy(str, Enum):
    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    IRRELEVANT = "irrelevant"
    INSUFFICIENT = "insufficient"
    UNKNOWN = "unknown"


@dataclass
class AdequacyResult:
    """Assessment of whether a guard set is adequate for a specific sink."""

    sink_api: str
    verdict: Adequacy
    required_categories: frozenset[str]
    present_categories: frozenset[str]
    missing_categories: frozenset[str]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_api": self.sink_api,
            "verdict": self.verdict.value,
            "required_categories": sorted(self.required_categories),
            "present_categories": sorted(self.present_categories),
            "missing_categories": sorted(self.missing_categories),
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Per-sink-class specifications
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SinkSpec:
    """What constitutes adequate protection for a sink class."""

    # Categories that MUST be present for the guard to be sufficient
    required: frozenset[str]
    # Categories that help but are not strictly required
    helpful: frozenset[str] = frozenset()
    # Categories that are irrelevant for this sink class
    irrelevant: frozenset[str] = frozenset()
    # Extra validation: regex that must appear in at least one guard's text
    text_pattern: re.Pattern | None = None
    # Human note about what "sufficient" means for this sink
    note: str = ""
    # Sufficiency cannot be established from guard categories/text at
    # all for this sink class (e.g. auth gates: an identifier that
    # LOOKS like a permission check proves nothing about what it
    # authorises).  Verdicts cap at PARTIAL — the LLM reviews.
    category_cap_partial: bool = False
    # Bounds-required sinks: SUFFICIENT additionally needs an actual
    # upper-bound comparison in a bounds-category guard.  ``len > 0``
    # matches the size-token text pattern but bounds nothing.
    requires_upper_bound: bool = False


# --- Memory copy sinks (buffer overflow) ---
_MEMCPY_SPEC = SinkSpec(
    required=frozenset({"bounds"}),
    helpful=frozenset({"null"}),
    irrelevant=frozenset({"auth", "config", "type"}),
    text_pattern=re.compile(
        r"(?:sizeof|size|len|capacity|_sz|_size|buf.*len|alloc)",
        re.IGNORECASE,
    ),
    note="bounds check must compare length against destination buffer size",
    requires_upper_bound=True,
)

# --- Command execution sinks (RCE) ---
_EXEC_SPEC = SinkSpec(
    required=frozenset({"auth"}),
    helpful=frozenset({"config", "type"}),
    irrelevant=frozenset({"bounds", "null", "resource"}),
    note="auth/permission gate required; bounds checks are irrelevant for RCE",
    category_cap_partial=True,
)

# --- Code evaluation sinks (code injection) ---
_EVAL_SPEC = SinkSpec(
    required=frozenset({"auth"}),
    helpful=frozenset({"config", "type"}),
    irrelevant=frozenset({"bounds", "null", "resource"}),
    note="auth gate required; input validation also needed but not detectable "
         "from guard category alone",
    category_cap_partial=True,
)

# --- Format string sinks ---
_FORMAT_SPEC = SinkSpec(
    required=frozenset({"bounds"}),
    helpful=frozenset({"type"}),
    irrelevant=frozenset({"auth", "config", "resource"}),
    text_pattern=re.compile(r"%[^%]", re.IGNORECASE),
    note="format string must not be attacker-controlled; bounds check on "
         "output buffer helps but format validation is the real fix",
)

# --- SQL / query construction sinks ---
_SQL_SPEC = SinkSpec(
    required=frozenset({"type"}),
    helpful=frozenset({"auth", "bounds"}),
    irrelevant=frozenset({"null", "resource"}),
    note="type check (parameterized query / prepared statement) is the "
         "primary defense; auth reduces blast radius",
)

# --- File operation sinks (path traversal) ---
_FILE_SPEC = SinkSpec(
    required=frozenset({"bounds"}),
    helpful=frozenset({"auth", "type"}),
    irrelevant=frozenset({"null", "config"}),
    text_pattern=re.compile(
        r"(?:\.\.|/|\\|path|traversal|normalize|realpath|abspath|canonical)",
        re.IGNORECASE,
    ),
    note="path validation (no .., canonicalization) required; generic "
         "bounds check insufficient",
)

# --- Deserialization sinks ---
_DESER_SPEC = SinkSpec(
    required=frozenset({"type", "auth"}),
    helpful=frozenset({"config"}),
    irrelevant=frozenset({"bounds", "null", "resource"}),
    note="type restriction (safe_load, allowlist) AND auth required",
    category_cap_partial=True,
)

# --- Memory allocation sinks (integer overflow → small alloc) ---
_ALLOC_SPEC = SinkSpec(
    required=frozenset({"bounds"}),
    helpful=frozenset({"null"}),
    irrelevant=frozenset({"auth", "config", "type"}),
    text_pattern=re.compile(
        r"(?:overflow|wrap|SIZE_MAX|UINT_MAX|>\s*0|<\s*\d{2,})",
        re.IGNORECASE,
    ),
    note="integer overflow check on size argument required before allocation",
    requires_upper_bound=True,
)

# Null dereference has no sink-API name to key on (dereference is an
# operator, not a call), so no deref spec can be registered in the
# name-keyed table below — that bug class is not assessable here.


# ---------------------------------------------------------------------------
# Sink → spec mapping
# ---------------------------------------------------------------------------

_SINK_SPECS: dict[str, SinkSpec] = {}


def _register(names: tuple, spec: SinkSpec) -> None:
    for n in names:
        _SINK_SPECS[n] = spec


_register((
    "memcpy", "memmove", "strncpy", "strncat", "bcopy",
    "copy_from_user", "copy_to_user", "__copy_from_user",
    "CopyMemory", "RtlCopyMemory", "wmemcpy",
), _MEMCPY_SPEC)

_register((
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "sscanf", "fscanf",
), SinkSpec(
    required=frozenset({"bounds"}),
    helpful=frozenset({"null"}),
    irrelevant=frozenset({"auth", "config", "type"}),
    note="unbounded copy — bounds check on source length required, "
         "or use bounded variant",
    requires_upper_bound=True,
))

_register((
    "system", "popen", "exec", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "ShellExecute",
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output",
    "subprocess.check_call", "Runtime.exec",
    "exec.Command", "os/exec.Command",
), _EXEC_SPEC)

_register((
    "eval", "eval_exec", "compile", "Function",
    "__import__", "importlib.import_module",
    "loadstring", "dofile", "load",
), _EVAL_SPEC)

_register((
    "printf", "fprintf", "snprintf", "vsnprintf",
    "syslog", "NSLog", "format",
), _FORMAT_SPEC)

_register((
    "sqlite3_exec", "mysql_query", "PQexec",
    "cursor.execute", "db.query", "connection.query",
    "sequelize.query", "knex.raw",
), _SQL_SPEC)

_register((
    "open", "fopen", "io.open", "os.open",
    "CreateFile", "CreateFileA", "CreateFileW",
    "unlink", "remove", "rmdir", "shutil.rmtree",
    "os.remove", "os.unlink",
    "fs.readFile", "fs.writeFile", "fs.unlink",
), _FILE_SPEC)

_register((
    "pickle.loads", "pickle.load", "yaml.load",
    "yaml.unsafe_load", "marshal.loads",
    "json.loads", "ObjectInputStream",
    "unserialize", "PHP_unserialize",
    "Marshal.load",
), _DESER_SPEC)

_register((
    "malloc", "calloc", "realloc", "kmalloc",
    "kzalloc", "vmalloc", "krealloc",
    "alloc", "LIBSSH2_ALLOC", "g_malloc",
    "HeapAlloc", "VirtualAlloc",
), _ALLOC_SPEC)


# ---------------------------------------------------------------------------
# Main API: assess guard adequacy
# ---------------------------------------------------------------------------

# An upper-bound comparison shape: ``len < X`` / ``len <= X`` (X may be
# an identifier — ``sizeof(buf)``, a named limit — or a literal), or
# the reversed ``X > len`` / ``X >= len``.  ``min()``/``min_t()``/
# ``clamp()`` count as upper-bounding uses.
_UPPER_BOUND_FWD_RE = re.compile(
    r"[\w)\]]\s*<=?\s*[a-zA-Z_0-9]"
)
_UPPER_BOUND_REV_RE = re.compile(
    r"[\w)\]]\s*>=?\s*[a-zA-Z_]"
)
_UPPER_BOUND_FN_RE = re.compile(r"\b(?:min|min_t|clamp|clamp_t)\s*\(")


def _has_upper_bound_comparison(text: str) -> bool:
    """True when the guard text contains an upper-bound comparison.

    ``len > 0`` / ``len != 0`` match the size-token text patterns but
    bound nothing from above — treating them as sufficient let a
    non-emptiness check stand in for a bounds check (verdict
    soundness).
    """
    return bool(
        _UPPER_BOUND_FWD_RE.search(text)
        or _UPPER_BOUND_REV_RE.search(text)
        or _UPPER_BOUND_FN_RE.search(text)
    )


def assess_guard_adequacy(
    sink_api: str,
    guards: list[GuardCondition],
) -> AdequacyResult:
    """Assess whether a guard set is adequate for a specific sink.

    Returns an AdequacyResult indicating whether the guards are
    sufficient, partial, irrelevant, or insufficient.
    """
    spec = _lookup_spec(sink_api)
    if spec is None:
        # Same semantics as the spec-found path: "unknown" carries no
        # category signal, so it is excluded from reporting here too.
        present = frozenset(
            g.category for g in guards if g.category != "unknown"
        )
        return AdequacyResult(
            sink_api=sink_api,
            verdict=Adequacy.UNKNOWN,
            required_categories=frozenset(),
            present_categories=present,
            missing_categories=frozenset(),
            notes=["no sink spec defined for this API"],
        )

    present_cats = frozenset(g.category for g in guards if g.category != "unknown")
    required = spec.required
    missing = required - present_cats
    notes: list[str] = []

    if spec.note:
        notes.append(spec.note)

    # Check text pattern requirement
    text_match = True
    if spec.text_pattern is not None:
        text_match = any(
            spec.text_pattern.search(g.text) for g in guards
        )
        if not text_match:
            notes.append(
                f"guard text doesn't match required pattern "
                f"(need: {spec.text_pattern.pattern!r})"
            )

    # Check if present guards are all irrelevant
    relevant_present = present_cats - spec.irrelevant
    all_irrelevant = (
        len(guards) > 0
        and len(relevant_present) == 0
        and len(present_cats) > 0
    )

    # Determine verdict
    if not guards:
        verdict = Adequacy.INSUFFICIENT
        notes.append("no guards present")
    elif not missing and text_match:
        verdict = Adequacy.SUFFICIENT
        # Category presence + token match is a lint-grade signal; the
        # consumer treats SUFFICIENT as strong enough to skip LLM
        # review, so SUFFICIENT must carry semantic weight:
        if spec.category_cap_partial:
            # Auth-style gates: a name that LOOKS like a permission
            # check proves nothing about what it authorises or binds.
            verdict = Adequacy.PARTIAL
            notes.append(
                "category/text match alone cannot establish "
                "sufficiency for this sink class — needs review"
            )
        elif spec.requires_upper_bound and not any(
            g.category == "bounds"
            and _has_upper_bound_comparison(g.text)
            for g in guards
        ):
            # ``len > 0`` matches the size-token pattern but bounds
            # nothing from above.
            verdict = Adequacy.PARTIAL
            notes.append(
                "bounds guard has no upper-bound comparison "
                "(non-emptiness is not a bounds check)"
            )
    elif not missing and not text_match:
        verdict = Adequacy.PARTIAL
        notes.append("required category present but text pattern unmatched")
    elif all_irrelevant:
        verdict = Adequacy.IRRELEVANT
        notes.append(
            f"all present guards ({', '.join(sorted(present_cats))}) "
            f"are irrelevant for {sink_api}"
        )
    elif len(missing) < len(required):
        verdict = Adequacy.PARTIAL
    else:
        verdict = Adequacy.INSUFFICIENT

    return AdequacyResult(
        sink_api=sink_api,
        verdict=verdict,
        required_categories=required,
        present_categories=present_cats,
        missing_categories=missing,
        notes=notes,
    )


def _lookup_spec(sink_api: str) -> SinkSpec | None:
    """Look up the spec for a sink API, trying exact then suffix match."""
    if sink_api in _SINK_SPECS:
        return _SINK_SPECS[sink_api]
    # Try last component (e.g. "os.system" → "system")
    parts = re.split(r"[.:\->]+", sink_api)
    if parts:
        last = parts[-1]
        if last in _SINK_SPECS:
            return _SINK_SPECS[last]
    return None


# ---------------------------------------------------------------------------
# Within-function sink comparison
# ---------------------------------------------------------------------------


@dataclass
class SinkAsymmetry:
    """A guard asymmetry between calls to the same sink within one function."""

    sink_file: str
    sink_function: str
    sink_api: str
    guarded_line: int
    unguarded_line: int
    guarded_categories: frozenset[str]
    missing_categories: frozenset[str]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_file": self.sink_file,
            "sink_function": self.sink_function,
            "sink_api": self.sink_api,
            "guarded_line": self.guarded_line,
            "unguarded_line": self.unguarded_line,
            "guarded_categories": sorted(self.guarded_categories),
            "missing_categories": sorted(self.missing_categories),
            "confidence": self.confidence,
        }


def compare_sink_guards(guards: list[SinkGuard]) -> list[SinkAsymmetry]:
    """Find asymmetries between calls to the same sink within one function.

    When the same sink API is called multiple times in a function, and
    some calls are guarded while others aren't, that's a strong signal
    of a missed check.
    """
    # Group by (file, function, sink_api)
    groups: dict[tuple[str, str, str], list[SinkGuard]] = {}
    for sg in guards:
        key = (sg.sink_file, sg.sink_function, sg.sink_api)
        groups.setdefault(key, []).append(sg)

    results: list[SinkAsymmetry] = []

    for (filepath, func_name, api), group in groups.items():
        if len(group) < 2:
            continue

        # Find the "best guarded" call and compare others against it.
        # Count only categorised guards — "unknown" guards carry no signal.
        best_guarded = max(
            group,
            key=lambda sg: sum(1 for g in sg.guards if g.category != "unknown"),
        )
        if not best_guarded.guards:
            continue

        best_cats = frozenset(
            g.category for g in best_guarded.guards
            if g.category != "unknown"
        )
        if not best_cats:
            continue

        for sg in group:
            if sg is best_guarded:
                continue
            sg_cats = frozenset(
                g.category for g in sg.guards
                if g.category != "unknown"
            )
            missing = best_cats - sg_cats
            if missing:
                # Confidence: higher when the best has auth/bounds
                # and the weaker one has nothing
                conf = 0.5
                if "auth" in missing:
                    conf += 0.2
                if "bounds" in missing:
                    conf += 0.2
                if sg.unconditional:
                    conf += 0.1

                results.append(SinkAsymmetry(
                    sink_file=filepath,
                    sink_function=func_name,
                    sink_api=api,
                    guarded_line=best_guarded.sink_line,
                    unguarded_line=sg.sink_line,
                    guarded_categories=best_cats,
                    missing_categories=missing,
                    confidence=min(1.0, conf),
                ))

    return results


# ---------------------------------------------------------------------------
# Batch API: assess all guards from a file
# ---------------------------------------------------------------------------


def assess_file_guards(
    guards: list[SinkGuard],
) -> tuple[list[AdequacyResult], list[SinkAsymmetry]]:
    """Run full adequacy analysis on all guards extracted from a file.

    Returns:
        (adequacy_results, asymmetry_findings)
    """
    adequacy_results = [
        assess_guard_adequacy(sg.sink_api, sg.guards)
        for sg in guards
    ]
    asymmetries = compare_sink_guards(guards)
    return adequacy_results, asymmetries
