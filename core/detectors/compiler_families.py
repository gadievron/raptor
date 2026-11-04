"""Shared compiler diagnostic families and their evidence policy."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class FamilySpec:
    """How one CWE family maps onto compiler diagnostics.

    ``reliable`` marks families the analyzer covers well enough that a
    clean run with no in-range diagnostic counts as refutation.  For
    everything else silence means ``inconclusive``, never ``refuted``.
    ``positive_evidence=False`` additionally keeps matching diagnostics as
    inconclusive review candidates instead of confirmation.
    """

    gcc_ids: tuple[str, ...]
    gcc_flags: tuple[str, ...]
    clang_engine: str  # "analyze" (path-sensitive) | "warning" (sema -W pass)
    clang_ids: tuple[str, ...]
    clang_flags: tuple[str, ...]
    clang_message_re: str  # "" = no message discrimination needed
    reliable: bool
    positive_evidence: bool = True  # a matching diagnostic may confirm a hypothesis


_OOB_SPEC = FamilySpec(
    gcc_ids=(
        "-Wanalyzer-out-of-bounds",
        "-Wstringop-overflow",
        "-Wstringop-overread",
        "-Warray-bounds",
    ),
    gcc_flags=(),
    clang_engine="warning",
    clang_ids=("-Warray-bounds", "-Wfortify-source"),
    clang_flags=("-Warray-bounds", "-Wfortify-source"),
    clang_message_re="",
    # Constant/locally-provable cases only — silence proves nothing
    # about runtime-sized accesses, so no refutation from this family.
    reliable=False,
)

# Loop-bound family: the analyzer's infinite-loop diagnostic
# (gcc >= 14) and clang's -Wloop-analysis (loop variable not updated /
# suspicious condition) fire only on locally-provable shapes —
# confirm-only (silence proves nothing about data-dependent loop
# bounds). Shared by CWE-835 (unreachable exit condition) and its
# parent CWE-834 (excessive iteration).
_LOOP_SPEC = FamilySpec(
    gcc_ids=("-Wanalyzer-infinite-loop",),
    gcc_flags=(),
    clang_engine="warning",
    clang_ids=("-Wloop-analysis",),
    clang_flags=("-Wloop-analysis",),
    clang_message_re="",
    reliable=False,
)

COMPILER_CWE_MAP: dict[str, FamilySpec] = {
    "CWE-416": FamilySpec(
        gcc_ids=("-Wanalyzer-use-after-free",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("unix.Malloc", "cplusplus.NewDelete"),
        clang_flags=(),
        clang_message_re=r"after it is (?:freed|deleted)|use.?after.?free",
        reliable=True,
    ),
    "CWE-415": FamilySpec(
        gcc_ids=("-Wanalyzer-double-free",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("unix.Malloc", "cplusplus.NewDelete"),
        clang_flags=(),
        clang_message_re=r"free released memory|double.?free",
        reliable=True,
    ),
    "CWE-476": FamilySpec(
        gcc_ids=(
            "-Wanalyzer-null-dereference",
            "-Wanalyzer-possible-null-dereference",
        ),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("core.NullDereference", "core.CallAndMessage"),
        clang_flags=(),
        clang_message_re=r"null",
        reliable=True,
    ),
    "CWE-401": FamilySpec(
        gcc_ids=("-Wanalyzer-malloc-leak",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("unix.Malloc", "cplusplus.NewDeleteLeaks"),
        clang_flags=(),
        clang_message_re=r"leak",
        reliable=True,
    ),
    "CWE-134": FamilySpec(
        gcc_ids=("-Wformat-security", "-Wformat-nonliteral"),
        gcc_flags=("-Wformat=2", "-Wformat-security"),
        clang_engine="warning",
        clang_ids=("-Wformat-security", "-Wformat-nonliteral"),
        clang_flags=("-Wformat=2", "-Wformat-security"),
        clang_message_re="",
        # -Wformat-security fires only when the non-literal format is
        # visible in this TU; wrappers defeat it — confirm-only.
        reliable=False,
    ),
    "CWE-119": _OOB_SPEC,
    "CWE-120": _OOB_SPEC,
    "CWE-121": _OOB_SPEC,
    "CWE-122": _OOB_SPEC,
    "CWE-125": _OOB_SPEC,
    "CWE-126": _OOB_SPEC,
    "CWE-130": _OOB_SPEC,
    "CWE-787": _OOB_SPEC,
    # Type confusion via pointer punning: strict-aliasing diagnostics
    # also fire for unused casts and unreachable accesses. Keep aggressive
    # discovery, but neither a warning nor silence is vulnerability proof.
    "CWE-843": FamilySpec(
        gcc_ids=("-Wstrict-aliasing",),
        gcc_flags=("-fstrict-aliasing", "-Wstrict-aliasing=1"),
        clang_engine="warning",
        clang_ids=("-Wstrict-aliasing",),
        clang_flags=("-fstrict-aliasing", "-Wstrict-aliasing"),
        clang_message_re="",
        reliable=False,
        positive_evidence=False,
    ),
    "CWE-834": _LOOP_SPEC,
    "CWE-835": _LOOP_SPEC,
    # Uncontrolled recursion: -Winfinite-recursion (gcc >= 12, clang)
    # fires only when every path through a function provably calls
    # itself — confirm-only (silence proves nothing about
    # data-dependent recursion depth, and an older gcc that rejects
    # the flag degrades this family to inconclusive, never a wrong
    # verdict).
    "CWE-674": FamilySpec(
        gcc_ids=("-Winfinite-recursion",),
        gcc_flags=("-Winfinite-recursion",),
        clang_engine="warning",
        clang_ids=("-Winfinite-recursion",),
        clang_flags=("-Winfinite-recursion",),
        clang_message_re="",
        reliable=False,
    ),
    "CWE-457": FamilySpec(
        gcc_ids=("-Wanalyzer-use-of-uninitialized-value",),
        gcc_flags=(),
        clang_engine="analyze",
        clang_ids=("core.uninitialized", "core.UndefinedBinaryOperatorResult"),
        clang_flags=(),
        clang_message_re=r"uninitial|garbage|undefined",
        reliable=False,
    ),
    # Unchecked return value: corroborates the fail_open channel's
    # ignored-return leg (the diagnostic is receipt material on its
    # confirmations).
    "CWE-252": FamilySpec(
        gcc_ids=("-Wunused-result",),
        gcc_flags=("-Wunused-result",),
        clang_engine="warning",
        clang_ids=("-Wunused-result",),
        clang_flags=("-Wunused-result",),
        clang_message_re="",
        # Fires only for warn_unused_result-attributed callees visible
        # in this TU; silence proves nothing — confirm-only.
        reliable=False,
    ),
}


def _normalise_cwe(cwe: str) -> str:
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return normalized


def compiler_applicable(cwe: str) -> bool:
    """True when the CWE has a compiler-diagnostic mapping."""
    return _normalise_cwe(cwe) in COMPILER_CWE_MAP


def get_compiler_check_role(cwe: str) -> str:
    """Role of the compiler check for a CWE.

    ``"verification"`` for mapped families whose diagnostics can confirm;
    ``"detection"`` for heuristic-only and unmapped families.
    """
    spec = COMPILER_CWE_MAP.get(_normalise_cwe(cwe))
    return "verification" if spec is not None and spec.positive_evidence else "detection"


def compiler_diagnostic_is_candidate(diag_id: str) -> bool:
    """Known heuristic diagnostics cannot acquire authority through a reader."""
    if not isinstance(diag_id, str):
        return False
    normalized = diag_id.removeprefix("compiler:")
    if normalized.startswith("-W"):
        normalized = normalized.partition("=")[0]
    return any(not spec.positive_evidence and _id_matches(normalized, spec.gcc_ids + spec.clang_ids)
               for spec in COMPILER_CWE_MAP.values())


def is_detection_rule_id(rule_id: str) -> bool:
    """Evidence-grade classifier for compiler receipts, including legacy ones."""
    return compiler_diagnostic_is_candidate(rule_id)


def _id_matches(diag_id: str, family_ids: tuple[str, ...]) -> bool:
    """Match a diagnostic id against the family's id list.

    gcc appends ``=`` to parameterised options (``-Wstringop-overflow=``);
    clang checker groups match by prefix (``core.uninitialized`` covers
    ``core.uninitialized.UndefReturn``).
    """
    norm = (diag_id or "").rstrip("=")
    for fam in family_ids:
        fam_norm = fam.rstrip("=")
        if norm == fam_norm or norm.startswith(fam_norm + "."):
            return True
    return False


# These IDs cover several hypothesis families but have an unambiguous broad
# reporting class. Specific compiler-emitted taxonomy metadata takes priority.
_DIAGNOSTIC_REPORTING_CWES = {
    "-Wanalyzer-out-of-bounds": "CWE-119",
    "-Warray-bounds": "CWE-119",
    "-Wfortify-source": "CWE-119",
    "-Wstringop-overflow": "CWE-120",
    "-Wstringop-overread": "CWE-125",
    "-Wanalyzer-infinite-loop": "CWE-835",
    "-Wloop-analysis": "CWE-834",
}


def _reported_cwe(value) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    from core.cve.cwe import canonicalize_cwe, format_cwe
    if isinstance(value, str):
        if len(value) > 32:
            return None
        canonical = canonicalize_cwe(value)
        if canonical:
            return format_cwe(canonical.removeprefix("CWE-"))
    return format_cwe(value)


def compiler_reported_cwe(diagnostic: dict, run: dict | None = None) -> str | None:
    """Read GCC JSON metadata or an explicitly identified SARIF CWE taxonomy.

    Several different taxonomy entries remain ambiguous: never choose one by
    list order. Unknown/malformed metadata does not remove a diagnostic.
    """
    found: set[str] = set()
    metadata = diagnostic.get("metadata")
    if isinstance(metadata, dict):
        cwe = _reported_cwe(metadata.get("cwe"))
        if cwe:
            found.add(cwe)
    taxa = diagnostic.get("taxa")
    if isinstance(taxa, list):
        if len(taxa) > 16:
            return None
        for entry in taxa:
            if not isinstance(entry, dict):
                continue
            component = entry.get("toolComponent")
            if not isinstance(component, dict):
                continue
            taxonomy = None
            name = component.get("name")
            if component.get("index") is not None and isinstance(run, dict):
                index = component.get("index")
                catalogs = run.get("taxonomies")
                if (isinstance(index, int) and not isinstance(index, bool) and isinstance(catalogs, list)
                        and 0 <= index < len(catalogs) and isinstance(catalogs[index], dict)):
                    taxonomy = catalogs[index]
                    indexed_name = taxonomy.get("name")
                    if name is not None and name != indexed_name:
                        continue
                    name = indexed_name
                else:
                    continue
            if not isinstance(name, str) or len(name) != 3 or name.casefold() != "cwe":
                continue
            value = entry.get("id")
            if value is None and isinstance(taxonomy, dict):
                index = entry.get("index")
                entries = taxonomy.get("taxa")
                if (isinstance(index, int) and not isinstance(index, bool) and isinstance(entries, list)
                        and 0 <= index < len(entries) and isinstance(entries[index], dict)):
                    value = entries[index].get("id")
            cwe = _reported_cwe(value)
            if cwe:
                found.add(cwe)
    return next(iter(found)) if len(found) == 1 else None


def diagnostic_cwe(diag_id: str, message: str = "", reported=None) -> str | None:
    """A reporting hint, independent of positive/negative evidence policy."""
    native = _reported_cwe(reported)
    if native:
        return native
    if not isinstance(diag_id, str):
        return None
    normalized = diag_id.partition("=")[0] if diag_id.startswith("-W") else diag_id
    if normalized in _DIAGNOSTIC_REPORTING_CWES:
        return _DIAGNOSTIC_REPORTING_CWES[normalized]
    if not isinstance(message, str) or len(message) > 4096:
        return None
    matches: set[str] = set()
    for cwe, spec in COMPILER_CWE_MAP.items():
        if _id_matches(normalized, spec.gcc_ids):
            matches.add(cwe)
        elif _id_matches(normalized, spec.clang_ids):
            if not spec.clang_message_re or (message and re.search(spec.clang_message_re, message, re.IGNORECASE)):
                matches.add(cwe)
    return next(iter(matches)) if len(matches) == 1 else None
