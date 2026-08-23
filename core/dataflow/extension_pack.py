"""Emit learned taint vocabulary as a CodeQL data-extension pack.

This is the PR2a emitter :mod:`core.dataflow.codeql_augmented_run`
documents: it turns validated project vocabulary — IRIS taint specs
(:class:`core.iris.specs.TaintSpec`) and sanitizer-evidence candidates
(:class:`core.dataflow.sanitizer_evidence.CandidateValidator`) — into a
models-as-data extension pack that ``codeql database analyze
--additional-packs <pack>`` consumes, so the *stock* queries learn the
target's own sources, sinks, summaries, and (for C/C++) barriers.

Row shapes are pinned to the extensible predicates of the vendored
stdlib packs this was verified against:

* ``codeql/cpp-all`` (12.x) — 9-column ``sourceModel``/``sinkModel``/
  ``barrierModel``, 10-column ``summaryModel``
  (namespace, type, subtypes, name, signature, ext, access…, kind,
  provenance).
* ``codeql/python-all`` (7.x) — 3-column ``sourceModel``/``sinkModel``
  (type, path, kind), 5-column ``summaryModel``
  (type, path, input, output, kind).

Languages whose stdlib row shapes have not been verified against a
real pack are refused loudly rather than emitted speculatively — a
malformed extension file fails the whole ``codeql database analyze``
invocation. Adding a language is a data-only change to
``_LANGUAGE_LAYOUTS`` once its shapes are confirmed.

Trust properties:

* **Provenance gate** — rows whose provenance is ``llm_prior`` /
  ``llm_summarized`` (training memory, unverified summarization) or
  missing are rejected, mirroring
  :func:`core.audit.condition_smt.DomainVocabulary`'s policy. The
  emitter reports every rejection with a reason; nothing is silently
  dropped.
* **Cell validation** — every learned name is validated against a
  strict per-family grammar before it is written. YAML emission uses
  ``json.dumps`` per row (JSON is a YAML subset), so no learned string
  can escape its cell.
* **Determinism** — rows are de-duplicated and sorted so packs diff
  cleanly across runs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Iterable, Mapping, Sequence

from core.evidence import EvidenceTier, TIER_RANK

SCHEMA_VERSION = 1

# ── provenance gate ──────────────────────────────────────────────────

#: Provenance values accepted into engine configuration. Everything
#: else is rejected: ``llm_prior`` (training memory), ``llm_summarized``
#: (unverified summarization), and unknown/missing values.
ACCEPTED_PROVENANCE = frozenset({
    "verbatim",          # study receipts: quoted from source
    "mechanical",        # study receipts: tool-derived
    "study",             # domain-model vocabulary
    "iris_refined",      # IRIS spec that survived the refinement loop
    "llm_extracted",     # LLM-extracted from source + identifier-validated
    "operator",          # operator-declared
    "annotation",        # human /annotate note
    "framework_catalog", # curated catalog
})

REJECTED_PROVENANCE = frozenset({"llm_prior", "llm_summarized"})

#: models-as-data provenance column value by RAPTOR provenance.
#: Human-attested rows are "manual"; everything learned is
#: "ai-generated" (upstream MaD vocabulary).
_MAD_PROVENANCE = {
    "operator": "manual",
    "annotation": "manual",
    "framework_catalog": "manual",
}
_MAD_PROVENANCE_DEFAULT = "ai-generated"

# ── roles and layouts ────────────────────────────────────────────────

ROLE_SOURCE = "source"
ROLE_SINK = "sink"
ROLE_SUMMARY = "summary"
ROLE_BARRIER = "barrier"
VALID_ROLES = frozenset({ROLE_SOURCE, ROLE_SINK, ROLE_SUMMARY, ROLE_BARRIER})

#: role → extensible predicate name, per language. Only combinations
#: verified against a vendored stdlib pack appear here.
_LANGUAGE_LAYOUTS: Mapping[str, Mapping[str, str]] = {
    "cpp": {
        ROLE_SOURCE: "sourceModel",
        ROLE_SINK: "sinkModel",
        ROLE_SUMMARY: "summaryModel",
        ROLE_BARRIER: "barrierModel",
    },
    "python": {
        ROLE_SOURCE: "sourceModel",
        ROLE_SINK: "sinkModel",
        ROLE_SUMMARY: "summaryModel",
        # python-all has no barrierModel extensible predicate; barrier
        # rows are rejected with a directed reason (use QL barrier
        # synthesis instead — core/dataflow/barrier_synth.py).
    },
    # java-all rows share the cpp 9/10-column family (package, type,
    # subtypes, name, signature, ext, access, kind, provenance) —
    # verified against codeql/java-all 9.0.4's ext/*.model.yml.
    "java": {
        ROLE_SOURCE: "sourceModel",
        ROLE_SINK: "sinkModel",
        ROLE_SUMMARY: "summaryModel",
        ROLE_BARRIER: "barrierModel",
    },
}

SUPPORTED_LANGUAGES = frozenset(_LANGUAGE_LAYOUTS)

_STDLIB_PACK = {
    "cpp": "codeql/cpp-all",
    "python": "codeql/python-all",
    "java": "codeql/java-all",
}

# ── cell grammars ────────────────────────────────────────────────────

# C/C++ namespace: alnum plus :: < > , * & space ~ -. No quotes,
# backslashes, or control characters can pass.
_CPP_NAMESPACE_RE = re.compile(r"^[A-Za-z_~][\w:<>,*&\s~-]*$")
_CPP_TYPE_RE = _CPP_NAMESPACE_RE
# Function name: a plain (optionally destructor) identifier.
_CPP_NAME_RE = re.compile(r"^~?[A-Za-z_]\w*$")
# Java package (dotted identifiers; empty = default package), type
# (identifier, nested via $ or .), name, and "(Type,Type)" signature
# of erased simple types — the stdlib ext-file conventions.
_JAVA_PACKAGE_RE = re.compile(r"^([A-Za-z_]\w*(\.[A-Za-z_]\w*)*)?$")
_JAVA_TYPE_RE = re.compile(r"^[A-Za-z_]\w*([.$][A-Za-z_]\w*)*$")
_JAVA_NAME_RE = re.compile(r"^[A-Za-z_]\w*$")
_JAVA_SIGNATURE_RE = re.compile(r"^\([\w\s,.<>\[\]$]*\)$")
# Python dotted type path; a leading ~ on a segment is the stdlib
# "match by name suffix" convention (e.g. asyncpg.~Connection).
_PY_TYPE_RE = re.compile(r"^~?[A-Za-z_]\w*(\.~?[A-Za-z_]\w*)*$")
# Access-path component grammar shared by both families:
#   Member[x], Argument[0], Argument[*1], Argument[0,query:],
#   Parameter[0], ReturnValue, Subscript[0], Awaited, Element, Field[x]
_ACCESS_PART_RE = re.compile(
    r"^(ReturnValue|Awaited|Element|MapKey|MapValue"
    r"|(Member|Argument|Parameter|Subscript|Field)\[[\w\s,.:*+-]*\])$"
)
_KIND_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_SIGNATURE_RE = re.compile(r"^[\w\s,:<>*&()\[\]~-]*$")


def _valid_access(path: str, *, allow_empty: bool = False) -> bool:
    if not path:
        return allow_empty
    return all(_ACCESS_PART_RE.match(part) for part in path.split("."))


# ── row model ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ModelRow:
    """One learned model row, engine-family neutral.

    cpp-family rows use ``namespace``/``type_name``/``name`` plus the
    access fields; python-family rows use ``type_name`` (dotted path)
    plus ``path`` (access path rooted at the type). ``model_kind`` is
    the source/sink/summary kind column (``remote``,
    ``sql-injection``, ``taint``, …); for barrier rows it names the
    sink kind the barrier neutralizes.
    """

    role: str
    provenance: str
    confidence: float = 1.0
    namespace: str = ""
    type_name: str = ""
    name: str = ""
    path: str = ""
    subtypes: bool = False
    signature: str = ""
    access_input: str = ""
    access_output: str = ""
    model_kind: str = ""

    def summary(self) -> str:
        coord = self.path or self.name or self.type_name
        scope = self.type_name if self.path or self.name else self.namespace
        where = f"{scope}.{coord}" if scope and coord != scope else coord
        return f"{self.role}:{where or '<empty>'}:{self.model_kind}"


@dataclass(frozen=True)
class RejectedRow:
    row: str
    reason: str


@dataclass(frozen=True)
class ExtensionPackResult:
    """Outcome of one :func:`write_extension_pack` call."""

    pack_dir: Path
    model_file: Path
    language: str
    pack_name: str
    counts: Mapping[str, int]          # extensible predicate → rows written
    rejected: tuple[RejectedRow, ...]  # every input row not written, with reason

    @property
    def rows_written(self) -> int:
        return sum(self.counts.values())

    def to_dict(self) -> dict:
        return {
            "pack_dir": str(self.pack_dir),
            "model_file": str(self.model_file),
            "language": self.language,
            "pack_name": self.pack_name,
            "counts": dict(self.counts),
            "rows_written": self.rows_written,
            "rejected": [
                {"row": r.row, "reason": r.reason} for r in self.rejected
            ],
        }


# ── validation ───────────────────────────────────────────────────────


def _gate_provenance(row: ModelRow) -> str | None:
    if not row.provenance:
        return "provenance missing"
    if row.provenance in REJECTED_PROVENANCE:
        return f"provenance {row.provenance!r} is not evidence-backed"
    if row.provenance not in ACCEPTED_PROVENANCE:
        return (
            f"provenance {row.provenance!r} unknown; accepted: "
            f"{sorted(ACCEPTED_PROVENANCE)}"
        )
    return None


def _validate_common(row: ModelRow) -> str | None:
    if row.role not in VALID_ROLES:
        return f"role {row.role!r} not in {sorted(VALID_ROLES)}"
    if not _KIND_RE.match(row.model_kind or ""):
        return f"model_kind {row.model_kind!r} fails kind grammar"
    if not (0.0 <= row.confidence <= 1.0):
        return f"confidence {row.confidence!r} outside [0, 1]"
    return None


def _validate_cpp(row: ModelRow) -> str | None:
    if row.namespace and not _CPP_NAMESPACE_RE.match(row.namespace):
        return f"namespace {row.namespace!r} fails cpp grammar"
    if row.type_name and not _CPP_TYPE_RE.match(row.type_name):
        return f"type {row.type_name!r} fails cpp grammar"
    if not _CPP_NAME_RE.match(row.name or ""):
        return f"name {row.name!r} fails cpp identifier grammar"
    if row.signature and not _SIGNATURE_RE.match(row.signature):
        return f"signature {row.signature!r} fails signature grammar"
    if row.role in (ROLE_SOURCE, ROLE_BARRIER) and not _valid_access(row.access_output):
        return f"output access {row.access_output!r} fails access grammar"
    if row.role == ROLE_SINK and not _valid_access(row.access_input):
        return f"input access {row.access_input!r} fails access grammar"
    if row.role == ROLE_SUMMARY and not (
        _valid_access(row.access_input) and _valid_access(row.access_output)
    ):
        return (
            f"summary access {row.access_input!r}→{row.access_output!r} "
            "fails access grammar"
        )
    return None


def _validate_python(row: ModelRow) -> str | None:
    if not _PY_TYPE_RE.match(row.type_name or ""):
        return f"type {row.type_name!r} fails python dotted-path grammar"
    if not _valid_access(row.path):
        return f"path {row.path!r} fails access grammar"
    if row.role == ROLE_SUMMARY and not (
        _valid_access(row.access_input) and _valid_access(row.access_output)
    ):
        return (
            f"summary access {row.access_input!r}→{row.access_output!r} "
            "fails access grammar"
        )
    return None


def _validate_java(row: ModelRow) -> str | None:
    if not _JAVA_PACKAGE_RE.match(row.namespace or ""):
        return f"package {row.namespace!r} fails java grammar"
    if not _JAVA_TYPE_RE.match(row.type_name or ""):
        return f"type {row.type_name!r} fails java grammar"
    if not _JAVA_NAME_RE.match(row.name or ""):
        return f"name {row.name!r} fails java identifier grammar"
    if not _JAVA_SIGNATURE_RE.match(row.signature or "()"):
        return f"signature {row.signature!r} fails java signature grammar"
    if row.role in (ROLE_SOURCE, ROLE_BARRIER) and not _valid_access(row.access_output):
        return f"output access {row.access_output!r} fails access grammar"
    if row.role == ROLE_SINK and not _valid_access(row.access_input):
        return f"input access {row.access_input!r} fails access grammar"
    if row.role == ROLE_SUMMARY and not (
        _valid_access(row.access_input) and _valid_access(row.access_output)
    ):
        return (
            f"summary access {row.access_input!r}→{row.access_output!r} "
            "fails access grammar"
        )
    return None


def _validate(row: ModelRow, language: str) -> str | None:
    reason = _gate_provenance(row) or _validate_common(row)
    if reason:
        return reason
    layout = _LANGUAGE_LAYOUTS[language]
    if row.role not in layout:
        if language == "python" and row.role == ROLE_BARRIER:
            return (
                "codeql/python-all has no barrierModel extensible "
                "predicate; use QL barrier synthesis "
                "(core/dataflow/barrier_synth.py) for python sanitizers"
            )
        return f"role {row.role!r} unsupported for language {language!r}"
    if language == "cpp":
        return _validate_cpp(row)
    if language == "java":
        return _validate_java(row)
    return _validate_python(row)


# ── cell emission ────────────────────────────────────────────────────


def _mad_provenance(row: ModelRow) -> str:
    return _MAD_PROVENANCE.get(row.provenance, _MAD_PROVENANCE_DEFAULT)


def _cells(row: ModelRow, language: str) -> list:
    if language in ("cpp", "java"):
        sig = row.signature
        if language == "java" and not sig:
            sig = "()"
        base = [
            row.namespace,
            row.type_name,
            row.subtypes,
            row.name,
            sig,
            "",  # ext (subclass extension column) — unused
        ]
        prov = _mad_provenance(row)
        if row.role == ROLE_SOURCE:
            return base + [row.access_output, row.model_kind, prov]
        if row.role == ROLE_SINK:
            return base + [row.access_input, row.model_kind, prov]
        if row.role == ROLE_BARRIER:
            return base + [row.access_output, row.model_kind, prov]
        return base + [row.access_input, row.access_output, row.model_kind, prov]
    # python family
    if row.role == ROLE_SUMMARY:
        return [
            row.type_name, row.path,
            row.access_input, row.access_output, row.model_kind,
        ]
    return [row.type_name, row.path, row.model_kind]


# ── pack emission ────────────────────────────────────────────────────

_DEFAULT_PACK_PREFIX = "raptor/learned-models"


def write_extension_pack(
    rows: Iterable[ModelRow],
    *,
    language: str,
    out_dir: Path,
    pack_name: str | None = None,
    pack_version: str = "0.0.0",
) -> ExtensionPackResult:
    """Write a CodeQL data-extension pack for *language* under *out_dir*.

    Returns an :class:`ExtensionPackResult` whose ``pack_dir`` feeds
    ``codeql database analyze --additional-packs`` (see
    :func:`core.dataflow.codeql_augmented_run.analyze`). Every input
    row that fails the provenance gate or a cell grammar lands in
    ``rejected`` with a reason — check ``rows_written`` before running
    an augmented analysis.

    Raises :class:`ValueError` for unsupported languages (unverified
    row shapes are never emitted speculatively) and for a
    ``pack_name`` outside CodeQL's ``scope/name`` grammar.
    """
    if language not in SUPPORTED_LANGUAGES:
        msg = (
            f"language {language!r} unsupported; verified layouts exist "
            f"for {sorted(SUPPORTED_LANGUAGES)}"
        )
        raise ValueError(msg)
    name = pack_name or f"{_DEFAULT_PACK_PREFIX}-{language}"
    if not re.match(r"^[a-z][\w-]*/[a-z][\w-]*$", name):
        msg = f"pack_name {name!r} is not a valid scope/name"
        raise ValueError(msg)
    if not re.match(r"^\d+\.\d+\.\d+$", pack_version):
        msg = f"pack_version {pack_version!r} is not semver"
        raise ValueError(msg)

    by_predicate: dict[str, set[tuple]] = {}
    rejected: list[RejectedRow] = []
    layout = _LANGUAGE_LAYOUTS[language]

    for row in rows:
        reason = _validate(row, language)
        if reason:
            rejected.append(RejectedRow(row=row.summary(), reason=reason))
            continue
        predicate = layout[row.role]
        by_predicate.setdefault(predicate, set()).add(
            tuple(_cells(row, language))
        )

    pack_dir = Path(out_dir) / name.replace("/", "-")
    models_dir = pack_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    stdlib_pack = _STDLIB_PACK[language]
    lines = [
        "# Generated by core.dataflow.extension_pack — do not hand-edit.",
        "# Learned project vocabulary emitted as models-as-data rows;",
        "# provenance-gated and cell-validated at emission time.",
        "extensions:",
    ]
    for predicate in sorted(by_predicate):
        lines.append("  - addsTo:")
        lines.append(f"      pack: {stdlib_pack}")
        lines.append(f"      extensible: {predicate}")
        lines.append("    data:")
        # json.dumps output is a valid YAML flow sequence; learned
        # strings cannot escape their cell.
        lines.extend(f"      - {json.dumps(list(cells))}" for cells in sorted(by_predicate[predicate]))
    model_file = models_dir / f"{language}.model.yml"
    model_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    (pack_dir / "codeql-pack.yml").write_text(
        "\n".join([
            f"name: {name}",
            f"version: {pack_version}",
            "library: true",
            "extensionTargets:",
            f"  {stdlib_pack}: \"*\"",
            "dataExtensions:",
            "  - models/*.model.yml",
        ]) + "\n",
        encoding="utf-8",
    )

    return ExtensionPackResult(
        pack_dir=pack_dir,
        model_file=model_file,
        language=language,
        pack_name=name,
        counts={p: len(r) for p, r in sorted(by_predicate.items())},
        rejected=tuple(rejected),
    )


# ── converters ───────────────────────────────────────────────────────

#: IRIS taint_class → MaD source kind (best-effort defaults; callers
#: may override via the converter's kind maps).
DEFAULT_SOURCE_KINDS: Mapping[str, str] = {
    "remote": "remote",
    "network": "remote",
    "http": "remote",
    "file": "file",
    "filesystem": "file",
    "environment": "environment",
    "env": "environment",
    "commandargs": "commandargs",
    "argv": "commandargs",
    "stdin": "stdin",
    "database": "database",
}
DEFAULT_SOURCE_KIND_FALLBACK = "local"

#: IRIS taint_class → MaD sink kind.
DEFAULT_SINK_KINDS: Mapping[str, str] = {
    "command_injection": "command-injection",
    "os_command": "command-injection",
    "sql_injection": "sql-injection",
    "sql": "sql-injection",
    "path_traversal": "path-injection",
    "path_injection": "path-injection",
    "code_injection": "code-injection",
    "eval": "code-injection",
    "ssrf": "request-forgery",
    "request_forgery": "request-forgery",
    "log_injection": "log-injection",
    "url_redirect": "url-redirection",
}

#: CandidateValidator semantics_tag → the sink kind the barrier
#: neutralizes (cpp barrierModel only).
DEFAULT_BARRIER_KINDS: Mapping[str, str] = {
    "sql_escape": "sql-injection",
    "path_normalize": "path-injection",
    "url_allowlist": "request-forgery",
}

#: Minimum evidence tier for spec-derived rows (inclusive).
DEFAULT_MIN_TIER = EvidenceTier.XREF_BACKED


@dataclass(frozen=True)
class ConversionResult:
    rows: tuple[ModelRow, ...]
    rejected: tuple[RejectedRow, ...] = field(default_factory=tuple)


def _split_cpp_function(qualified: str) -> tuple[str, str]:
    """``ns::sub::fn`` → (``ns::sub``, ``fn``); bare name → ("", name)."""
    if "::" in qualified:
        ns, _, fn = qualified.rpartition("::")
        return ns, fn
    return "", qualified


def _split_python_function(qualified: str) -> tuple[str, str]:
    """``pkg.mod.fn`` → (``pkg.mod``, ``fn``); bare name → ("", name)."""
    if "." in qualified:
        mod, _, fn = qualified.rpartition(".")
        return mod, fn
    return "", qualified


def rows_from_taint_specs(
    specs: Sequence,
    *,
    language: str,
    min_confidence: float = 0.6,
    min_tier: EvidenceTier = DEFAULT_MIN_TIER,
    source_kinds: Mapping[str, str] = DEFAULT_SOURCE_KINDS,
    sink_kinds: Mapping[str, str] = DEFAULT_SINK_KINDS,
    deref_cpp_args: bool = True,
) -> ConversionResult:
    """Convert IRIS :class:`~core.iris.specs.TaintSpec` records to rows.

    Gates: ``evidence_tier`` at or above *min_tier* (specs below it
    are LLM output that never earned corroboration) and ``confidence``
    at or above *min_confidence*. Sanitiser specs become cpp barrier
    rows; python sanitisers are rejected with a directed reason (no
    barrierModel predicate upstream). Propagator specs become summary
    rows. ``deref_cpp_args`` emits ``Argument[*N]`` (pointer content —
    the common case for C string/buffer APIs) instead of
    ``Argument[N]``.
    """
    rows: list[ModelRow] = []
    rejected: list[RejectedRow] = []
    min_rank = TIER_RANK[min_tier]

    for spec in specs:
        label = f"{spec.role}:{spec.function}"
        if TIER_RANK.get(spec.evidence_tier, -1) < min_rank:
            rejected.append(RejectedRow(
                row=label,
                reason=(
                    f"evidence tier {spec.evidence_tier.value} below "
                    f"{min_tier.value}"
                ),
            ))
            continue
        if spec.confidence < min_confidence:
            rejected.append(RejectedRow(
                row=label,
                reason=f"confidence {spec.confidence} below {min_confidence}",
            ))
            continue

        provenance = "iris_refined"
        if language == "cpp":
            ns, fn = _split_cpp_function(spec.function)
            arg = (lambda i: f"Argument[*{i}]") if deref_cpp_args else (
                lambda i: f"Argument[{i}]")
            common = dict(namespace=ns, name=fn, provenance=provenance,
                          confidence=spec.confidence)
        else:
            mod, fn = _split_python_function(spec.function)
            member = f"Member[{fn}]" if mod else fn
            common = dict(type_name=mod or fn, provenance=provenance,
                          confidence=spec.confidence)

        if spec.role == "source":
            kind = DEFAULT_SOURCE_KIND_FALLBACK
            for tc in spec.taint_classes:
                if tc in source_kinds:
                    kind = source_kinds[tc]
                    break
            if not spec.return_tainted:
                rejected.append(RejectedRow(
                    row=label,
                    reason="source spec without return_tainted has no "
                           "expressible output access",
                ))
                continue
            if language == "cpp":
                rows.append(ModelRow(role=ROLE_SOURCE, model_kind=kind,
                                     access_output="ReturnValue", **common))
            else:
                rows.append(ModelRow(
                    role=ROLE_SOURCE, model_kind=kind,
                    path=f"{member}.ReturnValue" if mod else "ReturnValue",
                    **common))
        elif spec.role == "sink":
            kind = None
            for tc in spec.taint_classes:
                if tc in sink_kinds:
                    kind = sink_kinds[tc]
                    break
            if kind is None:
                rejected.append(RejectedRow(
                    row=label,
                    reason=(
                        f"no sink kind mapping for taint_classes "
                        f"{spec.taint_classes!r}"
                    ),
                ))
                continue
            params = spec.params_affected or [0]
            for i in params:
                if language == "cpp":
                    rows.append(ModelRow(role=ROLE_SINK, model_kind=kind,
                                         access_input=arg(i), **common))
                else:
                    rows.append(ModelRow(
                        role=ROLE_SINK, model_kind=kind,
                        path=(f"{member}.Argument[{i}]" if mod
                              else f"Argument[{i}]"),
                        **common))
        elif spec.role == "sanitiser":
            if language != "cpp":
                rejected.append(RejectedRow(
                    row=label,
                    reason="sanitiser specs map to barrierModel, which "
                           "only codeql/cpp-all provides; use QL barrier "
                           "synthesis for python",
                ))
                continue
            kind = None
            for tc in spec.taint_classes:
                if tc in sink_kinds:
                    kind = sink_kinds[tc]
                    break
            if kind is None:
                rejected.append(RejectedRow(
                    row=label,
                    reason=(
                        f"no barrier kind mapping for taint_classes "
                        f"{spec.taint_classes!r}"
                    ),
                ))
                continue
            out = "ReturnValue" if spec.return_tainted else arg(
                (spec.params_affected or [0])[0])
            rows.append(ModelRow(role=ROLE_BARRIER, model_kind=kind,
                                 access_output=out, **common))
        elif spec.role == "propagator":
            params = spec.params_affected or [0]
            if language == "cpp":
                rows.append(ModelRow(role=ROLE_SUMMARY, model_kind="taint",
                                     access_input=arg(params[0]),
                                     access_output="ReturnValue", **common))
            elif not mod:
                rejected.append(RejectedRow(
                    row=label,
                    reason="python propagator needs a module-qualified "
                           "name (bare names have no type path)",
                ))
                continue
            else:
                rows.append(ModelRow(
                    role=ROLE_SUMMARY, model_kind="taint",
                    path=member,
                    access_input=f"Argument[{params[0]}]",
                    access_output="ReturnValue", **common))
        else:
            rejected.append(RejectedRow(row=label,
                                        reason=f"role {spec.role!r} unknown"))
    return ConversionResult(rows=tuple(rows), rejected=tuple(rejected))


def rows_from_candidate_validators(
    candidates: Sequence,
    *,
    language: str,
    min_confidence: float = 0.6,
    barrier_kinds: Mapping[str, str] = DEFAULT_BARRIER_KINDS,
) -> ConversionResult:
    """Convert :class:`CandidateValidator` sanitizer records to barrier
    rows (cpp only — see :func:`rows_from_taint_specs` for the python
    rationale). The validator's sanitized value is modelled as its
    return value; semantics tags without a barrier-kind mapping
    (``auth_check``, ``rate_limit``, ``other``…) are rejected because
    they don't neutralize a dataflow sink kind.
    """
    rows: list[ModelRow] = []
    rejected: list[RejectedRow] = []
    for cand in candidates:
        label = f"barrier:{cand.qualified_name}"
        if cand.confidence < min_confidence:
            rejected.append(RejectedRow(
                row=label,
                reason=f"confidence {cand.confidence} below {min_confidence}",
            ))
            continue
        if language != "cpp":
            rejected.append(RejectedRow(
                row=label,
                reason="barrierModel rows are cpp-only; use QL barrier "
                       "synthesis for python",
            ))
            continue
        kind = barrier_kinds.get(cand.semantics_tag)
        if kind is None:
            rejected.append(RejectedRow(
                row=label,
                reason=(
                    f"semantics_tag {cand.semantics_tag!r} has no "
                    "barrier-kind mapping"
                ),
            ))
            continue
        ns, fn = _split_cpp_function(cand.qualified_name)
        provenance = {
            "llm": "llm_extracted",
            "annotation": "annotation",
            "framework_catalog": "framework_catalog",
        }.get(cand.extraction_provenance, cand.extraction_provenance)
        rows.append(ModelRow(
            role=ROLE_BARRIER,
            namespace=ns,
            name=fn,
            access_output="ReturnValue",
            model_kind=kind,
            provenance=provenance,
            confidence=cand.confidence,
        ))
    return ConversionResult(rows=tuple(rows), rejected=tuple(rejected))
