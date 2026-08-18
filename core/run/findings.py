"""Per-finding provenance stamping + publication-grade projection.

Two responsibilities in one module:

* ``stamp_findings_in_run`` (lifecycle hook) — adds a ``provenance_refs``
  back-link from each finding to the run that produced it. Closes the gap
  between the L1 provenance layer (``.raptor-run.json``) and individual
  findings. See the per-feature notes below.
* ``finding_public_view`` (pure projector) — substrate for the disclosure
  tooling theme (``/cite``, ZKPoX 1.5+ attestation, hall-of-fame ingestion).
  Captures only the IMMUTABLE structural facts a finding carries; excludes
  every mutable interpretation (severity, status, ruling, reasoning) on the
  principle that those are operator-claim territory made at publication
  time, not stamped into a permanent record here.

------- provenance_refs stamping --------------------------------------

Closes the gap between the L1 provenance layer (which records *what produced
this run* in ``.raptor-run.json``) and individual findings (which historically
carried no back-reference to the run that produced them). After a run
completes, every finding gets a ``provenance_refs`` field — a list (always
plural, one entry at stamp time) of ``{run_id, ts, manifest_path}`` triples.

Why plural from day 1: cross-run merging (``core/project/merge.py``)
collapses N runs that surface the same finding into ONE record. The merged
record's ``provenance_refs`` is the UNION of all source runs' refs — the
plural shape makes that concatenation trivial without a singular/plural
schema awkwardness post-merge.

What's INTENTIONALLY thin in a ProvenanceRef:
  * run_id      = the run-dir basename (stable, file-system grep-able).
  * ts          = the manifest's start-time ISO timestamp.
  * manifest_path = the path to ``.raptor-run.json``, always relative to
    the run dir (see ``_relative_manifest_path``). Consumers resolve it
    against the run dir themselves; nothing in this module dereferences
    an absolute manifest_path from a finding record.

Engines / models / target / det_repro are NOT duplicated here. Consumers
that need them call ``core.run.load_run_metadata(Path(manifest_path).parent)``.
This keeps the per-finding payload small and forces single-source-of-truth
reads against the manifest.

NOT stamped: SARIF files (the SARIF spec has its own ``tool`` / ``run`` /
``originalUriBaseIds`` provenance; injecting our own field would mangle the
standard). Only files matching the ``findings.json`` convention.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

from core.logging import get_logger

from .metadata import RUN_METADATA_FILE, load_run_metadata

logger = get_logger()

# Field name on each finding dict. Always a list (plural-from-day-1).
PROVENANCE_REFS_FIELD = "provenance_refs"

# Files we stamp, relative to the run dir. Tested via load_findings_from_dir's
# shape detection (top-level list OR {"findings": [...]} wrapper).
_STAMP_PATHS: tuple = (
    "findings.json",
    "sca/findings.json",
)


def build_provenance_ref(run_dir: Path) -> dict[str, Any] | None:
    """Build the per-finding ProvenanceRef for ``run_dir``.

    Returns ``None`` if the run dir has no ``.raptor-run.json`` (an
    untracked output dir, or a stale partial run). Callers MUST treat
    ``None`` as "no provenance available" and SKIP stamping — never
    synthesise a partial ref.
    """
    manifest = load_run_metadata(run_dir)
    if not manifest:
        return None
    ref = {
        "run_id": run_dir.name,
        "manifest_path": str(_relative_manifest_path(run_dir)),
    }
    # Manifest top-level uses ``timestamp`` (per core/run/metadata.py
    # generate_run_metadata). Accept legacy/alternate keys defensively.
    ts = manifest.get("timestamp") or manifest.get("started_at") or manifest.get("ts")
    if ts:
        ref["ts"] = ts
    return ref


def _relative_manifest_path(run_dir: Path) -> Path:
    """Manifest path relative to ``run_dir`` (so it survives moves of the
    enclosing project dir). Always returns a relative path within the run."""
    return Path(RUN_METADATA_FILE)


def stamp_findings_in_run(run_dir: Path) -> dict[str, int]:
    """Walk every ``findings.json`` in ``run_dir`` and inject
    ``provenance_refs`` into each finding that doesn't already have it.

    Idempotent — re-running on an already-stamped run is a no-op. Best-effort
    per file: a malformed ``findings.json`` is logged and skipped, doesn't
    abort the lifecycle. Returns ``{"files_stamped", "findings_stamped",
    "files_skipped"}``.

    No-op when the run dir has no manifest (returns zeros) — callers must
    not assume stamping succeeded; check the counts.
    """
    counts = {"files_stamped": 0, "findings_stamped": 0, "files_skipped": 0}
    run_dir = Path(run_dir)
    ref = build_provenance_ref(run_dir)
    if ref is None:
        logger.debug("No manifest in %s; skipping stamping.", run_dir)
        return counts

    for rel in _STAMP_PATHS:
        path = run_dir / rel
        if not path.is_file():
            continue
        stamped = _stamp_file(path, ref)
        if stamped < 0:
            counts["files_skipped"] += 1
        elif stamped > 0:
            counts["files_stamped"] += 1
            counts["findings_stamped"] += stamped
    return counts


def _stamp_file(path: Path, ref: dict[str, Any]) -> int:
    """Stamp findings in one file. Returns count of findings newly stamped,
    or -1 on parse failure (file skipped, not modified)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("stamp_findings: read failed %s: %s", path, e)
        return -1
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("stamp_findings: parse failed %s: %s", path, e)
        return -1

    findings_list, _container_kind = _resolve_findings_list(data)
    if findings_list is None:
        # Shape we don't recognise — skip silently rather than risk mangling.
        return 0

    new_count = 0
    for f in findings_list:
        if not isinstance(f, dict):
            continue
        existing = f.get(PROVENANCE_REFS_FIELD)
        if isinstance(existing, list) and any(
            isinstance(r, dict) and r.get("run_id") == ref["run_id"]
            for r in existing
        ):
            # Idempotent — already stamped for this run.
            continue
        # Plural-from-day-1: always a list. New stamp = single-element.
        if isinstance(existing, list):
            existing.append(ref)
        else:
            f[PROVENANCE_REFS_FIELD] = [ref]
        new_count += 1

    if new_count == 0:
        return 0

    # Re-serialize ``data`` itself — the stamp mutated the findings
    # list by reference, so the container shape (top-level array vs
    # dict-wrapped) is preserved without shape-dependent branches.
    out = json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
    try:
        from core.atomic_fs import write_text_atomically
        write_text_atomically(path, out)
    except OSError as e:
        logger.warning("stamp_findings: write failed %s: %s", path, e)
        return -1
    return new_count


def _resolve_findings_list(
    data: Any,
) -> tuple[list[Any] | None, str | None]:
    """Mirror load_findings_from_dir's shape detection but return the LIST
    by reference so mutations stamp into the original container.

    Returns ``(list_ref, container_kind)`` where container_kind is
    ``"list"`` for a top-level array, ``"dict"`` for a wrapped shape, or
    ``(None, None)`` if neither applies.
    """
    if isinstance(data, list):
        return data, "list"
    if isinstance(data, dict):
        for key in ("findings", "results"):
            v = data.get(key)
            if isinstance(v, list):
                return v, "dict"
    return None, None


# ------- finding_public_view (publication-grade projector) -----------------
#
# Pure projection of immutable structural facts for publication-grade
# consumers (/cite, ZKPoX 1.5+ attestation, hall-of-fame ingestion).
# Captures only what cannot move post-discovery: file/line/cwe/vuln_type/
# provenance refs. Mutable interpretations (severity, status, ruling,
# reasoning) are deliberately excluded — they're operator-claim territory,
# made at publication time, not stamped here. This keeps the projection
# never-stale: if the underlying finding's status moves through validation,
# the public view doesn't lie because the public view never claimed it.

FINDING_PUBLIC_SCHEMA_VERSION = 1

# Top-level allowlist. Strings get L1-strict character validation; the
# ``file`` field additionally gets path-relativised. Lists/dicts that
# happen to land here (cwe_ids = list of strings, references = list of
# URLs) get per-element validation. provenance_refs passes through.
_ALLOWED_FIELDS = (
    "id", "finding_id",
    "file", "function", "line", "column",
    "vuln_type", "cwe_id", "cwe_ids",
    "references",
    "provenance_refs",
)


def finding_public_view(
    finding: dict[str, Any],
    *,
    target_path: str | None = None,
) -> dict[str, Any]:
    """Project ``finding`` into the publication-grade public view.

    Returns a dict containing only the immutable structural facts —
    where the bug lives (file/function/line/column), what class it is
    (vuln_type/cwe_id), and the back-link to the producing run
    (provenance_refs). Mutable interpretations (severity, status,
    ruling, reasoning, snippets) are dropped by design.

    ``target_path`` anchors the ``file`` field's relativisation. When
    omitted, the ``file`` field falls back to the basename. The
    ``manifest_path`` on provenance_refs is never dereferenced here:
    stamping only ever writes the run-dir-relative ``.raptor-run.json``
    and the projector has no run directory to resolve it inside, so an
    absolute ``manifest_path`` in a crafted record is treated as a
    missing manifest rather than read. Absolute paths are never
    emitted (they leak deployment topology).

    Strings are L1-strict validated (reject control bytes / ANSI
    escapes / unicode category C*). A field that fails validation is
    DROPPED rather than emitted — the other fields survive, so a
    single malformed value doesn't kill the projection.

    Pure / deterministic / idempotent: ``finding_public_view(
    finding_public_view(f, target_path=t), target_path=t)`` is equal
    to ``finding_public_view(f, target_path=t)``.
    """
    out: dict[str, Any] = {"schema": FINDING_PUBLIC_SCHEMA_VERSION}
    if not isinstance(finding, dict):
        return out

    anchor = target_path

    for key in _ALLOWED_FIELDS:
        if key not in finding:
            continue
        value = finding[key]
        if key == "file":
            cleaned = _publish_path(value, anchor)
        elif key == "provenance_refs":
            cleaned = _passthrough_provenance_refs(value)
        elif isinstance(value, str):
            cleaned = _publish_string(value)
        elif isinstance(value, list):
            cleaned = _publish_list(value)
        elif isinstance(value, (int, float, bool)) or value is None:
            cleaned = value
        elif isinstance(value, dict):
            # We deliberately don't recurse into arbitrary dicts —
            # the allowlist is flat, so a dict here is unexpected and
            # safest to drop rather than risk passing nested sensitive
            # content through.
            cleaned = _DROP
        else:
            cleaned = _DROP
        if cleaned is _DROP:
            continue
        out[key] = cleaned
    return out


# Sentinel — distinguishes "drop this field" from "emit None"
class _Drop:
    pass


_DROP = _Drop()


def _publish_string(value: str) -> Any:
    """L1-strict: reject control bytes (0x00-0x1f), ANSI escape (0x1b),
    unicode category C* (control/format incl. RTL override).
    Legitimate unicode (José, 李) is preserved."""
    for ch in value:
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7f:  # control bytes + DEL
            return _DROP
        cat = unicodedata.category(ch)
        if cat.startswith("C"):  # Cc / Cf / Cs / Co / Cn
            return _DROP
    return value


def _publish_list(items: list[Any]) -> Any:
    """Per-element validation; if any element fails the field's
    validation, drop the whole list. cwe_ids / references are the
    realistic cases here — both are lists of strings."""
    cleaned: list[Any] = []
    for item in items:
        if isinstance(item, str):
            v = _publish_string(item)
            if v is _DROP:
                return _DROP
            cleaned.append(v)
        elif isinstance(item, (int, float, bool)) or item is None:
            cleaned.append(item)
        else:
            return _DROP
    return cleaned


# provenance_refs is RAPTOR-generated; the stamping code in this module
# only writes {run_id, ts, manifest_path}. The projector restricts the
# passthrough to those keys so a hand-edited or hostile findings.json
# can't smuggle extra nested content out through the public view.
_PROVENANCE_REF_KEYS = ("run_id", "ts", "manifest_path")


def _passthrough_provenance_refs(refs: Any) -> Any:
    """Pass through provenance_refs as a list of dicts restricted to
    the known-safe keys (run_id, ts, manifest_path). Strings get
    L1-strict validation; entries that fail are dropped from the
    output list rather than crashing the projection."""
    if not isinstance(refs, list):
        return _DROP
    out = []
    for r in refs:
        if not isinstance(r, dict):
            continue
        clean: dict[str, Any] = {}
        for k in _PROVENANCE_REF_KEYS:
            v = r.get(k)
            if isinstance(v, str):
                vv = _publish_string(v)
                if vv is not _DROP:
                    clean[k] = vv
        if clean:
            out.append(clean)
    if not out:
        return _DROP
    return out


def _publish_path(value: Any, anchor: str | None) -> Any:
    """Relativise an absolute path against ``anchor`` when possible;
    fall back to basename when no anchor is known OR when the path
    contains ``..`` traversal segments. Always L1-strict validates
    the result.

    Path-traversal defence: ``../../etc/passwd`` in a published view
    could be misread as "the bug is in /etc/passwd" or hide the real
    file the bug lives in. Any path with a ``..`` segment collapses
    to its basename — preserves the filename (the publishable signal)
    without enabling traversal-style misdirection.
    """
    if not isinstance(value, str) or not value:
        return _DROP
    p = Path(value)
    if p.is_absolute():
        if anchor:
            try:
                rel = p.relative_to(anchor)
                value = str(rel)
            except ValueError:
                # Path isn't under the anchor — fall back to basename
                # rather than emit the leaky absolute path.
                value = p.name
        else:
            value = p.name
    # Relative paths with `..` traversal segments collapse to basename
    # (whether arrived-here-originally or via the relative_to path).
    if ".." in Path(value).parts:
        value = Path(value).name
    return _publish_string(value)


# NOTE: the projector deliberately never dereferences
# ``provenance_refs[].manifest_path``. Stamping only ever writes the
# run-dir-relative ``.raptor-run.json`` (see ``_relative_manifest_path``),
# and resolving a relative path needs the run directory, which the
# projector doesn't have. An earlier fallback read the manifest when the
# path was absolute — a value stamping never produces, so it only fired
# for hand-edited / hostile records and let them point the projector at
# an arbitrary file. Callers that want relativisation pass
# ``target_path`` explicitly.
