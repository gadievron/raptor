"""Provenance stamping for LLM-derived analysis artifacts.

docs/security.md invariant I2-(b) requires every consumer of
LLM-derived artifacts (context-map.json, flow-trace-*.json,
attack-surface.json, attack-tree.json, attack-paths.json,
hypotheses.json, disproven.json, variants.json, findings.json) to
treat their content as adversarial.  This module converts that
per-consumer obligation into one mechanical property:

* **Writers stamp.**  Every artifact writer calls
  :func:`stamp_provenance` before persisting.  The stamp is a
  top-level ``provenance`` object::

      {"generator": "<producer id>",
       "untrusted": true,
       "schema_validated": false}

  plus a top-level ``raptor_schema_version`` marker.  ``untrusted``
  means the content is materially LLM-derived (or mixed
  LLM + mechanical); purely mechanical writer paths may stamp
  ``untrusted: false``.  Once a stamp carries ``untrusted: true`` it
  is never downgraded by a later re-stamp.

* **Writers sanitise.**  Free-text (prose) fields are defanged at
  write time with :func:`sanitise_artifact_text` (the standard output
  sanitiser, ``core.security.prompt_output_sanitise.sanitise_string``,
  with an artifact-sized length cap).  :func:`sanitise_free_text`
  applies it to every field a schema marks with ``x_free_text``.

* **The gate refuses.**  ``libexec/raptor-validate-schema`` checks
  that the stamp is present and well-formed and that every marked
  free-text field is sanitiser-idempotent.  Artifacts written by
  older RAPTOR versions carry neither ``provenance`` nor
  ``raptor_schema_version`` and are accepted with a warning
  ("legacy artifact"); an artifact carrying the version marker but
  no valid stamp fails validation.

* **Consumers read.**  :func:`provenance_of` gives loaders a uniform
  view; a missing stamp reads as ``untrusted: true`` (fail-safe).

Top-level-array artifacts (attack-paths.json, hypotheses.json) cannot
carry a top-level object key without a format break, so the stamp is
applied per element; items appended by legacy writers are tolerated
and read as untrusted.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from core.security.prompt_output_sanitise import sanitise_string

PROVENANCE_KEY = "provenance"
SCHEMA_VERSION_KEY = "raptor_schema_version"
PROVENANCE_SCHEMA_VERSION = 2

# Marker key a schema uses to flag a string property as free text
# (prose that must be sanitiser-idempotent on disk). Code-bearing
# fields (snippets, payloads, operations) must NOT carry the marker —
# the sanitiser strips line-leading markdown chars that are
# significant in code.
FREE_TEXT_MARKER = "x_free_text"

# Post-escape length cap for free-text fields persisted in artifacts.
# Deliberately larger than the report-side default (500): artifacts
# feed later pipeline stages, so the cap only exists to bound hostile
# blobs, not to trim legitimate prose.
ARTIFACT_TEXT_MAX_CHARS = 20_000

# Provenance statuses returned by check_provenance().
STATUS_OK = "ok"
STATUS_LEGACY = "legacy"
STATUS_INVALID = "invalid"


def sanitise_artifact_text(s: str) -> str:
    """Standard output sanitiser, parameterised for artifact storage."""
    return sanitise_string(s, max_chars=ARTIFACT_TEXT_MAX_CHARS)


def build_provenance(
    generator: str,
    *,
    untrusted: bool = True,
    schema_validated: bool = False,
) -> dict:
    """Return a fresh provenance object."""
    return {
        "generator": generator,
        "untrusted": untrusted,
        "schema_validated": schema_validated,
    }


def _stamp_dict(
    data: dict,
    generator: str,
    *,
    untrusted: bool,
    schema_validated: bool,
    overwrite_generator: bool,
) -> None:
    existing = data.get(PROVENANCE_KEY)
    if isinstance(existing, dict):
        # Never downgrade an untrusted artifact to trusted.
        if existing.get("untrusted") is True:
            untrusted = True
        prior = existing.get("generator")
        if not overwrite_generator and isinstance(prior, str) and prior:
            generator = prior
    data[PROVENANCE_KEY] = build_provenance(
        generator, untrusted=untrusted, schema_validated=schema_validated
    )
    data[SCHEMA_VERSION_KEY] = PROVENANCE_SCHEMA_VERSION


def stamp_provenance(
    data: Any,
    generator: str,
    *,
    untrusted: bool = True,
    schema_validated: bool = False,
    overwrite_generator: bool = True,
) -> Any:
    """Stamp ``data`` (dict artifact, or list artifact per element).

    ``overwrite_generator=False`` is for normalisers / enrichers that
    rewrite an artifact authored elsewhere: an existing generator id
    is preserved, ``generator`` only fills the gap.

    Returns ``data`` for call-site convenience. Non-dict list elements
    and non-container inputs are left untouched.
    """
    if isinstance(data, dict):
        _stamp_dict(
            data, generator,
            untrusted=untrusted,
            schema_validated=schema_validated,
            overwrite_generator=overwrite_generator,
        )
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _stamp_dict(
                    item, generator,
                    untrusted=untrusted,
                    schema_validated=schema_validated,
                    overwrite_generator=overwrite_generator,
                )
    return data


def _stamp_errors(stamp: Any, path: str = "provenance") -> list[str]:
    """Shape-check one provenance object. Returns error strings."""
    if not isinstance(stamp, dict):
        return [f"{path}: must be an object, got {type(stamp).__name__}"]
    errors = []
    gen = stamp.get("generator")
    if not isinstance(gen, str) or not gen.strip():
        errors.append(f"{path}.generator: required non-empty string")
    if not isinstance(stamp.get("untrusted"), bool):
        errors.append(f"{path}.untrusted: required boolean")
    if not isinstance(stamp.get("schema_validated"), bool):
        errors.append(f"{path}.schema_validated: required boolean")
    return errors


def _check_dict(data: dict, path: str = "") -> tuple[str, list[str]]:
    prefix = f"{path}." if path else ""
    stamp = data.get(PROVENANCE_KEY)
    if stamp is None:
        if SCHEMA_VERSION_KEY in data:
            return STATUS_INVALID, [
                (
                    f"{prefix}{PROVENANCE_KEY}: missing on an artifact "
                    f"that carries {SCHEMA_VERSION_KEY} — new artifacts "
                    "must be stamped by their writer"
                ),
            ]
        return STATUS_LEGACY, []
    errors = _stamp_errors(stamp, f"{prefix}{PROVENANCE_KEY}")
    if errors:
        return STATUS_INVALID, errors
    return STATUS_OK, []


def check_provenance(data: Any) -> tuple[str, list[str]]:
    """Classify an artifact's provenance state.

    Returns ``(status, messages)`` where status is one of
    ``"ok"`` / ``"legacy"`` / ``"invalid"``:

    * ``ok`` — a well-formed stamp is present (for list artifacts: at
      least one element stamped, none malformed; messages may carry
      informational notes about unstamped elements).
    * ``legacy`` — no stamp and no version marker anywhere: written
      by an older RAPTOR version. Callers should warn, treat content
      as untrusted, and continue.
    * ``invalid`` — a stamp is present but malformed, or the version
      marker is present without a stamp. Callers should refuse the
      artifact; messages carry precise field paths.
    """
    if isinstance(data, dict):
        return _check_dict(data)
    if isinstance(data, list):
        errors: list[str] = []
        notes: list[str] = []
        stamped = 0
        unstamped = 0
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            status, msgs = _check_dict(item, path=f"[{i}]")
            if status == STATUS_INVALID:
                errors.extend(msgs)
            elif status == STATUS_LEGACY:
                unstamped += 1
            else:
                stamped += 1
        if errors:
            return STATUS_INVALID, errors
        if stamped == 0:
            return STATUS_LEGACY, []
        if unstamped:
            notes.append(
                f"{unstamped} element(s) without a provenance stamp "
                "(treated as untrusted)"
            )
        return STATUS_OK, notes
    return STATUS_LEGACY, []


def mark_schema_validated(data: Any) -> bool:
    """Set ``schema_validated: true`` on existing stamps.

    Returns True when anything changed. Only touches well-formed
    stamps — never creates one (that is the writer's job).
    """
    changed = False
    items = [data] if isinstance(data, dict) else data
    if not isinstance(items, list):
        return False
    for item in items:
        if not isinstance(item, dict):
            continue
        stamp = item.get(PROVENANCE_KEY)
        if (isinstance(stamp, dict) and not _stamp_errors(stamp)
                and stamp.get("schema_validated") is not True):
            stamp["schema_validated"] = True
            changed = True
    return changed


def provenance_of(data: Any) -> dict:
    """Consumer-side view of an artifact's provenance.

    Always returns ``generator`` / ``untrusted`` / ``schema_validated``
    / ``legacy``. Missing or malformed stamps read as untrusted and
    legacy (fail-safe). For list artifacts, ``untrusted`` is True when
    any element is untrusted or unstamped.
    """
    if isinstance(data, dict):
        stamp = data.get(PROVENANCE_KEY)
        if isinstance(stamp, dict) and not _stamp_errors(stamp):
            return {
                "generator": stamp["generator"],
                "untrusted": stamp["untrusted"],
                "schema_validated": stamp["schema_validated"],
                "legacy": False,
            }
        return {
            "generator": "unknown",
            "untrusted": True,
            "schema_validated": False,
            "legacy": True,
        }
    if isinstance(data, list):
        views = [provenance_of(i) for i in data if isinstance(i, dict)]
        if not views:
            return {
                "generator": "unknown",
                "untrusted": True,
                "schema_validated": False,
                "legacy": True,
            }
        generators = sorted({v["generator"] for v in views})
        return {
            "generator": generators[0] if len(generators) == 1 else "mixed",
            "untrusted": any(v["untrusted"] for v in views),
            "schema_validated": all(v["schema_validated"] for v in views),
            "legacy": all(v["legacy"] for v in views),
        }
    return {
        "generator": "unknown",
        "untrusted": True,
        "schema_validated": False,
        "legacy": True,
    }


# ─────────────────────────────────────────────────────────────────────
# Free-text field handling
# ─────────────────────────────────────────────────────────────────────

def iter_free_text_fields(
    data: Any, schema: dict, path: str = ""
) -> Iterator[tuple[str, str]]:
    """Yield ``(field_path, value)`` for schema-marked free-text strings.

    Walks ``data`` guided by a (subset) JSON-schema dict: only
    ``properties`` / ``items`` / :data:`FREE_TEXT_MARKER` are
    interpreted. A marker on a union-typed property (e.g. attack-path
    steps that may be strings or objects) applies to the string form;
    the object form is still recursed into.
    """
    if schema.get(FREE_TEXT_MARKER) and isinstance(data, str):
        yield path or "$", data
        return
    if isinstance(data, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            for key, sub in props.items():
                if isinstance(sub, dict) and key in data:
                    sub_path = f"{path}.{key}" if path else key
                    yield from iter_free_text_fields(data[key], sub, sub_path)
    elif isinstance(data, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for i, el in enumerate(data):
                yield from iter_free_text_fields(el, items, f"{path}[{i}]")


def _sanitise_walk(data: Any, schema: dict, path: str, changed: list[str]) -> None:
    """Recursive worker for :func:`sanitise_free_text` (mutates in place)."""
    if isinstance(data, dict):
        props = schema.get("properties")
        if not isinstance(props, dict):
            return
        for key, sub in props.items():
            if not (isinstance(sub, dict) and key in data):
                continue
            sub_path = f"{path}.{key}" if path else key
            value = data[key]
            if sub.get(FREE_TEXT_MARKER) and isinstance(value, str):
                clean = sanitise_artifact_text(value)
                if clean != value:
                    data[key] = clean
                    changed.append(sub_path)
            elif isinstance(value, (dict, list)):
                _sanitise_walk(value, sub, sub_path, changed)
    elif isinstance(data, list):
        items = schema.get("items")
        if not isinstance(items, dict):
            return
        for i, value in enumerate(data):
            sub_path = f"{path}[{i}]"
            if items.get(FREE_TEXT_MARKER) and isinstance(value, str):
                clean = sanitise_artifact_text(value)
                if clean != value:
                    data[i] = clean
                    changed.append(sub_path)
            elif isinstance(value, (dict, list)):
                _sanitise_walk(value, items, sub_path, changed)


def sanitise_free_text(data: Any, schema: dict) -> list[str]:
    """Sanitise every marked free-text field in place.

    ``schema`` may describe a dict artifact, or (with a top-level
    ``items`` key) a list artifact. Returns the paths that changed.
    """
    changed: list[str] = []
    _sanitise_walk(data, schema, "", changed)
    return changed


def check_free_text_idempotent(data: Any, schema: dict) -> list[str]:
    """Return paths of marked free-text fields the writer did not sanitise.

    A field passes when applying :func:`sanitise_artifact_text` is a
    no-op (the writer already sanitised).
    """
    offenders = []
    for field_path, value in iter_free_text_fields(data, schema):
        if sanitise_artifact_text(value) != value:
            offenders.append(field_path)
    return offenders


# ─────────────────────────────────────────────────────────────────────
# Free-text pseudo-schemas for artifacts without a formal schema
# ─────────────────────────────────────────────────────────────────────
# context-map.json / flow-trace-*.json / variants.json are written
# in-session by /understand and have no entry in
# packages.exploitability_validation.schemas — the marker tables below
# are their free-text schema for stamping writers and for the
# raptor-validate-schema idempotence check. Code-bearing fields
# (operation, matched_code, proof.*, path_conditions) are deliberately
# absent.

_FT = {FREE_TEXT_MARKER: True}

CONTEXT_MAP_TEXT_SCHEMA: dict = {
    "properties": {
        "sources": {"items": {"properties": {
            "trust": _FT, "description": _FT,
        }}},
        "sinks": {"items": {"properties": {
            "risk": _FT, "description": _FT,
        }}},
        "trust_boundaries": {"items": {"properties": {
            "implication": _FT,
        }}},
        "entry_points": {"items": {"properties": {
            "notes": _FT, "accepts": _FT, "description": _FT,
        }}},
        "sink_details": {"items": {"properties": {
            "notes": _FT, "description": _FT,
        }}},
        "boundary_details": {"items": {"properties": {
            "gaps": _FT, "notes": _FT,
        }}},
        "unchecked_flows": {"items": {"properties": {
            "missing_boundary": _FT, "notes": _FT,
        }}},
    },
}

FLOW_TRACE_TEXT_SCHEMA: dict = {
    "properties": {
        "steps": {"items": {"properties": {
            "description": _FT,
        }}},
        "summary": _FT,
        "attacker_control": _FT,
    },
}

VARIANTS_TEXT_SCHEMA: dict = {
    "properties": {
        "variants": {"items": {"properties": {
            "notes": _FT,
        }}},
        "root_cause_groups": {"items": {"properties": {
            "description": _FT, "fix_strategy": _FT,
        }}},
        "validation_scope": {"properties": {
            "note": _FT,
        }},
    },
}

# bug-report.json (crash-analysis fetch stage) carries prose lifted
# verbatim from a public bug tracker — the highest-injection-risk
# artifact in the set, so every prose field is marked. crash_command /
# crash_output are code-bearing (ASAN frames start with `#`, commands
# carry flags) and deliberately unmarked; attachments[].url is
# structural, not prose.
BUG_REPORT_TEXT_SCHEMA: dict = {
    "properties": {
        "tracker": _FT,
        "title": _FT,
        "summary": _FT,
        "reproduction_steps": {"items": _FT},
        "attachments": {"items": {"properties": {
            "description": _FT,
        }}},
        "affected_versions": {"items": _FT},
        "reporter_remarks": _FT,
        "fetch_notes": _FT,
    },
}

ARTIFACT_TEXT_SCHEMAS: dict[str, dict] = {
    "context-map": CONTEXT_MAP_TEXT_SCHEMA,
    "flow-trace": FLOW_TRACE_TEXT_SCHEMA,
    "variants": VARIANTS_TEXT_SCHEMA,
    "bug-report": BUG_REPORT_TEXT_SCHEMA,
}
