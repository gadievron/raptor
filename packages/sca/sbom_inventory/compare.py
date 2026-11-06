"""Conservative inventory comparisons: no inferred legal meaning or notifications."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
import re


def _declarations(row):
    def normalise(value):
        value = " ".join(value.split())
        terms = value.split(" OR ")
        # Flat alternatives are order independent; do not rewrite nested
        # expressions, WITH exceptions, AND groups or free-form text.
        if all(re.fullmatch(r"[A-Za-z0-9.+-]+", term) for term in terms):
            value = " OR ".join(sorted(terms))
        return value
    return sorted(normalise(value) for value in row.declarations)


def compare(before, after):
    """Pair exact occurrences first, then only unambiguous stable identities."""
    pairs, changes, ambiguities = [], [], []
    old = {(p.scope, p.id): p for p in before.records}
    new = {(p.scope, p.id): p for p in after.records}
    for key in list(old):
        if key in new and old[key].identity == new[key].identity:
            pairs.append((old.pop(key), new.pop(key)))
    left, right = defaultdict(list), defaultdict(list)
    for p in old.values():
        left[p.identity].append(p)
    for p in new.values():
        right[p.identity].append(p)
    for key in left.keys() & right.keys():
        a, b = left[key], right[key]
        if len(a) == len(b) == 1:
            pairs.append((a[0], b[0]))
        else:
            ambiguities.append({"identity": list(key), "before": [p.id for p in a], "after": [p.id for p in b]})
        for p in a:
            old.pop((p.scope, p.id))
        for p in b:
            new.pop((p.scope, p.id))

    def add(kind, a, b, *, attention=False):
        changes.append({"kind": kind, "scope": (a or b).scope,
                        "before": {"id": a.id, "name": a.name, "version": a.version,
                                   "declarations": a.declarations, "notice_status": a.notice_status,
                                   "notices": [asdict(n) for n in a.notices], "purl": a.purl, "kind": a.kind} if a else None,
                        "after": {"id": b.id, "name": b.name, "version": b.version,
                                  "declarations": b.declarations, "notice_status": b.notice_status,
                                  "notices": [asdict(n) for n in b.notices], "purl": b.purl, "kind": b.kind} if b else None,
                        "attention": attention})

    for p in old.values():
        add("removed", p, None)
    for p in new.values():
        add("added", None, p)
    for a, b in pairs:
        if a.version != b.version:
            add("version_changed", a, b)
        if _declarations(a) != _declarations(b):
            reference_only = all(re.fullmatch(r"LicenseRef-[A-Za-z0-9.+-]+", value)
                                 for value in a.declarations + b.declarations)
            add("license_reference_changed" if reference_only else "license_declaration_changed",
                a, b, attention=not reference_only)
        if not a.declaration_missing and b.declaration_missing:
            add("new_declaration_gap", a, b, attention=True)
        elif a.declaration_missing and not b.declaration_missing:
            add("resolved_declaration_gap", a, b)
        if a.notice_status == "captured" and b.notice_status in {"missing", "invalid"}:
            add("new_notice_gap", a, b, attention=True)
        elif a.notice_status in {"missing", "invalid"} and b.notice_status == "captured":
            add("resolved_notice_gap", a, b)
        if {n.sha256 for n in a.notices} != {n.sha256 for n in b.notices}:
            add("notice_text_changed", a, b)
        if {n.origin for n in a.notices} != {n.origin for n in b.notices}:
            add("notice_origin_changed", a, b)
    counts = defaultdict(int)
    for change in changes:
        counts[change["kind"]] += 1
    return {"format": "raptor-sbom-diff", "schema_version": 1,
            "before": before.source_sha256, "after": after.source_sha256,
            "matched": len(pairs), "counts": dict(sorted(counts.items())),
            "ambiguous": ambiguities, "changes": changes,
            "limitations": ["Notice-text changes are informational; legal meaning is not classified.",
                            "Ambiguous occurrences are not paired or silently collapsed.",
                            "Dependency-graph and binary-ownership changes are not classified."]}
