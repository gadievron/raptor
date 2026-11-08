"""Offline inventory distributions with explicit scopes and overlapping operands."""
from collections import Counter

from core.license.spdx import split_compound_expression


def ecosystem(row):
    if not row.purl.startswith("pkg:"):
        return "unidentified"
    return row.purl[4:].split("/", 1)[0]


def statistics(inventory, records):
    scopes = {}
    for scope in sorted({row.scope for row in records}):
        rows = [row for row in records if row.scope == scope]
        expressions, operands = Counter(), Counter()
        for row in rows:
            expressions.update(set(row.declarations) or {"not declared"})
            values = set()
            for claim in row.declarations:
                values.update(value.strip() for value in (split_compound_expression(claim.replace("(", " ").replace(")", " ")) or [claim]))
            operands.update(values or {"not declared"})
        scopes[scope] = {"records": len(rows), "license_expressions": dict(sorted(expressions.items())),
                         "license_operands": dict(sorted(operands.items())),
                         "ecosystems": dict(sorted(Counter(ecosystem(row) for row in rows).items())),
                         "notice_status": dict(sorted(Counter(row.notice_status for row in rows).items())),
                         "unresolved_declarations": sum(row.declaration_missing for row in rows)}
    return {"format": "raptor-sbom-statistics", "schema_version": 1,
            "source_sha256": inventory.source_sha256, "summary": inventory.summary(), "selection_scopes": scopes,
            "limitations": ["Counts describe supplied records, not verified runtime membership.",
                            "License operands overlap for AND/OR expressions; counts are not exclusive shares.",
                            "GPL versions, exceptions and complete expressions remain separate; no Other bucket is used.",
                            "Notice statuses are recorded evidence; this operation does not re-verify text bytes."]}
