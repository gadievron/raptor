# Corpus JSON schemas

Authoritative shapes live in `core/dataflow/`:

- `core/dataflow/finding.py` — `Finding`, `Step`
- `core/dataflow/label.py` — `GroundTruth`, valid verdicts, valid FP categories

This doc is a human-readable reference for hand-labelers. When the
shape changes, bump `SCHEMA_VERSION` in the corresponding module and
update both this doc and any committed corpus files.

## Finding (`<finding_id>.json`)

```json
{
  "schema_version": 1,
  "finding_id": "synthetic_codeql_sql-injection_001",
  "producer": "codeql",
  "rule_id": "py/sql-injection",
  "message": "user input flows into database query",
  "source": {
    "file_path": "app/handler.py",
    "line": 12,
    "column": 4,
    "snippet": "q = request.GET['q']",
    "label": "source"
  },
  "sink": {
    "file_path": "app/db.py",
    "line": 27,
    "column": 8,
    "snippet": "cursor.execute(sql)",
    "label": "sink"
  },
  "intermediate_steps": [
    {
      "file_path": "app/handler.py",
      "line": 14,
      "column": 4,
      "snippet": "sql = f\"SELECT * FROM users WHERE name='{q}'\"",
      "label": "step"
    }
  ],
  "raw": {}
}
```

Field notes:

- `finding_id` — stable across reruns; corpus replay matches labels by
  this exact string.
- `step.label` — one of `"source"`, `"step"`, `"sink"`, `"sanitizer"`,
  or `null`. Producers that don't distinguish use `null`.
- `raw` — producer's original record (e.g. SARIF result blob).
  Consumers must not depend on its shape.

## GroundTruth (`<finding_id>.label.json`)

```json
{
  "schema_version": 1,
  "finding_id": "synthetic_codeql_sql-injection_001",
  "verdict": "true_positive",
  "fp_category": null,
  "rationale": "user-controlled `q` reaches `cursor.execute` via f-string interpolation; no validator on path; classic SQLi.",
  "labeler": "johnc",
  "labeled_at": "2026-05-10"
}
```

Field rules:

- `finding_id` must equal the matching finding's `finding_id`.
- `verdict` ∈ `{"true_positive", "false_positive"}`. No `"uncertain"` —
  uncertain findings don't contribute measurement signal and stay out
  of the corpus.
- `fp_category` MUST be `null` for `true_positive`.
- `fp_category` MUST be one of the closed set for `false_positive`:
  - `missing_sanitizer_model` — producer's sanitizer catalog didn't
    know about a project-specific validator that covers the path.
    **The category this work targets.**
  - `infeasible_branch` — branch conditions on the path are mutually
    exclusive; SMT can prove unsat.
  - `framework_mitigation` — framework provides automatic protection
    (CSP, ORM parameterisation, auto-encoding) the producer doesn't
    model.
  - `dead_code` — sink site is unreachable from any real entry point.
  - `type_constraint` — type system / runtime check rules out the
    attack class (e.g. integer-only field).
  - `reflection_imprecision` — producer over-approximated through
    reflection / dynamic dispatch / wildcard imports.
- `rationale` — one paragraph; cite line ranges where useful. Future
  labelers and reviewers depend on it.
- `labeled_at` — ISO date (`YYYY-MM-DD`).
