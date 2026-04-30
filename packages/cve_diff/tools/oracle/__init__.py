"""Ground-truth oracle for cve-diff pipeline output verification.

Out-of-tree: `tools/oracle/` is observability, not a pipeline gate.
It compares `(cve_id, picked_slug, picked_sha)` against what OSV
and NVD carry, and returns a structured verdict so a bench run's
PASSes can be categorized as `verified` / `mirror` / `disputed` /
`orphan` / `likely_hallucination`.
"""
