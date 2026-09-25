# True-positive harvest (`raptor-tp-harvest`)

Turns a run's confirmed true positives into flywheel inputs:
detection-rule **candidates** and provenance-gated **corpus label**
records. Mechanical harvest, human-gated promotion — nothing it emits
changes a verdict, enables a rule, or publishes a label.

## Harvest a run

```
libexec/raptor-tp-harvest <run-dir>
```

Walks the run's findings and, for each finding whose recorded verdict
is a hard confirmation (`exploitable`, `confirmed`,
`confirmed_constrained`, `confirmed_blocked`, `validated`), emits
under `<run-dir>/tp-harvest/`:

- `records/<harvest-id>.json` — the harvest record: defect mechanism
  (rule id, CWE, validated flow), source span + function identity
  (the shared `core.staleness` span-hash convention), and evidence
  pointers (ruling, verified-outcome hashes).
- `candidates/<harvest-id>.candidate.yaml` — a Semgrep rule DRAFT
  generalised from the confirmed instance (call anchors stay
  concrete, other identifiers become metavariables). Candidates are
  never loaded by any scanner and cannot be written into the in-tree
  rules surface; the promotion runbook is the `README.md` written
  beside them (review, positive/negative fixture testing, hand
  promotion in a reviewed commit).
- `disclosure-backlog.jsonl` — one pointer per harvested finding
  (location identity + status only). By default every finding lands
  here: findings are **not labelable** until provenance is
  established.
- `harvest-manifest.json` — the audit trail: every finding either
  harvested or skipped with a named reason (`status_negative`,
  `status_unverified`, `path_escapes_target`, `already_harvested`,
  ...). Re-running is idempotent, keyed on finding identity; a record
  edited after emission is flagged `record_tampered`, and findings
  backed by a verified oracle outcome carry `oracle_verified: true`.

The run dir is treated as untrusted (imported runs ship arbitrary
content): any symlink under `tp-harvest/` refuses the whole harvest,
finding paths are confined to the run's target tree (escapes skip as
`path_escapes_target`), and seed lines longer than 1 KB skip as
`candidate_seed_oversized`.

`--status` shows the manifest + backlog without harvesting;
`--no-candidates` skips rule generation; `--json` for machine output.

## Flip provenance and emit a label (per finding)

Corpus labels need public provenance — the gate is default-closed,
and the operator flips it one finding at a time:

```
libexec/raptor-tp-harvest <run-dir> --label <harvest-id> \
    --provenance public --fix-commit <upstream-sha> \
    --bug-class trap --rationale "why this grades finding" \
    --repo <upstream-repo>
```

- `--provenance public` requires a public anchor: `--cve` or
  `--fix-commit` (the same anchors the corpus lint checks).
- `--provenance own-target` asserts the target is your own.
- Anything else refuses; the finding stays on the disclosure backlog.

The label is validated by the corpus's own schema
(`core.audit.corpus.label.FunctionLabel`) and written to the local
private label store (or `--labels-base <dir>`). The source pin's sha
is derived from the target tree — refused unless the tree is proven
clean (dirty or unknowable both refuse) — or passed with `--sha`.
Labels are never distributed with the tree.
