# Phase 04 — Security + Threat Model

## Severity counts

| Severity | Count |
|---|---:|
| HIGH | 0 |
| MEDIUM | 0 |
| INFO | 44 |

✓ **No HIGH-severity findings.**

## Subprocess audit

Total subprocess calls: **24** · mitigated: **15** · review: **0** · risk: **0**

## HTTP audit

Total HTTP calls: **18** · mitigated (timeout set): **18** · review: **0**

## Validator coverage

| Validator | Callsites in cve_diff/ |
|---|---:|
| `validate_commit_sha` | 0 **0 — UNUSED** |
| `validate_cve_id` | 1 ✓ |
| `validate_cvss_score` | 0 **0 — UNUSED** |
| `validate_path` | 0 **0 — UNUSED** |
| `validate_url` | 0 **0 — UNUSED** |

**Validators with 0 callsites (defense-in-depth gap or dead code):**

- `validate_url`
- `validate_path`
- `validate_commit_sha`
- `validate_cvss_score`
