# Sanitizer-cut parity — first baseline report

- Records in window: **7** (7 labelled — 4 should_suppress, 3 should_not_suppress)
- Rate criterion (noise-suppression ≥, bug-hiding ≤): **MET**
- No-regression guard (lexical-only suppressions = 2): **NOT MET**
- **Safe to remove lexical (Phase 16 gate): NO**

## Suppression rates (Wilson 95% CI)

| Method | Noise-suppression ↑ | Bug-hiding ↓ |
|--------|---------------------|--------------|
| Lexical |  50.0% (2/4) [15.0–85.0] |   0.0% (0/3) [0.0–56.2] |
| Value-bound |  50.0% (2/4) [15.0–85.0] |   0.0% (0/3) [0.0–56.2] |

Noise-suppression: fraction of genuinely-safe findings correctly suppressed (higher is better).
Bug-hiding: fraction of real findings wrongly suppressed (lower is better).

## Agreement matrix (all records)

| | Value-bound suppress | Value-bound keep |
|---|---|---|
| **Lexical suppress** | 0 | 2 |
| **Lexical keep** | 2 | 3 |

## By proposal kind

| Kind | both | lexical-only | value-bound-only | neither |
|------|-----:|-------------:|-----------------:|--------:|
| charset | 0 | 1 | 0 | 1 |
| charset_sub | 0 | 1 | 0 | 1 |
| sanitizer_cut | 0 | 0 | 2 | 1 |

> **Baseline, not the gating window.** This report is generated from a small synthetic fixture set (`core/dataflow/sanitizer_cut_parity_report.py`) to prove the telemetry machinery end-to-end and expose the value-bound gate's current coverage. The Phase 16 gate is decided on the real horizon window collected from `/agentic` runs via the shadow log — see `docs/sanitizer-cut-parity/HORIZON.md`.

