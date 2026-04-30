# Phase 02 — Function-by-function audit

Files audited: **19**, functions audited: **144**, flagged: **59**

## Flag breakdown

| Kind | Count |
|---|---:|
| `complexity` | 28 |
| `no_docstring` | 19 |
| `length` | 10 |
| `params` | 2 |

## Highest cyclomatic complexity (top 10)

| Function | File:Line | Complexity |
|---|---|---:|
| `run` | `cve_diff/agent/loop.py:199` | 66 |
| `render_flow` | `cve_diff/report/markdown.py:133` | 42 |
| `_deterministic_hints_impl` | `cve_diff/agent/tools.py:159` | 34 |
| `run` | `cve_diff/cli/main.py:222` | 34 |
| `_render_bench_markdown` | `cve_diff/cli/bench.py:318` | 33 |
| `extract_via_gitlab_api` | `cve_diff/diffing/extract_via_gitlab_api.py:62` | 27 |
| `validate_cve_id` | `cve_diff/security/validators.py:30` | 25 |
| `validate_url` | `cve_diff/security/validators.py:87` | 21 |
| `extract_via_api` | `cve_diff/diffing/extract_via_api.py:60` | 20 |
| `_flow_from_pipeline` | `cve_diff/cli/main.py:71` | 20 |

## Longest functions (top 10, > 80 LOC)

| Function | File:Line | LOC |
|---|---|---:|
| `run` | `cve_diff/agent/loop.py:199` | 332 |
| `run` | `cve_diff/cli/main.py:222` | 255 |
| `render_flow` | `cve_diff/report/markdown.py:133` | 147 |
| `_render_bench_markdown` | `cve_diff/cli/bench.py:318` | 144 |
| `_acquire_to_render` | `cve_diff/pipeline.py:213` | 135 |
| `extract_via_gitlab_api` | `cve_diff/diffing/extract_via_gitlab_api.py:62` | 126 |
| `bench` | `cve_diff/cli/bench.py:551` | 124 |
| `extract_via_api` | `cve_diff/diffing/extract_via_api.py:60` | 106 |
| `_run_one` | `cve_diff/cli/bench.py:105` | 100 |
| `_render_html` | `cve_diff/cli/bench.py:464` | 85 |

## Public functions missing docstring (19)

- `run` at `cve_diff/pipeline.py:166`
- `elapsed_s` at `cve_diff/agent/loop.py:159`
- `exhausted` at `cve_diff/agent/loop.py:162`
- `run` at `cve_diff/agent/loop.py:199`
- `anthropic_schema` at `cve_diff/agent/tools.py:62`
- `extract_diff` at `cve_diff/diffing/extractor.py:58`
- `is_valid_sha_format` at `cve_diff/diffing/commit_resolver.py:39`
- `validate_different` at `cve_diff/diffing/commit_resolver.py:47`
- `acquire` at `cve_diff/acquisition/layers.py:62`
- `acquire` at `cve_diff/acquisition/layers.py:72`
- `acquire` at `cve_diff/acquisition/layers.py:112`
- `acquire` at `cve_diff/acquisition/layers.py:160`
- `acquire` at `cve_diff/acquisition/layers.py:205`
- `progress_cb` at `cve_diff/cli/main.py:299`
- `render` at `cve_diff/report/markdown.py:496`
- `to_dict` at `cve_diff/report/consensus.py:51`
- `attempted_count` at `cve_diff/report/consensus.py:71`
- `to_dict` at `cve_diff/report/consensus.py:84`
- `render` at `cve_diff/report/osv_schema.py:27`
