# Phase 01 — File Inventory

Files: **51**, missing module docstring: **0**

## Smells (counts across project)

| Pattern | Count |
|---|---:|
| `except_exception` | 18 |
| `noqa` | 16 |
| `print_call` | 5 |
| `type_ignore` | 3 |
| `TODO` | 0 |
| `FIXME` | 0 |
| `XXX` | 0 |
| `HACK` | 0 |
| `bare_except` | 0 |
| `eval_call` | 0 |
| `exec_call` | 0 |
| `os_system` | 0 |
| `shell_true` | 0 |

## Functions over 80 LOC (review for splitting)

| File | Function | LOC |
|---|---|---:|
| `cve_diff/agent/loop.py` | `run` | 332 |
| `cve_diff/cli/main.py` | `run` | 255 |
| `cve_diff/report/markdown.py` | `render_flow` | 147 |
| `cve_diff/cli/bench.py` | `_render_bench_markdown` | 144 |
| `cve_diff/pipeline.py` | `_acquire_to_render` | 135 |
| `cve_diff/diffing/extract_via_gitlab_api.py` | `extract_via_gitlab_api` | 126 |
| `cve_diff/diffing/extract_via_api.py` | `extract_via_api` | 106 |
| `cve_diff/discovery/osv.py` | `parse` | 87 |

### Longest function in project
`run` in `cve_diff/agent/loop.py` — **332 LOC**

## Per-file detail

| File | LOC | Funcs | Public | Annotated | Doc | Smells |
|---|---:|---:|---:|---:|---|---:|
| `cve_diff/cli/bench.py` |  651 |  13 |   1 | 1/1 | ✓ | 4 |
| `cve_diff/report/markdown.py` |  568 |  20 |   3 | 3/3 | ✓ | 0 |
| `cve_diff/agent/loop.py` |  555 |   9 |   3 | 3/3 | ✓ | 6 |
| `cve_diff/pipeline.py` |  496 |  12 |   1 | 1/1 | ✓ | 6 |
| `cve_diff/cli/main.py` |  451 |  10 |   3 | 3/3 | ✓ | 7 |
| `cve_diff/agent/tools.py` |  450 |  20 |   1 | 1/1 | ✓ | 3 |
| `cve_diff/infra/github_client.py` |  243 |  15 |   8 | 7/8 | ✓ | 3 |
| `cve_diff/agent/prompt.py` |  225 |   1 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/diffing/extract_via_gitlab_api.py` |  211 |   3 |   2 | 2/2 | ✓ | 2 |
| `cve_diff/infra/service_health.py` |  209 |  13 |  12 | 12/12 | ✓ | 0 |
| `cve_diff/report/consensus.py` |  198 |   9 |   6 | 6/6 | ✓ | 0 |
| `cve_diff/security/validators.py` |  193 |   5 |   5 | 5/5 | ✓ | 1 |
| `cve_diff/discovery/nvd.py` |  192 |   8 |   3 | 3/3 | ✓ | 1 |
| `cve_diff/acquisition/layers.py` |  186 |   6 |   5 | 5/5 | ✓ | 2 |
| `cve_diff/diffing/extractor.py` |  184 |   7 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/diffing/extraction_agreement.py` |  179 |   4 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/discovery/osv.py` |  166 |   4 |   2 | 2/2 | ✓ | 0 |
| `cve_diff/llm/client.py` |  156 |   4 |   1 | 1/1 | ✓ | 2 |
| `cve_diff/discovery/distro_cache.py` |  153 |  10 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/diffing/extract_via_api.py` |  150 |   3 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/diffing/extract_via_patch_url.py` |  148 |   5 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/infra/api_status.py` |  137 |  12 |  12 | 12/12 | ✓ | 1 |
| `cve_diff/discovery/constants.py` |  134 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/core/models.py` |  128 |   2 |   0 | - | ✓ | 0 |
| `cve_diff/report/flow.py` |  112 |   2 |   2 | 2/2 | ✓ | 4 |
| `cve_diff/analysis/analyzer.py` |  109 |   4 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/report/osv_schema.py` |  108 |   3 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/diffing/commit_resolver.py` |  106 |   6 |   5 | 5/5 | ✓ | 0 |
| `cve_diff/agent/invariants.py` |  103 |   2 |   2 | 2/2 | ✓ | 0 |
| `cve_diff/agent/source_classes.py` |  101 |   5 |   5 | 5/5 | ✓ | 0 |
| `cve_diff/diffing/shape_dynamic.py` |  100 |   3 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/infra/rate_limit.py` |   90 |   4 |   2 | 2/2 | ✓ | 0 |
| `cve_diff/diffing/shape.py` |   80 |   2 |   1 | 1/1 | ✓ | 0 |
| `cve_diff/core/url_re.py` |   64 |   2 |   2 | 2/2 | ✓ | 0 |
| `cve_diff/agent/types.py` |   42 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/discovery/canonical.py` |   42 |   3 |   3 | 3/3 | ✓ | 0 |
| `cve_diff/security/__init__.py` |   42 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/infra/disk_budget.py` |   32 |   3 |   3 | 3/3 | ✓ | 0 |
| `cve_diff/core/__init__.py` |   30 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/core/exceptions.py` |   17 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/security/exceptions.py` |   11 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/__main__.py` |    4 |   0 |   0 | - | ✓ | 0 |
| `cve_diff/__init__.py` |    1 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/acquisition/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/analysis/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/cli/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/diffing/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/discovery/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/infra/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/llm/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
| `cve_diff/report/__init__.py` |    0 |   0 |   0 | - | ✗ | 0 |
