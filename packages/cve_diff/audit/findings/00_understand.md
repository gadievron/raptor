# Phase 00 — Architectural Map

Total files: **51**  ·  Total LOC (non-blank): **7557**

## Pipeline (5 stages)

Per `cve_diff/pipeline.py::Pipeline.run`:

```
  discover  →  acquire  →  resolve  →  diff  →  render
```

✓ Phase static list matches `_CANONICAL_STAGE_OF` in source.

## CLI exit codes

| Code | Meaning | Source location(s) |
|---:|---|---|
| 0 | success | **MISSING from main.py** |
| 1 | health command — at least one critical service unhealthy | main.py:497 |
| 4 | UnsupportedSource (closed-source vendor) | main.py:354 |
| 5 | DiscoveryError (no canonical repo found) | main.py:370 |
| 6 | AcquisitionError (clone/fetch cascade failed) | main.py:384 |
| 7 | IdenticalCommitsError (would diff HEAD..HEAD) | main.py:398 |
| 9 | AnalysisError / LLMCallFailed | main.py:413, main.py:425 |

## File inventory

| Module | LOC | Exports |
|---|---:|---|
| `cve_diff.cli.bench` |  651 | bench |
| `cve_diff.report.markdown` |  568 | render_flow, render_failure, render |
| `cve_diff.agent.loop` |  555 | AgentConfig, AgentLoop |
| `cve_diff.pipeline` |  496 | PipelineResult, Pipeline |
| `cve_diff.cli.main` |  451 | run, health |
| `cve_diff.agent.tools` |  450 | Tool |
| `cve_diff.infra.github_client` |  243 | warn_if_token_missing, get_repo, get_languages, commit_exists, get_commit, … (+3) |
| `cve_diff.agent.prompt` |  225 | build_user_message |
| `cve_diff.diffing.extract_via_gitlab_api` |  211 | extract_via_gitlab_api, extract_for_agreement |
| `cve_diff.infra.service_health` |  209 | HealthResult, probe_anthropic, probe_nvd, probe_osv, probe_github, … (+7) |
| `cve_diff.report.consensus` |  198 | MethodResult, ConsensusReport, run_consensus, render_markdown |
| `cve_diff.security.validators` |  193 | validate_cve_id, validate_url, validate_path, validate_commit_sha, validate_cvss_score |
| `cve_diff.discovery.nvd` |  192 | NvdDiscoverer |
| `cve_diff.acquisition.layers` |  186 | LayerReport, AcquisitionLayer, TargetedFetchLayer, ShallowCloneLayer, FullCloneLayer, … (+1) |
| `cve_diff.diffing.extractor` |  184 | extract_diff |
| `cve_diff.diffing.extraction_agreement` |  179 | compute_extraction_agreement |
| `cve_diff.discovery.osv` |  166 | OSVDiscoverer |
| `cve_diff.llm.client` |  156 | LLMResponse, LLMCallFailed, CostBudgetExceeded, ResilientLLMClient |
| `cve_diff.discovery.distro_cache` |  153 | DistroFetcher |
| `cve_diff.diffing.extract_via_api` |  150 | extract_via_api |
| `cve_diff.diffing.extract_via_patch_url` |  148 | extract_via_patch_url |
| `cve_diff.infra.api_status` |  137 | ApiKeySpec, record_rate_limit, rate_limit_events, reset_rate_limit_events, api_key_status, … (+8) |
| `cve_diff.discovery.constants` |  134 | _(internal)_ |
| `cve_diff.core.models` |  128 | PatchTuple, RepoRef, DiscoveryResult, FileChange, DiffBundle |
| `cve_diff.report.flow` |  112 | write_outcome_patches, write_flow_files |
| `cve_diff.analysis.analyzer` |  109 | AnalysisError, RootCause, RootCauseAnalyzer |
| `cve_diff.report.osv_schema` |  108 | render |
| `cve_diff.diffing.commit_resolver` |  106 | CommitResolver |
| `cve_diff.agent.invariants` |  103 | discover_validator, check_diff_shape |
| `cve_diff.agent.source_classes` |  101 | tried_classes, has_verified, enough_classes_tried, should_surrender_no_evidence, untried_classes |
| `cve_diff.diffing.shape_dynamic` |  100 | classify |
| `cve_diff.infra.rate_limit` |   90 | RateLimitTimeout, TokenBucket |
| `cve_diff.diffing.shape` |   80 | classify |
| `cve_diff.core.url_re` |   64 | normalize_slug, extract_github_slug |
| `cve_diff.agent.types` |   42 | AgentContext, AgentOutput, AgentSurrender |
| `cve_diff.discovery.canonical` |   42 | apply_mirror, is_tracker, score |
| `cve_diff.security.__init__` |   42 | _(internal)_ |
| `cve_diff.infra.disk_budget` |   32 | DiskBudgetExceeded, DiskStatus, check, assert_ok |
| `cve_diff.core.__init__` |   30 | _(internal)_ |
| `cve_diff.core.exceptions` |   17 | CveDiffError, DiscoveryError, AcquisitionError, IdenticalCommitsError, UnsupportedSource, … (+1) |
| `cve_diff.security.exceptions` |   11 | SecurityError, ValidationError, SSRFError |
| `cve_diff.__main__` |    4 | _(internal)_ |
| `cve_diff.__init__` |    1 | _(internal)_ |
| `cve_diff.acquisition.__init__` |    0 | _(internal)_ |
| `cve_diff.analysis.__init__` |    0 | _(internal)_ |
| `cve_diff.cli.__init__` |    0 | _(internal)_ |
| `cve_diff.diffing.__init__` |    0 | _(internal)_ |
| `cve_diff.discovery.__init__` |    0 | _(internal)_ |
| `cve_diff.infra.__init__` |    0 | _(internal)_ |
| `cve_diff.llm.__init__` |    0 | _(internal)_ |
| `cve_diff.report.__init__` |    0 | _(internal)_ |
