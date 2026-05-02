# cve-diff

Given a CVE id, `cve-diff` discovers the upstream fix commit, extracts
the patch (`fix^..fix`) via three independent sources, and emits an
OSV Schema 1.6.0 record + a human-readable Markdown report + a
per-stage trace.

```bash
ANTHROPIC_API_KEY=… GITHUB_TOKEN=… cve-diff run CVE-2022-21676 --output-dir ./out
```

## What it produces

For each PASS run, the output directory contains up to 7 files:

| File | Contents |
|---|---|
| `<cve>.osv.json`         | OSV Schema 1.6.0 record |
| `<cve>.md`               | Human-readable report — diff body, source-agreement table, optional root-cause |
| `<cve>.flow.md`          | Pipeline trace — all 5 stages with ✓/✗/⊘ markers |
| `<cve>.flow.jsonl`       | Per-tool-call telemetry (one JSON line per tool call) |
| `<cve>.clone.patch`      | Diff via `git diff fix^..fix` (clone source) |
| `<cve>.github_api.patch` | Diff via GitHub Commits API JSON (when GitHub) |
| `<cve>.gitlab_api.patch` | Diff via GitLab v4 API JSON (when GitLab) |
| `<cve>.patch_url.patch`  | Diff via forge raw `<sha>.patch` text endpoint |

The trace summary is also echoed to stdout at end of run, so a human
running the CLI sees the report without opening anything.

## Pipeline

Five stages, wired in `cve_diff/pipeline.py::Pipeline.run`. Each one
ends with a status (`✓` succeeded, `✗` reached and failed, `⊘` not
reached); all five always render in the trace.

```
                ┌──────────┐    ┌──────────┐    ┌──────────┐
   CVE-id  ─►   │ DISCOVER │ ─► │ ACQUIRE  │ ─► │ RESOLVE  │
                │  agent   │    │ cascade  │    │ commits  │
                └──────────┘    └──────────┘    └──────────┘
                                                      │
                                                      ▼
                ┌──────────┐    ┌────────────────────────┐
                │  RENDER  │ ◄─ │         DIFF           │
                │ osv + md │    │ clone × api × patchURL │
                └──────────┘    └────────────────────────┘
```

A disk-budget gate (`infra/disk_budget.assert_ok`, 80% default) fires
at every stage entry to fail fast on a full filesystem.

### Stage 1 — Discover (the agent)

Anthropic Claude Opus 4.7 in a tool-use loop (`cve_diff/agent/loop.py`).
The agent's job: pick a `(repository_url, fix_commit_sha)` tuple it
can defend, then submit. Hard caps per CVE: **30 iterations,
400 K tokens, $2.00, 720 s wall-clock.** Empirically: P50 ≈ $0.18,
P95 ≈ $1.00.

The agent has 16 tools, grouped into 7 *source classes* the
surrender rule tracks (see `cve_diff/agent/source_classes.py`):

| Class | Tools |
|---|---|
| `osv` | `osv_raw`, `osv_expand_aliases` |
| `nvd` | `nvd_raw` |
| `deterministic_hints` | `deterministic_hints` (parses OSV/NVD refs offline) |
| `github_search` | `gh_search_repos`, `gh_search_commits`, `gh_list_commits_by_path` |
| `distro_trackers` | `fetch_distro_advisory` (Debian/Ubuntu/Red Hat) |
| `non_github_forge` | `git_ls_remote`, `gitlab_commit`, `cgit_fetch` |
| `generic_http` | `http_fetch` |

Plus `gh_commit_detail`, `gh_compare`, `oracle_check`, and
`check_diff_shape` for verification + classification.

**Submit gate** (`cve_diff/agent/invariants.py`): the agent's pick
must clear three structural checks before it leaves the loop:

1. SHA format valid (40-char hex).
2. SHA *exists* in the repo (verified via `gh_commit_detail` /
   `gitlab_commit` / `cgit_fetch` calls captured during the run).
3. `PatchTuple(repo, sha)` constructs cleanly.

A submit with an unverified SHA gets one feedback round; after that
the loop force-surrenders.

**Surrender rule** (`source_classes.should_surrender_no_evidence`):
when the agent has tried ≥ 5 of 7 source classes, made zero
verification calls, AND spent ≥ $0.80, the loop force-surrenders
`no_evidence` rather than ramble. Calibrated to catch walker patterns
without harming legitimate PASSes.

### Stage 2 — Acquire (cascade)

Once the agent submits, the pipeline asks `CascadingRepoAcquirer`
(`cve_diff/acquisition/layers.py`) to land the fix-commit SHA on
disk. Three layers in order, stop on first success:

```
┌─────────────────────────────────────────────────────────────┐
│ TargetedFetchLayer   git init + fetch --depth=5 origin <sha>│  cheap
├─────────────────────────────────────────────────────────────┤
│ ShallowCloneLayer    git clone --depth=D for D in (100,500) │  fallback
├─────────────────────────────────────────────────────────────┤
│ FullCloneLayer       git clone (with 2 GB max-size guard)   │  last resort
└─────────────────────────────────────────────────────────────┘
```

Targeted fetch handles ~70% of CVEs in one round-trip. Progressive
shallow clones recover old git servers that reject unadvertised-SHA
fetches. The full clone is gated by a GitHub-API size lookup so a
typo to a kernel-sized repo can't burn the disk.

Every layer has a 120 s timeout. Failure detail per layer is
preserved in the `AcquisitionError` so the pipeline trace knows where
it broke.

### Stage 3 — Resolve

`CommitResolver.expand` widens abbreviated SHAs via `git rev-parse`.
`parent_of` returns `<sha>^`, falling back to git's empty-tree SHA
(`4b825dc6…`) for root commits so we still produce a full-file
"added" diff. `validate_different` blocks `HEAD..HEAD` empty-diff
fallbacks (a class of bug from earlier prototypes).

### Stage 4 — Diff (triangulation)

The pipeline runs **three independent extractors** in parallel and
compares their output. This is the user-facing integrity signal —
the trace's verdict line tells you at a glance whether the diff body
is real.

| Method | Endpoint | Format |
|---|---|---|
| `clone`     | `git diff --no-color --binary fix^..fix` (local clone) | unified diff via git CLI |
| `github_api` / `gitlab_api` | `GET /repos/<slug>/commits/<sha>` (or GitLab equivalent) | parsed-file JSON synthesized into a unified diff |
| `patch_url` | `https://<forge>/<slug>/commit/<sha>.patch` (or cgit `?format=patch`) | raw `git format-patch` text |

Coverage: GitHub gets all three; GitLab gets clone + gitlab_api +
patch_url; cgit (kernel.org / savannah) gets clone + patch_url
(no JSON API available); other forges get clone only.

After the bundles arrive, `diffing/extraction_agreement._summarize_n`
builds pairwise verdicts and a top-level signal:

| Verdict | Meaning |
|---|---|
| `agree`            | Every pairwise comparison matches: same paths, byte delta ≤ 5%. |
| `majority_agree`   | One outlier source disagrees with the rest. The outlier method is named in the trace. |
| `partial`          | Mixed pairwise verdicts but no clear majority. |
| `disagree`         | No two sources match. |
| `single_source`    | Only one extractor ran (rare; non-forge URL). |

Example trace from CVE-2022-21676:

```
## Stage 4 — DIFF ✓

**Sources:**
- **Clone** (`git diff fix^..fix`): 2 files, 2,244 bytes — shape `source`
- **GitHub API** (`/repos/socketio/engine.io/commits/c0e194d44933`): 2 files, 2,185 bytes
- **Patch URL** (`socketio/engine.io/commit/c0e194d44933.patch`): 2 files, 3,416 bytes

**Verdict:** ⚠ 2/3 agree — Patch URL differs
```

The clone path is also classified by `shape_dynamic` (consults the
forge's `/languages` endpoint) into `source` / `packaging_only` /
`notes_only`. A `notes_only` shape rejects (likely a CHANGELOG
commit, not the actual fix); `packaging_only` warns but does not
block.

### Stage 5 — Render

Writes the artifacts listed in *What it produces* and runs one final
auxiliary signal: **pointer-consensus**
(`cve_diff/report/consensus.py`). Two methods independently extract
a `(slug, sha)` from the advisory data and compare:

1. **OSV references** — scan `references[].url` for a forge-commit URL.
2. **NVD Patch-tagged** — scan NVD references with `tags: ["Patch"]`.

The report shows `Pointer consensus: N/2 method(s) agreed` so the
reader can see whether the agent's pick aligns with what the
authoritative advisories already published.

### Optional — `--with-root-cause`

Passes the rendered diff to a second Anthropic Opus call that returns
a structured root-cause record (CWE id, vulnerability type, why-chain).
Adds ~$0.05 and ~3 s; off by default.

## Install + use

```bash
uv venv && uv pip install -e ".[dev]"
```

```bash
# One CVE
cve-diff run CVE-2024-3094 --output-dir ./out

# Bench (parallel, summary table)
cve-diff bench --sample data/samples/random_200.json --output-dir /tmp/bench -w 4

# Health probes
cve-diff health
```

Sample CVE lists ship in `data/samples/`. The bench writes per-CVE
OSV JSON plus a `summary.{json,html,md}` aggregating outcomes
(PASS / correct refusal / pipeline issue) and a recovery-layers table.

### Environment

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | required — Opus 4.7 calls |
| `GITHUB_TOKEN`      | recommended — 5 K req/h vs 60 unauthenticated |
| `NVD_API_KEY`       | optional — avoids 429 storms on bench runs |

### Exit codes

| code | meaning |
|---:|---|
| 0 | success |
| 1 | `health` command — at least one critical service unhealthy |
| 4 | UnsupportedSource (closed-source vendor) |
| 5 | DiscoveryError (no canonical repo found) |
| 6 | AcquisitionError (clone / fetch cascade failed) |
| 7 | IdenticalCommitsError (would diff `HEAD..HEAD`) |
| 9 | AnalysisError / LLMCallFailed |

## Verifying your install

```bash
cve-diff --help                        # CLI loads
cve-diff health                        # probes OSV / GitHub / Anthropic
cve-diff run CVE-2024-3094 -o /tmp/out --disk-limit-pct 95
```

The third command runs the full pipeline on a known-good CVE (xz-utils
backdoor) — expect `✓ PASS` and 7 artifacts in `/tmp/out`.

## Out of scope

- **Non-forge artifacts.** CVEs whose canonical fix is a vendor patch
  tarball, a kernel mailing-list `git format-patch` post, or an SVN /
  Hg / Bazaar repo. The agent surrenders these as `unsupported`.
- **Coloured terminal output.** Plain markdown to stdout renders
  cleanly in any terminal and pipes safely.

## See also

- `cve_diff/agent/prompt.py` — the system prompt the agent runs with.
