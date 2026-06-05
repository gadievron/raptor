# raptor-sca — Software Composition Analysis

Mechanical-tier dep scanner: extract every dep from a project, match against OSV / KEV / EPSS, surface hygiene + supply-chain heuristics, propose hardening patches.

## Quick start

The user-facing entry point is `bin/raptor-sca`. It strips dangerous
env vars (LD_PRELOAD, PYTHON*, etc.) before dispatching to the Python
implementation. Add `bin/` to `$PATH` or invoke directly.

```bash
# Full analysis: produces findings.json, report.md, sbom.cdx.json, findings.sarif
bin/raptor-sca /path/to/project

# Show fix plan (safe default — no files modified)
bin/raptor-sca fix /path/to/project

# Apply fixes in-place
bin/raptor-sca fix /path/to/project --apply

# Upgrade all deps to latest safe version
bin/raptor-sca fix /path/to/project --apply --harden

# CI gate: exit 1 if findings above threshold
bin/raptor-sca /path/to/project --skip-review --skip-triage \
    --fail-on-severity high --fail-on-kev

# CI gate against an existing findings.json (no re-scan)
bin/raptor-sca render /path/to/findings.json \
    --fail-on-severity high --fail-on-kev
```

> **Note** — `libexec/raptor-sca-run` is the internal dispatch script.
> It refuses to run unless invoked via `bin/raptor-sca`, the RAPTOR
> launcher, or Claude Code. If you need to call it directly (e.g.,
> custom CI), set `_RAPTOR_TRUSTED=1` in the environment and ensure
> your env is otherwise clean.

## Sub-commands

| Sub-command | Purpose |
|---|---|
| `<path>` (default) | Walk the target, match every dep against OSV/KEV/EPSS, write findings.json + report.md + sbom.cdx.json + findings.sarif |
| `fix <path>` | Pin loose deps + fix CVEs; safe plan by default, `--apply` to modify. Flags: `--cve-only`, `--harden`, `--allow-major`, `--no-llm` |
| `check <eco> <name> <ver>` | Single-dep pre-install safety verdict (Clean / Review / Block) |
| `upgrade <eco> <name> <from> <to>` | Forward-looking upgrade impact: advisories resolved vs introduced |
| `diff <a.json> <b.json>` | Compare two findings.json files |
| `verify <path> --proposed <dir>` | Round-trip check: re-scan with proposed overlay applied |
| `render <findings.json>` | Re-render report.md / SARIF from an existing findings file |
| `purl <eco> <name> <ver>` | Build a canonical Package URL |
| `health` | Probe every registry client; report reachability |

## What gets scanned

**Manifests + lockfiles** (parsed by `parsers/`):

- Python: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `setup.py`, `setup.cfg`
- Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `shrinkwrap.json`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`
- Rust: `Cargo.toml`, `Cargo.lock`
- Go: `go.mod`, `go.sum`
- Ruby: `Gemfile`, `Gemfile.lock`
- .NET: `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json`
- PHP: `composer.json`, `composer.lock`

**Inline-install sources** (parsed by `parsers/inline_installs.py`):

- `Dockerfile`, `Containerfile`, `Dockerfile.<x>`, `*.dockerfile`
- `devcontainer.json` / `.devcontainer.json` — `postCreateCommand` / `onCreateCommand` / etc.
- `*.sh`, `*.bash`
- `.github/workflows/*.yml` — `run:` block bodies

Recognised commands across all four shapes:
`pip` / `pipx` / `uv pip` / `apt` / `apt-get` / `yum` / `dnf` / `apk` / `npm` / `npx` / `bunx` / `yarn` / `pnpm` / `cargo install` / `gem install` / `brew install` / `go install` / `dotnet add package` / `nuget install` / `Install-Package` / `composer require`.

## Output artefacts

Every analyse run produces:

| File | Format | Audience |
|---|---|---|
| `findings.json` | RAPTOR findings schema | other RAPTOR commands (`/validate`, `/patch`) |
| `report.md` | human-readable | operators |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | SBOM consumers, dependency-track, etc. |
| `findings.sarif` | SARIF 2.1.0 | GitHub / GitLab / IDE integrations |

`fix` adds:

| File | Format | Audience |
|---|---|---|
| `changes.json` | structured change record | tooling, CI |
| `changes.md` | human-readable change log | operators |
| `proposed/` | rewritten manifest copies | review, then `cp` or `git apply` |

## Data sources

| Source | Use | Cache |
|---|---|---|
| OSV.dev (`/v1/query`, `/v1/vulns/<id>`) | advisory + affected ranges | 24h disk |
| CISA KEV catalogue | known-exploited filter | 24h disk |
| FIRST.org EPSS | exploitation probability | 24h disk |
| Per-ecosystem registries | version listing for fix | 24h disk |

Registries supported: PyPI, npm, crates.io, RubyGems, Go (proxy.golang.org), Maven Central, Packagist, NuGet, Debian Sources, Homebrew. Run `raptor-sca health` to probe all ten in one shot.

## Common flags

### analyse

```
--include-commented       parse `# pkg==X` lines as deps (info severity)
--no-inline-installs      skip Dockerfile/sh/GHA inline install extraction
--no-supply-chain         skip mechanical supply-chain heuristics
--no-reachability         skip module-level reachability scan
--no-kev / --no-epss      skip the named enrichment
--offline                 skip network; cache-only
```

Reports include a reachability breakdown for vulnerable dependencies and group
the detailed vulnerability section into `Reachable / likely used`, `Present,
needs review`, and `Probably not reachable`.

## Reachability analysis

SCA reachability is mechanical. RAPTOR does not ask an LLM whether a dependency
is reachable; it derives the verdict from source evidence and advisory metadata.
LLM review can still run later in the pipeline, unless `--no-llm` is set, but it
is not the source of truth for the reachability verdict.

Best results come from scanning the full source tree. SBOM-only scans can still
identify vulnerable components, but they usually do not contain enough source
context to prove whether a vulnerable package or function is used.

```bash
# Source-first scan: best for reachability
python3 raptor.py sca --repo /path/to/full/source --no-llm --no-progress

# SBOM plus source: imports the component list, then uses source for reachability
python3 raptor.py sca \
  --repo /path/to/full/source \
  --sbom /path/to/sbom.cdx.json \
  --no-llm \
  --no-progress
```

The reachability flow has two tiers:

| Tier | What RAPTOR checks |
|---|---|
| Module/package reachability | Whether project source imports or requires the vulnerable dependency. Python uses AST import parsing; npm currently uses lightweight import/require scanning; other ecosystems use their own import scanners. |
| Function-level reachability | When advisory data names affected functions or symbols, RAPTOR builds a source inventory/call graph and checks whether those affected functions appear to be called from project code. |

Reachability verdicts:

| Verdict | Meaning |
|---|---|
| `likely_called` | RAPTOR found evidence that an advisory-listed affected function or symbol is called from project source. |
| `imported` | The vulnerable package is imported or required from non-test source, but RAPTOR has not proven a specific affected function call. |
| `not_function_reachable` | The package is present or imported, but advisory-listed affected functions were not found in the project call evidence. |
| `not_reachable` | RAPTOR found no production import/use evidence for the dependency. |
| `called_in_dead_code` | A call was found, but the call site appears to live in dead or unreachable code. |
| `not_evaluated` | RAPTOR could not make a reliable reachability claim for this dependency/ecosystem/run shape. |

Treat `not_reachable` and `not_function_reachable` as triage signals, not as
mathematical proof that the vulnerability is impossible to trigger. Dynamic
dispatch, plugin loading, reflection, generated code, incomplete source trees,
and SBOM-only input can all reduce confidence. In security review, these verdicts
are useful for prioritisation; they should not be used as the only reason to
ignore a high-impact issue.

### render

```
--only-reachable          render only likely_called/imported vuln findings
--hide-not-reachable      hide not_reachable/not_function_reachable vuln findings
--reachability <list>     comma-separated vuln reachability allowlist
```

Reachability filters apply only to `sca:vulnerable_dependency` rows; hygiene,
supply-chain, and license rows are preserved when re-rendering an existing
`findings.json`.

### fix

```
--apply                   apply changes directly to manifest files
--out <dir>               write rewritten manifests to a separate directory
--cve-only                only fix CVEs — don't tighten loose pins
--harden                  upgrade all deps to the latest safe version
--allow-major             include fixes that cross a major version boundary
--no-llm                  skip LLM analysis (mechanical-only, fast, CI-safe)
--findings <path>         reuse findings from a previous scan
```

## LLM auto-detection

When an LLM provider is configured, `fix --allow-major` automatically analyses
major-version-bump CVEs against your project's actual call sites. If the LLM
judges the bump safe, it's included in the plan. If breaking changes are found,
the output shows what breaks and where. In CI (no LLM), `fix` falls back to
mechanical mode — warns about major bumps and exits non-zero so the pipeline
can flag them. Use `--no-llm` to force mechanical-only mode regardless.

## CI patterns

### Hard gate: severity threshold

```yaml
- run: bin/raptor-sca $PROJECT --skip-review --skip-triage \
       --fail-on-severity high --fail-on-kev
  # exits 1 if any finding above threshold or KEV-listed
```

### Soft gate: track over time

```yaml
- run: |
    bin/raptor-sca $PROJECT --out before-${{github.sha}}
    bin/raptor-sca fix $PROJECT --apply
    bin/raptor-sca $PROJECT --out after-${{github.sha}}
    bin/raptor-sca diff before-*/findings.json after-*/findings.json
```

### Pre-flight: registries reachable

```yaml
- run: bin/raptor-sca health
  # exits 1 if any registry is unreachable; useful behind a corporate proxy
```

### PR gate: only fail on regressions

A turn-key workflow lives at `.github/workflows/sca-pr-gate.yml`.
Triggered on PRs touching any manifest / lockfile / Dockerfile, it:

1. Scans the PR head.
2. Scans `main` as baseline.
3. Diffs the two findings sets.
4. Posts the markdown delta as a PR comment (idempotent — updates the
   existing bot comment instead of creating new ones on every push).
5. Mirrors the same content to the workflow run's step summary.
6. Fails the build only when **new** high+ findings appear; resolved
   ones don't penalise the PR.

Operator-tunable: change `--fail-on-severity high` in the workflow to
`medium` for stricter gating, or to `critical` for noisier projects.
The diff command's exit code is 0 = no regression at threshold,
1 = regression found, 2 = inputs invalid.

## Limitations + follow-ups

- **Library-mode floor-raise unsupported on a handful of ecosystems** — `harden` refuses to corridor-pin a library's deps and emits `library_floor_raise_unsupported` for cases that can't be expressed as a range: inline-install (Dockerfile `RUN pip install foo`), Debian, Cargo, Go modules, RubyGems. The application path still pins these.
- **OSV `affected_functions` coverage is patchy** — function-level reachability (the `not_function_reachable` / `likely_called` verdicts) only fires when an advisory ships symbol-level metadata. Python + Go are the best-covered ecosystems; npm / Maven / others mostly stay at the module-level `imported` verdict.
- **CHA-precision for dynamic dispatch in Java / C#** — virtual / interface dispatch currently lands in `not_function_reachable` when the static graph can't narrow the receiver type. The reachability substrate has a scoping doc; the precision improvement is deferred until an operator signal justifies it.
