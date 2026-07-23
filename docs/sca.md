# Software Composition Analysis

RAPTOR's SCA subsystem is a mechanical-tier dependency scanner. It
extracts every dependency from a project, matches against OSV, CISA KEV
and EPSS advisories, surfaces hygiene and supply-chain heuristics, and
proposes hardening patches. No LLM is required for the core pipeline --
the scanner, advisory matcher, reachability analysis and fix planner are
all deterministic.

See also: [commands](python-cli.md), [dependencies](dependencies.md).

---

## Usage

**Slash command:**

```bash
/sca /path/to/project
/sca fix /path/to/project --apply
```

**CLI entry point:**

```bash
bin/raptor-sca /path/to/project
```

**Python dispatch:**

```bash
python3 raptor.py sca --repo /path/to/project
```

`bin/raptor-sca` strips dangerous environment variables (`LD_PRELOAD`,
`PYTHON*`, etc.) before dispatching to the Python implementation.

---

## Subcommands

The default (no subcommand) is `scan` -- the full analyse pipeline.

| Subcommand | Purpose |
|------------|---------|
| `scan` (default) | Walk the target, match every dep against OSV/KEV/EPSS, write findings + report + SBOM + SARIF. |
| `fix` | Pin loose deps and fix CVEs. Safe plan by default; `--apply` to modify files. |
| `check <eco> <name> <ver>` | Single-dep pre-install safety verdict (Clean / Review / Block). |
| `upgrade <eco> <name> <from> <to>` | Forward-looking upgrade impact: advisories resolved vs introduced. |
| `diff <a.json> <b.json>` | Compare two `findings.json` files. |
| `verify <path> --proposed <dir>` | Round-trip check: re-scan with proposed overlay applied. |
| `health` | Probe every registry client; report reachability. |
| `purl <eco> <name> <ver>` | Build a canonical Package URL. |
| `render <findings.json>` | Re-render `report.md` / SARIF from an existing findings file. |
| `clean-cache` | Reclaim disk space from stale cache entries. Removes entries older than `--max-age` days from `~/.raptor/cache/sca/`. |
| `dt-push` | Upload a CycloneDX SBOM to a Dependency-Track instance. Requires `--url` and `--api-key` (or `$DT_API_KEY`). |
| `suppress` | Manage the suppression overlay (`.raptor-sca-suppress.yml`). Sub-actions: `list` (view current suppressions), `check` (validate against fresh findings and surface stale entries). |
| `bump` | Dependency version bump operations. |
| `fingerprint` | Compute, save or check-drift on a binary or OCI image fingerprint. Modes: compute+print (default), `--save` (store baseline), `--check` (detect drift from saved baseline). Accepts local file paths or OCI image refs. |
| `triage` | LLM-assisted triage of supply-chain candidates (typosquat auditing). Runs automatically during scan unless `--skip-triage` is passed; this subcommand invokes it standalone. |

---

## Scanning

### Ecosystems

Eight ecosystems are supported with manifest and lockfile parsing:

| Ecosystem | Manifests and lockfiles |
|-----------|------------------------|
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `setup.py`, `setup.cfg` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `shrinkwrap.json` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json` |
| PHP | `composer.json`, `composer.lock` |

### Inline-Install Sources

In addition to manifests, RAPTOR parses inline package installs from:

- **Dockerfiles**: `Dockerfile`, `Containerfile`, `Dockerfile.<x>`, `*.dockerfile`
- **devcontainers**: `devcontainer.json` / `.devcontainer.json` (`postCreateCommand`, `onCreateCommand`, etc.)
- **Shell scripts**: `*.sh`, `*.bash`
- **GitHub Actions workflows**: `.github/workflows/*.yml` (`run:` block bodies)

Recognised commands across all four shapes: `pip`, `pipx`, `uv pip`,
`apt`, `apt-get`, `yum`, `dnf`, `apk`, `npm`, `npx`, `bunx`, `yarn`,
`pnpm`, `cargo install`, `gem install`, `brew install`, `go install`,
`dotnet add package`, `nuget install`, `Install-Package`,
`composer require`.

### Advisory Matching

| Source | Use | Cache |
|--------|-----|-------|
| OSV.dev (`/v1/query`, `/v1/vulns/<id>`) | Advisory and affected ranges | 24h disk |
| CISA KEV catalogue | Known-exploited filter | 24h disk |
| FIRST.org EPSS | Exploitation probability | 24h disk |
| Per-ecosystem registries | Version listing for fix | 24h disk |

Registries supported: PyPI, npm, crates.io, RubyGems,
Go (proxy.golang.org), Maven Central, Packagist, NuGet, Debian Sources,
Homebrew. Run `raptor-sca health` to probe all ten in one shot.

### Scan Flags

```
--include-commented       parse `# pkg==X` lines as deps (info severity)
--no-inline-installs      skip Dockerfile/sh/GHA inline install extraction
--no-supply-chain         skip mechanical supply-chain heuristics
--no-reachability         skip module-level reachability scan
--no-kev / --no-epss      skip the named enrichment
--offline                 skip network; cache-only
--skip-triage             skip LLM triage pass
```

---

## SBOM Generation

Every scan produces a **CycloneDX 1.5** SBOM with VEX block by default
(`sbom.cdx.json`).

An **SPDX 2.3** SBOM can be generated alongside the CycloneDX output by
passing `--spdx`:

```bash
bin/raptor-sca /path/to/project --spdx
```

This writes `sbom.spdx.json` in addition to the default `sbom.cdx.json`.
The SPDX emitter consumes the same resolved dependency data as the
CycloneDX emitter, rendered to the SPDX 2.3 JSON schema. SPDX 2.3 does
not have a native VEX block (SPDX 3.0 will); operators wanting
VEX-in-SPDX should use an external VEX overlay.

### Importing Existing SBOMs

The `--sbom` flag imports a CycloneDX SBOM as the dependency list,
bypassing manifest discovery and parser dispatch:

```bash
bin/raptor-sca /path/to/project --sbom /path/to/sbom.cdx.json
```

This is useful when the build system already emits an SBOM (cargo
auditable, Maven cyclonedx-plugin, Trivy, Snyk export) and you want to
scan the exact resolved deps the build produced rather than re-parsing
manifests. When combined with `--repo`, RAPTOR uses the source tree for
reachability analysis while taking the dep list from the SBOM.

---

## Reachability Analysis

SCA reachability is mechanical. RAPTOR does not ask an LLM whether a
dependency is reachable; it derives the verdict from source evidence and
advisory metadata. LLM review can still run later in the pipeline
unless `--no-llm` is set, but it is not the source of truth for the
reachability verdict.

Best results come from scanning the full source tree. SBOM-only scans
can still identify vulnerable components, but they usually do not
contain enough source context to prove whether a vulnerable package or
function is used.

### Two-Tier Analysis

| Tier | What RAPTOR checks |
|------|--------------------|
| Module/package reachability | Whether project source imports or requires the vulnerable dependency. Python uses AST import parsing; npm uses lightweight import/require scanning; other ecosystems use their own import scanners. |
| Function-level reachability | When advisory data names affected functions or symbols, RAPTOR builds a source inventory/call graph and checks whether those affected functions appear to be called from project code. |

### Reachability Verdicts

| Verdict | Meaning |
|---------|---------|
| `likely_called` | Evidence that an advisory-listed affected function or symbol is called from project source. |
| `imported` | The vulnerable package is imported or required from non-test source, but no specific affected function call proven. |
| `not_function_reachable` | The package is present or imported, but advisory-listed affected functions were not found in the project call evidence. |
| `not_reachable` | No production import/use evidence for the dependency. |
| `called_in_dead_code` | A call was found, but the call site appears to live in dead or unreachable code. |
| `not_evaluated` | RAPTOR could not make a reliable reachability claim for this dependency/ecosystem/run shape. |

Treat `not_reachable` and `not_function_reachable` as triage signals,
not as mathematical proof that the vulnerability is impossible to
trigger. Dynamic dispatch, plugin loading, reflection, generated code,
incomplete source trees, and SBOM-only input can all reduce confidence.

Reports group the detailed vulnerability section into *Reachable /
likely used*, *Present, needs review*, and *Probably not reachable*.

---

## Fix Planning

The `fix` subcommand pins loose dependencies and fixes CVEs:

```bash
# Show fix plan (no files modified)
bin/raptor-sca fix /path/to/project

# Apply fixes in place
bin/raptor-sca fix /path/to/project --apply

# Write rewritten manifests to a separate directory
bin/raptor-sca fix /path/to/project --out proposed/

# CVEs only, skip loose-pin tightening
bin/raptor-sca fix /path/to/project --cve-only

# Upgrade all deps to latest safe version
bin/raptor-sca fix /path/to/project --apply --harden

# Allow fixes that cross a major version boundary
bin/raptor-sca fix /path/to/project --allow-major

# Mechanical-only mode (no LLM, CI-safe)
bin/raptor-sca fix /path/to/project --no-llm
```

### Fix Flags

| Flag | Purpose |
|------|---------|
| `--apply` | Apply changes directly to manifest files |
| `--out <dir>` | Write rewritten manifests to a separate directory |
| `--cve-only` | Only fix CVEs -- do not tighten loose pins |
| `--harden` | Upgrade all deps to the latest safe version |
| `--allow-major` | Include fixes that cross a major version boundary |
| `--no-llm` | Skip LLM analysis (mechanical-only, fast, CI-safe) |
| `--findings <path>` | Reuse findings from a previous scan |

### LLM-Assisted Major Bumps

When an LLM provider is configured, `fix --allow-major` automatically
analyses major-version-bump CVEs against your project's actual call
sites. If the LLM judges the bump safe, it is included in the plan. If
breaking changes are found, the output shows what breaks and where.

In CI (no LLM), `fix` falls back to mechanical mode -- warns about
major bumps and exits non-zero so the pipeline can flag them. Use
`--no-llm` to force mechanical-only mode regardless.

### Fix Output

| File | Format | Audience |
|------|--------|----------|
| `changes.json` | Structured change record | Tooling, CI |
| `changes.md` | Human-readable change log | Operators |
| `proposed/` | Rewritten manifest copies | Review, then `cp` or `git apply` |

---

## CI Integration

### Hard Gate: Severity Threshold

```yaml
- run: bin/raptor-sca $PROJECT --skip-review --skip-triage \
       --fail-on-severity high --fail-on-kev
  # exits 1 if any finding above threshold or KEV-listed
```

### Soft Gate: Track Over Time

```yaml
- run: |
    bin/raptor-sca $PROJECT --out before-${{github.sha}}
    bin/raptor-sca fix $PROJECT --apply
    bin/raptor-sca $PROJECT --out after-${{github.sha}}
    bin/raptor-sca diff before-*/findings.json after-*/findings.json
```

### PR Gate: Only Fail on Regressions

A turn-key workflow lives at `.github/workflows/sca-pr-gate.yml`.
Triggered on PRs touching any manifest, lockfile, or Dockerfile, it:

1. Scans the PR head.
2. Scans `main` as baseline.
3. Diffs the two findings sets.
4. Posts the markdown delta as a PR comment (idempotent -- updates the
   existing bot comment instead of creating new ones on every push).
5. Mirrors the same content to the workflow run's step summary.
6. Fails the build only when new high+ findings appear; resolved ones
   do not penalise the PR.

Operator-tunable: change `--fail-on-severity high` in the workflow to
`medium` for stricter gating, or to `critical` for noisier projects.
The diff command's exit code is 0 = no regression at threshold,
1 = regression found, 2 = inputs invalid.

### Pre-Flight: Registries Reachable

```yaml
- run: bin/raptor-sca health
  # exits 1 if any registry is unreachable; useful behind a corporate proxy
```

### Gate Flags

| Flag | Purpose |
|------|---------|
| `--fail-on-severity <level>` | Exit non-zero if any finding meets or exceeds this severity (low / medium / high / critical) |
| `--fail-on-kev` | Exit non-zero if any finding is in the CISA Known Exploited Vulnerabilities catalogue |
| `--skip-review` | Skip LLM review pass (faster, CI-appropriate) |
| `--skip-triage` | Skip LLM triage pass |

---

## Output

Every scan run produces:

| File | Format | Audience |
|------|--------|----------|
| `findings.json` | RAPTOR findings schema | Other RAPTOR commands (`/validate`, `/patch`) |
| `report.md` | Human-readable | Operators |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | SBOM consumers, Dependency-Track, etc. |
| `sbom.spdx.json` | SPDX 2.3 | Compliance pipelines (only when `--spdx` passed) |
| `findings.sarif` | SARIF 2.1.0 | GitHub / GitLab / IDE integrations |

### Render Flags

The `render` subcommand re-renders `report.md` / SARIF from an existing
`findings.json` and supports reachability filters:

```
--only-reachable          render only likely_called/imported vuln findings
--hide-not-reachable      hide not_reachable/not_function_reachable vuln findings
--reachability <list>     comma-separated vuln reachability allowlist
```

Reachability filters apply only to `sca:vulnerable_dependency` rows;
hygiene, supply-chain, and licence rows are preserved when re-rendering.

---

## Limitations

- **Library-mode floor-raise unsupported on some ecosystems** --
  `harden` refuses to corridor-pin a library's deps and emits
  `library_floor_raise_unsupported` for inline-install (Dockerfile
  `RUN pip install foo`), Debian, Cargo, Go modules, RubyGems. The
  application path still pins these.
- **OSV `affected_functions` coverage is patchy** -- function-level
  reachability only fires when an advisory ships symbol-level metadata.
  Python and Go are the best-covered ecosystems; npm, Maven and others
  mostly stay at the module-level `imported` verdict.
- **CHA-precision for dynamic dispatch in Java / C#** -- virtual and
  interface dispatch currently lands in `not_function_reachable` when the
  static graph cannot narrow the receiver type.
