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
| `upgrade <eco> <name> <from> <to>` | Forward-looking upgrade impact: advisories resolved vs introduced. Exit codes: 0 = no new advisories introduced, 1 = non-trivial trade-off, 2 = invalid arguments **or verdict unavailable** (OSV lookup degraded; the report carries a "verdict unavailable" section instead of a wrong 0/1). |
| `diff <a.json> <b.json>` | Compare two `findings.json` files. |
| `verify <path> --proposed <dir>` | Round-trip check: re-scan with proposed overlay applied. |
| `health` | Probe every registry client; report reachability. |
| `purl <eco> <name> <ver>` | Build a canonical Package URL. |
| `render <findings.json>` | Re-render `report.md` / SARIF from an existing findings file. |
| `clean-cache` | Reclaim disk space from stale cache entries. Removes entries older than `--max-age` days from `~/.raptor/cache/sca/`. |
| `dt-push` | Upload a CycloneDX SBOM to a Dependency-Track instance. Requires `--url` and `$DT_API_KEY` (or the deprecated `--api-key` flag — argv is world-readable via `/proc/*/cmdline`; the env var wins when both are set). |
| `suppress` | Manage the suppression overlay (`.raptor-sca-suppress.yml`). Sub-actions: `list` (view current suppressions), `check` (validate against fresh findings and surface stale entries). |
| `bump` | Dependency version bump operations, including GitHub release asset pins. |
| `fingerprint` | Compute, save or check-drift on a binary or OCI image fingerprint. Modes: compute+print (default), `--save` (store baseline), `--check` (detect drift from saved baseline). Accepts local file paths or OCI image refs. |
| `triage` | LLM-assisted triage of supply-chain candidates (typosquat auditing). Runs automatically during scan unless `--skip-triage` is passed; this subcommand invokes it standalone. |
| `fix-diff` | Fetch the upstream fix diffs for findings in a `findings.json` (cap with `--max-cves`). |

---

## Scanning

### Ecosystems

The main ecosystems supported with manifest and lockfile parsing:

| Ecosystem | Manifests and lockfiles |
|-----------|------------------------|
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `shrinkwrap.json` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.lockfile` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json` |
| PHP | `composer.json`, `composer.lock` |
| C/C++ | `vcpkg.json`, `conanfile.txt`, `conanfile.py`, `conan.lock`, `CMakeLists.txt` (FetchContent) |

Discovery also covers `.gitmodules`, Helm charts (`Chart.yaml` /
`Chart.lock`), Docker Compose, GitLab CI, and
`.pre-commit-config.yaml`.

### Inline-Install Sources

In addition to manifests, RAPTOR parses inline package installs from:

- **Dockerfiles**: `Dockerfile`, `Containerfile`, `Dockerfile.<x>`, `*.dockerfile`
- **devcontainers**: `devcontainer.json` / `.devcontainer.json` (`postCreateCommand`, `onCreateCommand`, etc.)
- **Shell scripts**: `*.sh`, `*.bash`
- **GitHub Actions workflows**: `.github/workflows/*.yml` (`run:` block bodies)

Recognised commands across all four shapes: `pip`, `pipx`, `uv pip`,
`apt`, `apt-get`, `yum`, `dnf`, `apk`, `npm`, `npx`, `bunx`, `yarn`,
`pnpm`, `cargo install`, `gem install`, `brew install`, `go install`.

### Advisory Matching

| Source | Use | Cache |
|--------|-----|-------|
| OSV.dev (`/v1/querybatch`, `/v1/vulns/<id>`) | Advisory and affected ranges | 24h disk |
| CISA KEV catalogue | Known-exploited filter | 24h disk |
| FIRST.org EPSS | Exploitation probability | 24h disk |
| CISA Vulnrichment | SSVC exploitation decision (`active`/`poc`/`none`) | 7d disk (1d for upstream misses) |
| Per-ecosystem registries | Version listing for fix | 24h disk |

EPSS and Vulnrichment are fetched once per scan over the unique CVE
set: EPSS in 100-id batches, Vulnrichment SSVC in parallel under a
per-scan budget of 1000 uncached fetches (container-image scans can
carry tens of thousands of distro CVE findings). The budget is spent
on the highest-value CVEs first — non-KEV before KEV-listed, then by
severity and EPSS; findings past the budget simply show no SSVC
signal for that run, and later runs pick them up as the cache warms.

Registries supported: PyPI, npm, crates.io, RubyGems,
Go (proxy.golang.org), Maven Central, Packagist, NuGet, Debian Sources,
Homebrew. Run `raptor-sca health` to probe all ten in one shot.

Bundled data (the popular-package lists behind the typosquat
heuristics, the KEV/EPSS calibration corpus, and the calibration
project samples) is kept fresh by scheduled repository workflows —
see [CI controls](ci-controls.md) for the refresh cadence and the
matching manual scripts under `packages/sca/scripts/`. The typosquat
list refresh refuses an upstream feed that would replace more than
half of the existing reference set (supply-chain guard against a
poisoned feed); `--allow-churn` overrides after review.

For a known-benign npm deprecation, the reviewed-legit list can record
`reviewed_deprecation` with the exact `notice`, `decided_by: "human"`, and an
ISO `date`. Only that unchanged notice is acknowledged; changed notices,
registry removal, and malicious advisories still trigger re-review. Other
ecosystems' yanked/abandoned flags are not suppressed by this acknowledgement.

Maven coordinates parsed from Gradle DSL files use the canonical
`group:artifact` (colon) shape. Findings from historical runs that
recorded the old slash shape will not correlate with new runs — those
rows never matched an advisory, so re-scan rather than merge.

### Scan Flags

```
--include-commented       parse `# pkg==X` lines as deps (info severity)
--no-inline-installs      skip Dockerfile/sh/GHA inline install extraction
--no-supply-chain         skip mechanical supply-chain heuristics
--no-reachability         skip module-level reachability scan
--no-kev / --no-epss      skip the named enrichment
--offline                 skip network; cache-only
--use-offline-db          route OSV lookups through a local sqlite copy of
                          the OSV daily dumps (air-gapped environments;
                          --offline-db-path overrides its location)
--baseline <findings.json> additionally write baseline-delta.json/.md with
                          only NEW / CLEARED findings since a previous run
--pr-comment              with --baseline, also write pr-comment.md for
                          `gh pr comment --body-file` (--pr-comment-label
                          sets the header label)
--html                    write a self-contained report.html alongside
                          report.md
--skip-triage             skip LLM triage pass
--trust-repo              honour repo-shipped policy files this run
--no-trust-repo           keep strict checks, overriding --trust-repo
                          and the project's `config` trust marker
```

Repo trust is gated: on untrusted runs a repo-shipped suppression
overlay (`.raptor-sca-suppress.yml`) and license-policy file are
reported but ignored. Precedence: `--no-trust-repo` > `--trust-repo`
> the governing project's `config` trust marker (the run pin's project in-run, this session's project otherwise; one-target gated) > off.

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
not have a native VEX block; operators wanting
VEX-in-SPDX should use an external VEX overlay.

### Importing Existing SBOMs

The `--sbom` flag imports CycloneDX 1.5 or SPDX 2.3 JSON as scan input,
bypassing manifest discovery and parser dispatch:

```bash
bin/raptor-sca /path/to/project --sbom /path/to/sbom.cdx.json
```

This is useful when the build system already emits an SBOM (cargo
auditable, Maven cyclonedx-plugin, Trivy, Snyk export) and you want to
scan the exact resolved deps the build produced rather than re-parsing
manifests. When combined with `--repo`, RAPTOR uses the source tree for
reachability analysis while taking the dep list from the SBOM.

Import supports CycloneDX **1.5 JSON** and SPDX **2.3 JSON**, detected from
the document contents. Validation covers the structures used by the importer;
it is not complete schema or specification conformance validation. Unsupported versions,
malformed input, duplicate JSON keys or BOM references, conflicting package
versions, and dangling dependency references fail the scan. Invalid UTF-8 is
rejected rather than replacing bytes in licence or provenance evidence.

The full inventory is retained separately from the vulnerability-matching
view. `sbom.cdx.json` preserves nested components, repeated package instances,
source references, licence text/URLs, hashes, root image identity, and the
original dependency graph. Components without a supported package URL remain
in that inventory and participate in licence-policy checks; they are not
sent to vulnerability registries. Matching gaps are logged and recorded in
`analysis-gaps.jsonl`. External BOM links are preserved but not fetched;
their inventory is reported as outside the matching coverage.

Direct/transitive status and depth come from the root dependency graph when
available. SCA's own directness properties are also recognized. Without either,
directness is recorded as unknown and risk scoring conservatively treats the
package as direct. Repeated instances remain separate in the inventory;
aggregated scanning uses their most exposed context. Distro PURLs distinguish
Debian, Ubuntu and Alpine releases, including Ubuntu's LTS stream.
Unknown release context is reported as incomplete advisory coverage; it does
not enter a broad cross-release query.

Multiple licence declarations remain separate declarations; SCA evaluates
each without inventing an AND/OR expression. Imported SPDX expressions retain
their stated AND/OR semantics. Enrichment increments the document version and
updates its scan metadata. A document signature is removed from the modified
output; the input file remains untouched. Component signatures are also
removed if adding missing component references changes their signed content.

CycloneDX components explicitly classified as `file` remain in the retained
inventory, including their hashes, licence declarations, evidence and graph
references. They do not enter package vulnerability matching or licence policy,
even when they carry a PURL. One diagnostic reports the number of retained file
components and that file-level analysis is outside coverage. Other components
without usable PURLs still enter licence policy. Classification follows the
producer's declaration; RAPTOR does not infer file type from a name or path.

For CycloneDX input, `--spdx` emits the scan projection rather than a complete
cross-format conversion. A diagnostic records that limitation; the full
retained inventory and evidence remain in `sbom.cdx.json`.

For SPDX input, `sbom.spdx.json` is always written, even without `--spdx`.
It preserves the complete original document as JSON data, including package
occurrences, files, snippets, checksums, source relationships, custom
`LicenseRef` definitions, and declared versus concluded licences. Formatting
may change; source metadata and document identity are retained. Scan results
are separate findings artifacts. `sbom.cdx.json` contains the package scan/VEX
projection, and `analysis-gaps.jsonl` records that conversion's limited coverage.

SPDX package matching requires a supported PURL. Multiple distinct PURLs for
one package, conflicting versions, duplicate IDs, dangling element references,
undefined local `LicenseRef` identifiers, and malformed licence expressions
fail the scan. External SPDX documents are retained but never fetched. Only
package **declared** licences enter licence policy; conclusions remain distinct,
and differences are reported. `NONE`, `NOASSERTION`, and missing declarations
receive unknown-licence handling; registry enrichment does not replace them.
Custom licence text is retained without inferring an equivalent standard
licence; policy can match its `LicenseRef` identifier explicitly. File/snippet
licences remain evidence outside package-policy coverage, with a diagnostic.

Dependency depth uses `documentDescribes`/`DESCRIBES` roots and `DEPENDS_ON` or
inverse dependency relationships. `CONTAINS` and source relationships do not
imply dependency depth. Unconnected packages have unknown directness and are
conservatively treated as direct. Distro PURL `upstream` qualifiers identify a
source package and, when supplied, its source version. Queries use those
coordinates while the inventory retains its binary name, version and PURL.
Native image extraction uses dpkg's versioned `Source` field for the same
purpose. Missing source declarations remain a coverage gap; arbitrary source
relationships are not used to infer a mapping.

Distro advisory ranges and fixes are restricted to the matching source package
and release. Standard Ubuntu, Pro and FIPS streams remain distinct. Missing or
contradictory release data, known foreign vendor versions (such as NodeSource
packages labelled as Debian), and unavailable advisory records produce
`analysis-gaps.jsonl` events and scan-health findings. `lookup_failed()` also
marks those package results unavailable for candidate-safety consumers. A
completed scan can still exit successfully under the existing threshold rules;
its scan-health findings must be checked when complete coverage is required.
Namespace/version metadata does not independently prove package origin.

When query coordinates differ from the inventory, findings carry an
`advisory_package` object and reports label the source identity and **source
fix**. That fix is a source-package version, not an instruction to install or
downgrade the binary to the same string. Source-package matches identify a
source release covered by an advisory; they do not establish that every
binary built from it contains the affected code. Findings distinguish these
with `advisory_match_scope: source_package`. For example, kernel-source
advisories associated with development headers are not evidence that a
container ships or runs the vulnerable kernel. Generated SPDX 2.3 documents retain the
required `CC0-1.0` metadata licence; this does not change component licences.

---

## Preparing RAPTOR inventory exports

[Syft](https://github.com/anchore/syft) is an external SBOM generation tool;
RAPTOR does not install or require it for ordinary scans. The preparation
script supports native Syft JSON schema 16.x and paired CycloneDX 1.5/SPDX 2.3
exports from the same scan. For a clean RAPTOR checkout:

```bash
mkdir -p /tmp/raptor-sbom/raw
syft scan dir:. --source-name https://github.com/gadievron/raptor \
  --source-version "$(git rev-parse HEAD)" \
  --exclude '**/.git/**' --exclude '**/test/data/**' \
  -o syft-json=/tmp/raptor-sbom/raw/syft.json \
  -o cyclonedx-json@1.5=/tmp/raptor-sbom/raw/sbom.cdx.json \
  -o spdx-json@2.3=/tmp/raptor-sbom/raw/sbom.spdx.json
python3 .github/scripts/prepare_sbom.py \
  --syft /tmp/raptor-sbom/raw/syft.json \
  --cyclonedx /tmp/raptor-sbom/raw/sbom.cdx.json \
  --spdx /tmp/raptor-sbom/raw/sbom.spdx.json \
  --repo . --out /tmp/raptor-sbom/prepared
```

For container exports, pass the corresponding three inputs and omit `--repo`.
Use an image digest and explicitly choose the generation scope (runtime
filesystem or all layers). Preparation does not pull, execute or inspect an
image itself. Use a fresh output directory: inputs are retained unchanged.

Preparation writes `sbom.cdx.json`, `sbom.spdx.json` and `provenance.json`.
It matches package occurrences against the native inventory and refuses
conflicting identities or subjects. RAPTOR's local lockfile entry receives a
repository/commit identity; installed nvm source metadata and NodeSource vendor
metadata correct their registry origins where explicitly established. Existing
occurrence references and relationships remain stable. Original lookup
coordinates are retained as evidence; speculative CPEs are removed when the
identity changes. MIT is declared only for RAPTOR's original project code.

The reviewed pins in `.github/sbom-provenance.json` attach upstream source and
licence-file candidates for specific versions. They do not certify that a tag
accounts for all wheel contents or reproduce the installed binary. Unknown
vendor source, unverified correspondence and missing candidate versions are
recorded explicitly. Update the manifest after checking the new upstream tag
and commit; a package bump never silently reuses an older version's source pin.
The script performs no network access, installation or publication.

This is a provenance preparation step, not a complete repository/container
licence inventory. Bundled-data supplements, original installed notices and
complete build-source evidence still need their own generation inputs. The
prepared exports can be passed to `raptor-sca --sbom` like other supported SBOMs.

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

# Never edit test-fixture manifests (pins there are test assertions)
bin/raptor-sca fix /path/to/project --apply \
    --exclude '**/tests/**' --exclude '**/fixtures/**' \
    --exclude '**/testdata/**'
```

### Fix Flags

| Flag | Purpose |
|------|---------|
| `--apply` | Apply changes directly to manifest files |
| `--out <dir>` | Write rewritten manifests to a separate directory |
| `--cve-only` | Only fix CVEs -- do not tighten loose pins |
| `--harden` | Upgrade all deps to the latest safe version. Candidates the promotion-safety check demotes carry the distinct `demoted_safety` status in the candidates JSON and report (inert under every flag combination). |
| `--allow-major` | Include fixes that cross a major version boundary |
| `--no-llm` | Skip LLM analysis (mechanical-only, fast, CI-safe) |
| `--findings <path>` | Reuse findings from a previous scan |
| `--exclude <glob>` | Exclude matching paths from the write set (repeatable). Also accepted by `bump`. |

`--exclude` filters only what gets *edited* -- scanning still reports
findings in excluded trees. Globs match the target-relative path;
`*` spans `/`, and a leading `**/` also matches at the target root.
Typical use: protecting test-fixture manifests whose deliberately-old
pins are test assertions. When patterns drop candidates, the report
prints one summary line with the count; without `--exclude`, writes
that land under test/fixture paths get an informational note.

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

## Updating Downloaded Tools

For tools downloaded from GitHub releases, put their release tag and required
asset hashes and sizes in a `github-release-pins.json` file anywhere in your
project. For example:

```json
{
  "schema_version": 1,
  "tools": {
    "linter": {
      "repository": "example/lint-engine",
      "version": "v1.2.3",
      "assets": {
        "linux": {
          "name": "lint-linux.tar.gz",
          "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "size": 123456
        }
      }
    }
  }
}
```

Replace the example values with the real release's hash and size. Your
downloader must read these pins and verify the downloaded bytes; SCA maintains
the manifest and does not install or execute the tool.

Run `raptor-sca bump <project>` to preview updates, or add `--apply` to write
Clean-verdict updates. Each update changes the release tag and all required
asset hashes and sizes together. Existing exclusions, skip rules, and version
policies apply. The weekly self-bump workflow includes these updates in its PR.

All required assets must retain their filenames and have SHA-256 digests in
GitHub's release metadata. Missing assets or digests leave that tool's pins
unchanged and appear in the skipped report. Changing filenames requires a
manual update. Inventory scans report these tools under the GitHub ecosystem;
a Clean bump does not establish that a binary is free of vulnerabilities.

For repositories that publish several tools or release streams, add
`"release_tag_prefix": "engine-v"` alongside `repository` and pin a matching
tag such as `"version": "engine-v1.2.3"`. SCA selects the highest stable numeric
version after that literal prefix, ignoring drafts, prereleases, and other
streams. Major-version and minor-skew policies compare the numeric suffix.
The lookup follows release-list pagination up to 1,000 releases; if the list
exceeds that bound, the update is skipped rather than guessing the latest
version. Without a prefix, SCA continues to use GitHub's latest-release endpoint.

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
Triggered on PRs touching any manifest, lockfile,
Dockerfile/Containerfile, docker-compose file, CI workflow, or
pre-commit config, it:

1. Scans the PR merge result (the PR as merged into `main`).
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
| `--fail-on-severity <level>` | Exit non-zero if any vulnerable-dependency finding meets or exceeds this severity (info / low / medium / high / critical) |
| `--fail-on-kev` | Exit non-zero if any finding is in the CISA Known Exploited Vulnerabilities catalogue, even below `--fail-on-severity` |
| `--fail-on-supply-chain <level>` | Exit non-zero if any supply-chain finding meets or exceeds this severity |
| `--fail-on-hygiene <level>` | Exit non-zero if any hygiene finding meets or exceeds this severity |
| `--fail-on-license <level>` | Exit non-zero if any license finding meets or exceeds this severity |
| `--fail-on-capability-drift` | Exit non-zero on any image capability-drift finding, regardless of severity |
| `--max-added-capability-buckets <N>` | Exit non-zero when a capability-drift finding adds more than N capability buckets (0 = any new bucket fails) |
| `--include-suppressed` | Evaluate findings marked suppressed in `.raptor-sca-suppress.yml` (default: skip them) |
| `--skip-review` | Skip LLM review pass (faster, CI-appropriate) |
| `--skip-triage` | Skip LLM triage pass |

The same `--fail-on-*` flags work on `render findings.json`, so a CI
job can scan once and gate on the persisted findings.

---

## Output

Every scan run produces:

| File | Format | Audience |
|------|--------|----------|
| `findings.json` | RAPTOR findings schema | Other RAPTOR commands (`/validate`, `/patch`) |
| `report.md` | Human-readable | Operators |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | SBOM consumers, Dependency-Track, etc. |
| `sbom.spdx.json` | SPDX 2.3 | Compliance pipelines (`--spdx`, or preserved SPDX input) |
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

- **Dependency resolution is metadata-only by design** -- resolving
  versions never executes a package's build backend. Sdist-only
  manifests fail the dry-run loudly; `--allow-sdist-builds` is the
  explicit per-run risk acceptance.
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
