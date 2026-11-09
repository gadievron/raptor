# Software Composition Analysis

[Documentation index](README.md)

RAPTOR's SCA subsystem is a mechanical-tier dependency scanner. It
extracts every dependency from a project, matches against OSV, CISA KEV
and EPSS advisories, surfaces hygiene and supply-chain heuristics, and
proposes hardening patches. No LLM is required for the core pipeline --
the scanner, advisory matcher, reachability analysis and fix planner are
all deterministic.

**Related documentation:**
[slash-command reference](commands.md#software-composition-analysis) |
[Python CLI reference](python-cli.md) |
[dependencies](dependencies.md)

---

**On this page:**

- [Usage](#usage)
- [Choose a scan](#choose-a-scan)
- [Understand scan results](#understand-scan-results)
- [Explore inventories offline](#explore-inventories-offline)
- [Subcommands](#subcommands)
- [Scanning](#scanning)
- [SBOM Generation](#sbom-generation)
- [Preparing RAPTOR inventory exports](#preparing-raptor-inventory-exports)
- [Reachability Analysis](#reachability-analysis)
- [Fix Planning](#fix-planning)
- [Updating Downloaded Tools](#updating-downloaded-tools)
- [CI Integration](#ci-integration)
- [Output](#output)
- [Cache Cleanup](#cache-cleanup)
- [Limitations](#limitations)

## Usage

**In a RAPTOR session:**

```text
/sca /path/to/project
/sca fix /path/to/project
```

`fix` produces a plan by default. Add `--apply` when you intend to modify
the target's dependency files.

**In your terminal (CLI entry point):**

```bash
bin/raptor-sca /path/to/project
```

**In your terminal (Python dispatch):**

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
| `sbom <inspect\|diff\|notices>` | Offline SBOM inventories, evidence inspection, comparison and original-notice export. |
| `render <findings.json>` | Re-render `report.md` / SARIF from an existing findings file. |
| `clean-cache` | Reclaim stale entries and enforce a disposable disk budget. Supports `--dry-run`, `--max-age`, `--max-size-mb`, `--stress-max-age`, and `--stress-max-size-mb`. |
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
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.cfg`; `setup.py` detection only (see below) |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `shrinkwrap.json` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.lockfile` |
| Rust | `Cargo.toml`, `Cargo.lock` |
| Go | `go.mod`, `go.sum` |
| Ruby | `Gemfile`, `Gemfile.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `packages.lock.json` |
| PHP | `composer.json`, `composer.lock` |
| C/C++ | `vcpkg.json`, `conanfile.txt`, `conanfile.py`, `conan.lock`, `CMakeLists.txt` (FetchContent) |

Dependency declarations in executable `setup.py` scripts are not extracted.
RAPTOR reports a parse failure when dependency keywords are present; it never
runs the script to discover dependencies. Supply declarative metadata or a
lockfile for coverage.

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
manifests. Source reachability is not inferred from the working directory.
Add `--sbom-source-root /path/to/source` to use a corresponding source checkout;
that association is supplied by you, not authenticated by the scanner.

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

## Creating and scanning your own SBOM

A normal project scan writes `sbom.cdx.json`; add `--spdx` for SPDX 2.3 output.
An existing CycloneDX 1.5 or SPDX 2.3 JSON document can feed the same advisory
and licence-policy pipeline:

```bash
raptor-sca ./project --out scan --spdx
raptor-sca ./project --sbom release.cdx.json --out scan
raptor-sca ./project --sbom release.spdx.json --out scan
```

Add `--sbom-source-root /path/to/source` when you want checks against the
corresponding source checkout.
Supported Package URLs and resolved versions enable advisory matching; missing
or unsupported coordinates remain in the inventory with coverage diagnostics.
File records are retained as evidence, outside package vulnerability matching.
Advisory checks may need network access or a populated offline advisory cache.

Findings include available fixed-version recommendations. Compare explicit current/candidate package versions before changing your build:

```bash
raptor-sca upgrade npm example 1.0.0 1.0.1
raptor-sca upgrade PyPI example 1.0.0 --candidate 1.0.1 --candidate 1.1.0
```

`upgrade` compares advisory exposure at those versions; it does not rewrite an
SBOM or resolve an entire replacement image. A distro advisory's **source fix** is not necessarily an
installable binary-package version. `fix` rewrites supported source manifests;
an SBOM alone cannot supply those manifests or rebuild a container. Scan the
checkout and review its proposed changes when applying upgrades, then rebuild
and scan the resulting SBOM again. `sbom inspect`, `diff`, `why` and `notices`
work offline and do not perform vulnerability queries.

## Planning upgrades from an SBOM scan

Use `sbom plan` with the inventory and RAPTOR findings from the same scan:

```bash
raptor-sca ./project --sbom release.cdx.json --out scan
raptor-sca sbom plan scan/sbom.cdx.json --findings scan/findings.json --out upgrade-plan
raptor-sca sbom plan scan/sbom.cdx.json --findings scan/findings.json --format json
```

The plan groups repeated occurrences of the same package identity and retains
their occurrence IDs. It lists installed versions, recorded advisories, available
forward fix versions and unresolved gaps. Suppressed findings remain visible
and do not drive proposals. Unsupported or unversioned packages, unmatched
findings and scan-health gaps are explicit. Identity matching does not prove
that supplied findings came from the exact same scan; input fingerprints are
retained for traceability.

The default uses saved findings only and makes no network requests. Candidate
versions remain **not checked**. The combined proposal uses the highest usable
fix recommended by the recorded findings; it is not a claim that the version
is available, compatible or free of other vulnerabilities. Candidates may cross
a major version boundary and always require review.

Recheck the installed and candidate versions with the existing advisory client:

```bash
raptor-sca sbom plan scan/sbom.cdx.json --findings scan/findings.json \
  --check-candidates --out checked-upgrade-plan
raptor-sca sbom plan scan/sbom.cdx.json --findings scan/findings.json \
  --check-candidates --offline --cache-root advisory-cache --format json
```

Checks show advisories resolved, remaining and introduced at each candidate.
The smallest checked candidate with no known advisories becomes the proposal.
Advisory alias IDs use the existing SCA matching logic. Data can come from the
normal advisory cache; missing cache entries, unavailable records and failed
lookups remain **unavailable**, rather than being treated as clear. The shared
`check` and `upgrade` commands also return an unavailable verdict for a cold
offline cache or missing advisory records. These
checks do not resolve the full dependency graph, verify registry availability,
run tests or establish API/build compatibility. Rebuild and rescan the resulting
inventory after applying changes in the source project or image build.

For distro packages, the plan separates the installed binary version from its
source-package query and fix version. Source fixes require a corresponding
available binary build from the distributor; they are not install commands.
Missing release context prevents candidate checks.

`--max-candidates` defaults to five per package; `--max-queries` defaults to
1,000 unique installed/candidate coordinates across the plan. Omitted candidates
and unperformed checks are recorded. Findings are read with the existing
operator-input byte budget, projecting one row at a time and discarding unused
source text and descriptions.

`--out` requires a new directory and writes `upgrade-plan.json` plus a complete
`upgrade-plan.md`. JSON includes all package groups; terminal text shows the
first 50 actionable or uncertain groups. Inputs and source files are unchanged.
The JSON format is `raptor-sbom-upgrade-plan`, schema version 1.

| Mode | Exit code | Meaning |
|---|---:|---|
| Saved findings | 0 | Plan generated; candidates have not been rechecked |
| Candidate recheck | 0 | An advisory-clear option exists for each affected package |
| Candidate recheck | 1 | An affected package has no applicable fix or no checked option clears known advisories |
| Either | 2 | Invalid input; or requested verification has unavailable evidence, unmatched findings or scan-health gaps |

A successful recheck concerns the queried advisory coordinates only. It does
not certify the complete SBOM or approve an upgrade automatically.

## Verifying a rebuilt SBOM against an upgrade plan

After applying reviewed changes in your project or image build, scan the rebuilt
inventory and verify it against the saved plan:

```bash
raptor-sca ./project --sbom rebuilt.cdx.json --out rebuilt-scan
raptor-sca sbom verify-plan upgrade-plan/upgrade-plan.json rebuilt-scan/sbom.cdx.json \
  --findings rebuilt-scan/findings.json --out verification
raptor-sca sbom verify-plan upgrade-plan/upgrade-plan.json rebuilt-scan/sbom.cdx.json \
  --findings rebuilt-scan/findings.json --format json
```

`verify-plan` is offline and read-only. It compares the planned versions with
observed package occurrences. Versions at or above the proposal meet its
minimum-version target; compatibility is not established. Repeated
versions are kept separate; ambiguous occurrence matching remains unavailable.
Observed versions for each ambiguous identity are listed once in
`ambiguous_groups`, rather than repeated for every baseline version.
For distro packages, the planned source version is compared with the rebuilt
package's explicitly declared source coordinates, separately from its binary
version. A larger binary version without source coordinates cannot verify a
source fix.

New SCA scans emit `advisory-coverage.json` alongside their findings. This
records which package coordinates received an available advisory result and
hashes the emitted SBOM(s) and findings. Verification reads that receipt next
to `--findings` by default; use `--coverage PATH` if you moved it. Supply the
**SBOM emitted by that scan**, rather than a differently formatted copy of the
input inventory. Inventory snapshots and evidence bundles are refused here:
their recorded source fingerprints do not authenticate their current records.
Any change to the bound SBOM or findings invalidates the
receipt. These unsigned receipts establish local consistency, not authenticity;
use scan outputs and saved plans from a trusted producer. Older scans without a receipt can still show observed versions, but
cannot confirm advisory resolution; rescan to collect the required evidence.

The report separates resolved, remaining and newly reported advisories from
suppression changes. A previously reported advisory absent from current
findings is confirmed resolved only when the same package identity remains
listed and has matching positive query coverage. Otherwise it remains **not
reported** or **not observed**, with an explanation. An unlisted package is not
proof of file removal, and suppressing a finding is not resolving it. Feed
updates can produce newly reported findings without the rebuild causing them.

Coverage gaps, unmatched findings, unavailable queries and source/release
identity changes remain explicit. Package-query coverage does not establish
complete nested-payload inventory, complete advisory databases, build
provenance or compatibility. Receipts check local artifact consistency; they
are not signed attestations. File inventory and OS/container subjects remain
outside package-advisory matching.

Add `--max-coverage-age-hours 24` to require a receipt generated within the last
day. This checks receipt age, not the age of the upstream advisory feed. Older
receipts remain usable when no age requirement is requested.

`--out` requires a new directory and writes `upgrade-verification.json` and
`upgrade-verification.md`. JSON and saved Markdown retain all outcomes;
terminal text limits long sections to 50 entries. The JSON format is
`raptor-sbom-plan-verification`, schema version 1.

| Exit code | Meaning |
|---:|---|
| 0 | Planned targets met, with no outstanding active or newly reported advisory/suppression concerns within recorded package coverage |
| 1 | Unmet targets, unobserved affected packages, remaining/new advisories or newly suppressed findings need review |
| 2 | Coverage is unavailable, inconsistent or ambiguous; verification cannot conclude |

The command does not run a new scan, apply upgrades or change image publication.

## Inspecting SBOM inventories and collected notices

Use `raptor-sca sbom inspect` to examine an existing CycloneDX 1.5 or SPDX 2.3
JSON inventory. It shows licence declarations, supplied package relationships
and available notice evidence. RAPTOR container-evidence ZIPs and directories
also expose recorded executable ownership and source/build assessments.

```bash
raptor-sca sbom inspect sbom.cdx.json --out inventory
raptor-sca sbom inspect container-sbom.zip --license MIT --format csv
raptor-sca sbom inspect container-sbom.zip --package example --format json
```

`--out` writes `inventory.json`, `inventory.csv` and `summary.md`.
The JSON retains the complete package/source/subject projection, with the selected occurrence IDs
listed separately; CSV contains the selected records. Package records,
source-only dependency candidates and OS/container subjects remain separate scopes.
Subject records retain their supplied declarations and evidence; package-gap
counts do not assert a blanket licence for an operating system or image. A licence filter
matches an exact declaration operand, including compound expressions, without
choosing an `AND`/`OR` licensing option. The JSON retains supplied dependency
links and distinguishes missing graph data from an explicitly empty edge list.

A standalone SBOM containing licence identifiers or URLs may have no retained
notice text. That coverage is reported as **not assessed**. Embedded texts can
be inspected and exported. For an evidence bundle, retained notice bytes are
checked against their SHA-256 fingerprints. Recorded ownership and source/build
assessments retain their scopes and limitations; inspection is not a fresh
signature, build-provenance or legal review.

Compare two source inventories, collected-evidence bundles or saved inventory
snapshots:

```bash
raptor-sca sbom diff baseline/inventory.json current/inventory.json --out changes.json
raptor-sca sbom diff previous.cdx.json current.cdx.json
```

The comparison separates additions/removals, version updates, declaration
changes and notice fingerprints. It pairs stable occurrences first, then only
unambiguous package identities; repeated instances remain visible as ambiguous
groups. Notice-text updates, including spelling or copyright-year changes, are
informational. The command does not classify their legal meaning. Changes to
binary ownership and supplied dependency graphs appear in separate comparison sections.
Missing ownership or graph data is reported as unavailable, not as removals.
Duplicate file paths across layers remain ambiguous. An ownership-check removal
does not establish that the file disappeared from the image.

Trace supplied dependency paths without scanning a source tree:

```bash
raptor-sca sbom why sbom.cdx.json example
raptor-sca sbom why inventory/inventory.json example --root application --out paths.json
```

`why` keeps repeated package occurrences separate. It reports cycles, path/depth
limits and whether a requested root was reached. A boundary with no recorded
parents is not proof of a direct dependency. `--max-paths` and `--max-depth`
control output size; traversal also has a fixed budget of 10,000 node visits
and parent references combined. Exhausted searches are marked truncated.

Collect your own image's original notice bytes using a native **Syft 16.x**
image catalogue with file hashes, embedded image metadata and layer identities.
Supply the matching offline OCI blob store or explicitly enable registry access
with a single-platform manifest digest:

```bash
raptor-sca sbom collect --syft syft.json --oci-layout image-layout --out evidence
raptor-sca sbom collect --syft syft.json \
  --registry-ref example/image@sha256:PLATFORM_MANIFEST_DIGEST --out evidence
raptor-sca sbom inspect evidence --out inventory
raptor-sca sbom notices evidence --out collected-notices
```

The registry digest must match the catalogue's platform manifest; a mutable tag
or a multi-platform index digest is insufficient. Collection verifies layer and
file digests without executing the image. The output directory must be new;
failed collections leave no partial bundle. Add repeatable `--identify /path`
options to retain hashes for catalogued executables without saving their bytes.

The bundle includes the unchanged `syft.json`, image identity, capture receipts,
notice associations, original notice blobs and `prepared/sbom.cdx.json`. The
CycloneDX projection contains catalogued packages and supplied package links;
the original file inventory remains in `syft.json`. This does not translate
arbitrary Syft metadata into CycloneDX, establish bundled-dependency completeness
or infer build provenance. Missing declarations and notices remain explicit.
RAPTOR-specific source assessments are not invented for other images.

Inventory inspection decodes large arrays one record at a time and discards
unused file details after validation. It keeps the original input fingerprint,
package records and file count. Normal vulnerability scans continue to retain
the complete imported document for faithful enriched exports.

Export collected original licence and notice bytes to a **new** directory:

```bash
raptor-sca sbom notices container-sbom.zip --out collected-notices
raptor-sca sbom notices sbom.cdx.json --license MIT --out mit-notices
raptor-sca sbom inspect collected-notices
```

The export stores original bytes by SHA-256 and includes `notice-index.json`
with original paths, origins, layer/visibility evidence and package associations.
An unfiltered bundle export includes unassociated collected notices too. Standard
licence references and distributor notices keep their distinct origins. Existing
output paths are refused, and a missing/corrupt requested text cannot leave a
partially published export. Saved JSON inventory snapshots retain evidence
metadata; exporting their original bytes requires the original input bundle.

These commands operate offline. They read existing data without fetching
external licence URLs or executing image contents. Inputs are bounded to 96 MiB
per JSON document and 8 MiB per notice; ZIPs are limited to 10,000 entries and
2 GiB of declared uncompressed contents. A completed inspection or comparison
returns 0 even when gaps or changes are present; invalid inputs return 2.
Use each command's `--help` for options and examples.


## Authenticating a published container evidence download

The image-publishing job includes `evidence-checksums.sha256` and
`evidence-attestation.jsonl` in the `container-sbom` download when signing
succeeds. The checksum manifest covers the retained image manifest, image
digest, inventories, reports, provenance and notice files. It also covers
findings or coverage receipts if they are present; it does not create them.
Partial reports can be authenticated too: a signature identifies their
producer and preserves their bytes, without certifying their completeness.

Extract the download into a new directory and use a recent GitHub CLI to
verify the signature against RAPTOR's publishing workflow **before** checking
its file hashes:

```bash
cd container-sbom
gh attestation verify evidence-checksums.sha256 \
  --repo gadievron/raptor \
  --signer-workflow gadievron/raptor/.github/workflows/dockerhub-publish.yml \
  --deny-self-hosted-runners --bundle evidence-attestation.jsonl
sha256sum --check --strict evidence-checksums.sha256
```

Both commands must succeed. Compare the image digest in `image-digest.txt`
with the image you intend to inspect; an authentic older report is not proof
that it describes today's `latest` image. Files added after signing are not
covered by these checks. Signing failures are shown in the job summary and
annotations; unsigned downloads remain available and publication continues.

For an offline machine, obtain a trusted-root file on a trusted connected
machine with `gh attestation trusted-root`, then add
`--custom-trusted-root /trusted/path/trusted-root.jsonl` to the verification
command. Transfer that trust root independently of the download being checked.
See GitHub's [offline verification instructions](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).

This authenticates RAPTOR's producing workflow. It does not establish Node's
upstream build provenance, prove compiled native dependency membership, or
change the findings of `sbom verify-plan`, which checks local consistency.

Image builds also check uv's publisher provenance automatically. The installed
version selects its upstream container release; the check pins the fetched OCI
index and platform manifest, verifies layer digests, and requires an exact uv
binary hash match. GitHub CLI then verifies the index attestation against
Astral's `build-docker.yml` workflow. Failures produce a warning and an unknown
provenance result, while image publication continues.

The `uv-provenance/` directory contains `uv-container-binding.json`, original OCI documents,
`uv-publisher-attestation.jsonl` and the signature verifier's result. The binding alone is
an unsigned byte comparison. To verify the publisher signature independently:

```bash
gh attestation verify uv-provenance/index.json --repo astral-sh/uv \
  --signer-workflow astral-sh/uv/.github/workflows/build-docker.yml \
  --deny-self-hosted-runners --bundle uv-provenance/uv-publisher-attestation.jsonl
```

The same trusted-root option supports offline verification. The source layer's
binary bytes are checked during collection rather than retained in the download;
RAPTOR's signed checksum manifest authenticates the resulting binding record.
This establishes byte identity with a publisher image layer, separately from
runtime visibility, source correspondence or compiled dependency completeness.


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
filesystem or all layers). Default preparation uses local inputs. Optional
owner-file verification streams selected image layers without executing an image. Use a fresh output directory: inputs are retained unchanged.

Preparation writes `sbom.cdx.json`, `sbom.spdx.json` and `provenance.json`.
It matches package occurrences against the native inventory and refuses
conflicting identities or subjects. RAPTOR's local lockfile entry receives a
repository/commit identity; installed nvm source metadata and NodeSource vendor
metadata correct their registry origins where explicitly established. Existing
occurrence references and relationships remain stable. Original lookup
coordinates are retained as evidence; speculative CPEs are removed when the
identity changes. MIT is declared only for RAPTOR's original project code.

With `--repo`, preparation also attaches root-lockfile source archives. Package
name, version, registry and root `uv.lock` location must agree with the native
inventory. Every locked registry identity must be present; an incomplete root
inventory fails preparation. Missing sdists remain explicit per-package gaps.
Source URLs and expected SHA-256 values come from the checked-out lockfile;
preparation does not fetch archives or verify build correspondence. CycloneDX
stores archive hashes on distribution references, and SPDX stores the source
record in `sourceInfo`. Installed-package hashes, binary download locations and
licence assertions are preserved. Both repository input files are hashed in
`provenance.json` alongside the three exports and the provenance manifest.

The reviewed pins in `.github/sbom-provenance.json` attach upstream source and
licence-file candidates for specific versions. They do not certify that a tag
accounts for all wheel contents or reproduce the installed binary. Unknown
vendor source, unverified correspondence and missing candidate versions are
recorded explicitly. Update the manifest after checking the new upstream tag
and commit; a package bump never silently reuses an older version's source pin.
Default preparation performs no network access. Installation and publication
remain outside this script.

For repository input, the manifest's `bundles` rules also inventory committed
PSL data, retained dataflow source excerpts, calibration data and CVE-diff
sample metadata. File bytes and notice files must match their Git blob
identities before their SHA-256 values and commit-specific retrieval URLs are
emitted. Dirty, missing or unclassified material fails preparation. Source
excerpts carry their upstream licence scope; original RAPTOR annotations retain
MIT. Mixed data terms remain explicit unknowns with per-file source credits.

Bundle entries use CycloneDX `data` components and SPDX 2.3 `OTHER` packages,
with the data classification retained in provenance. Relationships express
repository containment. The original scanner components and relationships
remain intact. Unpopulated gitlinks are recorded as references. Preparation currently refuses
populated submodules; combining their separate inventories is not supported. Repository rules are not applied to container
exports, where actual image bytes must establish inclusion.

This is a provenance preparation step, not a complete repository/container
licence inventory. Original installed notices, reviewed mixed-data terms and
complete build-source evidence still need their own generation inputs. The
prepared exports can be passed to `raptor-sca --sbom` like other supported SBOMs.


### Capturing container notice evidence

The notice capture tool reads a native Syft 16.x **image** catalogue and recovers
original files from its single-platform, digest-pinned image. It never starts
the image. Use the same explicit Syft scope (`squashed` or `all-layers`) as the
inventory you are investigating:

```bash
python3 .github/scripts/capture_container_evidence.py \
  --syft /tmp/raptor-sbom/container/syft.json \
  --registry-ref 'registry.example/org/image@sha256:<platform-manifest-digest>' \
  --identify /usr/local/bin/uv \
  --out /tmp/raptor-sbom/container/evidence
```

`--registry-ref` must match the catalogue's platform manifest digest; a tag or
multi-platform index digest is refused. For offline use, replace it with
`--oci-layout /path/to/layout`, whose `blobs/sha256/` directory contains the
referenced compressed layers. The offline path does not import the HTTP backend.
Omit `--identify` when that file is not present; repeat it to hash other
catalogued files. Identity-only files are hashed without saving executable bytes.

The fresh output directory contains `evidence.json` and original notice bytes
under `notices/sha256/<hash>`. The report records the catalogue hash, image/config
digests, platform, scope, compressed layer digest, config's layer diff ID, file
path and SHA-256, and native package IDs. It retains package licence claims as
claims. Required catalogue evidence must be present and any supplied SHA-256 must
match. Compressed layers are size-checked and SHA-256 verified in full, and their
uncompressed tar streams must match the config diff IDs, before output is created.
Layer-local hard links resolve only against verified regular files in the same
layer; missing target selections cause a bounded replay, and cross-layer targets
and cycles are refused. Symlinks are never followed. Oversized selected payloads, unsafe archive entries and
unsupported compression fail capture. A failed output write can leave an
incomplete directory; `evidence.json` is written last as the completion record.

Selection includes catalogue licence locations, conventional notice filenames,
Debian common-licence files, and npm notice probes. It also scans package-local
notice filenames while reading layers, including case variants such as
`license-MIT`, declared npm licence-file pointers, and nested Python vendor
notices inside the owning `.dist-info`/`.egg-info` directory. Files in its dedicated
`licenses/` subtree are included even with nonstandard names such as
`THIRD-PARTY-NOTICES.md`. Nested npm
`node_modules` directories require their own package identity.

Python [RECORD inventories](https://packaging.python.org/en/latest/specifications/recording-installed-packages/#the-record-file)
can name notices absent from Syft's top-level file index. Capture format 2
requires those files within the owning distribution's metadata directory and
checks recorded SHA-256 and size claims when present. Relative and absolute
paths stay inside that directory; traversal, conflicting claims and unsupported
notice digest algorithms fail capture. Unindexed files retain unconfirmed final
filesystem visibility even when their origin-layer bytes and RECORD hashes match.
Preparation accepts existing format-1 captures, while format 2 also requires the
RECORD-listed notices. No licence conclusions are inferred from file membership. A licence
location can point to package metadata rather than the licence text: the report
distinguishes package manifests and Python `METADATA`/`PKG-INFO` records. Optional probes have unconfirmed runtime
visibility; origin-layer evidence does not independently replay filesystem
whiteouts or establish that a file survives in the final image. Packages without
an associated notice candidate remain explicit gaps. Captured filenames and
package associations do not establish the applicable terms or notice completeness.

To associate the captured files with packages and retain those links in paired
exports, pass the capture directory during preparation:

```bash
python3 .github/scripts/prepare_sbom.py \
  --syft /tmp/raptor-sbom/container/syft.json \
  --cyclonedx /tmp/raptor-sbom/container/sbom.cdx.json \
  --spdx /tmp/raptor-sbom/container/sbom.spdx.json \
  --notice-evidence /tmp/raptor-sbom/container/evidence \
  --out /tmp/raptor-sbom/container/prepared
```

Preparation binds the capture to the exact native catalogue hash, image, config,
platform and scan scope. It checks notice bytes against their recorded sizes and
SHA-256 values, including native file hashes where available. Missing required
locations, altered files, unsafe storage paths and symlinked stores fail before
output is created. Preparation trusts the capture's layer-origin records; it does
not refetch layers or treat an unsigned capture as an attestation.

Associations come from exact catalogue licence locations, notice candidates
within the same layer's Python distribution metadata directory or npm package
directory, verified Python RECORD notice claims, and explicit npm licence-file
pointers. Nested npm dependencies do not
inherit their parent's association. Debian copyright references can additionally
link to a captured common licence file; missing or ambiguous versions remain gaps.
Conventional directory matches are candidates, not conclusions about applicable
terms. Package metadata alone does not close a missing-notice gap.

CycloneDX stores hashed relative `evidence` references and structured
`raptor:notice-evidence` properties. SPDX retains the same structured record in
package comments. Existing licence declarations, conclusions, file inventories,
occurrence IDs and dependency relationships remain intact. `provenance.json`
records per-package status, association reasons and gaps, plus unassociated files
and identity-only records. The output also contains `notice-evidence.json` and
original notice bytes under `notices/sha256/`; keep them alongside the SBOMs so
relative links resolve. `--notice-evidence` and repository `--repo` preparation
are separate modes.

For CPython executables in a standard installation layout, preparation can recover
the project's explicit `PSF-2.0` declaration from its complete installed license.
All reported executable and shared-library locations must agree on the Python
version, installation prefix, ABI and layer. Unchanged reviewed notice text can
be reused after a version update; changed text stays unresolved. This identifies
the CPython project declaration, while incorporated third-party code retains its
own terms. It does not certify a binary's build source or set a license conclusion.

For occurrences that still lack their own notice candidate, preparation also
checks primary-location files against enclosing `deb` package inventories,
including vendor packages. An exact captured path/layer pair and matching
inventory checksum can link the enclosing package's captured notices as review
context. MD5 and SHA-1 are used only as inventory checksums; the capture retains
its SHA-256 identity. This is unsigned inventory correspondence, not an ownership
attestation or a conclusion about component-specific licence coverage.

The structured `distro_owner_context` records matched locations, checksum claims,
enclosing-package occurrence references and notice hashes. CycloneDX additionally
links those notices as scoped `evidence` references; SPDX retains the context in
package comments. Missing bytes, conflicting inventories, checksum mismatches,
ambiguous matching owners and absent parent notices remain unresolved leads.
Supporting locations cannot substitute for an explicitly identified primary
location. Own-notice status and gaps stay unchanged, and enclosing licence
expressions are not assigned to the child component. `distro_owner_statistics`
reports the contextual links separately.

Binary occurrences lacking their own notice candidate are also checked against
installed Python distributions' RECORD inventories. `python_record_owner_context`
links captured enclosing-distribution notices when a package-local path, layer,
SHA-256 and size match; `python_record_owner_statistics` counts these links
separately. Absolute RECORD paths, aliases and paths outside site-packages are
excluded. Conflicting claims and ambiguous enclosing distributions remain leads.
The verification label `catalogue_sha256_matches_python_record` means the native
catalogue's file measurement matches the RECORD claim; it does not mean preparation
independently read the binary. Retained or explicitly verified image bytes take
precedence when available and retain their respective verification labels.
Enclosing Python notices are review context, including for vendored executables;
their licence declarations are not inherited and own-notice gaps remain unchanged.

When an inventory lead lacks retained primary-file bytes, explicitly enable
transient verification during preparation:

```bash
python3 .github/scripts/prepare_sbom.py \
  --syft /tmp/raptor-sbom/container/syft.json \
  --cyclonedx /tmp/raptor-sbom/container/sbom.cdx.json \
  --spdx /tmp/raptor-sbom/container/sbom.spdx.json \
  --notice-evidence /tmp/raptor-sbom/container/evidence \
  --owner-registry-ref 'registry.example/org/image@sha256:<platform-manifest-digest>' \
  --out /tmp/raptor-sbom/container/verified
```

For air-gapped use, replace `--owner-registry-ref` with
`--owner-oci-layout /path/to/layout`. These options require `--notice-evidence`
and are mutually exclusive. The registry reference must pin the catalogue's exact
platform manifest. Preparation remains offline unless the registry option is
explicitly supplied; catalogue URLs never select network destinations.

Only indexed primary files needed for unresolved inventory checks are read.
Compressed-layer digests and sizes, uncompressed diff IDs, and available native
file SHA-256/size claims must agree. Missing files, unsafe links, conflicting
identity data, unsupported compression and unavailable layers fail before output
creation. Archive files are measured as bytes without unpacking or executing them.

Transient bytes are discarded after checksum comparison and are never added to
the notice bundle. `owner_file_verification` records their SHA-256, size and layer
origin; matched context uses `verified_image_bytes_match_inventory_checksum` to
distinguish these measurements from retained capture bytes. Inventory mismatches
or ambiguous owners stay unresolved. These checks still establish review context,
while component-specific terms and own-notice gaps remain unreviewed.

This process does not fetch corresponding source, infer unknown tool versions,
or publish anything. A file hash identifies bytes; it does not establish a build
source or permission to redistribute them.

---

## Reachability Analysis

SBOM-only scans leave reachability unevaluated unless you supply a
corresponding `--sbom-source-root`. Heuristic non-use and imports remain triage
evidence in VEX, rather than `not_affected` or proof of exploitability.

SCA reachability is mechanical. RAPTOR does not ask an LLM whether a
dependency is reachable; it derives the verdict from source evidence and
advisory metadata. LLM review can still run later in the pipeline
unless `--no-llm` is set, but it is not the source of truth for the
reachability verdict.

Best results come from scanning the full source tree. SBOM-only scans
can still identify vulnerable components, but they usually do not
contain enough source context to prove whether a vulnerable package or
function is used.

For CVE-bearing PyPI dependencies initially marked `not_reachable`, module
resolution can retry using on-demand wheel metadata. This may fetch metadata
on an online scan; results are cached by package/version. Offline scans use
local/cache evidence and do not fetch missing metadata.

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

### Dockerfile npm Pins

`raptor-sca bump` also updates exact `name@major.minor.patch` pins in direct
shell-form `RUN npm install`, `npm i` and `npm add` commands, including scoped
packages, quoted pins and continued commands. It uses the configured npm client
and proposes only strictly newer stable versions identified by the registry's
`latest` tag. It does not install packages or execute Dockerfile commands.

The same supply-chain, vulnerability, exclusion and policy gates apply before
`--apply` rewrites a pin. Changed runtime `engines`, deprecated targets or missing
version metadata require review. Engine requirements are compared with the
current version; SCA does not prove compatibility with every container runtime.

Ranges, prereleases, aliases, JSON-form RUNs, heredocs, custom shells and
unsupported shell syntax are excluded. Commands with registry or user-config
flags, and Dockerfiles that set npm registry configuration or copy `.npmrc`, are
also excluded so SCA does not query a different registry for those pins.

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

To save a separate comparison report while keeping the usual console or
`--json` output, choose a destination explicitly:

```bash
bin/raptor-sca diff before/findings.json after/findings.json \
  --report-format markdown --report-output comparison.md
```

Use `json` or `xml` for structured reports, or repeat `--report-format`
with a directory destination to save several formats. These reports show
category totals and up to 100 rows per category; `--show-persistent` includes
backlog details. Native `--json` retains the complete comparison. Report
failures appear on stderr and leave the regression gate's exit code intact.
With no report destination, the command creates no extra report files.
An item marked resolved is absent from the selected current findings; that
alone does not prove remediation or equivalent scan coverage.

`check` accepts the same explicit report options. For example:

```bash
bin/raptor-sca check npm lodash 4.17.4 \
  --report-format json --report-output package-review.json
```

The report retains the recorded verdict, advisory evidence, name-heuristic
candidates and transitive coverage limits. An unavailable advisory lookup
remains an unavailable verdict, with exit code 2. Report generation performs
no extra registry or advisory queries. It captures up to 100 records per
category with full totals; the native review retains the full list.

`verify` also accepts an explicit report destination, for example
`--report-format json --report-output verification.json`. It reports the
completed overlay comparison, the applied files and whether baseline
findings were reused. No additional scan runs to generate the report.
Unavailable advisory coverage still returns exit code 4; targeted patch
gates and native `delta.md`/`delta.json` outputs retain their existing meaning.

### Pre-Flight: Registries Reachable

```yaml
- run: bin/raptor-sca health
  # exits 1 if any registry is unreachable; useful behind a corporate proxy
```

### Gate Flags

| Flag | Purpose |
|------|---------|
| `--fail-on-severity <level>` | Exit non-zero if any vulnerable-dependency finding meets or exceeds this severity (info / low / medium / high / critical) |
| `--fail-on-incomplete` | Exit 1 on recorded coverage gaps; off by default |
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
| `scan-summary.json` | Completion status, checked/unavailable counts and timings | Operators and CI |
| `advisory-coverage.json` | Positive package-query availability bound to emitted SBOMs and findings | `sbom verify-plan` and CI coverage checks |
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

## Cache Cleanup

Online scans attempt cleanup at completion, at most once every ten minutes
per cache root. `tuning.json` sets `sca_cache_max_mb` (2048 MiB overall) and
`sca_stress_cache_max_mb` (512 MiB within that budget). These are soft limits:
active scans can exceed them. A zero overall budget disables automatic
cleanup; a zero stress budget removes all idle stress checkouts.

Cleanup removes entries older than 30 days and whole stress projects older
than seven days, then reclaims expired/oldest-used data when over budget,
targeting 80% of the limit. Stress projects and sharded inventories are
removed as whole units. Active scans are pinned; fingerprint baselines and
SQLite databases are preserved and excluded from the disposable budget.
Offline scans do not trigger cleanup.

Cleanup rechecks candidate generations before removal. A partially inspected
inventory or stress directory is retained as a whole; reported byte totals
cover inspected units, so errors can leave additional unaccounted data.
Dry-run applies the same eligibility checks. Failed maintenance is retried on
the next online scan; only successful passes refresh the ten-minute throttle.
Unexpected or future-dated throttle markers do not prevent reclamation.

```bash
raptor-sca clean-cache --dry-run
raptor-sca clean-cache --max-size-mb 1024 --stress-max-size-mb 256
```

`--max-age DAYS`, `--stress-max-age DAYS`, and `--cache-root PATH` override
cleanup retention/location. Manual `--max-size-mb 0` disables overall size
pruning while age/stress cleanup still applies. Exit code 1 means cleanup
was busy, encountered deletion errors, or could not meet the requested budget.


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

## Choose a scan

Preview what will run before starting a scan:

```bash
raptor-sca /path/to/project --profile mechanical --explain-plan
raptor-sca /path/to/project --profile fast --out scan
```

The preview prints JSON and runs no analysis, tools or network/model calls.
Use it to check whether a scan can send package information to registries,
send excerpts to an LLM, or incur model costs.

| Profile | Use it when you want… |
| --- | --- |
| `full` | Advisory and supply-chain checks, dependency resolution, image inspection, LLM review and triage |
| `mechanical` | Checks without model calls, while retaining dependency resolution and image inspection |
| `fast` | A quicker check that skips native dependency resolution and image inspection |
| `offline` | Local files and cached advisories, with no network or model calls |

Individual options can further restrict a profile. For example, `fast` never
runs a native resolver, even if other resolution options are present.

## Understand scan results

Read `scan-summary.json` alongside the findings. It shows whether package-query
coverage is complete or partial, how many packages were checked or unavailable,
and why. Parser failures, deliberately excluded checks and stage timings help
explain the result. Unrecoverable analysis errors record `failed` when the
output directory remains writable. Memory figures reflect the process's
lifetime peak and can include other work.

Zero reported vulnerabilities does not mean all packages were checked.
To fail your own CI job when recorded coverage is incomplete, opt in:

```bash
raptor-sca /path/to/project --profile mechanical --fail-on-severity high --fail-on-incomplete
```

Without that option, coverage gaps stay visible without causing a new failure
exit. Container publication keeps its existing warning-only policy. Active CI
checks reject malformed findings rather than silently treating them as clean.

When changing dependencies, choose either `fix PATH` to scan a target or
`fix --findings FILE` to reuse findings. Combining both is rejected so the
intended target cannot be silently ignored.

## Explore inventories offline

Find licence groups, missing declarations and packages without notice evidence:

```bash
raptor-sca sbom stats container-sbom.zip --scope packages
raptor-sca sbom inspect container-sbom.zip --unresolved --format jsonl
raptor-sca sbom inspect release.cdx.json --ecosystem npm --notice-status not_assessed --format csv
raptor-sca sbom inspect release.cdx.json --license MIT --format json --records-only
raptor-sca sbom inspect release.cdx.json --limit 25 --offset 25
```

Statistics keep package records, source candidates and image subjects separate.
GPL versions, exceptions and complete licence expressions remain visible; none
are hidden in “Other”. A package can have several licence operands, so counts
can overlap.

Use CSV, JSONL or `--format json --records-only` for the selected packages.
Ordinary inventory JSON keeps all records and identifies the selection, making
it suitable for later comparisons. `--limit` and `--offset` only change the
text you see; they do not truncate exports. Large exports stream to reduce
memory use.

Statistics, dependency-path explanations and upgrade plans use recorded notice
information. Use `sbom inspect` to check retained notice bytes, or `sbom notices`
to collect the original texts. These inventory operations work offline.
