# Calibration corpus — sources + attribution

This directory contains ground-truth signals + project samples used to
validate the risk-score weights in `packages/sca/risk.py`.

Each JSON file carries an inline `_source` block with its own license
and provenance. This file is the cross-reference that satisfies
attribution requirements for sources where the data license requires it.

## Sources

### `kev_signals.json` — CISA Known Exploited Vulnerabilities

- **License:** Public Domain (US Government work)
- **Source:** <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- **Feed:** <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- **Maintainer:** Cybersecurity and Infrastructure Security Agency (CISA), USA
- **Use:** Embedded verbatim. Public Domain — no attribution requirement,
  but cited for transparency.

### `epss_signals.json` — Exploit Prediction Scoring System

- **License:** Free for any use (FIRST.org)
- **Source:** <https://www.first.org/epss/>
- **API:** <https://api.first.org/data/v1/epss>
- **Maintainer:** Forum of Incident Response and Security Teams (FIRST.org)
- **Use:** Embedded subset (CVEs with EPSS ≥ 0.05).

### `exploitdb_signals.json` — Exploit-DB index

- **License:** Exploit-DB content is research/personal-use only.
  We embed **only** boolean signals + entry-ID references (public
  observable facts that an exploit exists for a given CVE).
- **Source:** <https://gitlab.com/exploit-database/exploitdb>
- **Index file:** `files_exploits.csv` from upstream main branch.
- **What's stored:** `{cve_id: {has_exploitdb_entry: true, edb_ids: [N, ...]}}`.
- **What's NEVER stored:** exploit bodies, payloads, shellcode, or
  any exploit content. The license-compliance check
  (`packages/sca/calibration/_license_check.py`) rejects any file
  containing forbidden field names (`body`, `payload`, `shellcode`,
  `exploit_code`, `poc_code`).

### `metasploit_signals.json` — Metasploit Framework module metadata

- **License:** Metasploit Framework is BSD-3-Clause. We could
  redistribute it freely but choose not to: the corpus only needs
  the FACT that a module exists per CVE. Storing module-path
  references + booleans is sufficient for calibration without
  vendoring the framework.
- **Source:** <https://github.com/rapid7/metasploit-framework>
- **Index file:** `db/modules_metadata_base.json` from upstream
  master branch.
- **What's stored:** `{cve_id: {has_msf_module: true, module_paths: ["exploits/...", ...]}}`.
- **What's NEVER stored:** Metasploit Framework code (modules,
  payloads, evasion, post-exploitation, etc.). Same forbidden-
  field-check applies.

### `github_poc_signals.json` — GitHub PoC URLs (derived)

- **License:** Derived signal — presence + public URL only. The URL
  itself is a public observable fact (the existence of a repo on
  github.com is not copyrightable). PoC repository content is **not**
  fetched or stored.
- **Source:** Re-parses the Exploit-DB index (`files_exploits.csv`)
  for ``source_url`` / ``application_url`` columns matching
  ``github.com/...`` patterns. Same network fetch as the EDB build.
- **What's stored:** `{cve_id: {has_github_poc: true, github_poc_urls: ["https://github.com/...", ...]}}`.
- **What's NEVER stored:** PoC repository code (clone targets, README
  content, exploit scripts). Operators inspecting the URL can clone
  if they want; the corpus stores only the public observable that
  the URL exists.

### `osv_evidence_signals.json` — OSV EVIDENCE references (filtered)

- **License:** Derived signal — presence + public URL only. OSV's
  data is CC-BY-4.0; we cite + don't redistribute its advisory
  bodies. URLs in the signal are public observable facts. Linked
  exploit content is **not** fetched or stored.
- **Source:** OSV `/v1/vulns/{id}` for every CVE present in
  `project_samples/` findings. We extract `references[]` entries
  where `type == "EVIDENCE"`.
- **Filter:** EVIDENCE refs whose host is in an explicit
  exploit-publication allowlist (exploit-db, packetstormsecurity,
  0day.today, huntr.dev, gist.github.com, seclists.org). Advisory-
  only hosts (snyk.io, hackerone.com, vendor blogs, mailing lists)
  are EXCLUDED — their presence indicates public knowledge of a
  vulnerability, not public availability of an exploit. The first
  unfiltered iteration of this signal collapsed Spearman ρ on the
  corpus by labelling 553 findings as `exploited` based on
  knowledge presence rather than exploit availability.
- **Scope:** corpus-only. OSV exposes no CVE-listing endpoint, so
  the queryable universe is bounded by what scans actually surface.
- **What's stored:** `{cve_id: {has_osv_evidence: true, evidence_urls: ["https://exploit-db.com/...", ...]}}`.
- **What's NEVER stored:** referenced exploit content. Operators
  inspecting the URL can navigate manually.

### `vulnrichment_signals.json` — CISA Vulnrichment (SSVC)

- **License:** CC0 1.0 Universal (Public Domain Dedication)
- **Source:** <https://github.com/cisagov/vulnrichment>
- **Tarball:** `https://codeload.github.com/cisagov/vulnrichment/tar.gz/refs/heads/develop`
  (`develop` is the repo's default branch — CISA does not publish to `main`)
- **Maintainer:** Cybersecurity and Infrastructure Security Agency (CISA), USA
- **What's stored:** `{cve_id: {ssvc_exploitation, ssvc_automatable, ssvc_technical_impact}}`
  for entries whose SSVC `Exploitation` is `poc` or `active`. `none`
  entries carry no exploit signal and are dropped.
- **Use:** Cross-ecosystem exploitation signal — covers Cargo / NuGet /
  Packagist, where the other five sources return ~0%. CC0 — no
  attribution requirement, cited for transparency.

### `stress_baseline.json` — SCA stress-test regression baseline

- **License:** MIT (RAPTOR-generated). Per-sample scan diagnostics
  (deps_analysed / vuln_findings / eco_breakdown /
  elapsed_seconds_p50) — no third-party content.
- **Source:** `packages.sca.calibration.stress.write_baseline` —
  re-generated locally by operators running
  `raptor-sca-stress --update-baseline` after intentional changes
  to the samples list, parser logic, or scoring formula.
- **What's stored:** ``{project_name: {ecosystem, deps_analysed,
  vuln_findings, eco_breakdown: {eco: n}, elapsed_seconds_p50}}``.
- **Captured commit:** the `_source.captured_with_commit` short
  SHA pins the baseline to a specific code state so reviewers
  can correlate regressions to changes between then and now.

### Tier 2 — future additions

- **GitHub Advisory Database (GHSA) refs** — already covered indirectly
  via OSV's GHSA mirror. A separate fetcher would be redundant.

## RAPTOR-generated artefacts

`project_samples/` contains scan outputs RAPTOR generated by running
`bin/raptor-sca` against public OSS projects. The scan output is
RAPTOR-generated and ships under RAPTOR's MIT license. The projects
themselves are NOT redistributed — only the scan findings (with
file paths under the discarded clone tree stripped before storage).

Populated by `packages/sca/scripts/raptor-sca-collect-samples`. The curated
project list lives in
`packages/sca/calibration/project_samples.py::PROJECT_SAMPLES`;
each entry pins a git ref so re-runs are reproducible. License-
filtering at collection time (`--only-licenses`) restricts the
scan-touch to OSI-permissive projects when operators want to
constrain the license footprint.

`validation/<date>.json` files (created on demand by
`packages/sca/scripts/raptor-sca-validate-corpus`) carry top-N precision +
Spearman correlation metrics computed against the
ground-truth signals. These are RAPTOR-generated and ship under
MIT. Each report cites the snapshot date of every ground-truth
source consulted, so reviewers can reproduce metrics.

`refit/<date>.json` files (created by `raptor-sca-refit-calibration`)
carry the per-constant risk-multiplier deltas + joint-precision
metrics from a refit run. Also RAPTOR-generated, MIT — no third-party
content.

Both `validation/` and `refit/` are first-party generated reports, so
they carry no `_source` block and are exempt from the per-file
attribution check below.

## Updates

Refreshed weekly by `.github/workflows/refresh-sca-calibration.yml`
(Tuesday 06:00 UTC). The workflow opens an auto-PR when sources have
shifted; reviewers approve before merge.

## Pre-commit license check

`packages/sca/calibration/_license_check.py` runs as a pre-commit
hook on changes under `packages/sca/data/calibration/`. It enforces:

  1. Every JSON file has an inline `_source.license` field
  2. Tier 2 sources (Exploit-DB / Metasploit) appear only as
     `has_*` booleans + `url` references — no `body` / `payload` /
     `shellcode` fields
  3. New sources require an entry here in `ATTRIBUTION.md`

First-party generated report subtrees (`refit/`, `validation/`) are
exempt — they are RAPTOR outputs, not attributed third-party sources.

Defence in depth against accidental ingestion of license-restricted
content.
