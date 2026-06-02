---
description: Software Composition Analysis — find vulnerable dependencies, gate CI, fix and pin
---

# RAPTOR Software Composition Analysis

**`--help` / `-h`:** If the user passes only `--help` or `-h`, run `python3 raptor.py sca --help` and present its output. That command is side-effect-free (no run, lifecycle, output directory, or LLM dispatcher) and is the complete, authoritative command/flag list — do NOT start a scan or hand-summarise from this doc.

You are helping the user analyse a project's third-party dependencies for known vulnerabilities, supply-chain red flags, and hygiene issues.

## Your task

1. **Identify the target**: Ask which directory/repository to scan if not specified.

2. **Pick the right sub-command**:
   - **Default — analyse the whole project**: `libexec/raptor-sca-run <target>`
     Walks every manifest+lockfile, queries OSV/KEV/EPSS, runs reachability + supply-chain + hygiene checks, emits `findings.json`, `report.md`, and `sbom.cdx.json`.
   - **Fix vulnerabilities and tighten pins**: `libexec/raptor-sca-run fix <target>`
     Shows a plan (safe default). Use `--apply` to modify manifests in place.
     Use `--cve-only` to fix only CVEs, `--harden` to upgrade all deps to latest safe versions.
   - **Pre-add evaluation of one package**: `libexec/raptor-sca-run check <ecosystem> <name> <version>`
     Quick verdict (Clean / Review / Block) before `npm install` / `pip install`.
   - **Forward-looking upgrade impact**: `libexec/raptor-sca-run upgrade <ecosystem> <name> <from> <to>`
     What an upgrade resolves vs introduces; supports `--candidate` for multi-target tables.
   - **CI / pre-commit gate**: `libexec/raptor-sca-run <target> --skip-review --skip-triage --fail-on-severity high --fail-on-kev`
     Mechanical-only path; exits 0/1 by threshold for build hooks.

3. **Analyse results**:
   - Read `<out>/report.md` for a human-readable severity-sorted view.
   - For tooling, parse `<out>/findings.json` (canonical schema, tagged `sca:vulnerable_dependency` / `sca:hygiene:<kind>` / `sca:supply_chain:<kind>`).
   - For SBOM consumers, read `<out>/sbom.cdx.json` (CycloneDX 1.5 with VEX block).
   - Surface critical and KEV-listed CVEs first; the report orders them that way.

4. **Help apply fixes**:
   - Run `fix` to generate `proposed/` rewrites (or `--apply` for in-place).
   - Show the diff (`git diff proposed/`) so the operator can review before applying.
   - Note which deps got skipped and why (Maven property references, npm git URLs, etc.).

## Example commands

Full analyse:
```bash
libexec/raptor-sca-run /path/to/project
```

Fix plan (safe default — no files modified):
```bash
libexec/raptor-sca-run fix /path/to/project
```

Apply fixes in-place:
```bash
libexec/raptor-sca-run fix /path/to/project --apply
```

Fix CVEs only (don't tighten loose pins):
```bash
libexec/raptor-sca-run fix /path/to/project --apply --cve-only
```

Upgrade all deps to latest safe versions:
```bash
libexec/raptor-sca-run fix /path/to/project --apply --harden
```

Allow major-version bumps (with LLM impact analysis when available):
```bash
libexec/raptor-sca-run fix /path/to/project --apply --allow-major
```

Skip LLM analysis (mechanical-only, fast, CI-safe):
```bash
libexec/raptor-sca-run fix /path/to/project --no-llm
```

CI gate that fails on any KEV-listed CVE or high-severity finding:
```bash
libexec/raptor-sca-run /path/to/project \
    --skip-review --skip-triage \
    --fail-on-severity high --fail-on-kev
```

Pre-add check:
```bash
libexec/raptor-sca-run check npm lodash 4.17.21
libexec/raptor-sca-run check PyPI django 4.2.10
libexec/raptor-sca-run check Maven org.springframework:spring-core 6.1.0
```

Upgrade impact comparison:
```bash
libexec/raptor-sca-run upgrade npm lodash 4.17.4 4.17.21
libexec/raptor-sca-run upgrade npm lodash 4.17.4 \
    --candidate 4.17.10 --candidate 4.17.21 --candidate 4.18.0
```

Offline mode (cache only — useful in CI when egress is restricted):
```bash
libexec/raptor-sca-run /path/to/project --offline
```

## Outputs

| File | Shape | Consumer |
|---|---|---|
| `findings.json` | List of findings (canonical schema) | other RAPTOR tools, CI |
| `report.md` | Severity-sorted markdown | humans |
| `sbom.cdx.json` | CycloneDX 1.5 + VEX | Dependency-Track, CycloneDX CLI |
| `coverage-sca.json` | Files examined | RAPTOR coverage layer |
| `proposed/` (fix --out) | Rewritten manifest files | operator review then `git apply` |
| `changes.json` / `changes.md` (fix) | Per-change record | review |

## Important notes

- Always use absolute paths for the target.
- 10 manifest/lockfile formats supported: `pom.xml`, `build.gradle`, `gradle.lockfile`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`.
- 8 ecosystems queried via OSV: Maven / npm / PyPI / Cargo / Go / RubyGems / NuGet / Packagist.
- KEV (CISA known-exploited) and EPSS (FIRST.org probability) are always checked when network is available; both degrade gracefully on outage.
- Reachability is **module-level** (Python AST + npm import sweep) — flags whether the dep is imported in non-test code, not whether the vulnerable function is called.
- All optional dependencies (`defusedxml`, `packaging`, `tomli` on 3.10-, `PyYAML`) degrade gracefully — missing one only narrows ecosystem coverage.
- **LLM auto-detection:** When an LLM provider is configured, `fix --allow-major` automatically analyses major-version-bump CVEs against your project's actual call sites. Safe bumps are included; breaking changes show migration guidance. Use `--no-llm` to force mechanical-only mode.

## Exit codes

- Analyse / sub-commands: 0 success, 2 invalid args, 3 internal error.
- Scan with `--fail-on-severity` / `--fail-on-kev`: 0 below threshold, 1 above threshold (build-fail).
- Check: 0 clean, 1 review-needed, 2 block.
- Upgrade: 0 net-positive trade, 1 mixed/regression.
- Fix: 0 success, 1 major-version bumps blocked (review needed), 2 invalid args, 3 internal error.
