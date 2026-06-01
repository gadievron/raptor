# RAPTOR CodeQL Package

Fully autonomous CodeQL security analysis with intelligent language detection, build system auto-detection, database caching, and SARIF output.

## Features

✅ **Phase 1 Complete - Foundation**

- ✅ Autonomous language detection (10 languages supported)
- ✅ Intelligent build system detection and command generation
- ✅ SHA256-based database caching (reuse databases for unchanged repos)
- ✅ Parallel database creation for multi-language repositories
- ✅ Official CodeQL security suite execution
- ✅ SARIF output for unified vulnerability processing
- ✅ Comprehensive workflow orchestration
- ✅ Integration with RAPTOR core configuration

## Architecture

```
packages/codeql/
├── agent.py                  # Main orchestrator (CLI entry point)
├── language_detector.py      # Auto-detect languages in repos
├── build_detector.py         # Auto-detect build systems & generate commands
├── database_manager.py       # Database lifecycle management with caching
├── query_runner.py           # CodeQL suite execution & SARIF generation
└── __init__.py              # Package exports

codeql_dbs/                   # Database cache directory (gitignored)
└── <repo_hash>/
    ├── java-db/
    ├── python-db/
    └── *-metadata.json

engine/codeql/
└── suites/                   # Custom query suites (optional)
```

## Quick Start

### Fully Autonomous (Zero Configuration)

```bash
# Auto-detect everything and run analysis
python3 packages/codeql/agent.py --repo /path/to/code
```

**What happens:**
1. ✅ Auto-detects languages (Java, Python, JavaScript, etc.)
2. ✅ Auto-detects build systems (Maven, Gradle, npm, etc.)
3. ✅ Generates build commands automatically
4. ✅ Creates CodeQL databases (cached for reuse)
5. ✅ Runs security-and-quality suites
6. ✅ Generates SARIF output
7. ✅ Creates comprehensive JSON report

### Specify Languages

```bash
# Analyze specific languages
python3 packages/codeql/agent.py --repo /path/to/code --languages java,python
```

### Custom Build Command

```bash
# Your example from earlier
export CODEQL_CLI=/Users/daniel/reverse_engineering/codeql/codeql

python3 packages/codeql/agent.py \
  --repo /Users/daniel/O365/CSR/Code/CodeQL-Crypto-Research/GHUniverse/acme-access-main \
  --languages java \
  --build-command "mvn clean compile -DskipTests"
```

### Extended Security Analysis

```bash
# Use security-extended suites (more comprehensive)
python3 packages/codeql/agent.py --repo /path/to/code --extended
```

### Force Database Recreation

```bash
# Ignore cached databases and recreate
python3 packages/codeql/agent.py --repo /path/to/code --force
```

## Supported Languages

| Language | Build Systems | CodeQL Suite |
|----------|--------------|--------------|
| **Java** | Maven, Gradle, Ant | `java-security-and-quality.qls` |
| **Python** | pip, Poetry, setuptools | `python-security-and-quality.qls` |
| **JavaScript** | npm, Yarn, pnpm | `javascript-security-and-quality.qls` |
| **TypeScript** | npm, Yarn | `javascript-security-and-quality.qls` |
| **Go** | go modules | `go-security-and-quality.qls` |
| **C/C++** | CMake, Make, Autotools, Meson | `cpp-security-and-quality.qls` |
| **C#** | dotnet, MSBuild | `csharp-security-and-quality.qls` |
| **Ruby** | Bundler, Rake | `ruby-security-and-quality.qls` |
| **Swift** | Swift Package Manager | `swift-security-and-quality.qls` |
| **Kotlin** | Gradle | `java-security-and-quality.qls` |

## Configuration

### Environment Variables

```bash
# CodeQL CLI path (auto-detected from PATH if not set)
export CODEQL_CLI=/path/to/codeql

# CodeQL queries directory (optional, uses official queries if not set)
export CODEQL_QUERIES=/path/to/codeql-queries

# RAPTOR output directory (optional)
export RAPTOR_OUT_DIR=/custom/output/dir
```

### RaptorConfig Settings

CodeQL resource settings live in **`tuning.json`** at the repo root (the
single source of truth, resolved by `core.tuning.get_tuning()`).
`RaptorConfig` exposes them as classproperties for code that wants the
resolved integers directly; new CodeQL invocations should use
`packages.codeql.CodeQLTunables.from_tuning()` instead so the flag set
stays consistent across consumers.

`tuning.json` keys:

```jsonc
{
  "codeql_ram_mb":  "auto",   // -M MB; "auto" = 25% of system RAM clamped [2048, 16384]
  "codeql_threads": "auto",   // -j N;  "auto" = 0 = all CPUs (override the codeql default of 1)
  "max_codeql_workers": 2     // parallel codeql operations in same process
}
```

Adding a new CodeQL invocation:

```python
from packages.codeql import CodeQLTunables

cmd = [codeql, "database", "analyze", db, query, "--format=sarif-latest", f"--output={sarif}"]
CodeQLTunables.from_tuning().append_to(cmd, include_disk_cache=False)
```

For `database create`, pass `include_disk_cache=True` (the `--max-disk-cache`
flag is only valid there).  See `packages/codeql/tunables.py` for the
full surface; the trust-witness corpus walker (`core.dataflow.cvefix_walk`)
is a worked operator example with CLI overrides for `--threads`/`--ram`/
`--max-disk-cache`.

Non-tuning settings still live in `core/config.py`:

```python
CODEQL_DB_DIR        = REPO_ROOT / "codeql_dbs"
CODEQL_TIMEOUT       = 1800   # 30 minutes (database creation)
CODEQL_ANALYZE_TIMEOUT = 2400 # 40 minutes (query execution)
CODEQL_MAX_PATHS     = 4      # Max dataflow paths per query
CODEQL_DB_CACHE_DAYS = 7      # Keep databases for 7 days
CODEQL_DB_AUTO_CLEANUP = True # Auto-cleanup old databases
```

## Output Structure

```
out/codeql_<repo>_<timestamp>/
├── codeql_java.sarif              # SARIF output per language
├── codeql_python.sarif
├── codeql_javascript.sarif
└── codeql_report.json             # Comprehensive workflow report
    ├── languages_detected
    ├── databases_created
    ├── analyses_completed
    ├── total_findings
    └── sarif_files

codeql_dbs/
└── <repo_hash>/                   # Cached databases (reusable)
    ├── java-db/
    ├── java-metadata.json
    ├── python-db/
    └── python-metadata.json
```

## Language Detection

**Confidence-based detection:**

- ✅ File extensions (`.java`, `.py`, `.js`, etc.)
- ✅ Build files (`pom.xml`, `package.json`, `go.mod`, etc.)
- ✅ Structural indicators (`src/main/java/`, `__init__.py`, etc.)
- ✅ File count ratios
- ✅ Minimum file threshold (default: 3 files)

**Test language detection:**

```bash
python3 packages/codeql/language_detector.py --repo /path/to/code --json
```

## Build System Detection

**Auto-detected build systems:**

- **Java**: Maven (`mvn clean compile`), Gradle (`./gradlew build -x test`), Ant
- **Python**: Poetry, pip, setuptools
- **JavaScript/TypeScript**: npm, Yarn, pnpm
- **Go**: go modules (`go build ./...`)
- **C/C++**: CMake, Make, Autotools, Meson
- **C#**: dotnet, MSBuild
- **Ruby**: Bundler, Rake

**Fallback**: No-build mode for interpreted languages

**Test build detection:**

```bash
python3 packages/codeql/build_detector.py --repo /path/to/code --language java --json
```

## Database Caching

Databases are cached using SHA256 hashing:

1. **Git repos**: Uses git commit hash (fast)
2. **Non-git**: Hashes directory structure and modification times

**Cache hit**: Database reused instantly (< 1 second)
**Cache miss**: Database created (5-30 minutes depending on repo size)

**Manual cache management:**

```bash
# View cache
ls -lh codeql_dbs/

# Clear cache
rm -rf codeql_dbs/

# Cleanup old databases (7+ days)
python3 packages/codeql/database_manager.py --cleanup 7
```

## Integration with RAPTOR

The CodeQL package integrates seamlessly with RAPTOR's existing workflow:

### Option 1: Standalone Usage

```bash
# Use CodeQL package independently
python3 packages/codeql/agent.py --repo /path/to/code
```

### Option 2: Integrated Workflow (Coming in Phase 2)

```bash
# Run full RAPTOR pipeline with CodeQL
python3 raptor_agentic.py \
  --repo /path/to/code \
  --policy-groups crypto,injection \
  --codeql \
  --autonomous-depth deep
```

**Workflow:**
1. Semgrep static analysis
2. CodeQL static analysis (parallel)
3. SARIF merging and deduplication
4. LLM-powered vulnerability analysis (Phase 2)
5. Dataflow validation (Phase 2)
6. Exploit generation (Phase 2)

## Performance

**Database Creation:**
- Small repo (< 1K files): 2-5 minutes
- Medium repo (1K-10K files): 5-15 minutes
- Large repo (10K+ files): 15-30 minutes

**Query Execution:**
- Security suite: 2-10 minutes per language
- Extended suite: 5-20 minutes per language

**Caching Benefits:**
- Repeat analysis: < 1 second (database reuse)
- Incremental changes: Full re-creation (incremental coming in future)

## Troubleshooting

### CodeQL not found

```bash
# Set explicit path
export CODEQL_CLI=/path/to/codeql

# Or use --codeql-cli flag
python3 packages/codeql/agent.py --repo /path/to/code --codeql-cli /path/to/codeql
```

### Build failures

```bash
# Use custom build command
python3 packages/codeql/agent.py \
  --repo /path/to/code \
  --languages java \
  --build-command "mvn clean install -DskipTests"

# Or use no-build mode (limited analysis)
# The system will automatically fallback to no-build if detection fails
```

### Database creation timeout

```python
# Increase timeout in core/config.py
CODEQL_TIMEOUT = 3600  # 60 minutes
```

### Out of memory

Edit `tuning.json` at the repo root (or run `/tune balanced` to do it):

```jsonc
{
  "codeql_ram_mb": 4096   // 4GB instead of "auto"
}
```

`CodeQLTunables.from_tuning()` picks this up immediately on the next run.

## Next Steps (Phase 2)

Phase 2 will add autonomous vulnerability analysis:

- 🔄 Dataflow validation with LLM analysis
- 🔄 Autonomous vulnerability analysis (multi-turn dialogue)
- 🔄 PoC exploit generation for CodeQL findings
- 🔄 Exploit compilation and validation
- 🔄 Integration with existing autonomous system
- 🔄 MCP agent integration for deep analysis

## Examples

### Example 1: Java Maven Project

```bash
python3 packages/codeql/agent.py \
  --repo /Users/daniel/O365/CSR/Code/CodeQL-Crypto-Research/GHUniverse/acme-access-main

# Output:
# ✓ Detected java (confidence: 0.92)
# ✓ Detected Maven build system
# ✓ Created database (5.2 minutes)
# ✓ Analysis completed: 12 findings
# SARIF: out/codeql_acme-access-main_20250114_123456/codeql_java.sarif
```

### Example 2: Multi-Language Repo

```bash
python3 packages/codeql/agent.py --repo /path/to/fullstack-app

# Output:
# ✓ Detected python (confidence: 0.85)
# ✓ Detected javascript (confidence: 0.78)
# ✓ Detected java (confidence: 0.91)
# ✓ Created 3 databases in parallel
# ✓ Analysis completed: 47 findings total
#   - java: 23 findings
#   - python: 15 findings
#   - javascript: 9 findings
```

### Example 3: Cached Repeat Analysis

```bash
# First run
python3 packages/codeql/agent.py --repo /path/to/code
# Database created: 8.3 minutes

# Second run (cache hit)
python3 packages/codeql/agent.py --repo /path/to/code
# ✓ Using cached database for java (0.2 seconds)
# Total time: 2.1 minutes (just query execution)
```

## Contributing

Phase 1 is complete. Future enhancements:

- Incremental database updates
- Custom query pack support
- Dataflow visualization
- Framework-specific analysis (Spring, Django, Express)
- CI/CD integration helpers

## License

Part of the RAPTOR autonomous security testing framework.
