# Python CLI

`raptor.py` is the direct entry point for CI pipelines, scripting, and
non-interactive use. For interactive analysis via Claude Code, launch with
`bin/raptor` instead.

See also: [commands](commands.md), [README](README.md),
[dependencies](dependencies.md).


## Usage

```
python3 raptor.py <mode> [flags]
```

Run `python3 raptor.py --help` for the mode list, or
`python3 raptor.py <mode> --help` for mode-specific flags.


## Modes

| Mode | Purpose |
|------|---------|
| `scan` | Static analysis with Semgrep |
| `sca` | Software Composition Analysis (dependencies, advisories, SBOM) |
| `binary` | Black-box binary investigation and evidence collection |
| `fuzz` | Binary fuzzing with AFL++ |
| `web` | Web application security testing |
| `agentic` | Full autonomous workflow (Semgrep + CodeQL + LLM analysis) |
| `codeql` | CodeQL-only deep analysis |
| `analyze` | LLM-powered analysis of existing SARIF files |
| `describe` | Pre-flight inspection: target type, tool readiness, cost estimate |
| `doctor` | Status report for local setup (no Claude needed) |
| `frida` | Dynamic instrumentation via Frida (alpha) |


## Global Flags

These sandbox flags apply to every mode. Pass them **after** the mode name:

```
--sandbox {full,debug,network-only,none}   Force a sandbox profile (default: full)
--no-sandbox                               Alias for --sandbox none
--audit                                    Log what enforcement would have blocked
--audit-verbose                            With --audit, log every traced syscall
--trust-repo                               Mark the target repo as trusted
--version                                  Show RAPTOR version and exit
```


## Examples

```bash
# Full autonomous workflow
python3 raptor.py agentic --repo /path/to/code

# Static analysis only
python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

# Agentic with pre-mapping and post-validation
python3 raptor.py agentic --repo /path/to/code --understand --validate

# Binary fuzzing (1 hour, 4 parallel instances)
python3 raptor.py fuzz --binary /path/to/binary --duration 3600 --parallel 4

# Export starter corpus then fuzz with it
python3 raptor.py fuzz --export-seed-corpus /tmp/seeds
python3 raptor.py fuzz --binary /path/to/binary --corpus /tmp/seeds

# Web scanning
python3 raptor.py web --url https://example.com

# CodeQL analysis
python3 raptor.py codeql --repo /path/to/code --languages java

# Analyse existing SARIF
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif --max-findings 10

# Black-box binary investigation
python3 raptor.py binary investigate /path/to/binary

# SCA dependency scan
python3 raptor.py sca --repo /path/to/code

# Pre-flight target description
python3 raptor.py describe --repo /path/to/code

# Check local tool setup
python3 raptor.py doctor

# Dynamic instrumentation
python3 raptor.py frida --target /path/to/binary

# CI pipeline (fast mode, no exploits, non-zero exit on critical findings)
python3 raptor.py agentic \
  --repo . \
  --policy-groups owasp,secrets \
  --max-findings 5 \
  --mode fast \
  --no-exploits
```


## Environment Variables

```bash
# LLM provider (at least one recommended for analysis modes)
export ANTHROPIC_API_KEY="sk-ant-..."   # Recommended
export OPENAI_API_KEY="sk-..."          # Alternative
export GEMINI_API_KEY="..."             # Google Gemini
export MISTRAL_API_KEY="..."            # Mistral

# AWS Bedrock (SigV4 auth)
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="eu-west-1"

# AWS Bedrock (bearer token auth)
export AWS_BEARER_TOKEN_BEDROCK="..."

# Optional overrides
export RAPTOR_ROOT="/path/to/raptor"
export RAPTOR_OUT_DIR="/custom/output/path"
export RAPTOR_CALLER_DIR="/original/cwd"
```



## Exit Codes

Exit code **0** means the pipeline completed successfully — it does **not**
mean no findings were produced. Exit code **1** indicates an error (missing
tools, invalid arguments, subprocess failure). Exit code **130** signals
SIGINT (Ctrl-C).

To gate CI on finding severity, use SCA's threshold flags:

```bash
python3 raptor.py sca --repo . --fail-on-severity high --fail-on-kev
```

For other modes, parse the output files (`findings.json`, SARIF) rather than
relying on the exit code.
## Output

All results are written to `out/` (or the active project directory). The
structure varies by mode; see [architecture](architecture.md) for details.
