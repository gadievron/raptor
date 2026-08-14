# Dependencies

RAPTOR does not bundle external binaries or libraries. Users install them
separately according to each tool's licence terms. A devcontainer is available
for those who prefer a batteries-included environment.

See also: [README](README.md), [architecture](architecture.md).


## Python

Python **3.10+** is required. RAPTOR uses PEP 604 union syntax (`X | Y`) at
function-definition time, which is a syntax error on 3.9 and earlier.


## Core Tools

| Tool | Required | Purpose | Install |
|------|----------|---------|---------|
| Semgrep | Yes | Static analysis scanning | `pip install semgrep` |
| Coccinelle (spatch) | No | Semantic patch analysis | `apt install coccinelle` (>=1.3) |
| CodeQL | No | Deep dataflow analysis | [codeql-cli-binaries](https://github.com/github/codeql-cli-binaries) |
| Joern | No | CPG dataflow queries (`/audit`, tiered taint sweeps) | [joern.io](https://joern.io) — **v4.0.458 or newer** (first 2026 release; needs a JVM) |
| AFL++ | No | Coverage-guided binary fuzzing | `apt install afl++` or `brew install afl++` |
| GDB | No | Crash analysis (Linux) | `apt install gdb` (pre-installed on most distros) |
| LLDB | No | Crash analysis (macOS) | Pre-installed with Xcode CLT |
| rr | No | Deterministic record-replay debugging | `apt install rr` (Linux x86_64 only) |
| radare2 (r2) | No | Binary disassembly, call-graph extraction | [radare2.org](https://rada.re/n/) |
| Frida | No | Dynamic instrumentation | `pip install frida-tools` |
| nm, objdump, readelf | No | Binary analysis (binutils) | Pre-installed on most systems |
| gcov | No | Code coverage (part of GCC) | Bundled with `gcc` |
| AddressSanitizer | No | Memory error detection | Built into gcc>=4.8 and clang>=3.1 |
| BigQuery CLI | No | GitHub Archive forensic queries (`/oss-forensics`) | Requires `GOOGLE_APPLICATION_CREDENTIALS` |


## Python Packages

Pinned versions are in `requirements.txt`. Install with
`pip install -r requirements.txt`.

**Required (core):**

| Package | Licence | Purpose |
|---------|---------|---------|
| requests | Apache 2.0 | HTTP client |
| urllib3 | MIT | Connection pooling, proxy handling |
| pydantic | MIT | Data validation and settings |
| typer | MIT | CLI framework for libexec scripts |
| instructor | MIT | Structured LLM output |
| pyyaml | MIT | YAML parsing (CodeQL pack trust, k8s manifests) |
| defusedxml | PSF | Safe XML parsing (Maven POM) |
| packaging | Apache 2.0 / BSD | PEP 440 version parsing (SCA) |
| tabulate | MIT | Table formatting |

**Optional (install when needed):**

| Package | Licence | Purpose |
|---------|---------|---------|
| anthropic | MIT | Anthropic Claude SDK |
| openai | MIT | OpenAI SDK (also used for Ollama and compatible endpoints) |
| google-genai | Apache 2.0 | Google Gemini native SDK |
| botocore | Apache 2.0 | AWS Bedrock SigV4 signing (parent-only, not needed for bearer-token auth) |
| beautifulsoup4 | MIT | HTML parsing (web scanning) |
| orjson | Apache 2.0 / MIT | Faster JSON parse and serialise (transparent fallback to stdlib `json`) |
| pwntools | MIT | Binary exploit analysis (ELF parsing, gadget search) — used if present, not in requirements.txt |
| r2pipe | LGPL v3 | Python bridge for radare2 |
| atheris | Apache 2.0 | Coverage-guided Python fuzzing engine |
| z3-solver | MIT | SMT-based constraint analysis (one-gadget feasibility, path validation) |
| tree-sitter + grammars | MIT | Rich inventory metadata (decorators, typed params) |
| sage-agent-sdk | -- | SAGE persistent memory |
| tomli | MIT | TOML reader on Python <3.11 (stdlib `tomllib` from 3.11+) |


## Licensing

RAPTOR itself is MIT-licensed. External tools are used as command-line programs
and are not linked as libraries. Users should review each tool's licence for
their use case:

- **Semgrep**: LGPL 2.1
- **CodeQL**: GitHub CodeQL Terms (free for security research; restrictions on commercial use)
- **AFL++**: Apache 2.0
- **GDB / binutils**: GPL v3 (called as external processes, not linked)
- **radare2**: LGPL v3
- **rr**: MIT
- **Z3**: MIT

Python packages carry their own licences (see the table above). All core
dependencies are MIT or Apache 2.0.

## Proxied hosts

RAPTOR is proxy-aware end to end on hosts behind a mandatory egress
proxy: set the conventional `https_proxy` / `http_proxy` (or
`all_proxy`) and `no_proxy` variables before launching. The sandbox
egress chokepoint chains upstream through them, JVM children get
matching `java.net` sysprops injected, `core.http` clients honour them,
and loopback sidecars (SAGE, Ollama, Joern) are exempted automatically.

Operator-side installs of external tools (joern, AFL++, frida-server,
jadx) happen outside RAPTOR — export the same proxy variables in the
installing shell. Note that JVM-based installers (e.g. coursier for
joern) ignore proxy env vars and need
`JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=<host> -Dhttps.proxyPort=<port>"`.
