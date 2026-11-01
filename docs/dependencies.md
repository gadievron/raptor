# Dependencies

A source checkout uses separately installed tools and Python packages, each
under its own licence. The devcontainer includes preinstalled tools and
dependencies; CodeQL is installed on first use. See the
[third-party notices](../THIRD_PARTY_NOTICES.md) for bundled source/data and
[CodeQL setup](codeql.md) for installation and offline provisioning.

See also: [README](../README.md), [architecture](architecture.md).


## Python

Python **3.12+** is required. The sandbox layer hard-requires
`os.unshare` (added in 3.12), and runtime modules use `typing.Self`
(3.11+) and PEP 604 union syntax (`X | Y`) at function-definition time —
the suite fails at import/setup on 3.11 and earlier.


## Core Tools

| Tool | Required | Purpose | Install |
|------|----------|---------|---------|
| Semgrep | Yes | Static analysis scanning | `uv tool install semgrep` |
| Coccinelle (spatch) | No | Semantic patch analysis | `apt install coccinelle` (>=1.3) |
| CodeQL | No | Deep dataflow analysis | [codeql-cli-binaries](https://github.com/github/codeql-cli-binaries) |
| Joern | No | CPG dataflow queries (`/audit`, tiered taint sweeps) | [joern.io](https://joern.io) — **v4.0.458 or newer** (first 2026 release; needs a JVM) |
| AFL++ | No | Coverage-guided binary fuzzing | `apt install afl++` or `brew install afl++` |
| GDB | No | Crash analysis (Linux) | `apt install gdb` (pre-installed on most distros) |
| LLDB | No | Crash analysis (macOS) | Pre-installed with Xcode CLT |
| rr | No | Deterministic record-replay debugging | `apt install rr` (Linux x86_64 only) |
| radare2 (r2) | No | Binary disassembly, call-graph extraction | [radare2.org](https://rada.re/n/) |
| Frida | No | Dynamic instrumentation | `uv tool install frida-tools` |
| nm, objdump, readelf | No | Binary analysis (binutils) | Pre-installed on most systems |
| gcov | No | Code coverage (part of GCC) | Bundled with `gcc` |
| AddressSanitizer | No | Memory error detection | Built into gcc>=4.8 and clang>=3.1 |
| BigQuery CLI | No | GitHub Archive forensic queries (`/oss-forensics`) | Requires `GOOGLE_APPLICATION_CREDENTIALS` |


## Python Packages

Install with `uv sync --locked`.

**Required (core):**

| Package | Licence | Purpose |
|---------|---------|---------|
| requests | Apache 2.0 | HTTP client |
| urllib3 | MIT | Connection pooling, proxy handling |
| pydantic | MIT | Data validation and settings |
| typer | MIT | CLI framework for libexec scripts |
| instructor | MIT | Structured LLM output |
| openai | Apache 2.0 | OpenAI SDK — also used for Ollama; hard-required by instructor |
| pyyaml | MIT | YAML parsing (CodeQL pack trust, k8s manifests) |
| defusedxml | PSF | Safe XML parsing (Maven POM) |
| packaging | Apache 2.0 / BSD | PEP 440 version parsing (SCA) |
| tabulate | MIT | Table formatting |
| pyelftools | Public domain | ELF metadata fallback when angr is absent |

**Optional (install when needed):**

| Package | Licence | Purpose |
|---------|---------|---------|
| anthropic | MIT | Anthropic Claude SDK |
| google-genai | Apache 2.0 | Google Gemini native SDK |
| botocore | Apache 2.0 | AWS Bedrock SigV4 signing (parent-only, not needed for bearer-token auth) |
| beautifulsoup4 | MIT | HTML parsing (web scanning) |
| orjson | MPL-2.0 AND (Apache-2.0 OR MIT) | Faster JSON parse and serialise (transparent fallback to stdlib `json`) |
| cvss | LGPL-3.0-or-later | Optional CVSS v4 scoring for SCA (`[cvss]` extra) |
| pwntools | MIT | Binary exploit analysis (ELF parsing, gadget search) — used if present, not in pyproject.toml |
| r2pipe | MIT | Python bridge for radare2 (binary disassembly, call-graph extraction, `--binary-edges`) |
| pyghidra | Apache 2.0 | Ghidra bridge — in-process analysis via pyghidra's sandboxed JVM worker |
| frida | wxWindows | Dynamic instrumentation (Frida validation bridge, coverage bridge) |
| jsonschema | MIT | SARIF full-schema validation and orchestrated-report contract checking |
| atheris | Apache 2.0 | Coverage-guided Python fuzzing engine — used if present, not in pyproject.toml |
| playwright | Apache 2.0 | Browser automation for web scanning (`[web]` optional extra) |
| z3-solver | MIT | SMT-based constraint analysis (one-gadget feasibility, path validation) |
| angr | BSD-2-Clause; transitive PyVEX includes GPL-2.0-only VEX | Binary symbolic execution (overflow witnesses, path constraints) — Python >=3.12; conflicts with standalone z3 pin |
| tree-sitter + grammars | MIT | Rich inventory metadata (decorators, typed params); audit mechanical witnesses (C and Go parsing) — absent grammars degrade to no-witness, never to a wrong verdict |
| sage-agent-sdk | Apache-2.0 | SAGE persistent memory (see [sage.md](sage.md)) |
| httpx | BSD | HTTP client used by the SAGE SDK (installed alongside it) |
| h2 | MIT | HTTP/2 for pooled LLM transports (opt-in via `RAPTOR_HTTP2=1`; see [llm.md](llm.md)) |


## Licensing

RAPTOR's original code is MIT-licensed. Standalone tools, Python libraries,
and their native dependencies retain their own terms. Invoking a tool as
a separate process does not remove obligations when redistributing that tool
in a container or other bundle.

- **Semgrep**: LGPL 2.1
- **CodeQL**: [GitHub CodeQL Terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md); permitted use depends on the codebase and any applicable GitHub agreement. The standard terms restrict redistribution.
- **AFL++**: Apache 2.0
- **GDB / binutils**: GPL v3 (called as external processes, not linked)
- **radare2**: LGPL v3
- **rr**: MIT
- **Z3**: MIT

The tables summarize direct packages, not every transitive component. Installed
distributions include additional terms, such as MPL-2.0 in certifi and
pathspec, and MPL-2.0 AND MIT in tqdm. Preserve the notices and applicable
source access for the exact components shipped.

The optional `binary` extra installs angr/PyVEX, including GPLv2 VEX. The
devcontainer installs that extra during operator-side setup; the published
image does not preinstall it. Redistributing a populated environment requires
reviewing the resulting combined stack and its licence/source obligations.

## Proxied hosts

RAPTOR is proxy-aware end to end on hosts behind a mandatory egress
proxy: set the conventional `https_proxy` / `http_proxy` (or
`all_proxy`) and `no_proxy` variables before launching. The sandbox
egress chokepoint chains upstream through them, JVM children get
matching `java.net` sysprops injected, `core.http` clients honour them,
and loopback sidecars (SAGE, Ollama, Joern) are exempted automatically.
The precise strip/normalise/augment rules are in
[Environment Variables](environment.md#proxy-family-http_proxy-https_proxy-no_proxy-all_proxy).

Operator-side installs of external tools (joern, AFL++, frida-server,
jadx) happen outside RAPTOR — export the same proxy variables in the
installing shell. Note that JVM-based installers (e.g. coursier for
joern) ignore proxy env vars and need
`JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=<host> -Dhttps.proxyPort=<port>"`.
