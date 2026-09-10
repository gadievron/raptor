# Dependencies

The source checkout does not redistribute external tool archives. Users install
host tools separately according to each tool's licence and terms.

See also: [README](README.md), [Fedora 44 + Copilot](fedora-copilot.md),
[architecture](architecture.md).


## Python

Python **3.10+** is required. RAPTOR uses PEP 604 union syntax (`X | Y`) at
function-definition time, which is a syntax error on 3.9 and earlier.

The standard development/Fedora environment pins `z3-solver==4.15.4.0`.
angr 9.3.4 requires `z3-solver==4.13.0.0`, so host installations must keep
angr in a separate venv; see
[angr isolation](fedora-copilot.md#angr-isolation).


## Agent CLIs

npm installations of current Claude Code and GitHub Copilot CLI require
**Node.js 22+**. The Fedora installer reuses an existing Node.js 22+ only when
npm works, requests Fedora Node.js 24 only when both commands are absent, and
refuses to mutate an old/incomplete active Node installation automatically.

The Fedora host guide pins Claude Code 2.1.263 and GitHub Copilot CLI 1.0.83.
Installing either CLI does not authenticate it; account eligibility,
authentication state, and credentials remain operator-managed. See
[Fedora 44 + Copilot](fedora-copilot.md).


## Core Tools

| Tool | Required | Purpose | Install |
|------|----------|---------|---------|
| Semgrep | Yes | Static analysis scanning | `pip install semgrep` |
| Coccinelle (spatch) | No | Semantic patch analysis | `apt install coccinelle` (>=1.3) |
| CodeQL | No | Deep dataflow analysis | [codeql-cli-binaries](https://github.com/github/codeql-cli-binaries) |
| Joern | No | CPG dataflow queries (`/audit`, tiered taint sweeps) | [joern.io](https://joern.io) — Fedora host recipe pins **4.0.622** (needs a JVM) |
| AFL++ | No | Coverage-guided binary fuzzing | `apt install afl++` or `brew install afl++` |
| GDB | No | Crash analysis (Linux) | `apt install gdb` (pre-installed on most distros) |
| LLDB | No | Crash analysis (macOS) | Pre-installed with Xcode CLT |
| rr | No | Deterministic record-replay debugging | `apt install rr` (Linux x86_64 only) |
| radare2 (r2) | No | Binary disassembly, call-graph extraction | [radare2.org](https://rada.re/n/) |
| Frida | No | Dynamic instrumentation | `pip install frida-tools` |
| nm, objdump, readelf | No | Binary analysis (binutils) | Pre-installed on most systems |
| gcov | No | Code coverage (part of GCC) | Bundled with `gcc` |
| AddressSanitizer | No | Memory error detection | Built into gcc>=4.8 and clang>=3.1 |
| BigQuery CLI | No | GitHub Archive forensic queries (`/oss-forensics`) | Included with Google Cloud CLI; requires runtime credentials, a billing project, and least-privilege IAM |


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
| openai | Apache 2.0 | OpenAI SDK — also used for Ollama; hard-required by instructor |
| pyyaml | MIT | YAML parsing (CodeQL pack trust, k8s manifests) |
| defusedxml | PSF | Safe XML parsing (Maven POM) |
| packaging | Apache 2.0 / BSD | PEP 440 version parsing (SCA) |
| tabulate | MIT | Table formatting |
| pyelftools | Unlicense | ELF metadata fallback when angr is absent |

**Optional (install when needed):**

| Package | Licence | Purpose |
|---------|---------|---------|
| anthropic | MIT | Anthropic Claude SDK |
| google-genai | Apache 2.0 | Google Gemini native SDK |
| botocore | Apache 2.0 | AWS Bedrock SigV4 signing (parent-only, not needed for bearer-token auth) |
| beautifulsoup4 | MIT | HTML parsing (web scanning) |
| orjson | MPL-2.0 AND (Apache-2.0 OR MIT) | Faster JSON parse and serialise (transparent fallback to stdlib `json`) |
| pwntools | Mostly MIT; some bundled GPL/BSD-2-Clause components | Binary exploit analysis (ELF parsing, gadget search) — used if present, not in requirements.txt |
| r2pipe | MIT | Python bridge for radare2 (binary disassembly, call-graph extraction, `--binary-edges`) |
| pyghidra | Apache 2.0 | Ghidra bridge — in-process analysis via pyghidra's sandboxed JVM worker |
| frida | wxWindows | Dynamic instrumentation (Frida validation bridge, coverage bridge) |
| jsonschema | MIT | SARIF full-schema validation and orchestrated-report contract checking |
| atheris | Apache 2.0 | Coverage-guided Python fuzzing engine — used if present, not in requirements.txt |
| playwright | Apache 2.0 | Browser automation for web scanning (commented in requirements.txt) |
| z3-solver | MIT | SMT-based constraint analysis (one-gadget feasibility, path validation) |
| angr | BSD | Binary symbolic execution (overflow witnesses, path constraints) — Python >=3.12; 9.3.4 requires z3-solver 4.13.0.0 rather than RAPTOR's standard 4.15.4.0 |
| tree-sitter + grammars | MIT | Rich inventory metadata (decorators, typed params); audit mechanical witnesses (C and Go parsing) — absent grammars degrade to no-witness, never to a wrong verdict |
| sage-agent-sdk | -- | SAGE persistent memory (see [sage.md](sage.md)) |
| httpx | BSD | HTTP client used by the SAGE SDK (installed alongside it) |
| h2 | MIT | HTTP/2 for pooled LLM transports (opt-in via `RAPTOR_HTTP2=1`; see [llm.md](llm.md)) |
| tomli | MIT | TOML reader on Python <3.11 (stdlib `tomllib` from 3.11+) |


## Licensing

RAPTOR itself is MIT-licensed. External tools are used as command-line programs
and are not linked as libraries. Users should review each tool's licence for
their use case:

- **Semgrep**: LGPL 2.1
- **CodeQL**: separate
  [GitHub CodeQL Terms and Conditions](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md);
  review the permitted uses and restrictions for your situation
- **AFL++**: current upstream project is
  [AGPL-3.0-or-later](https://github.com/AFLplusplus/AFLplusplus/blob/stable/LICENSING.md);
  many source files are individually Apache-2.0, while bundled third-party
  components retain their own licences; consult file-level SPDX notices
- **GDB / binutils**: GPL v3 (called as external processes, not linked)
- **radare2**: LGPL v3
- **rr**: MIT
- **Z3**: MIT

Python packages carry their own licences (see the table above). The licence
column summarises upstream package metadata and bundled notices for the
versions RAPTOR pins; review each distribution's complete licence files and
dependency tree for your use case.

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

For checksum-pinned Fedora host recipes, see
[Fedora 44 + Copilot](fedora-copilot.md).
