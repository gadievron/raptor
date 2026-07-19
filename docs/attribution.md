# Attribution & Licensing

Legal reference for what RAPTOR bundles, what it shells out to, and the
license each external tool carries. For *how to install* these tools, see
[`install.md`](install.md).

---

## What RAPTOR Includes

**Bundled with RAPTOR (RAPTOR's own code):**
- Custom Semgrep rules (`engine/semgrep/rules/`) — written by RAPTOR authors, MIT licensed
- CodeQL query suites (`engine/codeql/suites/`) — configuration files, MIT licensed
- Python code (`packages/`, `core/`) — written by RAPTOR authors, MIT licensed

**No external binaries or libraries are bundled with RAPTOR.** Everything
below is installed separately by the user (or via the devcontainer) and
retains its own upstream license.

---

## External Tools (User-Installed)

RAPTOR **requires users to install** these tools; none are bundled. RAPTOR
does not auto-download tools — you install each one yourself.

**Note on licensing:** examine each tool's license before using it in your
context. **CodeQL does not allow commercial use** — see [Compliance Notes](#compliance-notes).

### Required

| Tool | License | Source |
|------|---------|--------|
| **Semgrep** (static analysis scanner) | LGPL 2.1 | https://github.com/semgrep/semgrep |

### Optional (install when the feature is used)

| Tool | Used by | License | Source |
|------|---------|---------|--------|
| **AFL++** (binary fuzzer) | `/fuzz` | Apache 2.0 | https://github.com/AFLplusplus/AFLplusplus |
| **CodeQL** (static analysis engine) | `/codeql`, `/scan` deep analysis | GitHub CodeQL Terms — **free for security research, non-commercial use only** | https://github.com/github/codeql |
| **Ollama** (local/remote model server) | local or free LLM inference | MIT | https://github.com/ollama/ollama |
| **rr** (record-replay debugger) | `/crash-analysis` | MIT | https://github.com/rr-debugger/rr |
| **gcov** (code coverage tool) | `/crash-analysis` | GPL (part of GCC) | https://gcc.gnu.org/onlinedocs/gcc/Gcov.html |
| **AddressSanitizer** (memory error detector) | `/crash-analysis` enhanced diagnostics | Apache 2.0 | https://github.com/google/sanitizers |
| **Google Cloud BigQuery** (data warehouse) | `/oss-forensics` (GH Archive queries) | Google Cloud Terms of Service | https://cloud.google.com/bigquery |

### System Tools (pre-installed on most systems)

| Tool | License | Note |
|------|---------|------|
| **LLDB** (debugger) | Apache 2.0 (part of LLVM) | macOS, Xcode Command Line Tools |
| **GDB** (debugger) | GPL v3 | Most Linux distros; `brew install gdb` on macOS |
| **nm, addr2line, objdump, file, strings** (GNU Binutils) | GPL v3 | Pre-installed on macOS/Linux |

---

## Python Package Licenses

RAPTOR's required Python dependencies (`pip install -r requirements.txt`),
not bundled — installed and managed by pip:

| Package | License |
|---------|---------|
| requests | Apache 2.0 |
| urllib3 | MIT |
| pydantic | MIT |
| typer | MIT |
| instructor | MIT |
| tabulate | MIT |
| pyyaml | MIT |
| defusedxml | Python Software Foundation License (PSFL) |
| packaging | Apache 2.0 OR BSD-2-Clause (dual-licensed) |

Optional LLM provider SDKs (install only the ones you use — see
[`configuration.md`](configuration.md)): `anthropic` (MIT), `openai` (Apache
2.0), `google-genai` (Apache 2.0). Mistral and Ollama both go through the
`openai` SDK via the OpenAI-compatible endpoint, so they need no separate SDK.

---

## License Summary

**RAPTOR itself:**
- License: MIT
- Copyright: Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake),
  Michael Bargury, and John Cartwright
- See: `LICENSE` file at the repo root

**External tools RAPTOR uses (not bundled, user-installed):**
- Semgrep (LGPL 2.1)
- AFL++ (Apache 2.0)
- CodeQL (GitHub CodeQL Terms — **non-commercial**)
- Python packages (various open source, see [Python Package Licenses](#python-package-licenses)) — via pip
- System tools (GPL v3, Apache 2.0) — pre-installed on OS

**RAPTOR does not bundle external tools.** The devcontainer bundles them for
convenience only — it does not change their license terms.

---

## Compliance Notes

**For commercial or restricted use:**
- Review the Semgrep license (LGPL 2.1) for your use case.
- Review the **CodeQL Terms** — free for security research; **commercial use
  is not permitted** without a separate agreement with GitHub. Confirm this
  applies to your use case before relying on CodeQL in a commercial pipeline.
- GPL tools (GDB, binutils, gcov) are invoked as command-line tools, not
  linked libraries.

You should review all respective tool licenses on your own — the above is
informational, not legal advice.

**RAPTOR's MIT license applies only to RAPTOR's own code**, not to any
external tool a user installs alongside it.
