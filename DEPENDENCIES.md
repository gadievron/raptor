# RAPTOR Dependencies and Attribution

## What RAPTOR Includes

**Bundled with RAPTOR:**
- Custom Semgrep rules (engine/semgrep/rules/) - Written by RAPTOR authors, MIT licensed
- CodeQL query suites (engine/codeql/suites/) - Configuration files, MIT licensed
- Python code (all packages/, core/) - Written by RAPTOR authors, MIT licensed

**No external binaries or libraries are bundled with RAPTOR.**

---

## External Tools (User Installs)

RAPTOR **requires users to install** these external tools. RAPTOR does not bundle them.
You can use the devcontainer if you'd like to get these bundled.

**Warning**: Without bundling, RAPTOR auto-downloads tools as needed.

**Note on licensing**: Be sure to examine licenses for these tools prior to using them.
For example CodeQL does not allow commerical use.

### Required Tools

**Semgrep** (Static analysis scanner)
- Install: `pip install semgrep`
- License: LGPL 2.1
- Source: https://github.com/semgrep/semgrep
- Usage: RAPTOR calls `semgrep` command-line tool
- Note: User installs separately, not bundled with RAPTOR

**Python packages** (from requirements.txt)
- requests (Apache 2.0)
- anthropic (MIT)
- tabulate (MIT)
- Install: `pip install -r requirements.txt`
- Note: Managed by pip, not bundled with RAPTOR

### Optional Tools (Install When Needed)

**AFL++** (Binary fuzzer)
- Install: `brew install afl++` or `apt install afl++`
- License: Apache 2.0
- Source: https://github.com/AFLplusplus/AFLplusplus
- Usage: RAPTOR calls `afl-fuzz` command when using /fuzz
- Note: User installs separately

**CodeQL** (Static analysis engine)
- Install: Download from https://github.com/github/codeql-cli-binaries
- License: GitHub CodeQL Terms (free for security research)
- Source: https://github.com/github/codeql
- Usage: RAPTOR calls `codeql` command for deep analysis
- Note: User installs separately

**Ollama** (Local or remote model server)
- Install locally: Download from https://ollama.ai
- Configure remote: Set `OLLAMA_HOST` environment variable
- Default: `http://localhost:11434`
- License: MIT
- Source: https://github.com/ollama/ollama
- Usage: RAPTOR connects to Ollama server for local model inference
- Note: User installs separately, supports both local and remote servers

**rr** (Record-replay debugger)
- Install: `apt install rr` (Linux) or build from https://github.com/rr-debugger/rr
- License: MIT
- Source: https://github.com/rr-debugger/rr
- Usage: RAPTOR uses for deterministic debugging in /crash-analysis command
- Note: User installs separately, Linux only (x86_64)

**gcov** (Code coverage tool)
- Install: Bundled with gcc (no separate install needed)
- License: GPL (part of GCC)
- Source: https://gcc.gnu.org/onlinedocs/gcc/Gcov.html
- Usage: RAPTOR uses for code coverage analysis in /crash-analysis command
- Note: Automatically available with gcc installation

**AddressSanitizer** (Memory error detector)
- Install: Built into gcc >= 4.8 and clang >= 3.1 (compile flag: `-fsanitize=address`)
- License: Apache 2.0
- Source: https://github.com/google/sanitizers
- Usage: RAPTOR detects ASAN builds for enhanced crash diagnostics
- Note: Compile-time instrumentation, enabled via compiler flag

**radare2** (Binary analysis framework)
- Install: `brew install radare2` or `apt install radare2`
- License: LGPL-3.0
- Source: https://github.com/radareorg/radare2
- Usage: RAPTOR uses for enhanced binary analysis in /crash-analysis command
- Features: Disassembly, decompilation, cross-references, security analysis
- Note: User installs separately, optional (falls back to objdump if unavailable)

**Google Cloud BigQuery** (Data warehouse - for OSS forensics)
- Setup: Requires `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- License: Google Cloud Terms of Service
- Source: https://cloud.google.com/bigquery
- Usage: RAPTOR uses for GitHub Archive queries in /oss-forensics command
- Features: Query immutable GitHub event data for forensic investigations
- Note: User sets up separately, optional (required only for /oss-forensics)
- Documentation: See `.claude/skills/oss-forensics/github-archive/SKILL.md`

### System Tools (Pre-installed on Most Systems)

**LLDB** (Debugger)
- Pre-installed: macOS (Xcode Command Line Tools)
- License: Apache 2.0 (part of LLVM)
- Usage: RAPTOR uses for crash analysis on macOS
- Note: Part of operating system, not bundled

**GDB** (Debugger)
- Pre-installed: Most Linux distributions
- License: GPL v3
- Usage: RAPTOR uses for crash analysis on Linux
- Install on macOS: `brew install gdb` (if needed)
- Note: Part of operating system on Linux, not bundled

**Standard Unix tools:**
- nm, addr2line, objdump, file, strings (GNU Binutils)
- Pre-installed: macOS and most Linux distributions
- License: GPL v3
- Usage: RAPTOR uses for binary analysis
- Note: Part of operating system, not bundled

---

## License Summary

**RAPTOR itself:**
- License: MIT
- Copyright: Gadi Evron and Daniel Cuthbert
- See: LICENSE file

**External tools RAPTOR uses:**
- Semgrep (LGPL 2.1) - User installs
- AFL++ (Apache 2.0) - User installs
- CodeQL (GitHub Terms) - User installs
- Python packages (various open source) - User installs via pip
- System tools (GPL v3, Apache 2.0) - Pre-installed on OS

**Important:** RAPTOR does not bundle external tools. Users install them separately according to each tool's license terms.
You can use the devcontainer if you'd like to get these bundled.

**Warning**: Without bundling, RAPTOR auto-downloads tools as needed.

---

## Compliance Notes

**For commercial or restricted use:**
- Review Semgrep license (LGPL 2.1) for your use case
- Review CodeQL terms (free for security research, restrictions apply)
- GPL tools (GDB, binutils) are used as command-line tools, not linked libraries

You should review all respective tool licenses on your own, the above is merely informational.

**RAPTOR's MIT license applies only to RAPTOR's code**, not to external tools users install.
