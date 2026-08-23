"""Shared dangerous-sink vocabulary for supply-chain analyses.

Single authority for the sink names that ``version_diff_sinks`` and
``hook_guard_analysis`` both scan for. The two modules used to carry
independently-edited copies of the same core list; each now composes
its set from :data:`SHARED_SUPPLY_CHAIN_SINKS` plus its own documented
extras below. A drift-guard test pins the composed sets to the exact
pre-split values.
"""

from __future__ import annotations

# Sinks both analyses care about: shell/code execution, dangerous
# deserialization, network egress, and destructive file operations
# across the ecosystems SCA scans (Python, JS, Rust, C-in-bindings).
SHARED_SUPPLY_CHAIN_SINKS: frozenset[str] = frozenset({
    # Shell execution
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "system", "popen", "exec", "eval",
    # Code execution / deserialization
    "pickle.loads", "pickle.load", "marshal.loads",
    "yaml.load", "compile", "__import__",
    # Network egress
    "requests.get", "requests.post", "urllib.request.urlopen",
    "socket.connect",
    # File system manipulation
    "os.remove", "os.unlink", "shutil.rmtree", "open",
    # Rust
    "Command::new",
    # Node
    "child_process.exec", "child_process.spawn", "child_process.execSync",
})

# version_diff_sinks-only additions: the version diff also tracks
# guard-count changes around lower-level and per-language sinks that
# would be pure noise in hook payloads (memcpy in a diff context is a
# signal; in a 30-line install hook it is not).
VERSION_DIFF_EXTRA_SINKS: frozenset[str] = frozenset({
    "io.open", "os.open",
    "Runtime.exec", "ProcessBuilder",
    "passthru", "shell_exec",
    "Kernel.system", "Kernel.exec", "Kernel.eval", "Marshal.load",
    "exec.Command",
    "loadstring", "dofile",
    "cursor.execute", "cursor.executemany",
    "memcpy", "strcpy", "strcat", "sprintf", "gets",
})

# hook_guard_analysis-only additions: exfiltration and credential-read
# APIs that matter in install/lifecycle hook payloads specifically.
HOOK_PAYLOAD_EXTRA_SINKS: frozenset[str] = frozenset({
    "http.client.HTTPSConnection", "fetch", "XMLHttpRequest",
    "std::process::Command",
    "child_process.execFile", "fs.readFileSync",
})
