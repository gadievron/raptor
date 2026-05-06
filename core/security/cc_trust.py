"""
core/security/cc_trust.py

Trust check for target-repo Claude Code config files.

Called by every entry point that runs Claude Code against an untrusted repo:
    - bin/raptor (via libexec/raptor-cc-trust-check)
    - raptor_agentic.py
    - packages/codeql/build_detector.py

Returns True if the caller should refuse to dispatch CC.
Prints findings to stdout when anything noteworthy is found; silent when safe.

Trust override: a process-wide flag set by entry points when `--trust-repo`
is parsed. `bin/raptor` passes the override via argv to the libexec wrapper;
raptor_agentic.py calls `set_trust_override(True)` after argparse.
`build_detector.py` (and any other in-process caller) reads the flag via
`check_repo_claude_trust()` without needing its own argparse plumbing.

Deliberately NOT driven by an env var. Env would be vulnerable to injection
via a target repo's `settings.json` `env` dict (CC propagates that into its
subprocesses, including later RAPTOR invocations), which could forge trust
without the user's consent. The flag is the only source of trust.

Files inspected:
    .claude/settings.json, .claude/settings.local.json, .mcp.json

Dangerous fields (block):
    settings:  apiKeyHelper, awsAuthHelper, awsAuthRefresh, gcpAuthRefresh
               hooks.<Event>[].hooks[].command (type == "command")
               env.<KEY> for KEY in _DANGEROUS_ENV_VARS (LD_PRELOAD, EDITOR, ...)
               env.RAPTOR_* (attempts to forge our own control env vars)
    .mcp.json: mcpServers.<name>.command (stdio servers)
               mcpServers.<name> with unknown transport
    structural: symlinks, oversized, malformed (all → block)

Informational (no block):
    .mcp.json: url-only servers (sse/http transport)
"""

import json
import os
import stat
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple


# Process-wide trust override. Set by entry points via set_trust_override()
# when --trust-repo is parsed. Not an env var (see module docstring).
_trust_override_set = False


def set_trust_override(val: bool) -> None:
    """Set process-wide trust override. Call once from each entry point
    that parses --trust-repo. Idempotent."""
    global _trust_override_set
    _trust_override_set = bool(val)


@dataclass
class Finding:
    """One labelled row in the per-file findings table."""
    label: str          # e.g. "apiKeyHelper", "SessionStart hook", "env LD_PRELOAD"
    value: str          # e.g. the helper command, hook command, env value
    blocking: bool      # True = blocks dispatch; False = info only (URL MCP)


@dataclass
class FileScan:
    """Findings for one inspected file."""
    path: Path
    findings: List[Finding] = field(default_factory=list)

    def has_blocking(self) -> bool:
        return any(f.blocking for f in self.findings)


_CREDENTIAL_HELPER_KEYS = (
    "apiKeyHelper", "awsAuthHelper", "awsAuthRefresh", "gcpAuthRefresh",
)

_COMPREHENSIVE_DANGEROUS_ENV_VARS = frozenset({
    "TERMINAL", "BROWSER", "PAGER", "VISUAL", "EDITOR",
    "IFS", "CDPATH",
    "BASH_ENV", "ENV", "PROMPT_COMMAND",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
    "NODE_OPTIONS", "NODE_PATH",
    "PERL5OPT", "PERLLIB", "PERL5LIB",
    "RUBYOPT", "RUBYLIB",
    # Proxy redirection — a target repo's CC settings.json env can
    # silently route every outbound HTTP/HTTPS request through an
    # attacker-controlled proxy. Pre-fix, the standalone fallback
    # (used when core.config is unimportable — e.g. a stripped-down
    # CC install or partial repo) didn't catch these. The full
    # RaptorConfig.DANGEROUS_ENV_VARS list does, but the fallback was
    # the line of defence for everything else.
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
    "NO_PROXY", "no_proxy",
    # JVM / language-runtime injection. Any tool that spawns Java
    # picks JAVA_TOOL_OPTIONS up unconditionally; -javaagent loads
    # arbitrary code at JVM startup. _JAVA_OPTIONS is the older
    # variant. CLASSPATH adds attacker .jar to load path.
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
    "MAVEN_OPTS", "GRADLE_OPTS",
    # Cargo / Ruby / Node module-resolution overrides.
    "CARGO_HOME", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
    "PYTHONUSERBASE", "PYTHONBREAKPOINT",
    # Git config redirection — an env-set GIT_CONFIG_GLOBAL points
    # git at an attacker config file with `alias = !sh`,
    # `core.editor = arbitrary binary`, `credential.helper = ...`
    # firing on every fetch. GIT_SSH_COMMAND directly execs an
    # attacker binary on every ssh-based git op.
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG",
    "GIT_SSH_COMMAND", "GIT_SSH", "SSH_ASKPASS",
    # OpenSSL config — .conf files can load ENGINE .so files
    # (arbitrary code in any process that initialises OpenSSL).
    "OPENSSL_CONF",
    # TLS trust override — CA bundle / cert dir redirection makes
    # MITM trivial.
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS", "SSLKEYLOGFILE",
    # Kubernetes — `users[].user.exec` directive runs arbitrary
    # command for credential acquisition.
    "KUBECONFIG",
})
try:
    from core.config import RaptorConfig
    _DANGEROUS_ENV_VARS = (
        _COMPREHENSIVE_DANGEROUS_ENV_VARS
        | frozenset(RaptorConfig.DANGEROUS_ENV_VARS)
    )
except ImportError:
    _DANGEROUS_ENV_VARS = _COMPREHENSIVE_DANGEROUS_ENV_VARS

_MAX_CONFIG_BYTES = 1_000_000

# RAPTOR repo root = core/security/cc_trust.py -> ../../
_RAPTOR_DIR = Path(__file__).resolve().parents[2]

# U+2028/U+2029 line-separators — Zl/Zp categories slip past Cc/Cf below
# but terminals render them as newlines, which could split our output.
_EXTRA_STRIP = frozenset({"\u2028", "\u2029"})


def _safe(s: str) -> str:
    """Strip Unicode control/format chars and line/paragraph separators.
    Defends against ANSI escapes, Trojan Source bidi (CVE-2021-42574),
    zero-width chars, and line-separator-driven output splitting."""
    return "".join(
        c if c == "\t" or (
            c not in _EXTRA_STRIP
            and unicodedata.category(c) not in ("Cc", "Cf")
        ) else "?"
        for c in s
    )


def _truncate(s: str, limit: int = 80) -> str:
    safe = _safe(s)
    return safe[:limit] + "..." if len(safe) > limit else safe


def _path_present(p: Path) -> bool:
    try:
        return p.is_symlink() or p.exists()
    except OSError:
        return False


def _read_capped(path: Path) -> Optional[bytes]:
    """Read up to _MAX_CONFIG_BYTES+1. None on oversized/non-regular/error.

    O_NONBLOCK + fstat(S_ISREG) closes the FIFO-DoS and stat-vs-open TOCTOU
    holes. O_NOFOLLOW closes the symlink-redirect hole — the caller's
    `_check_cached` symlink branch records symlinks as findings without
    reading them, but a TOCTOU race could swap a regular file for a
    symlink between the symlink check and the open here. With
    O_NOFOLLOW the open fails with ELOOP and we fail-closed (return
    None). Broad except for any I/O surprise — fail-closed is the safe
    stance.
    """
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except Exception:
        return None
    data: Optional[bytes] = None
    try:
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read(_MAX_CONFIG_BYTES + 1)
        except Exception:
            return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if data is None or len(data) > _MAX_CONFIG_BYTES:
        return None
    return data


def _load_json(path: Path) -> Tuple[Optional[dict], bool]:
    """Return (data, ok). Broad except — any parse failure → fail-closed."""
    raw = _read_capped(path)
    if raw is None:
        return None, False
    try:
        # utf-8-sig handles a leading BOM transparently.
        data = json.loads(raw.decode("utf-8-sig"))
    except Exception:
        return None, False
    if not isinstance(data, dict):
        return None, False
    return data, True


def _scan_settings(path: Path) -> Optional[FileScan]:
    """Return FileScan with findings, or None if malformed/unreadable."""
    data, ok = _load_json(path)
    if not ok:
        return None
    fs = FileScan(path=path)

    try:
        for key in _CREDENTIAL_HELPER_KEYS:
            val = data.get(key)
            if val:
                value = val if isinstance(val, str) else repr(val)
                fs.findings.append(Finding(key, _truncate(value), True))

        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event_name, matchers in hooks.items():
                if not isinstance(matchers, list):
                    continue
                ev = _truncate(str(event_name), limit=40)
                for matcher in matchers:
                    inner = matcher.get("hooks") if isinstance(matcher, dict) else None
                    if not isinstance(inner, list):
                        continue
                    for entry in inner:
                        if not isinstance(entry, dict):
                            continue
                        # Pre-fix: only `type == "command"` hooks were
                        # flagged. CC's hook spec is small today (just
                        # `command`), but a future addition (or a
                        # caller-supplied custom hook type) would slip
                        # past entirely — we'd silently treat
                        # `type=plugin` / `type=script` / etc. as
                        # benign. Fail-closed: any hook entry whose
                        # type we don't recognise is treated as
                        # dangerous (the value field is rendered for
                        # operator review).
                        hook_type = entry.get("type")
                        if hook_type == "command":
                            cmd = entry.get("command")
                            value = _truncate(cmd) if isinstance(cmd, str) and cmd else "(empty)"
                            fs.findings.append(Finding(f"{ev} hook", value, True))
                        else:
                            # Unknown hook type — surface the type +
                            # the entry's keys so the operator can
                            # judge. Treated as blocking like every
                            # other hook finding.
                            type_label = _truncate(
                                str(hook_type) if hook_type is not None else "(missing)",
                                limit=40,
                            )
                            keys_summary = ",".join(sorted(entry.keys()))
                            fs.findings.append(Finding(
                                f"{ev} hook ({type_label}, unknown type)",
                                _truncate(keys_summary),
                                True,
                            ))

        env_cfg = data.get("env")
        if isinstance(env_cfg, dict):
            # Pre-fix the membership check was exact-match, so a target
            # setting `http_proxy` or `Https_Proxy` (both honoured by
            # curl, wget, requests, and most language stdlibs) bypassed
            # the dangerous-env detection because only uppercase
            # `HTTP_PROXY`/`HTTPS_PROXY` were in the set. POSIX doesn't
            # mandate uppercase env vars; the case-insensitive proxy
            # convention is real and widely exploited. Compare against
            # an upper-case-folded view of the dangerous set.
            dangerous_upper = {v.upper() for v in _DANGEROUS_ENV_VARS}
            for env_key, env_val in env_cfg.items():
                key_str = str(env_key)
                key_upper = key_str.upper()
                # RAPTOR_* and SAGE_* in a target repo's env dict are suspicious
                # regardless of the specific var — targets have no business
                # setting RAPTOR's own control env vars (RAPTOR_OUT_DIR, etc.)
                # nor SAGE's (SAGE_URL could redirect to a poisoned memory
                # server, SAGE_ENABLED could silently turn on persistent
                # memory the user didn't intend, etc.).
                if (key_upper in dangerous_upper
                        or key_upper.startswith("RAPTOR_")
                        or key_upper.startswith("SAGE_")):
                    k = _truncate(key_str, limit=40)
                    fs.findings.append(Finding(f"env {k}", _truncate(str(env_val)), True))
    except Exception:
        return None  # display-time crash → fail-closed
    return fs


def _scan_mcp(path: Path) -> Optional[FileScan]:
    data, ok = _load_json(path)
    if not ok:
        return None
    fs = FileScan(path=path)
    try:
        servers = data.get("mcpServers")
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                n = _truncate(str(name), limit=40)
                if not isinstance(cfg, dict):
                    fs.findings.append(Finding(f'unknown server "{n}"', "(not an object)", True))
                    continue
                if "command" in cfg:
                    cmd = cfg.get("command", "")
                    args = cfg.get("args", [])
                    parts = [str(cmd)] + [str(a) for a in (args if isinstance(args, list) else [])]
                    fs.findings.append(Finding(f'stdio server "{n}"', _truncate(" ".join(parts)), True))
                elif "url" in cfg:
                    fs.findings.append(Finding(f'url server "{n}"', _truncate(str(cfg.get("url", ""))), False))
                else:
                    fs.findings.append(Finding(f'unknown server "{n}"', _truncate(repr(cfg)), True))
    except Exception:
        return None
    return fs


def check_repo_claude_trust(repo_path: str, trust_override: Optional[bool] = None) -> bool:
    """Check target repo. Returns True if dispatch should be refused.

    trust_override:
        None  → read the module-level flag (set by set_trust_override()).
                The production default.
        True  → force trust (warn but never block). Tests, or callers with
                context the module flag doesn't capture.
        False → force strict. Tests, or code paths that want hard enforcement
                regardless of what the user opted into elsewhere.
    """
    if not repo_path:
        return False
    try:
        resolved = str(Path(repo_path).resolve())
    except (ValueError, OSError):
        return False
    if trust_override is None:
        trust_override = _trust_override_set
    scans, any_blocking = _scan_cached(resolved)
    # Print side-effects live OUTSIDE the cache. Pre-fix the print() calls
    # were inside `_check_cached` which was @lru_cache'd — so the operator
    # only saw the warning on the FIRST identical call per process; every
    # subsequent invocation silently returned the cached verdict with no
    # visible diagnostic. Re-emit the rendering on each invocation so the
    # warning isn't suppressed by cache-friendly callers (e.g. an
    # orchestrator that re-checks the same repo per finding).
    if scans:
        target = Path(resolved)
        _render_scan_report(target, scans, any_blocking, trust_override)
    return any_blocking and not trust_override


@lru_cache(maxsize=64)
def _scan_cached(resolved_path: str) -> Tuple[Tuple["FileScan", ...], bool]:
    """Pure scan: returns (scans, any_blocking). Cached because filesystem
    state for a given resolved path doesn't change within a session.
    Side-effect free so repeated cache hits don't suppress operator-
    visible warnings (handled in the caller)."""
    target = Path(resolved_path)
    if target == _RAPTOR_DIR:
        return ((), False)

    candidates = [
        ("settings", target / ".claude" / "settings.json"),
        ("settings", target / ".claude" / "settings.local.json"),
        ("mcp",      target / ".mcp.json"),
    ]
    present = [(kind, p) for kind, p in candidates if _path_present(p)]
    if not present:
        return ((), False)

    scans: List[FileScan] = []
    for kind, path in present:
        fs = FileScan(path=path)
        if path.is_symlink():
            try:
                tgt = str(path.readlink())
            except OSError:
                tgt = "<unreadable>"
            fs.findings.append(Finding("symlink", _truncate(tgt, limit=120), True))
            scans.append(fs)
            continue
        scanned = _scan_settings(path) if kind == "settings" else _scan_mcp(path)
        if scanned is None:
            fs.findings.append(Finding("(malformed)", "treated as dangerous", True))
            scans.append(fs)
        elif scanned.findings:
            scans.append(scanned)

    any_blocking = any(s.has_blocking() for s in scans)
    return (tuple(scans), any_blocking)


def _render_scan_report(target: Path, scans, any_blocking: bool,
                        trust_override: bool) -> None:
    """Pure rendering — separated from `_scan_cached` so the cache
    doesn't suppress the operator-visible warning on re-invocation."""
    safe_target = _safe(str(target))
    if any_blocking:
        if trust_override:
            print(f"raptor: {safe_target} has dangerous Claude Code config "
                  f"(trust override active):")
        else:
            print(f"raptor: {safe_target} has dangerous Claude Code config:")
    else:
        print(f"raptor: {safe_target} has Claude Code config:")

    for fs in scans:
        try:
            rel = fs.path.relative_to(target)
        except ValueError:
            rel = fs.path
        print(f"  {_safe(str(rel))}")
        label_w = max(len(f.label) for f in fs.findings) + 2
        for f in fs.findings:
            print(f"    {f.label:<{label_w}}{f.value}")
