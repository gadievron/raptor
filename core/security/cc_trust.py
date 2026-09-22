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
    settings:  apiKeyHelper, awsAuthRefresh, awsCredentialExport,
               gcpAuthRefresh, proxyAuthHelper, otelHeadersHelper
               hooks.<Event>[].hooks[].command (type == "command"), plus —
               fail-closed — any hook entry with an unrecognised type
               and any hooks/matcher value of an unrecognised shape
               env.<KEY> for KEY in _DANGEROUS_ENV_VARS (LD_PRELOAD, EDITOR, ...
               unioned with the canonical credential-env family:
               credential material, credential/config file pointers,
               exec-redirect names — see core/security/credential_env.py)
               env.<KEY> of credential-redirect SHAPE (*_TOKEN / *_KEY /
               *_SECRET / *_PASSWORD / *_CONFIG_FILE / *_ASKPASS ... —
               repo-supplied settings env has no legitimate reason to
               set any credential-shaped name)
               env.<KEY> of model-traffic-redirect SHAPE
               (ANTHROPIC_*BASE_URL* / AWS_ENDPOINT_URL* /
               CLAUDE_CODE_SKIP_* — per-provider endpoint variants and
               auth-mode flips, same redirect primitive as the exact
               ANTHROPIC_BASE_URL block)
               env.<PREFIX>* for PREFIX in _DANGEROUS_ENV_PREFIXES
               (RAPTOR_* / SAGE_* forge our own control env vars or
               repoint persistent memory; CLAUDE_CODE_USE_* /
               OTEL_EXPORTER_OTLP_* reroute model traffic / telemetry)
    .mcp.json: mcpServers.<name>.command (stdio servers)
               mcpServers.<name> with unknown transport
    structural: symlinks, oversized, malformed (all → block)

Informational (no block):
    .mcp.json: url-only servers (sse/http transport)
"""

import errno
import json
import logging
import os
import stat
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from core.security.capped_read import read_capped
from core.security.credential_env import (
    CREDENTIAL_ENV_FAMILY,
    TOOLCHAIN_HOME_ENV_VARS,
    is_credential_redirect_shaped,
    is_model_traffic_redirect_shaped,
)
from urllib.parse import urlsplit

# Plain stdlib logger — cc_trust runs at startup before
# core.logging may be configured, and the trust gate must not
# depend on lazy initialisation that could itself fail.
_logger = logging.getLogger(__name__)


# Process-wide trust override. Set by entry points via set_trust_override()
# when --trust-repo is parsed. Not an env var (see module docstring).
_trust_override_set = False


def set_trust_override(val: bool) -> None:
    """Set process-wide trust override. Call once from each entry point
    that parses --trust-repo. Idempotent."""
    global _trust_override_set
    _trust_override_set = bool(val)


def is_trust_overridden() -> bool:
    """Return the current process-wide trust override.

    Public reader for the flag set by :func:`set_trust_override`.
    Subsystems that want to surface a "trust state" diagnostic to the
    operator read this directly rather than going through the heavier
    ``check_repo_claude_trust`` repo scan.

    Returns True when the operator opted into trust via the CLI
    (``--trust-repo``); False by the default-strict posture.
    """
    return _trust_override_set


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
    findings: list[Finding] = field(default_factory=list)

    def has_blocking(self) -> bool:
        return any(f.blocking for f in self.findings)


_CREDENTIAL_HELPER_KEYS = (
    # Commands CC executes to obtain/refresh credentials. These are
    # the keys CC actually honours: `awsAuthHelper` (an earlier guess)
    # does not exist — the executed-script key is `awsCredentialExport`
    # — and `proxyAuthHelper` produces proxy auth headers the same way.
    "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport",
    "gcpAuthRefresh", "proxyAuthHelper",
    # otelHeadersHelper is a command CC executes to produce telemetry
    # headers — same command-execution primitive as the credential
    # helpers above (a repo-shipped script plus env OTEL_* arms it).
    "otelHeadersHelper",
)

# permissions.* sub-keys that only NARROW or gate what a CC session
# may do. Anything else under `permissions` in a target repo's
# settings.json (allow, defaultMode, additionalDirectories, future
# additions) can widen what a prompt-injected session does without
# HITL — fail-closed: flag every key not on this allowlist.
_PERMISSIONS_BENIGN_KEYS = frozenset({"deny", "ask"})

_COMPREHENSIVE_DANGEROUS_ENV_VARS = frozenset({
    "TERMINAL", "BROWSER", "PAGER", "VISUAL", "EDITOR",
    "IFS", "CDPATH",
    # PATH / HOME — a repo-supplied CC settings.json env dict has NO
    # legitimate reason to set either. env.PATH prepends an
    # attacker-controlled directory so every bare command name CC (or
    # a later RAPTOR invocation inheriting the env) runs resolves to
    # a repo-shipped binary; env.HOME repoints ~ so dotfile-consuming
    # tools (git, ssh, gh, pip, npm) read attacker-authored configs —
    # credential helpers, aliases, hooks — from a fake home. Both are
    # command-execution primitives on par with LD_PRELOAD for this
    # threat model. (This set only feeds the settings-env scan, so
    # listing them cannot affect legitimate process environments.)
    "PATH", "HOME",
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
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
    # Build-tool names (MAVEN_OPTS, GRADLE_OPTS, CARGO_HOME, GEM_HOME,
    # GEM_PATH, BUNDLE_GEMFILE and their per-ecosystem siblings) come
    # from the ecosystem surfaces in core/security/credential_env.py
    # via the CREDENTIAL_ENV_FAMILY union below — credential_env is
    # stdlib-only and imports even where core.config cannot, so the
    # standalone fallback keeps them without a private copy.
    "PYTHONUSERBASE", "PYTHONBREAKPOINT",
    # Git config redirection — an env-set GIT_CONFIG_GLOBAL points
    # git at an attacker config file with `alias = !sh`,
    # `core.editor = arbitrary binary`, `credential.helper = ...`
    # firing on every fetch. (GIT_SSH_COMMAND / GIT_SSH / GIT_ASKPASS /
    # SSH_ASKPASS live in the credential-env family unioned below.)
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG",
    # Git helper/template redirection — an env-set GIT_EXEC_PATH
    # substitutes every git-<cmd> helper binary; GIT_TEMPLATE_DIR
    # plants per-repo hook executables at `git init`. Both are in
    # RaptorConfig.DANGEROUS_ENV_VARS; the standalone fallback (used
    # when core.config is unimportable) must carry them on its own —
    # same degraded-install parity the proxy family got above.
    "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
    # OpenSSL config — .conf files can load ENGINE .so files
    # (arbitrary code in any process that initialises OpenSSL).
    "OPENSSL_CONF",
    # TLS trust override — CA bundle / cert dir redirection makes
    # MITM trivial.
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS", "SSLKEYLOGFILE",
    # Model-traffic redirect — CC honours this directly: BASE_URL
    # repoints every API call at an attacker endpoint (prompt +
    # source-code exfiltration, poisoned completions). A strictly
    # stronger primitive than the HTTP_PROXY family already blocked
    # above. The exact name alone is NOT enough: the CLI reads a
    # DIFFERENT base-URL name per provider mode (a Bedrock install
    # ignores ANTHROPIC_BASE_URL and reads the per-cloud
    # ANTHROPIC_*_BASE_URL variants), the JS AWS SDK honours
    # AWS_ENDPOINT_URL[_<SERVICE>], and CLAUDE_CODE_SKIP_* flips the
    # CLI's auth mode at whatever endpoint won — so the scan ALSO
    # applies is_model_traffic_redirect_shaped (the vocabulary's
    # shape rule, shared with cc_adapter's proxy strip) to every env
    # key. (ANTHROPIC_AUTH_TOKEN / ANTHROPIC_CUSTOM_HEADERS —
    # attacker-credential substitution and header riding — live in
    # the credential-env family unioned below.)
    "ANTHROPIC_BASE_URL",
}) | CREDENTIAL_ENV_FAMILY | TOOLCHAIN_HOME_ENV_VARS
# TOOLCHAIN_HOME_ENV_VARS joins THIS scan set only (never the general
# blocklists): a repo-supplied env.JAVA_HOME points the operator
# session's next mvn/gradle/ant invocation at `<repo>/jvm/bin/java` —
# repo binary executed at operator power. With env.PATH already
# blocked above, the toolchain-home names are the surviving
# launcher-redirect primitive on this lane. The traced-build lane's
# own env_detect passthrough is untouched (it reads the HOST env, not
# repo settings, and this set feeds only the settings scan).
# The canonical credential-env family (core/security/credential_env.py)
# joins the settings-scan blocklist wholesale: credential material
# (CLAUDE_CODE_OAUTH_TOKEN — attacker-credential substitution, the same
# rationale ANTHROPIC_AUTH_TOKEN is blocked for), credential/config
# file pointers whose pointed-to file can name an executed helper
# (AWS_CONFIG_FILE credential_process, KUBECONFIG users[].user.exec,
# DOCKER_CONFIG credsStore — the identical primitive this scan always
# blocked KUBECONFIG for), and exec-redirect names (GIT_ASKPASS,
# RUSTC_WRAPPER). A repo-supplied settings env dict has no legitimate
# reason to set ANY member.

# Env-key PREFIXES flagged wholesale (compared case-folded, like the
# name set above). RAPTOR_*/SAGE_* forge RAPTOR's own control env or
# repoint persistent memory; CLAUDE_CODE_USE_* flips CC onto alternate
# backends/transports (e.g. Bedrock/Vertex routing, where the endpoint
# then comes from further attacker-set env); OTEL_EXPORTER_OTLP_*
# redirects telemetry (and its auth headers) to an attacker collector.
_DANGEROUS_ENV_PREFIXES = (
    "RAPTOR_", "SAGE_", "CLAUDE_CODE_USE_", "OTEL_EXPORTER_OTLP_",
)
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


def _mask(s: str, keep: int = 8) -> str:
    """Render a secret-bearing config value without echoing it.

    Scan output lands on stdout and from there in retained CI logs, so
    credential-helper commands, env values, and MCP command lines must
    not be printed verbatim — a leaked settings.json would otherwise
    republish its secrets into every build log. Keep a short prefix
    (enough to identify the binary/helper for triage), redact the tail,
    and show the length so distinct values remain distinguishable.
    ``keep=0`` fully redacts — used for env values, where the value IS
    the secret and even a prefix is a partial leak.
    """
    safe = _safe(s)
    if not safe:
        return "(empty)"
    # A prefix of a value no longer than ``keep`` IS the value —
    # fully redact rather than echo it whole.
    prefix = safe[:keep] if 0 < keep < len(safe) else ""
    return f"{prefix}*** ({len(safe)} chars)"


def _mask_url(s: str) -> str:
    """Render a URL keeping only scheme + host (identifying, safe);
    userinfo, port, path, and query are redacted — MCP endpoints embed
    tokens in any of them."""
    safe = _safe(s)
    try:
        parsed = urlsplit(safe)
        host = parsed.hostname  # raises ValueError on malformed ports
    except ValueError:
        return _mask(safe)
    if parsed.scheme and host:
        return f"{parsed.scheme}://{host}/*** ({len(safe)} chars)"
    return _mask(safe)


def _read_capped(path: Path) -> bytes | None:
    """Read up to ``_MAX_CONFIG_BYTES``; delegates the hardened
    open/read to :func:`core.security.capped_read.read_capped`."""
    return read_capped(path, _MAX_CONFIG_BYTES)


def _load_json(path: Path, raw: bytes | None = None) -> tuple[dict | None, bool]:
    """Return (data, ok). Broad except — any parse failure → fail-closed.

    ``raw`` carries pre-read bytes (the cache-key read); when provided
    the file is NOT re-read, so the verdict is computed over exactly
    the bytes the cache key hashes — no window for a benign→malicious
    swap between fingerprinting and scanning.

    Pre-fix the bare `except Exception` swallowed everything
    silently. cc_trust is a SECURITY-critical scanner — when a
    settings file fails to parse, the operator should see a log
    line saying "we treated this as unsafe because of <reason>"
    so they can either fix the file or know the trust check is
    being bypassed. Without the diagnostic, an operator
    debugging "why won't /agentic dispatch CC?" had no signal
    that the underlying cause was a malformed settings JSON.

    Log at debug — fail-closed is the right default and we
    don't want to spam warnings on every scan, but the
    diagnostic is reachable via `--verbose` for operators
    actively debugging.
    """
    if raw is None:
        raw = _read_capped(path)
    if raw is None:
        return None, False
    try:
        # utf-8-sig handles a leading BOM transparently.
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        # Specific exception classes for the diagnostic.
        # `Exception` catch-all kept below for unknown classes
        # (Python version differences, future json variants).
        import logging
        logging.getLogger(__name__).debug(
            "cc_trust._load_json: parse failure on %s — %s: %s",
            path, type(exc).__name__, exc,
        )
        return None, False
    except Exception as exc:  # noqa: BLE001
        # Catch-all — log so an unexpected exception class
        # (e.g. MemoryError on a multi-GB file that slipped
        # past _read_capped) still produces a breadcrumb.
        import logging
        logging.getLogger(__name__).debug(
            "cc_trust._load_json: unexpected failure on %s — %s: %s",
            path, type(exc).__name__, exc,
        )
        return None, False
    if not isinstance(data, dict):
        import logging
        logging.getLogger(__name__).debug(
            "cc_trust._load_json: %s parsed but root is %s, not dict",
            path, type(data).__name__,
        )
        return None, False
    return data, True


def _scan_settings(path: Path, raw: bytes | None = None) -> FileScan | None:
    """Return FileScan with findings, or None if malformed/unreadable."""
    data, ok = _load_json(path, raw)
    if not ok or data is None:
        return None
    fs = FileScan(path=path)

    try:
        for key in _CREDENTIAL_HELPER_KEYS:
            val = data.get(key)
            if val:
                value = val if isinstance(val, str) else repr(val)
                # Masked: credential-helper commands routinely embed
                # keys/tokens inline and scan output is CI-log-retained.
                fs.findings.append(Finding(key, _mask(value), True))

        # Fail-closed on every unrecognised hooks shape: pre-fix, a
        # non-list Event value, a non-dict matcher, or a matcher whose
        # "hooks" wasn't a list was silently SKIPPED — so a dict-form
        # `"PreToolUse": {"command": ...}` (or any shape a future CC
        # accepts more leniently than this scanner) carried a command
        # past the scan with zero findings.
        hooks = data.get("hooks")
        if hooks is not None and not isinstance(hooks, dict):
            fs.findings.append(Finding(
                "hooks (unrecognised shape)",
                _mask(repr(hooks)), True))
        if isinstance(hooks, dict):
            for event_name, matchers in hooks.items():
                ev = _truncate(str(event_name), limit=40)
                if not isinstance(matchers, list):
                    fs.findings.append(Finding(
                        f"{ev} hooks (unrecognised shape)",
                        _mask(repr(matchers)), True))
                    continue
                for matcher in matchers:
                    if not isinstance(matcher, dict):
                        fs.findings.append(Finding(
                            f"{ev} hook matcher (unrecognised shape)",
                            _mask(repr(matcher)), True))
                        continue
                    inner = matcher.get("hooks")
                    if not isinstance(inner, list):
                        fs.findings.append(Finding(
                            f"{ev} hook matcher (unrecognised shape)",
                            _mask(repr(matcher)), True))
                        continue
                    for entry in inner:
                        if not isinstance(entry, dict):
                            fs.findings.append(Finding(
                                f"{ev} hook (unrecognised shape)",
                                _mask(repr(entry)), True))
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
                            # Non-string commands are masked via repr —
                            # still a blocking finding (a list-shaped
                            # command is command execution too).
                            if isinstance(cmd, str) and cmd:
                                value = _mask(cmd)
                            elif cmd:
                                value = _mask(repr(cmd))
                            else:
                                value = "(empty)"
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

        # statusLine.command is a command CC executes on every prompt
        # render — a repo-shipped settings.json with
        # `statusLine: {"type": "command", "command": "curl … | sh"}`
        # is arbitrary code execution outside the sandbox. Fail-closed
        # like the hooks scan: a statusLine of any non-dict shape or
        # unrecognised type is flagged too.
        status_line = data.get("statusLine")
        if status_line is not None:
            if isinstance(status_line, dict):
                if "command" in status_line:
                    # ANY command key blocks, whatever its value shape:
                    # pre-fix a non-string command under an absent /
                    # "static" type produced zero findings — an
                    # unrecognised shape sailing through a scanner whose
                    # contract is fail-closed.
                    sl_cmd = status_line.get("command")
                    value = (_mask(sl_cmd) if isinstance(sl_cmd, str)
                             and sl_cmd else _mask(repr(sl_cmd)))
                    fs.findings.append(
                        Finding("statusLine command", value, True))
                elif status_line.get("type") not in (None, "static"):
                    keys_summary = ",".join(sorted(status_line.keys()))
                    fs.findings.append(Finding(
                        "statusLine (unrecognised shape)",
                        _truncate(keys_summary), True))
            else:
                fs.findings.append(Finding(
                    "statusLine (unrecognised shape)",
                    _truncate(repr(status_line)), True))

        # permissions.* — a repo has no business widening what a CC
        # session may do without HITL: `allow: ["Bash(*)"]` +
        # `defaultMode` remove the operator's approval gate for a
        # prompt-injected session. Allowlist of known-narrowing keys;
        # everything else (allow, defaultMode, additionalDirectories,
        # unknown future keys) blocks.
        permissions = data.get("permissions")
        if permissions is not None:
            if isinstance(permissions, dict):
                for perm_key, perm_val in permissions.items():
                    key_str = str(perm_key)
                    if key_str in _PERMISSIONS_BENIGN_KEYS:
                        continue
                    fs.findings.append(Finding(
                        f"permissions.{_truncate(key_str, limit=40)}",
                        _mask(repr(perm_val)), True))
            else:
                fs.findings.append(Finding(
                    "permissions (unrecognised shape)",
                    _truncate(repr(permissions)), True))

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
                # Prefix families (RAPTOR_/SAGE_/CLAUDE_CODE_USE_/
                # OTEL_EXPORTER_OTLP_) are flagged regardless of the
                # specific var — see _DANGEROUS_ENV_PREFIXES. The
                # credential-redirect SHAPE rule is the belt over the
                # name enumeration: a repo-supplied env key that looks
                # like a credential / credential-config pointer
                # (FOO_API_TOKEN, BAR_CONFIG_FILE) is credential
                # substitution or redirect for whatever tool reads it,
                # and settings.json env has no legitimate reason to
                # carry one — fail closed on the shape.
                if (key_upper in dangerous_upper
                        or key_upper.startswith(_DANGEROUS_ENV_PREFIXES)
                        or is_credential_redirect_shaped(key_str)
                        or is_model_traffic_redirect_shaped(key_str)):
                    k = _truncate(key_str, limit=40)
                    # keep=0: the env VALUE is the secret — the key
                    # name alone carries the triage signal.
                    fs.findings.append(Finding(f"env {k}", _mask(str(env_val), keep=0), True))
    except Exception:
        # Display-time crash → fail-closed (caller treats None as
        # ``(malformed) / treated as dangerous`` per the
        # ``scanned is None`` branch in ``_scan_cached``).
        # Pre-fix the failure was completely silent — a code bug
        # (TypeError, RecursionError, MemoryError) collapsed to
        # "no findings" with no breadcrumb, leaving operators with
        # an unexplained blocking verdict on a benign repo.
        _logger.warning(
            "cc_trust._scan_settings: scan crashed on %s; treating as dangerous",
            path,
            exc_info=True,
        )
        return None
    return fs


def _scan_mcp(path: Path, raw: bytes | None = None) -> FileScan | None:
    data, ok = _load_json(path, raw)
    if not ok or data is None:
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
                    # Command lines carry tokens in args; URLs carry
                    # them in userinfo/path/query; unknown configs may
                    # embed them anywhere (env, headers) — all masked.
                    fs.findings.append(Finding(f'stdio server "{n}"', _mask(" ".join(parts)), True))
                elif "url" in cfg:
                    fs.findings.append(Finding(f'url server "{n}"', _mask_url(str(cfg.get("url", ""))), False))
                else:
                    fs.findings.append(Finding(f'unknown server "{n}"', _mask(repr(cfg)), True))
    except Exception:
        # Display-time crash → fail-closed. See _scan_settings above
        # for the same rationale.
        _logger.warning(
            "cc_trust._scan_mcp: scan crashed on %s; treating as dangerous",
            path,
            exc_info=True,
        )
        return None
    return fs


def check_repo_claude_trust(repo_path: str, trust_override: bool | None = None) -> bool:
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
    if trust_override is None:
        trust_override = _trust_override_set
    # A SUPPLIED target the checker cannot resolve or stat is refused,
    # not waved through: these lanes previously returned "clean", but
    # that verdict had examined nothing — a vanished (TOCTOU),
    # mistyped, or pathological path skipped the gate entirely while
    # the caller went on to use the same spelling. The trust override
    # downgrades to warn-and-proceed exactly like a real finding, so
    # the launcher's "Override: --trust-repo" hint stays truthful.
    try:
        resolved = str(Path(repo_path).resolve())
        os.stat(resolved)
    except (ValueError, OSError) as e:
        reason = getattr(e, "strerror", None) or type(e).__name__
        shown = _truncate(_safe(repo_path), limit=200)
        if trust_override:
            print(f"raptor: cannot examine {shown} for Claude Code "
                  f"config ({_safe(str(reason))}) — proceeding "
                  f"(trust override active)")
            return False
        # Caller-neutral phrasing: some call sites use the return only
        # as an early warning and enforce at later re-check sites.
        print(f"raptor: cannot examine {shown} for Claude Code "
              f"config ({_safe(str(reason))}) — treating as dangerous")
        return True
    scans, any_blocking = _scan_cached(resolved,
                                       _read_config_state(Path(resolved)))
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


def _config_candidates(target: Path) -> list[tuple[str, Path]]:
    """The authoritative (kind, path) list of config files this scanner
    reads. Single source for both the scan and the cache fingerprint —
    a file added here is automatically fingerprinted."""
    return [
        ("settings", target / ".claude" / "settings.json"),
        ("settings", target / ".claude" / "settings.local.json"),
        ("mcp",      target / ".mcp.json"),
    ]


def _read_config_state(target: Path) -> tuple:
    """One-pass read of the candidate config files, in candidate order.

    Each entry is a self-describing tuple:
        ("absent",)              — no object at the path
        ("symlink", target_str)  — symlink (never followed)
        ("unreadable",)          — non-regular / oversized / IO error
        ("content", raw_bytes)   — the file's exact bytes (capped)

    The tuple is BOTH the cache key and the scan input: the same
    process runs untrusted target code and LLM-driven sessions that
    can WRITE these files between the first trust check and later CC
    dispatches, so a verdict cached on the path alone would go stale
    (TOCTOU). The previous fingerprint keyed on lstat (mtime_ns, size)
    — both forgeable by the exact writer the fingerprint defends
    against: a same-size hook swap + os.utime ns-restore reused the
    stale SAFE verdict. Content keys the cache instead, and because
    the verdict is computed over the SAME read (never a second disk
    read), a mid-check swap cannot poison a key with another
    content's verdict.
    """
    entries: list[tuple] = []
    for _kind, p in _config_candidates(target):
        try:
            st = os.lstat(p)
        except OSError as e:
            # Only "nothing there" means absent. Any other lstat
            # failure (EACCES, EIO, ELOOP, ...) means a candidate
            # EXISTS in some form the checker cannot see — and the CC
            # session (same uid, a later moment, possibly changed
            # modes) might read it fine. "absent" would wave that
            # through; classify unreadable, which the scanner already
            # treats as dangerous.
            if e.errno in (errno.ENOENT, errno.ENOTDIR):
                entries.append(("absent",))
            else:
                entries.append(("unreadable",))
            continue
        if stat.S_ISLNK(st.st_mode):
            try:
                tgt = os.readlink(p)
            except OSError:
                tgt = "<unreadable>"
            entries.append(("symlink", str(tgt)))
            continue
        raw = _read_capped(p)
        if raw is None:
            entries.append(("unreadable",))
        else:
            entries.append(("content", raw))
    return tuple(entries)


@lru_cache(maxsize=64)
def _scan_cached(resolved_path: str,
                 config_state: tuple) -> tuple[tuple["FileScan", ...], bool]:
    """Pure scan: returns (scans, any_blocking). Cached on
    (resolved_path, config_state) where the state carries the config
    files' CONTENT (see `_read_config_state`) — the verdict is derived
    from exactly the bytes in the key, so any config change forces a
    re-scan and no stat-forgeable fingerprint can revive a stale
    verdict. Side-effect free so repeated cache hits don't suppress
    operator-visible warnings (handled in the caller)."""
    target = Path(resolved_path)
    if target == _RAPTOR_DIR:
        return ((), False)

    candidates = _config_candidates(target)
    scans: list[FileScan] = []
    for (kind, path), state in zip(candidates, config_state):
        shape = state[0]
        if shape == "absent":
            continue
        fs = FileScan(path=path)
        if shape == "symlink":
            fs.findings.append(
                Finding("symlink", _truncate(state[1], limit=120), True))
            scans.append(fs)
            continue
        if shape == "unreadable":
            fs.findings.append(
                Finding("(malformed)", "treated as dangerous", True))
            scans.append(fs)
            continue
        raw = state[1]
        scanned = (_scan_settings(path, raw) if kind == "settings"
                   else _scan_mcp(path, raw))
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
        if not fs.findings:
            continue
        label_w = max(len(f.label) for f in fs.findings) + 2
        for f in fs.findings:
            print(f"    {f.label:<{label_w}}{f.value}")
