"""RAPTOR startup — environment checks and session initialisation.

Gathers system status (tools, LLM, env, active project), formats
the startup banner, writes .startup-output, and sets up CLAUDE_ENV_FILE.

Entry point: `python3 -m core.startup.init`
"""

import logging
import os
import shutil
import stat
import sys
from pathlib import Path

from . import REPO_ROOT
from .banner import format_banner, read_logo, read_random_quote

sys.path.insert(0, str(REPO_ROOT))
OUTPUT_FILE = REPO_ROOT / ".startup-output"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_tools() -> tuple[list, list, set]:
    """Check for required external tools.

    Returns (results, warnings, unavailable_features).
    """
    from core.config import RaptorConfig

    results = []
    available = set()
    for name in sorted(RaptorConfig.TOOL_DEPS):
        found = bool(shutil.which(RaptorConfig.TOOL_DEPS[name]["binary"]))
        results.append((name, found))
        if found:
            available.add(name)

    warnings = []
    unavailable_features = set()

    # Group checks (e.g., need at least one scanner)
    for group_name, group in RaptorConfig.TOOL_GROUPS.items():
        members = sorted(n for n, d in RaptorConfig.TOOL_DEPS.items() if d.get("group") == group_name)
        if not any(m in available for m in members):
            warnings.append(f"{group['affects']} unavailable — no scanner ({' or '.join(members)})")
            for cmd in group["affects"].split(", "):
                unavailable_features.add(cmd.strip())

    # Individual checks (skip group members)
    for name in sorted(RaptorConfig.TOOL_DEPS):
        dep = RaptorConfig.TOOL_DEPS[name]
        if name in available or dep.get("group"):
            continue
        severity = dep.get("severity", "degrades")
        label = "unavailable" if severity == "required" else "limited"
        warnings.append(f"{dep['affects']} {label} — {name} not found")
        if severity == "required":
            for cmd in dep["affects"].split(", "):
                unavailable_features.add(cmd.strip())

    return results, warnings, unavailable_features


def _tighten_config_perms(path: Path) -> str | None:
    """Ensure `path` is 0o600. Returns a one-line notice or None.

    Only acts on regular files owned by the current user. Symlinks are
    flagged but never chmod'd through (chmod follows links; we refuse to
    touch something we may not own). chmod failures fall back to the
    pre-existing warning form.

    Returns:
        - None if nothing to say (already tight, missing, symlink target OK).
        - A notice starting with "tightened …" on successful fix.
        - A warning starting with "⚠ …" on anything we can't fix.

    The caller routes the string; this helper does not log or print.
    """
    try:
        st = path.lstat()
    except OSError:
        return None

    if stat.S_ISLNK(st.st_mode):
        try:
            tgt_mode = path.stat().st_mode
        except OSError:
            return None
        if tgt_mode & 0o077:
            return (f"⚠ {path} is a symlink to a permissive target "
                    f"(mode {oct(tgt_mode)[-3:]}). Fix target perms manually.")
        return None

    if not (st.st_mode & 0o077):
        return None

    if st.st_uid != os.getuid():
        return (f"⚠ {path} not owned by current user "
                f"(mode {oct(st.st_mode)[-3:]}). Fix perms manually.")

    # Open with O_NOFOLLOW + fchmod to close a TOCTOU race. Pre-fix
    # the sequence was `lstat` (not a symlink) → `os.chmod(path,
    # 0o600)`. `os.chmod` follows symlinks. Between the lstat and
    # the chmod, an attacker (or a careless install script) could
    # swap the file for a symlink to e.g. `/etc/passwd` — our
    # chmod would then change perms on the swap target. ELOOP from
    # the kernel when the path is now a symlink → falls through to
    # the OSError handler with a meaningful message.
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as e:
        return (f"⚠ {path} could not be opened for chmod: {e}. "
                f"Run: chmod 600 {path}")
    try:
        os.fchmod(fd, 0o600)
    except OSError as e:
        os.close(fd)
        return (f"⚠ {path} mode {oct(st.st_mode)[-3:]} and chmod failed: {e}. "
                f"Run: chmod 600 {path}")
    os.close(fd)

    return (f"tightened {path} permissions to 600 "
            f"(was {oct(st.st_mode)[-3:]}; contains API keys)")


def check_llm() -> tuple[list, list]:
    """Check LLM availability via config file + lightweight key validation.

    Reads ~/.config/raptor/models.json directly and tests API keys with
    simple HTTP requests — avoids importing heavy SDKs (~4.5s of imports).

    Returns (lines, warnings).
    """
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    lines = []
    warnings = []

    try:
        # Read config
        config_path = Path.home() / ".config/raptor/models.json"
        models = []
        if config_path.exists():
            # Auto-tighten if readable by others (contains API keys).
            notice = _tighten_config_perms(config_path)
            if notice:
                warnings.append(notice)
            try:
                data = json.loads(config_path.read_text())
                models = data.get("models", []) if isinstance(data, dict) else data
            except (json.JSONDecodeError, OSError):
                pass

        # Also check env vars for providers not in models.json
        env_keys = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "mistral": "MISTRAL_API_KEY",
        }
        config_providers = {m.get("provider") for m in models}
        for provider, env_var in env_keys.items():
            key = os.getenv(env_var)
            if key and provider not in config_providers:
                models.append({"provider": provider, "model": "default", "api_key": key, "_from_env": True})

        if models:
            # Validate keys in parallel
            key_status = {}
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {}
                seen = set()
                for m in models:
                    provider = m.get("provider", "unknown")
                    api_key = m.get("api_key") or os.getenv(env_keys.get(provider, ""))
                    if not api_key or provider in seen:
                        continue
                    seen.add(provider)
                    futures[pool.submit(_test_key, provider, api_key, m.get("api_base"))] = provider
                # `as_completed(timeout=5)` is an AGGREGATE
                # timeout — applies to the iterator, not to
                # individual futures. Pre-fix: with 5 providers
                # configured, timeout=5 covered ALL of them
                # collectively, so a single slow provider
                # (network-misconfigured Anthropic endpoint
                # taking 5s to fail-DNS) consumed the whole
                # budget and the remaining providers never had
                # their results collected — they got marked
                # False as if THEIR keys failed.
                #
                # Wrap each `future.result()` in its own
                # per-task `timeout=5` so each provider gets a
                # full 5-second budget independent of others.
                # The outer as_completed's timeout still bounds
                # total wall-clock at ~5×N seconds worst case
                # (acceptable for startup banner).
                for future in as_completed(futures):
                    provider = futures[future]
                    try:
                        key_status[provider] = future.result(timeout=5)
                    except Exception:
                        key_status[provider] = False

            # Build output lines (same format as before)
            primary = models[0]
            provider = primary.get("provider", "unknown")
            model = primary.get("model", primary.get("model_name", "unknown"))
            src = _key_source(provider, primary)
            lines.append(f"   llm: {provider}/{model} (primary, {src})")

            if key_status.get(provider) is False:
                warnings.append(f"{provider} API key validation failed")

            for fm in models[1:4]:
                fp = fm.get("provider", "unknown")
                fn = fm.get("model", fm.get("model_name", "unknown"))
                if f"{fp}/{fn}" != f"{provider}/{model}":
                    role = fm.get("role", "fallback")
                    lines.append(f"        {fp}/{fn} ({role}, {_key_source(fp, fm)})")
                    if key_status.get(fp) is False:
                        warnings.append(f"{fp} API key validation failed")
        else:
            lines.append("   llm: no external LLM configured")

        if shutil.which("claude"):
            lines.append("        claude code ✓")

    except Exception as e:
        lines.append("   llm: detection error")
        warnings.append(f"LLM detection: {e}")

    return lines, warnings


def _test_key(provider: str, api_key: str, api_base: str = None) -> bool:
    """Lightweight API key smoke test — no SDK imports."""
    import requests

    timeout = 3
    try:
        if provider == "gemini":
            # Use `x-goog-api-key` header rather than `?key=...` query
            # parameter. Both are documented; the header form keeps the
            # key out of any logs that capture URLs:
            #   * Gemini's server-side access logs.
            #   * Any HTTPS proxy in the path that captures CONNECT
            #     URLs (uncommon but seen on corporate gateways).
            #   * Downstream debugging tools (curl --trace, requests'
            #     hooks, anything that re-renders the request line).
            # The TLS encryption protects the bytes in transit; the
            # logging exposure is at endpoints.
            r = requests.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": api_key},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "openai":
            base = (api_base or "https://api.openai.com").rstrip("/")
            r = requests.get(
                f"{base}/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "anthropic":
            r = requests.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "mistral":
            r = requests.get(
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "ollama":
            base = (api_base or "http://localhost:11434").rstrip("/")
            r = requests.get(f"{base}/api/tags", timeout=timeout)
            return r.status_code == 200
        else:
            return True  # Unknown provider — can't test, assume OK
    except requests.RequestException:
        return False


def _key_source(provider: str, model_entry: dict = None) -> str:
    if provider == "ollama":
        return "local"
    env_keys = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "mistral": "MISTRAL_API_KEY",
    }
    if model_entry and model_entry.get("_from_env"):
        return f"via {env_keys.get(provider, 'env')}"
    env_var = env_keys.get(provider, "")
    if env_var and os.getenv(env_var):
        return f"via {env_var}"
    return "via models.json"


def check_env(unavailable_features: set) -> tuple[list, list]:
    """Check environment: output dir, disk, config vars, tree-sitter.

    Returns (env_parts, warnings).
    """
    from core.config import RaptorConfig

    parts = []
    warnings = []

    # Discourage running as root — RAPTOR executes untrusted code
    if os.getuid() == 0:
        warnings.append("Running as root is strongly discouraged — RAPTOR executes untrusted build commands, compiles PoCs, and runs fuzzing targets")

    # Python version. RAPTOR requires 3.10+: ``packages/
    # exploitability_validation/schemas.py`` (and other sites)
    # uses PEP 604 union syntax (``str | None``) at function-
    # definition time without ``from __future__ import
    # annotations``, so the module fails to import on 3.9 with
    # a confusing ``TypeError: unsupported operand type(s) for |``.
    # Surface the version mismatch early so the operator sees
    # "wrong Python" instead of a deep import trace.
    import platform
    py_version_str = platform.python_version()
    if sys.version_info < (3, 10):
        parts.append(f"Python {py_version_str} ✗")
        warnings.append(
            f"Python {py_version_str} at {sys.executable} — RAPTOR "
            f"requires Python 3.10+. PEP 604 union syntax used in "
            f"packages/exploitability_validation/schemas.py fails "
            f"to import on older versions."
        )
    else:
        parts.append(f"Python {py_version_str} ✓")

    # RAPTOR_DIR — defensive check for the "operator bypassed the
    # wrapper" path. ``bin/raptor`` / ``libexec/*`` scripts set this
    # automatically; ``CLAUDE_ENV_FILE`` propagates it into claude-
    # spawned Bash tool calls. Only unset when someone runs
    # ``python3 raptor.py …`` (or imports core/ modules) from a
    # bare shell. Specific value computed from REPO_ROOT so the
    # operator can copy-paste the right export line.
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if not raptor_dir:
        warnings.append(
            f"RAPTOR_DIR not set in this process; expected "
            f"{REPO_ROOT} based on checkout location. Affects "
            f"direct ``python3 raptor.py …`` invocations only — "
            f"bin/raptor and claude sessions set it automatically."
        )
    else:
        resolved = Path(raptor_dir).resolve()
        if not resolved.is_dir():
            warnings.append(
                f"RAPTOR_DIR={raptor_dir!r} does not resolve to a "
                f"directory"
            )
        else:
            missing = [
                d for d in ("core", "packages", "libexec", "bin")
                if not (resolved / d).is_dir()
            ]
            if missing:
                warnings.append(
                    f"RAPTOR_DIR={raptor_dir!r} is missing expected "
                    f"directories: {', '.join(missing)}"
                )

    # No check on .claude/raptor.env or .claude/settings.json
    # despite both being part of the SessionStart hook chain.
    # Failure modes for either file missing are: operator wiped
    # it (wilful — operator knows), hook script broken (RAPTOR
    # ship-side bug, doctor advice doesn't help), claude using
    # a different project's settings (operator-config; doctor
    # advice doesn't help). None are both common-enough-to-
    # design-for AND actionable-via-doctor-output. Dropping
    # avoids noise without missing real signal.

    out_dir = RaptorConfig.get_out_dir()
    out_ok = out_dir.exists() and os.access(out_dir, os.W_OK)
    parts.append("out/ ✓" if out_ok else "out/ ✗")
    if not out_ok:
        warnings.append("out/ directory not writable")

    try:
        stat = os.statvfs(str(out_dir if out_dir.exists() else REPO_ROOT))
        free_bytes = stat.f_bavail * stat.f_frsize
        free_gb = free_bytes / (1024 ** 3)
        parts.append(f"disk {free_gb:.0f} GB free" if free_gb >= 1 else f"disk {free_bytes / (1024**2):.0f} MB free")
        if free_gb < 5 and "/fuzz" not in unavailable_features:
            warnings.append(f"Low disk space ({free_gb:.1f} GB) — fuzzing may fail")
    except OSError:
        pass

    # Operator-supplied env values flow into the startup banner that
    # gets printed to the terminal. A value containing ANSI escapes
    # (`\x1b[2J`) blanks the terminal; a value with bidi controls
    # visually re-orders the line; CR/LF splits across lines.
    # Apply `escape_nonprintable` so dangerous bytes render as
    # `\xHH` literals.
    from core.security.log_sanitisation import escape_nonprintable
    out_dir_env = os.getenv("RAPTOR_OUT_DIR")
    if out_dir_env:
        parts.append(f"RAPTOR_OUT_DIR={escape_nonprintable(out_dir_env)}")
    config_env = os.getenv("RAPTOR_CONFIG")
    if config_env:
        parts.append(f"RAPTOR_CONFIG={escape_nonprintable(config_env)}")

    if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        warnings.append("/oss-forensics unavailable — BigQuery not configured")

    # Subprocess sandboxing. Layers reported per-platform:
    #   Linux: net + mount + landlock + seccomp (any combination — see
    #     core/sandbox/__init__.py module docstring)
    #   macOS: seatbelt (single integrated layer via sandbox-exec / SBPL)
    # Probing is a one-shot subprocess (cached); we report whatever is
    # actually available rather than an all-or-nothing flag.
    try:
        if sys.platform == "darwin":
            from core.sandbox import check_seatbelt_available
            seatbelt_ok = check_seatbelt_available()
            if seatbelt_ok:
                parts.append("sandbox ✓ (seatbelt)")
            else:
                parts.append("sandbox ✗")
                warnings.append(
                    "Subprocess sandboxing unavailable — sandbox-exec "
                    "smoke test failed. Verify Command Line Tools are "
                    "installed and "
                    "`sandbox-exec -p '(version 1)(allow default)' "
                    "/usr/bin/true` succeeds on this host."
                )
        else:
            from core.sandbox import (
                check_net_available, check_mount_available,
                check_landlock_available, check_seccomp_available,
            )
            net_ok = check_net_available()
            mount_ok = check_mount_available() if net_ok else False
            landlock_ok = check_landlock_available()
            seccomp_ok = check_seccomp_available()
            features = []
            if net_ok:
                features.append("net")
            if mount_ok:
                features.append("mount")
            if landlock_ok:
                features.append("landlock")
            if seccomp_ok:
                features.append("seccomp")
            if features:
                parts.append(f"sandbox ✓ ({'+'.join(features)})")
                # Partial-sandbox warnings — name what's missing so users
                # can decide whether the gap matters for their use case.
                # (The banner's feature list already shows what IS active.)
                if not net_ok:
                    warnings.append(
                        "Sandbox network isolation missing — user "
                        "namespaces not supported on this kernel. "
                        "Subprocesses can still reach the network unless "
                        "the caller passes allowed_tcp_ports to sandbox()."
                    )
                elif not landlock_ok:
                    warnings.append(
                        "Sandbox Landlock filesystem restriction missing "
                        "— kernel does not support Landlock (needs "
                        "5.13+). Network isolation still active; writes "
                        "outside the output dir are NOT restricted."
                    )
            else:
                parts.append("sandbox ✗")
                warnings.append(
                    "Subprocess sandboxing unavailable — neither user "
                    "namespaces nor Landlock are supported on this kernel"
                )
    except Exception:
        # Never let a sandbox-probe bug kill startup, but leave a trail
        # at DEBUG so the bug is findable instead of invisible.
        logging.getLogger("core.startup").debug(
            "sandbox availability probe failed", exc_info=True
        )

    return parts, warnings


def check_lang() -> str | None:
    """Check language support (tree-sitter). Returns formatted line or None."""
    try:
        from core.inventory.extractors import _get_ts_languages
        ts_langs = _get_ts_languages()
        if ts_langs:
            return f"  lang: tree-sitter ✓ ({', '.join(ts_langs)})"
        else:
            return f"  lang: tree-sitter ✗"
    except Exception:
        return None


def check_active_project() -> str | None:
    """Return a one-line project status string, or None if no active project."""
    try:
        from . import PROJECTS_DIR, get_active_name
        name = get_active_name()
        if not name:
            return None
        from core.json import load_json
        data = load_json(PROJECTS_DIR / f"{name}.json")
        if not data:
            return None
        proj_target = data.get("target", "")
        # Bounded read of the .auto marker. Pre-fix `read_text()`
        # loaded the WHOLE file into memory before the strip+compare.
        # The marker SHOULD only ever contain a project name (a few
        # bytes) but if the file was malformed (a hostile sample, a
        # corrupted sparse file, a symlink-to-/dev/zero) the unbounded
        # read OOM-killed the entire startup banner. Read just enough
        # bytes to compare against `name + 1` so any oversize file
        # rejects via the comparison.
        auto_marker = PROJECTS_DIR / ".auto"
        if auto_marker.exists():
            try:
                cap = max(len(name) + 64, 256)
                with auto_marker.open("rb") as fh:
                    head = fh.read(cap)
                if head.decode("utf-8", errors="replace").strip() == name:
                    return f"Auto-activated project: {name} ({proj_target}) — `/project none` to clear"
            except OSError:
                pass
        return f"Project: {name} ({proj_target}) — `/project none` to clear"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Environment setup
#
# `setup_env_file()` was removed: the live code path is
# `libexec/raptor-session-init:write_env_file` which is what the
# SessionStart hook actually invokes. The duplicate Python helper here
# was never wired into anything outside its own tests, and the two
# implementations had drifted (the libexec script overwrites the env
# file unconditionally; the Python helper appended via O_NOFOLLOW). The
# divergence was a hazard — if a future caller wired `setup_env_file`
# into startup, we'd silently get two contradicting env files written
# in the same session. Keeping one source of truth (the libexec
# script) avoids that.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logo = read_logo()
    quote = read_random_quote()

    try:
        logging.disable(logging.WARNING)

        tool_results, tool_warnings, unavailable = check_tools()
        llm_lines, llm_warnings = check_llm()
        env_parts, env_warnings = check_env(unavailable)
        lang_line = check_lang()
        project_line = check_active_project()

        logging.disable(logging.NOTSET)

        output = format_banner(
            logo, quote, tool_results, tool_warnings,
            llm_lines, llm_warnings, env_parts, env_warnings,
            project_line, lang_line,
        )
    except Exception:
        output = f"{logo}\n\nraptor:~$ {quote}"

    OUTPUT_FILE.write_text(output)
    print(output)


if __name__ == "__main__":
    main()
