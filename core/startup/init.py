"""RAPTOR startup — environment checks and session initialisation.

Gathers system status (tools, LLM, env, active project), formats
the startup banner, writes .startup-output, and sets up CLAUDE_ENV_FILE.

Entry point: `python3 -m core.startup.init`
"""

import importlib.util
import logging
import os
import shutil
import stat
import sys
from pathlib import Path

from . import REPO_ROOT
from .banner import format_banner, read_logo, read_random_quote

# Byte budgets for the small local records init reads: the
# tool-versions probe cache and the operator's models.json config.
_MAX_CACHE_BYTES = 1024 * 1024
_MAX_CONFIG_BYTES = 8 * 1024 * 1024

# No sys.path mutation here: this module is only importable when the
# repo root is already importable (relative imports above prove it),
# so the former module-level insert was pure global state pollution
# for every importer.
OUTPUT_FILE = REPO_ROOT / ".startup-output"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_tools() -> tuple[list, list, set]:
    """Check for required external tools.

    Returns (results, warnings, unavailable_features). Each result is
    ``(display_name, found)`` — the display name carries a version
    suffix for the version-gated tools (see the version-display
    convention at ``RaptorConfig.TOOL_DEPS``); a missing tool is
    always the bare TOOL_DEPS key, which doctor's install-hint lookup
    relies on.
    """
    from core.config import RaptorConfig

    results = []
    available = set()
    for name in sorted(RaptorConfig.TOOL_DEPS):
        dep = RaptorConfig.TOOL_DEPS[name]
        if "module" in dep:
            # Python-module dependency (e.g. z3) — no binary to probe.
            # find_spec locates without importing, so a broken module
            # can't crash the banner. Trade-off: a present-but-broken
            # wheel shows ✓ here and fails at first import; doctor
            # (not the banner — startup stays fast) verifies module
            # deps actually import.
            found = importlib.util.find_spec(dep["module"]) is not None
        else:
            found = bool(shutil.which(dep["binary"]))
        display = name
        if found:
            available.add(name)
            ver = _tool_version(name)
            if ver:
                display = f"{name} {ver}"
        results.append((display, found))

    warnings = []
    unavailable_features = set()

    # Group checks (e.g., need at least one scanner)
    satisfied_groups = set()
    for group_name, group in RaptorConfig.TOOL_GROUPS.items():
        members = sorted(n for n, d in RaptorConfig.TOOL_DEPS.items() if d.get("group") == group_name)
        if any(m in available for m in members):
            satisfied_groups.add(group_name)
        else:
            warnings.append(f"{group['affects']} unavailable — no scanner ({' or '.join(members)})")
            for cmd in group["affects"].split(", "):
                unavailable_features.add(cmd.strip())

    # Individual checks. Warnings name the missing BINARY (what the
    # operator must install / what doctor's install-hint lookup keys
    # on), not the TOOL_DEPS key — "spatch not found", not
    # "coccinelle not found".
    for name in sorted(RaptorConfig.TOOL_DEPS):
        dep = RaptorConfig.TOOL_DEPS[name]
        if name in available:
            continue
        binary = dep.get("binary", name)
        group = dep.get("group")
        if group:
            # Group totally absent → the group warning above already
            # covers it. Group satisfied by another member → this
            # tool's OWN commands are still affected (codeql missing
            # while semgrep present used to be silent); warn.
            if group in satisfied_groups:
                warnings.append(f"{dep['affects']} limited — {binary} not found")
            continue
        severity = dep.get("severity", "degrades")
        label = "unavailable" if severity == "required" else "limited"
        warnings.append(f"{dep['affects']} {label} — {binary} not found")
        if severity == "required":
            for cmd in dep["affects"].split(", "):
                unavailable_features.add(cmd.strip())

    return results, warnings, unavailable_features


# ---------------------------------------------------------------------------
# Tool-version probes (version-gated tools only — see the convention
# at RaptorConfig.TOOL_DEPS)
# ---------------------------------------------------------------------------

def _tool_version(name: str) -> str | None:
    """Version string for the version-gated TOOL_DEPS entries.

    Returns None for every other tool (presence-only display) and on
    any probe failure — never raises into the banner.
    """
    try:
        if name == "semgrep":
            return _semgrep_version()
        if name == "joern":
            return _joern_version()
    except Exception:
        logging.getLogger("core.startup").debug(
            "%s version probe failed", name, exc_info=True
        )
    return None


def _semgrep_version() -> str | None:
    """Semgrep version — behaviour varies across releases (CI pins one).

    Prefers the pip-installed distribution metadata (free, no
    subprocess). A pipx / standalone install is invisible to
    importlib.metadata, so fall back to a disk-cached CLI probe —
    ``semgrep --version`` costs ~1s of Python CLI startup, too slow
    to pay on every banner.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("semgrep")
    except PackageNotFoundError:
        return _cached_cli_version("semgrep")


def _joern_version() -> str | None:
    """Joern version via the distribution's jar names — a directory
    glob, never a JVM boot (startup budget). ``prereqs.version()``
    is NOT used here: its fallback path launches the JVM.
    """
    from packages.joern.prereqs import _joern_path, _version_from_dist

    joern = _joern_path()
    return _version_from_dist(joern) if joern else None


def _cached_cli_version(binary: str) -> str | None:
    """Disk-cached ``<binary> --version`` probe for startup-hot paths.

    Cache key is the resolved binary's realpath + mtime_ns + size, so
    upgrades and reinstalls invalidate naturally. Cache file:
    ``$XDG_CACHE_HOME/raptor/tool-versions.json`` (default
    ``~/.cache/raptor/``, alongside the sandbox calibration cache).
    Never raises; probe failures return None and are not cached.
    """
    import json
    import re
    import subprocess
    import tempfile

    path = shutil.which(binary)
    if not path:
        return None
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError:
        return None
    key = f"{real}:{st.st_mtime_ns}:{st.st_size}"

    cache_dir = Path(
        os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    ) / "raptor"
    cache_file = cache_dir / "tool-versions.json"
    from core.json import load_json

    cache: dict = {}
    loaded = load_json(cache_file, max_bytes=_MAX_CACHE_BYTES)
    if isinstance(loaded, dict):
        cache = loaded
    hit = cache.get(binary)
    if isinstance(hit, dict) and hit.get("key") == key \
            and isinstance(hit.get("version"), str):
        return hit["version"]

    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except Exception:  # noqa: BLE001
        env = None
    try:
        proc = subprocess.run(
            [real, "--version"], capture_output=True, text=True,
            check=False, timeout=15, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or proc.stderr or "").strip()
    first = out.splitlines()[0] if out else ""
    m = re.search(r"\d+\.\d+(?:\.\d+)*", first)
    if proc.returncode != 0 or not m:
        return None
    ver = m.group(0)

    # Best-effort atomic cache write (tempfile + rename); losing the
    # cache only costs the next banner one probe.
    cache[binary] = {"key": key, "version": ver}
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(cache_dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(cache, fh)
            os.replace(tmp, cache_file)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except OSError:
        pass
    return ver


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
        return (f"⚠ {path} mode {oct(st.st_mode)[-3:]} and chmod failed: {e}. "
                f"Run: chmod 600 {path}")
    finally:
        os.close(fd)

    return (f"tightened {path} permissions to 600 "
            f"(was {oct(st.st_mode)[-3:]}; contains API keys)")


def check_llm() -> tuple[list, list]:
    """Check LLM availability via config file + lightweight key validation.

    Reads ~/.config/raptor/models.json directly and tests API keys with
    simple HTTP requests — avoids importing heavy SDKs (~4.5s of imports).

    Returns (lines, warnings).
    """
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
            from core.json import load_json
            data = load_json(config_path, max_bytes=_MAX_CONFIG_BYTES)
            if data is not None:
                models = data.get("models", []) if isinstance(data, dict) else data

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
            # Probe the validator's own prerequisite (`requests`)
            # before spinning up the threadpool. If the venv is
            # broken (Python upgraded out from under it, missing
            # install), every `_test_key` call raises ImportError
            # which the future-result handler used to swallow as
            # `False` — producing one misleading "<provider> API
            # key validation failed" per configured model, even
            # though no HTTP probe ever ran. Emit a single, clear
            # "validator unavailable" warning instead, and skip
            # the per-key probes entirely.
            validator_available = _validator_available()
            if not validator_available:
                warnings.append(
                    "LLM key validation skipped — Python `requests` "
                    "package not installed (pip install requests)"
                )

            key_status = {}
            if validator_available:
                # Validate keys in parallel
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
                    # as_completed itself has no timeout; the
                    # per-future result(timeout=5) (plus _test_key's
                    # own request timeout) bounds total wall-clock
                    # at ~5×N seconds worst case (acceptable for
                    # startup banner).
                    for future in as_completed(futures):
                        provider = futures[future]
                        try:
                            key_status[provider] = future.result(timeout=5)
                        except Exception:  # noqa: BLE001
                            key_status[provider] = False

            # Build output lines (same format as before). Dedupe
            # per-provider warnings: `key_status` is keyed by
            # provider but the model list can have multiple
            # entries for the same provider (e.g. gemini pro +
            # gemini flash). Pre-fix that emitted one identical
            # "<provider> API key validation failed" per entry,
            # which the operator reads as "two separate keys
            # failed" when in reality only one HTTP probe ran.
            warned_providers: set[str] = set()

            def _warn_key_failure(p: str) -> None:
                if p in warned_providers:
                    return
                warned_providers.add(p)
                warnings.append(f"{p} API key validation failed")

            primary = models[0]
            provider = primary.get("provider", "unknown")
            model = primary.get("model", primary.get("model_name", "unknown"))
            src = _key_source(provider, primary)
            lines.append(f"   llm: {provider}/{model} (primary, {src})")

            if validator_available and key_status.get(provider) is False:
                _warn_key_failure(provider)

            for fm in models[1:4]:
                fp = fm.get("provider", "unknown")
                fn = fm.get("model", fm.get("model_name", "unknown"))
                if f"{fp}/{fn}" != f"{provider}/{model}":
                    role = fm.get("role", "fallback")
                    lines.append(f"        {fp}/{fn} ({role}, {_key_source(fp, fm)})")
                    if validator_available and key_status.get(fp) is False:
                        _warn_key_failure(fp)
        else:
            lines.append("   llm: no external LLM configured")

        if shutil.which("claude"):
            lines.append("        claude code ✓")

    except Exception as e:  # noqa: BLE001
        lines.append("   llm: detection error")
        warnings.append(f"LLM detection: {e}")

    return lines, warnings


def _validator_available() -> bool:
    """Probe whether the validator's HTTP dep is importable.

    Extracted so tests can stub the prereq state without
    monkeypatching `builtins.__import__`. A False return means
    `_test_key` cannot run; the orchestrator should skip the
    threadpool and emit one "validation skipped" warning rather
    than one misleading "<provider> API key validation failed"
    per configured model.
    """
    try:
        import requests  # noqa: F401 — prereq probe
        return True
    except ImportError:
        return False


def _test_key(provider: str, api_key: str, api_base: str | None = None) -> bool:
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
            # All ``requests.get`` calls in this block target
            # hardcoded provider hostnames (or operator-supplied
            # ``api_base`` override for OpenAI / Ollama). Not SSRF
            # — RAPTOR owns the URL prefix; ``api_base`` is the
            # operator's own config.
            r = requests.get(  # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": api_key},
                timeout=timeout,
            )
            return r.status_code == 200
        if provider == "openai":
            base = (api_base or "https://api.openai.com").rstrip("/")
            r = requests.get(  # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
                f"{base}/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            return r.status_code == 200
        if provider == "anthropic":
            r = requests.get(  # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                timeout=timeout,
            )
            return r.status_code == 200
        if provider == "mistral":
            r = requests.get(  # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            return r.status_code == 200
        if provider == "ollama":
            base = (api_base or "http://localhost:11434").rstrip("/")
            # loopback_safe_get: bypasses proxy env for loopback URLs
            # — a plain requests.get routed localhost through the
            # corporate proxy on mandatory-proxy hosts and the probe
            # always failed. Remote Ollama bases keep proxy-env
            # behaviour.
            from core.llm.egress import loopback_safe_get
            r = loopback_safe_get(f"{base}/api/tags", timeout=timeout)  # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
            return r.status_code == 200
        return True  # Unknown provider — can't test, assume OK
    except requests.RequestException:
        return False


def _key_source(provider: str, model_entry: dict | None = None) -> str:
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
    """Check environment: output dir, disk, config vars.

    Tree-sitter language support is checked separately by
    :func:`check_lang`.

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
    if sys.version_info < (3, 10):  # noqa: UP036 — deliberate runtime guard: surface "wrong Python" to operators on old interpreters
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
                check_landlock_available,
                check_mount_available,
                check_net_available,
                check_seccomp_available,
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
            landlock_abi = 0
            if landlock_ok:
                # Surface the kernel's Landlock capability tier once
                # at startup — the per-run sandbox warnings (egress
                # allowlist advisory on ABI < 4, scoping absent on
                # ABI < 6) otherwise repeat on every run with no
                # single place to see the host tier. Reads the cache
                # check_landlock_available() just populated — free.
                from core.sandbox import _get_landlock_abi
                landlock_abi = _get_landlock_abi()
                features.append(
                    f"landlock:abi{landlock_abi}" if landlock_abi
                    else "landlock"
                )
            if seccomp_ok:
                features.append("seccomp")
            if features:
                parts.append(f"sandbox ✓ ({'+'.join(features)})")
                if landlock_ok and 0 < landlock_abi < 4:
                    warnings.append(
                        f"Landlock ABI {landlock_abi} < 4 — no kernel "
                        f"TCP allowlist; on runs without a network-"
                        f"namespace bridge the sandbox egress "
                        f"allowlist is advisory only"
                    )
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

    parts_cap, warnings_cap = _check_analyzer_capabilities()
    parts.extend(parts_cap)
    warnings.extend(warnings_cap)

    return parts, warnings


def _check_analyzer_capabilities() -> tuple[list, list]:
    """Probe compiler-analyzer capability and the z3 version.

    /audit's compiler corroboration channel needs gcc >= 10 with
    ``-fanalyzer`` (or clang) — plain binary presence is not enough,
    so this reuses ``core.audit.compiler_sweep``'s cached capability
    probes. When neither works the channel silently degrades recall;
    surface that at run start instead. z3 presence is already covered
    by TOOL_DEPS; this adds the version (SMT feature coverage is
    version-gated) without importing the module.

    Never raises; returns ``([], [...])`` shaped like check_env parts.
    """
    parts: list = []
    warnings: list = []

    try:
        from core.audit.compiler_sweep import _clang_path, _gcc_analyzer

        gcc = _gcc_analyzer()
        clang = _clang_path()
        if gcc is not None:
            # gcc is version-gated (-fanalyzer needs gcc >= 10; see
            # the convention at RaptorConfig.TOOL_DEPS) — show which
            # gcc actually passed the probe. clang stays presence-
            # only: no clang version gate exists.
            gcc_ver = _gcc_version(gcc[0])
            if gcc_ver:
                parts.append(f"analyzer ✓ (gcc {gcc_ver} -fanalyzer)")
            else:
                parts.append("analyzer ✓ (gcc -fanalyzer)")
        elif clang is not None:
            parts.append("analyzer ✓ (clang --analyze)")
        else:
            # No ✗ part: a missing analyzer degrades (warning), it is
            # not a startup failure like a broken sandbox.
            warnings.append(
                "/audit compiler-analyzer corroboration limited — no "
                "gcc -fanalyzer (needs gcc >= 10) or clang on PATH"
            )
    except Exception:
        logging.getLogger("core.startup").debug(
            "compiler-analyzer capability probe failed", exc_info=True
        )

    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            parts.append(f"z3 {version('z3-solver')} ✓")
        except PackageNotFoundError:
            # Absent z3 is already warned about via TOOL_DEPS.
            logging.getLogger("core.startup").debug("z3-solver not installed")
    except Exception:
        logging.getLogger("core.startup").debug(
            "z3 version probe failed", exc_info=True
        )

    return parts, warnings


def _gcc_version(gcc_path: str) -> str | None:
    """``gcc -dumpfullversion`` — one cheap native exec (~10 ms),
    negligible next to the -fanalyzer probes that already ran.
    Never raises; None on any failure.
    """
    import re
    import subprocess

    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except Exception:  # noqa: BLE001
        env = None
    try:
        proc = subprocess.run(
            [gcc_path, "-dumpfullversion"], capture_output=True,
            text=True, check=False, timeout=5, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = proc.stdout.strip()
    if proc.returncode == 0 and re.fullmatch(r"\d+(\.\d+)*", out):
        return out
    return None


def check_lang() -> tuple[str | None, list]:
    """Check language support (tree-sitter).

    Returns ``(formatted line or None, warnings)``. Zero installed
    grammars is a warning, not just a ✗ glyph: the inventory silently
    degrades to regex extraction (fewer functions, no line_end, so
    span-based slicing across /audit, /agentic and /understand loses
    fidelity) — a state operators repeatedly failed to notice from
    the glyph alone.
    """
    warnings: list = []
    try:
        from core.inventory.extractors import _get_ts_languages
        ts_langs = _get_ts_languages()
        if ts_langs:
            return f"  lang: tree-sitter ✓ ({', '.join(ts_langs)})", warnings
        warnings.append(
            "no tree-sitter grammars installed — inventory degrades "
            "to regex extraction (fewer functions, no spans); "
            "install the grammar wheels listed in requirements.txt "
            "(tree-sitter, tree-sitter-python, tree-sitter-c, ...)"
        )
        return "  lang: tree-sitter ✗", warnings
    except Exception:  # noqa: BLE001
        return None, warnings


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
    except Exception:  # noqa: BLE001
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

def main() -> None:
    from core.config import RaptorConfig

    logo = read_logo(RaptorConfig.effective_version())
    quote = read_random_quote()

    try:
        try:
            logging.disable(logging.WARNING)
            tool_results, tool_warnings, unavailable = check_tools()
            llm_lines, llm_warnings = check_llm()
            env_parts, env_warnings = check_env(unavailable)
            lang_line, lang_warnings = check_lang()
            project_line = check_active_project()
        finally:
            logging.disable(logging.NOTSET)

        output = format_banner(
            logo, quote, tool_results, tool_warnings,
            llm_lines, llm_warnings, env_parts,
            env_warnings + lang_warnings,
            project_line, lang_line,
        )
    except Exception:  # noqa: BLE001
        output = f"{logo}\n\nraptor:~$ {quote}"

    OUTPUT_FILE.write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
