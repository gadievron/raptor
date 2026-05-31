"""Auto-detect whether an analysis target is a *library* (its public/exported
surface is the API consumers call) versus an *application* (entry points are
``main`` / CLI / framework dispatch).

Drives the ``auto`` setting of ``build_inventory(treat_exports_as_entries=)``:
when the operator does not force the flag, we sniff the per-ecosystem package
manifests and turn library mode on only when there is a positive library
signal.

FN-safety (why the asymmetry is safe): library mode only *promotes* exported
symbols toward reachable. A wrong "library" verdict over-analyses a few dead
public methods (a precision cost); a wrong "application" verdict just keeps
today's surface-only behaviour. Neither can suppress a live function. We
therefore require a positive library signal and otherwise stay OFF — that
matches the pre-auto default, so single-file targets, apps, and the synthetic
test fixtures (which carry no manifest) are unchanged.

Static + read-only: we parse manifest files (``package.json``,
``pyproject.toml``, ``*.csproj``, ``composer.json``, ``pom.xml``,
``build.gradle``, ``setup.py``/``setup.cfg``). No subprocess, no code
execution, no shell — safe on untrusted repos. Paths come from a bounded
``pathlib`` walk inside the target root; symlinks are skipped (no
traversal-read of out-of-tree files) and nothing is interpolated into a shell.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

_ON_WORDS = frozenset({"on", "true", "yes", "1", "enable", "enabled"})
_OFF_WORDS = frozenset({"off", "false", "no", "0", "disable", "disabled"})

# Directories never worth descending for manifests. Mirrors the dir entries of
# exclusions.DEFAULT_EXCLUDES (kept as a local exact-match frozenset for speed).
# Critically includes test/fixture/example dirs: a target's OWN test fixtures
# frequently carry foreign manifests (e.g. a struts CVE pom.xml under
# test/data/) that must not drive the host project's library verdict.
_SKIP_DIRS = frozenset({
    # vendored deps
    "node_modules", "vendor", "third_party", "third-party", "deps",
    "dependencies", "external", "site-packages",
    # build output
    "dist", "build", "target", "out", "output", "bin", "obj",
    # virtualenvs / caches
    ".venv", "venv", "env", "virtualenv", ".tox", ".eggs", "__pycache__",
    ".pytest_cache",
    # VCS / editor
    ".git", ".svn", ".hg", ".bzr", ".idea", ".vscode", ".vs",
    # tests / fixtures / examples / generated — foreign manifests live here
    "test", "tests", "__tests__", "spec", "testing", "fixtures",
    "__fixtures__", "testdata", "test-data", "examples", "example",
    "samples", "sample", "demo", "demos", "generated", "gen", "autogen",
})

# Bound the walk so a pathological / hostile tree can't turn detection into a
# DoS, and cap per-category manifests + per-file read size for the same reason.
_MAX_DIRS = 4000
_MAX_PER_CAT = 100
_MAX_MANIFEST_BYTES = 2_000_000


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return p.name


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _collect_manifests(root: Path) -> Dict[str, List[Path]]:
    """One bounded, vendor-skipping walk that buckets manifest files by kind.

    A single walk (rather than one per ecosystem) keeps the cost bounded
    regardless of how many ecosystems are present.
    """
    out: Dict[str, List[Path]] = {
        "npm": [], "pyproject": [], "setup": [], "csproj": [],
        "composer": [], "pom": [], "gradle": [], "pymain": [],
    }
    seen = 0
    stack: List[Path] = [root]
    while stack and seen < _MAX_DIRS:
        d = stack.pop()
        seen += 1
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir():
                    if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                        stack.append(e)
                    continue
                n = e.name
                if n == "package.json":
                    out["npm"].append(e)
                elif n == "pyproject.toml":
                    out["pyproject"].append(e)
                elif n in ("setup.py", "setup.cfg"):
                    out["setup"].append(e)
                elif n.endswith(".csproj"):
                    out["csproj"].append(e)
                elif n == "composer.json":
                    out["composer"].append(e)
                elif n == "pom.xml":
                    out["pom"].append(e)
                elif n in ("build.gradle", "build.gradle.kts"):
                    out["gradle"].append(e)
                elif n == "__main__.py":
                    out["pymain"].append(e)
            except OSError:
                continue
    for k in out:
        out[k] = out[k][:_MAX_PER_CAT]
    return out


# Per-ecosystem verdicts. ``library`` and ``application`` are the pure cases;
# ``hybrid`` means a target that ships BOTH a consumable API surface and a CLI/
# app entry (e.g. an npm package with ``main`` AND ``bin``, or a Python package
# with ``console_scripts``). A hybrid IS a library for our purposes — its public
# API is consumed externally — so library mode is enabled for it; the app entry
# is additive (reachability keeps main/CLI as entries too). ``None`` = the
# ecosystem contributes no signal.


def _check_npm(manifests, root):
    """package.json: main/module/exports = library surface; ``bin`` = CLI."""
    for p in manifests["npm"]:
        text = _read_text(p)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        has_lib = any(k in data for k in
                      ("main", "module", "exports", "types", "typings"))
        has_bin = bool(data.get("bin"))
        rel = _rel(p, root)
        if has_lib and has_bin:
            return ("hybrid", f"{rel}: library entry + bin (CLI)")
        if has_lib:
            return ("library", f"{rel}: library entry (main/module/exports)")
        if has_bin:
            return ("application", f"{rel}: bin-only (CLI)")
    return (None, "")


def _check_python(manifests, root):
    """Distributable package = library surface; console_scripts /
    [project.scripts] / __main__.py = app entry. Both → hybrid (a packaged CLI
    that is also importable, e.g. black/pytest)."""
    package = ""
    app = ""
    if manifests["pymain"]:
        app = f"{_rel(manifests['pymain'][0], root)}"
    for p in manifests["pyproject"]:
        text = _read_text(p) or ""
        if (re.search(r"(?m)^\s*\[project\]", text)
                or re.search(r"(?m)^\s*\[tool\.poetry\]", text)):
            package = package or f"{_rel(p, root)} ([project]/[tool.poetry])"
        if (re.search(r"(?m)^\s*\[project\.(gui-)?scripts\]", text)
                or re.search(r"(?m)^\s*\[tool\.poetry\.scripts\]", text)):
            app = app or f"{_rel(p, root)} ([project.scripts])"
    for p in manifests["setup"]:
        text = _read_text(p) or ""
        if (re.search(r"\b(packages|py_modules)\s*=", text)
                or re.search(r"(?m)^\s*packages\s*=", text)):
            package = package or f"{_rel(p, root)} (packages=)"
        if "console_scripts" in text or "gui_scripts" in text:
            app = app or f"{_rel(p, root)} (console_scripts)"
    if package and app:
        return ("hybrid", f"Python package {package} + app entry {app}")
    if package:
        return ("library", f"Python package: {package}")
    if app:
        return ("application", f"Python app entry: {app}")
    return (None, "")


def _check_csharp(manifests, root):
    """Library iff any .csproj is OutputType=Library (or a bare
    Microsoft.NET.Sdk classlib); Exe/WinExe/Web/Worker → application. A solution
    carrying both → hybrid."""
    lib = ""
    app = ""
    for p in manifests["csproj"]:
        text = _read_text(p)
        if text is None:
            continue
        rel = _rel(p, root)
        m = re.search(r"<OutputType>\s*([A-Za-z]+)\s*</OutputType>", text, re.I)
        if m:
            if m.group(1).lower() == "library":
                lib = lib or f"{rel} (OutputType=Library)"
            else:
                app = app or f"{rel} (OutputType={m.group(1)})"
            continue
        # No OutputType: bare Microsoft.NET.Sdk defaults to Library; the
        # trailing quote keeps Sdk.Web / Sdk.Worker (apps) from matching.
        if re.search(r'Sdk\s*=\s*"Microsoft\.NET\.Sdk"', text, re.I):
            lib = lib or f"{rel} (SDK class library)"
        elif re.search(r'Sdk\s*=\s*"Microsoft\.NET\.Sdk\.(Web|Worker)"', text, re.I):
            app = app or f"{rel} (Web/Worker SDK)"
    if lib and app:
        return ("hybrid", f"C# library {lib} + app {app}")
    if lib:
        return ("library", f"C#: {lib}")
    if app:
        return ("application", f"C#: {app}")
    return (None, "")


def _check_php(manifests, root):
    """composer.json: autoload = library surface; ``bin`` = CLI; ``type:
    project`` (Symfony/Laravel) = application. autoload + bin → hybrid."""
    for p in manifests["composer"]:
        text = _read_text(p)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        rel = _rel(p, root)
        if data.get("type") == "project":
            return ("application", f"{rel}: composer type=project")
        has_lib = bool(data.get("autoload") or data.get("autoload-dev"))
        has_bin = bool(data.get("bin"))
        if has_lib and has_bin:
            return ("hybrid", f"{rel}: composer autoload + bin (CLI)")
        if has_lib:
            t = data.get("type") or "library (default)"
            return ("library", f"{rel}: composer autoload, type={t}")
        if has_bin:
            return ("application", f"{rel}: composer bin-only (CLI)")
    return (None, "")


def _check_java(manifests, root, has_main):
    """Maven jar / Gradle (no ``application`` plugin) with no ``main`` method →
    library. war/ear or a ``main`` method → application. Java lib+CLI hybrids
    aren't reliably distinguishable from manifests, so we stay conservative
    (no hybrid verdict here)."""
    for p in manifests["pom"]:
        text = _read_text(p)
        if text is None:
            continue
        m = re.search(r"<packaging>\s*([a-z]+)\s*</packaging>", text, re.I)
        packaging = m.group(1).lower() if m else "jar"  # Maven default = jar
        if packaging in ("war", "ear"):
            return ("application", f"{_rel(p, root)}: Maven {packaging}")
        if has_main:
            return ("application", f"{_rel(p, root)}: Maven {packaging} with main()")
        return ("library", f"{_rel(p, root)}: Maven {packaging}, no main()")
    for p in manifests["gradle"]:
        text = _read_text(p)
        if text is None:
            continue
        if re.search(r"""(?:id|plugin:)\s*['"]application['"]""", text):
            return ("application", f"{_rel(p, root)}: Gradle application plugin")
        if has_main:
            return ("application", f"{_rel(p, root)}: Gradle build with main()")
        return ("library", f"{_rel(p, root)}: Gradle build, no main()")
    return (None, "")


def _has_java_main(files_info: Optional[List[Dict[str, Any]]]) -> bool:
    for f in files_info or []:
        if not isinstance(f, dict):
            continue
        if f.get("language") not in ("java", "kotlin"):
            continue
        for it in f.get("items", []) or []:
            if isinstance(it, dict) and it.get("name") == "main":
                return True
    return False


def detect_target_kind(
    target_path: str,
    files_info: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, str]:
    """Classify a target as ``library`` | ``hybrid`` | ``application`` |
    ``unknown`` from its package manifests, with a human ``reason``.

    ``hybrid`` (the seer / black / eslint case): ships both a consumable API
    surface AND a CLI/app entry. A hybrid is treated as a library for
    export-promotion (its public API is consumed externally) while the app
    entry remains an entry too — the two are additive.

    Note: only the dynamic/JVM ecosystems carry a lib-vs-app manifest signal.
    A C/C++/Makefile project returns ``unknown`` here — but that's harmless for
    reachability, which classifies native code by sound linkage (non-static =
    entry, ``main`` = entry) regardless of this verdict. ``files_info`` is used
    only for the Java/Kotlin "no main method" discriminator.
    """
    root = Path(target_path)
    if not root.exists():
        return ("unknown", "target path does not exist")
    if root.is_file():
        return ("unknown", "single-file target: no package manifest")

    manifests = _collect_manifests(root)
    has_main = _has_java_main(files_info)
    checks = (
        lambda: _check_npm(manifests, root),
        lambda: _check_python(manifests, root),
        lambda: _check_csharp(manifests, root),
        lambda: _check_php(manifests, root),
        lambda: _check_java(manifests, root, has_main),
    )
    lib_reasons: List[str] = []
    app_reasons: List[str] = []
    for fn in checks:
        try:
            verdict, reason = fn()
        except Exception:  # detection must never break the inventory build
            verdict, reason = None, ""
        if verdict == "hybrid":
            lib_reasons.append(reason)
            app_reasons.append(reason)
        elif verdict == "library":
            lib_reasons.append(reason)
        elif verdict == "application":
            app_reasons.append(reason)

    if lib_reasons and app_reasons:
        return ("hybrid", "; ".join(lib_reasons + app_reasons))
    if lib_reasons:
        return ("library", "; ".join(lib_reasons))
    if app_reasons:
        return ("application", "; ".join(app_reasons))
    return ("unknown", "no package manifest signal "
                       "(package.json/pyproject/csproj/composer/pom/gradle)")


def detect_library_target(
    target_path: str,
    files_info: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[bool, str]:
    """Back-compat bool wrapper over :func:`detect_target_kind`. Library mode is
    enabled for ``library`` and ``hybrid`` kinds (both have a consumed API)."""
    kind, reason = detect_target_kind(target_path, files_info)
    return (kind in ("library", "hybrid"), reason)


def _kind_from_token(tok: str) -> Optional[Tuple[bool, str]]:
    """Map an operator override token to ``(library_mode_enabled, kind)``, or
    ``None`` for ``auto``/unrecognised (→ fall through to detection).

    Accepts the first-class ``target_kind`` vocabulary (``library``/``hybrid``/
    ``application``) plus the legacy ``on``/``off`` aliases. ``hybrid`` enables
    library mode (its public API is consumed) exactly like ``library`` — the
    distinction is recorded in ``kind`` for the threat-model consumers (taint
    sources / attack surface / PoC shape treat a hybrid's inputs as the UNION
    of caller-controlled and app-I/O channels)."""
    t = (tok or "").strip().lower()
    if t == "library" or t in _ON_WORDS:
        return (True, "library")
    if t == "hybrid":
        return (True, "hybrid")
    if t == "application" or t in _OFF_WORDS:
        return (False, "application")
    return None


def resolve_library_mode(
    setting: Union[bool, str, None],
    target_path: str,
    files_info: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Resolve the ``treat_exports_as_entries`` setting to a record
    ``{enabled, source, reason, kind}``.

    The setting accepts ``True``/``False`` (back-compat), ``auto`` (default),
    or an explicit kind: ``library``/``hybrid``/``application`` (``on``/``off``
    are aliases for library/application). Precedence: an explicit programmatic
    value wins; otherwise (``auto``) the operator's ``RAPTOR_TARGET_KIND`` env
    override is consulted — the escape hatch for when auto-detection is wrong,
    and the only way to assert ``hybrid`` on a target whose manifest hides it
    (e.g. seer's C lib+CLI behind a pure-library Python binding) — and only if
    that too is unset/``auto`` do we run :func:`detect_target_kind`.
    """
    if setting is True:
        return {"enabled": True, "source": "operator", "reason": "forced library",
                "kind": "library"}
    if setting is False:
        return {"enabled": False, "source": "operator",
                "reason": "forced application", "kind": "application"}
    mapped = _kind_from_token(str(setting or "auto"))
    if mapped is not None:
        enabled, kind = mapped
        return {"enabled": enabled, "source": "operator",
                "reason": f"forced {kind}", "kind": kind}
    # setting == "auto": operator env override beats detection.
    mapped = _kind_from_token(os.environ.get("RAPTOR_TARGET_KIND", ""))
    if mapped is not None:
        enabled, kind = mapped
        return {"enabled": enabled, "source": "operator-env",
                "reason": f"forced {kind} (RAPTOR_TARGET_KIND)", "kind": kind}
    try:
        kind, reason = detect_target_kind(target_path, files_info)
    except Exception:
        return {"enabled": False, "source": "auto", "kind": "unknown",
                "reason": "auto-detection failed (defaulting off)"}
    return {"enabled": kind in ("library", "hybrid"), "source": "auto",
            "reason": reason, "kind": kind}
