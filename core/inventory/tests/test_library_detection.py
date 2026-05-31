"""Auto-detection of library vs application targets (drives the ``auto``
setting of build_inventory(treat_exports_as_entries=)).

The detector is manifest-only, so these tests need no tree-sitter grammar —
they write package manifests into a tmp tree and assert the verdict. FN-safety
contract under test: a positive library manifest signal flips it on; no
manifest / app marker / single file → off.
"""

from __future__ import annotations

import json

import pytest

from core.inventory.library_detection import (
    detect_library_target,
    detect_target_kind,
    resolve_library_mode,
)


def _det(tmp_path, files: dict, files_info=None):
    """Returns (library_mode_enabled, reason)."""
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return detect_library_target(str(tmp_path), files_info)


def _kind(tmp_path, files: dict, files_info=None):
    """Returns the target_kind string."""
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return detect_target_kind(str(tmp_path), files_info)[0]


# ── npm ────────────────────────────────────────────────────────────────────
def test_npm_main_is_library(tmp_path):
    ok, _ = _det(tmp_path, {"package.json": json.dumps({"name": "x", "main": "index.js"})})
    assert ok is True


def test_npm_exports_is_library(tmp_path):
    ok, _ = _det(tmp_path, {"package.json": json.dumps({"exports": "./index.js"})})
    assert ok is True


def test_npm_bin_only_is_app(tmp_path):
    ok, _ = _det(tmp_path, {"package.json": json.dumps({"name": "cli", "bin": {"cli": "c.js"}})})
    assert ok is False


def test_npm_main_and_bin_is_hybrid(tmp_path):
    # eslint/typescript shape: importable API + a CLI → hybrid (library mode ON)
    assert _kind(tmp_path, {"package.json":
                            json.dumps({"main": "i.js", "bin": {"t": "c.js"}})}) == "hybrid"


def test_npm_neither_is_not_library(tmp_path):
    ok, _ = _det(tmp_path, {"package.json": json.dumps({"name": "x", "dependencies": {}})})
    assert ok is False


def test_vendored_manifest_is_skipped(tmp_path):
    # A library package.json buried in node_modules must NOT count.
    ok, _ = _det(tmp_path, {"node_modules/dep/package.json":
                            json.dumps({"main": "i.js"})})
    assert ok is False


def test_fixture_manifest_is_skipped(tmp_path):
    # A foreign manifest under the target's OWN test fixtures must NOT drive
    # the verdict (regression: a CVE pom.xml under test/data/ flagged the host
    # repo as a library).
    ok, _ = _det(tmp_path, {"test/data/cve-fixture/pom.xml":
                            "<project><packaging>jar</packaging></project>"})
    assert ok is False


# ── python ───────────────────────────────────────────────────────────────--
def test_python_pyproject_project_is_library(tmp_path):
    assert _kind(tmp_path, {"pyproject.toml": "[project]\nname = 'x'\n"}) == "library"


def test_python_pyproject_with_scripts_is_hybrid(tmp_path):
    # package + CLI entry = hybrid (lib+CLI like black/pytest): library mode ON
    # because the public API is still consumed; the CLI entry is additive.
    assert _kind(tmp_path, {"pyproject.toml":
                            "[project]\nname='x'\n[project.scripts]\nx='x:main'\n"}) == "hybrid"


def test_python_dunder_main_is_hybrid(tmp_path):
    assert _kind(tmp_path, {"pyproject.toml": "[project]\nname='x'\n",
                            "x/__main__.py": "print(1)\n"}) == "hybrid"


def test_python_setup_packages_is_library(tmp_path):
    ok, _ = _det(tmp_path, {"setup.py": "from setuptools import setup\nsetup(packages=['x'])\n"})
    assert ok is True


def test_python_setup_console_scripts_is_hybrid(tmp_path):
    assert _kind(tmp_path, {"setup.py":
                            "setup(packages=['x'], entry_points={'console_scripts': ['c=x:m']})\n"}) == "hybrid"


def test_python_console_script_no_package_is_app(tmp_path):
    # app entry, no distributable package → pure application
    assert _kind(tmp_path, {"x/__main__.py": "print(1)\n"}) == "application"


# ── c# ───────────────────────────────────────────────────────────────────--
def test_csharp_library_outputtype(tmp_path):
    ok, _ = _det(tmp_path, {"L.csproj": "<Project><PropertyGroup><OutputType>Library</OutputType></PropertyGroup></Project>"})
    assert ok is True


def test_csharp_exe_is_app(tmp_path):
    ok, _ = _det(tmp_path, {"A.csproj": "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>"})
    assert ok is False


def test_csharp_sdk_classlib_default_is_library(tmp_path):
    ok, _ = _det(tmp_path, {"L.csproj": '<Project Sdk="Microsoft.NET.Sdk"></Project>'})
    assert ok is True


def test_csharp_sdk_web_is_app(tmp_path):
    ok, _ = _det(tmp_path, {"W.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>'})
    assert ok is False


# ── php ──────────────────────────────────────────────────────────────────--
def test_php_type_library(tmp_path):
    ok, _ = _det(tmp_path, {"composer.json":
                            json.dumps({"type": "library", "autoload": {"psr-4": {}}})})
    assert ok is True


def test_php_type_project_is_app(tmp_path):
    ok, _ = _det(tmp_path, {"composer.json":
                            json.dumps({"type": "project", "autoload": {"psr-4": {}}})})
    assert ok is False


def test_php_default_type_with_autoload_is_library(tmp_path):
    ok, _ = _det(tmp_path, {"composer.json": json.dumps({"autoload": {"psr-4": {}}})})
    assert ok is True


def test_php_autoload_and_bin_is_hybrid(tmp_path):
    assert _kind(tmp_path, {"composer.json":
                            json.dumps({"autoload": {"psr-4": {}}, "bin": ["bin/c"]})}) == "hybrid"


def test_php_bin_only_is_app(tmp_path):
    assert _kind(tmp_path, {"composer.json":
                            json.dumps({"bin": ["bin/c"]})}) == "application"


# ── java (uses the "no main()" discriminator) ──────────────────────────────-
def test_java_jar_no_main_is_library(tmp_path):
    ok, why = _det(tmp_path, {"pom.xml": "<project><packaging>jar</packaging></project>"})
    assert ok is True and "no main()" in why


def test_java_with_main_is_app(tmp_path):
    info = [{"language": "java", "items": [{"name": "main"}]}]
    ok, _ = _det(tmp_path, {"pom.xml": "<project><packaging>jar</packaging></project>"}, info)
    assert ok is False


def test_java_war_is_app(tmp_path):
    ok, _ = _det(tmp_path, {"pom.xml": "<project><packaging>war</packaging></project>"})
    assert ok is False


def test_java_gradle_application_plugin_is_app(tmp_path):
    ok, _ = _det(tmp_path, {"build.gradle": "plugins { id 'application' }\n"})
    assert ok is False


def test_java_gradle_no_app_is_library(tmp_path):
    ok, _ = _det(tmp_path, {"build.gradle": "plugins { id 'java-library' }\n"})
    assert ok is True


# ── edge cases ─────────────────────────────────────────────────────────────
def test_single_file_target_is_not_library(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("def f(): pass\n")
    ok, _ = detect_library_target(str(f))
    assert ok is False


def test_no_manifest_is_not_library(tmp_path):
    (tmp_path / "x.py").write_text("def f(): pass\n")
    ok, _ = detect_library_target(str(tmp_path))
    assert ok is False


def test_nonexistent_target(tmp_path):
    ok, _ = detect_library_target(str(tmp_path / "nope"))
    assert ok is False


def test_malformed_manifest_does_not_raise(tmp_path):
    ok, _ = _det(tmp_path, {"package.json": "{not json", "pyproject.toml": "[broken"})
    assert ok is False  # unparseable → no signal, no exception


# ── override resolution ──────────────────────────────────────────────────--
@pytest.mark.parametrize("setting,enabled,kind", [
    (True, True, "library"),
    (False, False, "application"),
    ("on", True, "library"),
    ("off", False, "application"),
    ("ON", True, "library"),
    ("disabled", False, "application"),
    ("library", True, "library"),
    ("hybrid", True, "hybrid"),       # hybrid enables library mode, records hybrid
    ("application", False, "application"),
    ("Hybrid", True, "hybrid"),       # case-insensitive
])
def test_resolve_forced(tmp_path, setting, enabled, kind):
    r = resolve_library_mode(setting, str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (enabled, "operator", kind)


def test_resolve_auto_on_library(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    r = resolve_library_mode("auto", str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (True, "auto", "library")


def test_resolve_auto_off_bare(tmp_path):
    (tmp_path / "x.py").write_text("def f(): pass\n")
    r = resolve_library_mode("auto", str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (False, "auto", "unknown")


def test_resolve_env_override_library_beats_detection(tmp_path, monkeypatch):
    # A bare app dir auto-detects unknown→off, but the operator env forces it.
    (tmp_path / "x.py").write_text("def f(): pass\n")
    monkeypatch.setenv("RAPTOR_TARGET_KIND", "library")
    r = resolve_library_mode("auto", str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (True, "operator-env", "library")


def test_resolve_env_override_hybrid(tmp_path, monkeypatch):
    # The seer case: operator asserts hybrid on a dir the manifest can't show.
    monkeypatch.setenv("RAPTOR_TARGET_KIND", "hybrid")
    r = resolve_library_mode("auto", str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (True, "operator-env", "hybrid")


def test_resolve_env_override_application_beats_detection(tmp_path, monkeypatch):
    # A library dir auto-detects library→on, but the operator env forces off.
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    monkeypatch.setenv("RAPTOR_TARGET_KIND", "application")
    r = resolve_library_mode("auto", str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (False, "operator-env", "application")


def test_resolve_explicit_arg_beats_env(tmp_path, monkeypatch):
    # An explicit programmatic value wins over the env override.
    monkeypatch.setenv("RAPTOR_TARGET_KIND", "library")
    r = resolve_library_mode("application", str(tmp_path))
    assert (r["enabled"], r["source"], r["kind"]) == (False, "operator", "application")


# ── builder integration (stdlib Python extractor → no grammar needed) ──────-
def _build(tmp_path, **kw):
    from core.inventory.builder import build_inventory
    return build_inventory(str(tmp_path), str(tmp_path / "_out"), **kw)


def _verdict(inv, name):
    from core.inventory.reach_audit import classify_reachability
    for f in inv["files"]:
        mod = ".".join(f["path"].rsplit(".", 1)[0].split("/"))
        for it in f["items"]:
            if it.get("name") == name:
                return classify_reachability(inv, f["path"], name,
                                             int(it.get("line_start") or 0), mod)
    return None


def test_build_auto_enables_on_python_library(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'mylib'\n")
    (tmp_path / "mylib.py").write_text("def public_api():\n    return 1\n")
    inv = _build(tmp_path)  # default treat_exports_as_entries="auto"
    assert inv["target_kind"] == "library"
    assert inv["target_kind_source"] == "auto"
    assert inv["treat_exports_as_entries"] is True
    assert _verdict(inv, "public_api") == "reachable"  # export = entry


def test_build_auto_hybrid_enables_library_mode(tmp_path):
    # lib + CLI (the seer/black shape) → hybrid → library mode ON, so the
    # public API is credited as reachable even though there's also a CLI entry.
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='tool'\n[project.scripts]\ntool='tool:cli'\n")
    (tmp_path / "tool.py").write_text("def public_api():\n    return 1\n")
    inv = _build(tmp_path)
    assert inv["target_kind"] == "hybrid"
    assert inv["treat_exports_as_entries"] is True
    assert _verdict(inv, "public_api") == "reachable"


def test_build_auto_off_without_manifest(tmp_path):
    (tmp_path / "app.py").write_text("def public_api():\n    return 1\n")
    inv = _build(tmp_path)
    assert inv["target_kind"] == "unknown"
    assert inv["target_kind_source"] == "auto"
    assert inv["treat_exports_as_entries"] is False
    assert _verdict(inv, "public_api") == "not_called"  # app default unchanged


def test_build_operator_off_overrides_library(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'mylib'\n")
    (tmp_path / "mylib.py").write_text("def public_api():\n    return 1\n")
    inv = _build(tmp_path, treat_exports_as_entries="off")
    assert inv["target_kind"] == "application"
    assert inv["target_kind_source"] == "operator"
    assert inv["treat_exports_as_entries"] is False
    assert _verdict(inv, "public_api") == "not_called"


def test_build_operator_bool_true_back_compat(tmp_path):
    (tmp_path / "app.py").write_text("def public_api():\n    return 1\n")
    inv = _build(tmp_path, treat_exports_as_entries=True)  # legacy bool
    assert inv["target_kind"] == "library"
    assert inv["target_kind_source"] == "operator"
    assert _verdict(inv, "public_api") == "reachable"


def test_build_operator_forces_hybrid(tmp_path):
    # seer case asserted by the operator: hybrid → library mode on + kind=hybrid
    # recorded (so the threat-model consumers see the union of input channels).
    (tmp_path / "app.py").write_text("def public_api():\n    return 1\n")
    inv = _build(tmp_path, treat_exports_as_entries="hybrid")
    assert inv["target_kind"] == "hybrid"
    assert inv["target_kind_source"] == "operator"
    assert inv["treat_exports_as_entries"] is True
    assert _verdict(inv, "public_api") == "reachable"
