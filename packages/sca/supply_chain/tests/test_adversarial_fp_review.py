"""Adversarial FP review — each test exercises a known-tricky shape
that COULD fire a false positive in the new Phase 5-8 detectors but
shouldn't.

For each detector we enumerated the shapes most likely to FP:

  * **C/G pattern substrate** — literal mention in docs/comments
    vs actual invocation
  * **Python setup.py** — README extraction, build helpers, env var
    references via ``os.environ`` (no ``$`` prefix)
  * **Composer** — Laravel ``@php artisan`` script entries, PHP
    method refs ``Vendor\\Class::method``
  * **RubyGems extconf.rb** — autoconf-style ``find_executable``,
    ``pkg-config`` probes
  * **commit_provenance** — canonical bot rebases (real dependabot
    on a long-running PR)
  * **gha_secret_flow cross-step** — non-tainted writes via
    ``$GITHUB_ENV``, aliased targets with no tainted content
  * **binary_in_package forensic** — pthread-using binary
    (formerly tripped ``clone`` after A.1 fix)

If a future pattern tightening starts firing one of these, the
test catches it before it ships.
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
from packages.sca.supply_chain import (
    binary_in_package,
    composer_lifecycle_hooks,
    gha_secret_flow,
    python_lifecycle_hooks,
    rubygems_lifecycle_hooks,
)


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


def _write_wf(tmp_path: Path, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Python — documentation strings, env-var access via os.environ
# ---------------------------------------------------------------------------

def test_setup_py_with_docstring_mentioning_credentials_no_finding(
    tmp_path: Path,
) -> None:
    """A docstring that explains where credentials live must not fire
    just because the literal text matches a credential-path pattern."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='x'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        '"""x — see ~/.npmrc setup notes in CONTRIBUTING.md."""\n'
        "from setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")], [_dep("x", "PyPI", declared_in=py)],
    )
    # The credential-pattern (~/.npmrc) hits, but worm-shape requires
    # ALSO a publish-action hit — absent here, no finding.
    assert findings == []


def test_setup_py_os_environ_access_does_not_match_c_set(
    tmp_path: Path,
) -> None:
    """Python's ``os.environ['GITHUB_TOKEN']`` doesn't have a leading
    ``$`` and therefore must NOT match the C set's
    ``$GITHUB_TOKEN`` shell-syntax pattern."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='y'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\n"
        "from setuptools import setup\n"
        "token = os.environ.get('GITHUB_TOKEN', '')\n"
        "setup(name='y')\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")], [_dep("y", "PyPI", declared_in=py)],
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Composer — Laravel @php script + PHP class refs
# ---------------------------------------------------------------------------

def test_composer_laravel_at_php_artisan_no_finding(tmp_path: Path) -> None:
    """Laravel composer.json typically has ``"@php artisan ..."``
    entries.  These are Composer command refs, not shell — no
    pattern should match."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "laravel/clone",
        "scripts": {
            "post-install-cmd": [
                "@php artisan key:generate --ansi",
                "@php artisan storage:link",
            ],
            "post-autoload-dump": [
                "Illuminate\\Foundation\\ComposerScripts::postAutoloadDump",
                "@php artisan package:discover",
            ],
        },
    }), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Composer")],
        [_dep("laravel/clone", "Composer", declared_in=cj)],
    )
    assert findings == []


def test_composer_phpunit_test_script_no_finding(tmp_path: Path) -> None:
    """``"test": "phpunit"`` is harmless test glue."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "vendor/x",
        "scripts": {"test": "phpunit --colors=always"},
    }), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Composer")],
        [_dep("vendor/x", "Composer", declared_in=cj)],
    )
    assert findings == []


# ---------------------------------------------------------------------------
# RubyGems — autoconf-style probes
# ---------------------------------------------------------------------------

def test_extconf_with_find_executable_pkg_config_no_finding(
    tmp_path: Path,
) -> None:
    """Standard autoconf-style probes in extconf.rb — ``find_executable``,
    ``have_library``, ``pkg-config`` shell-outs — must not fire."""
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        'require "mkmf"\n'
        'find_executable("pkg-config") or abort\n'
        'cflags = `pkg-config --cflags libxml-2.0`.strip\n'
        'have_library("xml2")\n'
        'have_header("libxml/parser.h")\n'
        'create_makefile("victim")\n',
        encoding="utf-8",
    )
    findings = rubygems_lifecycle_hooks.scan_target(tmp_path, [], [])
    assert findings == []


# ---------------------------------------------------------------------------
# GHA — non-tainted writes, aliased target with no tainted content
# ---------------------------------------------------------------------------

def test_gha_aliased_target_with_static_content_no_finding(
    tmp_path: Path,
) -> None:
    """``T=$GITHUB_ENV; echo X=static >> $T`` — aliasing IS detected,
    but no tainted value is written so no propagation occurs and
    downstream steps cannot fire."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T=$GITHUB_ENV
          echo "VERSION=1.2.3" >> $T
      - run: echo "Building $VERSION"
""")
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert hits == []


def test_gha_heredoc_with_only_static_content_no_finding(
    tmp_path: Path,
) -> None:
    """Heredoc to $GITHUB_ENV with only static values — propagation
    parser must not falsely flag any binding."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF >> $GITHUB_ENV
          VERSION=1.0.0
          BUILD_TYPE=release
          EOF
      - run: echo "Build $BUILD_TYPE $VERSION"
""")
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert hits == []


def test_gha_eval_of_static_redirect_no_finding(tmp_path: Path) -> None:
    """``eval "echo X=static >> $GITHUB_ENV"`` — the eval-recursion
    parses the inner shell but no tainted value is written."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: eval "echo VERSION=1.0.0 >> $GITHUB_ENV"
      - run: echo "Building $VERSION"
""")
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert hits == []


def test_gha_nested_group_with_static_content_no_finding(
    tmp_path: Path,
) -> None:
    """Nested ``{ { ... } } >> $GITHUB_ENV`` with static content."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {
            {
              echo "MODE=production"
            }
          } >> $GITHUB_ENV
      - run: echo "$MODE"
""")
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert hits == []


def test_gha_step_outputs_without_secret_no_finding(tmp_path: Path) -> None:
    """``steps.X.outputs.Y`` reference where Y was set from a NON-
    secret value — downstream consumer must not be flagged."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: cfg
        run: echo "VERSION=1.0.0" >> $GITHUB_OUTPUT
      - run: curl https://example.com/?v=${{ steps.cfg.outputs.VERSION }}
""")
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert hits == []


# ---------------------------------------------------------------------------
# binary_in_package forensic — pthread-using binary (the FP A.1 fixed)
# ---------------------------------------------------------------------------

def _write_elf_with_imports(p: Path, imports: list) -> None:
    """Construct a minimal ELF64 with the given imports as UNDEF
    dynsym entries.  Same construction as test_binary_forensic_evidence."""
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

    sh_null = _sh(0, 0, 0, 0, 0, 0, 0)
    sh_shstrtab = _sh(sh_names[".shstrtab"], 3, 0,
                      shstr_off, len(shstrtab), 0, 0)
    sh_dynstr = _sh(sh_names[".dynstr"], 3, 0,
                    dynstr_off, len(dynstr), 0, 0)
    sh_dynsym = _sh(sh_names[".dynsym"], 11, 0,
                    dynsym_off, len(dynsym), 2, 24)
    body += sh_null + sh_shstrtab + sh_dynstr + sh_dynsym
    ehdr = struct.pack(
        "<4sBBBBBBBBBBBBHHIQQQIHHHHHH",
        b"\x7fELF",
        2, 1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
        2, 0x3E, 1,
        0, 0, shoff, 0,
        EHSIZE, 0, 0,
        SHENTSIZE, 4, 1,
    )
    body[:EHSIZE] = ehdr
    p.write_bytes(bytes(body))


def test_binary_with_pthread_clone_imports_no_runtime_privilege_bucket(
    tmp_path: Path,
) -> None:
    """Post-A.1: an ELF that imports ``clone`` (typical pthread
    transitive) must NOT fire ``runtime_privilege``.  Ubiquitous-
    symbol exclusion was the FP fix."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "x"}', encoding="utf-8")
    binary_in_package._ALLOWLIST = None
    _write_elf_with_imports(
        tmp_path / "tools" / "worker",
        ["clone", "clone3", "prctl", "malloc", "free"],
    )
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert hits
    relevant = next(h for h in hits if h.relpath.endswith("worker"))
    buckets = relevant.forensic_evidence.get("capability_buckets", {})
    assert "runtime_privilege" not in buckets, (
        f"clone/prctl/clone3 must not populate runtime_privilege "
        f"after A.1 tightening; got {sorted(buckets)!r}"
    )


def test_java_class_file_not_classified_as_macho(tmp_path: Path) -> None:
    """Java ``.class`` files share the ``0xCAFEBABE`` magic with
    Mach-O fat binaries.  Dogfooded against RAPTOR's OWASP-benchmark
    corpus where ~75 ``.class`` files FP-fired as Mach-O before this
    fix.  Disambiguator uses bytes 4-7: ``< 20`` → Mach-O fat
    (nfat_arch), ``>= 20`` → Java class (major_version >= 45)."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "x"}', encoding="utf-8")
    # Java class file: CAFEBABE 0000 0034 (Java 8 / major_version=52)
    class_file = tmp_path / "lib" / "MyClass.class"
    class_file.parent.mkdir()
    class_file.write_bytes(
        b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 200,
    )
    binary_in_package._ALLOWLIST = None
    hits = binary_in_package.scan_target(tmp_path, [], [])
    java_hits = [h for h in hits if h.relpath.endswith("MyClass.class")]
    assert not java_hits, (
        f"Java .class file must not classify as Mach-O; "
        f"got {[h.family for h in java_hits]}"
    )


def test_real_macho_fat_still_classified(tmp_path: Path) -> None:
    """Genuine Mach-O fat (small nfat_arch) must STILL be classified
    — the Java disambiguator threshold is 20."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "x"}', encoding="utf-8")
    macho_file = tmp_path / "tools" / "universal_binary"
    macho_file.parent.mkdir()
    # Real Mach-O universal binary: CAFEBABE 00000002 (2 architectures)
    macho_file.write_bytes(
        b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 200,
    )
    binary_in_package._ALLOWLIST = None
    hits = binary_in_package.scan_target(tmp_path, [], [])
    matching = [h for h in hits if h.relpath.endswith("universal_binary")]
    assert matching and matching[0].family == "macho"


def test_out_dir_skipped_in_binary_walk(tmp_path: Path) -> None:
    """``out/`` is a generic build/scan-output directory — must not
    be walked.  Dogfooded against RAPTOR's ``out/dataflow-corpus-
    fixtures`` tree where committed test fixtures (juice-shop
    ``.exe``, OWASP benchmark ``.class`` files) FP-fired before
    this skip was added."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "x"}', encoding="utf-8")
    payload = tmp_path / "out" / "corpus" / "evil.exe"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"MZ" + b"\x00" * 200)
    binary_in_package._ALLOWLIST = None
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        "out/" in h.relpath or h.relpath.startswith("out")
        for h in hits
    )


def test_binary_with_only_libc_imports_no_high_severity(
    tmp_path: Path,
) -> None:
    """A clean ELF importing only standard libc (malloc/printf/read/
    write) must not surface ANY high-severity bucket."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "x"}', encoding="utf-8")
    binary_in_package._ALLOWLIST = None
    _write_elf_with_imports(
        tmp_path / "bin" / "tool",
        ["malloc", "free", "printf", "read", "write", "open", "close"],
    )
    hits = binary_in_package.scan_target(tmp_path, [], [])
    hit = next(h for h in hits if h.relpath.endswith("tool"))
    high = hit.forensic_evidence.get("high_severity_buckets", [])
    assert not high, (
        f"libc-only binary must not fire high-severity buckets; "
        f"got {high!r}"
    )
