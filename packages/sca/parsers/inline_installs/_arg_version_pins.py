"""Extract version-pin ``ARG`` lines from Dockerfiles as deps.

Many Dockerfiles pin a build-time toolchain version via an ``ARG``:

    ARG SEMGREP_VERSION=1.117.0
    ARG CLAUDE_CODE_VERSION=2.1.138
    ARG CODEQL_VERSION=2.25.3
    ARG PYTHON_VERSION=3.12

These are real version pins for real tools. Pre-fix, raptor-sca
ignored them entirely — the inline_installs parser only walks
``RUN pip install`` style commands. Operators wanting to know
"is the semgrep we ship in the devcontainer affected by any
CVE?" had to ad-hoc grep.

This extractor walks ARG lines whose name ends in ``_VERSION``
and resolves them to ``(ecosystem, name)`` via a small built-in
map plus operator-supplied inline comment overrides:

    ARG SEMGREP_VERSION=1.117.0  # raptor-sca: PyPI:semgrep
    ARG CUSTOM_TOOL_VERSION=2.0  # raptor-sca: skip
    ARG VENDORED_LIB_VERSION=1.0 # raptor-sca: npm:@vendor/lib

The built-in map handles the common cases. Unknown ARGs without
an inline override are silently skipped — we don't want to
pollute findings with deps we can't query OSV for. Tool ARGs
that genuinely have no SCA ecosystem (CodeQL CLI, Go runtime,
Python runtime) are listed as ``None`` in the built-in map so
operators don't have to add ``# raptor-sca: skip`` to every
boilerplate ARG.

Acknowledgement
---------------
The idea + the canonical use case (Dockerfile ARGs for semgrep /
codeql / claude-code in a devcontainer) come from
https://github.com/gadievron/raptor/pull/467 by
Natalie Somersall <natalie.somersall@gmail.com>. PR #467 ships a
GHA workflow that *updates* these ARGs to the latest GitHub
release; this module is the SCA-side complement — *check* them
for known CVEs as part of every scan."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...models import Confidence, Dependency, PinStyle


# ``ARG <NAME>=<value>`` optionally followed by a comment. Captures:
#   1: ARG name
#   2: value (no whitespace)
#   3: optional inline comment body (everything after ``# ``)
#
# Only ARGs whose name ends in ``_VERSION`` are considered — keeps the
# scope tight and excludes generic ARGs that aren't version pins
# (``ARG BUILD_TARGET=runtime``, ``ARG USER=raptor``).
_ARG_RE = re.compile(
    r"^\s*ARG\s+(\w+_VERSION)\s*=\s*(\S+?)\s*(?:#\s*(.+?)\s*)?$"
)

# Operator override inside the comment:
#   # raptor-sca: PyPI:semgrep
#   # raptor-sca: skip
_OVERRIDE_RE = re.compile(
    r"raptor-sca:\s*(?P<spec>skip|[\w. -]+:[\w/@.\-+_]+)"
)


# Built-in ARG name → ``(ecosystem, name)`` mapping. ``None`` means
# "known toolchain ARG with no SCA ecosystem; silently skip" so
# boilerplate doesn't require per-line ``# raptor-sca: skip``
# comments.
#
# Adding to this map: only include ARG names that map UNAMBIGUOUSLY
# to a single ecosystem+package across reasonable usage. Anything
# vendor-specific (``MYCO_FOO_VERSION``) belongs in the inline-
# comment override path so we don't accumulate operator-specific
# noise here.
_BUILTIN_ARG_MAP: Dict[str, Optional[Tuple[str, str]]] = {
    # Static-analysis tools shipped via pip
    "SEMGREP_VERSION": ("PyPI", "semgrep"),
    "BANDIT_VERSION":  ("PyPI", "bandit"),
    "RUFF_VERSION":    ("PyPI", "ruff"),
    "MYPY_VERSION":    ("PyPI", "mypy"),
    "PYRIGHT_VERSION": ("PyPI", "pyright"),
    "BLACK_VERSION":   ("PyPI", "black"),
    "PYLINT_VERSION":  ("PyPI", "pylint"),

    # JS toolchain (the bare common pins)
    "CLAUDE_CODE_VERSION": ("npm", "@anthropic-ai/claude-code"),
    "ESLINT_VERSION":      ("npm", "eslint"),
    "PRETTIER_VERSION":    ("npm", "prettier"),
    "TYPESCRIPT_VERSION":  ("npm", "typescript"),

    # Toolchain ARGs that don't map to any SCA ecosystem. Listed
    # explicitly so the operator doesn't need ``# raptor-sca: skip``
    # boilerplate in every Dockerfile.
    "CODEQL_VERSION":         None,  # github-releases-only CLI
    "PYTHON_VERSION":         None,  # interpreter, not a pip pkg
    "NODE_VERSION":           None,  # runtime
    "GO_VERSION":             None,
    "RUST_VERSION":           None,
    "RUBY_VERSION":           None,
    "JAVA_VERSION":           None,
    "DEBIAN_VERSION":         None,  # base image tag
    "UBUNTU_VERSION":         None,
    "ALPINE_VERSION":         None,
    "BUILDX_VERSION":         None,
    "DOCKER_VERSION":         None,
    "KUBECTL_VERSION":        None,
    "HELM_VERSION":           None,
    "TERRAFORM_VERSION":      None,
    "PACKER_VERSION":         None,
}


def extract(text: str, path: Path) -> List[Dependency]:
    """Walk a Dockerfile's ARG version pins, emit Dependency rows
    for those we can map to an SCA ecosystem.

    Lines without a mapping (no built-in entry, no inline override)
    are silently skipped — they'd just clutter findings with deps
    we can't query.
    """
    deps: List[Dependency] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        match = _ARG_RE.match(raw)
        if match is None:
            continue
        arg_name = match.group(1)
        value = match.group(2)
        comment = match.group(3)

        mapping = _resolve_mapping(arg_name, comment)
        if mapping is None:
            continue
        ecosystem, pkg_name = mapping

        version = _normalise_version(value)
        if version is None:
            # Value isn't version-shaped (e.g. ``${OTHER_VAR}``,
            # ``latest``, ``main``). Skip — we can't query OSV
            # for a non-version anyway.
            continue

        deps.append(_make_dep(
            ecosystem=ecosystem,
            name=pkg_name,
            version=version,
            declared_in=path,
            line_no=line_no,
            arg_name=arg_name,
        ))
    return deps


def _resolve_mapping(
    arg_name: str, comment: Optional[str],
) -> Optional[Tuple[str, str]]:
    """Inline ``# raptor-sca: ...`` takes precedence over the built-in
    map. ``raptor-sca: skip`` forces a skip even if the ARG is in
    the built-in map.
    """
    if comment:
        m = _OVERRIDE_RE.search(comment)
        if m is not None:
            spec = m.group("spec")
            if spec == "skip":
                return None
            eco, _, name = spec.partition(":")
            if eco and name:
                return (eco.strip(), name.strip())
    # No override → built-in map. ``None`` value = "known boilerplate
    # ARG with no SCA ecosystem"; missing key = "unknown ARG, skip".
    if arg_name in _BUILTIN_ARG_MAP:
        return _BUILTIN_ARG_MAP[arg_name]
    return None


# Version values we'll accept. Looks like a release identifier:
# digits + optional ``v`` + dots, optionally followed by a PEP440-
# / semver-style suffix:
#
#   * ``1.2.3``, ``1.2.3.4`` (NuGet 4-part)
#   * ``v1.2.3`` (Go-style v-prefix)
#   * ``1.2.3-rc.1``, ``1.2.3+build.5`` (semver suffixes)
#   * ``20.8b1``, ``20.8rc1``, ``20.8.dev0`` (PEP440 pre-/dev-)
#
# Rejects ``latest``, ``main``, branch refs, and shell expansions
# like ``${BASE}`` — those can't be queried against OSV anyway.
_VERSION_RE = re.compile(
    r"^v?\d+(?:\.\d+){0,3}"
    r"(?:[-+.]?[A-Za-z][\w.]*)?"
    r"(?:[-+][\w.]+)?$"
)


def _normalise_version(value: str) -> Optional[str]:
    """Strip a leading ``v`` if the value otherwise looks like a
    bare semver. Returns ``None`` for values that don't look like
    version pins at all.

    Why strip ``v``: OSV uses bare semver for most ecosystems
    (``1.2.3`` not ``v1.2.3``). PR #467's GHA-side script does the
    same lstrip; this is the SCA-side complement.
    """
    cleaned = value.strip().strip('"').strip("'")
    if not _VERSION_RE.match(cleaned):
        return None
    return cleaned.lstrip("v")


def _make_dep(
    *,
    ecosystem: str,
    name: str,
    version: str,
    declared_in: Path,
    line_no: int,
    arg_name: str,
) -> Dependency:
    # purl namespace handling for npm scoped packages like
    # @anthropic-ai/claude-code: the @ngs/pkg form has the
    # namespace before the slash.
    eco_lc = ecosystem.lower()
    purl_type = {
        "PyPI": "pypi", "npm": "npm", "Maven": "maven",
        "Cargo": "cargo", "Go": "golang", "RubyGems": "gem",
        "NuGet": "nuget", "Packagist": "composer",
    }.get(ecosystem, eco_lc)
    purl_namespace: Optional[str] = None
    purl_name = name
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        ns, _, n = name.partition("/")
        purl_namespace = ns
        purl_name = n
    purl_base = (
        f"pkg:{purl_type}/{purl_namespace}/{purl_name}"
        if purl_namespace else f"pkg:{purl_type}/{purl_name}"
    )
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=declared_in,
        # ``build`` scope: ARG version pins are toolchain used at
        # build time, not runtime application deps. Matches what
        # we already do for Maven parent-POM coordinates.
        scope="build",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"{purl_base}@{version}",
        parser_confidence=Confidence(
            "high",
            reason=(
                f"extracted from ARG {arg_name} at "
                f"{declared_in.name}:{line_no}"
            ),
        ),
        source_kind="dockerfile_arg",
    )
