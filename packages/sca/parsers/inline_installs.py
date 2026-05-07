"""Extract package installs from Dockerfile / devcontainer.json / shell / GHA.

These files aren't manifests, but they declare deps just as authoritatively
as ``requirements.txt`` — and they're routinely overlooked. A ``RUN
pip install django==4.2.7`` baked into a Dockerfile is a real PyPI dep
that needs CVE matching; ``apt install nginx=1.18.0-6`` is a Debian dep
that needs OSV lookup.

This module is **registry-driven**: each supported package manager is one
entry in ``_MANAGERS``. Adding ``cargo install`` or ``gem install`` is
~10 lines.

What we extract:

  - ``pip`` / ``pip3`` / ``python -m pip`` / ``python3 -m pip`` → PyPI
  - ``apt`` / ``apt-get install`` → Debian
  - ``yum`` / ``dnf install`` → Red Hat
  - ``apk add`` / ``apk install`` → Alpine

Where we look:

  - **Dockerfile** / **Containerfile**: each ``RUN`` instruction (with
    backslash-continuation collapsing).
  - **devcontainer.json**: ``postCreateCommand``, ``onCreateCommand``,
    ``postStartCommand`` (string or array form). ``features`` block is
    deferred — it needs a separate parser per feature.
  - **shell scripts** (``*.sh``, ``*.bash``): every line.
  - **GHA workflows** (``.github/workflows/*.yml``): every ``run:`` block
    body is treated as shell.

What we don't extract (yet):

  - Unpinned installs (``pip install foo`` with no version): emitted with
    ``version=None`` and ``pin_style=WILDCARD``. SBOM surfaces them but
    advisory matching cannot fire without a version.
  - ``-r requirements.txt`` / ``-c constraints.txt``: those files are
    discovered separately, so we'd just dedupe.
  - Cargo / npm / gem / brew: same shape, different syntax — straightforward
    to add when needed.
  - Dockerfile ``FROM`` base-image scanning is handled by a sibling
    module (``packages.sca.dockerfile_from``), not this parser. That
    module pulls the actual installed-package state from the base
    image's registry layers — much more accurate than guessing
    Debian / Red Hat / Alpine from inline ``apt-get install`` lines.

All emitted Dependency rows carry ``source_kind`` ∈ ``{"dockerfile",
"devcontainer", "shell_script", "gha_workflow"}`` so the report can show
where each dep came from.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Package-manager descriptor table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _PkgManager:
    """One row per supported package manager."""

    pattern: "re.Pattern[str]"      # matches the install command in a line
    ecosystem: str                  # the SCA ecosystem string
    purl_type: str                  # the purl `type` segment
    purl_namespace: Optional[str]   # the purl `namespace` segment (or None)
    parse_args: Callable[[str], Iterator[Tuple[str, Optional[str], PinStyle]]]


_NAME_RE = r"[A-Za-z0-9][A-Za-z0-9._+\-]*"


_PIP_FLAGS_WITH_VALUE = {
    "-r", "--requirement",
    "-c", "--constraint",
    "-e", "--editable",
    "-i", "--index-url",
    "--extra-index-url",
    "--find-links", "-f",
    "--trusted-host",
    "--target", "-t",
    "--prefix", "--root",
    "--cache-dir",
    "--retries",
}


def _parse_pip_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """Yield (name, version, pin_style) tuples from a ``pip install ...`` arg
    string.

    Handles the common pinning shapes: ``foo==1.2.3``, ``foo>=1.2.3``,
    ``foo~=1.2.3``, ``foo`` (unpinned), and PEP 508 multi-specifier
    forms like ``foo>=1,<2`` or ``foo>=1.0,!=1.5``. Skips flags and
    the path argument that follows ``-r``/``-c``/``-e`` etc. URL/VCS
    forms (``git+https://``) are skipped — they're rare inline and
    need the heavy URL-spec machinery from the requirements parser.

    Multi-specifier shapes go through ``packaging.specifiers.SpecifierSet``
    (same engine the requirements.txt parser uses) so the result is
    consistent across parsers — ``foo>=2.0,<3.0`` from requirements.txt
    and ``pip install 'foo>=2.0,<3.0'`` in a Dockerfile both produce
    ``(name='foo', version=None, pin_style=RANGE)`` rather than the
    nonsense ``version='2.0,<3.0'`` regex-extraction would yield.
    """
    tokens = _tokenise(args)
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _PIP_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("--") and "=" in tok:
            # ``--target=/opt`` shape: value is in-token, no skip needed.
            continue
        if tok.startswith("-"):
            continue
        if "://" in tok or tok.startswith(("git+", "hg+", "./", "../", "/")):
            continue
        # Strip surrounding quotes — `pip install "foo==1.2.3"`.
        tok = tok.strip("'\"")
        parsed = _classify_pip_token(tok)
        if parsed is not None:
            yield parsed


def _classify_pip_token(
    tok: str,
) -> Optional[Tuple[str, Optional[str], PinStyle]]:
    """Map one ``pkg[<spec>...]`` token to ``(name, version, pin_style)``.

    Splits on the first PEP 508 operator and runs the constraints
    through ``packaging.specifiers.SpecifierSet``. Returns None when
    the token doesn't look like a package spec (caller skips silently
    rather than yielding garbage)."""
    # Match name plus the rest (which may be empty, a single spec, or
    # multiple specs joined by commas).
    m = re.match(rf"^({_NAME_RE})\s*(.*)$", tok)
    if m is None:
        return None
    name = m.group(1)
    rest = m.group(2).strip()
    if not rest:
        # Bare name — surface for SBOM inventory.
        return name, None, PinStyle.WILDCARD
    # Anything after the name should look like one or more PEP 508
    # version specifiers; reject obvious garbage early.
    if not re.match(r"^[<>!~=]", rest):
        return None
    try:
        from packaging.specifiers import SpecifierSet
    except ImportError:
        # ``packaging`` is an optional dep for the parsers layer; if
        # it's missing fall back to the single-spec regex behaviour
        # rather than dropping the dep entirely.
        return _legacy_single_spec(name, rest)
    try:
        spec = SpecifierSet(rest)
    except Exception:                   # noqa: BLE001 — invalid PEP 508
        return _legacy_single_spec(name, rest)
    items = list(spec)
    if not items:
        return name, None, PinStyle.WILDCARD
    if len(items) == 1:
        only = items[0]
        op = only.operator
        ver = only.version
        if op in ("==", "==="):
            return name, ver, PinStyle.EXACT
        if op == "~=":
            return name, ver, PinStyle.TILDE
        # Single bound (>=, <, etc.) is still a RANGE — but the lower
        # bound is meaningful enough to OSV-query against.
        return name, ver, PinStyle.RANGE
    # Multi-specifier (e.g. ``>=2.0,<3.0``): emit RANGE with no
    # exact version. Mirrors requirements.txt parser semantics
    # exactly so a finding's reachability/CVE-match treats both
    # sources identically.
    return name, None, PinStyle.RANGE


def _legacy_single_spec(
    name: str, rest: str,
) -> Optional[Tuple[str, Optional[str], PinStyle]]:
    """Pre-``packaging`` fallback for single-specifier shapes only.

    Multi-spec rests get rejected (yield None) rather than mangled.
    """
    if "," in rest:
        return None
    m = re.match(r"^(==|>=|<=|~=|>|<|!=)\s*(\S+)$", rest)
    if m is None:
        return None
    op, version = m.group(1), m.group(2)
    pin = PinStyle.EXACT if op in ("==", "===") else (
        PinStyle.TILDE if op == "~=" else PinStyle.RANGE
    )
    return name, version, pin


_APT_FLAGS_WITH_VALUE = {
    "-t", "--target-release",
    "-c", "--config-file",
    "-o", "--option",
}


def _parse_apt_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``apt install nginx=1.18.0-6.1 curl`` — single ``=`` is the pin."""
    skip_next = False
    for tok in _tokenise(args):
        if skip_next:
            skip_next = False
            continue
        if tok in _APT_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        m = re.match(rf"^({_NAME_RE})=(\S+)$", tok)
        if m:
            yield m.group(1), m.group(2), PinStyle.EXACT
        elif re.match(rf"^{_NAME_RE}$", tok):
            yield tok, None, PinStyle.WILDCARD


_YUM_FLAGS_WITH_VALUE = {
    "--enablerepo", "--disablerepo",
    "--installroot",
    "--releasever",
    "--exclude",
    "-c", "--config",
}


def _parse_yum_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``yum install nginx-1.18.0-2.el8`` — version follows a dash; we
    split on the first dash followed by a digit. Plain ``nginx`` is
    unpinned."""
    skip_next = False
    for tok in _tokenise(args):
        if skip_next:
            skip_next = False
            continue
        if tok in _YUM_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        # name-version where version starts with a digit (rpm convention).
        m = re.match(rf"^({_NAME_RE}?)-(\d\S*)$", tok)
        if m:
            yield m.group(1), m.group(2), PinStyle.EXACT
        elif re.match(rf"^{_NAME_RE}$", tok):
            yield tok, None, PinStyle.WILDCARD


_APK_FLAGS_WITH_VALUE = {
    "-t", "--virtual",
    "--repository", "-X",
    "--keys-dir",
}


def _parse_apk_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``apk add nginx=1.18.0-r0`` — same shape as apt."""
    skip_next = False
    for tok in _tokenise(args):
        if skip_next:
            skip_next = False
            continue
        if tok in _APK_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        m = re.match(rf"^({_NAME_RE})=(\S+)$", tok)
        if m:
            yield m.group(1), m.group(2), PinStyle.EXACT
        elif re.match(rf"^{_NAME_RE}$", tok):
            yield tok, None, PinStyle.WILDCARD


# --- npm / yarn / pnpm ----------------------------------------------------

_NPM_FLAGS_WITH_VALUE = {
    "--prefix", "--registry",
    "--workspace", "-w",
    "--tag",
}

# npm package shape: ``lodash`` or ``@scope/name``. Version separator is
# the LAST ``@`` in the token (because scoped packages start with ``@``).
_NPM_SCOPED_RE = re.compile(r"^(@[A-Za-z0-9][A-Za-z0-9._\-]*/[A-Za-z0-9][A-Za-z0-9._\-]*)$")
_NPM_PLAIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)$")


def _split_npm_token(tok: str) -> Optional[Tuple[str, Optional[str]]]:
    """Split an npm install token into ``(name, version)``.

    Handles four shapes:
      - ``lodash``                    → ("lodash", None)
      - ``lodash@4.17.21``            → ("lodash", "4.17.21")
      - ``@angular/core``             → ("@angular/core", None)
      - ``@angular/core@12.3.1``      → ("@angular/core", "12.3.1")

    Skips URL / git refs (``git+https://`` etc).
    """
    if "://" in tok or tok.startswith(("git+", "github:", "file:")):
        return None
    if tok.startswith("@"):
        # Scoped package: must contain a '/'. The version, if any, comes
        # after a '@' that follows the slash.
        if "/" not in tok:
            return None
        slash_idx = tok.index("/")
        after_slash = tok[slash_idx:]
        if "@" in after_slash:
            ver_at = slash_idx + after_slash.index("@")
            name = tok[:ver_at]
            version = tok[ver_at + 1:]
            if _NPM_SCOPED_RE.match(name) and version:
                return name, version
            return None
        if _NPM_SCOPED_RE.match(tok):
            return tok, None
        return None
    # Plain package — at most one '@' separates name and version.
    if "@" in tok:
        name, version = tok.rsplit("@", 1)
        if _NPM_PLAIN_RE.match(name) and version:
            return name, version
        return None
    if _NPM_PLAIN_RE.match(tok):
        return tok, None
    return None


def _emit_npm_pkg(
    name: str,
    version: Optional[str],
) -> Tuple[str, Optional[str], PinStyle]:
    """Map an npm name+version into a Dependency-shaped tuple."""
    if version is None:
        return name, None, PinStyle.WILDCARD
    if version.startswith("^"):
        return name, version[1:], PinStyle.CARET
    if version.startswith("~"):
        return name, version[1:], PinStyle.TILDE
    return name, version, PinStyle.EXACT


def _parse_npm_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``npm install lodash@4.17.21 @angular/core@12.3.1``.

    Also covers ``npm i`` / ``yarn add`` / ``pnpm add`` since those land
    here via the same regex (different command, identical args grammar).
    """
    skip_next = False
    for tok in _tokenise(args):
        if skip_next:
            skip_next = False
            continue
        if tok in _NPM_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        split = _split_npm_token(tok)
        if split is None:
            continue
        yield _emit_npm_pkg(*split)


def _parse_npx_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``npx <pkg>[@version] <cmd-args...>`` — only the first positional is
    a package; subsequent positionals are arguments to the executed command.

    When ``-p``/``--package`` is given, packages come from the flags and
    the first positional is the command name (not a package).

    Same parser is reused for ``bunx``, ``pnpm dlx``, ``yarn dlx``.
    """
    tokens = _tokenise(args)
    packages: List[str] = []
    via_flag = False
    saw_positional = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-p", "--package"):
            via_flag = True
            if i + 1 < len(tokens):
                packages.append(tokens[i + 1].strip("'\""))
            i += 2
            continue
        if tok.startswith("--package="):
            via_flag = True
            packages.append(tok.split("=", 1)[1].strip("'\""))
            i += 1
            continue
        if tok in ("-c", "--call"):
            # Everything after ``-c`` is a shell command, not packages.
            break
        if tok.startswith("-"):
            i += 1
            continue
        if not via_flag and not saw_positional:
            packages.append(tok.strip("'\""))
            saw_positional = True
        i += 1

    for pkg in packages:
        split = _split_npm_token(pkg)
        if split is None:
            continue
        yield _emit_npm_pkg(*split)


# --- cargo / gem (single-positional with --version flag) -----------------

def _parse_versioned_flag_args(
    args: str,
    *,
    version_flags: set,
    name_re: "re.Pattern[str]",
    flags_with_value: set,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """Generic parser for ``<cmd> install <name> [--version X]`` shape.

    Used for cargo (``--version``) and gem (``-v`` / ``--version``).
    Multiple positionals share the same ``--version`` if present.
    """
    tokens = _tokenise(args)
    version: Optional[str] = None
    names: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in version_flags:
            if i + 1 < len(tokens):
                version = tokens[i + 1].strip("'\"")
            i += 2
            continue
        if tok in flags_with_value:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        clean = tok.strip("'\"")
        if name_re.match(clean):
            names.append(clean)
        i += 1
    for n in names:
        if version is not None:
            yield n, version, PinStyle.EXACT
        else:
            yield n, None, PinStyle.WILDCARD


_CARGO_RE = re.compile(rf"^{_NAME_RE}$")


def _parse_cargo_args(args: str):
    """``cargo install ripgrep --version 14.1.0``."""
    return _parse_versioned_flag_args(
        args,
        version_flags={"--version", "--vers"},
        name_re=_CARGO_RE,
        flags_with_value={"--target", "--root", "--registry", "--index",
                          "--git", "--branch", "--tag", "--rev", "--path",
                          "--bin", "--example", "--features"},
    )


_GEM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*$")


def _parse_gem_args(args: str):
    """``gem install rake -v 13.0.6``."""
    return _parse_versioned_flag_args(
        args,
        version_flags={"-v", "--version"},
        name_re=_GEM_NAME_RE,
        flags_with_value={"--source", "-s", "--bindir",
                          "--install-dir", "-i"},
    )


# --- brew (name@version like npm, but plain — no scopes) -----------------

def _parse_brew_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``brew install python@3.12 nginx``."""
    for tok in _tokenise(args):
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        # ``python@3.12`` or plain ``nginx``.
        if "@" in tok:
            name, version = tok.rsplit("@", 1)
            if _NPM_PLAIN_RE.match(name) and version:
                yield name, version, PinStyle.EXACT
                continue
        if _NPM_PLAIN_RE.match(tok):
            yield tok, None, PinStyle.WILDCARD


# --- go install (module-path@version) ------------------------------------

# Go module paths can have slashes and dots (``github.com/foo/bar``).
_GO_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._\-]*(?:[./][A-Za-z0-9._\-]+)*$")


def _parse_go_install_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``go install github.com/foo/bar@v1.2.3``."""
    for tok in _tokenise(args):
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        if "@" not in tok:
            # ``go install ./local/path`` — not a fetched module.
            continue
        name, version = tok.rsplit("@", 1)
        if not _GO_NAME_RE.match(name):
            continue
        # ``@latest`` is unpinned in practice.
        if version in ("latest", ""):
            yield name, None, PinStyle.WILDCARD
        else:
            yield name, version, PinStyle.EXACT


_MANAGERS: List[_PkgManager] = [
    _PkgManager(
        pattern=re.compile(
            r"\b(?:python3?\s+-m\s+)?pip3?\s+install\b", re.IGNORECASE),
        ecosystem="PyPI",
        purl_type="pypi",
        purl_namespace=None,
        parse_args=_parse_pip_args,
    ),
    # ``pipx install foo==1.2.3`` and ``uv pip install foo==1.2.3`` —
    # both pull from PyPI; same args grammar as pip.
    _PkgManager(
        pattern=re.compile(r"\bpipx\s+install\b", re.IGNORECASE),
        ecosystem="PyPI",
        purl_type="pypi",
        purl_namespace=None,
        parse_args=_parse_pip_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\buv\s+pip\s+install\b", re.IGNORECASE),
        ecosystem="PyPI",
        purl_type="pypi",
        purl_namespace=None,
        parse_args=_parse_pip_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\bapt(?:-get)?\s+install\b", re.IGNORECASE),
        ecosystem="Debian",
        purl_type="deb",
        purl_namespace="debian",
        parse_args=_parse_apt_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\b(?:yum|dnf)\s+install\b", re.IGNORECASE),
        ecosystem="Red Hat",
        purl_type="rpm",
        purl_namespace="redhat",
        parse_args=_parse_yum_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\bapk\s+(?:add|install)\b", re.IGNORECASE),
        ecosystem="Alpine",
        purl_type="apk",
        purl_namespace="alpine",
        parse_args=_parse_apk_args,
    ),
    # ``npm install foo@1.2.3`` / ``npm i`` / ``yarn add`` / ``pnpm add``.
    _PkgManager(
        pattern=re.compile(
            r"\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install|i))\b",
            re.IGNORECASE),
        ecosystem="npm",
        purl_type="npm",
        purl_namespace=None,
        parse_args=_parse_npm_args,
    ),
    # ``npx <pkg>[@version]`` / ``bunx <pkg>`` / ``pnpm dlx`` / ``yarn dlx``.
    # The package is fetched-and-executed transiently; same supply-chain
    # weight as a permanent install for our purposes.
    _PkgManager(
        pattern=re.compile(
            r"\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx)\b",
            re.IGNORECASE),
        ecosystem="npm",
        purl_type="npm",
        purl_namespace=None,
        parse_args=_parse_npx_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\bcargo\s+install\b", re.IGNORECASE),
        ecosystem="crates.io",
        purl_type="cargo",
        purl_namespace=None,
        parse_args=_parse_cargo_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\bgem\s+install\b", re.IGNORECASE),
        ecosystem="RubyGems",
        purl_type="gem",
        purl_namespace=None,
        parse_args=_parse_gem_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\bbrew\s+install\b", re.IGNORECASE),
        ecosystem="Homebrew",
        purl_type="brew",
        purl_namespace=None,
        parse_args=_parse_brew_args,
    ),
    _PkgManager(
        pattern=re.compile(r"\bgo\s+install\b", re.IGNORECASE),
        ecosystem="Go",
        purl_type="golang",
        purl_namespace=None,
        parse_args=_parse_go_install_args,
    ),
]


# ---------------------------------------------------------------------------
# Text → Dependency rows
# ---------------------------------------------------------------------------

def _tokenise(s: str) -> List[str]:
    """Split on whitespace, dropping empties. Doesn't honour shell quoting
    perfectly — quotes are stripped afterwards by the per-manager parser.
    """
    return [t for t in s.split() if t]


def _strip_inline_comment(line: str) -> str:
    """Drop trailing ``# ...`` comments from a shell line.

    Conservative: only strips ``#`` preceded by whitespace or at start, to
    avoid butchering ``url=https://example.com/path#frag``.
    """
    # Walk char-by-char; track whether we're inside single/double quotes.
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1].isspace():
                return line[:i].rstrip()
    return line


def _collapse_continuations(text: str) -> List[Tuple[int, str, bool]]:
    """Join ``\\``-continued lines into single logical lines.

    Returns ``(starting_line_no, joined, is_commented)`` triples.
    ``is_commented`` is True if every constituent line was a comment.
    """
    out: List[Tuple[int, str, bool]] = []
    raw = text.splitlines()
    i = 0
    while i < len(raw):
        start = i + 1            # 1-indexed line number
        chunks: List[str] = []
        all_commented = True
        while True:
            line = raw[i]
            stripped = line.lstrip()
            commented = stripped.startswith("#")
            if not commented:
                all_commented = False
            # Drop the leading `#`s from a commented continuation so the
            # body parses normally.
            body = stripped.lstrip("#").lstrip() if commented else line
            # Continuation marker?
            if body.rstrip().endswith("\\"):
                chunks.append(body.rstrip()[:-1])
                i += 1
                if i >= len(raw):
                    break
                continue
            chunks.append(body)
            break
        joined = " ".join(c.strip() for c in chunks).strip()
        if joined:
            out.append((start, joined, all_commented))
        i += 1
    return out


def _scan_shell_lines(
    lines: List[Tuple[int, str, bool]],
    declared_in: Path,
    source_kind: str,
) -> List[Dependency]:
    """Apply the manager patterns to each logical line; emit deps.

    Each subline is one install command — at most one manager should apply.
    We pick the *latest-starting* match so more-specific wrappers like
    ``uv pip install`` win over the inner ``pip install``.
    """
    deps: List[Dependency] = []
    for line_no, body, commented in lines:
        cleaned = _strip_inline_comment(body)
        for sub in _split_compound(cleaned):
            best: Optional[Tuple[_PkgManager, "re.Match[str]"]] = None
            for mgr in _MANAGERS:
                m = mgr.pattern.search(sub)
                if not m:
                    continue
                if best is None or m.start() > best[1].start():
                    best = (mgr, m)
            if best is None:
                continue
            mgr, m = best
            args = sub[m.end():]
            for name, version, pin in mgr.parse_args(args):
                deps.append(_make_dep(
                    name=name, version=version, pin_style=pin,
                    ecosystem=mgr.ecosystem,
                    purl_type=mgr.purl_type,
                    purl_namespace=mgr.purl_namespace,
                    declared_in=declared_in,
                    source_kind=source_kind,
                    commented=commented,
                    line_no=line_no,
                ))
    return deps


def _split_compound(line: str) -> List[str]:
    """Split a shell line on ``&&`` / ``||`` / ``;`` outside quotes."""
    out: List[str] = []
    buf: List[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch); i += 1; continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch); i += 1; continue
        if not in_single and not in_double:
            if line[i:i+2] in ("&&", "||"):
                out.append("".join(buf)); buf = []; i += 2; continue
            if ch == ";":
                out.append("".join(buf)); buf = []; i += 1; continue
        buf.append(ch); i += 1
    if buf:
        out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _make_dep(
    *,
    name: str,
    version: Optional[str],
    pin_style: PinStyle,
    ecosystem: str,
    purl_type: str,
    purl_namespace: Optional[str],
    declared_in: Path,
    source_kind: str,
    commented: bool,
    line_no: int,
) -> Dependency:
    canon = _canonicalise_name(name, ecosystem)
    purl_base = (
        f"pkg:{purl_type}/{purl_namespace}/{canon}"
        if purl_namespace else f"pkg:{purl_type}/{canon}"
    )
    purl = f"{purl_base}@{version}" if version else purl_base
    return Dependency(
        ecosystem=ecosystem,
        name=canon,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "medium",
            reason=(
                f"extracted from inline install command at "
                f"{declared_in.name}:{line_no}"
            ),
        ),
        commented_out=commented,
        source_kind=source_kind,
    )


def _canonicalise_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        # npm names are case-sensitive but conventionally lower-case;
        # scope and slash are preserved.
        return name.lower()
    return name


# ---------------------------------------------------------------------------
# File-shape entry points
# ---------------------------------------------------------------------------

def parse_dockerfile(path: Path) -> List[Dependency]:
    """Extract installs from a Dockerfile / Containerfile.

    Logic: collapse backslash-continuations, look at every line whose
    leading token is ``RUN`` (Docker's instruction keyword), and feed the
    rest through the shell scanner.
    """
    text = _safe_read(path)
    if text is None:
        return []
    runs = _extract_dockerfile_run_blocks(text)
    return _scan_shell_lines(runs, declared_in=path,
                             source_kind="dockerfile")


def parse_devcontainer_json(path: Path) -> List[Dependency]:
    """Extract installs from devcontainer.json post*Command hooks.

    Shell content is grabbed from ``postCreateCommand``, ``onCreateCommand``,
    ``postStartCommand``, ``updateContentCommand``. Each can be a string or
    an array of strings.
    """
    text = _safe_read(path)
    if text is None:
        return []
    try:
        data = _load_jsonc(text)
    except Exception:                       # noqa: BLE001
        logger.warning("sca.parsers: devcontainer.json parse failed: %s", path)
        return []
    cmd_keys = (
        "postCreateCommand",
        "onCreateCommand",
        "postStartCommand",
        "updateContentCommand",
        "postAttachCommand",
    )
    lines: List[Tuple[int, str, bool]] = []
    for key in cmd_keys:
        val = data.get(key)
        if val is None:
            continue
        for piece in _flatten_command(val):
            # Each piece is a self-contained shell snippet. Run the
            # continuation collapser to handle multi-line strings.
            lines.extend(_collapse_continuations(piece))
    return _scan_shell_lines(lines, declared_in=path,
                             source_kind="devcontainer")


def parse_shell_script(path: Path) -> List[Dependency]:
    """Extract installs from a ``.sh`` / ``.bash`` script."""
    text = _safe_read(path)
    if text is None:
        return []
    lines = _collapse_continuations(text)
    return _scan_shell_lines(lines, declared_in=path,
                             source_kind="shell_script")


def parse_gha_workflow(path: Path) -> List[Dependency]:
    """Extract installs and ``uses:`` action references from a GHA
    workflow YAML.

    Two extraction passes:

      * ``run:`` block bodies → pip / apt / yum / dnf / apk installs
        via ``_scan_shell_lines`` with ``source_kind="gha_workflow"``.
      * ``uses: <owner>/<action>@<ref>`` lines → one Dependency per
        reference with ``ecosystem="GitHub Actions"``,
        ``source_kind="gha_uses"``. These flow through OSV CVE
        matching (the GitHub Actions ecosystem is real) and through
        the sunset detector (``supply_chain.gha_sunset``) for
        deprecation / functionality-preservation alerts.

    A workflow can contain both shapes; the parser returns a flat
    union. We don't need a full YAML parser — both ``run:`` blocks
    and ``uses:`` lines are recognisable syntactically, and the
    best-effort extractor is more robust against ad-hoc YAML
    conventions in real workflows than a strict parser anyway.
    """
    text = _safe_read(path)
    if text is None:
        return []
    runs = _extract_gha_run_blocks(text)
    deps = _scan_shell_lines(
        runs, declared_in=path, source_kind="gha_workflow",
    )
    deps.extend(_extract_gha_uses(text, declared_in=path))
    return deps


# ---------------------------------------------------------------------------
# GHA `uses:` extraction
# ---------------------------------------------------------------------------

# Match ``uses: owner/repo@ref`` and ``uses: owner/repo/sub@ref``.
# Skip ``uses: ./local-action`` (no @ref), ``docker://image@digest``
# (different threat model — Dockerfile FROM scanner covers it).
_GHA_USES_RE = re.compile(
    r"""
    ^\s*-?\s*uses\s*:\s*
    (?P<spec>[A-Za-z0-9_./-]+@[A-Za-z0-9_./-]+)
    \s*(?:\#.*)?$
    """,
    re.VERBOSE,
)

_GHA_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _extract_gha_uses(
    text: str, *, declared_in: Path,
) -> List[Dependency]:
    """Pull ``uses: owner/repo@ref`` references out of a workflow.

    Each reference becomes one ``Dependency`` with ecosystem
    ``"GitHub Actions"``, name ``owner/repo`` (or ``owner/repo/sub``
    for sub-actions), version equal to the ref, and pin_style
    classified by ref shape:

      * 40-char hex → GIT (operator's pinning to the action's bytes)
      * starts with ``v<digit>`` → CARET (semver-tag pin; Action
        owner can re-publish, but it's the conventional pin shape)
      * else → UNKNOWN (branch / odd ref)
    """
    out: List[Dependency] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        m = _GHA_USES_RE.match(raw)
        if not m:
            continue
        spec = m.group("spec")
        if spec.startswith(("./", "../", "docker://")):
            continue
        if "@" not in spec:
            continue
        action, ref = spec.rsplit("@", 1)
        if "/" not in action:
            # Bare ``uses: setup-node@v3`` (no owner) — invalid GHA
            # but seen in copy-pasted snippets. Skip.
            continue
        pin_style, version = _classify_action_ref(ref)
        out.append(Dependency(
            ecosystem="GitHub Actions",
            name=action,
            version=version,
            declared_in=declared_in,
            scope="build",
            is_lockfile=False,
            pin_style=pin_style,
            direct=True,
            purl=f"pkg:githubactions/{action}@{ref}",
            parser_confidence=Confidence(
                "high" if pin_style != PinStyle.UNKNOWN else "medium",
                reason=(
                    f"GHA uses: {action}@{ref}"
                ),
            ),
            source_kind="gha_uses",
            source_extra={"ref": ref, "line": line_no},
        ))
    return out


def _classify_action_ref(ref: str) -> Tuple[PinStyle, Optional[str]]:
    """Classify a ``uses: <action>@<ref>`` reference.

    ``ref`` is the version-shaped suffix. Mapping:

      * 40-char hex SHA → ``GIT`` pin, version = ref (operator's
        pinning to the action's bytes; immutable).
      * ``v1`` / ``v1.2`` / ``v1.2.3`` / ``release-1.0`` → ``CARET``
        pin, version = ref (semver-tag convention; the action's
        owner can re-publish the same tag, hence the supply-chain
        warning from ``gha_drift``, but it's the standard pin
        shape and the version IS the ref).
      * Anything else → ``UNKNOWN``, version = ref.
    """
    if _GHA_SHA_RE.match(ref.lower()):
        return PinStyle.GIT, ref
    if re.match(r"^v?\d", ref) and "/" not in ref:
        return PinStyle.CARET, ref
    return PinStyle.UNKNOWN, ref


# ---------------------------------------------------------------------------
# Per-shape extractors
# ---------------------------------------------------------------------------

_DOCKERFILE_RUN_RE = re.compile(r"^\s*RUN\s+", re.IGNORECASE)


def _extract_dockerfile_run_blocks(text: str) -> List[Tuple[int, str, bool]]:
    """Yield ``(start_line, body, commented)`` for every RUN instruction.

    Live RUN instructions (and their backslash-continuations) come from
    :func:`core.dockerfile.parse_dockerfile` — the shared substrate
    handles tokenisation, line-continuation collapsing, and multi-stage
    AS-name tracking. Commented RUN blocks (``# RUN pip install foo``)
    are surfaced via a tiny pre-pass below; the core parser skips
    comments by design (correct for most consumers, but SCA wants to
    surface commented installs as info-severity findings).
    """
    from core.dockerfile import parse_dockerfile as _parse_dockerfile_core

    out: List[Tuple[int, str, bool]] = []

    # Live RUN instructions — delegated.
    for inst in _parse_dockerfile_core(text):
        if inst.directive == "RUN" and inst.args:
            out.append((inst.line, inst.args, False))

    # Commented RUN blocks — small inline pass. Rare but cheap to
    # preserve behaviour. Honours backslash continuation across
    # commented lines (``# RUN foo \`` then ``#  bar``).
    out.extend(_extract_commented_run_blocks(text))

    out.sort(key=lambda x: x[0])
    return out


def _extract_commented_run_blocks(
    text: str,
) -> List[Tuple[int, str, bool]]:
    """Scan for ``# RUN ...`` blocks. Returns the same shape as the
    live-RUN extractor with ``commented=True``."""
    out: List[Tuple[int, str, bool]] = []
    raw = text.splitlines()
    i = 0
    while i < len(raw):
        stripped = raw[i].lstrip()
        if not stripped.startswith("#"):
            i += 1
            continue
        body_line = stripped.lstrip("#").lstrip()
        m = _DOCKERFILE_RUN_RE.match(body_line)
        if m is None:
            i += 1
            continue
        start = i + 1
        chunks = [body_line[m.end():]]
        while chunks[-1].rstrip().endswith("\\"):
            chunks[-1] = chunks[-1].rstrip()[:-1]
            i += 1
            if i >= len(raw):
                break
            cont_line = raw[i].lstrip()
            if cont_line.startswith("#"):
                cont_line = cont_line.lstrip("#").lstrip()
            chunks.append(cont_line)
        joined = " ".join(c.strip() for c in chunks).strip()
        if joined:
            out.append((start, joined, True))
        i += 1
    return out


_GHA_RUN_OPEN_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*(\S.*?)?\s*$")
_GHA_RUN_BLOCK_OPEN_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*[|>][+-]?\s*$")


def _extract_gha_run_blocks(text: str) -> List[Tuple[int, str, bool]]:
    """Pull the body of every ``run:`` step out of a workflow.

    Supports both inline (``run: pip install foo``) and block-scalar form
    (``run: |\\n  pip install foo``). Block bodies are dedented to their
    first content line's indent.
    """
    out: List[Tuple[int, str, bool]] = []
    raw = text.splitlines()
    i = 0
    while i < len(raw):
        line = raw[i]
        block_m = _GHA_RUN_BLOCK_OPEN_RE.match(line)
        if block_m:
            base_indent = len(block_m.group(1))
            block_lines: List[str] = []
            start = i + 2
            i += 1
            block_indent: Optional[int] = None
            while i < len(raw):
                nxt = raw[i]
                if not nxt.strip():
                    block_lines.append("")
                    i += 1
                    continue
                indent = len(nxt) - len(nxt.lstrip())
                if indent <= base_indent:
                    break
                if block_indent is None:
                    block_indent = indent
                block_lines.append(nxt[block_indent:] if indent >= block_indent
                                   else nxt.lstrip())
                i += 1
            block_text = "\n".join(block_lines)
            for ln, body, commented in _collapse_continuations(block_text):
                out.append((start + ln - 1, body, commented))
            continue
        inline_m = _GHA_RUN_OPEN_RE.match(line)
        if inline_m and inline_m.group(2):
            body = inline_m.group(2).strip().strip("'\"")
            out.append((i + 1, body, False))
            i += 1
            continue
        i += 1
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("sca.parsers: cannot read %s: %s", path, e)
        return None


def _load_jsonc(text: str) -> dict:
    """Tolerant JSON-with-comments loader (devcontainer.json convention)."""
    cleaned = re.sub(r"//[^\n]*", "", text)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    # Tolerate trailing commas: ``{ "a": 1, }``.
    cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    return json.loads(cleaned)


def _flatten_command(val) -> List[str]:
    """devcontainer command fields can be string OR list-of-strings."""
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [v for v in val if isinstance(v, str)]
    return []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix == ".dockerfile":
        return True
    return False


def _is_devcontainer_json(path: Path) -> bool:
    if path.name == "devcontainer.json":
        return True
    # Some repos use ``.devcontainer.json`` at the root.
    if path.name == ".devcontainer.json":
        return True
    return False


def _is_shell_script(path: Path) -> bool:
    return path.suffix in (".sh", ".bash")


def _is_gha_workflow(path: Path) -> bool:
    if path.suffix not in (".yml", ".yaml"):
        return False
    parts = path.parts
    # ``.github/workflows/foo.yml`` — workflows at any depth.
    for j in range(len(parts) - 2):
        if parts[j] == ".github" and parts[j + 1] == "workflows":
            return True
    # Composite-action manifests carry the same ``uses:`` / ``run:``
    # shapes — same parser handles them. Two locations:
    #   * Repo-root ``action.yml`` / ``action.yaml`` (when the repo
    #     IS the action).
    #   * ``.github/actions/<name>/action.yml`` (composite actions
    #     defined inside a regular project).
    if path.name in ("action.yml", "action.yaml"):
        return True
    return False


register(predicate=_is_dockerfile)(parse_dockerfile)
register(predicate=_is_devcontainer_json)(parse_devcontainer_json)
register(predicate=_is_shell_script)(parse_shell_script)
register(predicate=_is_gha_workflow)(parse_gha_workflow)


__all__ = [
    "parse_dockerfile",
    "parse_devcontainer_json",
    "parse_shell_script",
    "parse_gha_workflow",
]
