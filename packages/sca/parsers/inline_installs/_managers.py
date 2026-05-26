"""Per-package-manager argument parsers + the registry table that
wires them into the shell-line scanner.

Split out of ``inline_installs/__init__.py`` to keep each file
under the unwritten ~700-line "still scannable" threshold. The
``__init__`` keeps the file-shape entry points
(parse_dockerfile / parse_devcontainer_json / parse_shell_script
/ parse_gha_workflow) and the shell-line scanner; this module
keeps everything per-PM (pip / apt / yum / apk / npm / cargo /
gem / brew / go install).

Adding a new package manager: write a ``_parse_<pm>_args``
generator yielding ``(name, version, pin_style)`` tuples and
append a ``_PkgManager(...)`` row to ``_MANAGERS`` below. Pattern
order in the table doesn't matter (the scanner picks the
latest-starting match).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional, Tuple

from ...models import PinStyle
from ..requirements import _spec_bounds


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


def _tokenise(s: str) -> List[str]:
    """Split on whitespace, dropping empties. Doesn't honour shell quoting
    perfectly — quotes are stripped afterwards by the per-manager parser.
    """
    return [t for t in s.split() if t]


# --- pip ------------------------------------------------------------------

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
) -> Optional[Tuple[str, Optional[str], PinStyle,
                    Optional[str], Optional[str]]]:
    """Map one ``pkg[<spec>...]`` token to
    ``(name, version, pin_style, floor, ceiling)``.

    Splits on the first PEP 508 operator and runs the constraints
    through ``packaging.specifiers.SpecifierSet``. ``floor`` / ``ceiling``
    are the safe-corridor bounds harden records (see
    ``requirements._spec_bounds``). Returns None when the token doesn't
    look like a package spec (caller skips silently rather than yielding
    garbage)."""
    m = re.match(rf"^({_NAME_RE})\s*(.*)$", tok)
    if m is None:
        return None
    name = m.group(1)
    rest = m.group(2).strip()
    if not rest:
        return name, None, PinStyle.WILDCARD, None, None
    if not re.match(r"^[<>!~=]", rest):
        return None
    try:
        from packaging.specifiers import SpecifierSet
    except ImportError:
        return _legacy_single_spec(name, rest)
    try:
        spec = SpecifierSet(rest)
    except Exception:                   # noqa: BLE001 — invalid PEP 508
        return _legacy_single_spec(name, rest)
    items = list(spec)
    if not items:
        return name, None, PinStyle.WILDCARD, None, None
    floor, ceiling = _spec_bounds(spec)
    # An ``==`` / ``===`` clause pins the version exactly even alongside
    # range bounds: ``foo>=2.0,==2.7.0,<3.0`` resolves to exactly 2.7.0.
    # The sibling bounds record the safe corridor (floor for downgrades,
    # ceiling for upgrades) that harden preserves across runs — the
    # effective version is the ``==`` operand. Mirrors the requirements
    # parser's _classify_specifier so both surfaces agree.
    exact = next(
        (s for s in items if s.operator in ("==", "===")), None)
    if exact is not None:
        return name, exact.version, PinStyle.EXACT, floor, ceiling
    if len(items) == 1:
        only = items[0]
        op = only.operator
        ver = only.version
        if op == "~=":
            return name, ver, PinStyle.TILDE, floor, ceiling
        return name, ver, PinStyle.RANGE, floor, ceiling
    return name, None, PinStyle.RANGE, floor, ceiling


def _legacy_single_spec(
    name: str, rest: str,
) -> Optional[Tuple[str, Optional[str], PinStyle,
                    Optional[str], Optional[str]]]:
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
    floor = version if op in (">=", ">") else None
    ceiling = version if op in ("<", "<=") else None
    return name, version, pin, floor, ceiling


# --- apt ------------------------------------------------------------------

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


# --- yum / dnf ------------------------------------------------------------

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
        m = re.match(rf"^({_NAME_RE}?)-(\d\S*)$", tok)
        if m:
            yield m.group(1), m.group(2), PinStyle.EXACT
        elif re.match(rf"^{_NAME_RE}$", tok):
            yield tok, None, PinStyle.WILDCARD


# --- apk ------------------------------------------------------------------

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

# npm package shape: ``lodash`` or ``@scope/name``.
_NPM_SCOPED_RE = re.compile(
    r"^(@[A-Za-z0-9][A-Za-z0-9._\-]*/[A-Za-z0-9][A-Za-z0-9._\-]*)$",
)
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
        if "@" in tok:
            name, version = tok.rsplit("@", 1)
            if _NPM_PLAIN_RE.match(name) and version:
                yield name, version, PinStyle.EXACT
                continue
        if _NPM_PLAIN_RE.match(tok):
            yield tok, None, PinStyle.WILDCARD


# --- go install (module-path@version) ------------------------------------

# Go module paths can have slashes and dots (``github.com/foo/bar``).
# ``.`` is only allowed *within* a path component — only ``/`` separates
# components. Putting ``.`` in both the segment class and the separator
# class would make the regex ambiguous (``a.b.c`` could group as one
# segment or three), giving exponential backtracking on adversarial
# input.
_GO_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._\-]*(?:/[A-Za-z0-9._\-]+)*$")


def _parse_go_install_args(
    args: str,
) -> Iterator[Tuple[str, Optional[str], PinStyle]]:
    """``go install github.com/foo/bar@v1.2.3``."""
    for tok in _tokenise(args):
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        if "@" not in tok:
            continue
        name, version = tok.rsplit("@", 1)
        if not _GO_NAME_RE.match(name):
            continue
        if version in ("latest", ""):
            yield name, None, PinStyle.WILDCARD
        else:
            yield name, version, PinStyle.EXACT


# ---------------------------------------------------------------------------
# Registry table
# ---------------------------------------------------------------------------

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
        ecosystem="Cargo",
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


__all__ = [
    "_MANAGERS",
    "_NAME_RE",
    "_PkgManager",
    "_tokenise",
]
