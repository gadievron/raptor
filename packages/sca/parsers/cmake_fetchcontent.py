"""CMake ``FetchContent_Declare`` parser.

Modern CMake projects pull external deps via the ``FetchContent``
module — direct git-clone or URL-download at configure time, not
through a package registry. The deps are real (compiled into the
binary, may have CVEs) but invisible to the existing C/C++
parsers (vcpkg / Conan / .gitmodules) because none of them are
the source of record.

Output: one :class:`Dependency` per ``FetchContent_Declare`` block
with a synthesised purl. When the ``GIT_REPOSITORY`` is on
github.com, the purl uses ``pkg:github/<owner>/<repo>@<ref>`` so
GHSA matching works; otherwise ``pkg:generic/...`` (no OSV
matching today).

## Recognised forms

Standard FetchContent_Declare with GIT_REPOSITORY:

    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG        release-1.12.1
    )

URL-based:

    FetchContent_Declare(
      json
      URL https://github.com/nlohmann/json/archive/v3.11.3.tar.gz
      URL_HASH SHA256=...
    )

## Out of scope

  * Variable expansion (``${...}``) — pass through verbatim;
    consumer can ARG-resolve.
  * ``ExternalProject_Add`` (the older mechanism) — different
    syntax, more rarely seen in modern projects. Add later if
    needed.
  * ``find_package`` system deps — those resolve to system /
    Conan / vcpkg packages, handled by other parsers.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


# Match the ``FetchContent_Declare(<name> ... )`` shape, capturing
# the entire arg block. Permissive whitespace handling — CMake is
# free-form; the args are "<key> <value>" pairs (case-insensitive
# keys, values may be unquoted).
_FETCHCONTENT_RE = re.compile(
    r"FetchContent_Declare\s*\(\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+"
    r"(?P<args>[^)]*)"
    r"\)",
    re.IGNORECASE | re.DOTALL,
)

# github.com/<owner>/<repo>(.git)? URL → pkg:github/<owner>/<repo>
_GITHUB_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9._-]+)/"
    r"(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$"
)

# Extract a tag-shaped string from a URL like
# ``.../archive/v3.11.3.tar.gz`` or ``.../<owner>/<repo>/-/archive/v1.tar.gz``.
# Best-effort; unrecognised URL shapes return None.
_URL_REF_RE = re.compile(
    r"/archive/(?:refs/tags/)?(?P<ref>[^/]+?)\.(?:tar\.gz|tar\.xz|tar\.bz2|zip)"
)


@register(filenames=["CMakeLists.txt"])
def parse_cmake_lists(path: Path) -> List[Dependency]:
    """Parse a ``CMakeLists.txt`` for ``FetchContent_Declare`` blocks.

    Returns one Dependency per declaration; the project's own
    sources (the ``add_executable`` / ``add_library`` rules)
    are out of scope — we only emit pulled-in external deps.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("sca.parsers.cmake_fetchcontent: skip %s (%s)",
                      path, e)
        return []

    out: List[Dependency] = []
    for name, args_text in _iter_declarations(text):
        dep = _build_dep(name, args_text, declared_in=path)
        if dep is not None:
            out.append(dep)
    return out


def _iter_declarations(text: str) -> Iterator[Tuple[str, str]]:
    """Yield ``(name, args_block)`` per matching declaration."""
    for m in _FETCHCONTENT_RE.finditer(text):
        yield m.group("name"), m.group("args")


def _build_dep(
    name: str, args_text: str, *, declared_in: Path,
) -> Optional[Dependency]:
    """Map a parsed declaration to a Dependency row.

    The ``args_text`` is the inside of the parentheses minus the
    leading name. Each arg pair is ``KEY VALUE`` where KEY is one
    of GIT_REPOSITORY / GIT_TAG / URL / URL_HASH / SOURCE_DIR /
    BINARY_DIR / etc.
    """
    kv = _parse_kv(args_text)
    git_repo = kv.get("GIT_REPOSITORY")
    git_tag = kv.get("GIT_TAG")
    url = kv.get("URL")

    ecosystem: str
    canonical_name: str
    version: Optional[str]
    pin_style: PinStyle
    purl: str

    if git_repo:
        gh = _GITHUB_RE.match(git_repo)
        if gh:
            owner, repo = gh.group("owner"), gh.group("repo")
            ecosystem = "GitHub"
            canonical_name = f"{owner}/{repo}"
            purl = f"pkg:github/{owner}/{repo}"
            version = git_tag
            pin_style = (
                PinStyle.EXACT if version else PinStyle.WILDCARD
            )
        else:
            ecosystem = "CMake-FetchContent"
            canonical_name = name
            purl = f"pkg:generic/{name}"
            version = git_tag
            pin_style = (
                PinStyle.EXACT if version else PinStyle.WILDCARD
            )
        if version:
            purl = f"{purl}@{version}"
    elif url:
        ref = None
        m = _URL_REF_RE.search(url)
        if m:
            ref = m.group("ref")
        gh = _GITHUB_RE.match(url.split("/archive/", 1)[0])
        if gh:
            owner, repo = gh.group("owner"), gh.group("repo")
            ecosystem = "GitHub"
            canonical_name = f"{owner}/{repo}"
            purl = f"pkg:github/{owner}/{repo}"
            version = ref
            pin_style = (
                PinStyle.EXACT if ref else PinStyle.WILDCARD
            )
        else:
            ecosystem = "CMake-FetchContent"
            canonical_name = name
            purl = f"pkg:generic/{name}"
            version = ref
            pin_style = (
                PinStyle.EXACT if ref else PinStyle.WILDCARD
            )
        if version:
            purl = f"{purl}@{version}"
    else:
        # Neither GIT_REPOSITORY nor URL — couldn't classify.
        return None

    return Dependency(
        ecosystem=ecosystem,
        name=canonical_name,
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
                "extracted from CMake FetchContent_Declare; OSV "
                "matching only fires for github.com-hosted deps"
            ),
        ),
        source_kind="cmake",
    )


def _parse_kv(args_text: str) -> dict:
    """Convert a ``KEY1 VALUE1 KEY2 VALUE2 ...`` block into a dict.

    CMake arg keys are upper-snake-case identifiers. Values are
    everything until the next key. Quoting (``"..."``) is
    respected for values; comments (``# ...``) are stripped.
    """
    # Strip ``# ...`` end-of-line comments before tokenising.
    text = re.sub(r"#[^\n]*", " ", args_text)
    # CMake keys we recognise — keeps the parser narrow + safe.
    KEYS = {
        "GIT_REPOSITORY", "GIT_TAG", "GIT_SHALLOW", "GIT_PROGRESS",
        "GIT_SUBMODULES", "URL", "URL_HASH", "URL_MD5",
        "DOWNLOAD_NAME", "SOURCE_DIR", "BINARY_DIR", "PATCH_COMMAND",
        "CONFIGURE_COMMAND", "BUILD_COMMAND", "INSTALL_COMMAND",
        "OVERRIDE_FIND_PACKAGE", "FIND_PACKAGE_ARGS", "EXCLUDE_FROM_ALL",
        "SYSTEM",
    }
    tokens = _tokenise(text)
    out = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.upper() in KEYS:
            key = tok.upper()
            # Collect everything up to the next known key.
            j = i + 1
            value_parts = []
            while j < len(tokens) and tokens[j].upper() not in KEYS:
                value_parts.append(tokens[j])
                j += 1
            out[key] = " ".join(value_parts).strip()
            i = j
        else:
            i += 1
    return out


def _tokenise(text: str) -> List[str]:
    """Whitespace-split with quoted-string awareness.

    CMake's quote rules are simple — ``"..."`` produces a single
    token preserving inner whitespace. Anything else splits on
    whitespace.
    """
    tokens: List[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == '"':
            j = text.find('"', i + 1)
            if j == -1:
                # unterminated quote — take to end
                tokens.append(text[i + 1:])
                break
            tokens.append(text[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < len(text) and not text[j].isspace():
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


__all__ = ["parse_cmake_lists"]
