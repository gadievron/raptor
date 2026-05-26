"""PEP 508 requirements*.txt parser (pip-style).

Handles the pip-extended PEP 508 grammar:
- ``pkg``, ``pkg==1.2.3``, ``pkg[extra1,extra2]``, ``pkg; python_version>='3.10'``
- ``-r other.txt`` / ``-c constraints.txt`` (recursive include, depth-capped)
- ``-e .`` / ``-e git+https://...`` (editable installs)
- Bare URLs (``git+https://``, ``https://.../*.tar.gz``, ``./local``)
- Inline ``# comments`` and ``--hash=...``
- Backslash line continuations

Ignored (intentionally — these are pip behaviour, not deps):
- ``--index-url``, ``--extra-index-url``, ``--find-links``, ``-f``
- ``--no-deps``, ``--pre``, ``--use-feature``, ``--trusted-host``
- ``--require-hashes`` and ``--hash`` directives

Recursion safety:
- Visited-set keyed by resolved absolute path → no cycles.
- Depth cap (``_MAX_INCLUDE_DEPTH``) → bounded work on adversarial files.
- Includes that escape the manifest's directory are still followed (we
  don't enforce containment) but a warning is logged so the operator
  notices the unusual layout.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

try:
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version
    _AVAILABLE = True
except ImportError:                       # pragma: no cover — env-dependent
    InvalidRequirement = Exception        # type: ignore[assignment,misc]
    Requirement = None                    # type: ignore[assignment]
    SpecifierSet = None                   # type: ignore[assignment]
    Version = None                        # type: ignore[assignment]
    _AVAILABLE = False
    logger.warning(
        "sca.parsers.requirements: 'packaging' not installed — requirements*.txt "
        "files will be skipped. `pip install packaging` to enable Python SCA."
    )

ECOSYSTEM = "PyPI"

# Bounded depth for -r / -c chains. Real projects nest 1-3 levels; >5 is
# almost certainly accidental or hostile.
_MAX_INCLUDE_DEPTH = 8

# pip option flags we silently skip (no dep semantics).
_PIP_OPTION_PREFIXES = (
    "--index-url",
    "-i", "--extra-index-url",
    "--find-links", "-f",
    "--no-deps",
    "--pre",
    "--use-feature",
    "--trusted-host",
    "--require-hashes",
    "--hash",
    "--no-binary",
    "--only-binary",
    "--prefer-binary",
    "--use-pep517",
    "--no-use-pep517",
    "--config-settings",
    "--global-option",
    "--no-build-isolation",
    "--proxy",
    "--cert",
    "--client-cert",
    "--no-cache-dir",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--editable",     # alias for -e; bare flag is rare but tolerated
)

# Lines that begin with this hash form are pure comments — anywhere else
# in a line, '#' is only a comment outside a URL fragment (which we
# handle conservatively below).
_COMMENT_LINE_RE = re.compile(r"^\s*#")

# Module-level toggle for ``--include-commented`` mode. Off by default
# so the analyse path doesn't surface low-signal information findings on
# every operator's commented-out optional-install hints. When set, the
# parser also yields ``# pkg==X`` lines as ``Dependency`` rows tagged
# ``commented_out=True``; the findings layer downgrades severity to
# ``info`` and the rewriter preserves the leading ``#``.
_INCLUDE_COMMENTED = False


def set_include_commented(value: bool) -> None:
    """Toggle commented-line scanning. The pipeline calls this once at
    run start; not safe to flip mid-run (no thread-local — we only
    drive a single pipeline at a time)."""
    global _INCLUDE_COMMENTED
    _INCLUDE_COMMENTED = bool(value)

# URL schemes treated as GIT for pin classification.
_GIT_URL_PREFIXES = ("git+", "git:", "git@")
_VCS_PREFIXES = _GIT_URL_PREFIXES + ("hg+", "svn+", "bzr+")


def parse(path: Path) -> List[Dependency]:
    """Entry point — parse the file plus any -r/-c includes."""
    if not _AVAILABLE:
        logger.warning(
            "sca.parsers.requirements: skipping %s — 'packaging' not installed",
            path,
        )
        return []
    visited: Set[Path] = set()
    return _parse_file(path, depth=0, visited=visited)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _parse_file(path: Path, depth: int, visited: Set[Path]) -> List[Dependency]:
    if depth > _MAX_INCLUDE_DEPTH:
        logger.warning(
            "sca.parsers.requirements: include depth cap hit at %s; "
            "stopping recursion.",
            path,
        )
        return []
    try:
        resolved = path.resolve(strict=False)
    except OSError as e:
        logger.warning(
            "sca.parsers.requirements: cannot resolve %s: %s", path, e
        )
        return []
    if resolved in visited:
        return []
    visited.add(resolved)

    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.requirements: read failed for %s: %s", resolved, e
        )
        return []

    deps: List[Dependency] = []
    for raw_line in _logical_lines(text):
        commented = False
        stripped = raw_line.strip()
        if _COMMENT_LINE_RE.match(stripped):
            if not _INCLUDE_COMMENTED:
                continue
            # Try parsing the body of the comment as a requirement. Strip
            # one or more leading ``#`` and following whitespace; if
            # what's left doesn't parse as a PEP 508 line, the parser
            # silently drops it (so ``# pip install foo`` and ``# this
            # is just a note`` don't pollute findings).
            body = stripped.lstrip("#").lstrip()
            if not body:
                continue
            line = body
            commented = True
        else:
            line = _strip_comment(raw_line).strip()
            if not line:
                continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            include_path = _include_path(line, resolved.parent)
            if include_path is None:
                continue
            deps.extend(_parse_file(include_path, depth + 1, visited))
            continue
        if _is_pip_option(line):
            continue

        editable = False
        if line.startswith("-e ") or line.startswith("--editable "):
            editable = True
            line = line.split(maxsplit=1)[1].strip()

        # Strip trailing inline directives that pip permits on a
        # requirement line (currently just ``--hash=...``). Anything
        # before the first such token is the actual requirement spec.
        line = _strip_inline_directives(line)
        if not line:
            continue

        d = _parse_requirement_line(
            line, declared_in=resolved, editable=editable,
            commented=commented,
        )
        if d is not None:
            deps.append(d)
    return deps


def _logical_lines(text: str) -> List[str]:
    """Join backslash-continued lines into single logical lines."""
    out: List[str] = []
    buf: List[str] = []
    for raw in text.splitlines():
        if raw.endswith("\\"):
            buf.append(raw[:-1])
            continue
        buf.append(raw)
        out.append("".join(buf))
        buf = []
    if buf:
        out.append("".join(buf))
    return out


def _strip_comment(line: str) -> str:
    """Drop ``# comment`` while preserving ``#`` inside URL fragments.

    pip treats ``#`` as a comment unless it appears after a URL's ``#egg=``
    fragment. Since both ``packaging.requirements.Requirement`` and the
    fallback URL handler do their own URL parsing, we only strip ``#``
    that's clearly a comment: preceded by whitespace or at start-of-line.
    """
    if _COMMENT_LINE_RE.match(line):
        return ""
    # Find first '#' preceded by whitespace.
    out_chars: List[str] = []
    prev_was_space = True   # treat start-of-line as preceding whitespace
    for ch in line:
        if ch == "#" and prev_was_space:
            break
        out_chars.append(ch)
        prev_was_space = ch.isspace()
    return "".join(out_chars).rstrip()


def _strip_inline_directives(line: str) -> str:
    """Drop trailing ``--hash=...`` (and similar pip directives) from a line.

    pip allows ``django==4.2.7 --hash=sha256:abcd``; PEP 508 doesn't.
    Anything from the first ``--hash`` onward is dropped.
    """
    # Tokenise on whitespace; truncate at the first directive token.
    tokens = line.split()
    out: List[str] = []
    for tok in tokens:
        if tok.startswith("--hash"):
            break
        out.append(tok)
    return " ".join(out)


def _is_pip_option(line: str) -> bool:
    head = line.split()[0] if line.split() else ""
    if head.startswith("--"):
        return any(line.startswith(p) for p in _PIP_OPTION_PREFIXES)
    if head in ("-i", "-f"):
        return True
    return False


def _include_path(line: str, parent_dir: Path) -> Optional[Path]:
    """Extract the path argument from ``-r``/``--requirement``/``-c`` lines."""
    parts = line.split(maxsplit=1)
    if len(parts) != 2:
        return None
    candidate = parts[1].strip()
    # Drop trailing inline options if any (rare; pip accepts e.g. --hash
    # only for top-level requirements, not includes — we still split on
    # whitespace to be safe).
    candidate = candidate.split()[0]
    if not candidate:
        return None
    p = Path(candidate)
    if not p.is_absolute():
        p = parent_dir / p
    return p


def _parse_requirement_line(
    line: str,
    *,
    declared_in: Path,
    editable: bool,
    commented: bool = False,
) -> Optional[Dependency]:
    """Parse one non-include requirement line; return None if unparseable."""
    if _looks_like_url_only(line):
        if commented:
            # `# https://ollama.ai` is documentation, not a dep. Without an
            # `#egg=name` we'd synthesise a fake `<url:...>` entry that
            # adds noise (and may leak internal URLs into reports).
            return None
        d = _from_url_spec(line, declared_in, editable=editable)
        if d is not None:
            d.commented_out = commented
        return d

    try:
        req = Requirement(line)
    except InvalidRequirement as e:
        logger.debug(
            "sca.parsers.requirements: invalid requirement %r in %s: %s",
            line, declared_in, e,
        )
        return None

    # Commented lines without a version specifier are almost always section
    # headers (`# Core`, `# Testing`, `# Linting`), not dep declarations.
    # Only emit commented entries that carry an explicit version pin —
    # otherwise the report fills up with false-positive `unpinned` finds.
    if commented and not list(req.specifier) and not req.url:
        return None

    pin_style, version = _classify_specifier(req.specifier, req.url)
    version_floor, version_ceiling = _spec_bounds(req.specifier)
    name = req.name
    if req.url:
        if req.url.startswith(_VCS_PREFIXES):
            pin_style = PinStyle.GIT
        elif req.url.startswith(("file:", "./", "../", "/", "~/")):
            pin_style = PinStyle.PATH
        else:
            pin_style = PinStyle.PATH

    if editable and pin_style is PinStyle.UNKNOWN:
        pin_style = PinStyle.PATH

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=_normalise_name(name),
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(name, version),
        parser_confidence=_confidence(pin_style, version, editable),
        version_floor=version_floor,
        version_ceiling=version_ceiling,
        commented_out=commented,
    )


def _looks_like_url_only(line: str) -> bool:
    """True if line is a bare VCS/HTTP/file spec without a pkg-name prefix."""
    head = line.split(" ", 1)[0]
    if head.startswith(_VCS_PREFIXES):
        return True
    if head.startswith(("http://", "https://", "file:", "./", "../", "/")):
        return True
    return False


def _from_url_spec(
    spec: str, declared_in: Path, *, editable: bool
) -> Optional[Dependency]:
    """Best-effort row for a bare URL/path requirement.

    The dependency name is recovered from ``#egg=name`` if present; otherwise
    we synthesise a placeholder so dedup still works.
    """
    name: Optional[str] = None
    version: Optional[str] = None
    if "#egg=" in spec:
        egg = spec.split("#egg=", 1)[1].split("&", 1)[0]
        if "==" in egg:
            name, version = egg.split("==", 1)
        else:
            name = egg
    if name is None:
        # Fall back to the URL stem; not a real package name but at least
        # disambiguates dedup keys.
        name = f"<url:{Path(spec).name or spec}>"

    pin_style = PinStyle.GIT if spec.startswith(_VCS_PREFIXES) else PinStyle.PATH
    if editable and pin_style is PinStyle.UNKNOWN:
        pin_style = PinStyle.PATH

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=_normalise_name(name),
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(name, version),
        parser_confidence=Confidence(
            "medium",
            reason="requirements.txt URL/path requirement; name from #egg=",
        ),
    )


def _classify_specifier(
    spec: SpecifierSet,
    url: Optional[str],
) -> Tuple[PinStyle, Optional[str]]:
    if url:
        # Resolved by the caller.
        return PinStyle.UNKNOWN, None
    items = list(spec)
    if not items:
        return PinStyle.WILDCARD, None
    # An ``==`` / ``===`` clause pins the version exactly even when it
    # sits alongside range bounds: ``>=2.0,==2.7.0,<3.0`` resolves to
    # exactly 2.7.0. The sibling bounds are a deliberate record of the
    # safe corridor — floor for downgrades, ceiling for upgrades — that
    # harden preserves across runs. The *effective* version is the
    # ``==`` operand, so classify the whole spec as EXACT.
    exact = next(
        (s for s in items if s.operator in ("==", "===")), None)
    if exact is not None:
        return PinStyle.EXACT, exact.version
    if len(items) == 1:
        only = items[0]
        op = only.operator
        ver = only.version
        if op == "~=":
            return PinStyle.TILDE, ver
        # >=, <=, >, <, != — a single bound is still a range.
        return PinStyle.RANGE, ver
    return PinStyle.RANGE, None


def _spec_bounds(spec) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(floor, ceiling)`` from a ``SpecifierSet``: the tightest
    lower (``>=`` / ``>``) and upper (``<`` / ``<=``) version bounds, or
    None when absent.

    harden records these so a future bounded *downgrade* knows how far
    down is acceptable (floor) and an upgrade knows its ceiling. ``==`` /
    ``~=`` / ``!=`` clauses pin or exclude — they don't bound the
    corridor — so they're ignored here.
    """
    if spec is None or Version is None:
        return None, None

    def _key(v: str):
        try:
            return Version(v)
        except Exception:                   # noqa: BLE001
            return Version("0")

    lowers = [s.version for s in spec if s.operator in (">=", ">")]
    uppers = [s.version for s in spec if s.operator in ("<", "<=")]
    floor = max(lowers, key=_key) if lowers else None
    ceiling = min(uppers, key=_key) if uppers else None
    return floor, ceiling


def _normalise_name(name: str) -> str:
    """PEP 503 normalisation: lower-case + dashes/underscores/dots collapsed."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _confidence(
    pin_style: PinStyle, version: Optional[str], editable: bool
) -> Confidence:
    if editable:
        return Confidence(
            "medium",
            reason="requirements.txt editable install; version unresolved",
        )
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason="requirements.txt spec unrecognised")
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence(
            "medium",
            reason="requirements.txt git/path source; version best-effort",
        )
    if version is None:
        return Confidence("medium", reason="requirements.txt unpinned entry")
    return Confidence("high", reason="requirements.txt structured spec")


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:pypi/{_normalise_name(name)}"
    if version:
        return f"{base}@{version}"
    return base


def _is_requirements_file(path: Path) -> bool:
    name = path.name
    return name.startswith("requirements") and name.endswith(".txt")


register(predicate=_is_requirements_file)(parse)
