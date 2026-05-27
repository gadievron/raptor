"""RubyGems parser.

Handles ``Gemfile`` (Bundler manifest, a Ruby DSL) and ``Gemfile.lock*``
(Bundler resolved-version output, a custom plain-text format).

The lockfile matcher is a *prefix* (``Gemfile.lock``) so it covers
release-time variants such as ``Gemfile.lock.release`` (ManageIQ) or
``Gemfile.lock.next`` (gem-version migrations) — same byte-for-byte
format, just renamed by convention. Pure ``Gemfile.modules`` (a DSL
fragment, not a lockfile) is excluded by the ``.lock`` substring.

The Gemfile is a Ruby script — fully Turing-complete — so we
deliberately don't execute it. We regex-parse the most common forms:

  gem 'rails'
  gem 'rails', '~> 7.1'
  gem 'rails', '7.1.2'
  gem 'rails', '>= 7.0', '< 8.0'
  gem 'rails', git: 'https://github.com/rails/rails', tag: 'v7.1'
  gem 'rails', github: 'rails/rails'
  gem 'rails', path: '../local'
  gem 'rails', source: 'https://my.gem.repo'

Anything that requires evaluating Ruby control flow (``if``, ``unless``,
loops) gets ``parser_confidence=Confidence("medium", reason="Gemfile DSL
— heuristic regex")`` because we may miss conditionally-included gems.

``Gemfile.lock`` is a structured plain-text format with a ``GEM``
section listing resolved versions and their dependencies. We extract
just the ``<name> (<version>)`` rows from the ``specs:`` block.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "RubyGems"
_PURL_TYPE = "gem"


# ``gem 'name'`` or ``gem "name"`` followed by optional version arg(s).
_GEM_LINE_RE = re.compile(
    r"""^\s*gem\s+
        (?P<quote>['"])(?P<name>[A-Za-z0-9_.\-]+)(?P=quote)
        (?P<rest>[^\n#]*)
    """,
    re.VERBOSE,
)

# Matches each '<op> <ver>' inside a comma-separated spec list.
_VERSION_SPEC_RE = re.compile(
    r"""(['"])\s*
        (?P<op>=|>=|<=|>|<|~>|\^)?\s*
        (?P<ver>[\w.\-+]+)
        \s*\1""",
    re.VERBOSE,
)


@register(filenames=["Gemfile"])
def parse_manifest(path: Path) -> List[Dependency]:
    """Parse a ``Gemfile`` and emit one Dependency per ``gem`` line."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.gemfile: cannot read %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    has_control_flow = bool(
        re.search(r"^\s*(if|unless|case|while)\b", text, re.MULTILINE))
    confidence_level = "medium" if has_control_flow else "high"
    reason = ("Gemfile DSL — heuristic regex" if has_control_flow
              else "Gemfile DSL — straight-line script")

    for raw in text.splitlines():
        # Skip comment-only lines fast.
        if raw.lstrip().startswith("#"):
            continue
        # Strip trailing comments.
        line = re.split(r"(?<!\\)#", raw, maxsplit=1)[0]
        m = _GEM_LINE_RE.match(line)
        if not m:
            continue
        name = m.group("name")
        rest = m.group("rest") or ""
        dep = _build_dep(
            name, rest, declared_in=path,
            confidence_level=confidence_level, reason=reason,
        )
        if dep is None or dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


def _is_gemfile_lockfile(path: Path) -> bool:
    """True for ``Gemfile.lock`` and release-time variants like
    ``Gemfile.lock.release`` (ManageIQ) / ``Gemfile.lock.next``."""
    return path.name.startswith("Gemfile.lock")


@register(predicate=_is_gemfile_lockfile)
def parse_lockfile(path: Path) -> List[Dependency]:
    """Parse a ``Gemfile.lock`` GEM section and emit one Dependency per
    resolved gem.

    Format (abridged):

        GEM
          remote: https://rubygems.org/
          specs:
            actionpack (7.1.2)
              activesupport (= 7.1.2)
              rack (>= 2.2.4)
            actionview (7.1.2)
              activesupport (= 7.1.2)

    We extract the top-level ``<name> (<version>)`` rows (indented two
    spaces under ``specs:``); inner-indented rows are runtime deps of
    the listed gem and don't get separate entries (they appear as their
    own top-level rows in the GEM section anyway).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.gemfile: cannot read %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    in_specs = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.lstrip().startswith("specs:"):
            in_specs = True
            continue
        if not in_specs:
            continue
        # Section change (non-indented or new GEM-like header).
        if line and not line.startswith(" "):
            in_specs = False
            continue
        # Top-level gem rows are indented exactly 4 spaces; runtime-dep
        # rows are indented 6+. Match strictly.
        m = re.match(r"^    (\S+)\s+\(([^)]+)\)\s*$", line)
        if not m:
            continue
        name = m.group(1)
        version = m.group(2).strip()
        # A Bundler-resolved version always starts with a digit (optionally
        # with a ``-platform`` suffix). Anything else is a malformed /
        # non-standard ``specs:`` row (templated lockfile, source annotation
        # mis-captured) — skip it rather than emit a phantom gem that 404s
        # on every registry lookup.
        if not (version and version[0].isdigit()):
            continue
        # ``<version>-<platform>`` forms (e.g. ``1.0.0-x86_64-linux``)
        # — keep the version as-is; OSV matches per-platform.
        dep = Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            declared_in=path,
            scope="main",
            is_lockfile=True,
            pin_style=PinStyle.EXACT,
            direct=False,                    # join layer flips when matched
            purl=_build_purl(name, version),
            parser_confidence=Confidence(
                "high",
                reason="Gemfile.lock plain-text — deterministic structure",
            ),
            source_kind="lockfile",
        )
        if dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_dep(
    name: str,
    rest: str,
    *,
    declared_in: Path,
    confidence_level: str,
    reason: str,
) -> Optional[Dependency]:
    """Translate ``gem '<name>'`` + tail args into a Dependency.

    ``rest`` is the text after the name token, up to end-of-line / comment.
    Recognises:
      - ``, '~> 7.1'``, ``, '>= 1.0', '< 2.0'``
      - ``, git: '...'`` / ``, github: '...'`` / ``, gitlab: '...'``
      - ``, path: '...'``
    """
    rest_clean = rest.strip().lstrip(",").strip()
    pin_style = PinStyle.WILDCARD
    version: Optional[str] = None

    # Git / path / github overrides — checked first, they win.
    if re.search(r"\bgit\s*:\s*(['\"])", rest_clean):
        pin_style = PinStyle.GIT
    elif re.search(r"\bgithub\s*:\s*(['\"])", rest_clean):
        pin_style = PinStyle.GIT
    elif re.search(r"\bpath\s*:\s*(['\"])", rest_clean):
        pin_style = PinStyle.PATH
    else:
        pin_style, version = _parse_version_specs(rest_clean)

    purl = _build_purl(name, version)
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            confidence_level,        # type: ignore[arg-type]
            reason=reason,
        ),
        source_kind="manifest",
    )


def _parse_version_specs(rest: str) -> Tuple[PinStyle, Optional[str]]:
    """Find one or more version-spec tokens in the tail of a gem line."""
    matches = list(_VERSION_SPEC_RE.finditer(rest))
    if not matches:
        return PinStyle.WILDCARD, None
    if len(matches) > 1:
        return PinStyle.RANGE, None
    m = matches[0]
    op = m.group("op") or "="
    ver = m.group("ver")
    # A RubyGems version always starts with a digit. A hand-written Gemfile
    # can quote a non-literal where a version goes (e.g. a constant such as
    # ``gem 'ibm_db', IBM_DB`` lexed loosely), which would otherwise be
    # emitted as version "IBM_DB" and 404 on every registry lookup. Reject
    # anything that isn't version-shaped — treat the gem as unpinned.
    if not (ver and ver[0].isdigit()):
        return PinStyle.WILDCARD, None
    if op in ("=",):
        return PinStyle.EXACT, ver
    if op == "~>":
        return PinStyle.TILDE, ver
    if op == "^":
        return PinStyle.CARET, ver
    return PinStyle.RANGE, ver


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = ["parse_manifest", "parse_lockfile"]
