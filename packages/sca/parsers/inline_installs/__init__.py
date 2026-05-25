"""Extract package installs from Dockerfile / devcontainer.json / shell / GHA.

These files aren't manifests, but they declare deps just as authoritatively
as ``requirements.txt`` — and they're routinely overlooked. A ``RUN
pip install django==4.2.7`` baked into a Dockerfile is a real PyPI dep
that needs CVE matching; ``apt install nginx=1.18.0-6`` is a Debian dep
that needs OSV lookup.

This package is **registry-driven**: each supported package manager is one
entry in :data:`packages.sca.parsers.inline_installs._managers._MANAGERS`.
Adding ``cargo install`` or ``gem install`` is ~10 lines in
:mod:`._managers`.

Module layout:

  * :mod:`._managers` — per-PM argument parsers + the registry
    table (~600 lines kept off the main file).
  * This ``__init__`` — file-shape entry points (parse_dockerfile,
    parse_devcontainer_json, parse_shell_script, parse_gha_workflow),
    the shared shell-line scanner, and the ``register()`` calls
    that wire each entry point to the parser dispatcher.

What we extract:

  - ``pip`` / ``pip3`` / ``python -m pip`` / ``python3 -m pip`` → PyPI
  - ``apt`` / ``apt-get install`` → Debian
  - ``yum`` / ``dnf install`` → Red Hat
  - ``apk add`` / ``apk install`` → Alpine
  - ``npm`` / ``yarn add`` / ``pnpm add`` / ``npx`` → npm
  - ``cargo install`` / ``gem install`` / ``brew install`` /
    ``go install`` → corresponding ecosystems

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
  - Dockerfile ``FROM`` base-image scanning is handled by a sibling
    module (``packages.sca.dockerfile_from``), not this parser. That
    module pulls the actual installed-package state from the base
    image's registry layers — much more accurate than guessing
    Debian / Red Hat / Alpine from inline ``apt-get install`` lines.

All emitted Dependency rows carry ``source_kind`` ∈ ``{"dockerfile",
"devcontainer", "shell_script", "gha_workflow", "gha_uses"}`` so the
report can show where each dep came from.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple

from ...models import Confidence, Dependency, PinStyle
from .. import register
from ._managers import (
    _MANAGERS,
    _NAME_RE,
    _PkgManager,
    _tokenise,
    # Per-PM parsers re-exported for backwards compat — older
    # callers may still ``from packages.sca.parsers.inline_installs
    # import _parse_apt_args`` etc.
    _classify_pip_token,
    _emit_npm_pkg,
    _legacy_single_spec,
    _parse_apk_args,
    _parse_apt_args,
    _parse_brew_args,
    _parse_cargo_args,
    _parse_gem_args,
    _parse_go_install_args,
    _parse_npm_args,
    _parse_npx_args,
    _parse_pip_args,
    _parse_versioned_flag_args,
    _parse_yum_args,
    _split_npm_token,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Text → Dependency rows
# ---------------------------------------------------------------------------

def _strip_inline_comment(line: str) -> str:
    """Drop trailing ``# ...`` comments from a shell line.

    Conservative: only strips ``#`` preceded by whitespace or at start, to
    avoid butchering ``url=https://example.com/path#frag``.
    """
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
            body = stripped.lstrip("#").lstrip() if commented else line
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
    skip_ecosystems: Optional[set] = None,
) -> List[Dependency]:
    """Apply the manager patterns to each logical line; emit deps.

    Each subline is one install command — at most one manager should apply.
    We pick the *latest-starting* match so more-specific wrappers like
    ``uv pip install`` win over the inner ``pip install``.

    ``skip_ecosystems`` lets a caller suppress specific managers in
    favour of a more authoritative source. The Dockerfile entry
    point uses this to delegate apt/Debian extraction to
    ``core.dockerfile.apt`` (POSIX-correct, sudo / pipe / bash -c
    aware) without duplicating those packages.
    """
    skip_ecosystems = skip_ecosystems or set()
    deps: List[Dependency] = []
    for line_no, body, commented in lines:
        cleaned = _strip_inline_comment(body)
        for sub in _split_compound(cleaned):
            best: Optional[Tuple[_PkgManager, "re.Match[str]"]] = None
            for mgr in _MANAGERS:
                if mgr.ecosystem in skip_ecosystems:
                    continue
                m = mgr.pattern.search(sub)
                if not m:
                    continue
                if best is None or m.start() > best[1].start():
                    best = (mgr, m)
            if best is None:
                continue
            mgr, m = best
            if commented and m.start() != 0:
                # Comment lines have their leading ``#`` + whitespace
                # stripped before reaching here, so an install verb at
                # the very start (``m.start() == 0``) reflects a
                # deliberate ``# pip install foo==1.0``-style
                # disabled-install hint — keep it. Anything else is
                # prose that happens to mention ``pip install`` /
                # ``apt install`` mid-sentence (e.g. ``# uv pip
                # install keeps a single source of truth``), where
                # tokens past the install verb are English words, not
                # package names. Skip to avoid emitting bogus deps.
                continue
            args = sub[m.end():]
            for parsed in mgr.parse_args(args):
                # Most managers yield (name, version, pin); the pip
                # manager additionally yields (floor, ceiling) corridor
                # bounds. Unpack defensively so both shapes work.
                name, version, pin = parsed[0], parsed[1], parsed[2]
                floor = parsed[3] if len(parsed) > 3 else None
                ceiling = parsed[4] if len(parsed) > 4 else None
                deps.append(_make_dep(
                    name=name, version=version, pin_style=pin,
                    version_floor=floor, version_ceiling=ceiling,
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
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            if line[i:i+2] in ("&&", "||"):
                out.append("".join(buf))
                buf = []
                i += 2
                continue
            if ch == ";":
                out.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
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
    version_floor: Optional[str] = None,
    version_ceiling: Optional[str] = None,
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
        version_floor=version_floor,
        version_ceiling=version_ceiling,
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

    Three-pass design:

    1. **apt / Debian** via ``core.dockerfile.extract_apt_packages``.
       The shared substrate is POSIX-correct (shlex tokenisation,
       sudo / pipe / subshell-paren / ``bash -c`` recursion / comment-
       in-continuation handling) and carries multi-stage attribution.
    2. **All other managers** (pip / yum / dnf / apk / npm / cargo /
       gem / brew / go) via the legacy regex-based shell scanner,
       with apt skipped to avoid duplicates.
    3. **ARG version pins** via ``_arg_version_pins.extract``. The
       canonical example is a devcontainer Dockerfile pinning
       ``ARG SEMGREP_VERSION=1.117.0`` for build-time install.
       The extractor maps a small set of well-known ARG names to
       their SCA ecosystem; operator-supplied inline comments
       (``# raptor-sca: PyPI:foo``) override the built-in map.

    All three passes return ``Dependency`` rows; downstream
    pipeline treats them uniformly. ARG pins carry
    ``source_kind="dockerfile_arg"`` and ``scope="build"`` so the
    operator can tell them apart from runtime app deps.
    """
    text = _safe_read(path)
    if text is None:
        return []
    deps: List[Dependency] = []
    # ARG pins first: when a Dockerfile both pins ``ARG FOO_VERSION=1.0``
    # AND has ``RUN pip install foo==${FOO_VERSION}``, the RUN scanner
    # emits ``foo@${FOO_VERSION}`` (literal placeholder string) and
    # ``select_canonical_for_osv`` picks the first manifest row per
    # ``(eco, name)``. Putting the ARG pass first means the concrete
    # version (``1.0``) wins and the placeholder row is deduped out.
    from . import _arg_version_pins
    deps.extend(_arg_version_pins.extract(text, path))
    deps.extend(_extract_apt_via_core_dockerfile(text, path))
    runs = _extract_dockerfile_run_blocks(text)
    deps.extend(_scan_shell_lines(
        runs, declared_in=path, source_kind="dockerfile",
        skip_ecosystems={"Debian"},
    ))
    return deps


def _extract_apt_via_core_dockerfile(
    text: str, path: Path,
) -> List[Dependency]:
    """Use ``core.dockerfile.apt`` to extract Debian deps from a
    Dockerfile.

    Returns one ``Dependency`` per ``AptPackage``. ``stage`` is
    threaded into ``scope`` so multi-stage SBOMs distinguish builder
    deps from runtime deps; absence of an ``AS <stage>`` clause
    falls back to ``scope="main"`` (the legacy default).
    """
    from core.dockerfile import (
        extract_apt_packages,
        parse_dockerfile as core_parse_dockerfile,
    )
    try:
        instructions = core_parse_dockerfile(text)
    except Exception:                               # noqa: BLE001
        logger.warning(
            "sca.parsers.inline_installs: core.dockerfile parse "
            "failed for %s — falling back to regex scanner",
            path, exc_info=True,
        )
        return []
    out: List[Dependency] = []
    for ap in extract_apt_packages(instructions):
        out.append(_apt_package_to_dep(ap, path))
    return out


def _apt_package_to_dep(ap, declared_in: Path) -> Dependency:
    canon = _canonicalise_name(ap.name, "Debian")
    purl_base = f"pkg:deb/debian/{canon}"
    purl = f"{purl_base}@{ap.version}" if ap.version else purl_base
    return Dependency(
        ecosystem="Debian",
        name=canon,
        version=ap.version,
        declared_in=declared_in,
        scope=ap.stage or "main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT if ap.version else PinStyle.WILDCARD,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high",
            reason=(
                f"core.dockerfile apt extractor at "
                f"{declared_in.name}:{ap.line}"
            ),
        ),
        commented_out=False,
        source_kind="dockerfile",
    )


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
    # Delegates to the shared size-bounded reader. Caps at 50 MB
    # (the package-wide default) — large enough for the biggest
    # legitimate Dockerfile / shell / GHA workflow, small enough
    # to refuse a hostile target-repo manifest that would
    # otherwise OOM the parser before the sandbox memory limit
    # kicks in. Returns None + logs a warning on bound violation;
    # the caller already treats None as "skip this file".
    from .._safe_read import read_bounded
    return read_bounded(path)


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
    if path.name == ".devcontainer.json":
        return True
    return False


def _is_shell_script(path: Path) -> bool:
    return path.suffix in (".sh", ".bash")


def _is_gha_workflow(path: Path) -> bool:
    if path.suffix not in (".yml", ".yaml"):
        return False
    parts = path.parts
    for j in range(len(parts) - 2):
        if parts[j] == ".github" and parts[j + 1] == "workflows":
            return True
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
    # Re-exports kept for the back-compat import path
    # ``from packages.sca.parsers.inline_installs import _parse_apt_args``;
    # used internally by tests and by older external callers. Listing
    # them in ``__all__`` is the canonical "yes this is intentional"
    # signal to ruff F401 and to import-star semantics.
    "_MANAGERS",
    "_NAME_RE",
    "_PkgManager",
    "_classify_pip_token",
    "_emit_npm_pkg",
    "_legacy_single_spec",
    "_parse_apk_args",
    "_parse_apt_args",
    "_parse_brew_args",
    "_parse_cargo_args",
    "_parse_gem_args",
    "_parse_go_install_args",
    "_parse_npm_args",
    "_parse_npx_args",
    "_parse_pip_args",
    "_parse_versioned_flag_args",
    "_parse_yum_args",
    "_split_npm_token",
    "_tokenise",
]
