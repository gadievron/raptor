"""``.pre-commit-config.yaml`` parser.

Pre-commit (https://pre-commit.com) declares hooks per repository:

    repos:
      - repo: https://github.com/astral-sh/ruff-pre-commit
        rev: v0.6.9
        hooks:
          - id: ruff
      - repo: https://github.com/psf/black
        rev: 24.10.0
        hooks:
          - id: black
      - repo: local
        hooks:
          - id: my-script
            entry: scripts/check.sh

Each entry pins a git ``rev`` of the hook-providing repo. Pre-commit
will fetch + run the hook on every commit, so a compromised hook
provider runs code on developer machines and in CI.

This parser:

  * Walks the YAML's ``repos`` array.
  * For each entry, resolves the ``repo:`` URL through a curated
    ``repo: → registry`` map (``data/precommit_repo_map.json``)
    so well-known hooks (ruff, black, mypy, etc.) get classified
    against their actual ecosystem (PyPI / npm / RubyGems) — OSV
    CVE matching then fires against the underlying tool, not just
    the GitHub repo name.
  * Falls back to ecosystem ``"GitHub"`` for unmapped repos
    (visibility in the SBOM; OSV won't match).
  * Skips ``repo: local`` entries (no version, no external code
    to scan).
  * Skips ``repo: meta`` entries (pre-commit's own pseudo-repo
    for built-in hooks).

Each repo emits ONE Dependency row regardless of how many ``hooks:``
entries it has — ``rev:`` pins the whole repository, so the per-
hook rows would all carry the same version. The hook IDs are
captured in ``source_extra.hook_ids`` for SBOM context.

Versions for unmapped (GitHub-purled) entries follow the
``.gitmodules`` model: emit with ``ecosystem="GitHub"`` and
``version=<rev>``. CVE matching won't fire (no GitHub OSV
ecosystem), but the SBOM has the entry for triage.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


_REPO_MAP_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "precommit_repo_map.json"
)

_GITHUB_FALLBACK_ECOSYSTEM = "GitHub"


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------


@register(filenames=[".pre-commit-config.yaml", ".pre-commit-config.yml"])
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "sca.parsers.precommit: read failed for %s: %s", path, e,
        )
        return []
    try:
        import yaml                 # type: ignore[import-untyped]
        from .._yaml_fast import safe_load
    except ImportError:
        logger.debug(
            "sca.parsers.precommit: PyYAML not installed; skipping %s",
            path,
        )
        return []
    try:
        data = safe_load(text)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.parsers.precommit: YAML parse failed for %s: %s",
            path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    repo_map = _load_repo_map()

    repos = data.get("repos") or []
    if not isinstance(repos, list):
        return []

    out: List[Dependency] = []
    for entry in repos:
        dep = _build_dep(entry, declared_in=path, repo_map=repo_map)
        if dep is not None:
            out.append(dep)
        # ``additional_dependencies`` — extra PyPI / npm packages
        # the hook needs at runtime. Each entry is a PEP 508 / npm
        # spec string. Common in ``mirrors-mypy`` configs:
        #   additional_dependencies: ["pydantic>=2.5", "types-PyYAML"]
        out.extend(_extract_additional_deps(entry, declared_in=path))
    return out


def _extract_additional_deps(
    entry: Any, *, declared_in: Path,
) -> List[Dependency]:
    """Extract ``hooks[].additional_dependencies`` entries.

    Each hook may declare extra runtime deps; pre-commit installs
    them into the hook's isolated environment. The string format
    follows the hook's underlying language (PyPI for ruff / mypy /
    black hooks, npm for eslint / prettier mirror hooks). We
    classify by reasonable heuristic: if the hook's repo has a
    mapped ecosystem (``PyPI`` / ``npm`` / etc. in the curated
    map), additional_dependencies inherit that ecosystem. For
    unmapped repos we default to ``PyPI`` since the dominant
    pre-commit shape is Python-based.
    """
    if not isinstance(entry, dict):
        return []
    repo = entry.get("repo")
    if not isinstance(repo, str):
        return []
    if repo in ("local", "meta"):
        return []
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return []

    repo_map = _load_repo_map()
    canonical = _canonicalise_repo(repo)
    if canonical:
        mapping = repo_map.get(canonical)
        ecosystem = mapping["ecosystem"] if mapping else "PyPI"
    else:
        ecosystem = "PyPI"

    out: List[Dependency] = []
    for hook in hooks:
        if not isinstance(hook, dict):
            continue
        hook_id = hook.get("id") if isinstance(hook.get("id"), str) else None
        addl = hook.get("additional_dependencies")
        if not isinstance(addl, list):
            continue
        for spec in addl:
            if not isinstance(spec, str) or not spec.strip():
                continue
            dep = _build_addl_dep(
                spec=spec.strip(),
                ecosystem=ecosystem,
                declared_in=declared_in,
                hook_id=hook_id,
                hook_repo=repo,
            )
            if dep is not None:
                out.append(dep)
    return out


def _build_addl_dep(
    *,
    spec: str,
    ecosystem: str,
    declared_in: Path,
    hook_id: Optional[str],
    hook_repo: str,
) -> Optional[Dependency]:
    """Build a Dependency from one ``additional_dependencies``
    string. The grammar is the underlying language's install
    spec: PEP 508 for PyPI (``pydantic>=2.5``, ``types-PyYAML``),
    npm spec for npm (``@types/node@20``, ``eslint-plugin-foo``).

    For first cut we use a simple split heuristic — extract the
    name (everything up to the first ``>`` / ``=`` / ``<`` /
    ``~`` / ``@`` after position 0) and treat the rest as the
    version constraint. Sufficient for SBOM visibility; CVE
    matching uses the package name + parsed version.
    """
    # PyPI extras like ``foo[bar]`` strip the brackets for purl /
    # name. ``foo[bar]>=1.0`` → name=``foo``, version=``>=1.0``.
    name, version, pin_style = _classify_addl_spec(spec, ecosystem)
    if not name:
        return None
    purl_type = _eco_to_purl(ecosystem)
    purl = f"pkg:{purl_type}/{name}"
    if version:
        purl += f"@{version}"
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="dev",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "medium",
            reason=(
                f"pre-commit additional_dependencies spec {spec!r} "
                f"on hook {hook_id or '<unknown>'} from {hook_repo}"
            ),
        ),
        source_kind="precommit_additional",
        source_extra={
            "spec": spec,
            "hook_id": hook_id,
            "hook_repo": hook_repo,
        },
    )


def _classify_addl_spec(
    spec: str, ecosystem: str,
) -> "tuple[str, Optional[str], PinStyle]":
    """Split a PEP 508 / npm install spec into (name, version,
    pin_style)."""
    import re as _re
    if ecosystem == "npm" and spec.startswith("@"):
        # Scoped npm: ``@scope/name@version``.
        # First ``@`` is the scope marker; tag separator is the
        # second.
        tail_match = _re.search(r"^(@[^/]+/[^@<>=~ ]+)([<>=~@].*)?$", spec)
        if tail_match:
            name = tail_match.group(1)
            ver_part = tail_match.group(2) or ""
            ver_part = ver_part.lstrip("@").strip()
            return _wrap_version(name, ver_part)
    # PEP 508 / non-scoped npm — name is everything before the
    # first comparator / @ / [.
    m = _re.match(r"^([A-Za-z0-9._\-]+)(\[[^\]]*\])?(.*)$", spec)
    if not m:
        return "", None, PinStyle.UNKNOWN
    name = m.group(1)
    rest = m.group(3).strip()
    return _wrap_version(name, rest)


def _wrap_version(
    name: str, ver_part: str,
) -> "tuple[str, Optional[str], PinStyle]":
    if not ver_part:
        return name, None, PinStyle.WILDCARD
    if ver_part.startswith("=="):
        return name, ver_part[2:].strip(), PinStyle.EXACT
    if ver_part.startswith("^"):
        return name, ver_part[1:].strip(), PinStyle.CARET
    if ver_part.startswith("~"):
        return name, ver_part[1:].strip(), PinStyle.TILDE
    if any(ch in ver_part for ch in "<>") or "," in ver_part:
        return name, ver_part, PinStyle.RANGE
    if ver_part.startswith("="):
        return name, ver_part.lstrip("=").strip(), PinStyle.EXACT
    # Fallback: bare version.
    return name, ver_part.lstrip("@").strip() or None, PinStyle.EXACT


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _load_repo_map() -> Dict[str, Dict[str, str]]:
    """Load the curated repo→registry map. Per-call rather than
    module-level so a future test injection point stays simple."""
    try:
        text = _REPO_MAP_PATH.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Dict[str, str]] = {}
    for key, val in data.items():
        if key.startswith("_"):
            continue
        if not isinstance(val, dict):
            continue
        eco = val.get("ecosystem")
        name = val.get("name")
        if isinstance(eco, str) and isinstance(name, str):
            out[key] = {"ecosystem": eco, "name": name}
    return out


def _build_dep(
    entry: Any,
    *,
    declared_in: Path,
    repo_map: Dict[str, Dict[str, str]],
) -> Optional[Dependency]:
    if not isinstance(entry, dict):
        return None
    repo = entry.get("repo")
    if not isinstance(repo, str) or not repo.strip():
        return None
    repo = repo.strip()
    if repo in ("local", "meta"):
        return None

    rev = entry.get("rev")
    if not isinstance(rev, str) or not rev.strip():
        return None
    rev = rev.strip()

    canonical = _canonicalise_repo(repo)
    if not canonical:
        return None

    hooks_raw = entry.get("hooks") or []
    hook_ids: List[str] = []
    if isinstance(hooks_raw, list):
        for h in hooks_raw:
            if isinstance(h, dict):
                hid = h.get("id")
                if isinstance(hid, str):
                    hook_ids.append(hid)

    mapping = repo_map.get(canonical)
    pin_style = _classify_rev(rev)

    if mapping is not None:
        eco = mapping["ecosystem"]
        name = mapping["name"]
        purl_type = _eco_to_purl(eco)
        purl = f"pkg:{purl_type}/{name}@{rev}"
    else:
        # Unmapped repo — fall back to GitHub purl for visibility.
        # ``canonical`` is ``{host}/{path}`` (lowercased) from
        # _canonicalise_repo, so partition the host off explicitly
        # rather than substring-matching the prefix.
        eco = _GITHUB_FALLBACK_ECOSYSTEM
        host, _, path = canonical.partition("/")
        name = path if host == "github.com" and path else canonical
        purl = f"pkg:github/{name}@{rev}"

    return Dependency(
        ecosystem=eco,
        name=name,
        version=rev,
        declared_in=declared_in,
        scope="dev",
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high" if mapping is not None else "medium",
            reason=(
                f"pre-commit repo {repo} mapped to {eco}:{name}"
                if mapping is not None
                else f"pre-commit repo {repo} unmapped — emitted as "
                     f"GitHub purl"
            ),
        ),
        source_kind="precommit",
        source_extra={
            "repo": repo,
            "canonical": canonical,
            "hook_ids": hook_ids,
        },
    )


def _canonicalise_repo(url: str) -> Optional[str]:
    """Normalise a pre-commit ``repo:`` URL to a lookup key.

    ``https://github.com/astral-sh/ruff-pre-commit.git`` →
    ``github.com/astral-sh/ruff-pre-commit``.
    SSH form ``git@github.com:org/repo.git`` is normalised.
    Strips trailing ``.git`` and lowercases for case-insensitive
    map lookup.
    """
    url = url.strip().rstrip("/")
    if url.startswith("git@") and ":" in url:
        host, _, path = url[len("git@"):].partition(":")
        url = f"https://{host}/{path}"
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    if not host or not path:
        return None
    return f"{host}/{path}".lower()


def _classify_rev(rev: str) -> PinStyle:
    """Classify a pre-commit ``rev:`` string."""
    import re
    if re.fullmatch(r"[0-9a-fA-F]{40}", rev):
        return PinStyle.GIT
    if re.match(r"^v?\d", rev):
        return PinStyle.EXACT
    return PinStyle.UNKNOWN


def _eco_to_purl(ecosystem: str) -> str:
    """Map SCA ecosystem string → purl type. Mirrors the per-
    ecosystem conventions used elsewhere in the codebase."""
    return {
        "PyPI": "pypi",
        "npm": "npm",
        "RubyGems": "gem",
        "Cargo": "cargo",
        "Go": "golang",
        "NuGet": "nuget",
        "Packagist": "composer",
        "Maven": "maven",
    }.get(ecosystem, ecosystem.lower())
