"""ARG name → upstream-latest source mapping.

Separate from ``_arg_version_pins._BUILTIN_ARG_MAP`` because the
two answer different questions:

* ``_BUILTIN_ARG_MAP`` (in parsers/inline_installs/) — given an
  ARG name, what ``(ecosystem, package_name)`` does the pinned
  version refer to for CVE / OSV lookup?
* ``_BUILTIN_UPSTREAM_MAP`` (here) — given an ARG name, where do
  we look up the LATEST stable version to propose as a bump
  target?

For some ARGs these are the same source (a PyPI package looks up
via OSV AND via PyPI metadata for latest). For others they
diverge: CODEQL_VERSION has no SCA ecosystem (out of OSV's
ecosystem set) but DOES have an upstream-latest source
(``github/codeql-cli-binaries``'s GitHub releases).

The bumper uses both: ``_BUILTIN_ARG_MAP`` to decide whether to
do bump-time CVE verdict, ``_BUILTIN_UPSTREAM_MAP`` to decide
where to fetch "what's the latest"."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Literal, Optional


@dataclass(frozen=True)
class UpstreamSource:
    """Where to look up the latest stable version.

    Originally an ARG-pin-only concept; expanded 2026-05-20 to
    also annotate the other bump-candidate kinds for audit-trail
    completeness (so ``--json`` output records the upstream
    source coordinate for every candidate, not just ARG pins).

    ``kind`` discriminates the registry:
      * ``"github_release"`` — GitHub releases API
        (``/repos/{coord}/releases/latest``). Used by ARG ↔
        GitHub-release-tagging projects (semgrep, ruff, mypy …)
        AND by ``gha_uses:`` candidates (each ``uses:`` ref is
        an ``owner/repo``).
      * ``"github_tag"`` — GitHub tags API
        (``/repos/{coord}/tags``; for projects that tag but
        don't cut releases).
      * ``"oci_tag"`` — OCI/Docker registry tag list. Used by
        ``from_image`` (Dockerfile FROM) and ``yaml_image``
        (k8s / compose / GitLab CI ``image:``) candidates.
        ``coordinate`` is the ``registry/repository`` string.
      * ``"pypi_meta"`` — PyPI registry. Used by
        ``inline_install_pip`` candidates (``RUN pip install
        pkg==N`` patterns). ``coordinate`` is the package name.
      * ``"helm_index"`` — Helm chart index. Used by
        ``helm_chart`` candidates. ``coordinate`` is the chart
        name (operator-supplied; index URL configured
        elsewhere).
      * ``"git_remote"`` — direct git refs. Used by
        ``git_submodule`` candidates. ``coordinate`` is the
        remote URL.

    ``coordinate`` is kind-specific (see above)."""

    kind: Literal[
        "github_release", "github_tag",
        "oci_tag", "pypi_meta", "helm_index", "git_remote",
    ]
    coordinate: str


# Built-in mapping. Coordinates picked to align with the
# corresponding ``_BUILTIN_ARG_MAP`` entries — every ARG with
# a CVE ecosystem mapping ALSO needs an upstream source so the
# bumper can propose a target version.
_BUILTIN_UPSTREAM_MAP: Dict[str, UpstreamSource] = {
    # PyPI tools — most cut proper GitHub releases.
    "SEMGREP_VERSION": UpstreamSource("github_release", "semgrep/semgrep"),
    "BANDIT_VERSION":  UpstreamSource("github_release", "PyCQA/bandit"),
    "RUFF_VERSION":    UpstreamSource("github_release", "astral-sh/ruff"),
    "MYPY_VERSION":    UpstreamSource("github_release", "python/mypy"),
    "PYRIGHT_VERSION": UpstreamSource("github_release", "microsoft/pyright"),
    "BLACK_VERSION":   UpstreamSource("github_release", "psf/black"),
    "PYLINT_VERSION":  UpstreamSource("github_release", "pylint-dev/pylint"),

    # JS toolchain. Anthropic claude-code uses tags (not releases),
    # so use github_tag.
    "CLAUDE_CODE_VERSION": UpstreamSource(
        "github_tag", "anthropics/claude-code",
    ),
    "ESLINT_VERSION":      UpstreamSource("github_release", "eslint/eslint"),
    "PRETTIER_VERSION":    UpstreamSource("github_release", "prettier/prettier"),
    "TYPESCRIPT_VERSION":  UpstreamSource(
        "github_release", "microsoft/TypeScript",
    ),

    # Toolchain ARGs that don't have a SCA ecosystem but DO have
    # an upstream-latest source. The bumper proposes bumps; the
    # verdict ladder for these is OSV-blind (no CVE eco mapping)
    # but the recent_publish detector still fires off the GitHub
    # release date.
    "CODEQL_VERSION": UpstreamSource(
        "github_release", "github/codeql-cli-binaries",
    ),
}


def lookup_upstream(arg_name: str) -> Optional[UpstreamSource]:
    """Return the upstream source for ``arg_name``, or ``None``
    if unknown. ``None`` means "the bumper can't propose a target
    for this ARG"; the operator can still get a verdict on a
    hand-specified target via ``raptor-sca check``."""
    return _BUILTIN_UPSTREAM_MAP.get(arg_name)
