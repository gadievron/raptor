"""Per-ecosystem native resolver wrappers.

Some upgrade plans only resolve cleanly when *additional* deps bump too —
"cascade resolution." The mechanical layer can't fully solve that; only
the language's own package manager can. This package wraps each
ecosystem's resolver in a uniform Protocol so ``raptor-sca fix`` can
validate proposed plans without re-implementing dep resolution.

Each resolver takes a project directory (containing the proposed
manifest), runs the language's dry-run resolver, and returns success +
the proposed lockfile content.

Sandbox model
-------------

Every resolver subprocess runs sandboxed via :func:`core.sandbox.run`
with the egress proxy engaged. From the resolver's point of view it
talks to the registry over HTTPS as normal; from the host's point of
view:

  - Outbound TCP is locked to the in-process proxy port (Landlock).
  - The proxy's hostname allowlist is set to the resolver's own
    ``proxy_hosts`` — npm can reach registry.npmjs.org and nothing
    else; pip can reach pypi.org + files.pythonhosted.org; etc.
  - UDP/DNS is blocked (seccomp), closing the DNS-exfil gap.
  - Reads are confined (``restrict_reads=True``) — $HOME is invisible
    so a tool vuln cannot read ~/.ssh, ~/.aws/credentials,
    ~/.config/raptor/, etc.
  - $HOME is faked (``fake_home=True``) — the tool's own caches
    (~/.cache/pip, ~/.npm, ~/go/pkg/mod) live in a per-run scratch
    directory, not the operator's account.

Tools we wrap today, grouped by ecosystem (all use ``--dry-run`` /
``--ignore-scripts`` / metadata-only flags so install hooks never
execute even *inside* the sandbox — defence in depth):

  - npm ecosystem: npm, yarn (classic + Berry), pnpm
  - PyPI ecosystem: pip / pip-compile, Poetry
  - Maven ecosystem: Maven, Gradle (system + ./gradlew)
  - crates.io: Cargo (temp-copy + ``cargo update``)
  - RubyGems: Bundler (temp-copy + ``bundle lock``)
  - NuGet: ``dotnet restore --use-lock-file``
  - Packagist: ``composer update --lock --no-install``
  - Go: ``go mod tidy``

Selection: when multiple resolvers register for one ecosystem (e.g.
yarn/pnpm/npm all map to the "npm" OSV ecosystem),
:func:`get_resolver` picks the right one for a given project
directory by checking each resolver's :meth:`Resolver.matches`
(typically a check for the tool's lockfile or config marker).
Single-tool ecosystems Just Work because the lone candidate is
always the fallback.

Scope of this layer: validate that a proposed manifest resolves
cleanly. We *do not* mutate the user's repo, and we never run install
hooks. ``proposed_lockfile`` is returned as bytes so the caller can
compare it to whatever lockfile shape the operator expects.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, Sequence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result + Protocol
# ---------------------------------------------------------------------------

@dataclass
class ResolverResult:
    """Return shape for a dry-run resolve."""

    ecosystem: str
    success: bool
    available: bool                  # was the toolchain present at all?
    proposed_lockfile: Optional[bytes] = None
    error: Optional[str] = None
    raw_output: str = ""


class Resolver(Protocol):
    """Every resolver wrapper conforms to this Protocol.

    Multiple resolvers can register for the same OSV ecosystem when
    multiple toolchains exist for it (npm/yarn/pnpm all resolve the
    "npm" ecosystem; pip/poetry both resolve "PyPI"; Maven/Gradle
    both resolve "Maven"). :func:`get_resolver` picks the best one
    for a given project directory by calling :meth:`matches` —
    typically a check for the tool's lockfile or config file.
    """

    ecosystem: str
    # Hostnames the resolver legitimately needs to reach for its
    # registry / module-proxy queries. Threaded into
    # :func:`core.sandbox.run` as the egress proxy's allowlist.
    proxy_hosts: Sequence[str]

    def is_available(self) -> bool:
        """True if the toolchain is installed and invocable."""
        ...

    def matches(self, project_dir: Path) -> bool:
        """True if this resolver's toolchain owns the given project.

        Detection is file-based — e.g. ``YarnResolver`` returns True
        when ``yarn.lock`` is present, ``PoetryResolver`` when
        ``[tool.poetry]`` is in ``pyproject.toml``. When multiple
        candidates match, the registered order wins; when none match,
        the first registered resolver for the ecosystem is the
        fallback so single-tool ecosystems Just Work.
        """
        ...

    def dry_run(self, project_dir: Path,
                *, timeout: int = 120) -> ResolverResult:
        """Run a dry-run resolve. Never mutates the project."""
        ...


def dry_run_batch(
    resolver: "Resolver",
    project_dirs: Sequence[Path],
    *,
    common_root: Optional[Path] = None,
    timeout: int = 120,
) -> "list[ResolverResult]":
    """Resolve N project_dirs and return one ``ResolverResult`` per
    input dir, in input order.

    Default behaviour is a sequential loop calling ``dry_run`` per
    project_dir — sandbox-correct but slow. Resolvers that can amortise
    cross-manifest setup (e.g. :class:`PipResolver` builds one shared
    venv and runs N pip-compile calls inside it) opt in by setting
    a class-level ``SUPPORTS_BATCH = True`` and providing a
    ``dry_run_batch(project_dirs, *, common_root, timeout)`` method.

    Opt-in marker rather than just ``hasattr(resolver, "dry_run_batch")``
    because attribute presence isn't safe to detect on duck-typed
    resolvers (``unittest.mock.MagicMock`` auto-creates the attribute,
    and ``list(MagicMock())`` returns ``[]`` rather than raising — a
    silent zero-result trap). The class-level flag is explicit and
    test-stub-safe.
    """
    if getattr(type(resolver), "SUPPORTS_BATCH", False):
        try:
            return list(resolver.dry_run_batch(    # type: ignore[attr-defined]
                list(project_dirs),
                common_root=common_root, timeout=timeout,
            ))
        except Exception as e:                          # noqa: BLE001
            # Defensive: a buggy batch impl falls back to sequential
            # rather than aborting the whole scan. Logged so the
            # operator can spot if the fast path ever stops working.
            logger.warning(
                "sca.resolvers: %s.dry_run_batch failed (%s); "
                "falling back to sequential dry_run",
                type(resolver).__name__, e,
            )
    return [resolver.dry_run(p, timeout=timeout) for p in project_dirs]


# ---------------------------------------------------------------------------
# Shared subprocess helper
# ---------------------------------------------------------------------------

# Cache: tool availability is stable for the lifetime of the process.
# Resolvers and the cascade orchestrator each probe `is_available`
# (``<tool> --version``) independently — without caching, ``npm
# --version`` (which is genuinely ~1s on most systems) gets invoked
# 3-4× per scan and dominates short-scan wall-clock time.
_CHECK_TOOL_CACHE: "dict[tuple, bool]" = {}


def _check_tool(cmd: list, *, timeout: int = 5) -> bool:
    """Return True if running ``cmd`` exits 0 and writes something to
    stdout/stderr (used as ``<tool> --version`` availability probe).

    Runs unsandboxed: the probe is a RAPTOR-chosen command (``<tool>
    --version``) reading no attacker-controlled input. Going through
    :func:`core.sandbox.run` for every availability check would burn
    a namespace + Landlock setup on every cascade attempt, which is
    measurable (~50ms × 3 resolvers = visible startup latency).

    Result is cached per-process. Tool installation/removal during a
    single scan is not a use case we support.
    """
    key = tuple(cmd)
    if key in _CHECK_TOOL_CACHE:
        return _CHECK_TOOL_CACHE[key]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        result = proc.returncode == 0 and bool(
            proc.stdout.strip() or proc.stderr.strip())
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        result = False
    _CHECK_TOOL_CACHE[key] = result
    return result


def _run(
    cmd: list,
    cwd: Path,
    timeout: int,
    proxy_hosts: Sequence[str],
    env: Optional[dict] = None,
    block_network: bool = False,
) -> subprocess.CompletedProcess:
    """Run a resolver subprocess sandboxed.

    Routes through :func:`core.sandbox.run` with:

      - ``target=cwd``: Landlock engages with the project dir as a
        readable surface so the resolver can read manifests +
        lockfiles.
      - ``output=<tempdir>``: the sandbox's writable surface is a
        per-call tempdir, NOT the project dir. The resolver's venv
        lives under ``/tmp`` anyway (see ``pip.py:_venv_dir``); the
        project dir doesn't need to be writable. Routing ``output=``
        to a tempdir avoids two collateral effects of using ``cwd``:
          * The sandbox creates ``.home/`` inside ``output=`` for the
            fake-HOME (see ``core/sandbox/context.py:_fake_home``).
            With ``output=cwd``, that pollutes the operator's
            project dir — bug observed during compromise-detection
            harness work, May 2026.
          * Any resolver bug that tried to write to cwd (lockfile
            mutation, log file dump) would silently land there.
            Routing writes through a tempdir means such bugs surface
            as EACCES at write time instead of polluting the tree.
      - ``use_egress_proxy=True`` + ``proxy_hosts``: HTTPS_PROXY is
        injected into the child env and TCP is pinned (Landlock) to
        the in-process proxy's loopback port. Any attempt to reach a
        host outside ``proxy_hosts`` fails the proxy's allowlist
        check; UDP/DNS is blocked at seccomp.
      - ``restrict_reads=True`` + ``fake_home=True``: $HOME is hidden
        so a resolver vuln (or a missed ``--ignore-scripts``) cannot
        read ~/.ssh / ~/.aws / ~/.config/raptor; the tool's own
        caches are written to the tempdir-located fake $HOME.

    Never raises on non-zero exit — the caller decides what's a
    failure. Does propagate :class:`subprocess.TimeoutExpired` from
    ``core.sandbox.run`` when ``timeout`` elapses; each per-resolver
    ``dry_run`` catches it and translates to a ``ResolverResult`` with
    a "timed out after Xs" error.
    """
    import tempfile
    from core.sandbox.context import run as sandbox_run

    with tempfile.TemporaryDirectory(prefix="raptor-sca-resolver-") as out_dir:
        # When the call is local-only (e.g. ``python -m venv``,
        # ``ensurepip``), pass ``block_network=True`` and skip the proxy
        # entirely — the sandbox refuses ``use_egress_proxy=True`` with an
        # empty allowlist, and we don't want network anyway.
        sandbox_kwargs = {
            "cwd": str(cwd),
            "capture_output": True,
            "text": True,
            "timeout": timeout,
            "env": env,
            "target": str(cwd),
            "output": out_dir,
            "restrict_reads": True,
            "fake_home": True,
            "caller_label": "sca-resolver",
        }
        if block_network or not proxy_hosts:
            sandbox_kwargs["block_network"] = True
        else:
            sandbox_kwargs["use_egress_proxy"] = True
            sandbox_kwargs["proxy_hosts"] = list(proxy_hosts)

        return sandbox_run(cmd, **sandbox_kwargs)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

from . import bundler as _bundler     # noqa: E402,F401
from . import cargo as _cargo         # noqa: E402,F401
from . import composer as _composer   # noqa: E402,F401
from . import gomod as _gomod         # noqa: E402,F401
from . import gradle as _gradle       # noqa: E402,F401
from . import maven as _maven         # noqa: E402,F401
from . import npm as _npm             # noqa: E402,F401
from . import nuget as _nuget         # noqa: E402,F401
from . import pip as _pip             # noqa: E402,F401
from . import pnpm as _pnpm           # noqa: E402,F401
from . import poetry as _poetry       # noqa: E402,F401
from . import yarn as _yarn           # noqa: E402,F401


# Resolver registry. Order matters per ecosystem in two ways:
#   1. Selection: the FIRST resolver whose ``matches(project_dir)``
#      returns True wins. Specific tools (yarn/pnpm/poetry/Gradle)
#      must come BEFORE the generic fallback (npm/pip/Maven) or
#      they'd never be picked.
#   2. Fallback: when no candidate matches (rare — empty project, or
#      project missing every recognised manifest), :func:`get_resolver`
#      returns the LAST candidate. The last one is the most-generic
#      tool, which fails with the clearest "no <ecosystem-canonical
#      manifest> found" message rather than "no yarn.lock found".
_RESOLVERS = (
    _yarn.YarnResolver(),
    _pnpm.PnpmResolver(),
    _npm.NpmResolver(),
    _poetry.PoetryResolver(),
    _pip.PipResolver(),
    _gomod.GoResolver(),
    _cargo.CargoResolver(),
    _gradle.GradleResolver(),
    _maven.MavenResolver(),
    _bundler.BundlerResolver(),
    _nuget.NugetResolver(),
    _composer.ComposerResolver(),
)


def get_resolver(
    ecosystem: str, project_dir: Optional[Path] = None,
) -> Optional[Resolver]:
    """Return the best resolver for ``(ecosystem, project_dir)``.

    When ``project_dir`` is given, prefer a resolver whose
    :meth:`Resolver.matches` returns True for that directory (e.g.
    ``YarnResolver`` if ``yarn.lock`` is present). When no candidate
    matches — or when ``project_dir`` is omitted entirely — return
    the LAST resolver registered for the ecosystem. The registry is
    ordered so the last entry is the most-generic tool (npm / pip /
    maven), which produces clearer error messages on the rare
    "project has no recognised manifest at all" path than e.g. yarn
    refusing for lack of a package.json.

    Returns ``None`` if no resolver is registered for the ecosystem.
    """
    candidates = [r for r in _RESOLVERS if r.ecosystem == ecosystem]
    if not candidates:
        return None
    if project_dir is not None:
        for r in candidates:
            if r.matches(project_dir):
                return r
    return candidates[-1]


__all__ = [
    "Resolver",
    "ResolverResult",
    "get_resolver",
]
