"""pip resolver wrapper.

Uses ``pip-compile`` (from pip-tools): the system install when
available, otherwise pip-tools installed into an ephemeral venv and
pip-compile retried from there (see the PEP 668 section below).
``pip-compile`` is the canonical way to deterministically resolve a
``requirements.in``-style spec into a fully-pinned
``requirements.txt`` without actually installing anything.

Neither path executes install hooks — pip-compile resolves from
wheel metadata without installing, and source-dist fallback is
disabled: ``PIP_ONLY_BINARY=:all:`` is set in the child environment
at every invocation site (system pip-compile, venv pipeline, batch
script), so pip never downloads an sdist and never runs a package's
build backend. A manifest that genuinely needs an sdist fails the
dry-run loudly with a clean non-success :class:`ResolverResult`.
The ``allow_sdist_builds`` escape hatch (CLI:
``--allow-sdist-builds``) skips the env var for operators who accept
build-backend execution inside the sandbox — see
:class:`PipResolver`.

PEP 668 (externally-managed-environment) handling
-------------------------------------------------
Most modern Linux distros ship the system Python marked
"externally-managed" (``/usr/lib/python*/EXTERNALLY-MANAGED``). When
pip detects that marker it refuses operations to protect distro state
— even ``--dry-run`` is blocked. raptor-sca scans run on operator
systems; if the system pip-compile refuses (or is missing), we fall
back to creating an ephemeral venv, installing pip-tools into it,
and re-running pip-compile with the venv's pip (which doesn't have
the marker). Per-run cost is ~3-5s for venv create + pip-tools
install. The venv lives at ``/tmp/raptor-sca-venv-<pid>-<hash>/``
— the sandbox mounts most of the project tree read-only, so the
per-call tmpfs at ``/tmp`` is the writeable surface — and vanishes
with that tmpfs when the sandbox call ends. See
:meth:`PipResolver._venv_dir` for the path rationale.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import sys
from pathlib import Path

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


# Metadata-only resolution policy (see package docstring in
# ``__init__.py``): force pip to consider wheels only. Building an
# sdist runs the package's build backend — arbitrary code, even under
# the sandbox — so the resolver refuses by default. ``PIP_ONLY_BINARY``
# is pip's environment-variable form of ``--only-binary``; it reaches
# pip through pip-compile at every invocation site, including the
# shell pipelines.
_ONLY_BINARY_ENV = "PIP_ONLY_BINARY=:all:"

# Process-wide default for the ``allow_sdist_builds`` escape hatch.
# The resolver registry constructs its ``PipResolver()`` singleton at
# import time, so the per-run ``--allow-sdist-builds`` CLI flag flows
# through this module-level default (same pattern as the parsers'
# module-level setters toggled by ``pipeline.run_sca``).
_ALLOW_SDIST_BUILDS_DEFAULT = False


def set_allow_sdist_builds(value: bool) -> None:
    """Set the process-wide default for :attr:`PipResolver.allow_sdist_builds`.

    Instances constructed with an explicit ``allow_sdist_builds``
    keep their pinned value; instances using the default (including
    the registry singleton) pick this up on the next ``dry_run``.
    """
    global _ALLOW_SDIST_BUILDS_DEFAULT
    _ALLOW_SDIST_BUILDS_DEFAULT = bool(value)


def _real_python() -> str:
    """Return the realpath of the running Python interpreter.

    ``sys.executable`` may live under ``$HOME`` (e.g. pyenv, asdf,
    user-installed Python) — but the sandbox uses ``fake_home=True``
    which hides ``$HOME`` from the child. Resolving the symlink chain
    to the underlying binary (typically under ``/usr/bin/``) makes the
    interpreter reachable inside the sandbox.
    """
    return os.path.realpath(sys.executable)


class PipResolver:
    """``pip-compile`` (preferred) with ephemeral-venv fallback.

    First tries system ``pip-compile`` in the sandbox; if that fails
    for any reason (PEP 668 refusal, missing binary, ``$HOME``-hidden
    install path under ``fake_home=True``, version mismatch, …) we
    fall back to creating an ephemeral venv at
    ``/tmp/raptor-sca-venv-<pid>-<hash>/`` and running pip-tools we
    install into it. The venv path always works given network access
    to PyPI, at the cost of ~5-8s setup per PyPI manifest dir.

    Supports batched cascade resolution
    (:meth:`dry_run_batch`) — one shared venv handles N manifests
    concurrently inside a single sandbox session. The ``SUPPORTS_BATCH``
    class flag is the opt-in marker the cascade orchestrator looks at.

    ``PIP_ONLY_BINARY=:all:`` is **always** set in the child
    environment — this is the metadata-only mode; pip never builds
    an sdist (which would run the package's build backend) via this
    path. A manifest whose deps only ship sdists fails the dry-run
    loudly. ``allow_sdist_builds=True`` (CLI: ``--allow-sdist-builds``)
    skips the env var — the trade-off is that pip may then execute
    arbitrary build-backend code from the resolved packages, contained
    only by the sandbox. Default is off.
    """

    SUPPORTS_BATCH = True

    def __init__(self, *, allow_sdist_builds: bool | None = None) -> None:
        # ``None`` defers to the process-wide default managed by
        # :func:`set_allow_sdist_builds` (CLI flag plumbing); an
        # explicit bool pins this instance regardless of the flag.
        self._allow_sdist_builds = allow_sdist_builds

    @property
    def allow_sdist_builds(self) -> bool:
        """True when sdist builds are permitted for this resolver."""
        if self._allow_sdist_builds is not None:
            return self._allow_sdist_builds
        return _ALLOW_SDIST_BUILDS_DEFAULT

    ecosystem = "PyPI"
    # Files the resolver-cache wrapper hashes to key memoisation.
    # See ``_cache.py``. ``constraints.txt`` would also affect
    # resolution but pip-compile picks it up only via ``-c`` on the
    # command line, not as a discovered manifest, so projects that
    # use it will need to invalidate manually if the cache miss-
    # fires (rare).
    MANIFEST_FILES = (
        "requirements.txt", "requirements.in", "pyproject.toml",
    )
    @property
    def proxy_hosts(self) -> list:
        """Egress-proxy hostname allowlist for the pip subprocess.

        Three-layer resolution: operator override
        (``~/.config/raptor/sca-proxy-hosts.json`` ``"pip"`` key) →
        calibrated profile → static default
        (``pypi.org`` + ``files.pythonhosted.org``).

        Org configs on a private mirror should populate the override;
        the static default covers public PyPI."""
        from ._proxy_hosts import proxy_hosts_for_pip
        return proxy_hosts_for_pip()

    def is_available(self) -> bool:
        # pip itself ships with every Python install; require a usable
        # one to claim availability.
        return _check_tool(["pip", "--version"])

    def matches(self, project_dir: Path) -> bool:
        # pip is the fallback resolver for the PyPI ecosystem — it
        # matches anything with a pip-style manifest. PoetryResolver
        # is registered before pip and steals projects with a
        # ``[tool.poetry]`` section in pyproject.toml.
        return _find_pip_manifest(project_dir) is not None

    def dry_run(
        self, project_dir: Path, *, timeout: int = 120,
    ) -> ResolverResult:
        if not self.is_available():
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=False,
                error="pip not found in PATH",
            )

        manifest = _find_pip_manifest(project_dir)
        if manifest is None:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=("no requirements*.txt or pyproject.toml in "
                       f"{project_dir}"),
            )

        # Prefer system pip-compile when present — it's deterministic
        # and produces a clean fully-pinned output. When the system
        # tool fails for any reason (PEP 668, missing, $HOME-hidden,
        # …), fall back to the venv pipeline which always works given
        # network access to PyPI.
        if _check_tool(["pip-compile", "--version"]):
            res = self._run_pip_compile(project_dir, manifest, timeout)
            if res.success:
                return res
            logger.debug(
                "sca.pip: system pip-compile failed (%s); "
                "falling back to venv pipeline", res.error,
            )
        return self._run_pip_compile_in_venv(
            project_dir,
            str(manifest.relative_to(project_dir)),
            timeout,
        )

    # ----- internals -----

    def _run_pip_compile(
        self, project_dir: Path, manifest: Path, timeout: int,
    ) -> ResolverResult:
        """Run system pip-compile under the sandbox. Returns a
        non-success ResolverResult on any failure — the caller is
        responsible for retrying via the venv pipeline.
        """
        rel_manifest = str(manifest.relative_to(project_dir))
        cmd = ["pip-compile", "--quiet", "--output-file", "-",
               rel_manifest]
        if not self.allow_sdist_builds:
            # Wheels only — an sdist-requiring manifest fails the
            # dry-run loudly instead of running its build backend.
            # ``env(1)`` prefix adds the single variable while the
            # sandbox's safe-env posture stays intact for the rest.
            cmd = ["env", _ONLY_BINARY_ENV, *cmd]
        try:
            proc = _run(
                cmd,
                cwd=project_dir, timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=f"pip-compile timed out after {timeout}s",
            )
        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem,
                success=False, available=True,
                error=(proc.stderr.strip()
                        or f"pip-compile exited {proc.returncode}"),
                raw_output=raw,
            )
        return ResolverResult(
            ecosystem=self.ecosystem,
            success=True, available=True,
            proposed_lockfile=proc.stdout.encode("utf-8"),
            raw_output=raw,
        )

    # --- ephemeral-venv pipeline ---------------------------------------

    def _venv_dir(self, project_dir: Path) -> Path:
        """Per-run venv path.

        Lives under ``/tmp`` rather than the project tree because the
        sandbox makes most subdirs of the project read-only at the
        mount-ns level (``output=cwd`` permits writes only to a
        narrow surface — a deeply-nested manifest dir like
        ``.devcontainer/`` may hit "Read-only file system" when we
        try to mkdir inside it). ``/tmp`` is in the sandbox's default
        writable_paths and is per-pid namespaced so concurrent runs
        on the same project don't collide.

        ``project_dir`` is hashed into the suffix so two parallel
        scans of different projects (e.g. CI matrix) get distinct
        venvs even when their PIDs happen to clash across containers.
        """
        import hashlib
        import os as _os
        proj_hash = hashlib.sha256(
            str(project_dir).encode("utf-8")
        ).hexdigest()[:8]
        return Path("/tmp") / f"raptor-sca-venv-{_os.getpid()}-{proj_hash}"

    def _create_venv(
        self, project_dir: Path, timeout: int,
    ) -> tuple[Path | None, str | None]:
        """Compute the ephemeral venv path; creates nothing itself.

        Each ``_run`` call gets a fresh mount-ns with its own tmpfs at
        ``/tmp`` — venv state created in one call does NOT persist into
        a follow-up call. So venv-create, ensurepip, the pip-tools
        install and the resolver invocation all have to run as a single
        shell pipeline inside one sandbox call. The sole caller,
        :meth:`_run_pip_compile_in_venv`, builds that pipeline with
        :meth:`_venv_setup_script` as its prefix; this helper only
        returns ``(venv_dir, None)`` so the caller can locate the venv
        by path inside its own sandbox call. Filesystem state is
        intentionally NOT created or inspected here (it would be gone
        with the sandbox tmpfs anyway).
        """
        return self._venv_dir(project_dir), None

    def _venv_setup_script(self, venv_dir: Path) -> str:
        """Shell snippet that creates the venv + bootstraps pip.

        Runs as the prefix of a combined sandbox invocation. ``set -e``
        so any failure short-circuits the rest of the pipeline.
        ``ensurepip`` doesn't accept ``--quiet`` (only ``-v`` for
        verbose), so silence its bundled-wheel install banner via
        stdout redirection instead.

        Override ``HOME`` and ``XDG_CACHE_HOME`` so pip / pip-tools
        write their caches under ``/tmp`` (writable in the sandbox)
        rather than the sandbox's ``fake_home`` bind-mount, which is
        read-only on some configurations.

        Exports ``PIP_ONLY_BINARY=:all:`` in the preamble (unless the
        ``allow_sdist_builds`` escape hatch is set) so every pip /
        pip-compile invocation in the pipeline — including the batch
        script's per-manifest subshells — inherits the wheels-only
        policy.
        """
        qvenv = shlex.quote(str(venv_dir))
        qpython = shlex.quote(_real_python())
        only_binary = (
            "" if self.allow_sdist_builds
            else f"export {_ONLY_BINARY_ENV}; "
        )
        return (
            f"set -e; "
            f"{only_binary}"
            f"export HOME={qvenv}/.fake-home; "
            f"export XDG_CACHE_HOME={qvenv}/.fake-home/.cache; "
            f"mkdir -p $HOME $XDG_CACHE_HOME; "
            f"{qpython} -m venv --without-pip {qvenv} && "
            f"{qvenv}/bin/python -m ensurepip --upgrade >/dev/null && "
        )

    # ----- batched venv pipeline (one venv, N parallel pip-compile) -----

    def dry_run_batch(
        self, project_dirs: list[Path], *,
        common_root: Path | None = None,
        timeout: int = 120,
    ) -> list[ResolverResult]:
        """Resolve N PyPI manifests in a single sandbox call.

        Standard ``dry_run`` builds a fresh venv per manifest —
        ``pip install pip-tools`` is network-bound at ~3-5s per call,
        so 4 manifests cost ~12s × 4 = ~50s sequentially. This batch
        path builds the venv ONCE and runs the N pip-compile
        invocations concurrently inside it (background subshells with
        ``wait``). Per-manifest cost drops to whatever pip-compile
        itself takes (~3-5s); total scales with the slowest manifest,
        not the sum.

        Constraints + how they're satisfied:
          * Sandbox tmpfs at ``/tmp`` resets per ``_run`` call — so
            EVERYTHING (venv build, ensurepip, pip-tools install,
            all pip-compile runs, result collection) goes in ONE
            shell pipeline.
          * ``target=cwd`` confines reads — so ``cwd`` is set to
            ``common_root`` (the scan target), expanding the sandbox
            surface to cover every manifest. Each pip-compile then
            ``cd`` into its own project_dir (relative path).
          * Concurrent pip-compiles share a venv — pip-tools is
            install-once, the resolver state is per-process so
            multiple ``pip-compile`` processes don't conflict.

        Falls back to per-manifest ``dry_run`` (the sequential path)
        when:
          * ``common_root`` is missing (caller didn't supply one).
          * Any project_dir isn't under ``common_root``.
          * ``len(project_dirs) <= 1`` — no batching benefit.
        """
        # Trivial cases — no batching benefit, use the sequential
        # path so the unbatched code stays the canonical reference
        # behaviour.
        if len(project_dirs) <= 1:
            return [
                self.dry_run(p, timeout=timeout) for p in project_dirs
            ]
        if common_root is None or not self.is_available():
            return [
                self.dry_run(p, timeout=timeout) for p in project_dirs
            ]

        # Resolve each manifest path relative to common_root. If any
        # project_dir is outside, we can't cover it with one
        # ``target=common_root`` sandbox — fall back to sequential.
        manifests: list[tuple[Path, Path, Path]] = []
        for pd in project_dirs:
            try:
                rel_dir = pd.resolve().relative_to(common_root.resolve())
            except ValueError:
                return [
                    self.dry_run(p, timeout=timeout) for p in project_dirs
                ]
            manifest = _find_pip_manifest(pd)
            if manifest is None:
                # Surface as a per-result failure later; for now
                # record so the index alignment stays correct.
                manifests.append((pd, rel_dir, None))      # type: ignore[arg-type]
            else:
                rel_manifest = manifest.relative_to(pd)
                manifests.append((pd, rel_dir, rel_manifest))

        # Use a single venv for the whole batch. Path includes the
        # common_root hash so concurrent scans of different repos
        # don't collide. Lives under /tmp (sandbox-writable).
        import hashlib
        proj_hash = hashlib.sha256(
            str(common_root).encode("utf-8")
        ).hexdigest()[:8]
        venv_dir = Path(
            f"/tmp/raptor-sca-venv-batch-{os.getpid()}-{proj_hash}"
        )

        script = self._build_batch_script(venv_dir, manifests)
        try:
            proc = _run(
                ["sh", "-c", script],
                cwd=common_root, timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return [
                ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=f"PEP 668 batch venv pipeline timed out "
                          f"after {timeout}s",
                )
                for _ in project_dirs
            ]

        return self._parse_batch_output(
            proc.stdout, proc.stderr, proc.returncode, manifests,
        )

    def _build_batch_script(
        self, venv_dir: Path,
        manifests: list[tuple[Path, Path, Path | None]],
    ) -> str:
        """Generate the combined sh script. One venv build, then N
        parallel pip-compile invocations writing to per-manifest
        result files, then a delimiter-separated dump back through
        stdout for the parser."""
        import shlex

        results_dir = f"{venv_dir}/results"
        # Stage 1: venv setup (the slow, network-bound part runs once).
        # ``set +e`` so a single pip-compile failure doesn't abort the
        # rest — we want per-manifest results.
        parts: list[str] = [
            "set +e",
            self._venv_setup_script(venv_dir),
            (f"{venv_dir}/bin/python -m pip install --quiet pip-tools "
             f"|| {{ echo '__BATCH_PIP_TOOLS_FAILED__' >&2; exit 90; }}"),
            f"mkdir -p {results_dir}",
        ]
        # Stage 2: per-manifest pip-compile in parallel. Each
        # subshell cd's into its dir and writes stdout/stderr/rc to
        # its own result files so concurrent runs don't interleave.
        for i, (_pd, rel_dir, rel_manifest) in enumerate(manifests):
            if rel_manifest is None:
                # Couldn't find a pip manifest — record a synthetic
                # rc=98 so the parser can attribute the failure.
                parts.append(
                    f"echo '__BATCH_NO_MANIFEST__' "
                    f"> {results_dir}/{i}.err"
                )
                parts.append(f"echo 98 > {results_dir}/{i}.rc")
                continue
            qdir = shlex.quote(str(rel_dir) or ".")
            qmf = shlex.quote(str(rel_manifest))
            parts.append(
                f"( cd {qdir} && {venv_dir}/bin/pip-compile "
                f"--quiet --output-file - {qmf} "
                f"> {results_dir}/{i}.out 2> {results_dir}/{i}.err; "
                f"echo $? > {results_dir}/{i}.rc ) &"
            )
        parts.append("wait")
        # Stage 3: emit results delimited so the Python parser can
        # reassemble per-manifest outputs from the single stdout
        # stream. Markers chosen to be implausible inside pip-compile
        # output (no pip-compile error message uses these literal
        # tokens).
        for i in range(len(manifests)):
            parts.append(f"echo '===RAPTOR_BATCH_OUT_{i}==='")
            parts.append(f"cat {results_dir}/{i}.out 2>/dev/null || true")
            parts.append(f"echo '===RAPTOR_BATCH_RC_{i}==='")
            parts.append(f"cat {results_dir}/{i}.rc 2>/dev/null || echo 99")
            parts.append(f"echo '===RAPTOR_BATCH_ERR_{i}==='")
            parts.append(f"cat {results_dir}/{i}.err 2>/dev/null || true")
        parts.append("echo '===RAPTOR_BATCH_END==='")
        return "\n".join(parts)

    def _parse_batch_output(
        self, stdout: str, stderr: str, returncode: int,
        manifests: list[tuple[Path, Path, Path | None]],
    ) -> list[ResolverResult]:
        """Split the batch sh stdout back into per-manifest
        ResolverResults. The script emitted three markers per index
        (OUT, RC, ERR) plus a final BATCH_END; we scan for them in
        order and bucket the lines between."""
        # Whole-pipeline failures (e.g. venv build, pip-tools install)
        # produce no per-manifest markers — surface the same error to
        # every result.
        if "__BATCH_PIP_TOOLS_FAILED__" in stderr:
            return [
                ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error="batch venv pipeline: pip-tools install failed "
                          "(network or PyPI proxy issue)",
                    raw_output=(stdout + "\n" + stderr).strip(),
                )
                for _ in manifests
            ]
        if "===RAPTOR_BATCH_END===" not in stdout:
            # Pipeline died before reaching the end marker. Fall back
            # to per-result failure with the raw output so the
            # operator can diagnose.
            return [
                ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=(
                        "batch venv pipeline aborted before per-manifest "
                        "results emitted: "
                        + (stderr.strip() or stdout.strip())[:200]
                    ),
                    raw_output=(stdout + "\n" + stderr).strip(),
                )
                for _ in manifests
            ]

        # Build a section index: for each i, find OUT_i, RC_i, ERR_i
        # marker offsets and slice the stdout between them.
        results: list[ResolverResult] = []
        for i in range(len(manifests)):
            out_marker = f"===RAPTOR_BATCH_OUT_{i}==="
            rc_marker = f"===RAPTOR_BATCH_RC_{i}==="
            err_marker = f"===RAPTOR_BATCH_ERR_{i}==="
            next_marker = (
                f"===RAPTOR_BATCH_OUT_{i + 1}==="
                if i + 1 < len(manifests)
                else "===RAPTOR_BATCH_END==="
            )
            sections = _slice_between(
                stdout, out_marker, rc_marker, err_marker, next_marker,
            )
            if sections is None:
                results.append(ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error="batch parser: missing markers for index "
                          f"{i} (script output truncated?)",
                    raw_output=(stdout + "\n" + stderr).strip(),
                ))
                continue
            out_text, rc_text, err_text = sections
            try:
                rc = int(rc_text.strip().splitlines()[0])
            except (ValueError, IndexError):
                rc = 99
            if rc == 98:
                results.append(ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=(
                        f"no requirements*.txt or pyproject.toml in "
                        f"{manifests[i][0]}"
                    ),
                ))
                continue
            if rc != 0:
                results.append(ResolverResult(
                    ecosystem=self.ecosystem, success=False, available=True,
                    error=(
                        err_text.strip()
                        or f"pip-compile exited {rc}"
                    ),
                    raw_output=(out_text + "\n" + err_text).strip(),
                ))
                continue
            results.append(ResolverResult(
                ecosystem=self.ecosystem, success=True, available=True,
                proposed_lockfile=out_text.encode("utf-8"),
                raw_output=(out_text + "\n" + err_text).strip(),
            ))
        return results

    def _run_pip_compile_in_venv(
        self, project_dir: Path, rel_manifest: str, timeout: int,
    ) -> ResolverResult:
        """Retry pip-compile in an ephemeral venv after PEP 668 refusal.

        All steps run in a single sandbox call: each ``_run`` invocation
        gets a fresh mount-ns + tmpfs at ``/tmp``, so the venv from one
        call wouldn't survive into the next. Combine venv-create +
        ensurepip + pip-tools install + pip-compile into one shell
        pipeline.
        """
        venv_dir, _ = self._create_venv(project_dir, timeout)
        # ``set -e`` short-circuits on any step's non-zero exit so the
        # whole call returns the first failing step's stderr.
        qvenv = shlex.quote(str(venv_dir))
        script = (
            self._venv_setup_script(venv_dir)
            + f"{qvenv}/bin/python -m pip install --quiet pip-tools && "
            + f"{qvenv}/bin/pip-compile --quiet "
            + f"--output-file - {shlex.quote(str(rel_manifest))}"
        )
        try:
            proc = _run(
                ["sh", "-c", script],
                cwd=project_dir, timeout=timeout,
                proxy_hosts=self.proxy_hosts,
            )
        except subprocess.TimeoutExpired:
            return ResolverResult(
                ecosystem=self.ecosystem, success=False, available=True,
                error=f"venv pipeline timed out after {timeout}s",
            )
        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem, success=False, available=True,
                error=("venv pipeline failed: "
                       + (proc.stderr.strip() or "exit non-zero")),
                raw_output=raw,
            )
        return ResolverResult(
            ecosystem=self.ecosystem, success=True, available=True,
            proposed_lockfile=proc.stdout.encode("utf-8"),
            raw_output=raw,
        )

def _slice_between(
    text: str, m_start: str, m_mid1: str, m_mid2: str, m_end: str,
) -> tuple[str, str, str] | None:
    """Pull three sub-strings out of ``text`` delimited by four markers.
    Returns ``(between m_start..m_mid1, m_mid1..m_mid2, m_mid2..m_end)``
    each with leading/trailing newlines stripped, or ``None`` when any
    marker is missing / out of order."""
    i_start = text.find(m_start)
    if i_start < 0:
        return None
    i_mid1 = text.find(m_mid1, i_start + len(m_start))
    if i_mid1 < 0:
        return None
    i_mid2 = text.find(m_mid2, i_mid1 + len(m_mid1))
    if i_mid2 < 0:
        return None
    i_end = text.find(m_end, i_mid2 + len(m_mid2))
    if i_end < 0:
        return None
    a = text[i_start + len(m_start):i_mid1].strip("\n")
    b = text[i_mid1 + len(m_mid1):i_mid2].strip("\n")
    c = text[i_mid2 + len(m_mid2):i_end].strip("\n")
    return (a, b, c)


def _find_pip_manifest(project_dir: Path) -> Path | None:
    """Return the path to a top-level pip-style manifest, if any.

    Preference order:
      1. ``pyproject.toml`` — fully self-describing project metadata.
      2. ``requirements.txt`` (the canonical name).
      3. ``requirements.in`` — pip-tools input.
      4. Any other ``requirements*.txt`` (covers ``requirements-dev``,
         ``requirements-all-optional``, ``requirements-prod``, etc.).

    Every declared ``MANIFEST_FILES`` entry outranks the glob fallback
    — the resolver cache hashes only declared files, so selecting a
    glob-matched file while a declared one exists would key the cache
    on a file that isn't the one being resolved (edits to the resolved
    file would then miss invalidation). With this order, whenever the
    cache is keyed at all, the resolved manifest is one of the hashed
    files; glob-only projects hash to ``None`` and bypass the cache.
    """
    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        return pyproject
    canonical = project_dir / "requirements.txt"
    if canonical.exists():
        return canonical
    req_in = project_dir / "requirements.in"
    if req_in.exists():
        return req_in
    # Fall through to any other requirements*.txt — sorted for
    # determinism so the same manifest is picked across runs.
    for c in sorted(project_dir.glob("requirements*.txt")):
        return c
    return None


__all__ = ["PipResolver"]
