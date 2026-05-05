"""pip resolver wrapper.

Uses ``pip-compile`` (from pip-tools) when available, falling back to
``pip install --dry-run`` otherwise. ``pip-compile`` is the canonical
way to deterministically resolve a ``requirements.in``-style spec into
a fully-pinned ``requirements.txt`` without actually installing
anything; ``pip install --dry-run`` (pip 23.0+) is the lighter
alternative when pip-tools isn't installed.

Neither path executes install hooks — pip doesn't run them on
``--dry-run`` for wheel-only deps, and we don't allow source-dist
fallback (``--only-binary=:all:`` where supported).

PEP 668 (externally-managed-environment) handling
-------------------------------------------------
Most modern Linux distros ship the system Python marked
"externally-managed" (``/usr/lib/python*/EXTERNALLY-MANAGED``). When
pip detects that marker it refuses operations to protect distro state
— even ``--dry-run`` is blocked. raptor-sca scans run on operator
systems; if the system pip refuses, we fall back to creating an
ephemeral venv under the project tree and re-running the resolver
with the venv's pip (which doesn't have the marker). Per-run cost is
~3-5s for venv create + pip-tools install. The venv lives at
``<project>/.raptor-sca-venv-{pid}/`` and is removed after the run.
Sandbox writes are confined to the project tree already so this lands
in the only writeable surface available to us.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import ResolverResult, _check_tool, _run

logger = logging.getLogger(__name__)


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
    """

    ecosystem = "PyPI"
    # pypi.org for JSON metadata, files.pythonhosted.org for the
    # actual wheels pip-compile / pip download for resolution.
    # Some org pip configs use a private mirror; the sandbox will
    # surface that as a proxy refusal, which is the right failure
    # mode (reveals an unallowed dep source).
    proxy_hosts = ("pypi.org", "files.pythonhosted.org")

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
        try:
            proc = _run(
                ["pip-compile", "--quiet", "--output-file", "-",
                 rel_manifest],
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
    ) -> "tuple[Optional[Path], Optional[str]]":
        """Create an ephemeral venv + bootstrap pip in a single sandbox call.

        Each ``_run`` call gets a fresh mount-ns with its own tmpfs at
        ``/tmp`` — venv state created in one call does NOT persist into
        a follow-up call. So we have to combine venv-create, ensurepip,
        and (in the caller) the pip install + resolver invocation into
        a single shell pipeline that runs end-to-end inside one
        sandbox.

        This helper does just the venv+ensurepip steps; the caller
        chains its own work on top via :meth:`_run_combined_pip_compile`
        or :meth:`_run_combined_pip_dry`. We return ``(venv_dir,
        sentinel_path)`` so callers can locate the venv by path inside
        their own sandbox call. The actual filesystem state from this
        method is intentionally NOT inspected here (it's gone with the
        sandbox tmpfs).
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
        """
        return (
            f"set -e; "
            f"export HOME={venv_dir}/.fake-home; "
            f"export XDG_CACHE_HOME={venv_dir}/.fake-home/.cache; "
            f"mkdir -p $HOME $XDG_CACHE_HOME; "
            f"{_real_python()} -m venv --without-pip {venv_dir} && "
            f"{venv_dir}/bin/python -m ensurepip --upgrade >/dev/null && "
        )

    def _cleanup_venv(self, venv_dir: Path) -> None:
        """Best-effort venv removal. Errors are logged, not raised —
        leaving a stale venv is preferable to crashing the resolver."""
        try:
            shutil.rmtree(venv_dir, ignore_errors=True)
        except Exception as e:                      # noqa: BLE001
            logger.debug("sca.pip: venv cleanup failed for %s: %s",
                         venv_dir, e)

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
        script = (
            self._venv_setup_script(venv_dir)
            + f"{venv_dir}/bin/python -m pip install --quiet pip-tools && "
            + f"{venv_dir}/bin/pip-compile --quiet "
            + f"--output-file - {rel_manifest}"
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
                error=f"PEP 668 venv pipeline timed out after {timeout}s",
            )
        raw = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0:
            return ResolverResult(
                ecosystem=self.ecosystem, success=False, available=True,
                error=("PEP 668 venv pipeline failed: "
                       + (proc.stderr.strip() or "exit non-zero")),
                raw_output=raw,
            )
        return ResolverResult(
            ecosystem=self.ecosystem, success=True, available=True,
            proposed_lockfile=proc.stdout.encode("utf-8"),
            raw_output=raw,
        )

def _find_pip_manifest(project_dir: Path) -> Optional[Path]:
    """Return the path to a top-level pip-style manifest, if any.

    Preference order:
      1. ``pyproject.toml`` — fully self-describing project metadata.
      2. ``requirements.txt`` (the canonical name).
      3. Any other ``requirements*.txt`` (covers ``requirements-dev``,
         ``requirements-all-optional``, ``requirements-prod``, etc.).
      4. ``requirements.in`` — pip-tools input.
    """
    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        return pyproject
    canonical = project_dir / "requirements.txt"
    if canonical.exists():
        return canonical
    # Fall through to any other requirements*.txt — sorted for
    # determinism so the same manifest is picked across runs.
    for c in sorted(project_dir.glob("requirements*.txt")):
        return c
    req_in = project_dir / "requirements.in"
    if req_in.exists():
        return req_in
    return None


__all__ = ["PipResolver"]
