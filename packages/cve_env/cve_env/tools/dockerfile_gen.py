"""Render a Dockerfile from structured input. LLM-emitted content is
validated before the Dockerfile text is returned.

The agent supplies: base_image, install_steps, workdir, cmd, ports,
apt_packages (optional). The function renders a canonical layout and
runs ``validate_dockerfile_semantics`` over the result so the agent
never sees a Dockerfile this module itself would reject downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from cve_env.utils.dockerfile_hygiene import validate_dockerfile_semantics
from cve_env.validators import validate_image_ref


@dataclass
class DockerfileRenderResult:
    """Outcome of a render attempt."""

    ok: bool
    dockerfile_text: str = ""
    issues: list[str] = field(default_factory=list)
    # Soft warnings — don't fail the render, but surface in tool result so the
    # agent sees patterns that risk dep-version drift (bare `apt-get install`,
    # `apt-get update` without version pin, etc.).
    warnings: list[str] = field(default_factory=list)


def _format_cmd(cmd: list[str]) -> str:
    parts = ", ".join(f'"{c}"' for c in cmd)
    return f"CMD [{parts}]"


# Detect dep-version-drift risk in install_steps.
# Match `apt install` / `apt-get install` and capture the rest-of-line so we can
# scan for unpinned package names. Char class includes `=`, `:`, `~`, `+` so
# `apache2=2.4.41-4ubuntu3` is captured as a single token.
_APT_INSTALL_RE = re.compile(
    r"\bapt(?:-get)?\s+install\s+([^\n;&|]+)",
    re.IGNORECASE,
)
_APT_GET_UPDATE_RE = re.compile(r"\bapt(?:-get)?\s+update\b", re.IGNORECASE)
# Tokens that are flags / known options, not package names.
_APT_FLAGS = frozenset(
    {
        "-y",
        "--yes",
        "-q",
        "--quiet",
        "-qq",
        "--no-install-recommends",
        "--no-install-suggests",
        "-f",
        "--fix-broken",
        "--reinstall",
        "--allow-unauthenticated",
        "--allow-downgrades",
    }
)


def _detect_dep_drift(
    install_steps: list[str],
    cve_named_packages: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Scan ``install_steps`` for patterns that pull whatever's CURRENT in the
    apt cache (= patched), instead of pinning to the CVE's affected version.

    Returns ``(hard_issues, soft_warnings)``:
    - **Hard issues** (caller fails the render): bare `apt install` of a
      CVE-named package (P20), `apt-get update` without same-line pin (P21).
    - **Soft warnings** (caller surfaces in tool result, render still ok):
      bare `apt install` of unpinned non-CVE-named packages.

    ``cve_named_packages`` is the list of packages the CVE specifically
    references (e.g., `["log4j-core", "spring-beans"]`). Empty/None means
    no CVE-named-package enforcement (back-compat for callers without context).
    """
    hard_issues: list[str] = []
    warnings: list[str] = []
    cve_pkgs = {p.lower() for p in (cve_named_packages or []) if isinstance(p, str)}
    for i, step in enumerate(install_steps):
        if not isinstance(step, str):
            continue
        # P21: apt-get update without immediate version-pinned install on the same RUN.
        if _APT_GET_UPDATE_RE.search(step) and "=" not in step:
            hard_issues.append(
                f"P21: install_steps[{i}]: contains `apt-get update` without "
                "version-pinned install on the same RUN — pulls latest "
                "security archive, may PATCH the very vuln. Either drop "
                "`apt-get update` or pin every package with `=<version>` in "
                "the same RUN."
            )
        # Bare `apt install pkg` with no `=`. Scan each install invocation.
        for match in _APT_INSTALL_RE.finditer(step):
            arg_blob = match.group(1)
            tokens = arg_blob.split()
            unpinned = [
                t
                for t in tokens
                if not t.startswith("-")
                and t not in _APT_FLAGS
                and "=" not in t
                and not t.startswith("&")
            ]
            if not unpinned:
                continue
            # P20: a bare unpinned install of a CVE-named package is a HARD
            # reject — that's the package whose version we MUST control.
            cve_named_unpinned = [t for t in unpinned if t.lower() in cve_pkgs]
            if cve_named_unpinned:
                head = ", ".join(cve_named_unpinned)
                hard_issues.append(
                    f"P20: install_steps[{i}]: bare `apt install {head}` is "
                    "the CVE-named package(s) — MUST pin to the affected "
                    "version. Use `=<affected-version>` syntax (3-tier "
                    "fallback: `=X.Y.Z` → `=X.Y.*` → bare apt install)."
                )
            # Other unpinned packages are still suspect but soft (could be
            # build-tools that don't matter for the vuln).
            non_cve_unpinned = [t for t in unpinned if t.lower() not in cve_pkgs]
            if non_cve_unpinned:
                head = ", ".join(non_cve_unpinned[:3])
                tail = ", ..." if len(non_cve_unpinned) > 3 else ""
                warnings.append(
                    f"install_steps[{i}]: bare `apt install {head}{tail}` "
                    "installs whatever's CURRENT in the apt cache. If any "
                    "of these are CVE-relevant, pin with `=<version>`. The "
                    "Phase 29 verify gate may downgrade success → "
                    "lifecycle_only_pass even on exploit-trigger."
                )
    return hard_issues, warnings


def _validate_copy_ops(copy_ops: list[dict[str, str]]) -> list[str]:
    """COPY <src> <dst> validation.

    src is a build-context-relative path (no leading '/', no '..' segments).
    dst is an absolute container path. Both must be non-empty strings.
    """
    issues: list[str] = []
    for i, op in enumerate(copy_ops):
        if not isinstance(op, dict):
            issues.append(f"copy_ops[{i}] must be a dict with src+dst")
            continue
        src = op.get("src", "")
        dst = op.get("dst", "")
        if not isinstance(src, str) or not src:
            issues.append(f"copy_ops[{i}].src must be a non-empty string")
        elif src.startswith("/"):
            issues.append(
                f"copy_ops[{i}].src {src!r} must be context-relative (no leading /)"
            )
        elif ".." in src.split("/"):
            issues.append(f"copy_ops[{i}].src {src!r} must not contain '..'")
        if not isinstance(dst, str) or not dst:
            issues.append(f"copy_ops[{i}].dst must be a non-empty string")
        elif not dst.startswith("/"):
            issues.append(f"copy_ops[{i}].dst {dst!r} must be an absolute path")
    return issues


def render_dockerfile(
    *,
    base_image: str,
    install_steps: list[str],
    workdir: str = "/app",
    cmd: list[str] | None = None,
    ports: list[int] | None = None,
    apt_packages: list[str] | None = None,
    copy_ops: list[dict[str, str]] | None = None,
    cve_named_packages: list[str] | None = None,
    apt_unsafe: bool = False,
) -> DockerfileRenderResult:
    """Render a Dockerfile; validate; return result.

    ``apt_packages``, when non-empty, becomes the first RUN layer so
    downstream build steps find the libraries. Use this to integrate
    a ``suggested_patch.apt_packages`` from a previous failed
    ``docker_build`` into the next attempt.

    ``copy_ops`` supports the platform-plus-extension pattern:
    ``[{"src": "plugin/", "dst": "/var/www/html/wp-content/plugins/foo/"}]``
    renders as ``COPY plugin/ /var/www/html/wp-content/plugins/foo/`` and
    is emitted after apt installs but before install_steps.

    ``cve_named_packages`` lists packages the CVE specifically references
    (headline app + named transitive deps). When set, bare
    `apt install <pkg>` for any package in the list is HARD-rejected (P20)
    so the agent cannot accidentally build with the CURRENT/patched version.
    Empty/None = back-compat (soft warnings only).
    """
    issues: list[str] = []

    base_issues = validate_image_ref(base_image)
    if base_issues:
        issues.extend(f"base_image: {msg}" for msg in base_issues)

    if not isinstance(install_steps, list) or not all(
        isinstance(s, str) for s in install_steps
    ):
        issues.append("install_steps must be a list of strings")

    if workdir and (not isinstance(workdir, str) or not workdir.startswith("/")):
        issues.append(f"workdir {workdir!r} must be an absolute path")

    clean_copy_ops = list(copy_ops or [])
    if clean_copy_ops:
        issues.extend(_validate_copy_ops(clean_copy_ops))

    # Hard reject on P20 (CVE-named bare install) + P21 (apt-get update
    # without same-line pin). Soft warnings on other unpinned installs.
    drift_issues: list[str] = []
    drift_warnings: list[str] = []
    if isinstance(install_steps, list):
        drift_issues, drift_warnings = _detect_dep_drift(
            install_steps, cve_named_packages
        )
    issues.extend(drift_issues)

    clean_apt = list(apt_packages or [])
    if issues:
        return DockerfileRenderResult(ok=False, issues=issues, warnings=drift_warnings)

    lines: list[str] = [f"FROM {base_image}"]
    lines.append(f"WORKDIR {workdir}")
    # When `apt_unsafe=True`, wrap apt-get with flags that bypass GPG
    # signature + valid-until checks. ONLY safe in disposable build
    # containers; never use in production. Mitigates "At least one invalid
    # signature was encountered" errors from stale-keyring base images (e.g.
    # mirror.gcr.io's bullseye images).
    apt_opts = (
        "-o Acquire::Check-Valid-Until=false "
        "-o Acquire::AllowInsecureRepositories=true "
        if apt_unsafe
        else ""
    )
    if clean_apt:
        apt_line = " ".join(clean_apt)
        lines.append(
            f"RUN apt-get {apt_opts}update && apt-get {apt_opts}install "
            f"-y --no-install-recommends "
            f"{apt_line} && rm -rf /var/lib/apt/lists/*"
        )
    for op in clean_copy_ops:
        lines.append(f"COPY {op['src']} {op['dst']}")
    for step in install_steps:
        step_stripped = step.strip()
        if not step_stripped:
            continue
        lines.append(f"RUN {step_stripped}")
    for port in ports or []:
        try:
            p = int(port)
        except (TypeError, ValueError):
            issues.append(f"port {port!r} is not an integer")
            continue
        lines.append(f"EXPOSE {p}")
    if cmd:
        if not all(isinstance(c, str) for c in cmd):
            issues.append("cmd entries must be strings")
        else:
            lines.append(_format_cmd(cmd))

    text = "\n".join(lines) + "\n"
    semantic_issues = validate_dockerfile_semantics(text)
    issues.extend(semantic_issues)

    if issues:
        return DockerfileRenderResult(
            ok=False, dockerfile_text=text, issues=issues, warnings=drift_warnings
        )

    return DockerfileRenderResult(
        ok=True, dockerfile_text=text, warnings=drift_warnings
    )


def render_to_payload(
    *,
    base_image: str,
    install_steps: list[str],
    workdir: str = "/app",
    cmd: list[str] | None = None,
    ports: list[int] | None = None,
    apt_packages: list[str] | None = None,
    copy_ops: list[dict[str, str]] | None = None,
    cve_named_packages: list[str] | None = None,
    apt_unsafe: bool = False,
) -> dict[str, Any]:
    """Wrap :func:`render_dockerfile` into the agent-tool dict shape."""
    result = render_dockerfile(
        base_image=base_image,
        install_steps=install_steps,
        workdir=workdir,
        cmd=cmd,
        ports=ports,
        apt_packages=apt_packages,
        copy_ops=copy_ops,
        cve_named_packages=cve_named_packages,
        apt_unsafe=apt_unsafe,
    )
    return {
        "ok": result.ok,
        "dockerfile_text": result.dockerfile_text,
        "issues": result.issues,
        "warnings": result.warnings,  # dep-drift warnings
    }
