"""docker build mechanics: run the build, classify what broke.

The dependency classifier maps compiler/linker stderr (missing headers,
``-l`` libraries, configure probes) to the Debian dev packages that
provide them — callers turn that into an actionable retry (add the
packages, rebuild) instead of a dead "build failed".
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.container.containers import is_external_image
from core.container.failures import classify_docker_stderr
from core.container.proc import run_cli


def extract_from_image(dockerfile_text: str | None, ctx: Path) -> str | None:
    """Parse the FROM image reference from a Dockerfile (text first;
    fall back to <ctx>/Dockerfile). Returns the image name (e.g.,
    'debian:11', 'app:build') or None if no FROM line found.

    Strips 'AS <stage>' aliases and '--platform=...' flags. Multi-stage
    Dockerfiles return the FIRST FROM (the base for stage 0); subsequent
    stages may FROM previous stages (local refs) but the gate is whether
    the BASE chain reaches an external registry.

    Returns first FROM only. Multi-stage with external later stages may
    miss --pull benefit. Acceptable: Docker caches are typically warm.
    """
    text = dockerfile_text
    if text is None:
        dockerfile_path = ctx / "Dockerfile"
        if not dockerfile_path.is_file():
            return None
        try:
            text = dockerfile_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line.upper().startswith("FROM "):
            continue
        # Strip optional --platform=... flag
        rest = re.sub(r"^FROM\s+(?:--\S+\s+)*", "", line, flags=re.IGNORECASE)
        # Strip ' AS <stage>'
        rest = re.split(r"\s+AS\s+", rest, maxsplit=1, flags=re.IGNORECASE)[0]
        return rest.strip() or None
    return None


DEPENDENCY_PACKAGE_MAP: dict[str, str] = {
    # APR (Apache Portable Runtime)
    "apr.h": "libapr1-dev",
    "apr_util.h": "libaprutil1-dev",
    "-lapr-1": "libapr1-dev",
    "-laprutil-1": "libaprutil1-dev",
    # OpenSSL
    "openssl/ssl.h": "libssl-dev",
    "openssl/crypto.h": "libssl-dev",
    "-lssl": "libssl-dev",
    "-lcrypto": "libssl-dev",
    # PCRE
    "pcre.h": "libpcre3-dev",
    "-lpcre": "libpcre3-dev",
    # Compression
    "zlib.h": "zlib1g-dev",
    "-lz": "zlib1g-dev",
    "expat.h": "libexpat1-dev",
    "-lexpat": "libexpat1-dev",
    "bz2.h": "libbz2-dev",
    "-lbz2": "libbz2-dev",
    # XML
    "libxml/parser.h": "libxml2-dev",
    "-lxml2": "libxml2-dev",
    # Networking
    "curl/curl.h": "libcurl4-openssl-dev",
    "-lcurl": "libcurl4-openssl-dev",
    # Database
    "mysql/mysql.h": "libmysqlclient-dev",
    "-lmysqlclient": "libmysqlclient-dev",
    "postgresql/libpq-fe.h": "libpq-dev",
    "-lpq": "libpq-dev",
    # Other common
    "readline/readline.h": "libreadline-dev",
    "-lreadline": "libreadline-dev",
    "ncurses.h": "libncurses5-dev",
    "-lncurses": "libncurses5-dev",
}

_CONFIGURE_KEYWORD_MAP: dict[str, str] = {
    "openssl": "libssl-dev",
    "apr-1": "libapr1-dev",
    "pcre": "libpcre3-dev",
}

_HEADER_NOT_FOUND_RE = re.compile(
    r"fatal error:\s*([^\s:]+\.h)(?::\s*No such file)?", re.IGNORECASE
)
_LIB_NOT_FOUND_RE = re.compile(
    r"(?:cannot find|/usr/bin/ld: cannot find)\s+(-l[\w+.\-]+)", re.IGNORECASE
)


# Keyword-to-error correlation is global (not line-scoped). May
# false-positive when keywords appear in unrelated lines.
def classify_build_error(stderr: str) -> list[str]:
    """Return apt packages implied by build stderr, or ``[]``."""
    if not stderr:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def _add(pkg: str) -> None:
        if pkg not in seen:
            seen.add(pkg)
            found.append(pkg)

    for match in _HEADER_NOT_FOUND_RE.finditer(stderr):
        header = match.group(1)
        pkg = DEPENDENCY_PACKAGE_MAP.get(header)
        if pkg is not None:
            _add(pkg)
            continue
        tail = header.split("/")[-1]
        for key, mapped in DEPENDENCY_PACKAGE_MAP.items():
            if key.endswith(tail) and key.endswith(".h"):
                _add(mapped)
                break

    for match in _LIB_NOT_FOUND_RE.finditer(stderr):
        lib = match.group(1).lower()
        pkg = DEPENDENCY_PACKAGE_MAP.get(lib)
        if pkg is not None:
            _add(pkg)

    lowered = stderr.lower()
    for keyword, pkg in _CONFIGURE_KEYWORD_MAP.items():
        if keyword in lowered and ("not found" in lowered or "not correct" in lowered):
            _add(pkg)

    return found


@dataclass
class BuildOutcome:
    """Result of :func:`build_image` — data, never an exception."""

    ok: bool
    image_tag: str = ""
    exit_code: int = 0
    logs_tail: str = ""
    stderr_tail: str = ""
    reason: str = ""  # "" | bad_context | timeout | build_failed
    reason_class: str = "ok"


def build_image(
    *,
    context_dir: str,
    tag: str,
    dockerfile_text: str | None = None,
    platform: str | None = None,
    timeout_seconds: int = 600,
    labels: dict[str, str] | None = None,
    local_prefixes: tuple[str, ...] = (),
) -> BuildOutcome:
    """Run ``docker build``; return a structured outcome.

    If ``dockerfile_text`` is provided, it is written to a tempfile and
    passed via ``-f``; otherwise ``<context>/Dockerfile`` is used. A
    genuinely-missing context dir is auto-created (FROM+RUN Dockerfiles
    need no COPY context; COPY still fails later at the COPY step,
    correctly); empty and exists-but-not-a-dir stay hard rejections.

    ``--pull`` is added when the FROM base resolves to an external
    registry image (fresh base bytes even under a warm local cache);
    locally-built bases (caller-declared ``local_prefixes``) skip it.
    """
    if not isinstance(context_dir, str) or not context_dir.strip():
        return BuildOutcome(
            ok=False,
            reason="bad_context",
            reason_class="unknown",
            stderr_tail="context_dir is empty",
        )
    ctx = Path(context_dir)
    if not ctx.exists():
        try:
            ctx.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return BuildOutcome(
                ok=False,
                reason="bad_context",
                reason_class="unknown",
                stderr_tail=f"{context_dir}: cannot create context dir ({exc})",
            )
    if not ctx.is_dir():
        return BuildOutcome(
            ok=False,
            reason="bad_context",
            reason_class="unknown",
            stderr_tail=f"{context_dir}: not a directory",
        )

    cmd: list[str] = ["docker", "build", "-t", tag]
    for k, v in (labels or {}).items():
        cmd.extend(["--label", f"{k}={v}"])
    if platform:
        cmd.extend(["--platform", platform])
    from_image = extract_from_image(dockerfile_text, ctx)
    if from_image and is_external_image(from_image,
                                        local_prefixes=local_prefixes):
        cmd.append("--pull")

    tmpfile: Path | None = None
    try:
        if dockerfile_text is not None:
            with tempfile.NamedTemporaryFile(  # noqa: SIM115 -- delete=False intentional
                mode="w",
                prefix="raptor-env-df-",
                suffix=".Dockerfile",
                delete=False,
            ) as fd:
                fd.write(dockerfile_text)
                tmpfile = Path(fd.name)
            cmd.extend(["-f", str(tmpfile)])
        cmd.append(str(ctx))

        outcome = run_cli(cmd, timeout=timeout_seconds)
        if outcome.timed_out:
            return BuildOutcome(
                ok=False,
                reason="timeout",
                reason_class="timeout",
                image_tag=tag,
                stderr_tail=f"timeout after {timeout_seconds}s",
                logs_tail=outcome.stdout[-4000:] if outcome.stdout else "",
            )

        stdout_tail = (outcome.stdout or "").splitlines()[-200:]
        stderr_tail = (outcome.stderr or "").splitlines()[-200:]
        logs_tail = "\n".join(stdout_tail)[-4000:]
        stderr_blob = "\n".join(stderr_tail)[-4000:]

        if outcome.returncode == 0:
            return BuildOutcome(
                ok=True,
                image_tag=tag,
                exit_code=0,
                logs_tail=logs_tail,
                stderr_tail=stderr_blob,
                reason_class="ok",
            )

        failure_class = classify_docker_stderr(outcome.stderr or "")
        # returncode is int | None (None when the subprocess never
        # started). Normalize to -1 to keep the field int-typed.
        exit_code = outcome.returncode if outcome.returncode is not None else -1
        return BuildOutcome(
            ok=False,
            image_tag=tag,
            exit_code=exit_code,
            logs_tail=logs_tail,
            stderr_tail=stderr_blob,
            reason="build_failed",
            reason_class=failure_class,
        )
    finally:
        if tmpfile is not None and tmpfile.exists():
            tmpfile.unlink()
