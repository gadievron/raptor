"""LLM review of version-to-version source diffs.

When a dependency's version changes between ``raptor-sca`` runs (compared
against a previous ``dependencies.json``), this stage:

1. Downloads both versions' source archives from the registry.
2. Extracts and diffs them (text files only, capped).
3. Asks the LLM whether the changes are consistent with the changelog
   and whether any anomalies (obfuscated code, unexpected binaries,
   behaviour changes) are present.

Cap: 50 MB per archive, 200 KB diff payload to the LLM.

**Mechanical override:** a "clean" LLM verdict does not suppress any
mechanical supply-chain finding.  The diff review is additive context
for the operator.
"""

from __future__ import annotations

import difflib
import io
import logging
import zipfile
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import dumps_display
from core.llm.task_types import TaskType
from core.tar import extract_files_from_tar

from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .exemplars import exfil_destinations_block
from .prompts import VERSION_DIFF_SYSTEM
from .schemas import VersionDiffVerdict

if TYPE_CHECKING:
    from core.http import HttpClient
    from ..models import Dependency

logger = logging.getLogger(__name__)

_MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB
_MAX_DIFF_CHARS = 200_000               # ~200 KB to the LLM
_MAX_FILE_SIZE = 512 * 1024             # skip files > 512 KB in diff
# Bounds the sink-diff payload injected into the prompt and the
# findings evidence record; ``total_changes`` still reflects the
# untruncated count.
_MAX_SINK_CHANGES_PER_KIND = 50
# Aggregate extraction budget: the per-member cap alone doesn't bound
# the sum, so many just-under-cap members (or millions of tiny ones)
# could still exhaust memory. Either limit aborts the extraction.
_MAX_TOTAL_EXTRACT_BYTES = 64 * 1024 * 1024  # cumulative across members
_MAX_ARCHIVE_MEMBERS = 10_000                # member-count bound
_TEXT_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
    ".java", ".kt", ".kts", ".scala", ".groovy",
    ".rs", ".go", ".rb", ".php", ".cs", ".fs",
    ".c", ".h", ".cpp", ".hpp", ".cc",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".cfg", ".ini",
    ".txt", ".md", ".rst", ".sh", ".bash", ".zsh", ".bat", ".ps1",
    ".lock", ".sum", ".mod",
})

# Per-ecosystem source-archive URL templates.
_ARCHIVE_URLS: dict[str, str] = {
    "npm": "https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz",
    "PyPI": "https://files.pythonhosted.org/packages/source/{initial}/{name}/{name}-{version}.tar.gz",
    "Cargo": "https://crates.io/api/v1/crates/{name}/{version}/download",
    "RubyGems": "https://rubygems.org/gems/{name}-{version}.gem",
    "Go": "https://proxy.golang.org/{name}/@v/{version}.zip",
    "NuGet": "https://api.nuget.org/v3-flatcontainer/{name_lower}/{version}/{name_lower}.{version}.nupkg",
    "Maven": "https://repo.maven.apache.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}-sources.jar",
    "Gradle": "https://repo.maven.apache.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}-sources.jar",
    "Packagist": "https://repo.packagist.org/p2/{name_lower}.json",
}

# Maven sources jar unavailable → fall back to binary jar (degraded signal).
_MAVEN_BINARY_FALLBACK = (
    "https://repo.maven.apache.org/maven2/"
    "{group_path}/{artifact}/{version}/{artifact}-{version}.jar"
)

def review_version_diff(
    client,
    old_dep: Dependency,
    new_dep: Dependency,
    http: HttpClient,
    changelog: str = "",
) -> tuple[VersionDiffVerdict, dict[str, Any] | None] | None:
    """Diff two versions of a package and ask the LLM for a verdict.

    Returns ``(verdict, sink_changes)`` where ``sink_changes`` is the
    mechanical sink-diff evidence dict (``None`` when the analyzer is
    unavailable or found nothing).  Returns ``None`` when archives
    can't be fetched or the LLM is unavailable — the caller falls
    back to mechanical-only analysis.
    """
    built = _build_diff(old_dep, new_dep, http)
    if built is None:
        return None
    diff_text, old_files, new_files = built

    sink_evidence = _sink_diff_evidence(old_files, new_files)

    slots = {
        "package_name": TaintedString(value=new_dep.name, trust="untrusted"),
        "ecosystem": TaintedString(value=new_dep.ecosystem, trust="trusted"),
        "old_version": TaintedString(value=old_dep.version or "?", trust="untrusted"),
        "new_version": TaintedString(value=new_dep.version or "?", trust="untrusted"),
    }

    blocks: list[UntrustedBlock] = [
        UntrustedBlock(
            content=diff_text,
            kind="VERSION_DIFF",
            origin=f"{new_dep.ecosystem}/{new_dep.name} "
                   f"{old_dep.version}→{new_dep.version}",
        ),
    ]
    if sink_evidence is not None:
        blocks.append(UntrustedBlock(
            content=(
                "Mechanical sink analysis of this version diff "
                "(added/removed dangerous calls and guard changes):\n"
                + dumps_display(sink_evidence, indent=2)
            ),
            kind="SINK_DIFF",
            origin=f"{new_dep.ecosystem}/{new_dep.name} "
                   f"{old_dep.version}→{new_dep.version} sink analysis",
        ))
    if changelog:
        blocks.append(UntrustedBlock(
            content=changelog[:10_000],
            kind="CHANGELOG",
            origin=f"{new_dep.ecosystem}/{new_dep.name} changelog",
        ))
    exfil = exfil_destinations_block()
    if exfil is not None:
        blocks.append(exfil)

    result: StageResult = run_stage(
        client=client,
        system=VERSION_DIFF_SYSTEM,
        untrusted_blocks=tuple(blocks),
        slots=slots,
        schema_cls=VersionDiffVerdict,
        task_type=TaskType.ANALYSE,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.version_diff_review: %s failed: %s",
                      new_dep.name, result.error)
        return None

    verdict: VersionDiffVerdict = result.model  # type: ignore[assignment]
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})
    return verdict, sink_evidence


# ------------------------------------------------------------------
# Archive download + diff
# ------------------------------------------------------------------

def _build_diff(
    old_dep: Dependency,
    new_dep: Dependency,
    http: HttpClient,
) -> tuple[str, dict[str, str], dict[str, str]] | None:
    """Download, extract, and diff two package versions.

    Returns ``(diff_text, old_files, new_files)`` — the file trees
    feed the mechanical sink analysis alongside the raw diff.
    """
    if not old_dep.version or not new_dep.version:
        return None

    old_files = _download_and_extract(old_dep, http)
    new_files = _download_and_extract(new_dep, http)
    if old_files is None or new_files is None:
        return None

    return _diff_trees(old_files, new_files), old_files, new_files


def _sink_diff_evidence(
    old_files: dict[str, str],
    new_files: dict[str, str],
) -> dict[str, Any] | None:
    """Mechanical sink diff between the two version trees.

    Graceful: any analyzer failure — or an empty result — returns
    ``None`` and the review proceeds on the raw diff alone.
    """
    try:
        from ..supply_chain.version_diff_sinks import (
            analyze_version_diff_sinks,
        )
        result = analyze_version_diff_sinks(old_files, new_files)
    except Exception:  # noqa: BLE001
        logger.debug(
            "sca.llm.version_diff: sink analysis failed", exc_info=True,
        )
        return None
    if result.total_changes == 0:
        return None

    evidence = result.to_dict()
    evidence["summary"] = result.summary_line()
    for key in ("added_sinks", "removed_sinks", "guard_changes"):
        if len(evidence[key]) > _MAX_SINK_CHANGES_PER_KIND:
            evidence[key] = evidence[key][:_MAX_SINK_CHANGES_PER_KIND]
    return evidence


def _download_and_extract(
    dep: Dependency, http: HttpClient,
) -> dict[str, str] | None:
    """Fetch archive → dict of {relative_path: text_content}."""
    # Composer: resolve the actual archive URL from packagist metadata.
    if dep.ecosystem == "Packagist":
        return _download_composer(dep, http)

    url = _archive_url(dep)
    if url is None:
        logger.debug("sca.llm.version_diff: no archive URL for %s/%s",
                      dep.ecosystem, dep.name)
        return None

    data = _fetch(url, http)

    # Maven/Gradle: sources jar may not exist → fall back to binary jar.
    if data is None and dep.ecosystem in ("Maven", "Gradle"):
        fallback = _maven_fallback_url(dep)
        if fallback:
            logger.debug("sca.llm.version_diff: trying Maven binary jar fallback")
            data = _fetch(fallback, http)

    # PyPI: sdist may not exist → fall back to smallest wheel (a zip).
    is_wheel = False
    if data is None and dep.ecosystem == "PyPI":
        data = _fetch_pypi_wheel(dep, http)
        if data is not None:
            is_wheel = True

    if data is None:
        return None

    eco = "NuGet" if is_wheel else dep.ecosystem  # wheel is a zip
    return _extract_text_files(data, eco)


def _fetch(url: str, http: HttpClient) -> bytes | None:
    """Download a URL, returning None on failure or oversize."""
    try:
        data = http.get_bytes(url, timeout=30)
    except Exception:  # noqa: BLE001
        logger.debug("sca.llm.version_diff: fetch failed for %s", url)
        return None
    if len(data) > _MAX_ARCHIVE_BYTES:
        logger.debug("sca.llm.version_diff: archive too large (%d bytes)", len(data))
        return None
    return data


def _fetch_pypi_wheel(dep: Dependency, http: HttpClient) -> bytes | None:
    """Fall back to the smallest wheel when no sdist is available."""
    if not dep.version:
        return None
    json_url = f"https://pypi.org/pypi/{dep.name}/{dep.version}/json"
    try:
        meta = http.get_json(json_url, timeout=15)
        urls = meta.get("urls", [])
        wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
        if not wheels:
            return None
        smallest = min(wheels, key=lambda u: u.get("size", float("inf")))
        whl_url = smallest.get("url")
        if not whl_url:
            return None
        return _fetch(whl_url, http)
    except Exception:  # noqa: BLE001
        logger.debug("sca.llm.version_diff: PyPI wheel fallback failed for %s",
                      dep.name)
        return None


def _download_composer(dep: Dependency, http: HttpClient) -> dict[str, str] | None:
    """Resolve Composer archive URL from packagist and extract."""
    meta_url = f"https://repo.packagist.org/p2/{dep.name.lower()}.json"
    try:
        meta = http.get_json(meta_url, timeout=15)
        packages = meta.get("packages", {}).get(dep.name.lower(), [])
        match = next(
            (p for p in packages if p.get("version") == dep.version), None,
        )
        if match is None:
            return None
        dist = match.get("dist", {})
        archive_url = dist.get("url")
        if not archive_url:
            return None
        data = _fetch(archive_url, http)
        if data is None:
            return None
        return _extract_text_files(data, dep.ecosystem)
    except Exception:  # noqa: BLE001
        logger.debug("sca.llm.version_diff: Composer fetch failed for %s",
                      dep.name)
        return None


def _archive_url(dep: Dependency) -> str | None:
    """Build the source-archive URL for a dependency."""
    template = _ARCHIVE_URLS.get(dep.ecosystem)
    if template is None:
        return None

    name = dep.name
    version = dep.version or ""

    if dep.ecosystem == "npm":
        basename = name.split("/")[-1] if "/" in name else name
        return template.format(name=name, basename=basename, version=version)
    if dep.ecosystem == "PyPI":
        if not name:
            return None
        initial = name[0].lower()
        return template.format(name=name, initial=initial, version=version)
    if dep.ecosystem == "NuGet":
        return template.format(
            name_lower=name.lower(), version=version,
        )
    if dep.ecosystem in ("Maven", "Gradle"):
        parts = name.split(":")
        if len(parts) != 2:
            return None
        group, artifact = parts
        group_path = group.replace(".", "/")
        return template.format(
            group_path=group_path, artifact=artifact, version=version,
        )
    if dep.ecosystem == "Packagist":
        return template.format(name_lower=name.lower())
    return template.format(name=name, version=version)


def _maven_fallback_url(dep: Dependency) -> str | None:
    """Binary jar URL when sources jar is unavailable."""
    parts = dep.name.split(":")
    if len(parts) != 2 or not dep.version:
        return None
    group, artifact = parts
    group_path = group.replace(".", "/")
    return _MAVEN_BINARY_FALLBACK.format(
        group_path=group_path, artifact=artifact, version=dep.version,
    )


def _extract_text_files(
    data: bytes, ecosystem: str,
) -> dict[str, str] | None:
    """Extract text source files from an archive."""
    files: dict[str, str] = {}
    try:
        if ecosystem in ("npm", "PyPI", "Cargo", "RubyGems"):
            _extract_tar(data, files)
        elif ecosystem in ("Go", "NuGet", "Maven", "Gradle", "Packagist"):
            _extract_zip(data, files)
        else:
            _extract_tar(data, files)
    except Exception:
        logger.debug("sca.llm.version_diff: extraction failed", exc_info=True)
        return None
    return files or None


def _extract_tar(data: bytes, out: dict[str, str]) -> None:
    """Pull text-source files out of a tar archive.

    Tar walking + safety filtering is centralised in
    :func:`core.tar.extract_files_from_tar`. Here we supply the
    SCA-specific selector: filter by extension, strip the top-level
    directory prefix that source distributions wrap their contents
    in, and decode bytes → str.
    """
    def _select(member):
        if Path(member.name).suffix.lower() not in _TEXT_EXTENSIONS:
            return None
        # Strip the top-level directory prefix for cleaner diffs
        # (``pkg-1.0/setup.py`` → ``setup.py``).
        parts = Path(member.name).parts
        return "/".join(parts[1:]) if len(parts) > 1 else member.name

    raw = extract_files_from_tar(
        data,
        selector=_select,
        mode="r:*",
        max_member_bytes=_MAX_FILE_SIZE,
        # Aggregate-size bomb defence: raises when the cumulative
        # extracted bytes exceed the budget (the per-member cap alone
        # doesn't bound the sum). Surfaces through the caller's
        # extraction-failure path. Entry-count bound is the helper's
        # default (50k), well above _MAX_ARCHIVE_MEMBERS-scale sources.
        max_total_bytes=_MAX_TOTAL_EXTRACT_BYTES,
    )
    for key, blob in raw.items():
        # ``errors="replace"`` decoding of the helper's ``bytes``
        # values cannot fail; anything raised here is a wiring bug
        # and must propagate.
        out[key] = blob.decode("utf-8", errors="replace")


def _extract_zip(data: bytes, out: dict[str, str]) -> None:
    # Cumulative budgets: track member count, declared uncompressed
    # sizes, AND actual bytes read (headers can lie in either
    # direction). Exceeding any budget raises, which surfaces through
    # the caller's extraction-failure path (``_extract_text_files``
    # returns None).
    members = 0
    declared_total = 0
    read_total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            members += 1
            if members > _MAX_ARCHIVE_MEMBERS:
                msg = (
                    f"zip exceeds {_MAX_ARCHIVE_MEMBERS} members "
                    f"(bomb-shape); refusing"
                )
                raise ValueError(msg)
            if info.is_dir() or info.file_size > _MAX_FILE_SIZE:
                continue
            suffix = Path(info.filename).suffix.lower()
            if suffix not in _TEXT_EXTENSIONS:
                continue
            declared_total += info.file_size
            if declared_total > _MAX_TOTAL_EXTRACT_BYTES:
                msg = (
                    f"zip declares more than {_MAX_TOTAL_EXTRACT_BYTES} "
                    f"cumulative bytes (bomb-shape); refusing"
                )
                raise ValueError(msg)
            try:
                blob = zf.read(info)
            except Exception:
                logger.debug(
                    "sca.llm.version_diff: failed to read zip member "
                    "%s; skipping", info.filename, exc_info=True,
                )
                continue
            read_total += len(blob)
            if read_total > _MAX_TOTAL_EXTRACT_BYTES:
                msg = (
                    f"zip extraction exceeds {_MAX_TOTAL_EXTRACT_BYTES} "
                    f"cumulative bytes (bomb-shape); refusing"
                )
                raise ValueError(msg)
            content = blob.decode("utf-8", errors="replace")
            parts = Path(info.filename).parts
            rel = "/".join(parts[1:]) if len(parts) > 1 else info.filename
            if "@v" in rel:
                rel = "/".join(
                    seg.partition("@")[0] if "@v" in seg else seg
                    for seg in rel.split("/")
                )
            out[rel] = content


def _diff_trees(
    old: dict[str, str], new: dict[str, str],
) -> str:
    """Produce a unified diff between two file trees, capped at _MAX_DIFF_CHARS."""
    all_paths = sorted(set(old) | set(new))
    chunks: list[str] = []
    total = 0

    for path in all_paths:
        old_lines = old.get(path, "").splitlines(keepends=True)
        new_lines = new.get(path, "").splitlines(keepends=True)
        diff = list(difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"a/{path}", tofile=f"b/{path}",
            lineterm="",
        ))
        if not diff:
            continue
        chunk = "\n".join(diff)
        if total + len(chunk) > _MAX_DIFF_CHARS:
            chunks.append(f"\n... diff truncated at {_MAX_DIFF_CHARS} chars ...")
            break
        chunks.append(chunk)
        total += len(chunk)

    return "\n".join(chunks) if chunks else ""
