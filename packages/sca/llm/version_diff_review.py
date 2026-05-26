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
from typing import Dict, List, Optional

from core.http import HttpClient
from core.llm.task_types import TaskType
from core.tar import extract_files_from_tar
from ..models import Dependency
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .exemplars import exfil_destinations_block
from .prompts import VERSION_DIFF_SYSTEM
from .schemas import VersionDiffVerdict

logger = logging.getLogger(__name__)

_MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB
_MAX_DIFF_CHARS = 200_000               # ~200 KB to the LLM
_MAX_FILE_SIZE = 512 * 1024             # skip files > 512 KB in diff
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
_ARCHIVE_URLS: Dict[str, str] = {
    "npm": "https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz",
    "PyPI": "https://files.pythonhosted.org/packages/source/{initial}/{name}/{name}-{version}.tar.gz",
    "Cargo": "https://crates.io/api/v1/crates/{name}/{version}/download",
    "RubyGems": "https://rubygems.org/gems/{name}-{version}.gem",
    "Go": "https://proxy.golang.org/{name}/@v/{version}.zip",
    "NuGet": "https://api.nuget.org/v3-flatcontainer/{name_lower}/{version}/{name_lower}.{version}.nupkg",
    "Maven": "https://repo.maven.apache.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}-sources.jar",
    "Gradle": "https://repo.maven.apache.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}-sources.jar",
    "Composer": "https://repo.packagist.org/p2/{name_lower}.json",
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
) -> Optional[VersionDiffVerdict]:
    """Diff two versions of a package and ask the LLM for a verdict.

    Returns ``None`` when archives can't be fetched or the LLM is
    unavailable — the caller falls back to mechanical-only analysis.
    """
    diff_text = _build_diff(old_dep, new_dep, http)
    if diff_text is None:
        return None

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
    return verdict


# ------------------------------------------------------------------
# Archive download + diff
# ------------------------------------------------------------------

def _build_diff(
    old_dep: Dependency,
    new_dep: Dependency,
    http: HttpClient,
) -> Optional[str]:
    """Download, extract, and diff two package versions."""
    if not old_dep.version or not new_dep.version:
        return None

    old_files = _download_and_extract(old_dep, http)
    new_files = _download_and_extract(new_dep, http)
    if old_files is None or new_files is None:
        return None

    return _diff_trees(old_files, new_files)


def _download_and_extract(
    dep: Dependency, http: HttpClient,
) -> Optional[Dict[str, str]]:
    """Fetch archive → dict of {relative_path: text_content}."""
    # Composer: resolve the actual archive URL from packagist metadata.
    if dep.ecosystem == "Composer":
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

    # PyPI: sdist may not exist → fall back to smallest wheel.
    if data is None and dep.ecosystem == "PyPI":
        data = _fetch_pypi_wheel(dep, http)

    if data is None:
        return None

    return _extract_text_files(data, dep.ecosystem)


def _fetch(url: str, http: HttpClient) -> Optional[bytes]:
    """Download a URL, returning None on failure or oversize."""
    try:
        data = http.get(url, timeout=30)
    except Exception:  # noqa: BLE001
        logger.debug("sca.llm.version_diff: fetch failed for %s", url)
        return None
    if len(data) > _MAX_ARCHIVE_BYTES:
        logger.debug("sca.llm.version_diff: archive too large (%d bytes)", len(data))
        return None
    return data


def _fetch_pypi_wheel(dep: Dependency, http: HttpClient) -> Optional[bytes]:
    """Fall back to the smallest wheel when no sdist is available."""
    if not dep.version:
        return None
    json_url = f"https://pypi.org/pypi/{dep.name}/{dep.version}/json"
    try:
        import json as _json
        raw = http.get(json_url, timeout=15)
        meta = _json.loads(raw)
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


def _download_composer(dep: Dependency, http: HttpClient) -> Optional[Dict[str, str]]:
    """Resolve Composer archive URL from packagist and extract."""
    import json as _json
    meta_url = f"https://repo.packagist.org/p2/{dep.name.lower()}.json"
    try:
        raw = http.get(meta_url, timeout=15)
        meta = _json.loads(raw)
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


def _archive_url(dep: Dependency) -> Optional[str]:
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
    if dep.ecosystem == "Composer":
        return template.format(name_lower=name.lower())
    return template.format(name=name, version=version)


def _maven_fallback_url(dep: Dependency) -> Optional[str]:
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
) -> Optional[Dict[str, str]]:
    """Extract text source files from an archive."""
    files: Dict[str, str] = {}
    try:
        if ecosystem in ("npm", "PyPI", "Cargo", "RubyGems"):
            _extract_tar(data, files)
        elif ecosystem in ("Go", "NuGet", "Maven", "Gradle", "Composer"):
            _extract_zip(data, files)
        else:
            _extract_tar(data, files)
    except Exception:  # noqa: BLE001
        logger.debug("sca.llm.version_diff: extraction failed", exc_info=True)
        return None
    return files if files else None


def _extract_tar(data: bytes, out: Dict[str, str]) -> None:
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
    )
    for key, blob in raw.items():
        try:
            out[key] = blob.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue


def _extract_zip(data: bytes, out: Dict[str, str]) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > _MAX_FILE_SIZE:
                continue
            suffix = Path(info.filename).suffix.lower()
            if suffix not in _TEXT_EXTENSIONS:
                continue
            try:
                content = zf.read(info).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            parts = Path(info.filename).parts
            rel = "/".join(parts[1:]) if len(parts) > 1 else info.filename
            out[rel] = content


def _diff_trees(
    old: Dict[str, str], new: Dict[str, str],
) -> str:
    """Produce a unified diff between two file trees, capped at _MAX_DIFF_CHARS."""
    all_paths = sorted(set(old) | set(new))
    chunks: List[str] = []
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
