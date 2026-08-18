"""Library summary cache for cross-audit amortisation.

Pre-computed summaries for widely-used libraries (OpenSSL, zlib,
libc, Django, Flask, etc.) are cached and reused across audits.
When a project imports a known library, cached summaries skip the
expensive LLM summary generation pass entirely.

Cache structure:
    {cache_dir}/{library}/{version}/summaries.json

Summaries are versioned by library version.  A version mismatch
triggers re-generation.  The cache key is (library, version).
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = "core/audit/summary_cache"


@dataclass
class CachedSummary:
    """A cached function summary from a library."""

    function: str
    library: str
    version: str
    param_preconditions: list[dict[str, str]] = field(default_factory=list)
    return_postconditions: list[dict[str, str]] = field(default_factory=list)
    taint_rules: list[dict[str, str]] = field(default_factory=list)
    error_behaviour: dict[str, Any] = field(default_factory=dict)
    state_transitions: list[dict[str, str]] = field(default_factory=list)
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "library": self.library,
            "version": self.version,
            "param_preconditions": self.param_preconditions,
            "return_postconditions": self.return_postconditions,
            "taint_rules": self.taint_rules,
            "error_behaviour": self.error_behaviour,
            "state_transitions": self.state_transitions,
            "confidence": self.confidence,
        }


@dataclass
class SummaryCache:
    """Persistent cache of library function summaries."""

    cache_dir: Path
    _index: dict[str, dict[str, CachedSummary]] = field(
        default_factory=dict,
    )

    def lookup(
        self,
        library: str,
        version: str,
        function: str,
    ) -> CachedSummary | None:
        key = f"{library}/{version}"
        lib_cache = self._index.get(key)
        if lib_cache is None:
            lib_cache = self._load_version(library, version)
            self._index[key] = lib_cache
        return lib_cache.get(function)

    def lookup_library(
        self,
        library: str,
        version: str,
    ) -> dict[str, CachedSummary]:
        if not self._safe_component(library) or not self._safe_component(version):
            return {}
        key = f"{library}/{version}"
        if key not in self._index:
            self._index[key] = self._load_version(library, version)
        return self._index[key]

    @staticmethod
    def _safe_component(value: str) -> bool:
        if not value or ".." in value or "/" in value or "\\" in value:
            return False
        return not Path(value).is_absolute()

    def store(
        self,
        library: str,
        version: str,
        summaries: list[CachedSummary],
    ) -> Path:
        if not self._safe_component(library) or not self._safe_component(version):
            raise ValueError(f"unsafe cache key: {library!r}/{version!r}")
        lib_dir = self.cache_dir / library / version
        lib_dir.mkdir(parents=True, exist_ok=True)

        data = [s.to_dict() for s in summaries]
        path = lib_dir / "summaries.json"

        fd, tmp = tempfile.mkstemp(dir=str(lib_dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, str(path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        key = f"{library}/{version}"
        self._index[key] = {s.function: s for s in summaries}

        return path

    def has_library(self, library: str, version: str) -> bool:
        if not self._safe_component(library) or not self._safe_component(version):
            return False
        path = self.cache_dir / library / version / "summaries.json"
        return path.is_file()

    def available_libraries(self) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        if not self.cache_dir.is_dir():
            return result
        for lib_dir in sorted(self.cache_dir.iterdir()):
            if not lib_dir.is_dir():
                continue
            for ver_dir in sorted(lib_dir.iterdir()):
                if not ver_dir.is_dir():
                    continue
                summary_path = ver_dir / "summaries.json"
                if summary_path.is_file():
                    result.append({
                        "library": lib_dir.name,
                        "version": ver_dir.name,
                    })
        return result

    def summary(self) -> str:
        libs = self.available_libraries()
        if not libs:
            return "Summary cache: empty"
        lib_names = sorted({entry["library"] for entry in libs})
        return (
            f"Summary cache: {len(libs)} versions across "
            f"{len(lib_names)} libraries ({', '.join(lib_names[:5])})"
        )

    def _load_version(
        self,
        library: str,
        version: str,
    ) -> dict[str, CachedSummary]:
        if not self._safe_component(library) or not self._safe_component(version):
            return {}
        path = self.cache_dir / library / version / "summaries.json"
        if not path.is_file():
            return {}

        try:
            data = json.loads(path.read_text())
        except Exception:
            logger.debug(
                "failed to load summary cache %s", path, exc_info=True,
            )
            return {}

        result: dict[str, CachedSummary] = {}
        for item in data:
            try:
                cs = CachedSummary(
                    function=item["function"],
                    library=item.get("library", library),
                    version=item.get("version", version),
                    param_preconditions=item.get("param_preconditions", []),
                    return_postconditions=item.get("return_postconditions", []),
                    taint_rules=item.get("taint_rules", []),
                    error_behaviour=item.get("error_behaviour", {}),
                    state_transitions=item.get("state_transitions", []),
                    confidence=item.get("confidence", "high"),
                )
                result[cs.function] = cs
            except Exception:  # noqa: BLE001, S112 — one malformed cache row must not sink the load
                continue

        return result


def load_summary_cache(cache_dir: Path | None = None) -> SummaryCache:
    """Load or create the summary cache."""
    if cache_dir is None:
        raptor_dir = os.environ["RAPTOR_DIR"]
        cache_dir = Path(raptor_dir) / _DEFAULT_CACHE_DIR
    return SummaryCache(cache_dir=cache_dir)


def detect_library_version(
    target_path: Path,
    library: str,
) -> str | None:
    """Detect the version of a library used by the target.

    Checks common dependency manifest files (requirements.txt,
    package.json, go.mod, Cargo.toml, etc.).
    """
    detectors = [
        ("requirements.txt", _parse_requirements_txt),
        ("setup.cfg", _parse_requirements_txt),
        ("Pipfile.lock", _parse_pipfile_lock),
        ("package.json", _parse_package_json),
        ("go.mod", _parse_go_mod),
        ("Cargo.toml", _parse_cargo_toml),
    ]

    for filename, parser in detectors:
        manifest = target_path / filename
        if manifest.is_file():
            try:
                version = parser(manifest.read_text(), library)
                if version:
                    return version
            except Exception:  # noqa: BLE001, S112 — per-manifest parse: try the next candidate
                continue

    return None


def _parse_requirements_txt(content: str, library: str) -> str | None:
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("==", ">=", "<=", "~=", "!="):
            if sep in line:
                name, version = line.split(sep, 1)
                if name.strip().lower() == library.lower():
                    return version.strip().split(",")[0].strip()
                break
    return None


def _parse_pipfile_lock(content: str, library: str) -> str | None:
    try:
        data = json.loads(content)
    except Exception:  # noqa: BLE001 — malformed lockfile: no version claim
        return None
    for section in ("default", "develop"):
        entry = data.get(section, {}).get(library)
        if entry and isinstance(entry, dict):
            version = entry.get("version", "")
            return version.lstrip("=") if version else None
    return None


def _parse_package_json(content: str, library: str) -> str | None:
    try:
        data = json.loads(content)
    except Exception:  # noqa: BLE001 — malformed manifest: no version claim
        return None
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if library in deps:
            version = deps[library]
            return version.lstrip("^~>=<")
    return None


def _parse_go_mod(content: str, library: str) -> str | None:
    """Match by exact module path, or by suffix on a '/' boundary —
    "crypto" matches golang.org/x/crypto but NOT github.com/x/cryptoutil.
    Substring matching returned whichever unrelated module happened to
    contain the name first."""
    for line in content.splitlines():
        parts = line.strip().split()
        if parts and parts[0] == "require" and len(parts) >= 3:
            # single-line `require example.com/mod v1.2.3`
            parts = parts[1:]
        if len(parts) >= 2:
            module = parts[0]
            if module == library or module.endswith("/" + library):
                return parts[1].lstrip("v")
    return None


_CARGO_INLINE_VERSION_RE = re.compile(r'version\s*=\s*"([^"]+)"')


def _parse_cargo_toml(content: str, library: str) -> str | None:
    for line in content.splitlines():
        line = line.strip()
        if line.startswith((f'{library} ', f'{library}=')):
            if "=" not in line:
                continue
            rhs = line.split("=", 1)[1].strip()
            if rhs.startswith("{"):
                # Inline table: foo = { version = "1.0", features = [...] }
                # Naive quote-stripping returned '{ version = "1.0' here,
                # which then became the cache directory / version key.
                m = _CARGO_INLINE_VERSION_RE.search(rhs)
                if m:
                    return m.group(1).lstrip("^~>=<").split(",")[0].strip()
                return None  # git/path dependency — no version key
            rhs = rhs.strip('"').strip("'")
            return rhs.lstrip("^~>=<").split(",")[0].strip()
    return None
