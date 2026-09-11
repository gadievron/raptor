"""Prepare deterministic fuzzing seed corpora from project fixtures.

The helper is intentionally conservative: it copies small parser/input fixtures into
kind-specific seed directories and records a manifest without printing or storing
file contents. Sensitive-looking files are skipped by default so generated corpora
can be shared with fuzzing runs and CI artifacts more safely.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from core.json import load_json, load_json_bounded, save_json

if TYPE_CHECKING:
    from collections.abc import Iterable

TEXT_EXTENSIONS = {
    ".cfg": "text",
    ".conf": "text",
    ".csv": "csv",
    ".html": "html",
    ".htm": "html",
    ".ini": "text",
    ".json": "json",
    ".jsonl": "json",
    ".md": "text",
    ".svg": "xml",
    ".toml": "text",
    ".txt": "text",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}

BINARY_EXTENSIONS = {
    ".bmp",
    ".bin",
    ".gif",
    ".ico",
    ".jpg",
    ".jpeg",
    ".pdf",
    ".png",
    ".wasm",
    ".webp",
    ".zip",
}

SKIP_DIR_NAMES = {
    ".cache",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}

SENSITIVE_EXACT_NAMES = {
    ".env",
    ".env.local",
    ".netrc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "secrets.json",
}

SENSITIVE_SUFFIXES = {
    ".crt",
    ".der",
    ".gpg",
    ".jks",
    ".key",
    ".kubeconfig",
    ".p12",
    ".pem",
    ".pfx",
}

SENSITIVE_SUBSTRINGS = (
    "access_token",
    "apikey",
    "api_key",
    "auth_token",
    "client_secret",
    "credential",
    "id_token",
    "password",
    "private_key",
    "refresh_token",
    "secret",
)

LOCKFILE_NAMES = {
    "bun.lockb",
    "composer.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "yarn.lock",
}

DEFAULT_MAX_FILE_SIZE = 1024 * 1024
GENERATED_SEED_KINDS = set(TEXT_EXTENSIONS.values()) | {"binary"}

# Provenance stamp for manifests this generator writes; the reset path
# only deletes kind directories under a manifest carrying it.
GENERATED_SEED_CORPUS_SOURCE = "raptor_generated_seed_corpus"
BUILTIN_SEED_CORPUS_DIR = Path(__file__).resolve().parent / "data" / "seed_corpus"

# packages/fuzzing/seed_corpus.py → repo root is two levels up.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _portable_path(path: Path) -> str:
    """Repo-relative POSIX form for paths inside the checkout.

    Generated manifests can be committed (seeds/); an absolute path
    would embed the local checkout location into the repository.
    Paths outside the checkout (run output dirs) keep their absolute
    form — there is nothing stable to relativise them against.
    """
    try:
        return path.resolve().relative_to(_REPO_ROOT).as_posix()
    except (ValueError, OSError):
        return str(path)


@dataclass(frozen=True)
class SeedCorpusOptions:
    """Options for seed corpus preparation."""

    source_dir: Path
    out_dir: Path
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    include_lockfiles: bool = False


def _is_under_interesting_dir(path: Path) -> bool:
    interesting = {
        "example",
        "examples",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "test",
        "tests",
    }
    return any(part.lower() in interesting for part in path.parts)


def _sensitive_reason(relative_path: Path) -> str | None:
    parts = [part.lower() for part in relative_path.parts]
    name = parts[-1]
    stem = Path(name).stem
    suffix = Path(name).suffix

    if name in SENSITIVE_EXACT_NAMES:
        return "sensitive filename"
    if suffix in SENSITIVE_SUFFIXES:
        return "sensitive file extension"
    if any(marker in name or marker in stem for marker in SENSITIVE_SUBSTRINGS):
        return "sensitive filename"
    if any(part in {".ssh", ".gnupg", "secrets", "credentials"} for part in parts[:-1]):
        return "sensitive directory"
    return None


def _classify_seed(relative_path: Path) -> str | None:
    suffix = relative_path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        return TEXT_EXTENSIONS[suffix]
    if suffix in BINARY_EXTENSIONS and _is_under_interesting_dir(relative_path):
        return "binary"
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_candidate_files(
    source_dir: Path, exclude_dir: Path | None = None
) -> Iterable[Path]:
    exclude_resolved = exclude_dir.resolve() if exclude_dir is not None else None
    for dirpath, dirnames, filenames in os.walk(source_dir, followlinks=False):
        current_dir = Path(dirpath).resolve()
        if exclude_resolved is not None and current_dir == exclude_resolved:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d.lower() not in SKIP_DIR_NAMES
            and not (Path(dirpath) / d).is_symlink()
            and (
                exclude_resolved is None
                or (Path(dirpath) / d).resolve() != exclude_resolved
            )
        )
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_git_repository_root(path: Path) -> bool:
    git_path = path / ".git"
    return git_path.is_dir() or git_path.is_file()


def _validate_output_directory(source_dir: Path, out_dir: Path) -> None:
    dangerous_paths = {Path(out_dir.anchor).resolve(), Path.home().resolve()}
    if out_dir in dangerous_paths:
        msg = "seed output directory is too broad or dangerous"
        raise ValueError(msg)
    if _is_git_repository_root(out_dir):
        msg = "seed output directory must not be a repository root"
        raise ValueError(msg)

    if out_dir == source_dir:
        msg = "seed output directory must not be the source directory"
        raise ValueError(msg)
    if _is_relative_to(source_dir, out_dir):
        msg = "seed output directory must not be an ancestor of the source directory"
        raise ValueError(msg)


def _reset_generated_output(out_dir: Path) -> None:
    """Remove files generated by previous corpus preparation runs.

    The CLI may be re-run against the same output directory while sources are
    changing. Deletion is provenance-gated (mirroring
    ``_reset_builtin_output``): the kind names (``text``, ``json``,
    ``binary``, ...) are common directory names, so an operator-chosen
    out_dir can legitimately contain same-named directories this helper
    never wrote. Only when the previous run's ``manifest.json`` proves
    the content is ours do we remove it; otherwise refuse loudly rather
    than destroy foreign data. A corrupt or provenance-less manifest is
    treated as foreign — the safe direction.
    """

    manifest_path = out_dir / "manifest.json"
    ours = False
    if manifest_path.is_file():
        previous = load_json(manifest_path, max_bytes=64 * 1024 * 1024)
        ours = (
            isinstance(previous, dict)
            and previous.get("source") == GENERATED_SEED_CORPUS_SOURCE
        )
        if not ours:
            msg = (
                f"refusing to reset {out_dir}: manifest.json was not "
                "written by the seed corpus generator — pick an empty "
                "or generator-owned output directory"
            )
            raise ValueError(msg)

    existing_kind_dirs = [
        kind for kind in sorted(GENERATED_SEED_KINDS)
        if (out_dir / kind).exists() or (out_dir / kind).is_symlink()
    ]
    if existing_kind_dirs and not ours:
        msg = (
            f"refusing to reset {out_dir}: {', '.join(existing_kind_dirs)} "
            "exist but no generator-written manifest.json proves they came "
            "from a previous corpus run — pick an empty or generator-owned "
            "output directory"
        )
        raise ValueError(msg)

    for kind in GENERATED_SEED_KINDS:
        kind_dir = out_dir / kind
        try:
            if kind_dir.is_dir() and not kind_dir.is_symlink():
                shutil.rmtree(kind_dir)
            else:
                kind_dir.unlink(missing_ok=True)
        except FileNotFoundError:
            pass

    manifest_path.unlink(missing_ok=True)


def prepare_seed_corpus(options: SeedCorpusOptions) -> dict:
    """Copy safe, deterministic seed inputs from ``source_dir`` into ``out_dir``.

    Returns the manifest dictionary and writes it to ``manifest.json``.
    """

    source_dir = options.source_dir.resolve()
    out_dir = options.out_dir.resolve()
    if not source_dir.is_dir():
        msg = f"source directory not found: {options.source_dir}"
        raise FileNotFoundError(msg)
    if options.max_file_size <= 0:
        msg = "max_file_size must be positive"
        raise ValueError(msg)

    _validate_output_directory(source_dir, out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _reset_generated_output(out_dir)

    counters: dict[str, int] = {}
    seeds: list[dict] = []
    skipped: list[dict] = []

    for path in _iter_candidate_files(source_dir, exclude_dir=out_dir):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            relative_path = path.relative_to(source_dir)
            relative_posix = relative_path.as_posix()

            if not options.include_lockfiles and path.name.lower() in LOCKFILE_NAMES:
                skipped.append({"path": relative_posix, "reason": "lockfile"})
                continue

            sensitive_reason = _sensitive_reason(relative_path)
            if sensitive_reason:
                skipped.append({"path": relative_posix, "reason": sensitive_reason})
                continue

            kind = _classify_seed(relative_path)
            if kind is None:
                skipped.append(
                    {"path": relative_posix, "reason": "unsupported file type"}
                )
                continue

            size = path.stat().st_size
            if size > options.max_file_size:
                skipped.append(
                    {"path": relative_posix, "reason": "too large", "size": size}
                )
                continue

            counters[kind] = counters.get(kind, 0) + 1
            destination_relative = (
                Path(kind) / f"seed-{counters[kind]:04d}{path.suffix.lower()}"
            )
            destination = out_dir / destination_relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            sha256 = _sha256_file(destination)
            seeds.append(
                {
                    "source": relative_posix,
                    "destination": destination_relative.as_posix(),
                    "kind": kind,
                    "size": size,
                    "sha256": sha256,
                }
            )
        except OSError as exc:
            try:
                rel = path.relative_to(source_dir).as_posix()
            except ValueError:
                rel = str(path)
            skipped.append({"path": rel, "reason": f"unreadable: {type(exc).__name__}"})

    manifest = {
        "source": GENERATED_SEED_CORPUS_SOURCE,
        "source_dir": _portable_path(source_dir),
        "out_dir": _portable_path(out_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "max_file_size": options.max_file_size,
        "include_lockfiles": options.include_lockfiles,
        "seed_count": len(seeds),
        "skipped_count": len(skipped),
        "seeds": seeds,
        "skipped": skipped,
    }

    manifest_path = out_dir / "manifest.json"
    save_json(manifest_path, manifest, sort_keys=True)
    return manifest


def prepare_builtin_seed_corpus(out_dir: Path, profile: str = "default") -> dict:
    """Materialise RAPTOR's curated community seed corpus into ``out_dir``.

    The checked-in corpus is deliberately source-controlled and tiny. This helper
    copies it into a flat AFL/libFuzzer-friendly directory and writes a generated
    manifest with sizes and hashes for the exact seeds used by this run.
    """

    out_dir = Path(out_dir).resolve()
    _validate_builtin_output_directory(out_dir)
    manifest_path = BUILTIN_SEED_CORPUS_DIR / "manifest.json"
    if not manifest_path.is_file():
        msg = f"built-in seed corpus manifest missing: {manifest_path}"
        raise FileNotFoundError(msg)

    try:
        # Repo-bundled data file; ValueError covers malformed JSON
        # and the byte-budget refusal.
        source_manifest = load_json_bounded(
            manifest_path, max_bytes=8 * 1024 * 1024,
        )
    except (ValueError, OSError) as exc:
        msg = f"malformed seed corpus manifest: {exc}"
        raise ValueError(msg) from exc
    seeds_config = source_manifest.get("seeds") or []
    if not isinstance(seeds_config, list):
        msg = "built-in seed corpus manifest has invalid seeds list"
        raise ValueError(msg)

    selected: list[tuple[dict, str, Path]] = []
    for item in seeds_config:
        profiles = set(item.get("profiles") or ["default"])
        if profile not in profiles and "default" not in profiles:
            continue

        name = str(item.get("name") or "").strip()
        path_str = str(item.get("path") or "").strip()
        if not name or "/" in name or "\\" in name or name in {".", ".."}:
            msg = f"invalid built-in seed name: {name!r}"
            raise ValueError(msg)
        if not path_str:
            msg = f"empty path for built-in seed: {name!r}"
            raise ValueError(msg)
        source_rel = Path(path_str)
        if source_rel.is_absolute() or ".." in source_rel.parts:
            msg = f"invalid built-in seed path: {source_rel}"
            raise ValueError(msg)

        source = BUILTIN_SEED_CORPUS_DIR / source_rel
        if not source.is_file() or source.is_symlink():
            msg = f"built-in seed missing: {source_rel}"
            raise FileNotFoundError(msg)

        selected.append((item, name, source_rel))

    if not selected:
        msg = f"built-in seed corpus profile produced no seeds: {profile}"
        raise ValueError(msg)

    out_dir.mkdir(parents=True, exist_ok=True)
    _reset_builtin_output(out_dir, {name for _, name, _ in selected})

    copied: list[dict] = []
    for item, name, source_rel in selected:
        source = BUILTIN_SEED_CORPUS_DIR / source_rel
        destination = out_dir / name
        shutil.copyfile(source, destination)
        copied.append({
            "name": name,
            "source": source_rel.as_posix(),
            "destination": name,
            "kind": item.get("kind", "generic"),
            "description": item.get("description", ""),
            "size": destination.stat().st_size,
            "sha256": _sha256_file(destination),
        })

    manifest = {
        "source": "raptor_builtin_seed_corpus",
        "source_manifest": _portable_path(manifest_path),
        "version": source_manifest.get("version", 1),
        "profile": profile,
        "out_dir": _portable_path(out_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed_count": len(copied),
        "seeds": copied,
    }
    save_json(out_dir / "manifest.json", manifest, sort_keys=True)
    return manifest


def _validate_builtin_output_directory(out_dir: Path) -> None:
    dangerous_paths = {Path(out_dir.anchor).resolve(), Path.home().resolve()}
    if out_dir in dangerous_paths:
        msg = "built-in seed output directory is too broad or dangerous"
        raise ValueError(msg)
    if _is_git_repository_root(out_dir):
        msg = "built-in seed output directory must not be a repository root"
        raise ValueError(msg)


def _reset_builtin_output(out_dir: Path, seed_names: set[str]) -> None:
    generated_names = set(seed_names)
    existing_manifest = out_dir / "manifest.json"
    if existing_manifest.is_file():
        # Manifest from a previous run of this generator; missing /
        # corrupt / oversize degrade to "no previous manifest".
        previous = load_json(existing_manifest, max_bytes=64 * 1024 * 1024)
        if previous is None:
            previous = {}
        if previous.get("source") == "raptor_builtin_seed_corpus":
            for seed in previous.get("seeds") or []:
                destination = str(seed.get("destination") or "")
                if destination and "/" not in destination and "\\" not in destination and ".." not in destination:
                    generated_names.add(destination)
        existing_manifest.unlink()

    for name in generated_names:
        path = out_dir / name
        try:
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        except (FileNotFoundError, OSError):
            pass


__all__ = [
    "DEFAULT_MAX_FILE_SIZE",
    "SeedCorpusOptions",
    "prepare_builtin_seed_corpus",
    "prepare_seed_corpus",
]
