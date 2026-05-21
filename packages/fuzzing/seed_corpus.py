"""Prepare deterministic fuzzing seed corpora from project fixtures.

The helper is intentionally conservative: it copies small parser/input fixtures into
kind-specific seed directories and records a manifest without printing or storing
file contents. Sensitive-looking files are skipped by default so generated corpora
can be shared with fuzzing runs and CI artifacts more safely.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

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
    with open(path, "rb") as fh:
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
        raise ValueError("seed output directory is too broad or dangerous")
    if _is_git_repository_root(out_dir):
        raise ValueError("seed output directory must not be a repository root")

    if out_dir == source_dir:
        raise ValueError("seed output directory must not be the source directory")
    if _is_relative_to(source_dir, out_dir):
        raise ValueError("seed output directory must not be an ancestor of the source directory")


def _reset_generated_output(out_dir: Path) -> None:
    """Remove files generated by previous corpus preparation runs.

    The CLI may be re-run against the same output directory while sources are
    changing. Remove only this helper's generated kind directories and manifest so
    stale seeds do not survive into the next run; leave unrelated files alone.
    """

    for kind in GENERATED_SEED_KINDS:
        kind_dir = out_dir / kind
        if kind_dir.is_dir() and not kind_dir.is_symlink():
            shutil.rmtree(kind_dir)
        elif kind_dir.exists():
            kind_dir.unlink()

    manifest_path = out_dir / "manifest.json"
    if manifest_path.is_file() or manifest_path.is_symlink():
        manifest_path.unlink()


def prepare_seed_corpus(options: SeedCorpusOptions) -> dict:
    """Copy safe, deterministic seed inputs from ``source_dir`` into ``out_dir``.

    Returns the manifest dictionary and writes it to ``manifest.json``.
    """

    source_dir = options.source_dir.resolve()
    out_dir = options.out_dir.resolve()
    if not source_dir.is_dir():
        raise FileNotFoundError(f"source directory not found: {options.source_dir}")
    if options.max_file_size <= 0:
        raise ValueError("max_file_size must be positive")

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
        "source_dir": str(source_dir),
        "out_dir": str(out_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "max_file_size": options.max_file_size,
        "include_lockfiles": options.include_lockfiles,
        "seed_count": len(seeds),
        "skipped_count": len(skipped),
        "seeds": seeds,
        "skipped": skipped,
    }

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


__all__ = ["DEFAULT_MAX_FILE_SIZE", "SeedCorpusOptions", "prepare_seed_corpus"]
