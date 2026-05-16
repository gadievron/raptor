"""Sandboxed Read/Grep/Glob tools for the hunt/trace dispatch loops.

The model's tool calls are *requests* — we execute them in our process.
Every handler validates that the requested path stays inside repo_root
to prevent path traversal (model returning ``../../etc/passwd``,
``/etc/passwd``, or symlink escapes).

Path-traversal defense:
    - ``Path.resolve()`` collapses ``..`` and follows symlinks.
    - ``resolved.is_relative_to(repo_root.resolve())`` is the test.
    - We resolve repo_root once at handler-construction time, not per
      call, so a TOCTOU on the parent dir doesn't matter — the agent
      can only escape by tricking us into resolving inside a moving
      target, and we never do.

Output caps:
    - Read returns at most _MAX_FILE_BYTES (256 KB).
    - Grep returns at most _MAX_GREP_MATCHES per call.
    - Glob returns at most _MAX_GLOB_MATCHES per call.

Errors:
    - All handlers return a JSON-encoded string. Errors are
      ``{"error": "..."}`` rather than raised — keeps the loop
      clean and lets the model recover (try a different path, etc.).

What gets scanned:
    - Hidden directories (``.git``, ``.tox``, ``__pycache__``, etc.)
      are skipped during walk-style operations (``grep``, ``glob_files``).
      The full skip list lives in ``_walk_files``.
    - Hidden FILES (e.g. ``.env``, ``.ssh/config``, ``.npmrc``) at the
      repo root or under non-skipped directories ARE scanned. If the
      target repo contains secrets in dotfiles, those secrets reach the
      LLM. Operators concerned about this should pre-filter their
      target directory or use a clean repo clone.
    - The model can also explicitly ``read_file(".env")`` if it wants —
      the absolute-path / traversal blocks don't restrict legitimate
      repo-relative paths.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List


# Output caps — generous but bounded. A hunt that exceeds these is
# almost certainly the model getting lost in the weeds.
_MAX_FILE_BYTES = 256 * 1024
_MAX_GREP_MATCHES = 200
_MAX_GLOB_MATCHES = 500
# Per-call iteration cap (bounds worst case for malicious globs)
_MAX_FILES_SCANNED = 50_000
# Per-line size cap for grep — a file with no newlines could otherwise
# allocate gigabytes when iterated by line. Lines longer than this are
# truncated for matching purposes; the snippet emitted in results is
# truncated separately to 300 chars.
_MAX_LINE_BYTES = 64 * 1024
# Skip files larger than this during grep — bounds worst-case wall-clock
# without missing matches in normal source files. Documented in result.
_MAX_GREP_FILE_BYTES = 16 * 1024 * 1024  # 16 MB


@dataclass(frozen=True)
class SandboxedTools:
    """Tool handlers bound to a specific repo_root.

    Construct one instance per dispatch call. The repo_root is resolved
    at construction; resolved paths in handlers are checked against it.
    """
    repo_root: Path

    @classmethod
    def for_repo(cls, repo_path: str | Path) -> "SandboxedTools":
        # Symmetric with _resolve_inside: NUL byte → clean error.
        if isinstance(repo_path, str) and "\x00" in repo_path:
            raise ValueError("repo_path contains NUL byte")
        root = Path(repo_path).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError(f"repo_path is not a directory: {root}")
        return cls(repo_root=root)

    # ----- handlers -----

    def read_file(self, path: str, *, max_lines: int | None = None) -> str:
        """Read a file relative to repo_root. Returns JSON string.

        Args:
            path: file path, may be absolute or relative to repo_root.
                Either way, must resolve inside repo_root.
            max_lines: if given, return at most this many leading lines.
                None or 0 returns the whole file (still capped by
                _MAX_FILE_BYTES). Must be int.
        """
        # Defensive: model output occasionally drifts on numeric fields.
        # Coerce or surface clearly rather than crashing at `> 0`.
        if max_lines is not None and (
            isinstance(max_lines, bool) or not isinstance(max_lines, int)
        ):
            return json.dumps({"error": "max_lines must be int or None"})

        # Detect repo_root disappearing (mirror of grep / glob_files).
        # Without this, _resolve_inside surfaces "path not found" for
        # every call, misleading the model into trying alternate paths.
        if not self.repo_root.is_dir():
            return json.dumps({"error": "repo_root no longer exists or is not a directory"})

        try:
            target = self._resolve_inside(path)
        except _SandboxError as e:
            return json.dumps({"error": str(e)})
        if not target.is_file():
            return json.dumps({"error": f"not a file: {path}"})

        # Read with a size cap so a giant file doesn't allocate gigabytes
        # of memory just to be sliced down. Read _MAX_FILE_BYTES + 1 to
        # detect overflow without buffering more than the cap.
        try:
            with target.open("rb") as fh:
                data = fh.read(_MAX_FILE_BYTES + 1)
        except OSError as e:
            return json.dumps({"error": f"read failed: {e}"})

        truncated = False
        if len(data) > _MAX_FILE_BYTES:
            data = data[:_MAX_FILE_BYTES]
            truncated = True

        # Decode with replacement; binary files become readable garbage
        # rather than raising. Models cope with that fine.
        text = data.decode("utf-8", errors="replace")

        if max_lines is not None and max_lines > 0:
            lines = text.splitlines(keepends=True)
            if len(lines) > max_lines:
                text = "".join(lines[:max_lines])
                truncated = True

        return json.dumps({
            "path": str(target.relative_to(self.repo_root)),
            "content": text,
            "truncated": truncated,
            "byte_cap": _MAX_FILE_BYTES,
        })

    def grep(
        self, pattern: str, *,
        path: str | None = None,
        regex: bool = False,
        case_sensitive: bool = True,
    ) -> str:
        """Search for ``pattern`` across files in repo_root.

        Args:
            pattern: literal substring (regex=False) or regex (regex=True).
            path: optional subpath inside repo_root to limit scope.
            regex: if True, treat pattern as a Python regex.
            case_sensitive: default True; toggle for case-insensitive.
        """
        if not isinstance(pattern, str) or not pattern:
            return json.dumps({"error": "pattern must be a non-empty string"})

        # Detect repo_root having gone missing since for_repo(). Without
        # this, os.walk silently yields nothing and the operator gets
        # an empty matches list indistinguishable from a real "no matches"
        # result.
        if not self.repo_root.is_dir():
            return json.dumps({"error": "repo_root no longer exists or is not a directory"})

        try:
            search_root = self._resolve_inside(path) if path else self.repo_root
        except _SandboxError as e:
            return json.dumps({"error": str(e)})
        if not search_root.exists():
            return json.dumps({"error": f"path not found: {path}"})
        # path scoping is directory-narrowing. A file path here would walk
        # nothing and silently return empty matches; surface clearly so
        # the model can read_file() the path instead.
        if not search_root.is_dir():
            return json.dumps({
                "error": f"path is a file, not a directory: {path}. "
                         f"Use read_file() to inspect a single file."
            })

        try:
            matcher = self._compile_matcher(pattern, regex, case_sensitive)
        except re.error as e:
            return json.dumps({"error": f"invalid regex: {e}"})

        matches: List[Dict[str, Any]] = []
        scanned = 0
        skipped_large: List[str] = []
        truncated = False

        for f in self._walk_files(search_root):
            scanned += 1
            if scanned > _MAX_FILES_SCANNED:
                truncated = True
                break
            # Skip files that would dominate wall-clock or memory.
            try:
                if f.stat().st_size > _MAX_GREP_FILE_BYTES:
                    skipped_large.append(str(f.relative_to(self.repo_root)))
                    continue
            except OSError:
                continue
            try:
                with f.open("rb") as fh:
                    lineno = 0
                    while True:
                        # Read one line at a time, bounded by _MAX_LINE_BYTES
                        # to defend against files with no newlines.
                        raw = fh.readline(_MAX_LINE_BYTES)
                        if not raw:
                            break
                        lineno += 1
                        # errors="replace" never raises — invalid bytes become
                        # U+FFFD. No try/except needed.
                        line = raw.decode("utf-8", errors="replace")
                        if matcher(line):
                            matches.append({
                                "file": str(f.relative_to(self.repo_root)),
                                "line": lineno,
                                # truncate snippet to avoid pathological lines
                                "snippet": line.rstrip("\r\n")[:300],
                            })
                            if len(matches) >= _MAX_GREP_MATCHES:
                                truncated = True
                                break
            except OSError:
                continue
            if truncated:
                break

        # Sort for deterministic output across runs and filesystems.
        # os.walk's iteration order is filesystem-dependent; without this,
        # two greps on the same repo could return different match orders.
        matches.sort(key=lambda m: (m["file"], m["line"]))

        return json.dumps({
            "pattern": pattern,
            "regex": regex,
            "matches": matches,
            "truncated": truncated,
            "match_cap": _MAX_GREP_MATCHES,
            "skipped_large_files": sorted(skipped_large[:20]),  # cap + sort
        })

    def glob_files(self, pattern: str) -> str:
        """List files matching a glob pattern, relative to repo_root.

        Pattern is matched against paths relative to repo_root with
        forward slashes (POSIX-style), regardless of OS.

        Pattern semantics use Python's ``fnmatch`` (NOT shell ``**``):
        - ``*`` matches any character INCLUDING ``/`` (unlike shell)
        - ``?`` matches a single character
        - ``[abc]`` matches a character class
        - ``**`` is interpreted as two ``*`` — works as recursive-ish
          glob in practice because ``*`` matches ``/``, but it's
          equivalent to a single ``*`` for matching purposes. Operators
          expecting strict shell-glob semantics should narrow with
          ``path=`` on grep instead.
        """
        if not isinstance(pattern, str) or not pattern:
            return json.dumps({"error": "pattern must be a non-empty string"})

        # Detect repo_root having gone missing (mirror of grep). Without
        # this, os.walk silently yields nothing and the operator gets
        # an empty matches list indistinguishable from "no files matched."
        if not self.repo_root.is_dir():
            return json.dumps({"error": "repo_root no longer exists or is not a directory"})

        # Normalize pattern: drop a leading "/" and "./" (in that order).
        # Use removeprefix throughout — str.lstrip() takes a character
        # set, not a prefix, which is a footgun mismatch we deliberately
        # avoid (matches the convention in code_understanding.adapters).
        pat = pattern.removeprefix("/").removeprefix("./")

        results: List[str] = []
        scanned = 0
        truncated = False
        for f in self._walk_files(self.repo_root):
            scanned += 1
            if scanned > _MAX_FILES_SCANNED:
                truncated = True
                break
            rel = str(f.relative_to(self.repo_root)).replace(os.sep, "/")
            if fnmatch.fnmatch(rel, pat):
                results.append(rel)
                if len(results) >= _MAX_GLOB_MATCHES:
                    truncated = True
                    break

        return json.dumps({
            "pattern": pattern,
            "matches": sorted(results),
            "truncated": truncated,
            "match_cap": _MAX_GLOB_MATCHES,
        })

    # ----- internals -----

    def _resolve_inside(self, path: str) -> Path:
        """Resolve path relative to repo_root and verify it stays inside.

        Raises _SandboxError if path traversal or symlink escape detected.
        """
        if not isinstance(path, str) or not path:
            raise _SandboxError("path must be a non-empty string")

        # NUL byte in path crashes Path.resolve on some systems with a
        # bare ValueError. Catch upfront for a clean error.
        if "\x00" in path:
            raise _SandboxError("path contains NUL byte")

        # Reject absolute paths outright — model should always be working
        # in repo-relative terms.
        p = Path(path)
        if p.is_absolute():
            raise _SandboxError(f"absolute paths not allowed: {path}")

        candidate = (self.repo_root / p)
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            # Resolve non-strictly to give the path-traversal check a chance,
            # then surface as not-found so the model can react.
            resolved = candidate.resolve()
            if not _is_inside(resolved, self.repo_root):
                raise _SandboxError(
                    f"path escapes repo_root: {path}"
                ) from None
            raise _SandboxError(f"path not found: {path}") from None
        except OSError as e:
            raise _SandboxError(f"resolve failed: {e}") from None

        if not _is_inside(resolved, self.repo_root):
            raise _SandboxError(f"path escapes repo_root: {path}")
        return resolved

    def _walk_files(self, root: Path):
        """Yield files under root, skipping common noise dirs.

        Skips: hidden dirs (starting with '.'), virtualenvs, build dirs,
        node_modules, __pycache__. Operators relying on hunt finding
        files inside .github/workflows etc. can pass path= explicitly.

        Iteration order is deterministic: directories and filenames
        are sorted at each step. ``os.walk`` is filesystem-dependent
        (ext4 yields insertion order, etc.), so without sorting, hitting
        a per-run cap (_MAX_GREP_MATCHES / _MAX_FILES_SCANNED) would
        produce DIFFERENT match SETS across runs on the same repo —
        not just different orders. That breaks reproducibility.
        """
        skip_dirs = {
            ".git", ".hg", ".svn", "node_modules", "__pycache__",
            "venv", ".venv", "env", ".env",
            "build", "dist", ".tox", ".mypy_cache", ".pytest_cache",
            "target",  # rust/maven
        }
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # In-place mutation tells os.walk not to descend.
            # Sort to fix deterministic order for cap-truncation.
            dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
            for fn in sorted(filenames):
                f = Path(dirpath) / fn
                # Symlink check — don't follow links to outside repo_root
                if f.is_symlink():
                    try:
                        target = f.resolve()
                        if not _is_inside(target, self.repo_root):
                            continue
                    except OSError:
                        continue
                yield f

    @staticmethod
    def _compile_matcher(
        pattern: str, regex: bool, case_sensitive: bool,
    ) -> Callable[[str], bool]:
        if regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled = re.compile(pattern, flags)
            return lambda line: bool(compiled.search(line))
        if case_sensitive:
            needle = pattern
            return lambda line: needle in line
        needle_lower = pattern.lower()
        return lambda line: needle_lower in line.lower()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _SandboxError(Exception):
    """Path traversal or sandbox violation — surfaces as a tool error."""


def _is_inside(path: Path, root: Path) -> bool:
    """True if path is at root or a descendant. Both must be already-resolved."""
    try:
        return path == root or path.is_relative_to(root)
    except (ValueError, AttributeError):
        # is_relative_to is 3.9+; AttributeError is a defensive guard
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
