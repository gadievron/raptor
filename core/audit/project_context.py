"""Persistent project-level context for cross-run learnings.

Stores and retrieves learnings (patterns, false-positive suppressions,
codebase-specific notes) that persist across audit runs within a project.
Inspired by Semgrep Assistant's "Memories" pattern.

Storage: ``project-context.json`` in the project output directory.
Schema:
    {
        "version": 1,
        "learnings": [
            {
                "id": "<uuid-hex-short>",
                "text": "This project uses OpenSSL 1.1.1 ...",
                "category": "architecture|pattern|suppression|note",
                "source": "human|llm",
                "created": "2026-06-22T...",
                "file": "src/crypto.c",       # optional scope
                "function": "encrypt_block",   # optional scope
                "strategy": "crypto",          # optional strategy tag
            },
            ...
        ]
    }

Reuse: Both /audit skill and future /audit --agentic load learnings
via assemble_context(). The store is append-only with dedup by text hash.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from core.json import load_json

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# project-context.json is a small RAPTOR-written learnings store.
_MAX_CONTEXT_BYTES = 8 * 1024 * 1024

_SCHEMA_VERSION = 1


@dataclass
class Learning:
    text: str
    category: str = "note"
    source: str = "human"
    created: str = ""
    id: str = ""
    file: str = ""
    function: str = ""
    strategy: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(self.text.encode()).hexdigest()[:12]
        if not self.created:
            self.created = datetime.now(timezone.utc).isoformat()


VALID_CATEGORIES = frozenset({
    "architecture", "pattern", "suppression", "note",
})


@dataclass
class ProjectContext:
    version: int = _SCHEMA_VERSION
    learnings: list[Learning] = field(default_factory=list)

    def add(self, learning: Learning) -> bool:
        """Add a learning if not already present (dedup by text hash)."""
        existing_ids = {lrn.id for lrn in self.learnings}
        if learning.id in existing_ids:
            return False
        self.learnings.append(learning)
        return True

    def remove(self, learning_id: str) -> bool:
        before = len(self.learnings)
        self.learnings = [lrn for lrn in self.learnings if lrn.id != learning_id]
        return len(self.learnings) < before

    def query(
        self,
        *,
        file: str | None = None,
        function: str | None = None,
        category: str | None = None,
        strategy: str | None = None,
    ) -> list[Learning]:
        """Filter learnings by optional scope."""
        results = []
        for lrn in self.learnings:
            if file and lrn.file and lrn.file != file:
                continue
            if function and lrn.function and lrn.function != function:
                continue
            if category and lrn.category != category:
                continue
            if strategy and lrn.strategy and lrn.strategy != strategy:
                continue
            results.append(lrn)
        return results

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "learnings": [asdict(lrn) for lrn in self.learnings],
        }


def _is_project_dir(d: Path) -> bool:
    """Check if a directory is a managed project output directory."""
    try:
        from core.project import is_project_output_dir
        return is_project_output_dir(d)
    except ImportError:
        return False


def load_project_context(out_dir: Path) -> ProjectContext:
    """Load project context from the output or project directory.

    Only checks the parent directory when it looks like a managed
    project directory (contains a project marker). This prevents
    loading stale context from unrelated runs that happen to share
    a generic parent like ``/tmp/``.
    """
    candidates = [out_dir / "project-context.json"]
    parent = out_dir.parent
    if parent != out_dir and _is_project_dir(parent):
        candidates.append(parent / "project-context.json")
    for candidate in candidates:
        if candidate.exists():
            try:
                data = load_json(candidate, max_bytes=_MAX_CONTEXT_BYTES)
                if not isinstance(data, dict):
                    continue
                learnings = [Learning(
                        text=item.get("text", ""),
                        category=item.get("category", "note"),
                        source=item.get("source", "human"),
                        created=item.get("created", ""),
                        id=item.get("id", ""),
                        file=item.get("file", ""),
                        function=item.get("function", ""),
                        strategy=item.get("strategy", ""),
                    ) for item in data.get("learnings", [])]
                return ProjectContext(
                    version=data.get("version", _SCHEMA_VERSION),
                    learnings=learnings,
                )
            except Exception:
                logger.warning("project-context load failed: %s", candidate, exc_info=True)
    return ProjectContext()


def save_project_context(ctx: ProjectContext, out_dir: Path) -> Path:
    """Save project context to the project directory (parent of run dir).

    Only writes to the parent directory when it is a managed project
    directory. Otherwise writes to ``out_dir/`` directly to avoid
    polluting generic parent directories like ``/tmp/``.
    """
    project_dir = out_dir.parent
    if project_dir != out_dir and _is_project_dir(project_dir):
        target = project_dir / "project-context.json"
        try:
            return _atomic_write(ctx, target)
        except OSError:
            pass

    target = out_dir / "project-context.json"
    try:
        return _atomic_write(ctx, target)
    except OSError as exc:
        logger.warning("could not save project context: %s", exc)
        raise


def _atomic_write(ctx: ProjectContext, target: Path) -> Path:
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), suffix=".tmp", prefix=".project-context-",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(ctx.to_dict(), f, indent=2)
        os.replace(tmp_name, str(target))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return target


def add_learning(
    out_dir: Path,
    text: str,
    *,
    category: str = "note",
    source: str = "human",
    file: str = "",
    function: str = "",
    strategy: str = "",
) -> Learning | None:
    """Add a learning to the project context. Returns the Learning if added."""
    if category not in VALID_CATEGORIES:
        msg = f"invalid category {category!r}; valid: {sorted(VALID_CATEGORIES)}"
        raise ValueError(msg)
    ctx = load_project_context(out_dir)
    learning = Learning(
        text=text,
        category=category,
        source=source,
        file=file,
        function=function,
        strategy=strategy,
    )
    if ctx.add(learning):
        save_project_context(ctx, out_dir)
        return learning
    return None
