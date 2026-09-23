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
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from core.json import load_json, save_json

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
    # Provenance default claims the HUMBLER tier: an unlabelled
    # construction must never mint a human-labelled learning (the
    # annotations doctrine — human provenance is asserted, never
    # defaulted). Machine producers set it explicitly anyway; the
    # legacy loader keeps its own tolerance for pre-source rows.
    source: str = "llm"
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


def _pinned_context_dir(out_dir: Path, for_write: bool) -> Path | None:
    """The run pin's project dir for context storage, or None.

    Returns the pinned project's dir when the run carries a real pin;
    None for a pin-null (standalone) run — its context stays run-local
    even when a parent LOOKS project-shaped. Pin-less legacy dirs
    return None here and take the caller's shape fallback (reads; a
    legacy WRITE also falls back, preserving pre-series behaviour for
    pre-series dirs).
    """
    try:
        from core.run.pin import pin_project_dir, resolve_run_pin
        pin = resolve_run_pin(out_dir)
        if pin.authoritative:
            return pin_project_dir(out_dir, for_write=for_write)
    except Exception:  # noqa: BLE001 — shape fallback below
        pass
    return None


def _pin_is_authoritative(out_dir: Path) -> bool:
    try:
        from core.run.pin import resolve_run_pin
        return resolve_run_pin(out_dir).authoritative
    except Exception:  # noqa: BLE001
        return False


def load_project_context(out_dir: Path) -> ProjectContext:
    """Load project context from the output or project directory.

    Only checks the parent directory when it looks like a managed
    project directory (contains a project marker). This prevents
    loading stale context from unrelated runs that happen to share
    a generic parent like ``/tmp/``.
    """
    candidates = [out_dir / "project-context.json"]
    pinned = _pinned_context_dir(out_dir, for_write=False)
    if pinned is not None:
        candidates.append(pinned / "project-context.json")
    elif not _pin_is_authoritative(out_dir):
        # Pin-less legacy run dir: the historical parent-shape probe.
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
    project_dir = _pinned_context_dir(out_dir, for_write=True)
    if project_dir is None and not _pin_is_authoritative(out_dir):
        parent = out_dir.parent
        if parent != out_dir and _is_project_dir(parent):
            project_dir = parent
    if project_dir is not None and project_dir != out_dir:
        target = project_dir / "project-context.json"
        try:
            return _atomic_write(ctx, target)
        except OSError:
            # The fallback FORKS the store: this run's learnings land
            # in the run dir while the project-level file stays stale,
            # and later runs read the project copy. Loud so the
            # operator can fix the permission/disk issue and re-merge.
            logger.warning(
                "project-context write to %s failed — falling back to "
                "the run directory %s (learnings recorded there will "
                "not be visible to other runs of this project)",
                target, out_dir, exc_info=True,
            )

    target = out_dir / "project-context.json"
    try:
        return _atomic_write(ctx, target)
    except OSError as exc:
        logger.warning("could not save project context: %s", exc)
        raise


def _atomic_write(ctx: ProjectContext, target: Path) -> Path:
    save_json(target, ctx.to_dict())
    return target


def add_learning(
    out_dir: Path,
    text: str,
    *,
    source: str,
    category: str = "note",
    file: str = "",
    function: str = "",
    strategy: str = "",
) -> Learning | None:
    """Add a learning to the project context. Returns the Learning if
    added. *source* is deliberately required: it is a provenance
    claim ("human" gets the operator tier in readers), and a default
    minted human-labelled learnings for every caller that forgot to
    say otherwise — machine callers pass "llm"."""
    if category not in VALID_CATEGORIES:
        msg = f"invalid category {category!r}; valid: {sorted(VALID_CATEGORIES)}"
        raise ValueError(msg)
    # Load→append→save is last-writer-wins across concurrent sessions
    # sharing a project: two simultaneous add_learning calls can drop
    # one learning. Learnings are advisory review hints (never verdict
    # state), sessions rarely write concurrently, and the file write
    # itself is atomic — accepted; revisit with a lock if this ever
    # carries authority.
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
