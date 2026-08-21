"""Disk-first spec store.

Two storage shapes, both plain JSON on disk (SAGE or any other recall
layer adds semantic search ON TOP of this; its absence costs fuzzy
recall only — the disk store is always authoritative):

* **Run-local**: a verified provisioning run writes the spec that
  produced it as ``environment-spec.json`` in its output directory —
  the durable "how to rebuild what this run verified" record.
* **Library**: a named collection under one root directory (typically
  ``<project>/env-specs/``), one ``<slug>.json`` per spec, for reuse
  across runs. A stale library spec costs one failed re-verify, never
  a wrong result — re-provisioning always re-runs the verify plan.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.atomic_fs import write_text_atomically
from core.env.spec import EnvironmentSpec

RUN_SPEC_FILENAME = "environment-spec.json"

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def _slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.strip().lower()).strip("-.")
    if not slug:
        raise ValueError(f"spec name {name!r} yields an empty slug")
    return slug


def save_run_spec(spec: EnvironmentSpec, output_dir: str | Path) -> Path:
    """Write the run-local ``environment-spec.json`` (atomic)."""
    path = Path(output_dir) / RUN_SPEC_FILENAME
    write_text_atomically(path, spec.to_json() + "\n")
    return path


def load_run_spec(output_dir: str | Path) -> EnvironmentSpec | None:
    """Load a run's spec, or None when the run recorded none."""
    path = Path(output_dir) / RUN_SPEC_FILENAME
    if not path.is_file():
        return None
    return EnvironmentSpec.from_json(path.read_text(encoding="utf-8"))


class SpecStore:
    """A named spec library rooted at one directory."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def path_for(self, name: str) -> Path:
        return self.root / f"{_slug(name)}.json"

    def save(self, spec: EnvironmentSpec) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(spec.name)
        write_text_atomically(path, spec.to_json() + "\n")
        return path

    def load(self, name: str) -> EnvironmentSpec | None:
        path = self.path_for(name)
        if not path.is_file():
            return None
        return EnvironmentSpec.from_json(path.read_text(encoding="utf-8"))

    def names(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(p.stem for p in self.root.glob("*.json"))
