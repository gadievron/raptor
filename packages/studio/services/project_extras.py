"""Studio-side sidecar for per-project metadata beyond raptor's schema.

Raptor's ``project.json`` is a 7-field schema (version, name, target,
output_dir, description, notes, created). We deliberately do not extend it —
we want projects created here to round-trip through raptor's CLI cleanly.

But raptor-studio needs to know extra things about each project:
  * type — ``source`` / ``binary`` / ``forensics`` (drives form UX)
  * binary — an optional secondary binary path for mixed projects that do
              both source analysis and fuzzing
  * focus — research question / scope hint (useful for forensics)
  * language — CodeQL language hint

These live in ``$STUDIO_DATA_DIR/project-extras/<name>.json`` and are
entirely optional — a project with no sidecar still works, and a project
created by raptor's CLI (no studio sidecar) gets a best-effort type guess
from its runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from packages.studio.config import STUDIO_DATA_DIR

PROJECT_TYPES = ("source", "binary", "forensics")

PROJECT_TYPE_LABELS = {
    "source":    "Source analysis",
    "binary":    "Binary fuzzing",
    "forensics": "OSS forensics",
}

PROJECT_TYPE_DESCRIPTIONS = {
    "source":    "Scan, agentic, CodeQL, and validate against a code repository.",
    "binary":    "AFL++ fuzz a compiled binary; analyse crashes with rr + GDB.",
    "forensics": "Evidence-backed investigation of a public GitHub repository.",
}


@dataclass
class ProjectExtras:
    type: Optional[str] = None
    # Path to a secondary source repository, used by binary-type projects that
    # also want to run source analysis against the source tree the binary was
    # built from.
    source_repo: str = ""
    # Forensics-type extras
    focus: str = ""
    vendor_report_url: str = ""
    # Source-type extras
    language: str = ""
    # Binary-type extras
    corpus_dir: str = ""
    created_via: str = ""  # "studio" | "raptor-cli" | ""

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "source_repo": self.source_repo,
            "focus": self.focus,
            "vendor_report_url": self.vendor_report_url,
            "language": self.language,
            "corpus_dir": self.corpus_dir,
            "created_via": self.created_via,
        }

    @property
    def is_empty(self) -> bool:
        return not any([
            self.type, self.source_repo, self.focus, self.vendor_report_url,
            self.language, self.corpus_dir, self.created_via,
        ])


def _sidecar_path(name: str, studio_dir: Path = STUDIO_DATA_DIR) -> Path:
    return studio_dir / "project-extras" / f"{name}.json"


def load(name: str, studio_dir: Path = STUDIO_DATA_DIR) -> ProjectExtras:
    path = _sidecar_path(name, studio_dir)
    if not path.is_file():
        return ProjectExtras()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return ProjectExtras()
    if not isinstance(data, dict):
        return ProjectExtras()
    return ProjectExtras(
        type=data.get("type") or None,
        source_repo=data.get("source_repo", "") or "",
        focus=data.get("focus", "") or "",
        vendor_report_url=data.get("vendor_report_url", "") or "",
        language=data.get("language", "") or "",
        corpus_dir=data.get("corpus_dir", "") or "",
        created_via=data.get("created_via", "") or "",
    )


def save(name: str, extras: ProjectExtras, studio_dir: Path = STUDIO_DATA_DIR) -> Path:
    path = _sidecar_path(name, studio_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(extras.to_dict(), indent=2) + "\n")
    return path


def delete(name: str, studio_dir: Path = STUDIO_DATA_DIR) -> None:
    path = _sidecar_path(name, studio_dir)
    if path.is_file():
        try:
            path.unlink()
        except OSError:
            pass


def infer_type_from_runs(runs) -> Optional[str]:
    """Best-effort type guess for projects without a sidecar.

    ``runs`` is an iterable of RaptorRun. Looks at the most-recent run's kind.
    """
    for run in runs:
        lane = _kind_to_type(run.kind)
        if lane:
            return lane
    return None


def _kind_to_type(kind: str) -> Optional[str]:
    if kind in ("fuzz", "crash-analysis"):
        return "binary"
    if kind == "oss-forensics":
        return "forensics"
    if kind in ("scan", "codeql", "agentic", "validate", "understand", "analyze", "web"):
        return "source"
    return None
