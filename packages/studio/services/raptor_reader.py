"""Read-only reader for raptor project data.

Consumes:
  - RAPTOR_PROJECTS_DIR/<name>.json    (project registry entries)
  - <project.output_dir>/*/             (timestamped run directories)
  - <run_dir>/.raptor-run.json          (run metadata)
  - <run_dir>/findings*.json            (findings output, location varies)

Schema source: raptor/core/project/schema.py (project.json + .raptor-run.json).
This reader does best-effort parsing; malformed files are skipped rather than
fatal so the UI degrades gracefully on a messy raptor install.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from packages.studio.config import RAPTOR_PROJECTS_DIR
from packages.studio.services import project_extras as extras_service
from packages.studio.services.run_kind import classify as classify_kind

FINDINGS_FILENAMES = (
    "findings.json",
    "findings_validated.json",
    "findings_agentic.json",
    "findings_merged.json",
)


@dataclass
class RaptorRun:
    directory: Path
    command: str
    timestamp: str
    status: str
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dir(cls, dir_path: Path) -> Optional["RaptorRun"]:
        meta = dir_path / ".raptor-run.json"
        if not meta.is_file():
            return None
        try:
            data = json.loads(meta.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        return cls(
            directory=dir_path,
            command=data.get("command", ""),
            timestamp=data.get("timestamp", ""),
            status=data.get("status", "unknown"),
            extra=data.get("extra", {}) if isinstance(data.get("extra"), dict) else {},
        )

    @property
    def name(self) -> str:
        return self.directory.name

    @property
    def kind(self) -> str:
        """Canonical kind for this run — see `services/run_kind.classify`."""
        return classify_kind(self.command, self.directory.name)

    def findings(self) -> list[dict]:
        """Return findings from this run.

        Precedence: any JSON file in FINDINGS_FILENAMES (rich, post-validated)
        → fall back to parsing SARIF directly (raw scanner output). SARIF
        findings are normalized via sarif_reader.parse_run_sarif.
        """
        for filename in FINDINGS_FILENAMES:
            path = self.directory / filename
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("findings", "items", "results"):
                    if isinstance(data.get(key), list):
                        return data[key]
        # Late import to avoid circular dependency at module load.
        from packages.studio.services.sarif_reader import parse_run_sarif
        return parse_run_sarif(self.directory)


@dataclass
class RaptorProject:
    name: str
    target: str
    output_dir: Path
    description: str = ""
    notes: str = ""
    created: str = ""

    @property
    def exists_on_disk(self) -> bool:
        return self.output_dir.is_dir()

    @property
    def extras(self) -> "extras_service.ProjectExtras":
        """Studio-side sidecar metadata (type, binary, focus, language)."""
        return extras_service.load(self.name)

    @property
    def kind(self) -> Optional[str]:
        """Project type: 'source' / 'binary' / 'forensics'.

        Prefers the studio sidecar; falls back to inferring from runs.
        None if neither source is conclusive.
        """
        ex = self.extras
        if ex.type:
            return ex.type
        return extras_service.infer_type_from_runs(self.runs())

    @property
    def target_is_url(self) -> bool:
        t = self.target or ""
        return t.startswith(("http://", "https://", "git@", "ssh://"))

    def runs(self) -> list[RaptorRun]:
        if not self.output_dir.is_dir():
            return []
        out: list[RaptorRun] = []
        for child in sorted(self.output_dir.iterdir(), reverse=True):
            if not child.is_dir():
                continue
            run = RaptorRun.from_dir(child)
            if run is not None:
                out.append(run)
        return out


def list_projects(projects_dir: Path = RAPTOR_PROJECTS_DIR) -> list[RaptorProject]:
    if not projects_dir.is_dir():
        return []
    out: list[RaptorProject] = []
    for entry in sorted(projects_dir.glob("*.json")):
        try:
            data = json.loads(entry.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        out.append(
            RaptorProject(
                name=data.get("name", entry.stem),
                target=data.get("target", ""),
                output_dir=Path(data.get("output_dir", "")) if data.get("output_dir") else Path(""),
                description=data.get("description", ""),
                notes=data.get("notes", ""),
                created=data.get("created", ""),
            )
        )
    return out


def get_project(
    name: str, projects_dir: Path = RAPTOR_PROJECTS_DIR
) -> Optional[RaptorProject]:
    for proj in list_projects(projects_dir):
        if proj.name == name:
            return proj
    return None
