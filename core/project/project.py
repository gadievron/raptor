"""Project model and manager.

A project is a lightweight pointer to a target codebase and its output
directory. Project files live in ~/.raptor/projects/<name>.json.
Output directories live wherever the user specifies (default: out/projects/<name>/).
"""

import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.json import load_json, save_json
from core.logging import get_logger

logger = get_logger()

# Default locations
PROJECTS_DIR = Path.home() / ".raptor" / "projects"
DEFAULT_OUTPUT_BASE = Path("out/projects")


@dataclass
class Project:
    """A RAPTOR project."""
    name: str
    target: str
    output_dir: str
    created: str = ""
    description: str = ""
    notes: str = ""
    version: int = 1

    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "name": self.name,
            "target": self.target,
            "output_dir": self.output_dir,
            "created": self.created,
            "description": self.description,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Project":
        return cls(
            name=data.get("name", ""),
            target=data.get("target", ""),
            output_dir=data.get("output_dir", ""),
            created=data.get("created", ""),
            description=data.get("description", ""),
            notes=data.get("notes", ""),
            version=data.get("version", 1),
        )

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)

    def get_run_dirs(self) -> List[Path]:
        """List run directories sorted newest-first.

        Uses the timestamp embedded in the directory name when available
        (deterministic), falls back to mtime for non-standard names.
        Excludes directories starting with '.' or '_' (internal/metadata dirs).
        """
        if not self.output_path.exists():
            return []
        from core.run.metadata import parse_timestamp_from_name

        def _sort_key(d: Path) -> str:
            ts = parse_timestamp_from_name(d.name)
            if ts:
                return ts
            # Fallback: convert mtime to ISO for consistent comparison
            return datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc).isoformat()

        dirs = [d for d in self.output_path.iterdir()
                if d.is_dir() and not d.name.startswith((".", "_"))]
        return sorted(dirs, key=_sort_key, reverse=True)

    def get_run_dirs_by_type(self) -> Dict[str, List[Path]]:
        """Group run directories by command type.

        Generates .raptor-run.json for any run directory that's missing it
        (JIT metadata for runs that predate the metadata system).
        """
        from core.run import infer_command_type, generate_run_metadata
        from core.run.metadata import RUN_METADATA_FILE
        groups: Dict[str, List[Path]] = {}
        for d in self.get_run_dirs():
            if not (d / RUN_METADATA_FILE).exists():
                generate_run_metadata(d)
            cmd_type = infer_command_type(d)
            groups.setdefault(cmd_type, []).append(d)
        return groups


class ProjectManager:
    """Manages project lifecycle."""

    def __init__(self, projects_dir: Path = None):
        self.projects_dir = projects_dir or PROJECTS_DIR
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    # Reserved names that cannot be used as project names
    RESERVED_NAMES = {"none"}

    # Project names must match: alphanumeric, hyphens, dots (not leading).
    # This prevents shell metacharacters, control characters, spaces, and
    # path separators from ever appearing in filenames or directory names.
    _NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')

    @classmethod
    def _validate_name(cls, name: str) -> None:
        """Validate project name is safe for use as a filename."""
        if not name or not name.strip():
            raise ValueError("Project name cannot be empty")
        if name.lower() in cls.RESERVED_NAMES:
            raise ValueError(f"Project name '{name}' is reserved")
        if len(name) > 100:
            raise ValueError(f"Project name too long (max 100 chars): {name}")
        if not cls._NAME_PATTERN.match(name):
            raise ValueError(
                f"Project name '{name}' contains invalid characters. "
                f"Use only letters, numbers, hyphens, dots, and underscores (cannot start with . or _)"
            )

    def create(self, name: str, target: str, description: str = "",
               output_dir: str = None, resolve_target: bool = True,
               created: str = None) -> Project:
        """Create a new project.

        Args:
            resolve_target: If True (default), resolve target to absolute path.
                Set to False for imports where the original path should be preserved.
            created: ISO timestamp override (for imports preserving original date).
        """
        self._validate_name(name)
        project_file = self.projects_dir / f"{name}.json"
        if project_file.exists():
            raise ValueError(f"Project '{name}' already exists")

        if not output_dir:
            output_dir = str((DEFAULT_OUTPUT_BASE / name).resolve())

        project = Project(
            name=name,
            target=str(Path(target).resolve()) if resolve_target else target,
            output_dir=output_dir,
            created=created or datetime.now(timezone.utc).isoformat(),
            description=description,
        )

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        save_json(project_file, project.to_dict())
        logger.info(f"Created project '{name}' → {output_dir}")
        return project

    def load(self, name: str) -> Optional[Project]:
        """Load a project by name. Returns None if not found or name invalid."""
        # Reject traversal attempts — load is called with user input
        project_file = (self.projects_dir / f"{name}.json").resolve()
        if not str(project_file).startswith(str(self.projects_dir.resolve()) + "/"):
            return None
        data = load_json(project_file)
        if data is None:
            return None
        return Project.from_dict(data)

    def list_projects(self) -> List[Project]:
        """List all projects."""
        projects = []
        for f in sorted(self.projects_dir.glob("*.json")):
            data = load_json(f)
            if data:
                projects.append(Project.from_dict(data))
        return projects

    def delete(self, name: str, purge: bool = False) -> None:
        """Delete a project. With purge=True, also delete the output directory."""
        project = self.load(name)
        if not project:
            raise ValueError(f"Project '{name}' not found")

        if purge and project.output_path.exists():
            # Safety: refuse to delete paths that could cause serious damage
            output = project.output_path.resolve()
            home = Path.home().resolve()
            if (output == home or output == Path("/")
                    or len(output.parts) < 3
                    or str(home).startswith(str(output) + "/")):
                raise ValueError(f"Refusing to delete suspicious path: {output}")
            shutil.rmtree(project.output_path)
            logger.info(f"Deleted output directory: {project.output_dir}")

        project_file = self.projects_dir / f"{name}.json"
        project_file.unlink(missing_ok=True)

        # Clear .active symlink if it pointed to this project
        active_link = self.projects_dir / ".active"
        if active_link.is_symlink() and os.readlink(active_link) == f"{name}.json":
            active_link.unlink()

        logger.info(f"Deleted project '{name}'")

    def rename(self, old_name: str, new_name: str) -> Project:
        """Rename a project."""
        self._validate_name(new_name)
        project = self.load(old_name)
        if not project:
            raise ValueError(f"Project '{old_name}' not found")

        new_file = self.projects_dir / f"{new_name}.json"
        if new_file.exists():
            raise ValueError(f"Project '{new_name}' already exists")

        # Update project
        project.name = new_name

        # Save new, delete old
        save_json(new_file, project.to_dict())
        old_file = self.projects_dir / f"{old_name}.json"
        old_file.unlink(missing_ok=True)

        # Update .active symlink if it pointed to the old name
        active_link = self.projects_dir / ".active"
        if active_link.is_symlink() and os.readlink(active_link) == f"{old_name}.json":
            self.set_active(new_name)

        logger.info(f"Renamed project '{old_name}' → '{new_name}'")
        return project

    def update_notes(self, name: str, notes: str) -> Project:
        """Update project notes."""
        project = self.load(name)
        if not project:
            raise ValueError(f"Project '{name}' not found")

        project.notes = notes
        save_json(self.projects_dir / f"{name}.json", project.to_dict())
        return project

    def update_description(self, name: str, description: str) -> Project:
        """Update project description."""
        project = self.load(name)
        if not project:
            raise ValueError(f"Project '{name}' not found")

        project.description = description
        save_json(self.projects_dir / f"{name}.json", project.to_dict())
        return project

    def add_directory(self, name: str, directory: str, target: str = None,
                      output_dir: str = None) -> int:
        """Add existing run directory (or directory of runs) to a project.

        If project doesn't exist and target is provided, creates it.
        Returns the number of runs added.
        """
        project = self.load(name)
        if not project:
            if not target:
                raise ValueError(f"Project '{name}' not found. Use --target to create it.")
            project = self.create(name, target, output_dir=output_dir)

        src = Path(directory).resolve()
        if not src.exists():
            raise ValueError(f"Directory not found: {directory}")

        from core.run import is_run_directory, generate_run_metadata

        added = 0
        skipped = 0
        dest_base = project.output_path

        if is_run_directory(src):
            # Single run directory
            dest = dest_base / src.name
            if dest.exists():
                skipped = 1
            else:
                shutil.move(str(src), str(dest))
                generate_run_metadata(dest)
                added = 1
        else:
            # Directory containing runs
            for child in sorted(src.iterdir()):
                if child.is_dir() and is_run_directory(child):
                    dest = dest_base / child.name
                    if dest.exists():
                        skipped += 1
                    else:
                        shutil.move(str(child), str(dest))
                        generate_run_metadata(dest)
                        added += 1

        if added:
            logger.info(f"Added {added} run(s) to project '{name}'")
        if skipped:
            logger.info(f"Skipped {skipped} run(s) already in project '{name}'")
        return added

    def remove_run(self, name: str, run_name: str, to_path: str = None) -> None:
        """Remove a run from the project directory.

        Moves the run to to_path. Does not delete.
        """
        project = self.load(name)
        if not project:
            raise ValueError(f"Project '{name}' not found")

        if not to_path:
            raise ValueError("--to is required: specify where to move the run")

        run_dir = project.output_path / run_name
        if not run_dir.exists():
            raise ValueError(f"Run '{run_name}' not found in project '{name}'")

        dest = Path(to_path)
        dest.mkdir(parents=True, exist_ok=True)
        shutil.move(str(run_dir), str(dest / run_name))
        logger.info(f"Moved '{run_name}' to {to_path}")

    def set_active(self, name: str = None) -> None:
        """Set the active project symlink and update CLAUDE_ENV_FILE.

        Pass None to clear.
        """
        active_link = self.projects_dir / ".active"
        if active_link.is_symlink() or active_link.exists():
            active_link.unlink()
        if name is not None:
            active_link.symlink_to(f"{name}.json")

        # Update CLAUDE_ENV_FILE so env vars stay in sync mid-session
        self._update_env_file(name)

    def get_active(self) -> Optional[str]:
        """Get the active project name from the .active symlink."""
        active_link = self.projects_dir / ".active"
        if active_link.is_symlink():
            target = os.readlink(active_link)
            if target.endswith(".json") and "/" not in target and "\\" not in target:
                project_file = self.projects_dir / target
                if project_file.exists():
                    return target[:-5]
                # Dangling — clean up
                active_link.unlink(missing_ok=True)
        return None

    def _update_env_file(self, name: str = None) -> None:
        """Update CLAUDE_ENV_FILE with project env vars.

        Writes project vars directly to the env file without modifying
        os.environ (the launcher manages process env vars).
        """
        env_file = os.environ.get("CLAUDE_ENV_FILE")
        if not env_file:
            return

        env_path = Path(env_file)
        try:
            existing = env_path.read_text() if env_path.exists() else ""
        except OSError:
            return

        lines = [l for l in existing.splitlines()
                 if not l.startswith("export RAPTOR_PROJECT_")]

        if name:
            project = self.load(name)
            if project:
                def _sh(v):
                    return v.replace('\\', '\\\\').replace('"', '\\"')
                lines.append(f'export RAPTOR_PROJECT_DIR="{_sh(project.output_dir)}"')
                lines.append(f'export RAPTOR_PROJECT_NAME="{_sh(project.name)}"')
                lines.append(f'export RAPTOR_PROJECT_TARGET="{_sh(project.target)}"')

        try:
            env_path.write_text("\n".join(lines) + "\n" if lines else "")
        except OSError:
            pass

    def find_project_for_target(self, target: str) -> Optional[Project]:
        """Auto-detect: find a project whose target matches the given path."""
        resolved = str(Path(target).resolve())
        for project in self.list_projects():
            if project.target == resolved:
                return project
        return None
