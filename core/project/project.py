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

    def _list_run_dirs(self) -> List[Path]:
        """List run directories (unsorted). Shared by get_run_dirs and sweep."""
        if not self.output_path.exists():
            return []
        generated_dirs = {"findings"}
        return [d for d in self.output_path.iterdir()
                if d.is_dir()
                and not d.name.startswith((".", "_"))
                and d.name not in generated_dirs]

    def get_run_dirs(self, sweep=False) -> List[Path]:
        """List run directories sorted newest-first.

        Uses the timestamp embedded in the directory name when available
        (deterministic), falls back to mtime for non-standard names.
        When sweep=True, marks stale 'running' dirs as failed.
        Inside Claude Code (CLAUDECODE=1), keeps the newest running dir
        (may be active). Outside Claude Code, sweeps all.
        Default is sweep=False to avoid damaging active runs from read-only
        commands (status, findings, coverage).
        """
        from core.run.metadata import parse_timestamp_from_name

        def _sort_key(d: Path) -> str:
            ts = parse_timestamp_from_name(d.name)
            if ts:
                return ts
            return datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc).isoformat()

        dirs = self._list_run_dirs()
        if sweep:
            in_session = bool(os.environ.get("CLAUDECODE"))
            self._sweep_stale(dirs, keep_latest=in_session)
        return sorted(dirs, key=_sort_key, reverse=True)

    def sweep_stale_runs(self, keep_latest=False) -> int:
        """Mark stale 'running' run dirs as failed.

        Args:
            keep_latest: if True, skip the most recent 'running' dir
                         (it may be actively running this session).
                         False at startup (nothing is running).

        Returns count of dirs marked failed.
        """
        return self._sweep_stale(self._list_run_dirs(), keep_latest)

    def _sweep_stale(self, dirs: list, keep_latest=False) -> int:
        """Mark 'running' dirs as failed if their session is dead.

        Checks session_pid in metadata — if the PID is still alive, the
        session that started the run is still running and will clean up
        its own runs. Only sweeps runs whose session has died.

        Args:
            keep_latest: if True, skip the most recent 'running' dir even
                         if its session is dead (legacy fallback for runs
                         without session_pid).
        """
        from core.run.metadata import RUN_METADATA_FILE, fail_run, _pid_alive
        from core.json import load_json

        # Find all running dirs with their timestamps and PIDs
        running = []
        for d in dirs:
            meta_file = d / RUN_METADATA_FILE
            if not meta_file.exists():
                continue
            meta = load_json(meta_file)
            if meta and meta.get("status") == "running":
                running.append((meta.get("timestamp", ""), d, meta.get("session_pid")))

        if not running:
            return 0

        swept = 0
        # Sort newest first for keep_latest
        running.sort(reverse=True)

        for i, (ts, d, pid) in enumerate(running):
            # If session_pid is recorded and alive, skip — session will clean up
            if pid is not None and _pid_alive(pid):
                continue
            # No PID (legacy run) — use keep_latest heuristic
            if pid is None and keep_latest and i == 0:
                continue
            fail_run(d, "stale — session ended without completion",
                     record_timing=False)
            swept += 1

        return swept

    def get_run_dirs_by_type(self) -> Dict[str, List[Path]]:
        """Group run directories by command type.

        Generates .raptor-run.json for any run directory that's missing it
        (JIT metadata for runs that predate the metadata system).
        """
        from core.run import infer_command_type, generate_run_metadata
        from core.run.metadata import RUN_METADATA_FILE
        groups: Dict[str, List[Path]] = {}
        for d in self.get_run_dirs(sweep=False):
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

        # `add_runs` is the user-facing import path — operators
        # explicitly bring in directories that may not have
        # `.raptor-run.json` yet (legacy runs, manually-copied
        # subsets). `generate_run_metadata` below backfills it.
        # Pass `strict=False` so the lenient match still admits
        # those legacy shapes; the import is gated by an explicit
        # operator action so the over-match risk is acceptable here
        # (unlike sweep / cleanup paths which run automatically).
        if is_run_directory(src, strict=False):
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
                if child.is_dir() and is_run_directory(child, strict=False):
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
        """Set the active project symlink. Pass None to clear.

        The symlink is the single source of truth for project state.
        Uses atomic create-temp-then-rename to avoid TOCTOU races.
        """
        import os
        active_link = self.projects_dir / ".active"
        auto_marker = self.projects_dir / ".auto"
        auto_marker.unlink(missing_ok=True)
        if name is not None:
            # Atomic swap: create temp symlink then rename over the active link
            tmp_link = self.projects_dir / ".active.tmp"
            tmp_link.unlink(missing_ok=True)
            tmp_link.symlink_to(f"{name}.json")
            os.rename(str(tmp_link), str(active_link))
        else:
            active_link.unlink(missing_ok=True)

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

    def find_project_for_target(self, target: str) -> Optional[Project]:
        """Auto-detect: find a project whose target matches the given path."""
        resolved = str(Path(target).resolve())
        for project in self.list_projects():
            if project.target == resolved:
                return project
        return None
