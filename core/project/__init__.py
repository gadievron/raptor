"""Project infrastructure — named workspaces for RAPTOR analysis runs.

A project is a named parent directory for run output. Commands create
timestamped subdirectories within it. The project corrals related runs
so results accumulate instead of scattering across separate output dirs.

Public API:
    from core.project import Project, ProjectManager
    from core.project import is_project_output_dir
    from core.project import clean_project, plan_clean, execute_clean
    from core.project import generate_project_report
"""

from .project import Project, ProjectManager, is_project_output_dir
from .clean import clean_project, plan_clean, execute_clean
from .report import generate_project_report

__all__ = [
    "Project",
    "ProjectManager",
    "clean_project",
    "execute_clean",
    "generate_project_report",
    "is_project_output_dir",
    "plan_clean",
]
