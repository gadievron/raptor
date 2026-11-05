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

from typing import Any

# Session/scratch metadata imports this package during every helper startup.
# Resolve the heavier project-management API only when it is requested.
# Reloading the package must refresh aliases just as eager re-exports did.
for _cached_export in globals().get("_LAZY_EXPORTS", ()):
    globals().pop(_cached_export, None)
globals().pop("_cached_export", None)

_LAZY_EXPORTS = {
    "project": ("core.project.project", None),
    "clean": ("core.project.clean", None),
    "report": ("core.project.report", None),
    "Project": ("core.project.project", "Project"),
    "ProjectManager": ("core.project.project", "ProjectManager"),
    "is_project_output_dir": ("core.project.project", "is_project_output_dir"),
    "clean_project": ("core.project.clean", "clean_project"),
    "plan_clean": ("core.project.clean", "plan_clean"),
    "execute_clean": ("core.project.clean", "execute_clean"),
    "generate_project_report": ("core.project.report", "generate_project_report"),
}


def __getattr__(name: str) -> Any:
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module_name, attribute = spec
    module = import_module(module_name)
    value = module if attribute is None else getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))

__all__ = [
    "Project",
    "ProjectManager",
    "clean_project",
    "execute_clean",
    "generate_project_report",
    "is_project_output_dir",
    "plan_clean",
]
