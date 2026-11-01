"""Read-only CodeQL distribution paths for sandboxed CLI execution."""
from pathlib import Path


def codeql_tool_paths(executable: str | None) -> list[str]:
    if not executable:
        return []
    root = Path(executable).resolve().parent
    from core.sandbox.python_paths import _home_roots
    if any(root == home or root in home.parents for home in _home_roots()):
        raise ValueError('CodeQL needs a dedicated installation directory; refusing to expose HOME or its ancestors')
    return [str(root)]
