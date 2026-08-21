"""raptor-review resolves the active project from the registry.

Pre-fix ``_resolve_project_dir`` looked for a ``<repo-root>/.active``
path nothing creates (the real pointer is
``~/.raptor/projects/.active`` → ``<name>.json``), so without
``--project`` every project-level layer silently read as absent.
"""

from __future__ import annotations

import importlib.util
import json
import os
import types
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_cli():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = REPO_ROOT / "libexec" / "raptor-review"
    spec = importlib.util.spec_from_file_location(
        "raptor_review_cli", script, submodule_search_locations=[],
    )
    if spec is None:
        # Extensionless script — no default loader; exec it by hand.
        mod = types.ModuleType("raptor_review_cli")
        mod.__file__ = str(script)
        code = compile(script.read_text(), str(script), "exec")
        exec(code, mod.__dict__)
        return mod
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cli = _load_cli()


def test_explicit_project_wins(tmp_path):
    assert _cli._resolve_project_dir(str(tmp_path)) == tmp_path
    assert _cli._resolve_project_dir(str(tmp_path / "missing")) is None


def test_active_project_resolved_via_registry(tmp_path):
    proj_dir = tmp_path / "out" / "projects" / "myproj"
    proj_dir.mkdir(parents=True)
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "myproj.json").write_text(json.dumps(
        {"name": "myproj", "output_dir": str(proj_dir)},
    ))
    import core.startup
    with patch.object(core.startup, "PROJECTS_DIR", registry), \
         patch.object(core.startup, "get_active_name", lambda: "myproj"):
        assert _cli._resolve_project_dir(None) == proj_dir


def test_no_active_project_is_none(tmp_path):
    import core.startup
    with patch.object(core.startup, "PROJECTS_DIR", tmp_path), \
         patch.object(core.startup, "get_active_name", lambda: None):
        assert _cli._resolve_project_dir(None) is None
