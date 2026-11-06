"""Skip only invariant steps whose complete input families are unchanged."""

from __future__ import annotations

import json
import os
from pathlib import Path

import check_env_docs as env_docs
from ci_change_scope import changed_paths
import runtime_universe as runtime


def plan(repo: Path, changed: list[str] | None) -> dict[str, bool]:
    full = {"env_docs_run": True, "redos_run": True}
    if changed is None:
        return full
    env_run = redos_run = False
    env_roots = {*env_docs.PY_ROOTS, *env_docs.BASH_ROOTS}
    excluded = runtime.EXCLUDED_PARTS | {runtime.DEV_SCRIPTS_PART}
    for name in changed:
        path = Path(name)
        # Missing/renamed inputs, discovery changes and execution metadata
        # cannot establish irrelevance. Unknown steps also default to running.
        try:
            if (path.is_absolute() or ".." in path.parts or name != path.as_posix()
                    or not (repo / path).is_file()):
                return full
        except OSError:
            return full
        parts = path.parts
        if (parts[0] == ".github" or path.name == "conftest.py"
                or path.name in {"pyproject.toml", "uv.lock", "uv.toml", "pytest.ini",
                                 ".python-version", ".gitignore", ".gitattributes", ".gitmodules"}
                or path.name.startswith("requirements")):
            return full
        root_python = len(parts) == 1 and path.suffix == ".py"
        env_run |= (
            root_python
            or name in {"docs/environment.md", "core/llm/model_brokers/registry.json"}
            or (any(path.is_relative_to(root) for root in env_roots) and (not path.suffix or env_docs.source_kind(repo / path) is not None))
        )
        # Shared pytest infrastructure can affect execution even though it
        # is outside the runtime census. Derive roots/exclusions from its
        # actual walker; do not grow another independent runtime-root list.
        redos_run |= (
            root_python or parts[:2] == ("core", "testing")
            or (any(path.is_relative_to(root) for root in runtime.RUNTIME_ROOTS)
                and not runtime._is_excluded(parts, excluded))
        )
    return {"env_docs_run": env_run, "redos_run": redos_run}


def main() -> int:
    repo = Path.cwd()
    changes = (changed_paths(repo, os.environ.get("BASE_SHA", ""))
               if os.environ.get("EVENT") in {"pull_request", "push", "merge_group"}
               else None)
    result = plan(repo, changes)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for name, run in result.items():
            output.write(f"{name}={str(run).lower()}\n")
    print(json.dumps({"changes_known": changes is not None, **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
