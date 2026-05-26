"""End-to-end pipeline test: discover → parse → join.

Full mechanical-layer-minus-OSV smoke test. Builds a fixture
repo with manifest+lockfile pairs in two ecosystems (npm + Python),
adds a transitive-only dep that should *not* be promoted to direct,
and asserts the joined view is what every downstream consumer (OSV
matcher, SBOM emitter, hygiene checks) will see.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.discovery import find_manifests
from packages.sca.join import join
from packages.sca.parsers import parse_manifest


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_discover_parse_join_full_pipeline(tmp_path: Path) -> None:
    repo = tmp_path / "repo"

    # --- npm: manifest + lockfile in same dir + a transitive dep -------
    _write(repo / "frontend" / "package.json", json.dumps({
        "name": "frontend",
        "dependencies": {"lodash": "^4.17.21"},
    }))
    _write(repo / "frontend" / "package-lock.json", json.dumps({
        "name": "frontend",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "frontend",
                "dependencies": {"lodash": "^4.17.21"},
            },
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/ms": {"version": "2.1.3"},  # transitive
        },
    }))

    # --- Python: requirements.txt + Pipfile.lock, ancestor walk --------
    _write(repo / "backend" / "requirements.txt", "django==4.2.7\n")
    _write(repo / "backend" / "Pipfile.lock", json.dumps({
        "_meta": {},
        "default": {
            "django":  {"version": "==4.2.7"},
            "asgiref": {"version": "==3.7.2"},  # transitive
        },
        "develop": {},
    }))

    # ------------------------------------------------------------------
    manifests = find_manifests(repo)
    raw_deps = []
    for m in manifests:
        raw_deps.extend(parse_manifest(m))

    joined = join(raw_deps)

    # Index lockfile rows for assertion clarity.
    lock_rows = {(d.ecosystem, d.name): d for d in joined if d.is_lockfile}

    # npm: lodash declared → direct=True after join, ms transitive.
    assert lock_rows[("npm", "lodash")].direct is True
    assert lock_rows[("npm", "ms")].direct is False
    assert lock_rows[("npm", "lodash")].version == "4.17.21"

    # PyPI: django declared in requirements.txt → direct=True;
    # asgiref transitive-only stays direct=False.
    assert lock_rows[("PyPI", "django")].direct is True
    assert lock_rows[("PyPI", "asgiref")].direct is False
    assert lock_rows[("PyPI", "django")].version == "4.2.7"

    # Manifest rows pass through unchanged.
    manifest_rows = {(d.ecosystem, d.name): d for d in joined
                     if not d.is_lockfile}
    assert manifest_rows[("npm", "lodash")].pin_style.value == "caret"
    assert manifest_rows[("PyPI", "django")].pin_style.value == "exact"
