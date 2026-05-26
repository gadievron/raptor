"""End-to-end smoke: discover + parse all six lockfile formats together.

Verifies discovery surfaces every supported lockfile, the dispatcher routes
each to its parser, and the merged dependency stream marks every row with
``is_lockfile=True``. Also catches obvious wiring breaks (e.g., a parser
registered under the wrong filename).
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.discovery import find_manifests
from packages.sca.parsers import parse_manifest


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_full_pipeline_across_six_lockfiles(tmp_path: Path) -> None:
    repo = tmp_path / "repo"

    # Maven — gradle.lockfile
    _write(repo / "service" / "gradle.lockfile", """\
# generated
ch.qos.logback:logback-classic:1.4.11=runtimeClasspath
junit:junit:4.13.2=testRuntimeClasspath
empty=annotationProcessor
""")

    # npm — package-lock.json (v3)
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
        },
    }))

    # npm — yarn.lock (classic)
    _write(repo / "yarn-app" / "yarn.lock", """\
# yarn lockfile v1

react@^18.0.0:
  version "18.2.0"
  resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz#abc"
""")

    # npm — pnpm-lock.yaml (v6)
    _write(repo / "pnpm-app" / "pnpm-lock.yaml", """\
lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      vite:
        specifier: ^5.0
        version: 5.0.0
packages:
  /vite@5.0.0:
    resolution: {integrity: sha512-x}
""")

    # PyPI — Pipfile.lock
    _write(repo / "pipenv-app" / "Pipfile.lock", json.dumps({
        "_meta": {},
        "default": {"django": {"version": "==4.2.7"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    }))

    # PyPI — poetry.lock
    _write(repo / "poetry-app" / "poetry.lock", """\
[[package]]
name = "rich"
version = "13.7.0"
optional = false
""")

    manifests = find_manifests(repo)
    discovered = {m.path.name for m in manifests}
    assert discovered == {
        "gradle.lockfile",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Pipfile.lock",
        "poetry.lock",
    }
    # Every discovered file is correctly flagged as a lockfile.
    assert all(m.is_lockfile for m in manifests)

    all_deps = []
    for m in manifests:
        all_deps.extend(parse_manifest(m))

    # Every emitted row carries is_lockfile=True.
    assert all_deps and all(d.is_lockfile for d in all_deps)

    by_name = {(d.ecosystem, d.name): d for d in all_deps}

    # Spot-check one dep per ecosystem made it through the pipeline.
    assert ("Maven", "ch.qos.logback:logback-classic") in by_name
    assert by_name[("Maven", "ch.qos.logback:logback-classic")].version == "1.4.11"
    assert ("Maven", "junit:junit") in by_name
    assert by_name[("Maven", "junit:junit")].scope == "test"
    assert by_name[("npm", "lodash")].version == "4.17.21"
    assert by_name[("npm", "lodash")].direct is True
    assert by_name[("npm", "react")].version == "18.2.0"
    assert by_name[("npm", "vite")].version == "5.0.0"
    assert by_name[("PyPI", "django")].version == "4.2.7"
    assert by_name[("PyPI", "pytest")].scope == "dev"
    assert by_name[("PyPI", "rich")].version == "13.7.0"
