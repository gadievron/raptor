"""End-to-end smoke: ``find_manifests`` → ``parse_manifest`` → list[Dependency].

Builds a fixture repo with four common manifest types (plus a vendored
node_modules tree that must be skipped), runs discovery, dispatches each
discovered manifest through the parser registry, and asserts the merged
dependency set matches what the fixtures declare.

This exists to catch wiring breaks between discovery and parsers — a
parser that registers under the wrong filename, or a discovery rule that
fails to surface a manifest, fails this test before it reaches operators.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.discovery import find_manifests
from packages.sca.parsers import parse_manifest


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_full_pipeline_across_four_ecosystems(tmp_path: Path) -> None:
    repo = tmp_path / "repo"

    # 1. Maven POM
    _write(repo / "service" / "pom.xml", """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>svc</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""")

    # 2. npm package.json
    _write(repo / "frontend" / "package.json", json.dumps({
        "name": "frontend",
        "dependencies":     {"lodash": "^4.17.21"},
        "devDependencies":  {"jest": "~29.0.0"},
    }))

    # 3. Python requirements (with -r include)
    _write(repo / "tools" / "requirements.txt", "-r base.txt\nrequests==2.31.0\n")
    _write(repo / "tools" / "base.txt", "django==4.2.7\n")

    # 4. Python pyproject.toml (PEP 621 + Poetry tool table)
    _write(repo / "lib" / "pyproject.toml", """\
[project]
name = "lib"
dependencies = ["click==8.1.7"]

[tool.poetry.dependencies]
python = "^3.10"
rich = "^13.7"
""")

    # 5. Vendored node_modules — must be skipped by discovery.
    _write(repo / "frontend" / "node_modules" / "evil" / "package.json",
           json.dumps({"dependencies": {"should-not-appear": "1.0.0"}}))

    # ------------------------------------------------------------------
    manifests = find_manifests(repo)
    discovered_paths = {str(m.path.relative_to(repo)) for m in manifests}
    # ``base.txt`` is intentionally absent: the requirements parser
    # recurses into it via ``-r``; discovery only surfaces top-level
    # files matching ``requirements*.txt``.
    assert discovered_paths == {
        "service/pom.xml",
        "frontend/package.json",
        "tools/requirements.txt",
        "lib/pyproject.toml",
    }

    all_deps = []
    for m in manifests:
        all_deps.extend(parse_manifest(m))

    by_key = {(d.ecosystem, d.name): d for d in all_deps}

    # Maven
    assert ("Maven", "org.apache.logging.log4j:log4j-core") in by_key
    assert by_key[("Maven", "org.apache.logging.log4j:log4j-core")].version == "2.14.1"

    # npm — both production and dev deps surfaced
    assert by_key[("npm", "lodash")].version == "4.17.21"
    assert by_key[("npm", "jest")].scope == "dev"

    # Python — requirements + recursive include + pyproject
    assert by_key[("PyPI", "django")].version == "4.2.7"
    assert by_key[("PyPI", "requests")].version == "2.31.0"
    assert by_key[("PyPI", "click")].version == "8.1.7"
    assert by_key[("PyPI", "rich")].pin_style.value == "caret"

    # Hostile sentinel never made it through.
    assert ("npm", "should-not-appear") not in by_key
