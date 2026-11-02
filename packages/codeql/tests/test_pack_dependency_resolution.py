"""Native sandbox regression for bundled workspace dependency discovery."""
import json
from pathlib import Path
import shlex
import shutil
import sys

import pytest

from core.sandbox import run
from packages.codeql.query_runner import QueryRunner
from packages.codeql.temp_env import temporary_command
from packages.codeql.tool_paths import codeql_tool_paths


@pytest.mark.integration
@pytest.mark.parametrize("language", ["cpp", "java"])
def test_bundled_workspace_resolves_transitive_dependencies(tmp_path, monkeypatch, language):
    native = shutil.which("codeql")
    if not native:
        pytest.skip("CodeQL CLI required")
    if sys.platform != "linux":
        pytest.skip("Linux sandbox regression")
    native = str(Path(native).resolve())
    install = tmp_path / "distribution with spaces" / "codeql"
    install.mkdir(parents=True)
    wrapper = install / "codeql"
    wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(native)} "$@"\n')
    wrapper.chmod(0o755)
    workspace = install.parent / "codeql-queries"
    library = workspace / language / "ql" / "lib"
    library.mkdir(parents=True)
    shared = workspace / "shared" / "common"
    shared.mkdir(parents=True)
    (workspace / "codeql-workspace.yml").write_text(
        f"provide:\n  - {language}/ql/lib/qlpack.yml\n  - shared/common/qlpack.yml\n")
    (library / "qlpack.yml").write_text(
        f'name: codeql/{language}-all\nversion: 0.0.1\nlibrary: true\n'
        'dbscheme: test.dbscheme\ndependencies:\n  raptor-tests/shared: ${workspace}\n')
    (library / "test.dbscheme").write_text("// Resolver-only fixture.\n")
    (shared / "qlpack.yml").write_text("name: raptor-tests/shared\nversion: 0.0.1\nlibrary: true\n")
    pack = tmp_path / "consumer"
    pack.mkdir()
    (pack / "qlpack.yml").write_text(
        f'name: raptor-tests/consumer\nversion: 0.0.1\ndependencies:\n  codeql/{language}-all: "*"\n')
    query = pack / "Example.ql"
    query.write_text("select 1\n")
    output = tmp_path / "output"
    database = tmp_path / "database"
    home = tmp_path / "home"
    for path in (output, database, home):
        path.mkdir()
    # Isolate discovery from the operator's cache and CLI override. The real
    # resolver uses --common-caches below; Python's pack discovery uses home().
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("CODEQL_QUERIES", raising=False)
    monkeypatch.setenv("CODEQL_CLI", "/not-the-selected-distribution/codeql")
    runner = QueryRunner.__new__(QueryRunner)
    runner.codeql_cli = str(wrapper)
    base = [str(wrapper), "resolve", "library-path", f"--query={query}",
            f"--common-caches={output / 'cache'}", "--format=json"]

    def resolve(command):
        scope = runner._analysis_scope(command, database, output, pack)
        # The fixture launcher delegates execution to the real installed CLI.
        # Grant that executable's runtime, without exposing its sibling packs.
        scope["tool_paths"].extend(codeql_tool_paths(native))
        assert str(workspace) in scope["readable_paths"]
        assert str(install.parent) not in scope["readable_paths"]
        assert str(home) not in scope["writable_paths"]
        return run(temporary_command(command, scoped=True), block_network=True,
                   **scope, capture_output=True, text=True, timeout=60)

    before = resolve(base)
    assert before.returncode != 0
    assert f"codeql/{language}-all" in before.stderr
    roots = runner._local_dependency_roots(language, query)
    after = resolve(base + [f"--additional-packs={root}" for root in roots])
    assert after.returncode == 0, after.stderr
    paths = json.loads(after.stdout)["libraryPath"]
    assert str(library) in paths
    assert str(shared) in paths
    assert not (pack / "codeql-pack.lock.yml").exists()

    # A cached published pack and a lockfile must win over the available
    # source workspace, including when network access is forbidden.
    cached = output / "cache" / "packages" / "codeql" / f"{language}-all" / "0.0.2"
    cached.mkdir(parents=True)
    (cached / "qlpack.yml").write_text(
        f"name: codeql/{language}-all\nversion: 0.0.2\nlibrary: true\ndbscheme: test.dbscheme\n")
    (cached / "test.dbscheme").write_text("// Pinned published resolver fixture.\n")
    (pack / "qlpack.yml").write_text(
        f"name: raptor-tests/consumer\nversion: 0.0.1\ndependencies:\n  codeql/{language}-all: 0.0.2\n")
    lock = pack / "codeql-pack.lock.yml"
    lock.write_text(f"lockVersion: 1.0.0\ndependencies:\n  codeql/{language}-all:\n    version: 0.0.2\n")
    original_lock = lock.read_bytes()
    assert runner._local_dependency_roots(language, query) == []
    pinned = resolve(base)
    assert pinned.returncode == 0, pinned.stderr
    pinned_paths = json.loads(pinned.stdout)["libraryPath"]
    assert str(cached) in pinned_paths
    assert str(library) not in pinned_paths
    assert lock.read_bytes() == original_lock
    shutil.rmtree(cached)
    missing = resolve(base)
    assert missing.returncode != 0
    assert f"codeql/{language}-all" in missing.stderr
    assert lock.read_bytes() == original_lock
