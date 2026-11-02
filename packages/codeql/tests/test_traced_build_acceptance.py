"""Opt-in real CodeQL traced build using a disposable, dependency-free fixture."""
import json
import os
from pathlib import Path
import shlex
import shutil
import sys

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow,
              pytest.mark.skipif(os.environ.get('RAPTOR_CODEQL_FLOOR_ACCEPTANCE') != '1',
                                 reason='opt-in real CodeQL traced-build acceptance')]


def test_real_traced_build_confines_repo_home_and_runtime(tmp_path, monkeypatch):
    import core.sandbox
    from core.build.build_detector import BuildSystem
    from core.config import RaptorConfig
    from packages.codeql.database_manager import DatabaseManager
    from packages.codeql.tunables import CodeQLTunables

    assert sys.platform in ('linux', 'darwin'), 'Linux or macOS required'
    executable = shutil.which('codeql')
    compiler = '/usr/bin/cc' if Path('/usr/bin/cc').is_file() else shutil.which('cc')
    assert not executable or Path(os.path.realpath(executable)).name != 'raptor-codeql-bootstrap', (
        'install CodeQL before native acceptance; this test never downloads dependencies')
    assert executable and compiler, 'installed CodeQL and C compiler required'
    monkeypatch.setattr(RaptorConfig, 'CODEQL_TIMEOUT', 180)
    monkeypatch.setattr(CodeQLTunables, 'from_tuning',
                        lambda **kwargs: CodeQLTunables(threads=1, ram_mb=2048, max_disk_cache_mb=64))
    repo = tmp_path/'source'
    outside = tmp_path/'operator-private'
    repo.mkdir()
    outside.mkdir()
    canary = outside/'credentials'
    canary.write_text('disposable data, never real credentials')
    forbidden = outside/'forbidden'
    (repo/'main.c').write_text('int main(void){return 0;}\n')
    proof = repo/'build-proof.json'
    build = repo/'build.py'
    build.write_text('import json, os, pathlib, subprocess, sys\n'
        'try: pathlib.Path('+repr(str(canary))+').read_bytes()\n'
        'except OSError: pass\nelse: raise AssertionError("outside read succeeded")\n'
        'try: pathlib.Path('+repr(str(forbidden))+').write_text("bad")\n'
        'except OSError: pass\nelse: raise AssertionError("outside write succeeded")\n'
        'home=pathlib.Path(os.environ["HOME"])\n'
        'if sys.platform == "linux": assert home == pathlib.Path("/tmp/.home"), home\n'
        'else: assert home.is_relative_to(pathlib.Path('+repr(str(tmp_path/'databases'))+')), home\n'
        '(home/"cache-proof").write_text("cache works")\n'
        'assert (home/"cache-proof").read_text() == "cache works"\n'
        'subprocess.run('+repr([compiler, '-o', str(repo/'fixture'), str(repo/'main.c')])+', check=True)\n'
        'pathlib.Path('+repr(str(proof))+').write_text(json.dumps({"home":str(home),"tmpdir":os.environ.get("TMPDIR"),"home_cache_verified":True}))\n')
    manager = DatabaseManager(db_root=tmp_path/'databases', codeql_cli=executable)
    # A failed traced fixture must be a failure, never a successful buildless
    # retry that would hide an unreachable compiler or denied build writes.
    monkeypatch.setattr(manager, '_buildless_fallback', lambda *args, **kwargs: None)
    original = core.sandbox.run
    replies = []
    def observe(command, **kwargs):
        reply = original(command, **kwargs)
        if 'database' in command and 'create' in command:
            replies.append(reply)
            (tmp_path/'codeql.stdout.log').write_text(reply.stdout or '')
            (tmp_path/'codeql.stderr.log').write_text(reply.stderr or '')
        return reply
    monkeypatch.setattr(core.sandbox, 'run', observe)
    system = BuildSystem(type='make', command=shlex.join([sys.executable, '-I', '-S', str(build)]),
                         working_dir=repo, env_vars={}, confidence=1.0, detected_files=[])
    result = manager.create_database(repo, 'cpp', system, traced_build=True)
    assert result.success, result.errors
    assert len(replies) == 1
    info = replies[0].sandbox_info
    required = 'mount-ns' if sys.platform == 'linux' else 'seatbelt'
    assert info['containment_tier'] == required, info
    assert info['containment_floor'] == required, info
    assert result.metadata.build_system != 'buildless'
    assert (repo/'fixture').is_file()
    record = json.loads(proof.read_text())
    home = Path(record['home'])
    # Linux HOME lives in the private namespace tmpfs. Its path cannot
    # be dereferenced by the parent after the sandbox exits; the fixture
    # verifies cache I/O inside the same namespace that performed the build.
    if sys.platform == 'linux':
        assert home == Path('/tmp/.home')
    else:
        assert home.is_relative_to(manager.db_root)
    assert record['home_cache_verified'] is True
    assert canary.read_text() == 'disposable data, never real credentials'
    assert not forbidden.exists()
