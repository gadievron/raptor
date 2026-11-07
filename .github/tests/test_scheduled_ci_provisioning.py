"""Scheduled runners reuse exact project envs and fingerprint standalone tools."""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import textwrap
import venv
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
PIN = '.github/scripts/semgrep-cli.txt'
CONSUMERS = [
    ('nightly-self-test.yml', 'self-test'),
    ('nightly.yml', 'slow-integration'),
    ('nightly.yml', 'semgrep-regressions'),
]


def job(file, name):
    source = (ROOT / '.github/workflows' / file).read_text().split('\njobs:\n', 1)[1]
    match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:|\Z)',
                      source, re.M | re.S)
    assert match is not None
    return match[1]


def steps(source):
    return re.split(r'^      - ', source, flags=re.M)[1:]


def named_step(source, name):
    matches = [body for body in steps(source) if body.splitlines()[0] == f'name: {name}']
    assert len(matches) == 1, f'expected one {name} step'
    return matches[0]


def script(body):
    run = re.search(r'^        run: \|\n((?:          .*\n|\n)+)', body, re.M)
    if run:
        return textwrap.dedent(run[1])
    run = re.search(r'^        run: (.+)$', body, re.M)
    assert run is not None
    return run[1]


def test_semgrep_pin_has_one_exact_version():
    assert re.fullmatch(r'semgrep==[0-9]+\.[0-9]+\.[0-9]+\n', (ROOT / PIN).read_text())


def test_all_semgrep_installers_use_the_pin_and_include_it_in_download_cache_inputs():
    owners = set()
    for path in (ROOT / '.github/workflows').glob('*.y*ml'):
        source = path.read_text().split('\njobs:\n', 1)[1]
        for match in re.finditer(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)', source, re.M | re.S):
            body = match[2]
            installers = [step for step in steps(body) if 'uv tool install' in step and 'semgrep' in step]
            if not installers:
                continue
            owners.add((path.name, match[1]))
            assert len(installers) == 1
            assert f'"$(cat {PIN})"' in script(installers[0])
            assert not re.search(r'semgrep==[0-9]', script(installers[0]))
            uv = named_step(body, 'Install uv')
            assert {'uv.lock', 'pyproject.toml', 'uv.toml', PIN} <= set(
                re.findall(r'^            (\S+)$', uv, re.M))
    assert owners == set(CONSUMERS)


@pytest.mark.parametrize('file,name', [
    ('nightly-self-test.yml', 'self-test'), ('ubuntu26-canary.yml', 'sandbox-canary'),
    ('weekly_corpus.yml', 'corpus-drivers'), ('preflight.yml', 'preflight'),
])
def test_scheduled_jobs_use_shared_exact_venv_and_save_successful_rebuilds(file, name):
    source = job(file, name)
    restore = named_step(source, 'Restore or rebuild venv')
    assert '        uses: ./.github/actions/setup-venv\n' in restore
    assert "          save-on-rebuild: 'true'\n" in restore
    assert 'uv-export-extra-args' not in restore  # Same base/dev dependency selection.
    assert 'cache-key-prefix' not in restore  # Base environment, with method in its key.
    if file in {'preflight.yml', 'weekly_corpus.yml'}:
        assert '          install-method: sync\n' in restore
    assert 'uv venv' not in source
    assert 'uv sync' not in source
    assert source.index('actions/setup-python@') < source.index('uses: ./.github/actions/setup-venv')


def test_canary_still_probes_and_asserts_the_real_host_before_cache_restore():
    source = job('ubuntu26-canary.yml', 'sandbox-canary')
    assert '    runs-on: ubuntu-26.04\n' in source
    names = [body.splitlines()[0] for body in steps(source)]
    restore = names.index('name: Restore or rebuild venv')
    for name in ['Probe kernel features (stock image)', 'Enable unprivileged user namespaces',
                 'Probe kernel features (userns enabled)', 'Assert the ubuntu-24.04 capability baseline holds']:
        assert names.index('name: ' + name) < restore
    assert 'python -m pytest core/sandbox' in script(named_step(source, 'Run sandbox fast tier'))


def test_selftest_still_runs_the_full_tier_zero_and_refuses_missing_toolchains():
    source = job('nightly-self-test.yml', 'self-test')
    run = script(named_step(source, 'Run self-test (tier 0)'))
    assert 'python libexec/raptor-self-test' in run and '--timeout 600' in run
    refuse = named_step(source, 'Refuse a toolchain-less self-test nightly')
    assert 'if: ${{ !cancelled() }}' in refuse
    assert 'command -v r2' in script(refuse) and 'command -v gcc' in script(refuse)


@pytest.mark.parametrize('file,name', CONSUMERS)
def test_real_semgrep_install_shell_uses_the_setup_python_and_exact_pin(tmp_path, file, name):
    source = job(file, name)
    installer = next(body for body in steps(source) if 'uv tool install' in body and 'semgrep' in body)
    command = script(installer)
    assert 'source ' not in command, 'standalone tools must not bind to the project venv'
    pin = tmp_path / PIN
    pin.parent.mkdir(parents=True)
    pin.write_bytes((ROOT / PIN).read_bytes())
    tools = tmp_path / 'tools with spaces'
    tools.mkdir()
    (tools / 'python3').symlink_to(sys.executable)
    record = tmp_path / 'uv-argv.json'
    uv = tools / 'uv'
    uv.write_text(f'#!{sys.executable}\nimport json,os,pathlib,sys\npathlib.Path(os.environ["UV_RECORD"]).write_text(json.dumps(sys.argv[1:]))\n')
    uv.chmod(0o755)
    semgrep = tools / 'semgrep'
    semgrep.write_text('#!/bin/sh\nexit 0\n')
    semgrep.chmod(0o755)
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', command],
        cwd=tmp_path, env=dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin', UV_RECORD=str(record)),
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(record.read_text()) == [
        'tool', 'install', '--python', str(tools / 'python3'), pin.read_text().strip(),
    ]


def test_tool_pin_changes_have_a_ci_lint_owner():
    with patch.object(sys, 'path', [str(ROOT / '.github/scripts'), *sys.path]):
        from test_scope import TIERS, file_in_dir
    assert any(file_in_dir(Path(PIN), owner) for owner in TIERS['ci_lint']['extra_triggers'])


def test_shuffled_nightly_reuses_grammar_profile_and_keeps_order_coverage():
    source = job('nightly_shuffled.yml', 'shuffled-fast')
    restore = named_step(source, 'Restore or rebuild venv (with grammars)')
    assert '        uses: ./.github/actions/setup-venv\n' in restore
    assert '          cache-key-prefix: venv-grammars\n' in restore
    assert '          install-method: sync\n' in restore
    assert '          uv-export-extra-args: --extra grammars\n' in restore
    assert "          save-on-rebuild: 'true'\n" in restore
    assert 'uv sync' not in source
    assert '        iteration: [1, 2, 3]\n' in source
    run = script(named_step(source, 'Shuffled default-tier tests (seed ${{ matrix.iteration }})'))
    assert 'seed="${{ github.run_id }}-${{ matrix.iteration }}"' in run
    assert 'RAPTOR_RANDOMISE_TESTS="$seed"' in run
    assert 'python -m pytest core packages engine' in run
    assert '-n auto --dist loadfile --no-loadscope-reorder' in run
    budget = script(named_step(source, 'Check default-tier skip count against its recorded budget'))
    assert '--lane nightly-default --full' in budget
    # Keep grammar extras aligned; install methods remain separately keyed.
    other = named_step(job('nightly.yml', 'intentional-crashes'), 'Restore or rebuild venv')
    assert 'cache-key-prefix: venv-grammars' in other
    assert 'uv-export-extra-args: --extra grammars' in other


def test_corpus_job_keeps_real_drivers_and_toolchain_skip_refusal():
    source = job('weekly_corpus.yml', 'corpus-drivers')
    run = script(named_step(source, 'Run corpus-scale drivers'))
    assert 'python -m pytest -m corpus core packages engine' in run
    assert '--junitxml="$RUNNER_TEMP/corpus-results.xml"' in run
    assert 'rustup component add llvm-tools' in script(named_step(source, 'Install Rust llvm-tools (profraw format match)'))
    refuse = script(named_step(source, 'Refuse an all-skipped measurement run'))
    assert 'executed = tests - skipped' in refuse
    assert 'if executed == 0:' in refuse and 'sys.exit(1)' in refuse


@pytest.mark.parametrize('file,name', [
    ('nightly_shuffled.yml', 'shuffled-fast'), ('weekly_corpus.yml', 'corpus-drivers'),
    ('ubuntu26-canary.yml', 'sandbox-canary'), ('preflight.yml', 'preflight'),
    ('nightly.yml', 'intentional-crashes'), ('mypy-nightly.yml', 'mypy'),
])
def test_warm_venv_callers_do_not_restore_an_unused_uv_download_cache(file, name):
    source = job(file, name)
    assert 'astral-sh/setup-uv@' not in source
    assert 'uv sync' not in source
    assert 'uv run' not in source
    assert 'uses: ./.github/actions/setup-venv' in source


def test_preflight_activates_cached_environment_before_all_hazard_checks():
    source = job('preflight.yml', 'preflight')
    text = (ROOT / '.github/workflows/preflight.yml').read_text()
    assert '  VENV_PATH: .venv\n' in text
    run = script(named_step(source, 'Run changed tests under simulation'))
    activate = 'source "$VENV_PATH/bin/activate"'
    assert activate in run
    assert run.index(activate) < run.index('hide_modules.py')
    assert 'python .github/scripts/preflight_scope.py' in run
    assert '--base "$BASE_SHA" --repo . --run' in run
    assert 'if [ "$rc" -eq 5 ]; then exit 0; fi' in run
    assert 'hidden-optional-deps' in source and 'hidden-tree-sitter' in source
    assert 'duration-guard' in source and 'tree-hygiene' in source
    assert 'shuffle-a' in source and 'shuffle-b' in source


@pytest.mark.parametrize('file,name', [
    ('mypy-nightly.yml', 'mypy'), ('nightly.yml', 'cpp-query-regressions'),
    ('tests.yml', 'python-unit-tests-sca'), ('tests.yml', 'python-unit-tests-sandbox'),
    ('tests.yml', 'python-unit-tests-exploit-feasibility'),
])
def test_remaining_consumers_save_exact_fallback_before_checks(file, name):
    source = job(file, name)
    restore = next(step for step in steps(source)
                   if 'uses: ./.github/actions/setup-venv\n' in step)
    assert "          save-on-rebuild: 'true'\n" in restore
    assert 'cache-key-prefix' not in restore
    assert 'install-method' not in restore
    assert 'uv-export-extra-args' not in restore
    assert source.index('actions/setup-python@') < source.index('uses: ./.github/actions/setup-venv')


def test_floor_canary_owns_its_inputs_and_keeps_fresh_install_and_same_test_subset():
    source = (ROOT / '.github/workflows/python-floor-canary.yml').read_text()
    events = source.split('\nconcurrency:', 1)[0]
    assert set(re.findall(r"^      - '([^']+)'$", events, re.M)) == {
        'pyproject.toml', 'uv.lock', 'uv.toml', '.github/workflows/python-floor-canary.yml',
        '.github/scripts/pytest_workers.py',
    }
    body = job('python-floor-canary.yml', 'floor-canary')
    install = named_step(body, 'Create venv from the lockfile on the floor interpreter')
    assert '        shell: bash\n' in install
    assert 'uv export --locked --no-hashes | uv pip install -r -' in script(install)
    assert 'uses: ./.github/actions/setup-venv' not in body  # Fresh install is the canary's contract.
    run = script(named_step(body, 'Fast test subset'))
    assert 'python .github/scripts/pytest_workers.py core/inventory core/dataflow' in run
    assert 'python -m pytest core/inventory core/dataflow -q -n "$workers" --dist loadfile' in run
    assert '-n auto' not in run
    assert 'python - <<' in script(named_step(body, 'Import smoke'))
    assert '  PYTHON_VERSION: \'3.12\'' in source


@pytest.mark.parametrize('failure', ['', 'venv', 'export', 'pip'])
def test_floor_install_binds_setup_python_and_propagates_failures(tmp_path, failure):
    body = job('python-floor-canary.yml', 'floor-canary')
    command = script(named_step(body, 'Create venv from the lockfile on the floor interpreter'))
    tools = tmp_path / 'tools with spaces'
    tools.mkdir()
    (tools / 'python3').symlink_to(sys.executable)
    record = tmp_path / 'uv-arguments.jsonl'
    uv = tools / 'uv'
    uv.write_text(f'#!{sys.executable}\n' + textwrap.dedent('''\
        import json, os, pathlib, sys
        args = sys.argv[1:]
        payload = {"argv": args}
        if args[0] == "pip":
            payload["stdin"] = sys.stdin.read()
        with open(os.environ["UV_RECORD"], "a") as output:
            output.write(json.dumps(payload) + "\\n")
        if args[0] == os.environ["FAIL_STAGE"]:
            sys.exit(19)
        if args[0] == "venv":
            activate = pathlib.Path(args[-1]) / "bin/activate"
            activate.parent.mkdir(parents=True)
            activate.write_text(":\\n")
        elif args[0] == "export":
            print("floor-fixture==1.0")
    '''))
    uv.chmod(0o755)
    venv = tmp_path / 'environment with spaces'
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', command],
        cwd=tmp_path,
        env=dict(os.environ, PATH=str(tools) + ':/usr/bin:/bin', VENV_PATH=str(venv),
                 UV_RECORD=str(record), FAIL_STAGE=failure),
        capture_output=True, text=True, timeout=10,
    )
    assert (result.returncode == 0) is (not failure), result.stdout + result.stderr
    calls = [json.loads(line) for line in record.read_text().splitlines()]
    assert calls[0]['argv'] == ['venv', '--python', str(tools / 'python3'), str(venv)]
    if not failure:
        by_command = {call['argv'][0]: call for call in calls}
        assert by_command['export']['argv'] == ['export', '--locked', '--no-hashes']
        assert by_command['pip'] == {'argv': ['pip', 'install', '-r', '-'],
                                     'stdin': 'floor-fixture==1.0\n'}


def test_mypy_remains_a_full_tree_type_check_after_restore():
    source = job('mypy-nightly.yml', 'mypy')
    run = script(named_step(source, 'Run mypy'))
    assert 'mypy --config-file pyproject.toml core/ packages/' in run
    assert source.index('uses: ./.github/actions/setup-venv') < source.index('name: Run mypy')


RUNTIME_CONSUMERS = [
    ('sca-pr-gate.yml', 'diff'), ('sca-compromise-check.yml', 'compromise-check'),
    ('typosquat-reaudit.yml', 'reaudit'),
]

CVSS_CONSUMERS = [
    ('sca-stress-sweep.yml', 'sweep', 'venv-runtime-cvss', '--no-dev --extra cvss'),
    ('refresh-sca-project-samples.yml', 'collect', 'venv-runtime-cvss', '--no-dev --extra cvss'),
    ('sca-self-bump.yml', 'self-bump', 'venv-cvss', '--extra cvss'),
]

INTERPRETER_CONSUMERS = RUNTIME_CONSUMERS + [(file, name) for file, name, _, _ in CVSS_CONSUMERS]


@pytest.mark.parametrize('file,name', RUNTIME_CONSUMERS)
def test_sca_consumers_share_only_the_runtime_profile(file, name):
    source = job(file, name)
    restore = named_step(source, 'Restore or rebuild runtime venv')
    assert 'uses: ./.github/actions/setup-venv' in restore
    assert '          cache-key-prefix: venv-runtime\n' in restore
    assert '          uv-export-extra-args: --no-dev\n' in restore
    assert "          save-on-rebuild: 'true'\n" in restore
    assert 'install-method:' not in restore  # Preserve locked export/install.
    assert 'astral-sh/setup-uv@' not in source
    assert 'uv pip install' not in source
    text = (ROOT / '.github/workflows' / file).read_text()
    assert '\nenv:\n  VENV_PATH: .venv\n' in text
    expose = named_step(source, 'Expose runtime interpreter to subsequent steps')
    assert source.index('actions/setup-python@') < source.index(restore)
    assert source.index(restore) < source.index(expose)
    assert 'shell: bash' in expose
    if file != 'typosquat-reaudit.yml':
        paths = set(re.findall(r"^      - '([^']+)'$", text, re.M))
        assert {'uv.toml', '.github/scripts/ci_cache_key.py'} <= paths
        if file == 'sca-compromise-check.yml':
            assert {'pyproject.toml', 'uv.lock', '.github/workflows/sca-compromise-check.yml',
                    '.github/actions/setup-venv/action.yml',
                    '.github/actions/enable-userns/action.yml'} <= paths
    else:
        assert 'pull_request:' not in text


@pytest.mark.parametrize('file,name', INTERPRETER_CONSUMERS)
@pytest.mark.parametrize('absolute', [False, True])
def test_sca_path_handoff_selects_the_restored_interpreter(tmp_path, file, name, absolute):
    source = job(file, name)
    command = script(named_step(source, 'Expose runtime interpreter to subsequent steps'))
    checkout = tmp_path / 'checkout with spaces'
    checkout.mkdir()
    environment = checkout / 'runtime environment'
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    paths = tmp_path / 'github-path'
    paths.write_text('/earlier/tool/location\n')
    env = dict(os.environ, GITHUB_PATH=str(paths),
               VENV_PATH=str(environment) if absolute else environment.name)
    result = subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', command],
        cwd=checkout, env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert paths.read_text().splitlines() == ['/earlier/tool/location', str(environment / 'bin')]
    # Model the runner applying GITHUB_PATH before the next step. Execute
    # both names used by the workflows and env-python script shebangs.
    for executable in ('python', 'python3'):
        child = subprocess.run(
            [executable, '-I', '-c', 'import sys; print(sys.prefix)'],
            cwd=checkout, env=dict(env, PATH=str(environment / 'bin') + os.pathsep + env['PATH']),
            capture_output=True, text=True, timeout=10,
        )
        assert child.returncode == 0, child.stdout + child.stderr
        assert Path(child.stdout.strip()) == environment


def test_runtime_cache_does_not_replace_the_compromise_or_reaudit_checks():
    compromise = job('sca-compromise-check.yml', 'compromise-check')
    run = script(named_step(compromise, 'Run compromise-detection harness'))
    assert 'packages/sca/scripts/raptor-sca-compromise-check' in run
    assert 'test/data/sca-e2e/compromise-corpus' in run and '--no-offline' in run
    assert "_RAPTOR_TRUSTED: '1'" in compromise
    reaudit = job('typosquat-reaudit.yml', 'reaudit')
    run = script(named_step(reaudit, 'Re-audit reviewed-legit (mechanical, no LLM)'))
    assert 'python -m packages.sca.supply_chain.typosquat_audit --reaudit' in run
    assert 'name: Open / update issue when entries are flagged' in reaudit


@pytest.mark.parametrize('file,name,prefix,args', CVSS_CONSUMERS)
def test_cvss_jobs_cache_the_locked_extra_and_keep_dependency_groups(file, name, prefix, args):
    source = job(file, name)
    restore = named_step(source, 'Restore or rebuild CVSS venv')
    assert 'uses: ./.github/actions/setup-venv' in restore
    assert f'          cache-key-prefix: {prefix}\n' in restore
    assert f'          uv-export-extra-args: {args}\n' in restore
    assert "          save-on-rebuild: 'true'\n" in restore
    assert 'install-method:' not in restore
    assert 'astral-sh/setup-uv@' not in source
    assert 'uv pip install' not in source
    assert 'cvss==' not in source
    expose = named_step(source, 'Expose runtime interpreter to subsequent steps')
    assert source.index('actions/setup-python@') < source.index(restore) < source.index(expose)
    assert '\nenv:\n  VENV_PATH: .venv\n' in (ROOT / '.github/workflows' / file).read_text()
