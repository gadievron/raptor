#!/usr/bin/env python3
"""Run registered wrapper contracts or native cells, rejecting missing coverage."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from sandbox_wrapper_tests import ROOT, load_registry, registry_errors


def check_report(path: Path, *, expected: int | None = None, minimum: int = 1) -> list[str]:
    if not path.is_file():
        return ['pytest did not produce JUnit coverage']
    try:
        cases = list(ET.parse(path).iter('testcase'))
    except ET.ParseError:
        return ['invalid JUnit report']
    problems = []
    if len(cases) < minimum or (expected is not None and len(cases) != expected):
        problems.append(f'expected {expected if expected is not None else "at least " + str(minimum)} executed cases, got {len(cases)}')
    for case in cases:
        for kind in ('skipped', 'failure', 'error'):
            if case.find(kind) is not None:
                problems.append(kind + ': ' + case.get('classname', '') + '::' + case.get('name', ''))
    return problems


def interpreter_tool_path(executable: str, inherited: str) -> str:
    """Keep console scripts installed beside the selected venv interpreter visible.

    Do not resolve the executable symlink: that would select the base Python
    bin directory instead of the virtual environment containing the tools.
    """
    return str(Path(executable).absolute().parent) + os.pathsep + inherited


def selected_targets(registry: dict, selection: dict, platform: str):
    """Reject empty, stale or cross-platform selection instead of running zero tests."""
    if not isinstance(selection, dict) or selection.get('platform') != platform:
        raise ValueError('selection platform does not match this runner')
    contracts, families = selection.get('contracts'), selection.get('families')
    for values in (contracts, families):
        if (not isinstance(values, list) or any(not isinstance(v, str) for v in values)
                or len(set(values)) != len(values)):
            raise ValueError('selection targets must be unique string lists')
    eligible_contracts = {selector for row in registry['wrappers']
                          for selector in row.get('contract_platforms', {}).get(platform, row['contracts'])}
    eligible_families = {family['id'] for family in registry['native']
                         if family['platforms'][platform].get('tests')
                         and not family['platforms'][platform].get('manual')}
    if not set(contracts) <= eligible_contracts or not set(families) <= eligible_families:
        raise ValueError('selection contains unregistered targets')
    full = selection.get('full')
    if type(full) is not bool:
        raise ValueError('selection must explicitly declare full or scoped coverage')
    if full and (set(contracts) != eligible_contracts or set(families) != eligible_families):
        raise ValueError('full selection omits registered targets')
    return contracts, None if full else families


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=('contracts', 'native'), required=True)
    parser.add_argument('--report-dir', type=Path, required=True)
    parser.add_argument('--selection-json', help='validated per-platform CI selection')
    parser.add_argument('--family', action='append', default=[])
    parser.add_argument('--include-manual', action='store_true', help='require hardware/operator-tool cells too; no skip waiver')
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    registry = load_registry()
    errors = registry_errors(ROOT, registry)
    if errors:
        # Preserve the refusal even though pytest never started. CI can then
        # upload useful preflight evidence instead of failing again because
        # the report directory contains no files. --list stays read-only.
        if not args.list:
            report = args.report_dir.resolve()
            report.mkdir(parents=True, exist_ok=True)
            (report/'summary.json').write_text(json.dumps(dict(
                platform=sys.platform, lane=args.lane,
                preflight_errors=errors, results=[],
            ), indent=2)+'\n')
        print('\n'.join(errors), file=sys.stderr)
        return 1
    if sys.platform not in ('linux', 'darwin'):
        parser.error('native Linux or macOS required')
    selected_contracts = selected_families = None
    if args.selection_json:
        if args.family:
            parser.error('--selection-json and --family cannot be combined')
        try:
            selected_contracts, selected_families = selected_targets(
                registry, json.loads(args.selection_json), sys.platform,
            )
        except (ValueError, TypeError, KeyError) as error:
            parser.error(str(error))
        if args.lane == 'contracts' and not selected_contracts:
            parser.error('contract selection is empty')
        if args.lane == 'native' and selected_families == []:
            parser.error('native selection is empty')
        if selected_families is not None:
            args.family = selected_families
    runs, unavailable = [], []
    if args.lane == 'contracts':
        selectors = sorted({selector for row in registry['wrappers']
                            for selector in row.get('contract_platforms', {}).get(sys.platform, row['contracts'])})
        if selected_contracts is not None:
            selectors = sorted(selected_contracts)
        runs.append(('contracts', selectors, None, {}, len(selectors)))
    else:
        known = {family['id'] for family in registry['native']}
        if set(args.family) - known:
            parser.error('unknown family: ' + ', '.join(sorted(set(args.family) - known)))
        for family in registry['native']:
            if args.family and family['id'] not in args.family:
                continue
            cell = family['platforms'][sys.platform]
            if not cell.get('tests') or (cell.get('manual') and not args.include_manual):
                unavailable.append(dict(family=family['id'], reason=cell['reason']))
                continue
            runs.append((family['id'], cell['tests'], cell['expected'], family.get('env', {}), 1))
    plan = dict(platform=sys.platform, lane=args.lane,
                selected=[dict(family=name, tests=nodes, expected=count) for name, nodes, count, _, _ in runs],
                not_exercised=unavailable)
    if args.list:
        print(json.dumps(plan, indent=2))
        return 0
    report = args.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=True)
    (report/'plan.json').write_text(json.dumps(plan, indent=2)+'\n')
    if args.family and unavailable:
        print('Requested family cannot execute here: ' + json.dumps(unavailable), file=sys.stderr)
        return 1
    if not runs:
        print('No registered cases selected', file=sys.stderr)
        return 1
    private_base = os.confstr(65537) if sys.platform == 'darwin' else str(report)
    results = []
    deadline = time.monotonic() + (600 if args.lane == 'contracts' else 1200)
    for name, selectors, expected, overrides, minimum in runs:
        # A fresh HOME for every group, never account-state copies.
        with tempfile.TemporaryDirectory(prefix='raptor-wrapper-ci-', dir=private_base) as private:
            root = Path(private)
            for directory in ('home', 'scratch', 'out', 'registry'):
                (root/directory).mkdir(mode=0o700)
            env = dict(os.environ, HOME=str(root/'home'), TMPDIR=str(root/'scratch'),
                       PATH=interpreter_tool_path(sys.executable, os.environ.get('PATH', os.defpath)),
                       RAPTOR_OUT_DIR=str(root/'out'), RAPTOR_REGISTRY_HOME=str(root/'registry'),
                       PYTHONDONTWRITEBYTECODE='1', RAPTOR_MAX_TEST_SECONDS='', **overrides)
            for key in ('RAPTOR_ALLOW_DEGRADED_UNTRUSTED', 'RAPTOR_TEST_EMULATE_PLATFORM', 'PYTHONPATH'):
                env.pop(key, None)
            xml = report/(name+'.xml')
            command = [sys.executable, '-I', '-B', '-m', 'pytest', *selectors,
                       '-o', 'addopts=', '-o', 'cache_dir='+str(root/'cache'),
                       '--basetemp='+str(root/'pytest'), '--junitxml='+str(xml),
                       '-q', '-ra', '--tb=short', '--durations=15']
            print('Running', name, flush=True)
            try:
                with (report/(name+'.log')).open('w') as log:
                    code = subprocess.run(command, cwd=ROOT, env=env, stdout=log,
                                          stderr=subprocess.STDOUT,
                                          timeout=max(1, min(600, deadline-time.monotonic()))).returncode
            except subprocess.TimeoutExpired:
                code = 124
            problems = check_report(xml, expected=expected, minimum=minimum)
            results.append(dict(family=name, returncode=code, coverage_errors=problems))
            print((report/(name+'.log')).read_text()[-12000:], flush=True)
            (report/'summary.json').write_text(json.dumps(dict(plan=plan, results=results), indent=2)+'\n')
            if code or problems:
                print('\n'.join(problems), file=sys.stderr)
                return code or 1
    print('Native exclusions (not acceptance passes): ' + json.dumps(unavailable), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
