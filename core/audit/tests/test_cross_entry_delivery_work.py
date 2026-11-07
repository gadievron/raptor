"""Delivery bookkeeping preserves first matches and acknowledges shadow work once."""

from dataclasses import replace

import pytest

from core.audit.cross_entry import runner
from core.audit.cross_entry.model import Limits, StudySlice
from core.json import load_json


def record(number):
    key = f'evidence{number}'
    return {'namespace': 'main', 'view_id': 'view', 'id': f'job{number}',
            'consumer': 'consumer', 'focus': '', 'status': 'prepared', 'attempts': 1,
            'result': '{"key":"' + key + '"}', 'outcome': {'key': key}, 'evidence': key}


@pytest.fixture
def data():
    available = [record(i) for i in range(1000)]
    units, requested, jobs = [], {}, {}
    for i in range(6):
        fid = f'function{i}'
        unit = StudySlice(f'unit{i}', fid, [fid], [], [], [], [], [], 0, '', 'fingerprint')
        units.append(unit)
        requested[fid] = f'a.c:f{i}'
        jobs[unit.id] = record(990 + i)
    return available, units, requested, jobs


def lookup(data):
    return runner._delivery_lookup(*data)


def test_lookup_keeps_first_match_and_only_requested_rows(data):
    available, units, requested, jobs = data
    first = record(990)
    first['evidence'] = 'first-duplicate'
    available.insert(0, first)
    found = lookup(data)
    assert len(found) == len(units)
    assert found['job990'] is first
    for unit in units:
        jid = jobs[unit.id]['id']
        assert found.get(jid) is next(row for row in available if row['id'] == jid)
    assert len(available) == 1001
    found.clear()
    assert len(lookup(data)) == len(units)


def test_lookup_stops_after_all_wanted_matches(data):
    available, units, requested, jobs = data
    available[:] = [jobs[unit.id] for unit in units] + [{'missing-id': True}] * 1000
    assert set(lookup(data)) == {jobs[unit.id]['id'] for unit in units}


def test_missing_ids_produce_an_empty_index(data):
    available, units, requested, jobs = data
    available[:] = available[:500]
    assert lookup(data) == {}


def test_small_batch_keeps_direct_scan(data):
    available, units, requested, jobs = data
    assert runner._delivery_lookup(available[:10], units, requested, jobs) is None
    assert runner._delivery_lookup(available, units[:3], requested, jobs) is None


def test_duplicate_report_labels_do_not_trigger_unneeded_lookup(data):
    available, units, requested, jobs = data
    requested.update({unit.consumer: 'one-report' for unit in units})
    assert lookup(data) is None


def test_unrequested_units_are_not_indexed(data):
    available, units, requested, jobs = data
    del requested[units[-1].consumer]
    found = lookup(data)
    assert len(found) == len(units) - 1
    assert jobs[units[-1].id]['id'] not in found


class AdaptedId(str):
    __hash__ = None


class AdaptedRow(dict):
    pass


@pytest.mark.parametrize('kind', ['null-row-id', 'adapted-row-id', 'missing-row-id',
                                  'adapted-row', 'null-job-id', 'adapted-job-id',
                                  'missing-job', 'adapted-report-label'])
def test_legacy_and_adapted_inputs_keep_equality_scan(data, kind):
    available, units, requested, jobs = data
    if kind == 'null-row-id':
        available[0]['id'] = None
    elif kind == 'adapted-row-id':
        available[0]['id'] = AdaptedId('job0')
    elif kind == 'missing-row-id':
        del available[0]['id']
    elif kind == 'adapted-row':
        available[0] = AdaptedRow(available[0])
    elif kind == 'null-job-id':
        jobs[units[0].id]['id'] = None
    elif kind == 'adapted-job-id':
        jobs[units[0].id]['id'] = AdaptedId('job990')
    elif kind == 'missing-job':
        del jobs[units[0].id]
    else:
        requested[units[0].consumer] = ['unhashable-label']
    assert lookup(data) is None


@pytest.mark.parametrize('unmapped', [False, True], ids=['eligible-units', 'no-eligible-units'])
def test_shadow_acknowledges_once_at_first_eligible_unit(tmp_path, monkeypatch, unmapped):
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached('probe.c', 'int f(void){return 0;}')[0] is None:
        pytest.skip('requires tree-sitter C grammar')
    root, out = tmp_path / 'src', tmp_path / 'out'
    root.mkdir()
    (root / 'a.c').write_text('struct state {int value;};\n' + ''.join(
        f'int get{i}(struct state *p){{return p->value;}}\n' for i in range(3)))
    gaps = [{'file': 'a.c', 'name': f'get{i}'} for i in range(3)]
    acknowledged = []
    original = runner.WorkQueue

    class CountedQueue(original):
        def acknowledge(self, view, job, evidence):
            acknowledged.append((view, job, evidence))
            return super().acknowledge(view, job, evidence)

    monkeypatch.setattr(runner, 'WorkQueue', CountedQueue)
    if unmapped:
        build = runner.build_slices

        def unrequested(*args, **kwargs):
            units, deferred = build(*args, **kwargs)
            return [replace(unit, consumer='not-requested') for unit in units], deferred

        monkeypatch.setattr(runner, 'build_slices', unrequested)
    limits = replace(Limits(), graph_seconds=100, scan_seconds=100)
    assert runner.prepare(root, gaps, mode='shadow', out_dir=out, include_dirs=(root,), limits=limits) == {}
    progress = load_json(out / 'cross-entry-progress.json')
    assert len(acknowledged) == (0 if unmapped else 3)
    assert len(set(acknowledged)) == len(acknowledged)
    assert progress['undelivered_results'] == (3 if unmapped else 0)


def test_large_context_batch_uses_lookup_and_keeps_exact_receipts(tmp_path, monkeypatch):
    import sqlite3
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached('probe.c', 'int f(void){return 0;}')[0] is None:
        pytest.skip('requires tree-sitter C grammar')
    root, out = tmp_path / 'src', tmp_path / 'out'
    root.mkdir()
    (root / 'a.c').write_text('struct state {int value;};\n' + ''.join(
        f'int get{i}(struct state *p){{return p->value;}}\n' for i in range(18)))
    gaps = [{'file': 'a.c', 'name': f'get{i}'} for i in range(18)]
    indexed = []
    original = runner._delivery_lookup

    def tracked(*args):
        found = original(*args)
        indexed.append(found)
        return found

    monkeypatch.setattr(runner, '_delivery_lookup', tracked)
    limits = replace(Limits(), graph_seconds=100, scan_seconds=100)
    receipts = {}
    contexts = runner.prepare(root, gaps, mode='context', out_dir=out, include_dirs=(root,),
                              limits=limits, delivery_receipts=receipts)
    assert len(contexts) == len(receipts) == 18
    assert len(indexed) == 1 and len(indexed[0]) == 18
    functions = load_json(out / 'cross-entry-index.json')['functions']
    with sqlite3.connect(out / 'cross-entry-work.sqlite') as db:
        db.row_factory = sqlite3.Row
        for key, receipt in receipts.items():
            job = db.execute('SELECT * FROM jobs WHERE namespace=? AND view_id=? AND id=?',
                             (receipt['namespace'], receipt['view'], receipt['job'])).fetchone()
            assert job is not None
            assert functions[job['consumer']]['name'] == key.partition(':')[2]
            assert indexed[0][job['id']]['evidence'] == receipt['evidence']


def test_nullable_legacy_job_ids_keep_original_shadow_passes(tmp_path, monkeypatch):
    import json
    import sqlite3
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached('probe.c', 'int f(void){return 0;}')[0] is None:
        pytest.skip('requires tree-sitter C grammar')
    root, out = tmp_path / 'src', tmp_path / 'out'
    root.mkdir()
    (root / 'a.c').write_text('struct state {int value;};\n' + ''.join(
        f'int get{i}(struct state *p){{return p->value;}}\n' for i in range(3)))
    gaps = [{'file': 'a.c', 'name': f'get{i}'} for i in range(3)]
    calls = []
    original = runner.WorkQueue

    class LegacyQueue(original):
        seeded = False

        def add_jobs(self, view, descriptors):
            super().add_jobs(view, descriptors)
            if not self.seeded:
                rows = self.db.execute('SELECT id FROM jobs WHERE namespace=? AND view_id=?',
                                       (self.namespace, view)).fetchall()
                for number, row in enumerate(rows):
                    self.db.execute("UPDATE jobs SET id=NULL,status='prepared',result=? WHERE namespace=? AND view_id=? AND id=?",
                                    (json.dumps({'key': f'legacy{number}'}), self.namespace, view, row['id']))
                self.db.commit()
                self.seeded = True

        def acknowledge(self, *args):
            calls.append(args)
            return super().acknowledge(*args)

    monkeypatch.setattr(runner, 'WorkQueue', LegacyQueue)
    limits = replace(Limits(), graph_seconds=100, scan_seconds=100)
    assert runner.prepare(root, gaps, mode='shadow', out_dir=out, include_dirs=(root,), limits=limits) == {}
    # SQLite permits every repeated INSERT when job_id is NULL. Preserve that
    # legacy behavior rather than silently treating these writes as no-ops.
    assert len(calls) == 9
    assert load_json(out / 'cross-entry-progress.json')['undelivered_results'] == 3
    with sqlite3.connect(out / 'cross-entry-work.sqlite') as db:
        assert db.execute('SELECT count(*) FROM acknowledgements WHERE job_id IS NULL').fetchone()[0] == 9
