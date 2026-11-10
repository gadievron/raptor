"""Bounded per-run activity: parent execution receipts plus verified evidence.

An observation is an attempt, not proof of an operation's success. The report
never infers an empty syscall/DNS history from missing logs, and never parses
HTTP inside a TLS tunnel. Current-process receipts are retained outside the
writable run tree. Historical unsigned input cannot become trusted activity.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import re
from pathlib import Path
import threading

from core.atomic_fs import write_text_atomically
from core.security.log_sanitisation import sanitise_for_terminal
from core.security.redaction import redact_secrets
from . import telemetry_mac

EVENTS_FILE = 'sandbox-activity.jsonl'
SUMMARY_FILE = 'sandbox-activity-summary.json'
TEXT_FILE = 'sandbox-activity.txt'
MAX_EVENTS = 4096
MAX_BYTES = 2 * 1024 * 1024
MAX_RUNS = 32
_lock = threading.Lock()
_runs: dict[str, dict] = {}
log = logging.getLogger(__name__)


def _text(value) -> str | None:
    if value is None:
        return None
    return sanitise_for_terminal(redact_secrets(str(value)[:4096]))[:512]


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def _state() -> dict:
    return {'events': [], 'seen': set(), 'bytes': 0, 'issues': set(),
            'observed': False, 'proxy': False, 'policy': 'no_denial_artifact',
            'key_hidden': True, 'calls': 0}


def _append(state: dict, source: str, action: str, resource=None, *, outcome='unknown',
            timestamp=None, pid=None, details=None, identity=None) -> None:
    timestamp = (timestamp if type(timestamp) in (int, float) and math.isfinite(timestamp)
                 else _text(timestamp) if isinstance(timestamp, str) else None)
    pid = pid if type(pid) is int and pid > 0 else None
    row = {'source': source, 'timestamp': timestamp, 'pid': pid,
           'action': _text(action) or 'unknown', 'resource': _text(resource), 'outcome': outcome}
    if details:
        row['details'] = details
    # Preserve genuinely repeated events; deduplicate only a known source
    # identity (e.g. source seq + timestamp), never merely a matching path.
    key = _json([source, identity]) if identity is not None else None
    if key is not None and key in state['seen']:
        return
    raw = _json(row)
    if len(state['events']) >= MAX_EVENTS or state['bytes'] + len(raw) > MAX_BYTES:
        state['issues'].add('activity_budget_exhausted')
        return
    if key is not None:
        state['seen'].add(key)
    state['events'].append(row)
    state['bytes'] += len(raw)


def _capture_observe(directory: Path, info: dict):
    from . import observe_profile as reader, evidence
    from .audit_control import AUDIT_CONTROL_TYPES
    nonce = info['observe_nonce']
    profile = reader.parse_observe_log(directory, expected_nonce=nonce,
                                       sandbox_info=info, current_run=True)
    observations: list[tuple[dict, list]] = []
    capped = False
    if not profile.nonce_trusted:
        return profile, observations, capped
    path = evidence.resolve_read_path(directory, reader.OBSERVE_FILENAME)
    size = 0
    for index, record in enumerate(reader._iter_records(path, profile=profile)):
        if not isinstance(record, dict) or record.get('nonce') != nonce:
            profile.capture_incomplete = True
            continue
        if record.get('type') in AUDIT_CONTROL_TYPES:
            continue
        name = record.get('syscall')
        if not isinstance(name, str) or not name:
            continue  # control-plane loss is already retained by the profile
        resource = record.get('path')
        if name in reader._OPEN_SYSCALLS:
            flags = reader._open_record_flags(record)
            action = ('open' if name in ('open', 'openat') and flags is None else
                      'open_write' if reader._open_record_is_write_intent(record) else 'open_read')
        elif reader._is_macos_write_action(name):
            action = 'open_write'
        elif name in reader._STAT_SYSCALLS:
            action = 'stat'
        elif name in reader._CONNECT_SYSCALLS:
            action = 'connect'
            target = reader._parse_connect_path(record)
            if target is not None:
                resource = f'{target.ip}:{target.port}'
        else:
            action = name
        verdict = record.get('verdict')
        # Entry notifications and synthetic returncode=0 are not syscall exits.
        outcome = 'allowed' if verdict == 'allow' else 'denied' if verdict == 'deny' else 'attempted'
        event = {'action': action, 'resource': _text(resource), 'outcome': outcome,
                 'timestamp': record.get('ts'), 'pid': record.get('pid'),
                 'details': {'syscall': _text(name), 'operation_success': 'unknown'}}
        encoded = _json(event)
        if len(observations) >= MAX_EVENTS or size + len(encoded) > MAX_BYTES:
            capped = True
            break
        size += len(encoded)
        # Index retains distinct repeated attempts; digest prevents a replaced
        # stream from reusing an index to hide a different accepted operation.
        identity = [hashlib.sha256(nonce.encode()).hexdigest(), index,
                    hashlib.sha256(encoded.encode('ascii')).hexdigest()]
        observations.append((event, identity))
    return profile, observations, capped


def record_execution(run_dir, *, result=None, error=None, job_budget=None, observation_dir=None) -> None:
    """Retain a bounded parent-owned receipt; telemetry must not mask an error."""
    if run_dir is None:
        return
    try:
        key = str(Path(run_dir).resolve())
        info = getattr(result, 'sandbox_info', {}) if result is not None else {}
        # Parse the existing protected observe channel before releasing its
        # per-invocation nonce. The nonce itself is never persisted here.
        profile = None
        observations = []
        observation_capped = False
        observe_error = None
        if info.get('observe_nonce'):
            try:
                profile, observations, observation_capped = _capture_observe(
                    Path(observation_dir or run_dir), info)
            except Exception as exc:
                observe_error = type(exc).__name__
        now = datetime.now(timezone.utc).isoformat()
        with _lock:
            if key not in _runs and len(_runs) >= MAX_RUNS:
                log.warning('sandbox activity active-run budget exhausted')
                return
            state = _runs.setdefault(key, _state())
            state['calls'] += 1
            if observe_error is not None:
                state['issues'].add('observe_receipt_failed:' + observe_error)
            state['proxy'] |= bool(info.get('proxy_enforcement'))
            if info.get('proxy_enforcement') == 'advisory':
                state['issues'].add('proxy_enforcement_advisory')
            if result is not None:
                state['key_hidden'] &= bool(info.get('mount_ns_active') or info.get('restrict_reads'))
            else:
                # An exception can occur after an unconfined child executed,
                # but before its CompletedProcess posture was published. A
                # receipt is not independent proof that the key stayed hidden.
                state['key_hidden'] = False
                state['issues'].add('execution_posture_unavailable')
            _append(state, 'execution', 'process_exit' if result is not None else 'setup_or_execution_error',
                    outcome=('failed' if error is not None else
                             'succeeded' if result is not None and result.returncode == 0 else
                             'failed' if result is not None else 'unknown'), timestamp=now,
                    details={'returncode': getattr(result, 'returncode', getattr(error, 'returncode', None)),
                             'error_type': type(error).__name__ if error is not None else None,
                             'posture': {k: info[k] for k in (
                                 'containment_tier', 'containment_floor', 'mount_ns_active',
                                 'proxy_enforcement', 'udp_block_engaged', 'audit_engaged',
                                 'mount_ns_degraded', 'signal', 'signal_num', 'crashed',
                                 'sanitizer', 'resource_exceeded') if k in info},
                             'job_budget': job_budget or {}})
            if error is not None:
                state['issues'].add('execution_or_cleanup_failed')
            if job_budget and (job_budget.get('receipt_integrity')
                               or job_budget.get('receipt') not in (None, 'written')):
                state['issues'].add('job_budget_receipt_incomplete')
            if profile is not None:
                state['observed'] = True
                if not profile.nonce_trusted:
                    state['issues'].add('observe_provenance_unavailable')
                else:
                    for event, identity in observations:
                        _append(state, 'observe', identity=identity, **event)
                if observation_capped:
                    state['issues'].add('activity_observe_budget_exhausted')
                if profile.budget_truncated:
                    state['issues'].add('observe_budget_truncated')
                if profile.capture_incomplete:
                    state['issues'].add('observe_capture_incomplete')
    except Exception as exc:
        log.warning('sandbox activity receipt could not be retained (%s)', type(exc).__name__)


def _merge_verified_inputs(run_dir: Path, state: dict) -> None:
    from . import triage, summary
    # Reuse the existing schema, sequence/count-sidecar and MAC checks. A
    # malformed or missing expected artifact remains a coverage gap.
    binding = telemetry_mac.run_binding(run_dir)
    posture = summary.get_run_posture(run_dir)
    if not state['calls'] and posture is None:
        state['key_hidden'] = False
        state['issues'].add('independent_key_hiding_posture_unavailable')
    if posture is not None and not posture.get('mac_key_hidden', False):
        state['key_hidden'] = False
    if not state['key_hidden']:
        unknown = {'execution_posture_unavailable', 'independent_key_hiding_posture_unavailable'}
        state['issues'].add('telemetry_key_hiding_unavailable' if unknown & state['issues']
                            else 'telemetry_key_exposed')
    raw_summary = triage._load_json(run_dir / summary.SUMMARY_FILE)
    usable, integrity = triage._verify_summary(raw_summary, binding, allow_legacy=False)
    if raw_summary is not None and integrity != 'verified':
        state['issues'].add('denial_provenance_' + integrity)
    if usable is not None and state['key_hidden']:
        state['policy'] = 'verified_denial_artifact'
        if any(usable.get(k) for k in ('capped', 'cap_reached', 'corrupt_lines',
                                      'inode_mismatch', 'evidence_write_failure')):
            state['issues'].add('denial_capture_incomplete')
        capture = usable.get('audit_capture') or {}
        if (capture.get('capture_incomplete') or capture.get('budget_truncated')
                or len(usable.get('denials', [])) >= summary.MAX_DENIALS_PER_RUN):
            state['issues'].add('denial_capture_incomplete')
        for index, row in enumerate(usable.get('denials', [])):
            _append(state, 'policy_denial', str(row.get('type') or 'denial'),
                    row.get('path') or row.get('host') or row.get('detail'),
                    outcome='denied', timestamp=row.get('ts') or row.get('timestamp') or row.get('t'),
                    pid=row.get('pid') if type(row.get('pid')) is int else None,
                    identity=index)
        allowed = usable.get('allowed_reports')
        if allowed:
            try:
                accepted = isinstance(allowed, list) and telemetry_mac.verify(
                    telemetry_mac.allowed_activity_fields(allowed, binding),
                    usable.get('allowed_activity_mac'))
            except (ValueError, TypeError, RecursionError):
                accepted = False
            if accepted:
                for index, row in enumerate(allowed):
                    if not isinstance(row, dict):
                        state['issues'].add('malformed_allowed_policy_record')
                        continue
                    _append(state, 'policy_allowed', _text(row.get('type')) or 'policy_allow',
                            row.get('path') or row.get('host'), outcome='allowed',
                            timestamp=row.get('ts'), pid=row.get('pid'), identity=index,
                            details={'operation_success': 'unknown'})
            else:
                state['issues'].add('allowed_policy_records_unverified')
    elif triage._artifact_present(run_dir / summary.SUMMARY_FILE):
        state['policy'] = 'unusable_denial_artifact'
        state['issues'].add('denial_evidence_unusable')
    from .proxy import PROXY_EVENTS_FILENAME, PROXY_EVENTS_COUNT_FILENAME
    issues: set[str] = set()
    events, over_bound = triage._load_jsonl_stream(run_dir / PROXY_EVENTS_FILENAME, issues=issues)
    count = triage._load_json(run_dir / PROXY_EVENTS_COUNT_FILENAME)
    checked, rejected, integrity, note = triage._verify_proxy_events(
        events, binding, allow_legacy=False, count_record=count, over_bound=over_bound)
    if events or count is not None or triage._artifact_present(run_dir / PROXY_EVENTS_FILENAME):
        state['proxy'] = True
    if rejected or issues or over_bound or integrity != 'verified' or note:
        state['issues'].add('proxy_evidence_incomplete_or_unverified')
    if state['key_hidden']:
        from .egress_summary import _CONTROL_PLANE_RESULTS
        for row in checked:
            if not isinstance(row, dict):
                state['issues'].add('malformed_proxy_event')
                continue
            verdict = str(row.get('result', 'unknown'))
            if verdict in _CONTROL_PLANE_RESULTS:
                state['issues'].add('proxy_' + verdict)
                continue
            outcome = ('allowed' if verdict == 'allowed' else 'denied' if verdict.startswith('denied_')
                       else 'attempted' if verdict.startswith('would_deny_') else 'failed')
            try:
                metadata_verified = telemetry_mac.verify(
                    telemetry_mac.proxy_activity_fields(row, binding), row.get('activity_mac'))
            except (ValueError, TypeError, RecursionError):
                metadata_verified = False
            if not metadata_verified:
                state['issues'].add('proxy_activity_fields_unverified')
            def numeric(name):
                value = row.get(name) if metadata_verified else None
                if value is None:
                    return None
                if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                    return value
                state['issues'].add('malformed_proxy_activity_metadata')
                return None
            _append(state, 'proxy', 'connect_tunnel', row.get('host'), outcome=outcome,
                    timestamp=row.get('t') if metadata_verified else None,
                    identity=row.get('seq'),
                    details={'port': numeric('port'), 'resolved_ip': _text(row.get('resolved_ip')),
                             'decision': _text(verdict), 'bytes_c2u': numeric('bytes_c2u'),
                             'bytes_u2c': numeric('bytes_u2c'), 'duration': numeric('duration'),
                             'metadata_verified': bool(metadata_verified),
                             'http_method': 'not_visible', 'url_path': 'not_visible'})
    posture = summary.get_run_posture(run_dir)
    if posture is not None and not posture.get('mac_key_hidden', False):
        state['key_hidden'] = False
        state['issues'].add('telemetry_key_exposed')
    # The outside watcher can survive owner death. Its purpose-separated
    # receipt is useful after a crash, but a token alone does not establish
    # key confidentiality on an unknown or exposed posture.
    from . import evidence, job_budget
    receipt_path = evidence.resolve_read_path(run_dir, job_budget.RECEIPTS_FILE)
    receipt_issues: set[str] = set()
    receipts, clipped = triage._load_jsonl_stream(receipt_path, issues=receipt_issues)
    if receipt_issues or clipped:
        state['issues'].add('job_budget_receipt_incomplete')
    parent_jobs = {row.get('details', {}).get('job_budget', {}).get('job_id')
                   for row in state['events'] if row['source'] == 'execution'}
    for receipt in receipts:
        job_id = receipt.get('job_id')
        try:
            valid = (isinstance(job_id, str) and re.fullmatch('[a-f0-9]{32}', job_id)
                     and receipt.get('run') == binding
                     and isinstance(receipt.get('requested'), dict)
                     and isinstance(receipt.get('result'), dict)
                     and telemetry_mac.verify(job_budget.receipt_fields(receipt), receipt.get('mac')))
        except (ValueError, TypeError, RecursionError):
            valid = False
        if not valid or not state['key_hidden']:
            state['issues'].add('job_budget_receipt_unverified')
            continue
        if job_id in parent_jobs:
            continue
        parent_jobs.add(job_id)
        record = {'job_id': job_id, 'requested': receipt['requested'],
                  'effective': receipt.get('effective', {}),
                  'status': 'watcher_receipt; payload_outcome_unknown', **receipt['result']}
        _append(state, 'job_budget', 'job_cleanup', outcome=(
            'succeeded' if record.get('cleanup') == 'complete' else 'failed'),
            timestamp=record.get('finished_at'),
            details={'job_budget': record}, identity=job_id)


def _fields(report: dict, run_dir: Path) -> dict:
    body = {k: v for k, v in report.items() if k != 'mac'}
    return {'kind': 'sandbox-activity-report', 'run': telemetry_mac.run_binding(run_dir),
            'sha256': hashlib.sha256(_json(body).encode('ascii')).hexdigest()}


def verify_report(run_dir: Path, report: dict, *, key_hidden: bool = False) -> bool:
    """Verify only with independently established key-hiding posture.

    A token from a known key-exposed run is not parent provenance. Callers
    must not infer key hiding from this report's own editable fields.
    """
    if not key_hidden or not isinstance(report, dict) or report.get('integrity') != 'verified':
        return False
    try:
        from core.security.capped_read import read_capped
        raw = read_capped(run_dir / EVENTS_FILE, MAX_BYTES + MAX_EVENTS * 256)
        return (raw is not None
                and hashlib.sha256(raw).hexdigest() == report.get('events_sha256')
                and telemetry_mac.verify(_fields(report, run_dir), report.get('mac')))
    except (OSError, TypeError, ValueError, RecursionError):
        return False


def finalize(run_dir: Path) -> dict:
    """Write private machine-readable events, authenticated summary and text.

    No source is described as complete merely because it is empty. This first
    report joins existing evidence; it adds neither a DNS listener nor TLS MITM.
    """
    run_dir = Path(run_dir)
    key = str(run_dir.resolve())
    with _lock:
        original = _runs.get(key)
        if original is None:
            state = _state()
        else:
            state = {**original, 'events': list(original['events']),
                     'seen': set(original['seen']), 'issues': set(original['issues'])}
    if original is None:
        from . import triage, summary
        previous = triage._load_json(run_dir / SUMMARY_FILE)
        posture = summary.get_run_posture(run_dir)
        if previous is not None and verify_report(run_dir, previous,
                key_hidden=bool(posture and posture.get('mac_key_hidden'))):
            return previous
    _merge_verified_inputs(run_dir, state)
    if not state['observed']:
        state['issues'].add('observe_disabled_or_unavailable')
    if not state['calls']:
        state['issues'].add('parent_execution_receipts_unavailable')
    jobs = [row.get('details', {}).get('job_budget', {}) for row in state['events']
            if row['source'] in ('execution', 'job_budget') and row.get('details', {}).get('job_budget', {}).get('requested')]
    if len(jobs) > 16:
        state['issues'].add('job_budget_summary_truncated')
    counts = Counter((event['action'], event['outcome']) for event in state['events'])
    # Sequence describes ingestion order, not a fabricated cross-source clock.
    lines = ''.join(_json({'seq': i, **row}) + '\n' for i, row in enumerate(state['events']))
    report = {'schema_version': 1, 'run': telemetry_mac.run_binding(run_dir),
              'generated_at': datetime.now(timezone.utc).isoformat(),
              'events_file': EVENTS_FILE, 'events_sha256': hashlib.sha256(lines.encode('ascii')).hexdigest(),
              'event_count': len(state['events']), 'execution_count': state['calls'],
              'job_budgets': jobs[:16], 'job_budget_records': len(jobs),
              'counts': [{'action': action, 'outcome': outcome, 'count': count}
                         for (action, outcome), count in sorted(counts.items())],
              'coverage': {'complete': not state['issues'], 'issues': sorted(state['issues']),
                           'observe': 'engaged' if state['observed'] else 'disabled_or_unavailable',
                           'proxy': 'enabled_or_captured' if state['proxy'] else 'not_observed',
                           'policy': state['policy'],
                           'scope': 'enabled sources; hard in-kernel denials can bypass tracing',
                           'all_activity_observed': False,
                           'dns': 'proxy_resolution_only; query names/types not comprehensively observed',
                           'https': 'CONNECT destination and tunnel only; encrypted methods/paths not visible',
                           'ordering': 'ingestion; source timestamps may use different clocks'},
              'integrity': 'verified' if state['key_hidden'] and (state['calls'] or jobs) else 'unavailable'}
    token = telemetry_mac.mint(_fields(report, run_dir))
    if token is None:
        report['integrity'] = 'unavailable'
        report['coverage']['complete'] = False
        report['coverage']['issues'].append('provenance_key_unavailable')
    else:
        report['mac'] = token
    text = ['Sandbox activity', 'Integrity: ' + report['integrity'], f"{report['execution_count']} execution receipt(s), {report['event_count']} event(s).",
            'Coverage: ' + ('complete for enabled sources' if report['coverage']['complete'] else 'incomplete'),
            *('  ' + issue for issue in report['coverage']['issues'])]
    text.extend(f"  {row['action']}: {row['outcome']} ({row['count']})" for row in report['counts'])
    text.extend(f"  Job budget: {job.get('status', 'unknown')}; cleanup: {job.get('cleanup', 'unknown')}"
                for job in jobs[:16])
    text.append('Activity examples (full detail in ' + EVENTS_FILE + '):')
    text.extend(f"  {row['source']}: {row['action']} {row['resource'] or ''} → {row['outcome']}"
                for row in state['events'][:100])
    if len(state['events']) > 100:
        text.append('  Further events omitted from this view; see the bounded event stream.')
    text.append('Attempts do not establish success. HTTPS methods/paths and full DNS queries are not visible.')
    write_text_atomically(run_dir / EVENTS_FILE, lines, mode=0o600, root=run_dir)
    write_text_atomically(run_dir / SUMMARY_FILE, _json(report) + '\n', mode=0o600, root=run_dir)
    write_text_atomically(run_dir / TEXT_FILE, '\n'.join(text) + '\n', mode=0o600, root=run_dir)
    with _lock:
        if _runs.get(key) is original:
            _runs.pop(key, None)
    return report
