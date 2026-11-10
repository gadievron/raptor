"""Optional delegated cgroup v2 budgets for one Linux namespace execution.

No delegation is created or privileged service reconfigured. Controls must
already be delegated to the parent selected by the operator. A separate trusted
watcher remains outside the job, owns its lifetime pipe, kills the entire job
on owner EOF, and reads counters before removing its empty cgroup. Its control
FDs are never selected for inheritance by the payload.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import logging
import os
from pathlib import Path
import select
import signal
import secrets
import sys
import time

from core.security import cgroup_scope
from core.security.capped_read import read_capped_text
from .errors import SandboxSetupError

log = logging.getLogger(__name__)
_MAX_REPLY = 4096
_WAIT_SECONDS = 10.0
RECEIPTS_FILE = '.sandbox-job-budgets.jsonl'


def receipt_fields(receipt: dict) -> dict:
    body = {k: v for k, v in receipt.items() if k != 'mac'}
    encoded = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    return {'kind': 'sandbox-job-budget', 'run': receipt.get('run'),
            'sha256': hashlib.sha256(encoded.encode('ascii')).hexdigest()}


class JobBudgetError(SandboxSetupError):
    """A required budget or verified job cleanup could not be delivered."""

    def __init__(self, message: str, record: dict):
        super().__init__(message,
                         'Provide a writable delegated cgroup v2 subtree with the requested controllers; '
                         'RAPTOR does not alter host delegation. See docs/sandbox.md job budgets.')
        self.job_budget = record


@dataclass(frozen=True)
class Budget:
    controls: tuple[tuple[str, str], ...]
    required: bool = True
    parent: Path | None = None

    @classmethod
    def parse(cls, raw: object) -> Budget | None:
        if raw is None:
            return None
        if not isinstance(raw, dict) or not raw:
            raise ValueError('job_budget must be a non-empty object')
        unknown = raw.keys() - {'memory_max', 'cpu_max', 'pids_max', 'required', 'parent'}
        if unknown:
            raise ValueError('unknown job_budget fields: ' + ', '.join(sorted(unknown)))
        required = raw.get('required', True)
        if type(required) is not bool:
            raise ValueError('job_budget.required must be boolean')
        parent = raw.get('parent')
        if parent is not None:
            if not isinstance(parent, str) or not Path(parent).is_absolute() or '..' in Path(parent).parts:
                raise ValueError('job_budget.parent must be an absolute cgroup path without ..')
            parent = Path(parent)
        controls = []
        for key, name in [('memory_max', 'memory.max'), ('pids_max', 'pids.max')]:
            if key in raw:
                value = raw[key]
                if type(value) is not int or value <= 0 or value > 2**63 - 1:
                    raise ValueError(key + ' must be a positive integer')
                controls.append((name, str(value)))
                if key == 'memory_max':
                    # Bound total job memory rather than permit unlimited
                    # swapping outside the resident-memory ceiling.
                    controls.append(('memory.swap.max', '0'))
        if 'cpu_max' in raw:
            cpu = raw['cpu_max']
            if (not isinstance(cpu, (list, tuple)) or len(cpu) != 2
                    or any(type(v) is not int for v in cpu)
                    or cpu[0] < 1000 or cpu[0] > 2**63 - 1
                    or not 1000 <= cpu[1] <= 1_000_000):
                raise ValueError('cpu_max must be [quota_us >= 1000, period_us between 1000 and 1000000]')
            controls.append(('cpu.max', f'{cpu[0]} {cpu[1]}'))
        if not controls:
            raise ValueError('job_budget needs at least one finite budget')
        return cls(tuple(controls), required, parent)


    def as_dict(self) -> dict:
        values = dict(self.controls)
        raw: dict[str, object] = {'required': self.required}
        for key, name in [('memory_max', 'memory.max'), ('pids_max', 'pids.max')]:
            if name in values:
                raw[key] = int(values[name])
        if 'cpu.max' in values:
            raw['cpu_max'] = [int(v) for v in values['cpu.max'].split()]
        if self.parent is not None:
            raw['parent'] = str(self.parent)
        return raw


def load_budget(raw: object, *, config_path: Path | None = None) -> Budget | None:
    """Use explicit per-call configuration, otherwise the existing sandbox config.

    Budget syntax errors refuse: a misspelled requested limit cannot silently
    become an unbudgeted run. No virtual-address-space limit is introduced.
    """
    if raw is None:
        if config_path is None:
            from .preexec import _CONFIG_PATH
            config_path = _CONFIG_PATH
        try:
            text = read_capped_text(config_path, 65536, errors='strict',
                                    follow_symlinks=True, raise_on_refusal=True)
        except FileNotFoundError:
            return None
        from .evidence import _unique_evidence_object
        config = json.loads(text, object_pairs_hook=_unique_evidence_object)
        if not isinstance(config, dict):
            raise ValueError('sandbox config must be an object')
        raw = config.get('job_budget')
    return Budget.parse(raw)


def _snapshot(scope) -> dict:
    usage: dict[str, object] = {}
    selected = {
        'memory.events': {'low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'},
        'cpu.stat': {'usage_usec', 'user_usec', 'system_usec', 'nr_periods',
                     'nr_throttled', 'throttled_usec', 'nr_bursts', 'burst_usec'},
    }
    for name in ('memory.current', 'memory.peak', 'memory.events', 'cpu.stat',
                 'pids.current', 'pids.peak'):
        try:
            raw = cgroup_scope._read(scope.node, name).strip()
            if name in selected:
                values = {}
                for line in raw.splitlines():
                    key, value = line.split()
                    if key in selected[name]:
                        if not value.isdecimal() or len(value) > 20:
                            raise ValueError('invalid cgroup counter')
                        values[key] = int(value)
                usage[name] = values
            else:
                if not raw.isdecimal() or len(raw) > 20:
                    raise ValueError('invalid cgroup counter')
                usage[name] = int(raw)
        except (OSError, ValueError) as exc:
            usage[name] = {'unavailable': type(exc).__name__}
    return usage


def _finish_scope(scope) -> dict:
    report: dict[str, object] = {'usage': {}, 'cleanup': 'failed'}
    try:
        report['usage'] = _snapshot(scope)
        scope.close_admission()
        report['killed_remaining_processes'] = scope.stop(timeout=5)
        # Includes final CPU and OOM accounting; the pre-kill snapshot remains
        # available for the job's live memory and process usage.
        report['final_usage'] = _snapshot(scope)
        scope.release()
        report['cleanup'] = 'complete'
    except BaseException as exc:
        report['cleanup_error'] = type(exc).__name__
    finally:
        try:
            scope.close()
        except BaseException as exc:
            report['cleanup'] = 'failed'
            report['close_error'] = type(exc).__name__
    report['finished_at'] = time.time()
    return report


def _watch(scope, lifetime: int, reply: int, close_fds, owner_pid: int,
           receipt_fd=None, receipt=None, signer=None) -> None:
    """Trusted watcher body; only bounded kernel controls and owned pipes."""
    finished = False
    code = 1
    try:
        keep = {lifetime, reply, scope.node, scope.parent}
        if receipt_fd is not None:
            keep.add(receipt_fd)
        close_fds(keep)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_IGN)
        # PPID corroboration also handles an unrelated fork retaining a
        # lifetime-writer copy: that copy cannot keep an orphaned job alive.
        # An explicit stop byte handles normal completion without waiting for
        # EOF from every transient inherited writer.
        while os.getppid() == owner_pid:
            readable, _, _ = select.select([lifetime], [], [], .1)
            if readable:
                os.read(lifetime, 1)
                break
        report = _finish_scope(scope)
        finished = True
        if receipt_fd is not None:
            try:
                record = {**receipt, 'result': report}
                record['mac'] = signer(receipt_fields(record))
                encoded = (json.dumps(record, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')
                if len(encoded) <= _MAX_REPLY:
                    if os.write(receipt_fd, encoded) != len(encoded):
                        report['receipt'] = 'incomplete'
                    else:
                        os.fsync(receipt_fd)
                        report['receipt'] = 'written'
                        report['receipt_provenance'] = 'available' if record['mac'] else 'unavailable'
                else:
                    report['receipt'] = 'oversized'
            except BaseException as exc:
                report['receipt'] = 'failed'
                report['receipt_error'] = type(exc).__name__
        raw = json.dumps(report, sort_keys=True).encode('ascii')
        if len(raw) > _MAX_REPLY:
            raw = b'{"cleanup":"failed","cleanup_error":"oversized watcher reply"}'
        os.set_blocking(reply, False)
        if os.write(reply, raw) != len(raw):
            os._exit(1)
        code = 0 if report['cleanup'] == 'complete' else 1
    except BaseException:
        if not finished:
            try:
                _finish_scope(scope)
            except BaseException:
                pass
    finally:
        os._exit(code)




def find_delegation(controls) -> Path:
    """Use an existing owned controller-ready parent; never enable controllers.

    systemd commonly keeps a login shell in a non-delegated session scope
    while delegating the same user's user@UID.service subtree separately.
    Rootless/non-systemd installations can name their parent explicitly.
    """
    controllers = {name.split('.')[0] for name, _ in controls}
    candidates = [cgroup_scope.current_group(),
                  cgroup_scope.CGROUP_ROOT / 'user.slice' / f'user-{os.geteuid()}.slice'
                  / f'user@{os.geteuid()}.service']
    for path in candidates:
        node = None
        try:
            node = cgroup_scope._open_directory(path)
            if (os.fstat(node).st_uid == os.geteuid() and os.access(path, os.W_OK)
                    and controllers <= set(cgroup_scope._read(node, 'cgroup.subtree_control').split())):
                return path
        except OSError:
            pass
        finally:
            if node is not None:
                os.close(node)
    raise OSError(errno.ENOTSUP, 'no owned writable controller-ready delegation; set job_budget.parent')


def _prepare_control_sealer():
    # Resolve the module and callable in the parent, before any fork. Mount
    # hiding is mandatory even when /sys carries a writable cgroup submount.
    from .mount_ns import _mount, MS_RDONLY
    def seal():
        if os.path.isdir('/sys/fs/cgroup'):
            _mount('tmpfs', '/sys/fs/cgroup', 'tmpfs', MS_RDONLY | 2 | 4 | 8,
                   'size=4096,nr_inodes=16,mode=0555')
    return seal


class Job:
    """Parent-side per-dispatch owner; attach is called before the go gate."""

    def __init__(self, budget: Budget | None, *, namespace_backend: bool, run_dir=None):
        self.budget = budget
        self.scope: cgroup_scope.Scope | None = None
        self.writer: int | None = None
        self.reader: int | None = None
        self.watcher: int | None = None
        self.attached = False
        self.run_dir = run_dir
        self.receipt_handle = None
        self.record: dict[str, object] = {'requested': dict(budget.controls) if budget else {},
                       'required': bool(budget and budget.required),
                       'effective': {}, 'status': 'not_requested', 'cleanup': 'not_needed',
                       'job_id': secrets.token_hex(16)}
        if budget is None:
            return
        try:
            if sys.platform != 'linux' or not namespace_backend:
                raise OSError(errno.ENOTSUP, 'job budgets require the Linux mount/PID namespace launch gate')
            self.control_sealer = _prepare_control_sealer()
            parent = budget.parent if budget.parent is not None else find_delegation(budget.controls)
            self.scope = cgroup_scope.Scope.create(parent)
            for name, value in budget.controls:
                cgroup_scope._write(self.scope.node, name, value)
                # Kernel read-back can round memory limits to page boundaries;
                # requiring exact equality refuses rather than overstates them.
                if cgroup_scope._read(self.scope.node, name).strip() != value:
                    raise OSError(errno.EIO, 'cgroup control read-back mismatch: ' + name)
            if self.run_dir is not None:
                from . import evidence, telemetry_mac
                self.receipt_handle = evidence.EvidenceFile.open(self.run_dir, RECEIPTS_FILE)
                self.signer = telemetry_mac.prepare_signer()
            self._start_watcher()
            self.record.update(status='prepared', effective=dict(budget.controls),
                               path=str(self.scope.path), identity=self.scope.identity,
                               cleanup='pending')
        except BaseException as exc:
            if self.watcher is not None:
                try:
                    self.close()
                except BaseException as cleanup_error:
                    exc.add_note('job preparation cleanup: ' + type(cleanup_error).__name__)
                cleanup = {k: self.record[k] for k in ('cleanup', 'cleanup_error') if k in self.record}
            else:
                cleanup = _finish_scope(self.scope) if self.scope is not None else {}
                self.scope = None
            self.record.update(status='unavailable', effective={},
                               reason=type(exc).__name__, **cleanup)
            if self.receipt_handle is not None:
                try:
                    self.receipt_handle.close()
                except BaseException as receipt_error:
                    exc.add_note('job receipt cleanup: ' + type(receipt_error).__name__)
                self.receipt_handle = None
            if not isinstance(exc, Exception):
                raise
            if budget.required or cleanup.get('cleanup') == 'failed':
                raise JobBudgetError('Required sandbox job budget unavailable before execution', self.record) from exc
            log.warning('Sandbox job budget unavailable; explicit optional budget uses rlimits only (%s)',
                        type(exc).__name__)

    def _start_watcher(self) -> None:
        from . import _spawn
        from ._fd_sweep import close_fds_except
        from ._retirement import retire_parent_resources
        owner_pid = os.getpid()
        if self.budget is None or self.scope is None:
            raise ValueError('watcher needs a validated budget and scope')
        receipt = {'run': Path(self.run_dir).resolve().name if self.run_dir is not None else None,
                   'job_id': self.record['job_id'], 'requested': dict(self.budget.controls),
                   'effective': dict(self.budget.controls), 'scope_identity': self.scope.identity,
                   'policy': 'full_mount_pid_namespace_required'}
        receipt_fd = self.receipt_handle.fd if self.receipt_handle is not None else None
        signer = self.signer if self.receipt_handle is not None else None
        lifetime, writer = _spawn.open_death_pipe()
        reader = reply = None
        try:
            reader, reply = os.pipe()
            with _spawn._DEATH_W_LOCK:
                watcher = os.fork()
            if watcher == 0:
                _watch(self.scope, lifetime, reply, close_fds_except, owner_pid,
                       receipt_fd, receipt, signer)
                os._exit(1)
            self.writer, self.reader, self.watcher = writer, reader, watcher
        except BaseException:
            retire_parent_resources(
                lambda: _spawn.close_death_w(writer),
                lambda: os.close(reader) if reader is not None else None,
            )
            raise
        finally:
            retire_parent_resources(
                lambda: os.close(lifetime),
                lambda: os.close(reply) if reply is not None else None,
            )

    def ensure_lane(self, lane: str, *, namespace_isolated: bool = False) -> None:
        if self.scope is not None and (lane != 'mount-ns spawn' or not namespace_isolated):
            raise JobBudgetError('Prepared job budget requires full mount/PID namespace dispatch', self.record)

    def ensure_exports(self, paths, descriptors) -> None:
        try:
            self._check_exports(paths, descriptors)
        except Exception as exc:
            raise JobBudgetError('Cannot verify cgroup control export isolation', self.record) from exc

    def _check_exports(self, paths, descriptors) -> None:
        """Do not let a declared path/FD grant hand back job controls."""
        if self.scope is None:
            return
        aliases = [cgroup_scope.CGROUP_ROOT]
        from core.security.capped_read import read_capped
        raw = read_capped(Path('/proc/self/mountinfo'), 1024 * 1024, raise_on_refusal=True)
        for line in raw.decode('utf-8', errors='strict').splitlines():
            before, after = line.split(' - ', 1)
            if after.split()[0] == 'cgroup2':
                import re
                mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), before.split()[4])
                aliases.append(Path(mount))
        device = os.fstat(self.scope.node).st_dev
        for path in paths:
            if not path:
                continue
            resolved = Path(path).resolve()
            if (any(resolved == alias or resolved in alias.parents or alias in resolved.parents
                    for alias in aliases) or os.stat(resolved).st_dev == device):
                raise JobBudgetError('Job budget refuses export of cgroup controls', self.record)
        for value in descriptors:
            if value is None:
                continue
            fd = value if type(value) is int else value.fileno()
            if fd < 0:
                continue
            try:
                st = os.fstat(fd)
            except OSError as exc:
                if exc.errno == errno.EBADF and fd in (0, 1, 2):
                    continue
                raise
            if st.st_dev == device:
                raise JobBudgetError('Job budget refuses inherited cgroup control descriptors', self.record)

    def attach(self, pid: int) -> None:
        if self.scope is None:
            return
        try:
            self.scope.attach(pid)
            # Verify membership while this exact child is alive behind its
            # gate. A failure is fatal, including for optional budgets: once
            # admission starts, silently falling back would be ambiguous.
            members = cgroup_scope._read(self.scope.node, 'cgroup.procs').split()
            if str(pid) not in members:
                raise OSError(errno.EIO, 'launcher not present in job cgroup')
            self.attached = True
            self.record['status'] = 'applied'
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            raise JobBudgetError('Sandbox job cgroup admission failed; payload not released', self.record) from exc

    def close(self) -> None:
        if self.scope is None:
            return
        from . import _spawn
        writer, self.writer = self.writer, None
        reader, self.reader = self.reader, None
        try:
            if writer is not None:
                try:
                    os.write(writer, b'S')
                finally:
                    _spawn.close_death_w(writer)
            if reader is None or self.watcher is None:
                raise ValueError("job watcher ownership missing")
            os.set_blocking(reader, False)
            deadline = time.monotonic() + _WAIT_SECONDS
            raw = bytearray()
            while time.monotonic() < deadline:
                readable, _, _ = select.select([reader], [], [], max(0, deadline - time.monotonic()))
                if not readable:
                    break
                chunk = os.read(reader, _MAX_REPLY + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > _MAX_REPLY:
                    raise ValueError('oversized job watcher response')
            report = json.loads(raw)
            if not isinstance(report, dict) or report.get('cleanup') != 'complete':
                raise ValueError('job watcher could not prove cleanup')
            while time.monotonic() < deadline:
                pid, status = os.waitpid(self.watcher, os.WNOHANG)
                if pid:
                    self.watcher = None
                    if os.waitstatus_to_exitcode(status) != 0:
                        raise ValueError('job watcher failed')
                    break
                time.sleep(.01)
            else:
                raise TimeoutError('job watcher not reaped')
            self.record.update(report)
        except BaseException as exc:
            self.record.update(_finish_scope(self.scope))
            self.record['cleanup'] = 'failed'
            self.record['cleanup_error'] = type(exc).__name__
            if not isinstance(exc, Exception):
                raise
            raise JobBudgetError('Sandbox job cleanup could not be verified', self.record) from exc
        finally:
            from ._retirement import retire_parent_resources

            def reap_watcher():
                # An unreaped owned child cannot be confused with PID reuse.
                if self.watcher is None:
                    return
                pid, _ = os.waitpid(self.watcher, os.WNOHANG)
                if not pid:
                    os.kill(self.watcher, signal.SIGKILL)
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        pid, _ = os.waitpid(self.watcher, os.WNOHANG)
                        if pid:
                            break
                        time.sleep(.01)
                if not pid:
                    raise TimeoutError('budget watcher could not be reaped')
                self.watcher = None

            def close_scope():
                scope, self.scope = self.scope, None
                if scope is not None:
                    scope.close()

            def close_receipt():
                handle, self.receipt_handle = self.receipt_handle, None
                if handle is not None and not handle.close():
                    self.record['receipt_integrity'] = 'tampered_or_unavailable'

            def retire(callback):
                def owned():
                    try:
                        callback()
                    except BaseException as exc:
                        self.record['cleanup'] = 'failed'
                        self.record['cleanup_error'] = type(exc).__name__
                        if not isinstance(exc, Exception):
                            raise
                        raise JobBudgetError('Sandbox job owner cleanup failed', self.record) from exc
                return owned

            retire_parent_resources(
                retire(reap_watcher),
                retire(lambda: os.close(reader) if reader is not None else None),
                retire(close_scope), retire(close_receipt),
            )
