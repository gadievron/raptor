"""Owned ordinary output receipts retain primary errors during rollback."""
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.env import build


@pytest.fixture
def rollback(tmp_path, monkeypatch):
    state = SimpleNamespace(root=tmp_path, unlink_error=None, diagnostic_error=None,
                            fail_before_unlink=False, attempts=[], diagnostics=[])

    class OutputPath(type(Path())):
        def unlink(self, *args, **kwargs):
            if self.name == 'second' and state.fail_before_unlink:
                state.attempts.append(self.name)
                raise state.unlink_error
            super().unlink(*args, **kwargs)
            state.attempts.append(self.name)
            if self.name == 'second' and state.unlink_error is not None:
                raise state.unlink_error

    paths = [OutputPath(tmp_path / name) for name in ('first', 'second')]
    receipts = []
    for path in paths:
        path.write_bytes(b'inert published artifact')
        info = path.lstat()
        receipts.append((path, (info.st_dev, info.st_ino)))
    product = build.BuildProduct(ok=False)
    product.artifacts.update({p.name: p for p in paths})
    product.checksums.update({p.name: 'recorded' for p in paths})

    class DiagnosticHandler(logging.Handler):
        def emit(self, record):
            state.diagnostics.append(record)
            if state.diagnostic_error is not None:
                raise state.diagnostic_error

    logger = logging.Logger('owned-artifact-rollback', level=logging.WARNING)
    logger.propagate = False
    handler = DiagnosticHandler()
    logger.addHandler(handler)
    monkeypatch.setattr(build, 'logger', logger)
    state.product, state.paths, state.receipts = product, paths, receipts

    def run(primary):
        with build._artifact_outputs(product) as owned:
            owned.extend(receipts)
            if primary is not None:
                raise primary

    state.run = run
    try:
        yield state
    finally:
        logger.removeHandler(handler)
        handler.close()


def assert_rolled_back(state):
    assert state.attempts == ['second', 'first']
    assert not any(path.exists() for path in state.paths)
    assert not state.product.artifacts and not state.product.checksums


@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('diagnostic_type', [MemoryError, KeyboardInterrupt, SystemExit])
def test_diagnostic_failure_does_not_stop_native_rollback(rollback, primary_type, diagnostic_type):
    primary = primary_type('active publication failure')
    rollback.unlink_error = OSError('after native unlink')
    rollback.diagnostic_error = diagnostic_type('diagnostic refusal')
    with pytest.raises(primary_type) as caught:
        rollback.run(primary)
    assert caught.value is primary
    assert_rolled_back(rollback)
    assert len(rollback.diagnostics) == 1
    record = rollback.diagnostics[0]
    assert record.exc_info[1] is rollback.unlink_error
    assert record.args == (rollback.paths[1],)


def test_successful_warning_keeps_native_rollback_policy(rollback):
    primary = RuntimeError('active publication failure')
    rollback.unlink_error = OSError('after native unlink')
    with pytest.raises(RuntimeError) as caught:
        rollback.run(primary)
    assert caught.value is primary
    assert_rolled_back(rollback)
    assert len(rollback.diagnostics) == 1


def test_failed_unlink_retains_file_and_retires_sibling(rollback):
    primary = KeyboardInterrupt('active publication failure')
    rollback.unlink_error = OSError('before native unlink')
    rollback.fail_before_unlink = True
    rollback.diagnostic_error = MemoryError('diagnostic refusal')
    with pytest.raises(KeyboardInterrupt) as caught:
        rollback.run(primary)
    assert caught.value is primary
    assert rollback.attempts == ['second', 'first']
    assert not rollback.paths[0].exists()
    assert rollback.paths[1].read_bytes() == b'inert published artifact'
    assert not rollback.product.artifacts and not rollback.product.checksums
    assert len(rollback.diagnostics) == 1


def test_error_without_cleanup_fault_retires_all_receipts(rollback):
    primary = KeyboardInterrupt('active publication failure')
    with pytest.raises(KeyboardInterrupt) as caught:
        rollback.run(primary)
    assert caught.value is primary
    assert_rolled_back(rollback)
    assert rollback.diagnostics == []


def test_success_keeps_published_files_and_bookkeeping(rollback):
    rollback.run(None)
    assert rollback.attempts == [] and rollback.diagnostics == []
    assert set(rollback.product.artifacts) == {'first', 'second'}
    assert set(rollback.product.checksums) == {'first', 'second'}
    assert all(path.read_bytes() == b'inert published artifact' for path in rollback.paths)


def test_rollback_preserves_replacement_identity(rollback):
    second = rollback.paths[1]
    retired = rollback.root / 'retired'
    second.rename(retired)
    second.write_bytes(b'borrowed replacement')
    primary = SystemExit('active publication failure')
    with pytest.raises(SystemExit) as caught:
        rollback.run(primary)
    assert caught.value is primary
    assert rollback.attempts == ['first']
    assert second.read_bytes() == b'borrowed replacement'
    assert retired.read_bytes() == b'inert published artifact'
    assert not rollback.paths[0].exists()
    assert not rollback.product.artifacts and not rollback.product.checksums
    assert rollback.diagnostics == []


def test_already_absent_receipt_does_not_block_sibling(rollback):
    Path(rollback.paths[1]).unlink()
    primary = ValueError('active publication failure')
    with pytest.raises(ValueError) as caught:
        rollback.run(primary)
    assert caught.value is primary
    assert rollback.attempts == ['first']
    assert not any(path.exists() for path in rollback.paths)
    assert not rollback.product.artifacts and not rollback.product.checksums
    assert rollback.diagnostics == []
