"""Actual logging fixture helper preserves borrowed instance bindings."""
from contextlib import ExitStack
import pytest
import core.audit.tests.test_prefilter as native

@pytest.mark.parametrize('phase', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('layout', ['absent', 'present', 'mixed'])
def test_actual_helper_preserves_exact_logger_entries(phase, layout):
    logger = native._prefilter.logger
    with ExitStack() as owner:
        for key in ('warning', 'debug'):
            if key in vars(logger):
                owner.callback(setattr, logger, key, vars(logger)[key])
            else:
                owner.callback(vars(logger).pop, key, None)
            vars(logger).pop(key, None)
            if layout == 'present' or (layout == 'mixed' and key == 'warning'):
                setattr(logger, key, native.TestPhpSqlInjectionFailSafe._Recorder())
        configured = {key: (key in vars(logger), vars(logger).get(key)) for key in ('warning', 'debug')}
        error = KeyboardInterrupt if phase == 'interrupt' else RuntimeError
        def invoke():
            with pytest.MonkeyPatch.context() as patch:
                warning, debug = native.TestPhpSqlInjectionFailSafe._Recorder(), native.TestPhpSqlInjectionFailSafe._Recorder()
                native.TestPhpSqlInjectionFailSafe()._log_with(patch, warning, debug)
                logger.warning('owned warning')
                logger.debug('owned debug')
                assert len(warning.calls) == len(debug.calls) == 1
                if phase != 'normal':
                    raise error('owned caller exit')
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned caller exit'):
                invoke()
        for key, (present, value) in configured.items():
            assert (key in vars(logger)) == present
            assert vars(logger).get(key) is value
