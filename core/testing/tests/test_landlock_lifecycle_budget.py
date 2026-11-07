"""Run the actual probe lifecycle with its production and fault budgets."""
from importlib import import_module
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux Landlock probes')


@pytest.mark.parametrize('phase', [
    'normal', 'negative', 'before_verdict', 'after_verdict', 'abnormal_exit', 'read_error', 'cancel',
])
def test_native_lifecycle_preserves_success_and_fault_budgets(phase, tmp_path):
    native = import_module('core.sandbox.tests.test_landlock_probe_lifecycle')
    with pytest.MonkeyPatch.context() as scope:
        native._owned_local_probe_modules.__wrapped__(scope)
        production_budget = native.probes._PROBE_CHILD_TIMEOUT_S
        expected = production_budget if phase == 'normal' else 0.1
        real_wait = native.probes._wait_for_probe_child
        budgets = []

        def observe(*args, **kwargs):
            actual = native.probes._PROBE_CHILD_TIMEOUT_S
            budgets.append(actual)
            assert actual == expected
            return real_wait(*args, **kwargs)

        scope.setattr(native.probes, '_wait_for_probe_child', observe)
        native.test_real_probe_child_and_artifacts_are_cleaned(scope, tmp_path, phase)
        assert budgets == [expected]
