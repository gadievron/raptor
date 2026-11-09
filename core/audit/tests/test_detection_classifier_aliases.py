"""Branch-local classifier names preserve each owner's call contract."""
from types import ModuleType

import pytest

from core.audit import orchestrator
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize('module,prefix', [
    ('core.analysis.coccinelle_metadata', 'coccinelle'),
    ('core.audit.joern_verify', 'joern'),
    ('core.audit.fail_open_verify', 'fail_open'),
    ('core.audit.peer_evidence', 'consistency'),
    ('core.audit.ptr_lifecycle', 'ptr_lifecycle'),
    ('core.audit.lock_region', 'lock_region'),
    ('core.audit.resource_bounds', 'resource_bounds'),
    ('core.audit.release_order', 'release_order'),
    ('core.audit.protocol_state', 'protocol_state'),
], ids=['coccinelle', 'joern', 'fail-open', 'consistency', 'ptr-lifecycle',
        'lock-region', 'resource-bounds', 'release-order', 'protocol-state'])
@pytest.mark.parametrize('detection', [True, False], ids=['detection', 'verification'])
def test_detection_branch_preserves_owner_result_and_arguments(module, prefix, detection):
    calls = []
    tool_id = f'{prefix}:owned-rule'
    provider = ModuleType(module)

    def classify(rule_id, *, library=None):
        calls.append((rule_id, library))
        return detection

    provider.is_detection_rule_id = classify
    with scoped_function_imports(
        orchestrator, ['_is_detection_only'], {module: provider},
    ):
        assert orchestrator._is_detection_only(tool_id) is detection
    assert calls == [(tool_id, None)]
