"""Activity finalisation remains reachable after egress summary failures."""
from core.run import metadata
from core.sandbox import egress_summary
from core.testing.module_views import module_function_view
import builtins
from types import SimpleNamespace


def test_activity_finalizes_even_when_egress_summary_raises(tmp_path):
    calls = []
    def fail(*args):
        calls.append('egress')
        raise OSError('owned output refusal')
    modules = {
        'core.sandbox.egress_summary': module_function_view(egress_summary, bindings={'finalize_egress_summary': fail}),
        'core.sandbox.activity': SimpleNamespace(finalize=lambda path: calls.append(('activity', path))),
    }
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    view = module_function_view(metadata, import_hook=imports)
    view._finalize_egress_summary(tmp_path)
    assert calls == ['egress', ('activity', tmp_path)]
