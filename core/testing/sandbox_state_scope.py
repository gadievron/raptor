"""Own sandbox-test state and evidence descriptors before restoring callers."""

from contextlib import ExitStack, contextmanager
from types import ModuleType

from core.testing.module_state import isolated_module_state


SUMMARY_DEFAULTS = {
    "_active_run_dir": None, "_active_run_generation": 0,
    "_evidence_handle": None, "_evidence_open_failed": False,
    "_evidence_next_open_attempt": 0.0, "_denial_count": 0,
}
SUMMARY_REGISTRIES = (
    "_evidence_write_failures", "_evidence_inode_mismatches",
    "_degraded_markers", "_run_postures", "_proxy_persist_state",
    "_cli_disables", "_floor_refusals",
)


def _private_value(value):
    return value.copy() if isinstance(value, (dict, list, set)) else value


@contextmanager
def isolated_summary_state():
    """Detach borrowed state; close only owned evidence before restoring it.

    The fixture's monkeypatch stack must finish inside this scope. Otherwise
    a test-body override could reinstall a private binding after restoration.
    The evidence class inherits the real file implementation and records
    successful construction so an overwritten handle still gets closed.
    """
    from core.sandbox import summary

    owned = []
    real_evidence = summary._evidence.EvidenceFile
    real_close = real_evidence.close
    evidence = ModuleType(summary._evidence.__name__)
    vars(evidence).update(vars(summary._evidence))

    class OwnedEvidence(real_evidence):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owned.append(self)

    evidence.EvidenceFile = OwnedEvidence
    summary_state = {**SUMMARY_DEFAULTS,
                     **{name: {} for name in SUMMARY_REGISTRIES},
                     "_evidence": evidence}

    def close_handle(handle):
        try:
            handle.close()
        except BaseException:
            real_close(handle)
            raise

    with ExitStack() as scope:
        scope.enter_context(isolated_module_state(
            summary, summary_state, lock=summary._lock))
        # ExitStack runs every cleanup even when finalization or a close fails.
        with ExitStack() as cleanup:
            cleanup.callback(summary.set_active_run_dir, None)
            try:
                yield
            finally:
                for handle in owned:
                    cleanup.callback(close_handle, handle)


@contextmanager
def isolated_sandbox_state(state_names):
    """Own selected sandbox state plus summary resources for the same lifetime."""
    from core.sandbox import state

    names = (*state_names, "_speculative_failure_cache", "_unshare_engage_cache")
    replacements = {name: _private_value(getattr(state, name)) for name in names}
    with isolated_module_state(state, replacements), isolated_summary_state():
        yield
