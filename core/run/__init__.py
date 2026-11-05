"""Run infrastructure — metadata, lifecycle, subprocess execution.

Tracks what commands do: start, complete, fail, cancel. Every run
directory gets a .raptor-run.json recording the outcome.

Public API:
    from core.run import tracked_run, start_run, complete_run, fail_run, cancel_run
"""

from .metadata import (
    RUN_METADATA_FILE,
    RunOwnershipError,
    cancel_run,
    complete_run,
    ensure_run_command,
    fail_run,
    generate_run_metadata,
    infer_command_type,
    interrupt_run,
    is_run_directory,
    load_run_metadata,
    parse_timestamp_from_name,
    resume_run,
    start_run,
    tracked_run,
)

# Metadata is a lightweight startup dependency. Output resolution imports the
# full configuration, so load these exports only for callers that need them.
# Reloading the package must refresh aliases just as eager re-exports did.
for _cached_export in globals().get("_LAZY_EXPORTS", ()):
    globals().pop(_cached_export, None)
globals().pop("_cached_export", None)

_LAZY_EXPORTS = {
    "output": ("core.run.output", None),
    "TargetMismatchError": ("core.run.output", "TargetMismatchError"),
    "get_output_dir": ("core.run.output", "get_output_dir"),
}


def __getattr__(name: str):
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module_name, attribute = spec
    module = import_module(module_name)
    value = module if attribute is None else getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))

__all__ = [
    "RUN_METADATA_FILE",
    "RunOwnershipError",
    "TargetMismatchError",
    "cancel_run",
    "complete_run",
    "ensure_run_command",
    "fail_run",
    "generate_run_metadata",
    "get_output_dir",
    "infer_command_type",
    "interrupt_run",
    "is_run_directory",
    "load_run_metadata",
    "parse_timestamp_from_name",
    "resume_run",
    "start_run",
    "tracked_run",
]
