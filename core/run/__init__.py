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
from .output import TargetMismatchError, get_output_dir

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
