"""Run infrastructure — metadata, lifecycle, subprocess execution.

Tracks what commands do: start, complete, fail, cancel. Every run
directory gets a .raptor-run.json recording the outcome.

Public API:
    from core.run import tracked_run, start_run, complete_run, fail_run
"""

from .metadata import (
    tracked_run, start_run, complete_run, fail_run, cancel_run,
    load_run_metadata, is_run_directory, infer_command_type,
    generate_run_metadata, parse_timestamp_from_name, RUN_METADATA_FILE,
)
from .output import get_output_dir, TargetMismatchError

__all__ = [
    "tracked_run",
    "start_run",
    "complete_run",
    "fail_run",
    "cancel_run",
    "load_run_metadata",
    "is_run_directory",
    "infer_command_type",
    "generate_run_metadata",
    "parse_timestamp_from_name",
    "get_output_dir",
    "TargetMismatchError",
    "RUN_METADATA_FILE",
]
