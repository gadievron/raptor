#!/usr/bin/env python3
"""
RAPTOR Structured Logging System

Provides comprehensive logging with both human-readable console output
and machine-parsable JSON audit trails.
"""

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import RaptorConfig


# Reserved attribute names on `logging.LogRecord`. Any kwarg with a
# colliding name passed via `extra=` causes
# `logging.makeRecord` → `KeyError: "Attempt to overwrite '<name>'
# in LogRecord"`. RaptorLogger filters these and renames colliders
# with an `extra_` prefix.
_RESERVED_LOGRECORD_NAMES = frozenset({
    "name", "msg", "args", "levelname", "levelno",
    "pathname", "filename", "module", "exc_info", "exc_text",
    "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName",
    "process", "message", "asctime",
})


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON string representation of log record
        """
        # ISO 8601 with timezone offset rather than the legacy
        # `%Y-%m-%d %H:%M:%S,xxx` format from `formatTime`. ISO is
        # the canonical form across the codebase (matches every
        # other tz-aware timestamp emitted by run/metadata,
        # sandbox/audit, telemetry — see batches 154, 173). Mixed
        # formats in the JSONL audit trail force consumers to
        # parse two date shapes.
        from datetime import datetime, timezone
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "job_id"):
            log_obj["job_id"] = record.job_id
        if hasattr(record, "tool"):
            log_obj["tool"] = record.tool
        if hasattr(record, "duration"):
            log_obj["duration"] = record.duration

        # `default=str` so non-JSON-native types in `extra` (Path,
        # datetime, UUID, custom dataclass repr) serialise as their
        # string form instead of crashing the format() call with
        # `TypeError: Object of type X is not JSON serializable`.
        # Pre-fix a single such kwarg from any caller anywhere
        # killed the audit-trail write for that record AND every
        # subsequent record in the same handler buffer (logging's
        # default error handler doesn't recover the formatter).
        return json.dumps(log_obj, default=str)


class RaptorLogger:
    """
    Centralized logger for RAPTOR framework.

    Provides both console and file logging with structured JSON output
    for audit trails.
    """

    _instance: Optional["RaptorLogger"] = None
    _initialized: bool = False

    def __new__(cls) -> "RaptorLogger":
        """Singleton pattern to ensure one logger instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the logger (only once)."""
        if RaptorLogger._initialized:
            return

        self.logger = logging.getLogger("raptor")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        # Ensure log directory exists
        RaptorConfig.ensure_directories()

        # Console handler with standard formatting
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(RaptorConfig.LOG_FORMAT_CONSOLE)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler with JSON formatting for audit trail.
        #
        # Filename includes PID and a 4-digit monotonic-ns tail
        # alongside the wall-clock second. Pre-fix the name was just
        # `raptor_<unix_seconds>.jsonl` — two RAPTOR processes
        # starting in the same wall-clock second computed identical
        # filenames. `logging.FileHandler` opens with mode "a"
        # (append), so the two processes' logs interleaved into one
        # file with no PID separator — operators couldn't reconstruct
        # which line came from which run.
        #
        # Same shape as `core/run/output.unique_run_suffix` (batch
        # 143): wall-clock second + pid + 4-digit monotonic-ns tail.
        import os as _os
        ns_tail = time.monotonic_ns() % 10_000
        log_file = (
            RaptorConfig.LOG_DIR
            / f"raptor_{int(time.time())}_pid{_os.getpid()}_{ns_tail:04d}.jsonl"
        )
        # `delay=True` defers opening the file until the first emit.
        # Pre-fix every `RaptorLogger()` instantiation eagerly created
        # a file in `LOG_DIR`, even for processes that:
        #
        # * Imported `core.logging` but never logged (CLI `--help`,
        #   `raptor --version`, dry-run / probe modes)
        # * Crashed before the first emit (config error, env-var
        #   validation failure)
        # * Spawned worker subprocesses that exited fast (process
        #   pool warmup, sandbox probe processes)
        #
        # Each created an empty `raptor_*.jsonl` file that
        # accumulated under `LOG_DIR` indefinitely. Operators saw
        # the dir grow with hundreds of empty files per long-lived
        # session, with no signal that any of them were empty until
        # opening one. `delay=True` only opens the file when there's
        # actually a record to write — empty processes leave no
        # trace in `LOG_DIR`.
        file_handler = logging.FileHandler(log_file, delay=True)
        file_handler.setLevel(logging.DEBUG)
        json_formatter = JSONFormatter()
        file_handler.setFormatter(json_formatter)
        self.logger.addHandler(file_handler)

        RaptorLogger._initialized = True

        self.debug(f"RAPTOR logging initialized - audit trail: {log_file}")

    def _split_kwargs(self, kwargs: dict) -> tuple:
        """Separate caller kwargs into:
          * `exc_info` / `stack_info` (logger-call params).
          * `extra` dict (the rest), with reserved LogRecord attribute
            names filtered out.

        Pre-fix only `exc_info` / `stack_info` were popped before
        passing kwargs as `extra=`. Python's `logging.makeRecord`
        raises KeyError if `extra` contains any name that collides
        with a reserved LogRecord attribute (`name`, `message`,
        `asctime`, `levelname`, `pathname`, `lineno`, `funcName`,
        `created`, `msecs`, `relativeCreated`, `thread`, `threadName`,
        `processName`, `process`, `args`, `levelno`, `module`,
        `filename`, `exc_text`). A caller passing `logger.info("hi",
        name="alice")` crashed with `KeyError: "Attempt to overwrite
        'name' in LogRecord"` — common because `name` is a natural
        kwarg name for many log payloads.

        Filter and rename: collisions get prefixed with `extra_` so
        the value still surfaces in the structured output instead
        of crashing the call.
        """
        exc_info = kwargs.pop('exc_info', False)
        stack_info = kwargs.pop('stack_info', False)
        extra = {}
        for k, v in kwargs.items():
            if k in _RESERVED_LOGRECORD_NAMES:
                extra[f"extra_{k}"] = v
            else:
                extra[k] = v
        return exc_info, stack_info, extra

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.debug(message, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.info(message, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.warning(message, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.error(message, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        # Extract reserved parameters that must not be in extra dict
        exc_info = kwargs.pop('exc_info', False)
        stack_info = kwargs.pop('stack_info', False)
        self.logger.critical(message, extra=kwargs, exc_info=exc_info, stack_info=stack_info)

    def log_job_start(self, job_id: str, tool: str, arguments: Dict[str, Any]) -> None:
        """Log job start event."""
        self.info(
            f"Job started: {tool}",
            job_id=job_id,
            tool=tool,
            arguments=str(arguments),
        )

    def log_job_complete(
        self, job_id: str, tool: str, status: str, duration: float
    ) -> None:
        """Log job completion event."""
        self.info(
            f"Job completed: {tool} ({status})",
            job_id=job_id,
            tool=tool,
            status=status,
            duration=duration,
        )

    def log_security_event(
        self, event_type: str, message: str, **kwargs: Any
    ) -> None:
        """Log security-relevant event."""
        self.warning(
            f"SECURITY: {event_type} - {message}",
            event_type=event_type,
            **kwargs,
        )


# Global logger instance
def get_logger(name: Optional[str] = None) -> "logging.Logger":
    """Get a RAPTOR logger.

    With no `name` (default): returns the singleton RaptorLogger
    wrapper for the framework's audit-trail behaviour.

    With a `name`: returns a `logging.Logger` child of "raptor"
    namespaced under that name, e.g. `get_logger("core.sarif")`
    returns `logging.getLogger("raptor.core.sarif")`. Lets modules
    distinguish their log lines for grep-by-source while still
    inheriting the framework's handler / formatter configuration
    (Python logging propagates from child to parent by default,
    so the audit-trail file handler still picks up child logs as
    long as `propagate=True`).

    Pre-fix `get_logger()` accepted no args — every caller got the
    same flat-namespace singleton, making it impossible to filter
    logs by source module without textual greps. Modules that DID
    want a per-module logger had to bypass `get_logger` entirely
    and call `logging.getLogger(__name__)` directly, defeating the
    centralisation.
    """
    # Always ensure the base singleton is initialised first
    # (handlers attached, audit file open) before any caller
    # creates a child logger that needs to inherit from it.
    base = RaptorLogger()
    if name is None:
        return base
    # Namespace under "raptor" so child propagation reaches the
    # audit handlers attached to the base "raptor" logger.
    safe_name = name if name.startswith("raptor.") else f"raptor.{name}"
    return logging.getLogger(safe_name)
