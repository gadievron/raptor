"""
RAPTOR Structured Logging System

Provides comprehensive logging with both human-readable console output
and machine-parsable JSON audit trails.
"""

import json
import logging
import os
import sys
import threading
import time
from typing import Any, Optional, Self

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

CONSOLE_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _raptor_logger() -> logging.Logger:
    return logging.getLogger("raptor")


def _is_console_handler(handler: logging.Handler) -> bool:
    return (
        isinstance(handler, logging.StreamHandler)
        and not isinstance(handler, logging.FileHandler)
    )


def _raptor_console_handlers() -> list[logging.Handler]:
    return [handler for handler in _raptor_logger().handlers if _is_console_handler(handler)]


def _raptor_root_console_handlers() -> list[logging.Handler]:
    return [
        handler for handler in logging.getLogger().handlers
        if _is_console_handler(handler)
        and getattr(handler, "_raptor_root_handler", False)
    ]


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging."""

    _STANDARD_ATTRS = frozenset(logging.LogRecord(
        "", 0, "", 0, "", (), None,
    ).__dict__)

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
        log_obj: dict[str, Any] = {
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

        for key, value in record.__dict__.items():
            if key not in self._STANDARD_ATTRS and key not in log_obj:
                log_obj[key] = value

        # `default=str` so non-JSON-native types in `extra` (Path,
        # datetime, UUID, custom dataclass repr) serialise as their
        # string form instead of crashing the format() call with
        # `TypeError: Object of type X is not JSON serializable`.
        # Pre-fix a single such kwarg from any caller anywhere
        # killed the audit-trail write for that record AND every
        # subsequent record in the same handler buffer (logging's
        # default error handler doesn't recover the formatter).
        return json.dumps(log_obj, default=str)


# Characters that make up decorative separator banners. Several CLIs
# print `logger.info("=" * 70)` framing for the console; persisted into
# the JSONL audit trail they are pure noise (hundreds of records per
# long run whose message is 70 equals-signs).
_SEPARATOR_CHARS = set("=-─═*# ")


def _drop_separator_records(record: logging.LogRecord) -> bool:
    """Handler filter: False for records that are only a separator."""
    try:
        msg = record.getMessage().strip()
    except Exception:  # noqa: BLE001 — malformed record: let it through
        return True
    return not (len(msg) >= 10 and set(msg) <= _SEPARATOR_CHARS)


class _OwnerOnlyFileHandler(logging.FileHandler):
    """``FileHandler`` whose audit file is created owner-only (0o600).

    The JSONL audit trail persists exception bodies and prompt
    fragments; the stdlib default 0644 let any other local user read
    them on a shared host. Match the deliberate 0o600 on the LLM
    response cache and ``LLMConfig.to_file``. Mode is applied at
    creation via ``os.open`` (not a post-hoc chmod), so there is no
    world-readable window; a stricter umask still tightens further.
    """

    def _open(self):
        fd = os.open(
            self.baseFilename,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            return open(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except Exception:
            os.close(fd)
            raise


def _file_log_level() -> int:
    """Audit-trail file level: INFO unless RAPTOR_LOG_FILE_LEVEL says
    otherwise (unknown names fall back to INFO rather than erroring
    during logger bootstrap)."""
    name = os.environ.get("RAPTOR_LOG_FILE_LEVEL", "").strip().upper()
    if name:
        level = getattr(logging, name, None)
        if isinstance(level, int):
            return level
    return logging.INFO


class RaptorLogger:
    """
    Centralized logger for RAPTOR framework.

    Provides both console and file logging with structured JSON output
    for audit trails.
    """

    _instance: Optional["RaptorLogger"] = None
    _initialized: bool = False
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> Self:
        """Singleton pattern to ensure one logger instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the logger (only once)."""
        if RaptorLogger._initialized:
            return
        with RaptorLogger._lock:
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
            ns_tail = time.monotonic_ns() % 10_000
            log_file = (
                RaptorConfig.LOG_DIR
                / f"raptor_{int(time.time())}_pid{os.getpid()}_{ns_tail:04d}.jsonl"
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
            file_handler = _OwnerOnlyFileHandler(log_file, delay=True)
            # Default INFO, not DEBUG. At DEBUG the audit trail
            # persisted every per-LLM-call line (usage/cost, "Using
            # model", "Structured generation successful") and 3-4
            # provider-init lines per task — roughly half of a typical
            # file was this repetition. Investigations that need the
            # full firehose opt back in per run:
            #   RAPTOR_LOG_FILE_LEVEL=DEBUG
            file_handler.setLevel(_file_log_level())
            # Decorative separator banners ("====...====", "----")
            # belong on the console, not in a JSONL audit trail —
            # filter them from the file only.
            file_handler.addFilter(_drop_separator_records)
            json_formatter = JSONFormatter()
            file_handler.setFormatter(json_formatter)
            self.logger.addHandler(file_handler)

            # Also attach the SAME console handler to the root logger so
            # INFO-level messages from modules that use the stdlib
            # ``logging.getLogger(__name__)`` pattern (108+ modules in
            # this codebase, e.g. ``packages.llm_analysis.dataflow_validation``)
            # surface in operator output. Pre-fix, RAPTOR's handlers
            # were attached only to the "raptor" namespace; stdlib-named
            # loggers propagated to root, found no handler, and INFO
            # messages were silently dropped — most visible in
            # subprocess contexts (e.g. ``agent.py`` running under
            # ``raptor agentic``) where no other code calls basicConfig.
            #
            # Root level set to INFO so module-level INFO surfaces
            # without flooding with third-party DEBUG. Third-party
            # libraries that emit INFO (httpx request lines, openai
            # client status, etc.) will surface too — same behaviour
            # operators already see in scripts that call basicConfig,
            # so no behaviour regression.
            #
            # ``self.logger.propagate = False`` (line above) means the
            # "raptor" namespace doesn't double-fire to the root
            # handler. Stdlib-named loggers do propagate, get handled
            # at root, and their format follows the same
            # LOG_FORMAT_CONSOLE shape as raptor's own messages.
            root_logger = logging.getLogger()
            # Idempotent guard: only attach once even if RaptorLogger
            # is re-instantiated (shouldn't happen via the singleton,
            # but the file handler's eager initialisation has been a
            # source of bugs before — see the audit-trail filename
            # comment above).
            if not _raptor_root_console_handlers():
                root_console = logging.StreamHandler(sys.stderr)
                root_console.setLevel(logging.INFO)
                root_console.setFormatter(console_formatter)
                root_console._raptor_root_handler = True  # sentinel for the guard above
                root_logger.addHandler(root_console)
                # Ensure root accepts INFO-level records; default is WARNING.
                if root_logger.level == logging.NOTSET or root_logger.level > logging.INFO:
                    root_logger.setLevel(logging.INFO)

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

    # ── Level methods ──────────────────────────────────────────────
    #
    # All five accept the standard stdlib `logging.Logger` signature
    # `(message, *args, **kwargs)` so format strings work natively:
    #
    #     logger.info("Processing %s files", count)
    #     logger.warning("%(host)s failed: %(err)s", {"host": h, "err": e})
    #
    # `args` flows through to `self.logger.<level>(...)`; the stdlib
    # `LogRecord.getMessage()` applies %-formatting lazily (only when
    # a handler is at the right level), so DEBUG calls cost nothing
    # when the configured level is WARNING.
    #
    # Pre-fix the signature was `(message, **kwargs)` — positional
    # args raised `TypeError: info() takes 2 positional arguments but
    # 3 were given`, forcing callers into eagerly-formatted f-strings.
    # See `get_logger("name")` which already returned a raw stdlib
    # `logging.Logger`; the two surfaces are now consistent.

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.debug(message, *args, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log info message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.info(message, *args, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.warning(message, *args, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log error message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.error(message, *args, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message."""
        exc_info, stack_info, extra = self._split_kwargs(kwargs)
        self.logger.critical(message, *args, extra=extra, exc_info=exc_info, stack_info=stack_info)

    def log_security_event(
        self, event_type: str, message: str, **kwargs: Any
    ) -> None:
        """Log security-relevant event.

        Observability stream, not a control: emitters call this on
        rejection / denial / fail-closed paths whose behaviour is
        already decided. The call must therefore NEVER raise — a
        broken sink (unwritable audit file, closed stderr, handler
        misconfiguration) must not turn a working rejection into a
        crash. Same rationale as ``_drop_separator_records``'s
        malformed-record guard.

        Payload hygiene contract for emitters: ``message`` and
        ``kwargs`` carry the event type and path / URL / context
        IDENTIFIERS only — never environment values, key material,
        or other secrets. Callers logging URLs must redact userinfo
        first (``core.security.redaction``).
        """
        try:
            self.warning(
                f"SECURITY: {event_type} - {message}",
                event_type=event_type,
                **kwargs,
            )
        except Exception:  # noqa: BLE001, S110 — observability must never break the emitter
            pass


def log_security_event(event_type: str, message: str, **kwargs: Any) -> None:
    """Module-level convenience for :meth:`RaptorLogger.log_security_event`.

    The security-event stream predates the per-module logger split:
    when it was introduced, every emitter held the RaptorLogger
    singleton (``get_logger()``) and called the method directly.
    Modules have since moved to stdlib per-module loggers
    (``logging.getLogger(__name__)``), which don't carry the method —
    this function lets those modules emit without switching logger
    styles.

    Never raises: on top of the method's own guard, this covers
    RaptorLogger initialisation failure (e.g. ``LOG_DIR`` cannot be
    created during bootstrap). Emission is best-effort by design.
    """
    try:
        RaptorLogger().log_security_event(event_type, message, **kwargs)
    except Exception:  # noqa: BLE001, S110 — observability must never break the emitter
        pass


# Global logger instance
def get_logger(name: str | None = None) -> "logging.Logger":
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


def set_console_log_level(level: int, *, include_root: bool = False) -> None:
    """Set operator-facing console verbosity without touching file audit logs."""
    # Ensure RAPTOR handlers exist before mutating them.
    RaptorLogger()

    for handler in _raptor_console_handlers():
        handler.setLevel(level)

    if not include_root:
        return

    root_logger = logging.getLogger()
    for handler in _raptor_root_console_handlers():
        handler.setLevel(level)
    root_logger.setLevel(level)


def configure_run_logging(log_level: str | None, verbose: bool) -> None:
    """Apply run-level console logging flags."""
    if log_level:
        set_console_log_level(getattr(logging, log_level.upper()), include_root=True)
    elif verbose:
        set_console_log_level(logging.DEBUG, include_root=True)
