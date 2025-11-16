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
        log_obj: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
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

        return json.dumps(log_obj)


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

        # File handler with JSON formatting for audit trail
        log_file = RaptorConfig.LOG_DIR / f"raptor_{int(time.time())}.jsonl"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        json_formatter = JSONFormatter()
        file_handler.setFormatter(json_formatter)
        self.logger.addHandler(file_handler)

        RaptorLogger._initialized = True

        self.info(f"RAPTOR logging initialized - audit trail: {log_file}")

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self.logger.debug(message, extra=kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self.logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self.logger.warning(message, extra=kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self.logger.error(message, extra=kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        self.logger.critical(message, extra=kwargs)

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
def get_logger() -> RaptorLogger:
    """Get the global RAPTOR logger instance."""
    return RaptorLogger()
