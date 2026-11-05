"""Resolve the historical package logger against the current logging factory."""


def __getattr__(name: str):
    if name == "logger":
        from core.logging import get_logger
        return get_logger()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
