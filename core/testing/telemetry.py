"""Give tests a private prompt-defense collector without clearing borrowed state."""


def pin_defense_telemetry(monkeypatch, *consumers):
    """Install one fresh collector on the caller's monkeypatch undo stack.

    Consumers with an import-time ``defense_telemetry`` alias must be named
    explicitly. Runtime imports from prompt_telemetry see the same collector.
    The borrowed collector is never reset, including when fixture setup fails.
    """
    from core.security import prompt_telemetry

    collector = prompt_telemetry.DefenseTelemetry()
    for module in (prompt_telemetry, *consumers):
        monkeypatch.setattr(module, "defense_telemetry", collector)
    return collector
