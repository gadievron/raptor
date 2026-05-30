"""Frida dynamic-instrumentation substrate for RAPTOR.

Hosts the host-side runner, CLI, and curated hook templates. The
runner attaches to (or spawns) a target via the frida Python bindings,
loads a JS hook script, captures events emitted via ``send(...)`` into
``events.jsonl``, and renders a short ``frida-report.md`` summary into
a lifecycle-managed run directory.

Not in scope:
  * Vendoring ``frida-server`` for any target architecture - the
    operator installs frida-server on the target; ``raptor doctor``
    reports availability of the host-side ``frida`` CLI.
  * LLM-autonomous instrumentation. A later integration plugs this
    substrate into ``/agentic`` and ``/validate``; the standalone
    runner is the prerequisite, not the consumer.
"""
