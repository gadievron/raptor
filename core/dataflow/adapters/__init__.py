"""Per-producer adapters that convert producer-native finding shapes
into :class:`core.dataflow.Finding`.

Each adapter is independent — adding a new producer (Semgrep, IRIS-direct,
dynamic-web) means adding a new module here, not changing existing ones.
The :class:`Finding` schema is the only contract.
"""
