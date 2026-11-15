"""Validation of optional solver witness objectives, without native allocation."""


def parse_witness_preference(
    spec: str | tuple[str, str] | None,
) -> tuple[str, str] | None:
    """Normalise a prefer_witness spec.

    Accepts either a ``(name, direction)`` tuple or a colon-separated
    string ``"max:varname"`` / ``"min:varname"`` (the form the libexec
    shim CLI parses out of a single ``--prefer-witness`` argument).

    Stored tuple fields and string characters define the objective;
    subclass protocols cannot replace or silently drop it.

    Returns ``None`` when input is ``None`` or empty.  Raises
    ``TypeError`` on unsupported input types and ``ValueError`` on malformed
    fields, so the caller fails fast rather
    than silently dropping the objective.
    """
    if spec is None:
        return None
    if isinstance(spec, tuple):
        size = tuple.__len__(spec)
        if size != 2:
            msg = f"prefer_witness tuple must be (name, direction), got {size} fields"
            raise ValueError(msg)
        name, direction = tuple.__getitem__(spec, 0), tuple.__getitem__(spec, 1)
    elif isinstance(spec, str):
        spec = str.__str__(spec)
        if spec == "":
            return None
        if ":" not in spec:
            msg = (
                f"prefer_witness string must be 'max:name' or 'min:name', "
                f"got {spec!r}"
            )
            raise ValueError(msg)
        direction, _, name = spec.partition(":")
    else:
        msg = (
            f"prefer_witness must be tuple, str, or None — got "
            f"{type(spec).__name__}"
        )
        raise TypeError(msg)
    if not isinstance(name, str) or not isinstance(direction, str):
        raise ValueError("prefer_witness name and direction must be strings")
    direction = str.__str__(direction).strip().lower()
    name = str.__str__(name).strip()
    if direction not in ("max", "min"):
        msg = (
            f"prefer_witness direction must be 'max' or 'min', "
            f"got {direction!r}"
        )
        raise ValueError(msg)
    if not name:
        msg = "prefer_witness variable name must not be empty"
        raise ValueError(msg)
    return (name, direction)
