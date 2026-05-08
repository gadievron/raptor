"""YAML loader for CWE-specialized strategies.

Strategies are stored under ``core/llm/cwe_strategies/strategies/``
as ``<name>.yml`` files. The format is intentionally narrow:

    name: input_handling
    description: Parsers, protocol handlers, network packet handling
    signals:
      paths: [net/, drivers/input/]
      includes: [linux/skbuff.h]
      function_keywords: [parse, decode]
    key_questions:
      - "What format/size assumptions does this code make?"
      - "Are length fields validated before use?"
    prompt_addendum: |
      Focus on bounds checks and trust boundaries on incoming data.
    exemplars:
      - cve: CVE-2023-0179
        title: nftables payload length confusion
        pattern: |
          Length field from packet trusted before bounds check.
        why_buggy: |
          Caller-controlled length used to size a copy without
          validation against the available buffer.

Unknown top-level keys are rejected — a typo in a strategy file
should fail loudly, not silently disable a signal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml

from .models import Exemplar, Signals, Strategy


class StrategyLoadError(ValueError):
    """Raised on malformed strategy YAML. Message identifies the
    file + the problem so operators editing strategies see it."""


_TOP_LEVEL_KEYS = {
    "name", "description", "signals", "key_questions",
    "prompt_addendum", "exemplars",
}
_SIGNAL_KEYS = {
    "paths", "includes", "function_keywords",
    "function_calls", "cwes",
}
_EXEMPLAR_KEYS = {"cve", "title", "pattern", "why_buggy"}


def builtin_strategies_dir() -> Path:
    """Directory containing the strategy YAMLs shipped with RAPTOR.

    Operators wanting to customise can either edit these in place
    or pass a different directory to ``load_all``.
    """
    return Path(__file__).resolve().parent / "strategies"


def _check_keys(
    where: str, data: Dict[str, Any], allowed: set,
) -> None:
    """Reject unknown keys with a clear message naming the file."""
    if not isinstance(data, dict):
        raise StrategyLoadError(f"{where}: expected mapping, got {type(data).__name__}")
    extra = set(data) - allowed
    if extra:
        raise StrategyLoadError(
            f"{where}: unknown keys {sorted(extra)}; allowed: {sorted(allowed)}"
        )


def _str_tuple(value: Any, where: str) -> Tuple[str, ...]:
    """Coerce a YAML list-of-strings into a tuple. Empty / missing
    values yield an empty tuple. Type errors raise."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise StrategyLoadError(
            f"{where}: expected list of strings, got {type(value).__name__}"
        )
    out = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise StrategyLoadError(
                f"{where}[{i}]: expected string, got {type(item).__name__}"
            )
        out.append(item)
    return tuple(out)


def _load_signals(data: Any, where: str) -> Signals:
    if data is None:
        return Signals()
    _check_keys(where, data, _SIGNAL_KEYS)
    return Signals(
        paths=_str_tuple(data.get("paths"), f"{where}.paths"),
        includes=_str_tuple(data.get("includes"), f"{where}.includes"),
        function_keywords=_str_tuple(
            data.get("function_keywords"),
            f"{where}.function_keywords",
        ),
        function_calls=_str_tuple(
            data.get("function_calls"), f"{where}.function_calls",
        ),
        cwes=_str_tuple(data.get("cwes"), f"{where}.cwes"),
    )


def _load_exemplars(data: Any, where: str) -> Tuple[Exemplar, ...]:
    if data is None:
        return ()
    if not isinstance(data, list):
        raise StrategyLoadError(
            f"{where}: expected list of exemplars, got {type(data).__name__}"
        )
    out: List[Exemplar] = []
    for i, item in enumerate(data):
        sub = f"{where}[{i}]"
        _check_keys(sub, item, _EXEMPLAR_KEYS)
        for required in ("cve", "title", "pattern", "why_buggy"):
            if required not in item:
                raise StrategyLoadError(
                    f"{sub}: missing required field {required!r}"
                )
            if not isinstance(item[required], str):
                raise StrategyLoadError(
                    f"{sub}.{required}: expected string"
                )
        out.append(Exemplar(
            cve=item["cve"],
            title=item["title"],
            pattern=item["pattern"],
            why_buggy=item["why_buggy"],
        ))
    return tuple(out)


def load_strategy(path: Path) -> Strategy:
    """Load one strategy YAML. Raises StrategyLoadError on any
    schema problem — operators editing files want loud failures."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise StrategyLoadError(f"{path}: {e}") from e
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise StrategyLoadError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise StrategyLoadError(
            f"{path}: top-level must be a mapping"
        )
    _check_keys(str(path), data, _TOP_LEVEL_KEYS)
    for required in ("name", "description"):
        if required not in data:
            raise StrategyLoadError(
                f"{path}: missing required field {required!r}"
            )
        if not isinstance(data[required], str) or not data[required]:
            raise StrategyLoadError(
                f"{path}.{required}: expected non-empty string"
            )
    return Strategy(
        name=data["name"],
        description=data["description"],
        signals=_load_signals(data.get("signals"), f"{path}.signals"),
        key_questions=_str_tuple(
            data.get("key_questions"), f"{path}.key_questions",
        ),
        prompt_addendum=str(data.get("prompt_addendum") or ""),
        exemplars=_load_exemplars(
            data.get("exemplars"), f"{path}.exemplars",
        ),
    )


def load_all(directory: Path | None = None) -> List[Strategy]:
    """Load every ``*.yml`` strategy in ``directory``.

    Defaults to the bundled strategies dir. Files are loaded in
    sorted order for stable output. Duplicate ``name`` fields raise
    — every strategy must have a unique identifier.
    """
    directory = Path(directory) if directory is not None else builtin_strategies_dir()
    if not directory.exists():
        return []
    strategies: List[Strategy] = []
    seen_names: set = set()
    for path in sorted(directory.glob("*.yml")):
        s = load_strategy(path)
        if s.name in seen_names:
            raise StrategyLoadError(
                f"{path}: duplicate strategy name {s.name!r}"
            )
        seen_names.add(s.name)
        strategies.append(s)
    return strategies
