"""Template scaffolding for atheris (Python) fuzz harnesses.

Atheris drives a Python ``TestOneInput(data: bytes)`` callback the way
libFuzzer drives ``LLVMFuzzerTestOneInput``. Operators usually write
that harness themselves; for the simple case — a target function that
takes a single ``bytes`` or ``str`` argument — this module generates
one mechanically from an operator-named ``module:function`` entry
point. Deliberately template-only: no LLM is involved, the emitted
source is a fixed skeleton with validated identifier slots, and the
file is clearly marked as generated so nobody mistakes it for a
reviewed harness.

The entry-point grammar is strict (dotted Python identifiers only) —
the names are interpolated into source code that is subsequently
EXECUTED against untrusted package code, so anything that is not a
plain identifier chain is rejected at spec construction, never
escaped.
"""

from __future__ import annotations

import keyword
import re
from dataclasses import dataclass
from pathlib import Path

from core.logging import get_logger

logger = get_logger()

#: Payload shapes the scaffold knows how to feed the target function.
PAYLOAD_MODES = ("bytes", "text")

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_ENTRY_LEN = 256


def _validate_dotted_name(name: str, what: str) -> str:
    """Validate a dotted Python name (``pkg.mod`` / ``func``).

    Every segment must be a non-keyword Python identifier. Raises
    ValueError otherwise — the name lands verbatim in generated,
    executed source, so there is no escaping fallback.
    """
    if not name or len(name) > _MAX_ENTRY_LEN:
        msg = f"{what} must be a non-empty dotted name of at most {_MAX_ENTRY_LEN} characters"
        raise ValueError(msg)
    for segment in name.split("."):
        if not _IDENTIFIER_RE.match(segment) or keyword.iskeyword(segment):
            msg = (
                f"{what} must be a chain of Python identifiers "
                f"(got {name!r})"
            )
            raise ValueError(msg)
    return name


@dataclass
class AtherisHarnessSpec:
    """Specification for a scaffolded atheris harness.

    ``entry`` is the operator's ``module:function`` string —
    ``json:loads``, ``mypkg.parser:parse_bytes``. ``payload`` selects
    what the fuzzer bytes become before the call: ``bytes`` passes
    them through, ``text`` derives a str via
    ``FuzzedDataProvider.ConsumeUnicodeNoSurrogates``.
    """

    entry: str
    payload: str = "bytes"
    module: str = ""
    function: str = ""

    def __post_init__(self) -> None:
        if self.payload not in PAYLOAD_MODES:
            msg = f"payload must be one of {PAYLOAD_MODES}, got {self.payload!r}"
            raise ValueError(msg)
        if ":" not in self.entry:
            msg = (
                f"entry point must be 'module:function' "
                f"(got {self.entry!r})"
            )
            raise ValueError(msg)
        module, function = self.entry.split(":", 1)
        self.module = _validate_dotted_name(module, "entry module")
        # Dotted function chains (``Cls.method``) stay valid targets.
        self.function = _validate_dotted_name(function, "entry function")


_HARNESS_TEMPLATE = '''\
#!/usr/bin/env python3
"""GENERATED atheris harness — RAPTOR template scaffold, not a reviewed harness.

Target: {module}.{function}({payload_desc})

This is the mechanical simple-case scaffold: the fuzzer bytes go into
the target function as a single argument, and EVERY uncaught exception
counts as a crash. If the target legitimately raises on malformed
input (ValueError on a parser, for example), edit TestOneInput to
swallow those expected types before trusting the crash list.
"""

import sys

import atheris

with atheris.instrument_imports():
    import {import_module}


def TestOneInput(data: bytes) -> None:
{payload_prep}    {module}.{function}(payload)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
'''

_PAYLOAD_PREP = {
    "bytes": "    payload = data\n",
    "text": (
        "    fdp = atheris.FuzzedDataProvider(data)\n"
        "    payload = fdp.ConsumeUnicodeNoSurrogates(len(data))\n"
    ),
}

_PAYLOAD_DESC = {"bytes": "bytes", "text": "str"}


def generate_atheris_harness(spec: AtherisHarnessSpec) -> str:
    """Render the harness source for *spec*."""
    # ``import a.b.c`` binds the top-level package name; the call site
    # uses the full dotted module path, which that import makes
    # resolvable.
    return _HARNESS_TEMPLATE.format(
        module=spec.module,
        function=spec.function,
        import_module=spec.module,
        payload_prep=_PAYLOAD_PREP[spec.payload],
        payload_desc=_PAYLOAD_DESC[spec.payload],
    )


def write_atheris_harness(spec: AtherisHarnessSpec, out_dir: Path) -> Path:
    """Write the scaffolded harness under *out_dir* and return its path.

    Filename is derived from the validated identifiers only, so it can
    never act as a path.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"fuzz_{spec.module.replace('.', '_')}_{spec.function.replace('.', '_')}.py"
    target = out_dir / name
    target.write_text(generate_atheris_harness(spec), encoding="utf-8")
    logger.info("Wrote generated atheris harness: %s", target)
    return target
