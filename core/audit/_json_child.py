"""Child-process bootstrap for :mod:`core.audit.subproc_json`.

Executed as a NAMED script by path (``python <this file> module:func``),
never via ``python -c``: an interpreter launched with an inline
importlib-dispatch blob is indistinguishable from a malware loader to
endpoint-security heuristics, while an on-disk script inside the RAPTOR
tree is attributable and auditable. Same protocol as before the split:

* ``argv[1]`` names the dispatch entry as ``module:function``;
* the request arrives as JSON on stdin;
* the JSON-encoded result leaves on stdout.

``default=str`` coerces any non-JSON-native leaf (a stray solver term
in a witness dict) to its string form instead of crashing the child —
the verdict fields the parents read are all JSON-native. Child stdout
is decoded as JSON by the parent, never as a Python object stream (see
the package-side docstring in :mod:`core.audit.subproc_json`).

Import resolution is pinned to ``RAPTOR_DIR`` (hard lookup — KeyError
when unset is the correct failure): ``sys.path[0]`` — the directory of
this script, which Python prepends for path-executed scripts — is
REPLACED, not appended to, so the child sees exactly one RAPTOR tree
and this package directory can never shadow stdlib modules.
"""

import importlib
import json
import os
import sys


_ALLOWED_ENTRIES = frozenset({
    "core.audit.condition_smt:_z3_dispatch_json",
    "core.audit.sweep:_run_smt_verb_inner_json",
})


def main() -> None:
    entry = sys.argv[1]
    if entry not in _ALLOWED_ENTRIES:
        raise SystemExit(f"_json_child: entry {entry!r} not in allowlist")
    sys.path[:1] = [os.environ["RAPTOR_DIR"]]
    mod, _, func = entry.rpartition(":")
    fn = getattr(importlib.import_module(mod), func)
    result = fn(json.loads(sys.stdin.buffer.read().decode("utf-8")))
    sys.stdout.write(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
