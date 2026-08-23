"""Crash-isolated JSON child calls for the Z3/SMT verification layer.

One parameterised runner replaces the near-identical per-verb pickle
subprocess wrappers in :mod:`core.audit.condition_smt` and
:mod:`core.audit.sweep`. The child protocol is JSON — dataclass
arguments and results are flattened to plain dicts by the dispatchers
on each side — so child stdout is never unpickled: a future sandboxing
of the solver children is not defeated by an object-deserialisation
channel, and a compromised/crashed child can at worst hand back
malformed JSON (decoded to ``None`` here).

Crash-isolation semantics are unchanged from the pickle runners: the
child is a fresh, single-threaded ``fork+exec`` interpreter, so Z3
assertion failures (segfaults in the C++ core) kill only the child and
degrade to ``None``.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Generic child bootstrap — a NAMED sibling script executed by path
#: (see :mod:`core.audit._json_child` for the protocol). Deliberately
#: not ``python -c`` with an inline blob: endpoint-security heuristics
#: cannot tell an inline importlib-dispatch one-liner from a malware
#: loader, and this child fires once per SMT/Z3 verification. The
#: path is resolved from THIS module's location so parent and child
#: always come from the same tree (the child then re-pins its imports
#: to the ``RAPTOR_DIR`` the caller's env carries).
_CHILD_SCRIPT_PATH = str(Path(__file__).resolve().with_name("_json_child.py"))


def run_json_child(
    entry: str,
    request: Any,
    *,
    env: dict,
    timeout: int = 10,
    label: str = "",
) -> Any:
    """Run dispatch function *entry* (``module:function``) in a child.

    *request* must be JSON-serialisable; the child function receives
    the decoded object as its single argument and must return a
    JSON-serialisable result. *env* is the sanitised child environment
    (callers pass their ``smt_child_env()`` / ``_z3_child_env()`` —
    ``RAPTOR_DIR`` pinned to this tree, LLM surface stripped).

    Returns the decoded result, or ``None`` when the child crashed,
    timed out, exited nonzero, or produced undecodable output.
    """
    tag = label or entry
    try:
        request_bytes = json.dumps(request).encode("utf-8")
    except (TypeError, ValueError):
        logger.debug(
            "json child request not serialisable (%s)", tag, exc_info=True,
        )
        return None
    try:
        proc = subprocess.run(
            [sys.executable, _CHILD_SCRIPT_PATH, entry],
            input=request_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        logger.debug("json child timed out after %ds (%s)", timeout, tag)
        return None
    if proc.returncode != 0:
        logger.debug(
            "json child exited %d (%s)", proc.returncode, tag,
        )
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        logger.debug("json child output undecodable (%s)", tag)
        return None
