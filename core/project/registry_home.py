"""Single resolution seam for the operator-registry locations.

Three user-level operator registries share one location contract:

* the projects registry (``~/.raptor/projects`` — project JSON files),
* the last-activated bookmark (``<projects>/.active`` symlink),
* the sessions registry (``~/.local/share/raptor/sessions.d`` —
  session bindings, run ledgers, pin witnesses, ledger locks).

Session binding, the ``.active`` default, and ledger locking all key
on these being ONE shared set of locations for every consumer in the
process tree. Historically each consumer computed its own copy at
IMPORT time (``core.project.project.PROJECTS_DIR``,
``core.project.sessions.SESSIONS_DIR``, ``core.startup``'s
``PROJECTS_DIR``/``ACTIVE_LINK``), so an env-less product misuse or a
conftest-less test extract resolved the REAL home with no override
seam. This module is the single call-time resolver every consumer
derives from — Python (this module), the launcher's session seeder
(``bin/raptor``) and the coverage read hook
(``plugins/coverage/libexec/raptor-hook-read``) honour the same
contract in bash.

Override: ``RAPTOR_REGISTRY_HOME=<absolute dir>`` relocates ALL of
them together — ``<dir>/projects``, ``<dir>/projects/.active`` and
``<dir>/sessions.d`` — so the shared-location contract cannot split.
A non-absolute value (including a literal ``~`` — the bash consumers
cannot expand one, and the shell already expands it at export time)
is refused loudly: a cwd-relative registry would silently wander with
the process's cwd — the exact defect class this seam removes. Unset
or empty means the byte-identical historical defaults above, so
existing operator state keeps working.

Resolution is deliberately UNCACHED: every call re-reads the env, so
a consumer reading at call time sees a mid-process override change
(test harnesses re-point the registry per test) and never a stale
copy. The reads are two ``os.environ`` lookups and a couple of Path
joins — not worth a cache that could pin a torn value.

Import weight: stdlib-only. Keep it that way — ``core.startup``'s
light readers reach this module at call time.
"""

from __future__ import annotations

import os
from pathlib import Path

#: The operator-registry relocation override (absolute path only).
ENV_REGISTRY_HOME = "RAPTOR_REGISTRY_HOME"


class RegistryHomeError(ValueError):
    """A present-but-invalid ``RAPTOR_REGISTRY_HOME`` override.

    Distinct subtype so resolution corridors that swallow OTHER
    failures by design (e.g. active-project resolution falling back
    projectless past a corrupt project JSON) can escalate exactly the
    operator-override refusal — an explicit instruction that could not
    be honoured is a hard error, never a fallback — without escalating
    every ``ValueError`` in reach. Stays a ``ValueError`` so existing
    catchers keep working.
    """


def registry_home() -> Path | None:
    """The override base from ``RAPTOR_REGISTRY_HOME``, or ``None``.

    Unset/empty → ``None`` (callers use the historical defaults).
    A set-but-non-absolute value raises ``RegistryHomeError`` (a
    ``ValueError``) — loud, never a cwd-dependent registry, and
    byte-for-byte the same rule the bash consumers apply (no ``~``
    expansion on either side).
    """
    raw = os.environ.get(ENV_REGISTRY_HOME, "")
    if not raw:
        return None
    base = Path(raw)
    if not base.is_absolute():
        raise RegistryHomeError(
            f"{ENV_REGISTRY_HOME} must be an absolute path, got: {raw!r}")
    return base


def projects_dir() -> Path:
    """The projects registry directory (call-time resolution)."""
    base = registry_home()
    if base is not None:
        return base / "projects"
    return Path.home() / ".raptor" / "projects"


def sessions_dir() -> Path:
    """The sessions registry directory (call-time resolution)."""
    base = registry_home()
    if base is not None:
        return base / "sessions.d"
    return Path.home() / ".local" / "share" / "raptor" / "sessions.d"


def active_link() -> Path:
    """The last-activated ``.active`` bookmark symlink path.

    Always ``projects_dir() / ".active"`` — derived, never resolved
    independently, so the bookmark can never split from the registry
    it points into.
    """
    return projects_dir() / ".active"
