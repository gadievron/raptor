import os
from pathlib import Path

# core/startup/__init__.py → core/ → raptor/ (repo root)
REPO_ROOT = Path(__file__).resolve().parents[2]


def _projects_dir() -> Path:
    """The projects registry directory for THIS call.

    Historically an import-time copy of ``Path.home() / ".raptor" /
    "projects"`` — which resolved the REAL home with no override seam
    (env-less product misuse; conftest-less test extracts). Now
    resolved at call time through the shared operator-registry seam
    (``core.project.registry_home``, honouring
    ``RAPTOR_REGISTRY_HOME``) — imported inside the accessor so a bare
    ``import core.startup`` stays as light as before.

    Test-estate compatibility: a module-dict entry named
    ``PROJECTS_DIR`` (the suite-wide ``monkeypatch.setattr`` /
    ``mock.patch`` pin spelling) takes precedence over the seam.
    """
    override = globals().get("PROJECTS_DIR")
    if override is not None:
        return Path(override)
    from core.project import registry_home
    return registry_home.projects_dir()


def _active_link() -> Path:
    """The ``.active`` bookmark path for THIS call.

    Derivation order keeps the single-location contract under every
    pin spelling: an explicit ``ACTIVE_LINK`` module-dict override
    wins; else a ``PROJECTS_DIR`` override anchors the link INSIDE the
    patched registry (pre-seam, a test that pinned only
    ``PROJECTS_DIR`` left the import-time ``ACTIVE_LINK`` pointing at
    the real home); else the seam resolves both from one base.
    """
    override = globals().get("ACTIVE_LINK")
    if override is not None:
        return Path(override)
    projects_override = globals().get("PROJECTS_DIR")
    if projects_override is not None:
        return Path(projects_override) / ".active"
    from core.project import registry_home
    return registry_home.active_link()


def __getattr__(name: str) -> Path:
    # PEP 562: the historical constant names stay importable but now
    # resolve at ACCESS time through the seam. Only reached when no
    # module-dict override exists — a test's setattr wins by
    # construction.
    if name == "PROJECTS_DIR":
        return _projects_dir()
    if name == "ACTIVE_LINK":
        return _active_link()
    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}")


def _expired_light(name):
    """Light machine-project expiry probe (no ProjectManager import):
    only machine-named projects (``is_machine_project_name``) can
    expire — a hand-edited ``expires_at`` on an operator project must
    never deactivate it here when ``get_active`` (which applies the
    name gate) would keep it. Unparseable = not expired (fail open)."""
    import json
    from datetime import datetime, timezone
    try:
        from core.project.project import is_machine_project_name
        if not is_machine_project_name(name):
            return False
    except Exception:  # noqa: BLE001 — predicate unavailable: fail open
        return False
    try:
        data = json.loads((_projects_dir() / f"{name}.json").read_text(
            encoding="utf-8"))
        expires = data.get("expires_at") if isinstance(data, dict) else None
        if not expires:
            return False
        # str() + TypeError in the net: fromisoformat(non-str) raises
        # TypeError, which escaped and crashed every start_run on one
        # corrupt project file — while get_active (str-coercing)
        # reported the project healthy. The two must never disagree.
        stamp = datetime.fromisoformat(str(expires))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp < datetime.now(timezone.utc)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return False


def get_active_name():
    """The active project name for THIS context, or None — layered
    like ``ProjectManager.get_active()``: session binding
    first (authoritative, incl. bound-to-none and the stale-binding
    rule), then the last-activated ``.active`` symlink. Both layers
    get the machine-expiry vet, so the two chokepoints can never
    resolve DIFFERENT projects within one run (remediation — clearing
    the producing layer — is get_active()'s job; this reader only
    agrees on the result).

    Lightweight — no ProjectManager import (the sessions module is
    os/pathlib-only).

    TOCTOU-safe symlink read: `os.readlink` first, catch `OSError`
    (covers not-a-symlink and deleted-between-checks); the caller's
    next operation against the project file is the authoritative
    existence test.
    """
    try:
        from core.project.sessions import session_binding
        name, state = session_binding()
    except Exception:  # noqa: BLE001 — registry failure = symlink layer
        name, state = None, "absent"
    if state == "bound" and name is not None:
        if not (_projects_dir() / f"{name}.json").exists():
            return None  # stale binding — authoritative none
        if _expired_light(name):
            return None
        return name
    if state == "none":
        return None
    try:
        target = os.readlink(_active_link())
    except OSError:
        return None
    if target.endswith(".json") and "/" not in target and "\\" not in target:
        name = target[:-5]
        if not (_projects_dir() / target).exists():
            return None  # dangling bookmark — same answer get_active gives
        if _expired_light(name):
            return None
        return name
    return None
