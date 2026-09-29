"""The operator-registry resolution seam (core.project.registry_home).

The projects registry, the ``.active`` bookmark, and the sessions
registry are ONE shared-location contract: every consumer must derive
all three from the same call-time resolution, honouring the
``RAPTOR_REGISTRY_HOME`` override, with byte-identical historical
defaults when the override is unset. These tests pin:

* defaults unchanged without the env (read-only assertions — nothing
  here ever writes to the real home);
* the override moves all three TOGETHER and mutually consistent;
* resolution is call-time — a mid-process env change is visible
  through the seam and through the consumer modules;
* the consumer modules (``core.project.project``,
  ``core.project.sessions``, ``core.startup``) resolve their
  historical attribute names through the seam;
* the test-estate contract survives: a module-attribute patch
  (``monkeypatch.setattr(sessions, "SESSIONS_DIR", ...)`` and the
  ``mock.patch`` spellings across the suite) still overrides what the
  in-module consumers use.

Hermetic: overrides always point into per-test scratch; the
default-path assertions are pure path comparisons.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import core.startup as startup
from core.project import registry_home
from core.project import project as project_mod
from core.project import sessions as sessions_mod


@pytest.fixture(autouse=True)
def _bare_seam(monkeypatch: pytest.MonkeyPatch):
    """Expose the seam: clear the override env and any module-dict
    shadows of the historical constant names (the root conftest's
    autouse registry pins, and values frozen into the module dict by
    earlier tests' patch teardowns). ``monkeypatch`` restores both
    layers afterwards, so the surrounding isolation is untouched."""
    monkeypatch.delenv(registry_home.ENV_REGISTRY_HOME, raising=False)
    monkeypatch.delattr(project_mod, "PROJECTS_DIR", raising=False)
    monkeypatch.delattr(sessions_mod, "SESSIONS_DIR", raising=False)
    monkeypatch.delattr(startup, "PROJECTS_DIR", raising=False)
    monkeypatch.delattr(startup, "ACTIVE_LINK", raising=False)


# ---------------------------------------------------------------- seam


def test_defaults_byte_identical_without_env() -> None:
    home = Path.home()
    assert registry_home.registry_home() is None
    assert registry_home.projects_dir() == home / ".raptor" / "projects"
    assert registry_home.sessions_dir() == (
        home / ".local" / "share" / "raptor" / "sessions.d")
    assert registry_home.active_link() == (
        home / ".raptor" / "projects" / ".active")


def test_empty_env_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "")
    assert registry_home.registry_home() is None
    assert registry_home.projects_dir() == (
        Path.home() / ".raptor" / "projects")


def test_override_moves_all_three_together(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    base = tmp_path / "reg"
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(base))
    assert registry_home.projects_dir() == base / "projects"
    assert registry_home.sessions_dir() == base / "sessions.d"
    assert registry_home.active_link() == base / "projects" / ".active"
    # Mutual consistency: the bookmark lives INSIDE the projects
    # registry, and both share the sessions registry's base — the
    # shared-location contract cannot split under one override.
    assert registry_home.active_link().parent == registry_home.projects_dir()
    assert registry_home.projects_dir().parent == base
    assert registry_home.sessions_dir().parent == base


def test_call_time_env_change_flows_through(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "a"))
    first = registry_home.projects_dir()
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "b"))
    second = registry_home.projects_dir()
    assert first == tmp_path / "a" / "projects"
    assert second == tmp_path / "b" / "projects"


def test_relative_override_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "relative/dir")
    with pytest.raises(ValueError, match="RAPTOR_REGISTRY_HOME"):
        registry_home.registry_home()


def test_literal_tilde_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # No expansion on either side of the contract: the bash consumers
    # (launcher seeder, coverage read hook) cannot expand a literal
    # ``~``, so the python seam must not silently accept one and split
    # the registry between the two worlds.
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "~/reg")
    with pytest.raises(ValueError, match="RAPTOR_REGISTRY_HOME"):
        registry_home.projects_dir()


# ---------------------------------------------------------- consumers


def test_module_attributes_resolve_through_seam(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    base = tmp_path / "reg"
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(base))
    assert project_mod.PROJECTS_DIR == base / "projects"
    assert sessions_mod.SESSIONS_DIR == base / "sessions.d"
    assert startup.PROJECTS_DIR == base / "projects"
    assert startup.ACTIVE_LINK == base / "projects" / ".active"


def test_module_attributes_are_call_time(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "a"))
    before = (project_mod.PROJECTS_DIR, sessions_mod.SESSIONS_DIR,
              startup.ACTIVE_LINK)
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "b"))
    after = (project_mod.PROJECTS_DIR, sessions_mod.SESSIONS_DIR,
             startup.ACTIVE_LINK)
    assert before == (tmp_path / "a" / "projects",
                      tmp_path / "a" / "sessions.d",
                      tmp_path / "a" / "projects" / ".active")
    assert after == (tmp_path / "b" / "projects",
                     tmp_path / "b" / "sessions.d",
                     tmp_path / "b" / "projects" / ".active")


def test_unknown_module_attribute_still_raises() -> None:
    with pytest.raises(AttributeError):
        _ = sessions_mod.NO_SUCH_REGISTRY_CONSTANT
    with pytest.raises(AttributeError):
        _ = project_mod.NO_SUCH_REGISTRY_CONSTANT
    with pytest.raises(AttributeError):
        _ = startup.NO_SUCH_REGISTRY_CONSTANT


def test_project_manager_default_derives_from_seam(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    base = tmp_path / "reg"
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(base))
    mgr = project_mod.ProjectManager()
    assert mgr.projects_dir == base / "projects"
    assert mgr.projects_dir.is_dir()  # created under scratch, not home


def test_get_active_name_reads_override_registry(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    base = tmp_path / "reg"
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(base))
    # No adopted ancestor session, no env credential: the symlink
    # layer decides (mirrors core.testing.state_isolation's pin).
    monkeypatch.setattr(sessions_mod, "_walk_session_pid", lambda: None)
    monkeypatch.delenv(sessions_mod.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions_mod.ENV_SESSION_TOKEN, raising=False)

    assert startup.get_active_name() is None  # empty override registry

    projects = base / "projects"
    projects.mkdir(parents=True)
    (projects / "regseam.json").write_text("{}", encoding="utf-8")
    (projects / ".active").symlink_to("regseam.json")
    assert startup.get_active_name() == "regseam"


# ------------------------------------------------- test-estate contract


def test_setattr_override_still_wins_for_consumers(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The suite-wide patch spelling (state_isolation, the root
    conftest, and the per-file ``mock.patch`` sites) sets the module
    attribute — in-module consumers must prefer that over the seam."""
    seam_base = tmp_path / "seam"
    patched = tmp_path / "patched"
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(seam_base))
    monkeypatch.setattr(sessions_mod, "SESSIONS_DIR",
                        patched / "sessions.d", raising=False)
    monkeypatch.setattr(project_mod, "PROJECTS_DIR",
                        patched / "projects", raising=False)
    monkeypatch.setattr(startup, "PROJECTS_DIR",
                        patched / "projects", raising=False)
    assert sessions_mod._sessions_dir() == patched / "sessions.d"
    assert project_mod._projects_dir() == patched / "projects"
    assert startup._projects_dir() == patched / "projects"
    mgr = project_mod.ProjectManager()
    assert mgr.projects_dir == patched / "projects"


def test_startup_active_link_follows_patched_projects_dir(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A test that pins ``core.startup.PROJECTS_DIR`` alone must not
    leave the bookmark pointing at the seam's registry — the link
    derives from the patched dir (single-location contract, patched
    spelling included)."""
    patched = tmp_path / "patched" / "projects"
    monkeypatch.setattr(startup, "PROJECTS_DIR", patched, raising=False)
    assert startup._active_link() == patched / ".active"
    # An explicit ACTIVE_LINK patch still wins outright.
    monkeypatch.setattr(startup, "ACTIVE_LINK",
                        tmp_path / "elsewhere" / ".active", raising=False)
    assert startup._active_link() == tmp_path / "elsewhere" / ".active"


# --------------------------------------------- import-discipline fence


#: The modules whose historical constant names now resolve through the
#: seam via PEP 562 module ``__getattr__``, and the names they serve.
_SEAM_SURFACES: dict[str, frozenset[str]] = {
    "core.startup": frozenset({"PROJECTS_DIR", "ACTIVE_LINK"}),
    "core.project.project": frozenset({"PROJECTS_DIR"}),
    "core.project.sessions": frozenset({"SESSIONS_DIR"}),
}

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCAN_ROOTS: tuple[str, ...] = ("core", "packages", "libexec")
#: Path components that mark non-runtime code (tests, dev tooling).
_EXCLUDED_PARTS: frozenset[str] = frozenset(
    {"tests", "scripts", "__pycache__"})
_FROM_IMPORT_RE: re.Pattern[str] = re.compile(
    r"^from\s+([.\w]+)\s+import\b(.*)$")


def _package_of(path: Path) -> str:
    """The dotted package a file's relative imports resolve against
    (for both a submodule and a package ``__init__.py``, that is the
    containing directory's dotted name)."""
    rel = path.relative_to(_REPO_ROOT)
    return ".".join(rel.parts[:-1])


def _resolve_module(module_text: str, package: str) -> str:
    """Absolute dotted module for a ``from X import`` clause."""
    dots = len(module_text) - len(module_text.lstrip("."))
    if dots == 0:
        return module_text
    base = package.split(".") if package else []
    base = base[:len(base) - (dots - 1)] if dots > 1 else base
    remainder = module_text[dots:]
    if remainder:
        base = [*base, remainder]
    return ".".join(base)


def _import_clause(lines: list[str], idx: int, clause: str) -> str:
    """Join a (possibly parenthesised / backslash-continued) import
    clause into one string, without executing or importing anything."""
    joined = clause
    j = idx
    while (("(" in joined and ")" not in joined)
           or joined.rstrip().endswith("\\")):
        j += 1
        if j >= len(lines):
            break
        joined = joined.rstrip().rstrip("\\") + " " + lines[j]
    return joined


def _bound_names(clause: str) -> frozenset[str]:
    """The names a ``from X import ...`` clause binds (pre-``as``)."""
    text = clause.split("#", 1)[0].replace("(", " ").replace(")", " ")
    names: set[str] = set()
    for part in text.split(","):
        tokens = part.split()
        if tokens:
            names.add(tokens[0])
    return frozenset(names)


def _census_offenders() -> list[str]:
    """Module-TOP-LEVEL value-binding imports of the historical
    constant names from the seam surfaces, across runtime code."""
    offenders: list[str] = []
    for root in _SCAN_ROOTS:
        base = _REPO_ROOT / root
        for path in sorted(base.rglob("*") if root == "libexec"
                           else base.rglob("*.py")):
            if not path.is_file():
                continue
            rel = path.relative_to(_REPO_ROOT)
            if _EXCLUDED_PARTS & set(rel.parts):
                continue
            if rel.name.startswith("test_") or rel.name == "conftest.py":
                continue
            try:
                lines = path.read_text(
                    encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            package = _package_of(path) if root != "libexec" else ""
            for idx, line in enumerate(lines):
                match = _FROM_IMPORT_RE.match(line)
                if match is None:
                    continue  # indented (function-local) lines never match
                module = _resolve_module(match.group(1), package)
                wanted = _SEAM_SURFACES.get(module)
                if wanted is None:
                    continue
                clause = _import_clause(lines, idx, match.group(2))
                hits = wanted & _bound_names(clause)
                if hits:
                    offenders.append(
                        f"{rel}:{idx + 1}: binds {sorted(hits)} at module "
                        f"top level: {line.strip()}")
    return offenders


def test_no_module_level_imports_of_historical_names() -> None:
    """The PEP 562 seam only works because every runtime consumer of
    the historical constant names uses a FUNCTION-LOCAL value-binding
    import, re-executed per call. A module-top-level
    ``from core.startup import PROJECTS_DIR`` (any seam surface, any
    of the served names) would freeze the default at import time and
    silently stop tracking the override — nothing else catches that
    hoist, so this census does."""
    offenders = _census_offenders()
    assert not offenders, (
        "module-top-level imports freeze the registry seam — use a "
        "function-local `from ... import` instead:\n"
        + "\n".join(offenders))
