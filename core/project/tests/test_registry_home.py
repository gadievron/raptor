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

import ast
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

#: Every name any seam surface serves — the census pre-filter.
_SERVED_NAMES: frozenset[str] = frozenset().union(*_SEAM_SURFACES.values())

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SCAN_ROOTS: tuple[str, ...] = ("core", "packages", "libexec")
#: Path components that mark non-runtime code (tests, dev tooling).
_EXCLUDED_PARTS: frozenset[str] = frozenset(
    {"tests", "scripts", "__pycache__"})


def _package_of(path: Path, repo_root: Path) -> str:
    """The dotted package a file's relative imports resolve against
    (for both a submodule and a package ``__init__.py``, that is the
    containing directory's dotted name)."""
    rel = path.relative_to(repo_root)
    return ".".join(rel.parts[:-1])


def _resolve_from(module: str | None, level: int, package: str) -> str:
    """Absolute dotted module for a ``from X import`` clause."""
    if level == 0:
        return module or ""
    parts = package.split(".") if package else []
    if level > 1:
        parts = parts[:len(parts) - (level - 1)]
    if module:
        parts = [*parts, module]
    return ".".join(parts)


def _is_type_checking_test(test: ast.expr) -> bool:
    """``if TYPE_CHECKING:`` / ``if typing.TYPE_CHECKING:`` guard —
    annotation-only, never executed at runtime, so nothing inside it
    can freeze a runtime value."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _dotted_chain(node: ast.expr) -> str | None:
    """``a.b.c`` for a pure Name/Attribute chain, else ``None``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


class _ImportTimeCensus(ast.NodeVisitor):
    """Collects import-time value bindings of the served names.

    Two offender shapes, both of which resolve the seam ONCE while the
    module is being imported and keep the result for the process
    lifetime:

    * ``from core.startup import PROJECTS_DIR`` (plain, aliased,
      relative, parenthesised) — the value-binding import;
    * ``import core.startup`` (plain, ``as`` alias, the submodule
      binding ``from core import startup``, or a module-level
      assignment alias ``_m = core.startup``) followed by an
      import-time attribute access such as
      ``Y = core.startup.PROJECTS_DIR`` — the module ``__getattr__``
      fires once at binding time, freezing the value equally.

    Only code that EXECUTES at import time is walked: the module body,
    module-level compound statements (``if``/``try``/``with``/loops),
    class bodies, and the import-time expressions of a ``def``
    (decorators, parameter defaults). Function and lambda BODIES are
    skipped — a function-local resolution re-executes per call, which
    is the sanctioned discipline. ``if TYPE_CHECKING:`` arms are
    skipped too (annotation-only, never executed at runtime).
    """

    def __init__(self, rel: Path, package: str, lines: list[str]) -> None:
        self._rel = rel
        self._package = package
        self._lines = lines
        #: import-time access prefix (``core.startup``, an ``as``
        #: alias, a ``from core import startup`` binding) → the seam
        #: surface module it names.
        self._aliases: dict[str, str] = {}
        self.offenders: list[str] = []

    def _flag(self, node: ast.AST, names: list[str], how: str) -> None:
        lineno: int = getattr(node, "lineno", 1)
        line = self._lines[lineno - 1].strip()
        self.offenders.append(
            f"{self._rel}:{lineno}: {how} {sorted(names)} at import "
            f"time: {line}")

    # ----------------------------------- import-time scope control
    def visit_FunctionDef(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Decorators and parameter defaults evaluate at import time;
        # the body does not.
        for dec in node.decorator_list:
            self.visit(dec)
        for default in (*node.args.defaults,
                        *(d for d in node.args.kw_defaults
                          if d is not None)):
            self.visit(default)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in (*node.args.defaults,
                        *(d for d in node.args.kw_defaults
                          if d is not None)):
            self.visit(default)

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_test(node.test):
            for stmt in node.orelse:
                self.visit(stmt)
            return
        self.generic_visit(node)

    # ----------------------------------- the two offender shapes
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in _SEAM_SURFACES:
                self._aliases[alias.asname or alias.name] = alias.name

    def visit_Assign(self, node: ast.Assign) -> None:
        # A plain module-level assignment can alias a seam surface
        # (``_m = core.startup``; also an alias of an alias) — track
        # it exactly like an ``as`` alias so ``_m.PROJECTS_DIR``
        # below is flagged. Any other RHS un-aliases the name (a
        # rebound Name stops being an alias).
        chain = _dotted_chain(node.value)
        module = None
        if chain is not None:
            module = self._aliases.get(chain) or (
                chain if chain in _SEAM_SURFACES else None)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if module is not None:
                    self._aliases[target.id] = module
                else:
                    self._aliases.pop(target.id, None)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = _resolve_from(node.module, node.level, self._package)
        served = _SEAM_SURFACES.get(module)
        for alias in node.names:
            if served is not None and alias.name in served:
                self._flag(node, [alias.name], "binds")
            submodule = f"{module}.{alias.name}" if module else alias.name
            if submodule in _SEAM_SURFACES:
                self._aliases[alias.asname or alias.name] = submodule

    def visit_Attribute(self, node: ast.Attribute) -> None:
        chain = _dotted_chain(node.value)
        if chain is not None:
            module = self._aliases.get(chain) or (
                chain if chain in _SEAM_SURFACES else None)
            if module is not None and node.attr in _SEAM_SURFACES[module]:
                self._flag(node, [node.attr], "freezes")
        self.generic_visit(node)


def _census_offenders(repo_root: Path = _REPO_ROOT,
                      scan_roots: tuple[str, ...] = _SCAN_ROOTS) -> list[str]:
    """Import-time value bindings of the historical constant names
    from the seam surfaces, across runtime code. Purely static: files
    are parsed, never imported or executed. The defaults census the
    live repo; the parameters exist so the self-tests below can point
    the same machinery at synthetic trees."""
    offenders: list[str] = []
    for root in scan_roots:
        base = repo_root / root
        for path in sorted(base.rglob("*") if root == "libexec"
                           else base.rglob("*.py")):
            if not path.is_file():
                continue
            rel = path.relative_to(repo_root)
            if _EXCLUDED_PARTS & set(rel.parts):
                continue
            if rel.name.startswith("test_") or rel.name == "conftest.py":
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not any(name in source for name in _SERVED_NAMES):
                # Both offender shapes spell a served name literally
                # (the import clause binds it; the attribute access is
                # ``.<name>``) — skip the parse when none appears.
                continue
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError):
                continue  # non-Python (bash libexec shims) cannot import
            package = _package_of(path, repo_root) if root != "libexec" else ""
            census = _ImportTimeCensus(rel, package, source.splitlines())
            census.visit(tree)
            offenders.extend(census.offenders)
    return offenders


def test_no_module_level_imports_of_historical_names() -> None:
    """The PEP 562 seam only works because every runtime consumer of
    the historical constant names resolves them FUNCTION-LOCALLY,
    re-executed per call. Two import-time shapes defeat that:
    ``from core.startup import PROJECTS_DIR`` at module top level, and
    the sibling ``import core.startup`` followed by a module-level
    ``Y = core.startup.PROJECTS_DIR`` — both freeze the default at
    import time and silently stop tracking the override. Nothing else
    catches either hoist, so this census does."""
    offenders = _census_offenders()
    assert not offenders, (
        "import-time bindings freeze the registry seam — resolve the "
        "name inside the consuming function instead:\n"
        + "\n".join(offenders))


# ------------------------------------------------ census self-tests


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, source in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def test_census_flags_offender_shapes_exactly(tmp_path: Path) -> None:
    """Synthetic-source pin of the census machinery itself: every
    documented offender shape is flagged (file, line, verb, names)
    and nothing else is. A census weakened anywhere — class bodies
    unwalked, import-alias or assignment-alias tracking dropped, the
    pre-filter made vacuous, the ``TYPE_CHECKING`` skip widened to
    every ``if`` — changes this exact set."""
    _write_tree(tmp_path, {
        "core/off_fromimport.py": (
            "from core.startup import PROJECTS_DIR\n"),
        "core/off_classbody.py": (
            "import core.startup\n"
            "\n"
            "\n"
            "class Holder:\n"
            "    FROZEN = core.startup.PROJECTS_DIR\n"),
        "core/off_importalias.py": (
            "import core.startup as _alias\n"
            "\n"
            "Y = _alias.ACTIVE_LINK\n"),
        "core/off_ifarm.py": (
            "import os\n"
            "\n"
            "if os.sep:\n"
            "    from core.project.sessions import SESSIONS_DIR\n"),
        "core/off_modalias.py": (
            "import core.startup\n"
            "\n"
            "_cs = core.startup\n"
            "y = _cs.PROJECTS_DIR\n"),
        # tests/ is non-runtime by census contract — never flagged.
        "core/tests/off_excluded.py": (
            "from core.startup import PROJECTS_DIR\n"),
    })
    offenders = _census_offenders(repo_root=tmp_path, scan_roots=("core",))
    assert sorted(offenders) == sorted([
        "core/off_fromimport.py:1: binds ['PROJECTS_DIR'] at import "
        "time: from core.startup import PROJECTS_DIR",
        "core/off_classbody.py:5: freezes ['PROJECTS_DIR'] at import "
        "time: FROZEN = core.startup.PROJECTS_DIR",
        "core/off_importalias.py:3: freezes ['ACTIVE_LINK'] at import "
        "time: Y = _alias.ACTIVE_LINK",
        "core/off_ifarm.py:4: binds ['SESSIONS_DIR'] at import "
        "time: from core.project.sessions import SESSIONS_DIR",
        "core/off_modalias.py:4: freezes ['PROJECTS_DIR'] at import "
        "time: y = _cs.PROJECTS_DIR",
    ])


def test_census_green_on_sanctioned_shapes(tmp_path: Path) -> None:
    """Function-local resolution, ``TYPE_CHECKING``-guarded imports,
    and a rebound module alias are the sanctioned discipline — zero
    flags. The file spells the served names, so the pre-filter cannot
    be what keeps it green."""
    _write_tree(tmp_path, {
        "core/ok_sanctioned.py": (
            "import typing\n"
            "\n"
            "import core.startup\n"
            "\n"
            "if typing.TYPE_CHECKING:\n"
            "    from core.startup import PROJECTS_DIR\n"
            "\n"
            "_alias = core.startup\n"
            "_alias = object()\n"
            "\n"
            "\n"
            "def _projects_dir():\n"
            "    from core.startup import PROJECTS_DIR\n"
            "    return PROJECTS_DIR\n"
            "\n"
            "\n"
            "def _active_link():\n"
            "    return core.startup.ACTIVE_LINK\n"),
    })
    assert _census_offenders(repo_root=tmp_path, scan_roots=("core",)) == []
