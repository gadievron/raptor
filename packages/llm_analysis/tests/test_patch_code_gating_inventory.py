"""Registry lint: every ``patch_code`` assignment site must be gated.

Miniature of the ``core/security/report_writer_audit.py`` architecture:
a small AST walker inventories every site in ``packages/llm_analysis``
that assigns ``patch_code`` onto a result / finding record, and the
test asserts the inventory matches a hand-maintained registry of
gated paths exactly — in both directions. A future patch-producing
path that skips :func:`packages.llm_analysis.patch_gate.run_patch_gate`
then fails this test at merge time instead of shipping ungated
patches silently; a removed path fails as a stale registry entry.

Detected forms (LLM-authored patch landing on a record):

  * ``record.patch_code = <expr>`` (attribute assign)
  * ``record["patch_code"] = <expr>`` (string-key subscript assign)
  * ``record.setdefault("patch_code", <expr>)`` (the assign-if-absent
    idiom the merge path uses in spirit)

Assignments of the literal ``None`` are ignored — clearing a patch is
not producing one (``scripts/e2e_verify_exploit.py`` and the
``VulnerabilityContext`` initialiser both do this legitimately).

Extending: a new patch-producing path must (1) run the mechanical
gate with the same best-effort posture as the registered sites and
(2) add its ``(file, qualified function)`` pair to
:data:`GATED_PATCH_CODE_PATHS` with a one-line audit note saying
where its gate call lives.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

PACKAGE_DIR = REPO / "packages" / "llm_analysis"

# ---------------------------------------------------------------------------
# Registry — (file relative to packages/llm_analysis, qualified function)
# mapped to an audit note pointing at the gate call for that path.
# ---------------------------------------------------------------------------

GATED_PATCH_CODE_PATHS: dict[tuple[str, str], str] = {
    ("agent.py", "AutonomousSecurityAgentV2.generate_patch"): (
        "run_patch_gate called in the same method before the save; "
        "gate crash degrades to a warning (agent.py generate_patch)"
    ),
    ("tasks.py", "PatchTask.finalize"): (
        "PatchTask._gate_patch wraps run_patch_gate; gated ids are "
        "recorded on task.gated_ids for the merge step"
    ),
    ("orchestrator.py", "_merge_results"): (
        "inline CC-schema patches gated via _gate_inline_patch; "
        "pre-gated ids (PatchTask side-channel) keep their stored gate"
    ),
}


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------


def _is_none(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_patch_code_target(target: ast.AST) -> bool:
    if isinstance(target, ast.Attribute) and target.attr == "patch_code":
        return True
    if isinstance(target, ast.Subscript):
        sl = target.slice
        return isinstance(sl, ast.Constant) and sl.value == "patch_code"
    return False


class _PatchCodeAssignVisitor(ast.NodeVisitor):
    """Collect ``(qualname, lineno)`` for patch_code-producing sites."""

    def __init__(self) -> None:
        self.sites: list[tuple[str, int]] = []
        self._stack: list[str] = []

    def _qualname(self) -> str:
        return ".".join(self._stack) or "<module>"

    def _scoped_visit(self, node: ast.AST, name: str) -> None:
        self._stack.append(name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped_visit(node, node.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scoped_visit(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scoped_visit(node, node.name)

    def _record(self, node: ast.AST) -> None:
        self.sites.append((self._qualname(), node.lineno))

    def visit_Assign(self, node: ast.Assign) -> None:
        if not _is_none(node.value) and any(
            _is_patch_code_target(t) for t in node.targets
        ):
            self._record(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and not _is_none(node.value) \
                and _is_patch_code_target(node.target):
            self._record(node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if _is_patch_code_target(node.target):
            self._record(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # record.setdefault("patch_code", <non-None>) — assign-if-absent.
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "setdefault"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "patch_code"
            and len(node.args) > 1
            and not _is_none(node.args[1])
        ):
            self._record(node)
        self.generic_visit(node)


def collect_patch_code_sites(source: str) -> list[tuple[str, int]]:
    visitor = _PatchCodeAssignVisitor()
    visitor.visit(ast.parse(source))
    return visitor.sites


def _package_files() -> list[Path]:
    files = []
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        rel_parts = path.relative_to(PACKAGE_DIR).parts
        if "tests" in rel_parts or "__pycache__" in rel_parts:
            continue
        files.append(path)
    return files


def _inventory() -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    for path in _package_files():
        rel = path.relative_to(PACKAGE_DIR).as_posix()
        for qualname, lineno in collect_patch_code_sites(
            path.read_text(encoding="utf-8"),
        ):
            found.setdefault((rel, qualname), []).append(lineno)
    return found


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


class TestPatchCodeGatingInventory:

    def test_every_assignment_site_is_registered_gated(self):
        found = _inventory()
        unregistered = {
            site: lines for site, lines in found.items()
            if site not in GATED_PATCH_CODE_PATHS
        }
        assert not unregistered, (
            "patch_code is assigned onto a record outside the "
            "registered gated paths — patches on that route would "
            "reach reports without run_patch_gate annotations. "
            "Gate the new path and register it in "
            f"GATED_PATCH_CODE_PATHS with an audit note: {unregistered}"
        )

    def test_no_stale_registry_entries(self):
        found = _inventory()
        stale = [
            site for site in GATED_PATCH_CODE_PATHS if site not in found
        ]
        assert not stale, (
            "registered gated paths no longer assign patch_code — "
            f"remove the stale entries: {stale}"
        )

    def test_registry_notes_are_meaningful(self):
        for site, note in GATED_PATCH_CODE_PATHS.items():
            assert note and len(note.strip()) >= 20, (
                f"registry entry {site} needs a real audit note"
            )
            assert "todo" not in note.lower(), (
                f"registry entry {site} has a placeholder note"
            )


class TestWalkerSelfTest:
    """The walker itself must detect / ignore the right shapes."""

    def test_detects_attribute_assignment(self):
        sites = collect_patch_code_sites(
            "class A:\n"
            "    def save(self, v):\n"
            "        self.patch_code = v\n"
        )
        assert sites == [("A.save", 3)]

    def test_detects_subscript_assignment(self):
        sites = collect_patch_code_sites(
            "def merge(rec, v):\n"
            "    rec['patch_code'] = v\n"
        )
        assert sites == [("merge", 2)]

    def test_detects_setdefault(self):
        sites = collect_patch_code_sites(
            "def merge(rec, v):\n"
            "    rec.setdefault('patch_code', v)\n"
        )
        assert sites == [("merge", 2)]

    def test_ignores_none_clearing_assignments(self):
        sites = collect_patch_code_sites(
            "def clear(rec):\n"
            "    rec.patch_code = None\n"
            "    rec['patch_code'] = None\n"
            "    rec.setdefault('patch_code', None)\n"
        )
        assert sites == []

    def test_ignores_annotation_only_and_schema_keys(self):
        sites = collect_patch_code_sites(
            "class A:\n"
            "    def __init__(self):\n"
            "        self.patch_code: str | None = None\n"
            "SCHEMA = {'patch_code': {'type': 'string'}}\n"
        )
        assert sites == []

    def test_detects_annotated_assignment_with_value(self):
        sites = collect_patch_code_sites(
            "def f(rec, v):\n"
            "    rec.patch_code: str = v\n"
        )
        assert sites == [("f", 2)]

    def test_module_level_qualname(self):
        sites = collect_patch_code_sites("rec['patch_code'] = 'x'\n")
        assert sites == [("<module>", 1)]
