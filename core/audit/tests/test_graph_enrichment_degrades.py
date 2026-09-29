"""Graph-store enrichment lanes degrade on any failure.

The graph lanes are best-effort: opening/ingesting the store mkdirs
the graph directory (OSError), binds artifact-derived values (sqlite
bind overflows), and parses artifact shapes. Every failure must land
in the existing skip/debug lane — never crash prep, nor revoke an
otherwise-successful run at its final optional enrichment step.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from core.audit.tests.checklist_corpus import ChecklistBuildCache

RAPTOR_DIR = Path(__file__).resolve().parents[3]


@pytest.fixture()
def prep_run_dir(
    checklist_builds: ChecklistBuildCache, tmp_path: Path,
) -> tuple[Path, Path]:
    """A real checklist for a tiny target, built the way prep expects.

    The corpus is shared with every other test starting from the same
    trivial tree (one CLI build per process); the run dir is this
    test's private copy — prep writes journals/artifacts into it. The
    ``out`` parent stays a private near-empty dir: prep's cross-run
    readers scan ``out_dir.parent``.
    """
    build = checklist_builds.build(
        {"app.py": "def entry(data):\n    return data.strip()\n"},
    )
    out = build.make_run_dir(tmp_path / "out" / "run")
    return build.target, out


def test_prep_graph_boost_degrades_on_permission_error(
        prep_run_dir: tuple[Path, Path], monkeypatch, caplog):
    """PermissionError from the graph store lands in the skip lane."""
    import core.understand_graph as ug
    from core.audit import orchestrator as orch
    from core.audit.orchestrator import OrchestratorConfig, _compute_audit_prep

    # The graph enrichment lane is under test; prep's
    # mechanical-detector phase is incidental substrate (sandboxed
    # Coccinelle runs on spatch-equipped hosts plus the detector-cache
    # import-closure fingerprint — the bulk of the call's cost, enough
    # to trip the default-tier duration guard on a loaded CI runner).
    # Same seam and (dict, set) return contract as the
    # test_consistency_wiring stub.
    monkeypatch.setattr(
        orch, "_run_mechanical_detectors",
        lambda *args, **kwargs: ({}, set()),
    )

    target, out = prep_run_dir
    graph_file = out / "graph" / "raptor.graph.sqlite"
    graph_file.parent.mkdir(parents=True)
    graph_file.touch()

    monkeypatch.setattr(
        ug, "graph_path_for_run",
        lambda run_dir, target_path=None: graph_file,
    )

    def _denied(*args, **kwargs):
        raise PermissionError("graph dir not writable")

    monkeypatch.setattr(ug, "hypothesis_seeds", _denied)

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        force=True,
        include_stale=False,
        enable_session_context=False,
        propagate_constraints=False,
    )
    with caplog.at_level(logging.DEBUG, logger="core.audit.orchestrator"):
        prep = _compute_audit_prep(config)
    assert prep is not None
    assert any("graph hypothesis_seeds skipped" in rec.message
               for rec in caplog.records)


def test_prep_graph_boost_degrades_on_bind_overflow(
        prep_run_dir: tuple[Path, Path], monkeypatch, caplog):
    """OverflowError (sqlite bind of an oversize artifact int) lands in
    the same skip lane — the artifact-derived value surface is not
    limited to filesystem errors."""
    import core.understand_graph as ug
    from core.audit import orchestrator as orch
    from core.audit.orchestrator import OrchestratorConfig, _compute_audit_prep

    # Same incidental-substrate stub as the permission-error test
    # above: the graph lane under test runs regardless of the
    # mechanical-detector phase's output.
    monkeypatch.setattr(
        orch, "_run_mechanical_detectors",
        lambda *args, **kwargs: ({}, set()),
    )

    target, out = prep_run_dir
    graph_file = out / "graph" / "raptor.graph.sqlite"
    graph_file.parent.mkdir(parents=True)
    graph_file.touch()

    monkeypatch.setattr(
        ug, "graph_path_for_run",
        lambda run_dir, target_path=None: graph_file,
    )

    def _overflow(*args, **kwargs):
        raise OverflowError("Python int too large to convert to SQLite INTEGER")

    monkeypatch.setattr(ug, "hypothesis_seeds", _overflow)

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        force=True,
        include_stale=False,
        enable_session_context=False,
        propagate_constraints=False,
    )
    with caplog.at_level(logging.DEBUG, logger="core.audit.orchestrator"):
        prep = _compute_audit_prep(config)
    assert prep is not None
    assert any("graph hypothesis_seeds skipped" in rec.message
               for rec in caplog.records)


def _handlers_for_message(path: Path, message: str) -> list[set[str]]:
    """Exception-name sets of every handler whose body logs *message*."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[set[str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            continue
        body_consts = {
            c.value for stmt in node.body for c in ast.walk(stmt)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
        }
        if message not in body_consts:
            continue
        names = {
            n.id for n in ast.walk(node.type) if isinstance(n, ast.Name)
        } | {
            n.attr for n in ast.walk(node.type)
            if isinstance(n, ast.Attribute)
        }
        out.append(names)
    return out


@pytest.mark.parametrize(
    ("rel_path", "message", "expected_sites"),
    [
        ("core/audit/orchestrator.py", "graph hypothesis_seeds skipped", 1),
        ("core/audit/orchestrator.py", "graph store enrichment skipped", 1),
        ("raptor.py", "graph store enrichment skipped", 1),
    ],
)
def test_enrichment_handlers_catch_broadly(
        rel_path: str, message: str, expected_sites: int):
    """All three best-effort enrichment tails catch Exception.

    The run-tail lanes (raptor.py scan/codeql, _run_audit_body) fire
    after success is already recorded and are structurally identical
    to the prep lane exercised behaviorally above; pin the handler
    shape at the source level so a regression cannot silently
    re-narrow it to an enumerated tuple that misses a class (OSError
    and sqlite bind OverflowError both escaped earlier spellings).
    """
    sites = _handlers_for_message(RAPTOR_DIR / rel_path, message)
    assert len(sites) == expected_sites
    for names in sites:
        assert "Exception" in names, (
            f"{rel_path}: handler logging {message!r} is narrower than "
            f"Exception (catches {sorted(names)})"
        )
