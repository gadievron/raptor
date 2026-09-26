"""Taint-pack models-as-data augmentation pass on the /codeql agent.

Pins: off by default (zero cost — the pass returns before touching
any component), the staged pack rides ``additional_model_packs`` into
the standard-suite run, the augmentation record lands in the run
directory, the IRIS channel passes through the provenance seam, and
every entry-point parser accepts the flag.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from core.dataflow.extension_pack import ROLE_SOURCE, ROLE_SUMMARY, ModelRow
from core.taint.mad_rows import RECORD_FILENAME
from packages.codeql.agent import CodeQLAgent

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def agent(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.js").write_text("console.log('x');\n")
    a = CodeQLAgent.__new__(CodeQLAgent)
    a.repo_path = repo
    a.out_dir = tmp_path / "out"
    a.out_dir.mkdir()
    a.query_runner = SimpleNamespace(additional_model_packs=None)
    return a


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(RaptorConfig, "CODEQL_TAINT_MAD_ENABLED", True)


@pytest.fixture
def no_iris(monkeypatch):
    monkeypatch.setattr("core.iris.api.load_project_specs",
                        lambda **kw: [])


def test_config_switch_defaults_off():
    assert RaptorConfig.CODEQL_TAINT_MAD_ENABLED is False


def test_disabled_pass_returns_none_before_touching_components():
    # No query_runner, no repo_path: the default-off gate must return
    # before any component access (the zero-cost-when-off pin).
    bare = CodeQLAgent.__new__(CodeQLAgent)
    assert bare._run_taint_pack_models_pass({"python": Path("/x")}) is None


def test_disabled_pass_stages_nothing_on_an_armed_agent(agent):
    # The DISCRIMINATING flag-off pin: the bare-agent test above also
    # passes via the degrade path (missing attributes swallow into
    # None), so on its own it cannot tell the gate from the exception
    # handler. This agent is fully armed — repo_path, out_dir, a real
    # query_runner slot — so with the gate removed the pass WOULD
    # stage 42 javascript rows and write the record. Flag off must
    # mean: None result, no staged packs, no output directory, no
    # record file.
    assert RaptorConfig.CODEQL_TAINT_MAD_ENABLED is False
    out = agent._run_taint_pack_models_pass({
        "javascript": agent.out_dir / "db-js",
        "python": agent.out_dir / "db-py",
    })
    assert out is None
    assert agent.query_runner.additional_model_packs is None
    assert not (agent.out_dir / "taint-mad").exists()
    assert not (agent.out_dir / RECORD_FILENAME).exists()


def test_no_augmentable_language_returns_none(agent, enabled):
    assert agent._run_taint_pack_models_pass(
        {"cpp": Path("/db-cpp")}) is None


def test_happy_path_stages_packs_and_writes_the_record(
    agent, enabled, no_iris, tmp_path,
):
    out = agent._run_taint_pack_models_pass({
        "javascript": tmp_path / "db-js",
        "python": tmp_path / "db-py",
        "cpp": tmp_path / "db-cpp",   # not augmentable, skipped
    })
    assert out is not None and set(out) == {"javascript", "python"}

    # The staged packs are what analyze_all_databases consumes.
    staged = agent.query_runner.additional_model_packs
    for lang in ("javascript", "python"):
        (entry,) = staged[lang]
        pack_dir, pack_name = entry
        assert pack_name == f"raptor/taint-mad-{lang}"
        assert Path(pack_dir) == agent.out_dir / "taint-mad" / lang
        model_files = list(Path(pack_dir).rglob("*.model.yml"))
        assert model_files, lang

    # The record file names the augmented surfaces.
    record_path = agent.out_dir / RECORD_FILENAME
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["flag_family"] == "--taint-crossfile"
    js = record["languages"]["javascript"]
    assert "command-injection" in js["augmented_sink_kinds"]
    assert "path-injection" in js["augmented_sink_kinds"]
    assert "html-injection" in js["augmented_sink_kinds"]
    assert js["augmented_source_kinds"] == ["remote"]
    assert js["rows_written"] > 0
    assert js["counts"]["sourceModel"] == 5
    # template-injection sinks and sanitizers are counted refusals.
    assert js["rejected"]
    # The returned cells are the record cells.
    assert out["javascript"] == js


def test_iris_rows_pass_the_provenance_seam(
    agent, enabled, monkeypatch, tmp_path,
):
    monkeypatch.setattr("core.iris.api.load_project_specs",
                        lambda **kw: [SimpleNamespace(
                            evidence_tier=SimpleNamespace(
                                value="xref_backed"))])
    iris_rows = (
        ModelRow(role=ROLE_SOURCE, type_name="fixturepkg",
                 path="Member[taintedValue].ReturnValue",
                 model_kind="remote", provenance="iris_refined"),
        ModelRow(role=ROLE_SUMMARY, type_name="fixturepkg",
                 path="Member[pass]", access_input="Argument[0]",
                 access_output="ReturnValue", model_kind="taint",
                 provenance="iris_refined"),
    )
    monkeypatch.setattr(
        "core.dataflow.extension_pack.rows_from_taint_specs",
        lambda specs, language: SimpleNamespace(
            rows=iris_rows, rejected=()),
    )
    out = agent._run_taint_pack_models_pass(
        {"javascript": tmp_path / "db-js"})
    cell = out["javascript"]
    # The learned source widened detection; the learned summary was
    # refused at the seam and shows up as a counted refusal.
    assert cell["iris"]["specs"] == 1
    assert cell["iris"]["rows"] == 1
    assert cell["iris"]["evidence_tiers"] == {"xref_backed": 1}
    assert any("operator-grade" in r["reason"] for r in cell["rejected"])
    model_file = Path(cell["model_file"])
    assert "fixturepkg" in model_file.read_text(encoding="utf-8")


def test_pack_load_failure_degrades_to_none(agent, enabled, monkeypatch):
    def boom(*a, **kw):
        raise ValueError("pack exploded")
    monkeypatch.setattr("core.taint.packs.load_packs", boom)
    assert agent._run_taint_pack_models_pass(
        {"python": Path("/db-py")}) is None
    assert agent.query_runner.additional_model_packs is None


class TestCliFlag:
    @pytest.mark.parametrize("script", [
        REPO_ROOT / "packages" / "codeql" / "agent.py",
        REPO_ROOT / "raptor_codeql.py",
        REPO_ROOT / "raptor_agentic.py",
    ])
    def test_parsers_accept_taint_crossfile_mad(self, script):
        proc = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "--taint-crossfile-mad" in proc.stdout
