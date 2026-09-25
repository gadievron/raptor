"""Detector-correctness tests for the transcript-seam census."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_transcript_seam.py"
REPO = Path(__file__).resolve().parents[3]

_PROVIDERS_STUB = (
    "class LLMProvider:\n    pass\n"
    "class AlphaProvider(LLMProvider):\n    pass\n"
    "class BetaProvider(LLMProvider):\n    pass\n"
)

_FACTORY_STUB = (
    "from core.llm.client import LLMClient\n"
    "def get_client():\n"
    "    return LLMClient()\n"
)


@pytest.fixture(scope="module")
def det():
    spec = importlib.util.spec_from_file_location(
        "check_transcript_seam", _SCRIPT,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plant(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _seeded_tree(tmp_path: Path) -> Path:
    """Minimal synthetic repo carrying the census's two derivation
    anchors (providers module + factory pin)."""
    root = tmp_path / "repo"
    _plant(root, "core/llm/providers.py", _PROVIDERS_STUB)
    _plant(root, "core/llm/factory.py", _FACTORY_STUB)
    return root


class TestDetection:
    def test_clean_seeded_tree_has_no_findings(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        assert det.census(root) == {}

    def test_plain_client_construction_flagged(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "def run():\n    client = LLMClient()\n",
        )
        assert det.census(root) == {
            "llm_client:packages/thing/stage.py::run": 1,
        }

    def test_attribute_construction_flagged(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "core/thing.py",
            "import core.llm.client as c\n"
            "client = c.LLMClient()\n",
        )
        assert det.census(root) == {
            "llm_client:core/thing.py::<module>": 1,
        }

    def test_fenced_scope_passes(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "from core.llm.transcript import fence_unadopted_dispatch\n"
            "def run():\n"
            "    fence_unadopted_dispatch('thing stage')\n"
            "    client = LLMClient()\n",
        )
        assert det.census(root) == {}

    def test_fence_in_sibling_function_does_not_exempt(self, det, tmp_path):
        """A fence in one function never covers a construction in
        another — the fence only refuses replay on the path that
        actually executes it."""
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "from core.llm.transcript import fence_unadopted_dispatch\n"
            "def guarded():\n"
            "    fence_unadopted_dispatch('thing stage')\n"
            "def unguarded():\n"
            "    client = LLMClient()\n",
        )
        assert det.census(root) == {
            "llm_client:packages/thing/stage.py::unguarded": 1,
        }

    def test_fence_covers_nested_scopes(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "def run():\n"
            "    fence_unadopted_dispatch('thing stage')\n"
            "    def inner():\n"
            "        return LLMClient()\n"
            "    return inner\n",
        )
        assert det.census(root) == {}

    def test_module_level_fence_exempts_module(self, det, tmp_path):
        """A module-level fence executes at import time, so under
        replay the module is unusable before any construction runs."""
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "fence_unadopted_dispatch('thing module')\n"
            "def run():\n"
            "    return LLMClient()\n",
        )
        assert det.census(root) == {}

    def test_client_subclass_definition_flagged(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "from core.llm.client import LLMClient\n"
            "class MyClient(LLMClient):\n"
            "    pass\n",
        )
        assert det.census(root) == {
            "llm_client:packages/thing/stage.py::MyClient": 1,
        }

    def test_transcript_client_subclass_definition_flagged(
        self, det, tmp_path,
    ):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "class Sneaky(TranscriptLLMClient):\n"
            "    pass\n",
        )
        assert det.census(root) == {
            "llm_client:packages/thing/stage.py::Sneaky": 1,
        }

    def test_provider_subclass_outside_core_llm_flagged(
        self, det, tmp_path,
    ):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/transport.py",
            "class MyProvider(AlphaProvider):\n"
            "    pass\n",
        )
        assert det.census(root) == {
            "provider:packages/thing/transport.py::MyProvider": 1,
        }

    def test_provider_subclass_inside_core_llm_allowed(
        self, det, tmp_path,
    ):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "core/llm/extra.py",
            "class InSeamProvider(AlphaProvider):\n"
            "    pass\n",
        )
        assert det.census(root) == {}

    def test_import_as_alias_construction_flagged(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/stage.py",
            "from core.llm.client import LLMClient as LC\n"
            "def run():\n"
            "    return LC()\n",
        )
        assert det.census(root) == {
            "llm_client:packages/thing/stage.py::run": 1,
        }

    def test_provider_factory_alias_flagged(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/transport.py",
            "from core.llm.providers import create_provider as mk\n"
            "def build(cfg):\n"
            "    return mk(cfg)\n",
        )
        assert det.census(root) == {
            "provider:packages/thing/transport.py::build": 1,
        }

    def test_provider_factory_call_outside_core_llm_flagged(
        self, det, tmp_path,
    ):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/transport.py",
            "def build():\n    return create_provider(cfg)\n",
        )
        assert det.census(root) == {
            "provider:packages/thing/transport.py::build": 1,
        }

    def test_direct_provider_class_outside_core_llm_flagged(
        self, det, tmp_path,
    ):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "packages/thing/transport.py",
            "def build():\n    return AlphaProvider()\n",
        )
        assert det.census(root) == {
            "provider:packages/thing/transport.py::build": 1,
        }

    def test_provider_construction_inside_core_llm_allowed(
        self, det, tmp_path,
    ):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "core/llm/cc_adapter.py",
            "def build():\n    return create_provider(cfg)\n",
        )
        assert det.census(root) == {}

    def test_same_site_counts_accumulate(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "core/thing.py",
            "def run(model):\n"
            "    return LLMClient(pinned_model=model) if model "
            "else LLMClient()\n",
        )
        assert det.census(root) == {"llm_client:core/thing.py::run": 2}

    def test_local_replay_case_content_outside_the_universe(
        self, det, tmp_path,
    ):
        """A maintainer's local case corpus may carry target-source
        snapshots; eval CONTENT never joins the census."""
        root = _seeded_tree(tmp_path)
        _plant(
            root,
            "core/audit/corpus/replay-cases/case-a/repo/src/x.py",
            "client = LLMClient()\n",
        )
        assert det.census(root) == {}

    def test_replay_cases_name_elsewhere_still_censused(
        self, det, tmp_path,
    ):
        """The corpus exclusion is a rel-path PREFIX, never a bare
        directory name — a runtime dir sharing the name must not
        shrink the census universe."""
        root = _seeded_tree(tmp_path)
        _plant(
            root,
            "packages/llm_analysis/replay-cases/helper.py",
            "client = LLMClient()\n",
        )
        assert det.census(root) == {
            "llm_client:packages/llm_analysis/replay-cases/helper.py"
            "::<module>": 1,
        }

    def test_test_files_outside_the_universe(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(
            root, "core/thing/tests/test_x.py",
            "client = LLMClient()\n",
        )
        assert det.census(root) == {}


class TestVacuousnessPins:
    def test_missing_factory_pin_refused(self, det, tmp_path):
        root = tmp_path / "repo"
        _plant(root, "core/llm/providers.py", _PROVIDERS_STUB)
        _plant(root, "core/llm/factory.py", "def get_client():\n    pass\n")
        with pytest.raises(ValueError, match="vacuous"):
            det.census(root)

    def test_provider_derivation_floor_refused(self, det, tmp_path):
        root = tmp_path / "repo"
        _plant(root, "core/llm/providers.py", "class OnlyProvider:\n    pass\n")
        _plant(root, "core/llm/factory.py", _FACTORY_STUB)
        with pytest.raises(ValueError, match="vacuous"):
            det.census(root)

    def test_unparseable_runtime_file_refused(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        _plant(root, "core/broken.py", "def (:\n")
        with pytest.raises(ValueError, match="cannot parse"):
            det.census(root)


class TestBaselineSemantics:
    def _baseline(self, tmp_path: Path, entries: dict) -> Path:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps({"entries": entries}), encoding="utf-8")
        return p

    def test_unbaselined_site_fails(self, det, tmp_path, capsys):
        root = _seeded_tree(tmp_path)
        _plant(root, "core/thing.py", "client = LLMClient()\n")
        baseline = self._baseline(tmp_path, {})
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 1
        assert "NEW dispatch site" in capsys.readouterr().out

    def test_baselined_site_passes_and_growth_fails(
        self, det, tmp_path, capsys,
    ):
        root = _seeded_tree(tmp_path)
        _plant(root, "core/thing.py", "client = LLMClient()\n")
        baseline = self._baseline(
            tmp_path,
            {"llm_client:core/thing.py::<module>":
                {"count": 1, "note": "accepted"}},
        )
        assert det.main(
            ["--root", str(root), "--baseline", str(baseline)],
        ) == 0
        _plant(
            root, "core/thing.py",
            "client = LLMClient()\nother = LLMClient()\n",
        )
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 1
        assert "grew" in capsys.readouterr().out

    def test_stale_entry_warns_but_passes(self, det, tmp_path, capsys):
        root = _seeded_tree(tmp_path)
        baseline = self._baseline(
            tmp_path,
            {"llm_client:core/gone.py::<module>":
                {"count": 1, "note": "accepted"}},
        )
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 0
        assert "stale" in capsys.readouterr().out

    def test_noteless_baseline_entry_refused(self, det, tmp_path, capsys):
        root = _seeded_tree(tmp_path)
        baseline = self._baseline(
            tmp_path,
            {"llm_client:core/x.py::<module>": {"count": 1}},
        )
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 2
        assert "note" in capsys.readouterr().err

    def test_countless_baseline_entry_refused(self, det, tmp_path, capsys):
        root = _seeded_tree(tmp_path)
        baseline = self._baseline(
            tmp_path,
            {"llm_client:core/x.py::<module>": {"note": "accepted"}},
        )
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 2
        assert "count" in capsys.readouterr().err

    def test_bool_count_refused(self, det, tmp_path, capsys):
        """bool is an int subclass; a `true` count must not read as
        headroom 1."""
        root = _seeded_tree(tmp_path)
        baseline = self._baseline(
            tmp_path,
            {"llm_client:core/x.py::<module>":
                {"count": True, "note": "accepted"}},
        )
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 2
        assert "count" in capsys.readouterr().err

    def test_headroom_warns_distinctly_but_passes(
        self, det, tmp_path, capsys,
    ):
        """A recorded count above the observed one is unused headroom
        (a new construction would pass silently inside it) — its own
        warning, distinct from a stale row."""
        root = _seeded_tree(tmp_path)
        _plant(root, "core/thing.py", "client = LLMClient()\n")
        baseline = self._baseline(
            tmp_path,
            {"llm_client:core/thing.py::<module>":
                {"count": 3, "note": "accepted"}},
        )
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "unused headroom" in out
        assert "stale" not in out

    def test_corrupt_baseline_refused(self, det, tmp_path, capsys):
        root = _seeded_tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        baseline.write_text("[1, 2", encoding="utf-8")
        rc = det.main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 2
        assert "baseline" in capsys.readouterr().err

    def test_absent_baseline_is_preadoption_empty(self, det, tmp_path):
        root = _seeded_tree(tmp_path)
        rc = det.main(
            ["--root", str(root),
             "--baseline", str(tmp_path / "missing.json")],
        )
        assert rc == 0

    def test_list_mode_prints_census(self, det, tmp_path, capsys):
        root = _seeded_tree(tmp_path)
        _plant(root, "core/thing.py", "client = LLMClient()\n")
        rc = det.main(["--root", str(root), "--list"])
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == {
            "llm_client:core/thing.py::<module>": 1,
        }


class TestRealTree:
    def test_shipped_baseline_matches_the_tree(self, det):
        """The committed baseline and the real tree agree: the gate
        exits 0 with no NEW/grown sites (stale warns allowed)."""
        assert det.main([]) == 0

    def test_real_tree_census_sees_known_seam_consumers(self, det):
        """Non-vacuousness against the live tree: the census keys
        include at least one llm_client and one provider arm entry."""
        observed = det.census(REPO)
        arms = {key.split(":", 1)[0] for key in observed}
        assert {"llm_client", "provider"} <= arms
