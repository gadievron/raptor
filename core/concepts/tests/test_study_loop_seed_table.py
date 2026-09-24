"""study-loop report seed table + study-questions completion render."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path
from types import ModuleType

RAPTOR_DIR = Path(__file__).resolve().parents[3]
STUDY_LOOP = str(RAPTOR_DIR / "libexec" / "raptor-study-loop")


def _load_loop_module() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_loop_seed_table", STUDY_LOOP)
    spec = importlib.util.spec_from_file_location(
        "raptor_study_loop_seed_table", STUDY_LOOP, loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_loop = _load_loop_module()


def _write_study_list(out: Path, items: list[dict]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "study-list.json").write_text(
        json.dumps({"target": "t", "items": items}), encoding="utf-8")


class TestSeedTable:
    def test_lists_every_seed_with_why_and_honesty(
            self, tmp_path: Path) -> None:
        _write_study_list(tmp_path, [
            {"id": "1", "kind": "function", "name": "op_fn",
             "file": "a.c", "seed_source": "operator"},
            {"id": "2", "kind": "function", "name": "parse_hdr",
             "file": "a.c", "seed_source": "bridge_seed"},
            {"id": "3", "kind": "function", "name": "auto_fn",
             "file": "a.c", "seed_source": ""},
        ])
        (tmp_path / "bridge-seeds.json").write_text(json.dumps({
            "schema_version": 1,
            "seeds": [{"name": "parse_hdr",
                       "why": "parser boundary candidate"}],
        }), encoding="utf-8")
        lines = _loop._render_seed_table(tmp_path)
        text = "\n".join(lines)
        assert "## Seed Provenance" in text
        # The honesty line is rendered FROM the bridge constant
        # (capitalised mechanically) — the report and the contract
        # string cannot drift apart.
        from core.orchestration.binary_study_bridge import HONESTY_LINE
        assert (HONESTY_LINE[:1].upper() + HONESTY_LINE[1:]) in text
        assert HONESTY_LINE == "seed selection is target-influenced"
        assert "`op_fn` | operator | operator-asked identifier" in text
        assert ("`parse_hdr` | bridge_seed "
                "| parser boundary candidate") in text
        # Autonomous items are not seeds — they stay out of the table.
        assert "auto_fn" not in text
        # Operator seeds sort first (they outrank).
        assert text.index("op_fn") < text.index("parse_hdr")

    def test_overflow_rows_render_with_annotation(
            self, tmp_path: Path) -> None:
        _write_study_list(tmp_path, [
            {"id": "1", "kind": "function", "name": "tail_fn",
             "file": "a.c", "seed_source": "bridge_seed_overflow"},
        ])
        text = "\n".join(_loop._render_seed_table(tmp_path))
        assert "`tail_fn` | bridge_seed_overflow |" in text
        assert "beyond the derived-attention cap" in text

    def test_no_seeds_no_section(self, tmp_path: Path) -> None:
        _write_study_list(tmp_path, [
            {"id": "1", "kind": "function", "name": "auto_fn",
             "file": "a.c", "seed_source": ""},
        ])
        assert _loop._render_seed_table(tmp_path) == []

    def test_why_cells_are_escaped(self, tmp_path: Path) -> None:
        _write_study_list(tmp_path, [
            {"id": "1", "kind": "function", "name": "f",
             "file": "a.c", "seed_source": "bridge_seed"},
        ])
        (tmp_path / "bridge-seeds.json").write_text(json.dumps({
            "schema_version": 1,
            "seeds": [{"name": "f", "why": "evil\x1b[31m|pipe"}],
        }), encoding="utf-8")
        text = "\n".join(_loop._render_seed_table(tmp_path))
        assert "\x1b" not in text
        assert "\\|" in text  # table-cell pipe escaping
