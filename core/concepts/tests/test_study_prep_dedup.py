"""study-prep name-level dedup: one paid study item per function NAME.

The extractor deliberately returns every regex match — forward
declarations and duplicate decomp thunks included — and its docstring
promises consumers merge on name keys preferring the entry with a
body. The item builder keyed ids on name+line instead, so each
line-distinct duplicate became its own paid study item (observed
live: identical decomp-tree thunks studied several times over), and
the "bridge seeds matched X/Y" line counted item occurrences, printing
impossible ratios like 52/36.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

_PREP_PATH = (Path(__file__).resolve().parents[3]
              / "libexec" / "raptor-study-prep")


def _load_prep() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_prep_dedup", str(_PREP_PATH))
    spec = importlib.util.spec_from_file_location(
        "raptor_study_prep_dedup", str(_PREP_PATH), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prep = _load_prep()


def _run_prep(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(  # noqa: PLW1510 - callers assert on returncode
        [sys.executable, str(_PREP_PATH)] + args,
        env=env, capture_output=True, text=True, timeout=120,
    )


def _fn(name: str, line: int, *, body: str = "", doc: str = "",
        file: str = "a.c") -> dict:
    return {
        "name": name,
        "file": file,
        "line": line,
        "signature": f"int {name}(void)",
        "param_types": ["void"],
        "return_type": "int",
        "doc_comment": doc,
        "signals": {},
        "body": body,
    }


class TestNameLevelDedup:
    def test_duplicate_names_collapse_to_one_item(self):
        # Decomp-tree thunk shape: the same function extracted at
        # three different lines.
        fns = [_fn("stack_guard", 10, body="{ return 1; }"),
               _fn("stack_guard", 90, body="{ return 1; }"),
               _fn("stack_guard", 170, body="{ return 1; }")]
        items = prep._build_study_items([], fns, [])
        func_names = [it.name for it in items if it.kind == "function"]
        assert func_names == ["stack_guard"]

    def test_implementation_wins_and_decl_doc_carries(self):
        # A forward declaration often carries the doc comment while
        # the implementation carries the body: the survivor must get
        # both, in either scan order.
        decl = _fn("parse_hdr", 5, doc="/** parses the header */")
        impl = _fn("parse_hdr", 40, body="{ return 0; }")
        for order in ([decl, impl], [impl, decl]):
            items = prep._build_study_items([], list(order), [])
            (it,) = [i for i in items if i.kind == "function"]
            assert it.line == 40
            assert "{ return 0; }" in it.definition
            assert "parses the header" in it.doc_comment

    def test_last_body_bearing_entry_wins_like_the_call_graph(self):
        # Among several body-bearing entries the LAST wins — the same
        # tie-break _build_call_graph applies — so the survivor's
        # definition and its calls come from the same entry (the
        # first-wins alternative pairs one entry's body with the
        # other's callees).
        fns = [_fn("dup_fn", 10, body="{ return helper_a(); }"),
               _fn("dup_fn", 50, body="{ return helper_b(); }")]
        items = prep._build_study_items([], fns, [])
        (it,) = [i for i in items if i.kind == "function"]
        assert it.line == 50
        assert "helper_b" in it.definition

    def test_distinct_names_keep_first_seen_order(self):
        fns = [_fn("alpha_fn", 1, body="{ return 1; }"),
               _fn("beta_fn", 9, body="{ return 2; }")]
        items = prep._build_study_items([], fns, [])
        names = [it.name for it in items if it.kind == "function"]
        assert names == ["alpha_fn", "beta_fn"]


class TestCliDedupAndBridgeRatio:
    def test_thunk_duplicates_and_matched_ratio(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        # Three identical thunks + a struct whose refcount field mints
        # a second item with the struct's own name: both historic
        # over-count shapes in one tree.
        (repo / "decomp.c").write_text(
            "int stack_guard(void) { return 1; }\n"
            "int stack_guard(void) { return 1; }\n"
            "int stack_guard(void) { return 1; }\n"
            "struct conn { int use_count; char buf[16]; };\n"
            "int parse_hdr(char *buf) { return buf[0]; }\n",
            encoding="utf-8",
        )
        bridge = tmp_path / "bridge-seeds.json"
        bridge.write_text(json.dumps({
            "schema_version": 1,
            "generated_by": "binary_study_bridge",
            "seeds": [
                {"name": "conn", "seed_source": "bridge_seed",
                 "origin": "parser_boundary", "why": "w",
                 "derived_from_target": True},
            ],
            "concepts": [],
        }), encoding="utf-8")
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--bridge-seed-file", str(bridge),
        ])
        assert result.returncode == 0, result.stderr
        data = json.loads(
            (out / "study-list.json").read_text(encoding="utf-8"))
        func_dupes = [it for it in data["items"]
                      if it["kind"] == "function"
                      and it["name"] == "stack_guard"]
        assert len(func_dupes) == 1
        # "conn" names two items (struct + refcount) but is ONE seed
        # name: the ratio counts names, never item occurrences.
        m = re.search(r"bridge seeds matched (\d+)/(\d+)",
                      result.stderr)
        assert m is not None, result.stderr
        assert (m.group(1), m.group(2)) == ("1", "1")
