"""Header pattern dispatch with owned catalogue records and caches."""

import ast
from functools import partial
from itertools import chain
from pathlib import Path

from core.audit.run_memo import BoundedMemo


def test_cpp_header_patterns_share_catalogue_and_alignment_pin():
    source = Path(__file__).parents[1] / "context.py"
    tree = ast.parse(source.read_text())
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_load_language_patterns"
        or isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_LANG_PATTERN_EXT_MAP"
            for target in node.targets)
    ]
    reads = []

    def load(name):
        reads.append(name)
        return [("OWNED", "common scalar" if name == "common" else "C scalar", "summary", True)]

    namespace = {
        "Path": Path, "partial": partial, "chain": chain,
        "_patterns_cache": BoundedMemo(4), "_pattern_file_cache": BoundedMemo(4),
        "_load_pattern_file": load,
        "_render_pattern_tiers": lambda full, short: (" / ".join(full), " / ".join(short)),
    }
    module = ast.Module(body=ast.parse("from __future__ import annotations").body + nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source), "exec"), namespace)
    for suffix in [".h", ".hh", ".hpp", ".hxx", ".HH"]:
        result = namespace["_load_language_patterns"]("owned" + suffix)
        assert result == {"tier1": "common scalar / C scalar", "tier2": ""}
    assert reads == ["common", "c"]
    assert namespace["_load_language_patterns"]("owned.txt") is None
    assert reads == ["common", "c"]
    pins = ast.parse(Path(__file__).with_name("test_language_map_alignment.py").read_text())
    assignment = next(node for node in pins.body if isinstance(node, ast.AnnAssign)
                      and isinstance(node.target, ast.Name) and node.target.id == "_VALUE_DIVERGENCES")
    assert (".hh", "c") in ast.literal_eval(assignment.value)["pattern_files"]
