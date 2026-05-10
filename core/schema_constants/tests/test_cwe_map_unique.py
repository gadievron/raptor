"""Guard against duplicate keys in CWE_TO_VULN_TYPE.

A duplicate key in a Python dict literal silently keeps only the last
value — earlier entries (and their documenting comments) are dropped at
parse time. The dict at runtime gives no signal that they ever existed.

Pre-batch the literal had `"CWE-20"` and `"CWE-77"` listed twice, and
the only reason it wasn't a behaviour bug was that the colliding values
happened to agree. If a future edit uses different vuln_type values for
the same CWE, the silent override would map every consumer to the wrong
verdict.

Detect the bug at module-parse time by reading the source and checking
that every CWE-N key appears exactly once. AST is more robust than a
plain regex (handles multi-line literals, escapes, comments).
"""

import ast
import collections
from pathlib import Path

import core.schema_constants as sc


def _extract_cwe_keys_from_source() -> list:
    """Parse schema_constants source, return CWE_TO_VULN_TYPE keys in order."""
    src = Path(sc.__file__).read_text()
    module = ast.parse(src)
    for node in ast.walk(module):
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "CWE_TO_VULN_TYPE"
                and isinstance(node.value, ast.Dict)):
            keys = []
            for k in node.value.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.append(k.value)
            return keys
    raise AssertionError("CWE_TO_VULN_TYPE dict literal not found")


def test_cwe_to_vuln_type_keys_unique_in_source():
    keys = _extract_cwe_keys_from_source()
    counts = collections.Counter(keys)
    dups = {k: n for k, n in counts.items() if n > 1}
    assert not dups, (
        f"CWE_TO_VULN_TYPE has duplicate source-level keys (silently "
        f"merged at parse time, dropping comment-documented intent): "
        f"{dups}"
    )


def test_cwe_to_vuln_type_runtime_count_matches_source():
    """Belt-and-braces: runtime dict size == source key count.

    If they differ, a duplicate-key collision happened at parse time.
    """
    src_keys = _extract_cwe_keys_from_source()
    assert len(sc.CWE_TO_VULN_TYPE) == len(src_keys), (
        f"CWE_TO_VULN_TYPE source has {len(src_keys)} keys but runtime "
        f"dict has {len(sc.CWE_TO_VULN_TYPE)} — duplicate keys collapsed."
    )
