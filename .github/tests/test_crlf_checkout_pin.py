r"""Class-level pin: a CRLF checkout analyses like its LF twin.

Companion to ``test_crlf_line_model_census`` — the census keeps new
``.split("\n")`` / MULTILINE-``$`` sites adjudicated; this pin runs a
small twin tree (identical content, LF vs CRLF terminators) through
the real front half of the pipeline and asserts the two checkouts
produce the same analysis view:

* inventory build (byte-decode lane, the big ``\r``-carrying surface)
  mints identical review units with identical spans;
* the audit function-source chokepoint hands back identical text;
* one real mechanical detector renders the identical verdict.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_C_BODY = (
    "#include <stdio.h>\n\n"
    "int locked_path(int x) {\n"
    "    spin_lock(&lk);\n"
    "    if (x < 0)\n"
    "        return -1;\n"
    "    spin_unlock(&lk);\n"
    "    return 0;\n"
    "}\n\n"
    "static int helper(int y) {\n"
    "    return y + 1;\n"
    "}\n"
)
_PY_BODY = "def alpha(a):\n    return a\n\n\ndef beta(b):\n    return b * 2\n"


def _mk_tree(root: Path, crlf: bool) -> Path:
    root.mkdir()

    def enc(s: str) -> bytes:
        return (s.replace("\n", "\r\n") if crlf else s).encode()

    (root / "src.c").write_bytes(enc(_C_BODY))
    (root / "mod.py").write_bytes(enc(_PY_BODY))
    return root


def test_crlf_checkout_analyses_like_lf(tmp_path: Path) -> None:
    from core.audit.condition_smt import check_lock_discipline
    from core.audit.diagnostics import read_function_source
    from core.inventory.builder import build_inventory

    views = {}
    for name in ("lf", "crlf"):
        root = _mk_tree(tmp_path / name, crlf=(name == "crlf"))
        inv = build_inventory(
            str(root),
            output_dir=str(tmp_path / f"{name}-out"),
            parallel=False,
        )
        items = {
            f["path"]: [
                (i.get("name"), i.get("kind"),
                 i.get("line_start"), i.get("line_end"))
                for i in f.get("items", [])
            ]
            for f in inv.get("files", [])
        }
        # Chokepoint text for the C function's span from the minted
        # inventory span itself (end-to-end, no hardcoded lines).
        span = next(
            (i["line_start"], i["line_end"])
            for i in next(
                f for f in inv["files"] if f["path"] == "src.c"
            )["items"]
            if i.get("name") == "locked_path"
        )
        source = read_function_source(root, "src.c", "locked_path", *span)
        verdict = check_lock_discipline(source).to_dict()
        views[name] = (items, source, verdict)

    assert views["lf"] == views["crlf"]
    items, source, verdict = views["crlf"]
    # Non-vacuous: real units minted, clean text, real verdict.
    assert any(n == "locked_path" for n, _, _, _ in items["src.c"])
    assert any(n == "beta" for n, _, _, _ in items["mod.py"])
    assert "\r" not in source and "spin_lock" in source
    assert verdict["violation_found"] is True
