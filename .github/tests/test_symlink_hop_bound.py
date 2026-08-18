"""Every bash symlink-resolution loop must carry a hop bound.

Why this test exists
--------------------
The launcher scripts resolve ``$0`` / ``BASH_SOURCE`` through symlinks
with a hand-rolled ``while [ -L ... ]`` loop (BSD readlink lacks
``-f``). An unbounded loop hangs forever on a symlink cycle — a local
denial of service on the operator-facing entry points. The bounded
variant (hop counter, limit 32) was applied to the ``libexec/`` copies;
this test pins the bound on EVERY copy, including the ``bin/`` entry
points, so new scripts cannot reintroduce the unbounded loop.

Two layers:

* static — every ``while [ -L`` loop in ``bin/`` and ``libexec/``
  increments and checks a hop counter inside the loop body;
* behavioural — each loop, extracted verbatim from the script and
  pointed at a real symlink cycle, terminates promptly with a non-zero
  exit instead of spinning.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

_WHILE_RE = re.compile(r'^\s*while \[ -L "\$\{?(?P<var>[A-Za-z_][A-Za-z0-9_]*)')


def _scripts() -> list[Path]:
    out = [p for p in sorted((REPO / "bin").iterdir()) if p.is_file()]
    out += [
        p
        for p in sorted((REPO / "libexec").glob("raptor-*"))
        if p.is_file()
    ]
    return out


def _loops(text: str) -> list[tuple[int, int, str]]:
    """Return (while_line_idx, done_line_idx, var) per symlink loop."""
    lines = text.splitlines()
    found = []
    for i, line in enumerate(lines):
        m = _WHILE_RE.match(line)
        if not m:
            continue
        for j in range(i + 1, len(lines)):
            if lines[j].strip() == "done":
                found.append((i, j, m.group("var")))
                break
        else:
            raise AssertionError(f"unterminated while loop at line {i + 1}")
    return found


class TestStaticBound(unittest.TestCase):
    def test_every_symlink_loop_is_hop_bounded(self):
        offenders = []
        for script in _scripts():
            text = script.read_text(encoding="utf-8")
            for i, j, _var in _loops(text):
                body = "\n".join(text.splitlines()[i : j + 1])
                if "_symhops" not in body or not re.search(
                    r"\bexit [1-9]", body
                ):
                    offenders.append(f"{script.relative_to(REPO)}:{i + 1}")
        self.assertEqual(
            offenders,
            [],
            "symlink-resolution loops without a hop bound (add the "
            f"_symhops counter + limit): {offenders}",
        )


class TestBehaviouralBound(unittest.TestCase):
    def test_extracted_loops_terminate_on_symlink_cycle(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "link1").symlink_to("link2")
            (tmp / "link2").symlink_to("link1")
            cycle = tmp / "link1"

            for script in _scripts():
                text = script.read_text(encoding="utf-8")
                lines = text.splitlines()
                for i, j, var in _loops(text):
                    # Include the _symhops=0 init immediately above the
                    # loop when present.
                    start = i
                    while start > 0 and "_symhops=0" in lines[start - 1]:
                        start -= 1
                    snippet = "\n".join(lines[start : j + 1])
                    harness = (
                        "set -uo pipefail\n"
                        f'{var}="$1"\n'
                        f"{snippet}\n"
                        'echo "RESOLVED"\n'
                    )
                    with self.subTest(script=str(script), loop_line=i + 1):
                        proc = subprocess.run(
                            ["bash", "-c", harness, "harness", str(cycle)],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            cwd=td,
                            check=False,
                        )
                        self.assertNotEqual(
                            proc.returncode,
                            0,
                            f"{script}: loop resolved a symlink cycle "
                            f"without erroring: {proc.stdout!r}",
                        )
                        self.assertIn("hop limit", proc.stderr)


if __name__ == "__main__":
    unittest.main()
