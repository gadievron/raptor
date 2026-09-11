"""Python path safety: library modules use the RAPTOR_DIR hard lookup.

Half of the package had migrated to ``sys.path.insert(0,
os.environ["RAPTOR_DIR"])`` while four modules still carried the
positional ``Path(__file__).parents[2]`` walk — a relocation broke the
stragglers silently while the migrated files failed loud. Pin the whole
package to the canonical pattern.
"""

from __future__ import annotations

from pathlib import Path

_PKG = Path(__file__).resolve().parents[1]


def test_no_positional_sys_path_inserts():
    offenders = []
    for mod in sorted(_PKG.glob("*.py")):
        for lineno, line in enumerate(
            mod.read_text(encoding="utf-8").splitlines(), 1,
        ):
            if "sys.path.insert" in line and "RAPTOR_DIR" not in line:
                offenders.append(f"{mod.name}:{lineno}: {line.strip()}")
    assert offenders == [], (
        "positional sys.path setup found (use the RAPTOR_DIR hard "
        f"lookup — see CLAUDE.md 'Python path safety'): {offenders}"
    )
