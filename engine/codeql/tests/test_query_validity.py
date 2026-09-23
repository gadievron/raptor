"""Compile-validity gate for the curated CodeQL query packs.

The engine's other rule families carry mechanical validity gates
(coccinelle: per-rule spatch parse + fixture closure; semgrep:
derived-universe --validate + CWE gate); the curated CodeQL queries
had none — a broken query surfaced only as a per-run
``QueryResult(success=False)`` warning on operator runs, and the
packs' floating ``codeql/<lang>-all: "*"`` dependency means an
upstream API break used to land silently.

The universe is derived exactly the way the production runner
discovers packs (``analyze_curated_packs``: a per-language directory
with a ``qlpack.yml`` and at least one ``.ql``), and dependency
resolution mirrors the runner too: plain resolution first, then the
vendored ``<lang>-all`` roots from cached standard query packs via
``--additional-packs``. Only a RESOLUTION failure on a host with no
usable pack cache skips (environmental); a compile error always
fails.

The packs deliberately keep the floating dependency instead of a
committed lockfile: the production runner's offline path resolves
against whatever ``<lang>-all`` version the standard-suite cache
carries, and a committed pin would fail exactly those hosts. The
floating dep's risk (silent upstream break) is what this gate
converts into a loud CI failure.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_QUERIES_ROOT = Path(__file__).resolve().parents[1] / "queries"

_RESOLUTION_FAILURE_MARKERS = (
    "version solving failed",
    "Could not resolve library path",
    "cannot be found",
)


def _pack_dirs() -> list[Path]:
    """Per-language curated packs, discovered the runner's way."""
    return sorted(
        d for d in _QUERIES_ROOT.iterdir()
        if d.is_dir()
        and (d / "qlpack.yml").is_file()
        and any(d.glob("*.ql"))
    )


def _compile(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — fixed local binary, repo input
        ["codeql", "query", "compile", *args],
        capture_output=True, text=True, timeout=1200,
    )


def _compile_with_fallback(
    target: Path, lang: str,
) -> subprocess.CompletedProcess:
    """Compile, retrying with the runner's vendored-stdlib fallback."""
    proc = _compile([str(target)])
    if proc.returncode == 0 or not _is_resolution_failure(proc.stderr):
        return proc
    from packages.codeql.query_runner import vendored_stdlib_roots

    extra = [f"--additional-packs={root}" for root in
             vendored_stdlib_roots(lang)]
    if not extra:
        pytest.skip(
            f"codeql cannot resolve {lang}-all offline and no standard "
            f"query pack is cached (runner would hit the same wall): "
            f"{proc.stderr[-500:]}"
        )
    proc = _compile([*extra, str(target)])
    if proc.returncode != 0 and _is_resolution_failure(proc.stderr):
        pytest.skip(
            f"codeql dependency resolution unavailable offline for "
            f"{lang}: {proc.stderr[-500:]}"
        )
    return proc


def _is_resolution_failure(stderr: str) -> bool:
    return any(m in stderr for m in _RESOLUTION_FAILURE_MARKERS)


def test_universe_is_nonempty():
    # Guards the derivation itself — a moved queries dir must not turn
    # the compile gate into a vacuous zero-case pass.
    packs = _pack_dirs()
    assert len(packs) >= 2
    assert sum(len(list(d.glob("*.ql"))) for d in packs) >= 8


@pytest.mark.slow
@pytest.mark.skipif(
    shutil.which("codeql") is None, reason="codeql not installed",
)
@pytest.mark.parametrize("pack", _pack_dirs(), ids=lambda p: p.name)
def test_curated_pack_compiles(pack: Path):
    proc = _compile_with_fallback(pack, pack.name)
    assert proc.returncode == 0, (
        f"curated pack {pack.name} failed codeql query compile — a "
        f"broken query is a silent per-run outage on every /codeql "
        f"and /agentic run:\n{proc.stderr[-4000:]}"
    )


@pytest.mark.slow
@pytest.mark.skipif(
    shutil.which("codeql") is None, reason="codeql not installed",
)
def test_gate_detects_broken_query(tmp_path):
    # Self-check: the gate proves the universe clean only if a broken
    # query actually fails compilation in this environment.
    src = _QUERIES_ROOT / "java"
    probe = tmp_path / "java"
    shutil.copytree(src, probe)
    bad = probe / "Broken.ql"
    bad.write_text(
        "import java\n\nfrom NoSuchClass c\nselect c\n",
        encoding="utf-8",
    )
    proc = _compile_with_fallback(bad, "java")
    assert proc.returncode != 0
    assert not _is_resolution_failure(proc.stderr)
