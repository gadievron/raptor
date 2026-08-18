#!/usr/bin/env python3
"""Joern version-compatibility matrix — live E2E per release.

Dev tool: downloads joern releases from GitHub, and for each one runs
the full RAPTOR pipeline against a known-vulnerable C fixture with NO
mocks:

    joern-parse CPG build -> server boot (GC flag adaptation on the
    host JDK) -> importCpg -> method query -> intra- and
    inter-procedural taint queries -> tiered sweep (C_CPP profile)
    -> clean shutdown

Each release is downloaded, tested, and deleted sequentially so peak
disk stays ~5 GB (release archives are ~1.7 GB).

Usage (from the repo root):

    # newest 10 releases (the standing support target)
    python3 packages/joern/scripts/compat_matrix.py

    # explicit tags, e.g. verify the support floor
    python3 packages/joern/scripts/compat_matrix.py --tags v4.0.458

    # newest N
    python3 packages/joern/scripts/compat_matrix.py --versions 3

    # test an already-extracted install without downloading
    python3 packages/joern/scripts/compat_matrix.py --joern-dir ~/bin/joern/joern-cli

Exit code 0 iff every tested version passes every step.

The per-version E2E runs in a subprocess (--e2e mode, internal) with
the release's joern-cli dir prepended to PATH: packages.joern.prereqs
caches binary resolution per process, so each version needs a fresh
interpreter.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

# packages/joern/scripts/compat_matrix.py
#   parents[0] = scripts/
#   parents[1] = joern/
#   parents[2] = packages/
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
# Hard-SET (never setdefault): children of this tree must import this
# tree even when the launching shell exported RAPTOR_DIR for another
# checkout (see core.config.pin_raptor_dir).
from core.config import pin_raptor_dir_in_environ

pin_raptor_dir_in_environ()

_RELEASES_API = "https://api.github.com/repos/joernio/joern/releases"
# Newer releases ship per-platform archives; older ones (v4.0.458
# through ~v4.0.5xx) ship a single platform-independent joern-cli.zip.
_DOWNLOAD_URLS = (
    ("https://github.com/joernio/joern/releases/download/"
     "{tag}/joern-cli-linux-{arch}.zip"),
    ("https://github.com/joernio/joern/releases/download/"
     "{tag}/joern-cli.zip"),
)
# A real release archive is ~1.7 GB; anything tiny is an error page.
_MIN_ARCHIVE_BYTES = 100_000_000
_E2E_TIMEOUT_S = 600

# Fixture with one intra-procedural flow (process -> strcpy) and one
# inter-procedural flow (main argv -> process -> strcpy).  The taint
# query sources from method parameters, so both are reachable; the
# expected counts below are pinned against joern 4.0.594-603.
_FIXTURE_C = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("%s\\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        char *data = getenv("USER_DATA");
        if (data) process(data);
        process(argv[1]);
    }
    return 0;
}
"""


def _arch() -> str:
    m = platform.machine()
    return {"x86_64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)


def _newest_tags(count: int) -> list[str]:
    with urllib.request.urlopen(
        f"{_RELEASES_API}?per_page={max(count, 30)}", timeout=30
    ) as resp:
        releases = json.load(resp)
    tags = [r["tag_name"] for r in releases if not r.get("prerelease")]
    return tags[:count]


def _download(tag: str, dest: Path) -> None:
    last_err: Exception | None = None
    for template in _DOWNLOAD_URLS:
        url = template.format(tag=tag, arch=_arch())
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, \
                    open(dest, "wb") as out:
                shutil.copyfileobj(resp, out, length=1 << 20)
        except urllib.error.HTTPError as e:
            last_err = e
            continue
        size = dest.stat().st_size
        if size < _MIN_ARCHIVE_BYTES:
            raise RuntimeError(
                f"download too small ({size} bytes) — bad asset?"
            )
        return
    raise RuntimeError(f"no downloadable asset for {tag}: {last_err}")


def _extract(archive: Path, dest: Path) -> Path:
    """Unzip preserving unix mode bits; return the joern-cli dir."""
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            extracted = Path(zf.extract(info, dest))
            mode = info.external_attr >> 16
            if mode:
                extracted.chmod(mode)
    for launcher in dest.rglob("joern"):
        if launcher.is_file():
            return launcher.parent
    raise RuntimeError("no joern launcher in extracted archive")


# ---------------------------------------------------------------------------
# Per-version E2E (subprocess entry point)
# ---------------------------------------------------------------------------


def run_e2e(joern_dir: str) -> dict:
    """Full pipeline against one joern install. Returns step results."""
    os.environ["PATH"] = joern_dir + os.pathsep + os.environ["PATH"]

    from packages.joern.lang_config import C_CPP
    from packages.joern.prereqs import version as joern_version
    from packages.joern.runner import build_cpg
    from packages.joern.server import JoernServer

    results: dict = {"joern_version": joern_version() or "?"}
    t0 = time.monotonic()

    fixture_dir = Path(tempfile.mkdtemp(prefix="joern-matrix-src-"))
    cpg_dir = Path(tempfile.mkdtemp(prefix="joern-matrix-cpg-"))
    srv = None
    try:
        (fixture_dir / "vuln.c").write_text(_FIXTURE_C, encoding="utf-8")

        cpg = build_cpg(fixture_dir, output_dir=cpg_dir)
        results["parse"] = "ok"

        srv = JoernServer()
        srv.start()
        results["boot"] = f"ok({time.monotonic() - t0:.0f}s)"

        results["import"] = "ok" if srv.import_cpg(cpg.path) else "FAIL"

        r = srv.query("cpg.method.name.l")
        body = r.raw_output or ""
        results["query"] = (
            "ok" if ("process" in body and "main" in body) else "FAIL"
        )

        intra = srv.run_taint_query("process", "strcpy")
        results["taint_intra"] = f"ok({len(intra)})" if intra else "FAIL(0)"

        inter = srv.run_taint_query("main", "strcpy")
        inter_ok = any(
            getattr(f, "is_inter_procedural", False) for f in inter
        )
        results["taint_inter"] = f"ok({len(inter)})" if inter_ok else "FAIL"

        sweep = srv.run_tiered_sweep(lang_profile=C_CPP)
        if sweep.errors:
            results["sweep"] = "FAIL:" + sweep.errors[0][:80]
        elif not sweep.flows:
            results["sweep"] = "FAIL(0 flows)"
        else:
            results["sweep"] = f"ok({len(sweep.flows)})"
    except Exception as e:  # noqa: BLE001 — report, don't crash the matrix
        results["exception"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        if srv is not None:
            try:
                srv.stop()
            except (OSError, subprocess.SubprocessError):
                # Best-effort teardown: stop() can leak OSError from
                # signalling and TimeoutExpired from the post-SIGKILL
                # wait; a wiring bug must still crash the matrix.
                pass
        shutil.rmtree(fixture_dir, ignore_errors=True)
        shutil.rmtree(cpg_dir, ignore_errors=True)

    results["total_s"] = round(time.monotonic() - t0)
    results["pass"] = "exception" not in results and not any(
        "FAIL" in str(v) for v in results.values()
    )
    return results


def _run_e2e_subprocess(joern_dir: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()),
         "--e2e", str(joern_dir)],
        capture_output=True, text=True, timeout=_E2E_TIMEOUT_S,
        check=False,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("E2E_RESULT|"):
            return json.loads(line.split("|", 1)[1])
    return {
        "pass": False,
        "exception": f"driver produced no result (rc={proc.returncode}): "
                     f"{(proc.stderr or proc.stdout)[-200:]}",
    }


# ---------------------------------------------------------------------------
# Matrix orchestration
# ---------------------------------------------------------------------------


def _format_row(tag: str, r: dict) -> str:
    verdict = "PASS" if r.get("pass") else "FAIL"
    steps = " ".join(
        f"{k}={v}" for k, v in r.items()
        if k not in ("pass", "joern_version")
    )
    return f"{tag:<12} {verdict:<5} {steps}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--versions", type=int, default=10,
                    help="test the newest N releases (default 10)")
    ap.add_argument("--tags", type=str, default=None,
                    help="comma-separated release tags (overrides --versions)")
    ap.add_argument("--joern-dir", type=Path, default=None,
                    help="test one already-extracted joern-cli dir; no download")
    ap.add_argument("--workdir", type=Path, default=None,
                    help="scratch dir for downloads (default: mkdtemp)")
    ap.add_argument("--keep", action="store_true",
                    help="keep downloaded archives and extracted trees")
    ap.add_argument("--e2e", type=str, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.e2e:
        results = run_e2e(args.e2e)
        print("E2E_RESULT|" + json.dumps(results), flush=True)
        return 0 if results["pass"] else 1

    if args.joern_dir:
        results = _run_e2e_subprocess(args.joern_dir.resolve())
        tag = results.get("joern_version", "?")
        print(_format_row(tag, results))
        return 0 if results.get("pass") else 1

    if args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    else:
        print(f"resolving newest {args.versions} release tags...", flush=True)
        tags = _newest_tags(args.versions)

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="joern-matrix-"))
    workdir.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, dict]] = []
    for tag in tags:
        archive = workdir / f"{tag}.zip"
        tree = workdir / tag
        try:
            print(f"[{tag}] downloading...", flush=True)
            _download(tag, archive)
            joern_dir = _extract(archive, tree)
            print(f"[{tag}] running E2E...", flush=True)
            result = _run_e2e_subprocess(joern_dir)
        except Exception as e:  # noqa: BLE001 — one bad tag shouldn't stop the matrix
            result = {"pass": False,
                      "exception": f"{type(e).__name__}: {e}"[:200]}
        finally:
            if not args.keep:
                archive.unlink(missing_ok=True)
                shutil.rmtree(tree, ignore_errors=True)
        rows.append((tag, result))
        print(_format_row(tag, result), flush=True)

    if not args.keep and args.workdir is None:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n=== joern compatibility matrix ===")
    for tag, result in rows:
        print(_format_row(tag, result))
    failed = [tag for tag, r in rows if not r.get("pass")]
    print(f"\n{len(rows) - len(failed)}/{len(rows)} versions pass"
          + (f" — FAILURES: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
