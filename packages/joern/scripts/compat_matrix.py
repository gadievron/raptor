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

    # record sha256 pins for the downloaded assets / enforce them
    python3 packages/joern/scripts/compat_matrix.py --tags v4.0.458 --update-pins
    python3 packages/joern/scripts/compat_matrix.py --tags v4.0.458 --require-pinned

Exit code 0 iff every tested version passes every step.

Downloads are sha256-checked against compat_matrix_pins.json (the
extracted launcher is EXECUTED, so a compromised release asset is code
execution here): pinned+mismatch refuses the archive, unpinned warns
loudly with the computed digest, --require-pinned refuses unpinned
tags outright.

The per-version E2E runs in a subprocess (--e2e mode, internal) with
the release's joern-cli dir prepended to PATH: packages.joern.prereqs
caches binary resolution per process, so each version needs a fresh
interpreter.
"""

from __future__ import annotations

import argparse
import contextlib
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
# checkout (see core.config.pin_raptor_dir). Import must follow the
# sys.path insert above.
from core.config import pin_raptor_dir_in_environ  # noqa: E402
from core.run.scratch import scratch_dir  # noqa: E402

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

# sha256 pins for release assets. The matrix downloads archives from
# the live releases API and EXECUTES the extracted launcher — a
# compromised release asset (or API response steering to one) is code
# execution on the dev host. Pins are trust-on-first-use: an unpinned
# asset downloads with a loud warning that prints its digest;
# ``--update-pins`` records the digests of everything downloaded this
# run; ``--require-pinned`` refuses unpinned tags outright (use it for
# the standing support floor). Keyed "<tag>/<asset-filename>" so the
# per-platform and platform-independent archives of one tag pin
# independently.
_PINS_FILE = Path(__file__).resolve().parent / "compat_matrix_pins.json"

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


def _load_pins(path: Path = _PINS_FILE) -> dict[str, str]:
    """The pins mapping, without documentation keys. Missing or
    unparseable file means "no pins" (every download warns)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        k: v for k, v in data.items()
        if not k.startswith("_") and isinstance(v, str)
    }


def _save_pins(pins: dict[str, str], path: Path = _PINS_FILE) -> None:
    """Persist *pins* (sorted, with the format comment preserved)."""
    payload: dict[str, str] = {
        "_comment": (
            "sha256 pins for joern release assets, keyed "
            "'<tag>/<asset-filename>'. Populate by running "
            "compat_matrix.py --update-pins after verifying a "
            "download out-of-band; verify pinned tags with "
            "--require-pinned."
        ),
    }
    payload.update({k: pins[k] for k in sorted(pins)})
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _pin_key(tag: str, asset_name: str) -> str:
    return f"{tag}/{asset_name}"


def _tag_has_pin(pins: dict[str, str], tag: str) -> bool:
    """Whether ANY candidate asset for *tag* carries a pin — the
    pre-download gate for ``--require-pinned`` (checked before
    spending a ~1.7 GB download on an asset we'd refuse anyway)."""
    candidates = {
        template.format(tag=tag, arch=_arch()).rsplit("/", 1)[1]
        for template in _DOWNLOAD_URLS
    }
    return any(_pin_key(tag, name) in pins for name in candidates)


def _verify_pin(
    pins: dict[str, str], tag: str, asset_name: str, digest: str,
) -> bool:
    """True when the asset is pinned and matches; False when unpinned.
    A pinned-but-mismatching digest raises — the archive must not be
    extracted, let alone executed."""
    expected = pins.get(_pin_key(tag, asset_name))
    if expected is None:
        return False
    if expected.lower() != digest.lower():
        msg = (
            f"sha256 mismatch for {tag}/{asset_name}: pinned "
            f"{expected}, downloaded {digest} — refusing to extract"
        )
        raise RuntimeError(msg)
    return True


def _download(tag: str, dest: Path) -> tuple[str, str]:
    """Download one release archive; returns (asset_name, sha256hex).

    The digest is computed while streaming so pin verification never
    re-reads the ~1.7 GB archive.
    """
    import hashlib

    last_err: Exception | None = None
    for template in _DOWNLOAD_URLS:
        url = template.format(tag=tag, arch=_arch())
        asset_name = url.rsplit("/", 1)[1]
        digest = hashlib.sha256()
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, \
                    Path(dest).open("wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    digest.update(chunk)
                    out.write(chunk)
        except urllib.error.HTTPError as e:
            last_err = e
            continue
        size = dest.stat().st_size
        if size < _MIN_ARCHIVE_BYTES:
            msg = f"download too small ({size} bytes) — bad asset?"
            raise RuntimeError(msg)
        return asset_name, digest.hexdigest()
    msg = f"no downloadable asset for {tag}: {last_err}"
    raise RuntimeError(msg)


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
    msg = "no joern launcher in extracted archive"
    raise RuntimeError(msg)


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

    # Scratch via core.run.scratch: removed when the stack closes in
    # the finally below, and the joern-matrix- prefix is listed in the
    # tmp reaper's static tuple, so a SIGKILLed matrix run strands
    # nothing past the age floor.
    _scratch = contextlib.ExitStack()
    fixture_dir = _scratch.enter_context(scratch_dir("joern-matrix-src-"))
    cpg_dir = _scratch.enter_context(scratch_dir("joern-matrix-cpg-"))
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

        # Learned flow semantics: a kill row on the pass-through
        # function must suppress the inter-procedural main→strcpy
        # flow that the baseline finds. Exercises the FullNameSemantics
        # / DefaultSemantics().after API this joern release ships —
        # the exact drift surface this matrix exists to catch.
        baseline = srv.run_taint_queries_batch([("main", "strcpy")])
        srv.set_flow_semantics(["process"])
        killed = srv.run_taint_queries_batch([("main", "strcpy")])
        srv.set_flow_semantics([])
        if not baseline:
            results["semantics_kill"] = "FAIL(0 baseline flows)"
        elif killed:
            results["semantics_kill"] = (
                f"FAIL({len(killed)} flows survived kill)"
            )
        else:
            results["semantics_kill"] = f"ok(0 vs {len(baseline)})"
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
        _scratch.close()

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
    ap.add_argument("--update-pins", action="store_true",
                    help="record the sha256 of every downloaded asset "
                         "into compat_matrix_pins.json")
    ap.add_argument("--require-pinned", action="store_true",
                    help="refuse tags whose release asset has no sha256 "
                         "pin (use for the standing support floor)")
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

    # Hand-rolled (not scratch_dir): ownership is conditional — the dir
    # survives on --keep or an operator-supplied --workdir. The
    # joern-matrix- prefix is listed in the tmp reaper's static tuple,
    # so an auto-created dir stranded by SIGKILL (or forgotten --keep
    # output) is reclaimed past the age floor.
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="joern-matrix-"))
    workdir.mkdir(parents=True, exist_ok=True)

    pins = _load_pins()
    rows: list[tuple[str, dict]] = []
    for tag in tags:
        archive = workdir / f"{tag}.zip"
        tree = workdir / tag
        try:
            if args.require_pinned and not _tag_has_pin(pins, tag):
                rows.append((tag, {
                    "pass": False,
                    "exception": "unpinned release refused "
                                 "(--require-pinned)",
                }))
                print(_format_row(tag, rows[-1][1]), flush=True)
                continue
            print(f"[{tag}] downloading...", flush=True)
            asset_name, digest = _download(tag, archive)
            pinned = _verify_pin(pins, tag, asset_name, digest)
            if args.require_pinned and not pinned:
                # The tag had SOME pin (pre-download gate passed) but
                # the asset actually served isn't the pinned one.
                msg = (
                    f"asset {asset_name} for {tag} has no pin "
                    f"(--require-pinned); sha256={digest}"
                )
                raise RuntimeError(msg)
            if not pinned:
                if args.update_pins:
                    pins[_pin_key(tag, asset_name)] = digest
                    _save_pins(pins)
                    print(f"[{tag}] pinned {asset_name} "
                          f"sha256={digest}", flush=True)
                else:
                    print(
                        f"[{tag}] WARNING: {asset_name} is not sha256-"
                        f"pinned — downloaded digest {digest}. Re-run "
                        f"with --update-pins to record it, or add it "
                        f"to {_PINS_FILE.name}.",
                        flush=True,
                    )
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
