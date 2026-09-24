"""Match-precision measurement harness for packages.ghidra.match.

Builds a small embedded C corpus twice (v1 at ``-O0``, v2 at ``-O2``
with source edits), strips the v2 binary, imports all three via the
r2 importer, and matches the NAMED v1 database against the STRIPPED
v2 database. Ground truth comes from the named v2 import joined to
the stripped import by address — so every emitted pair is checkable.

The load-bearing number is **pair precision**: the fraction of
emitted match pairs that are correct. A wrong pair silently
transplants triage attention (and any downstream annotation) onto an
unrelated function, so precision gates trust in ``diff --matched``
output; recall merely bounds how much manual matching remains.

The r2 importer emits no xrefs and no string addresses, so this
harness exercises the name, decompilation-hash, and similarity tiers
against real decompiler output. The anchor and call-graph tiers get
their signal only from Ghidra imports and are covered by the
perturbation tests in ``tests/test_match.py``.

Run: ``python3 -m packages.ghidra.match_precision [--out DIR]``
Output: ``report.json`` + stdout summary. Exit 3 when the toolchain
(cc, strip, r2) is unavailable.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

from core.atomic_fs import write_text_atomically
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional

_CORPUS_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_flags(const char *s) {
    int f = 0;
    while (*s) { if (*s == 'v') f |= 1; if (*s == 'q') f |= 2; s++; }
    return f;
}

static int check_password(const char *pw) {
    if (!pw) { fprintf(stderr, "auth: empty password\n"); return -1; }
    if (strlen(pw) < 8) { fprintf(stderr, "auth: too short\n"); return -1; }
    return strcmp(pw, "hunter2-hunter2") == 0;
}

static void audit_log(const char *event, int code) {
    fprintf(stderr, "audit: %s (%d)\n", event, code);
}

static int read_header(FILE *fp, unsigned char *buf, int cap) {
    int n = (int)fread(buf, 1, (size_t)cap, fp);
    if (n < 4) { audit_log("short header", n); return -1; }
    return n;
}

static int checksum(const unsigned char *p, int n) {
    int acc = 0x1505;
    for (int i = 0; i < n; i++) acc = acc * 33 + p[i];
    return acc;
}

static int checksum_alt(const unsigned char *p, int n) {
    int acc = 0x811c;
    for (int i = 0; i < n; i++) acc = (acc ^ p[i]) * 0x0101;
    return acc;
}

#ifdef V2
static int validate_frame(const unsigned char *p, int n) {
    if (n < 8) return -1;                 /* v2: stricter minimum */
    if (p[0] != 0x7e) { audit_log("bad magic", p[0]); return -1; }
    if (checksum(p + 1, n - 1) == 0) return -1;
    return 0;
}

static void report_version(void) {
    printf("demo v2.0 (frame validation enabled)\n");
}
#else
static int validate_frame(const unsigned char *p, int n) {
    if (n < 4) return -1;
    if (p[0] != 0x7e) { audit_log("bad magic", p[0]); return -1; }
    return 0;
}

static void legacy_probe(void) {
    printf("probing legacy transport...\n");
}
#endif

static void run_pipeline(FILE *fp, int flags) {
    unsigned char buf[64];
    int n = read_header(fp, buf, (int)sizeof buf);
    if (n < 0) return;
    if (validate_frame(buf, n) != 0) return;
    if (flags & 1)
        printf("frame ok: sum=%d alt=%d\n",
               checksum(buf, n), checksum_alt(buf, n));
}

int main(int argc, char **argv) {
    int flags = argc > 1 ? parse_flags(argv[1]) : 0;
    if (argc > 2 && check_password(argv[2]) != 1) {
        audit_log("auth failure", flags);
        return 1;
    }
#ifdef V2
    report_version();
#else
    legacy_probe();
#endif
    run_pipeline(stdin, flags);
    return 0;
}
"""


@dataclass
class Report:
    matched: int
    correct: int
    wrong_pairs: List[Dict[str, str]]
    truth_pairs: int
    per_tier: Dict[int, Dict[str, int]]
    toolchain: Dict[str, str]

    @property
    def precision(self) -> Optional[float]:
        return self.correct / self.matched if self.matched else None

    @property
    def recall(self) -> Optional[float]:
        return (self.correct / self.truth_pairs
                if self.truth_pairs else None)

    def to_dict(self) -> Dict[str, object]:
        return {
            "matched": self.matched,
            "correct": self.correct,
            "precision": self.precision,
            "recall": self.recall,
            "truth_pairs": self.truth_pairs,
            "wrong_pairs": self.wrong_pairs,
            "per_tier": {str(k): v for k, v in
                         sorted(self.per_tier.items())},
            "toolchain": self.toolchain,
        }


def _tool_version(cmd: List[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=30, check=False)
        return (out.stdout or out.stderr).splitlines()[0].strip()
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return "unknown"


def _compile(cc: str, src: Path, out: Path,
             extra: List[str]) -> None:
    subprocess.run(
        [cc, "-o", str(out), str(src), *extra],
        check=True, capture_output=True, timeout=120,
    )


def run_measurement(out_dir: Path) -> Report:
    from packages.ghidra.match import _is_auto_named, match_databases
    from packages.ghidra.r2_import import import_binary_r2

    cc = shutil.which("cc") or shutil.which("gcc")
    strip = shutil.which("strip")
    if not cc or not strip:
        raise RuntimeError("toolchain missing: need cc/gcc and strip")

    with TemporaryDirectory(prefix="binmatch-precision-") as td:
        work = Path(td)
        src = work / "demo.c"
        src.write_text(_CORPUS_C)
        v1 = work / "demo-v1"
        v2 = work / "demo-v2"
        v2s = work / "demo-v2-stripped"
        _compile(cc, src, v1, ["-O0", "-g"])
        _compile(cc, src, v2, ["-O2", "-g", "-DV2"])
        shutil.copy2(v2, v2s)
        subprocess.run([strip, str(v2s)], check=True, timeout=60)

        db_old = import_binary_r2(v1)
        db_truth = import_binary_r2(v2)
        db_new = import_binary_r2(v2s)

    truth_name_at: Dict[int, str] = {
        f.address: str(f.name) for f in db_truth.functions
        if not _is_auto_named(f)
    }
    old_names = {str(f.name) for f in db_old.functions
                 if not _is_auto_named(f)}
    truth_pairs = sum(1 for n in truth_name_at.values()
                      if n in old_names)

    result = match_databases(db_old, db_new)
    old_name_at = {f.address: str(f.name) for f in db_old.functions}

    correct = 0
    wrong: List[Dict[str, str]] = []
    per_tier: Dict[int, Dict[str, int]] = {}
    for p in result.pairs:
        expected = truth_name_at.get(p.new_address)
        got = old_name_at.get(p.old_address, "")
        # pairs on functions the truth import cannot name (auto-only
        # regions like _start glue) are unscoreable; count separately
        bucket = per_tier.setdefault(
            p.tier, {"correct": 0, "wrong": 0, "unscoreable": 0})
        if expected is None:
            bucket["unscoreable"] += 1
            continue
        if got == expected:
            correct += 1
            bucket["correct"] += 1
        else:
            bucket["wrong"] += 1
            wrong.append({"old": got, "matched_to": expected,
                          "tier": str(p.tier)})

    scoreable = correct + len(wrong)
    report = Report(
        matched=scoreable,
        correct=correct,
        wrong_pairs=wrong,
        truth_pairs=truth_pairs,
        per_tier=per_tier,
        toolchain={
            "cc": _tool_version([cc, "--version"]),
            "strip": _tool_version([strip, "--version"]),
            "r2": _tool_version(["radare2", "-v"]),
        },
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    # Atomic write (planted-symlink defence at the predictable
    # artifact name in the reused out dir).
    write_text_atomically(
        out_dir / "report.json", json.dumps(report.to_dict(), indent=2))
    return report


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="python3 -m packages.ghidra.match_precision",
        description=("Measure match_databases pair precision on a "
                     "real stripped cross-optimization build."),
    )
    p.add_argument("--out", type=Path, default=None,
                   help="output dir (default: "
                        "out/binmatch-precision/runs/<ts>)")
    args = p.parse_args(argv)

    try:
        from packages.ghidra.r2_import import r2_available
        if not r2_available():
            print("r2 unavailable — cannot measure", file=sys.stderr)
            return 3
    except ImportError:
        print("r2 importer unavailable — cannot measure",
              file=sys.stderr)
        return 3

    out = args.out
    if out is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = Path("out/binmatch-precision/runs") / ts

    try:
        report = run_measurement(out)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"measurement failed: {exc}", file=sys.stderr)
        return 3

    prec = report.precision
    rec = report.recall
    if prec is None:
        print("binmatch-precision: no scoreable pairs")
    else:
        print(f"binmatch-precision: {report.matched} scoreable "
              f"pairs, {report.correct} correct — "
              f"precision={prec:.3f}")
    if rec is not None:
        print(f"binmatch-precision: recall={rec:.3f} "
              f"over {report.truth_pairs} truth pairs")
    for w in report.wrong_pairs:
        print(f"  WRONG (tier {w['tier']}): {w['old']} "
              f"matched to {w['matched_to']}")
    print(f"binmatch-precision: report -> {out / 'report.json'}")
    return 0 if not report.wrong_pairs else 1


if __name__ == "__main__":
    raise SystemExit(main())
