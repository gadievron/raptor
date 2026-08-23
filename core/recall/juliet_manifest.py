"""Generate a HELD-OUT recall manifest from the Juliet Java suite.

HOLDOUT DOCTRINE (the binary-oracle discipline, applied to recall):
detection mechanisms are tuned against the OWASP Benchmark corpus
ONLY. Juliet results are generalization checks — run once per round,
reported at first contact, and never used to tune probes, rules,
gates, or thresholds. A mechanism that only moves the OWASP numbers
has been overfit; the Juliet delta is the evidence either way.

Ground truth comes from Juliet's own structure: every single-file
test case declares its ``bad*`` methods first and its ``good*``
methods after (verified empirically on the pinned mirror — the
generator refuses files that violate the ordering rather than
mislabelling them). The bad-method span becomes one ``expected``
entry; the good-method span becomes one ``clean_region``. Multi-file
variants (``_54a.java``-style flows spanning classes) are excluded
from this first manifest and counted, not silently dropped; the
separate Juliet-B manifest (``generate_manifest_b`` / ``--variant-b``)
covers them with sink-anchored labeling.

The suite is NOT bundled: the generator reads an operator-acquired
clone of the public find-sec-bugs mirror of the NIST suite, pinned by
sha (labels are sha-bound like every recall corpus).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from core.recall.manifest import SCHEMA_VERSION

#: Public mirror of the NIST Juliet Java suite (v1.2 content).
JULIET_REPO_URL = "https://github.com/find-sec-bugs/juliet-test-suite"
JULIET_PINNED_SHA = "b2c6df3733e2176fe7097e4784895c6891632b4c"
JULIET_DEFAULT_CLONE = "out/recall-corpus/juliet-java"
_TESTCASES = "src/testcases"

#: Juliet CWE directories comparable to the OWASP Benchmark classes.
#: Labels keep Juliet's own CWE numbers; the matcher's family
#: tolerance bridges 23/36 -> 22 and 80/83 -> 79. CWE81 is excluded:
#: it has no family bridge, so misses there would measure taxonomy,
#: not detection. The mirror ships no CWE330/CWE501 Java cases.
COMPARABLE_DIRS: dict[str, int] = {
    "CWE78_OS_Command_Injection": 78,
    "CWE89_SQL_Injection": 89,
    "CWE90_LDAP_Injection": 90,
    "CWE23_Relative_Path_Traversal": 23,
    "CWE36_Absolute_Path_Traversal": 36,
    "CWE80_XSS": 80,
    "CWE83_XSS_Attribute": 83,
    "CWE327_Use_Broken_Crypto": 327,
    "CWE328_Reversible_One_Way_Hash": 328,
}

_MULTI_FILE_RE = re.compile(r"_\d+[a-z]\.java$")
_DECL_RE = re.compile(
    r"^\s*(?:public|private|protected)\s+[\w<>\[\]., ]*?"
    r"\s(bad\w*|good\w*)\s*\(")

_ACQUIRE_HINT = (
    f"git clone {JULIET_REPO_URL} <clone-dir> && "
    f"git -C <clone-dir> checkout {JULIET_PINNED_SHA}"
)


class JulietManifestError(RuntimeError):
    pass


def _verify_clone(clone_dir: Path) -> None:
    if not (clone_dir / _TESTCASES).is_dir():
        msg = (
            f"Juliet clone not found or incomplete at {clone_dir} — "
            f"acquire with: {_ACQUIRE_HINT}"
        )
        raise JulietManifestError(msg)
    try:
        proc = subprocess.run(
            ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        head = proc.stdout.strip().lower()
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"cannot sha-verify {clone_dir}: {exc}"
        raise JulietManifestError(msg) from exc
    if proc.returncode != 0 or not head:
        msg = f"cannot sha-verify {clone_dir}: {proc.stderr.strip()}"
        raise JulietManifestError(msg)
    if head != JULIET_PINNED_SHA:
        msg = (
            f"{clone_dir} is at {head[:12]}, labels are pinned to "
            f"{JULIET_PINNED_SHA[:12]} — {_ACQUIRE_HINT}"
        )
        raise JulietManifestError(msg)


def split_bad_good_spans(
        text: str) -> tuple[tuple[int, int], tuple[int, int]] | None:
    """Return ((bad_start, bad_end), (good_start, good_end)) or None.

    Line numbers are 1-based. None means the file has no usable
    bad/good split (no bad method, no good method, or an ordering
    violation — a good method before the last bad method — which
    would make span labels lie).
    """
    decls: list[tuple[int, str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        m = _DECL_RE.match(line)
        if m:
            decls.append((i, m.group(1)))
    bad = [i for i, name in decls if name.startswith("bad")]
    good = [i for i, name in decls if name.startswith("good")]
    if not bad or not good:
        return None
    if max(bad) > min(good):
        return None  # ordering violation — refuse, never mislabel
    return (min(bad), min(good) - 1), (min(good), len(lines))


def _entry(case_id: str, rel_file: str, cwe: int,
           span: tuple[int, int]) -> dict:
    return {
        "id": case_id,
        "file": rel_file,
        "line_start": span[0],
        "line_end": span[1],
        "cwe": f"CWE-{cwe}",
        "provenance": {
            "kind": "benchmark",
            "suite": "juliet-java-fsb-mirror",
            "case": case_id,
        },
    }


def generate_manifest(clone_dir: Path, *, cwes: list[int] | None = None,
                      limit: int | None = None) -> dict:
    """Build the held-out manifest dict from the verified clone.

    ``cwes`` filters to specific Juliet CWE numbers; ``limit`` caps
    expected entries per CWE (deterministic: sorted by path).
    """
    _verify_clone(clone_dir)
    expected: list[dict] = []
    clean: list[dict] = []
    skipped_multi = 0
    skipped_unsplit = 0
    per_cwe_count: dict[int, int] = {}

    for dirname, cwe in sorted(COMPARABLE_DIRS.items()):
        if cwes and cwe not in cwes:
            continue
        cwe_dir = clone_dir / _TESTCASES / dirname
        if not cwe_dir.is_dir():
            continue
        for path in sorted(cwe_dir.rglob("*.java")):
            if _MULTI_FILE_RE.search(path.name):
                skipped_multi += 1
                continue
            spans = split_bad_good_spans(
                path.read_text(encoding="utf-8", errors="replace"))
            if spans is None:
                skipped_unsplit += 1
                continue
            if limit is not None:
                n = per_cwe_count.get(cwe, 0)
                if n >= limit:
                    continue
                per_cwe_count[cwe] = n + 1
            bad_span, good_span = spans
            rel = str(path.relative_to(clone_dir))
            case_id = path.stem
            expected.append(_entry(case_id, rel, cwe, bad_span))
            clean.append(
                _entry(f"{case_id}__good", rel, cwe, good_span))

    if not expected:
        msg = "no expected entries survived the filters"
        raise JulietManifestError(msg)

    return {
        "schema_version": SCHEMA_VERSION,
        "name": "juliet-java-holdout",
        "target": {
            "repo_url": JULIET_REPO_URL,
            "pinned_sha": JULIET_PINNED_SHA,
            "local_path": str(clone_dir),
        },
        "language": "java",
        # scan-codeql is the recall-bearing profile: measured 84.3% vs
        # 29.7% for semgrep-only on this corpus (threat-model=local
        # covers Juliet's console/env/file/properties sources).
        "profile": "scan-codeql",
        "tolerance": {"line_drift": 0, "cwe_family_match": True},
        "expected": expected,
        "clean_regions": clean,
        # Coverage honesty: what the generator dropped, and why this
        # corpus exists.
        "notes": {
            "holdout_doctrine": (
                "Generalization check ONLY: mechanisms are tuned on "
                "the OWASP corpus; Juliet runs are reported at first "
                "contact and never used to tune."),
            "skipped_multi_file_variants": skipped_multi,
            "skipped_no_bad_good_split": skipped_unsplit,
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-recall-measure juliet-manifest",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--clone-dir", type=Path,
                   default=Path(JULIET_DEFAULT_CLONE))
    p.add_argument("--out", type=Path, required=True,
                   help="manifest JSON output path")
    p.add_argument("--cwe", action="append", type=int, default=[],
                   help="restrict to Juliet CWE number (repeatable)")
    p.add_argument("--limit", type=int, default=None,
                   help="cap expected entries per CWE (sorted, "
                        "deterministic)")
    p.add_argument("--variant-b", action="store_true",
                   help="generate the Juliet-B (multi-file) manifest")
    args = p.parse_args(argv)

    try:
        gen = generate_manifest_b if args.variant_b else generate_manifest
        manifest = gen(
            args.clone_dir, cwes=args.cwe or None, limit=args.limit)
    except JulietManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n",
                        encoding="utf-8")
    notes = manifest["notes"]
    if args.variant_b:
        print(f"manifest: {args.out} "
              f"({len(manifest['expected'])} expected, "
              f"{len(manifest['clean_regions'])} clean regions; "
              f"refused {sum(notes['refused'].values())}: "
              f"{notes['refused']})")
    else:
        print(f"manifest: {args.out} "
              f"({len(manifest['expected'])} expected, "
              f"{len(manifest['clean_regions'])} clean regions; skipped "
              f"{notes['skipped_multi_file_variants']} multi-file + "
              f"{notes['skipped_no_bad_good_split']} unsplittable)")
    return 0


# ---------------------------------------------------------------------------
# Juliet-B: the multi-file variants (cross-file flow), sink-anchored.
#
# LEDGER-FRESH corpus: no mechanism has ever been tuned against these
# cases (the single-file generator skipped them from day one), so every
# Juliet-B run is a pure first-contact datapoint until the ledger says
# otherwise.
#
# Juliet ships three multi-file layouts (verified on the pinned mirror):
#
#  * letter chains (``_54a``..``_54e``, ``_51a``/``_51b``, ``_66``..
#    ``_75``): the terminal file's ``badSink`` holds the dangerous
#    operation; intermediate files define forwarding ``badSink``
#    wrappers. The terminal file is the HIGHEST letter that defines
#    ``badSink`` AND whose ``badSink`` body does not forward to another
#    ``.badSink(`` — a chain whose chosen terminal still forwards is
#    refused, never guessed.
#  * source-split chains (``_61a``/``_61b``): ``badSource`` lives in
#    ``b``; the sink stays inside ``bad()`` in ``a``. No file defines
#    ``badSink``; the ``bad()``-defining file is the sink file.
#  * polarity splits (``_81_bad.java`` + ``_81_goodG2B.java`` ...):
#    the ``_bad`` file holds the dangerous action override (whole-file
#    expected entry); each ``_good*`` file is a whole-file clean
#    region; ``_base`` files label nothing.
#
# Everything else (``_good1``-style oddities, ordering violations,
# missing polarity twins) is refused and counted by reason.
# ---------------------------------------------------------------------------

_CHAIN_RE = re.compile(r"^(?P<base>.+_\d+)(?P<letter>[a-z])\.java$")
_POLAR_RE = re.compile(
    r"^(?P<base>.+_\d+)_(?P<role>bad|base|goodG2B|goodB2G|good\d*)\.java$")
_FORWARD_RE = re.compile(r"\.\s*badSink\s*\(")


def _method_spans(text: str) -> list[tuple[int, str]]:
    """(line, name) for every bad*/good* declaration, in order."""
    out: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _DECL_RE.match(line)
        if m:
            out.append((i, m.group(1)))
    return out


def _chain_sink_file(files: dict[str, str]) -> tuple[str, str] | None:
    """Pick the sink file of a letter chain; None = refuse.

    Returns (letter, refusal_reason_or_empty). ``files`` maps letter ->
    file text.
    """
    sink_definers = sorted(
        letter for letter, text in files.items()
        if _decl_defines(text, "badSink"))
    if sink_definers:
        terminal = sink_definers[-1]
        decls = _method_spans(files[terminal])
        bad_lines = [i for i, n in decls if n.startswith("bad")]
        good_lines = [i for i, n in decls if n.startswith("good")]
        if not bad_lines or not good_lines:
            return None
        body_start = min(bad_lines)
        body_end = min(good_lines) - 1
        body = "\n".join(
            files[terminal].splitlines()[body_start - 1:body_end])
        if _FORWARD_RE.search(body):
            return None  # chosen terminal still forwards — ambiguous
        return terminal, ""
    # source-split (61-style): no badSink anywhere; sink is in bad().
    bad_definers = [
        letter for letter, text in files.items()
        if _decl_defines(text, "bad")]
    if len(bad_definers) == 1:
        return bad_definers[0], ""
    return None


def _decl_defines(text: str, name: str) -> bool:
    return any(n == name for _, n in _method_spans(text))


def generate_manifest_b(clone_dir: Path, *, cwes: list[int] | None = None,
                        limit: int | None = None) -> dict:
    """Build the Juliet-B (multi-file) manifest from the verified clone.

    Sink-anchored: every expected entry sits at the file that contains
    the dangerous operation, because detectors report at the sink and
    labeling a forwarding file would manufacture phantom misses.
    """
    _verify_clone(clone_dir)
    expected: list[dict] = []
    clean: list[dict] = []
    refused: dict[str, int] = {}
    per_cwe_count: dict[int, int] = {}

    def _refuse(reason: str) -> None:
        refused[reason] = refused.get(reason, 0) + 1

    for dirname, cwe in sorted(COMPARABLE_DIRS.items()):
        if cwes and cwe not in cwes:
            continue
        cwe_dir = clone_dir / _TESTCASES / dirname
        if not cwe_dir.is_dir():
            continue
        # Group within each concrete directory (s01/s02/... or flat):
        # sibling files of one case always share a directory.
        chains: dict[Path, dict[str, Path]] = {}
        polars: dict[Path, dict[str, Path]] = {}
        for path in sorted(cwe_dir.rglob("*.java")):
            m = _CHAIN_RE.match(path.name)
            if m:
                key = path.parent / m.group("base")
                chains.setdefault(key, {})[m.group("letter")] = path
                continue
            m = _POLAR_RE.match(path.name)
            if m:
                key = path.parent / m.group("base")
                polars.setdefault(key, {})[m.group("role")] = path

        for key, members in sorted(chains.items()):
            if len(members) < 2:
                continue  # single-letter leftovers are not multi-file
            if limit is not None and per_cwe_count.get(cwe, 0) >= limit:
                continue
            texts = {letter: p.read_text(encoding="utf-8",
                                         errors="replace")
                     for letter, p in sorted(members.items())}
            picked = _chain_sink_file(texts)
            if picked is None:
                _refuse("chain_sink_ambiguous")
                continue
            letter, _ = picked
            spans = split_bad_good_spans(texts[letter])
            if spans is None:
                _refuse("chain_sink_no_bad_good_split")
                continue
            bad_span, good_span = spans
            sink_path = members[letter]
            rel = str(sink_path.relative_to(clone_dir))
            case_id = key.name
            expected.append(_entry(case_id, rel, cwe, bad_span))
            clean.append(_entry(f"{case_id}__good", rel, cwe, good_span))
            per_cwe_count[cwe] = per_cwe_count.get(cwe, 0) + 1

        for key, members in sorted(polars.items()):
            if "bad" not in members:
                _refuse("polarity_missing_bad")
                continue
            goods = {r: p for r, p in members.items()
                     if r.startswith("good") and r not in ("good1",
                                                           "good2")}
            if not goods:
                _refuse("polarity_missing_good_twin")
                continue
            if any(r in members for r in ("good1", "good2")):
                _refuse("polarity_odd_good_numbering")
                continue
            if limit is not None and per_cwe_count.get(cwe, 0) >= limit:
                continue
            case_id = key.name
            bad_path = members["bad"]
            bad_lines = bad_path.read_text(
                encoding="utf-8", errors="replace").count("\n") + 1
            rel_bad = str(bad_path.relative_to(clone_dir))
            expected.append(_entry(case_id, rel_bad, cwe,
                                   (1, bad_lines)))
            for role, gp in sorted(goods.items()):
                g_lines = gp.read_text(
                    encoding="utf-8", errors="replace").count("\n") + 1
                clean.append(_entry(f"{case_id}__{role}",
                                    str(gp.relative_to(clone_dir)),
                                    cwe, (1, g_lines)))
            per_cwe_count[cwe] = per_cwe_count.get(cwe, 0) + 1

    if not expected:
        msg = "no Juliet-B expected entries survived the filters"
        raise JulietManifestError(msg)

    return {
        "schema_version": SCHEMA_VERSION,
        "name": "juliet-b-multifile",
        "target": {
            "repo_url": JULIET_REPO_URL,
            "pinned_sha": JULIET_PINNED_SHA,
            "local_path": str(clone_dir),
        },
        "language": "java",
        "profile": "scan-codeql",
        "tolerance": {"line_drift": 0, "cwe_family_match": True},
        "expected": expected,
        "clean_regions": clean,
        "notes": {
            "ledger": (
                "LEDGER-FRESH first-contact corpus: no mechanism has "
                "been tuned against multi-file Juliet cases. Record "
                "every run's first-contact status; tuning against "
                "Juliet-B moves it to the Juliet ledger's disclosed "
                "tier."),
            "sink_anchoring": (
                "expected entries sit at the sink file (terminal "
                "badSink / bad()-holding file / _bad polarity file); "
                "forwarding files are unlabeled — neutral, not clean."),
            "refused": refused,
        },
    }

