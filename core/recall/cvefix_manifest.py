"""Bridge a CVE fix commit into recall-manifest ground truth.

Sibling of :mod:`core.dataflow.cvefix_corpus_generator` (which labels
producer SARIF pairs); this module needs no producer run at all — the
fix commit's own diff is the label source:

  * pre-fix tree (``fix_commit^``)  → the RECALL manifest: every
    pre-image hunk span the fix touched is a candidate expected
    finding (the vulnerability the fix removed lived there);
  * post-fix tree (``fix_commit``)  → the FP-ONLY twin manifest: the
    post-image spans are labelled-clean regions (the fix is the
    sanitizer) — a finding still emitted there is the
    ``missing_sanitizer_model`` FP class.

CANDIDATE LABELS, NOT GROUND TRUTH (the cvefix generator's caveat,
inherited verbatim): a fix diff can touch refactor lines, and an
incomplete fix leaves the post-fix tree genuinely vulnerable. Every
expected entry therefore carries ``"review": "unreviewed-candidate"``
and the manifest notes demand hand-verification before this corpus
gates anything — treating raw output as an FN gate would corrupt the
very measurement it exists to protect.

Public provenance is a hard gate: entries carry ``kind: "cve"`` with
the CVE id and full fix-commit sha, which the manifest parser
validates. No CVE id or no public fix commit → no corpus entry.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from core.git import get_safe_git_env, safe_git_readonly_command
from core.recall.manifest import SCHEMA_VERSION

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

#: Diff spans approximate sink locations; a small drift window keeps
#: honest matches without letting unrelated findings claim credit.
_DEFAULT_DRIFT = 3

#: Test-tree fragments excluded from candidate labels by default: a
#: fix commit's test additions describe the vulnerability, they are
#: not where it lives (spec key ``include_tests`` opts back in).
_TEST_FRAGMENTS = ("/test/", "/tests/")

REVIEW_CANDIDATE = "unreviewed-candidate"


class CvefixManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class CvefixSpec:
    cve_id: str
    repo_url: str
    fix_commit: str
    local_clone: Path
    language: str
    cwe: str
    file_suffixes: tuple[str, ...] = (".java",)
    include_tests: bool = False

    @classmethod
    def from_dict(cls, raw: dict) -> CvefixSpec:
        errors = []
        cve = str(raw.get("cve_id", ""))
        if not _CVE_RE.match(cve):
            errors.append(f"cve_id {cve!r} is not a CVE id")
        sha = str(raw.get("fix_commit", "")).lower()
        if not _SHA_RE.match(sha):
            errors.append("fix_commit must be a full 40-hex sha "
                          "(public provenance is a hard gate)")
        errors.extend(f"spec needs {key}" for key in ("repo_url", "local_clone", "language", "cwe") if not raw.get(key))
        cwe = str(raw.get("cwe", ""))
        if cwe and not re.match(r"^CWE-\d+$", cwe):
            errors.append(f"cwe {cwe!r} must look like CWE-NNN")
        if errors:
            raise CvefixManifestError(
                "invalid cvefix spec:\n  " + "\n  ".join(errors))
        return cls(
            cve_id=cve, repo_url=str(raw["repo_url"]), fix_commit=sha,
            local_clone=Path(raw["local_clone"]),
            language=str(raw["language"]), cwe=cwe,
            file_suffixes=tuple(raw.get("file_suffixes") or (".java",)),
            include_tests=bool(raw.get("include_tests", False)),
        )


def _git(clone: Path, *args: str) -> str:
    # The clone is INTERNET-SOURCED (the operator ran `git clone
    # <repo_url>`), so its `.git/config` is untrusted: hostile
    # entries (core.fsmonitor, core.pager, diff.external, hooksPath)
    # execute attacker commands on ordinary git ops. Route through
    # the strict read-only argv (per-invocation `-c` neutralisers +
    # protocol.allow=never) with the sanitised git env. Every command
    # this module issues is local plumbing over committed trees —
    # no transport, no worktree re-hash.
    proc = subprocess.run(
        safe_git_readonly_command("-C", str(clone), *args),
        capture_output=True, text=True, timeout=120, check=False,
        env=get_safe_git_env())
    if proc.returncode != 0:
        msg = (
            f"git {' '.join(args[:2])} failed in {clone}: "
            f"{proc.stderr.strip()}"
        )
        raise CvefixManifestError(msg)
    return proc.stdout


def _resolve(clone: Path, rev: str) -> str:
    sha = _git(clone, "rev-parse", rev).strip().lower()
    if not _SHA_RE.match(sha):
        msg = f"cannot resolve {rev} in {clone}"
        raise CvefixManifestError(msg)
    return sha


@dataclass(frozen=True)
class HunkSpan:
    file: str
    pre: tuple[int, int] | None   # (start, end) in fix_commit^
    post: tuple[int, int] | None  # (start, end) in fix_commit


def parse_fix_hunks(diff_text: str,
                    suffixes: tuple[str, ...]) -> list[HunkSpan]:
    """Pre/post spans per hunk, filtered to the language's files.

    Pure-addition hunks (the added sanitizer) have no pre span; pure
    deletions have no post span. Both sides are kept where present —
    the recall manifest consumes pre spans, the fp-only twin consumes
    post spans.
    """
    spans: list[HunkSpan] = []
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            current = path if path.endswith(suffixes) else None
            continue
        if line.startswith("+++ /dev/null"):
            current = None  # deleted file: no post side to label
            continue
        m = _HUNK_RE.match(line)
        if m and current:
            old_start, old_n = int(m.group(1)), int(m.group(2) or "1")
            new_start, new_n = int(m.group(3)), int(m.group(4) or "1")
            pre = ((old_start, old_start + old_n - 1)
                   if old_n > 0 else None)
            post = ((new_start, new_start + new_n - 1)
                    if new_n > 0 else None)
            spans.append(HunkSpan(file=current, pre=pre, post=post))
    return spans


def _entry(spec: CvefixSpec, ident: str, file: str,
           span: tuple[int, int], *, review: str | None) -> dict:
    d = {
        "id": ident,
        "file": file,
        "line_start": span[0],
        "line_end": span[1],
        "cwe": spec.cwe,
        "provenance": {
            "kind": "cve",
            "cve_id": spec.cve_id,
            "fix_commit": spec.fix_commit,
        },
    }
    if review is not None:
        # Additive field: the parser ignores it; the review workflow
        # and the FN-corruption caveat live on it.
        d["review"] = review
    return d


def generate_manifests(spec: CvefixSpec) -> tuple[dict, dict]:
    """Return (recall_manifest, fp_only_twin) dicts for the spec."""
    clone = spec.local_clone
    if not (clone / ".git").exists():
        msg = (
            f"{clone} is not a git clone — acquire the repo first "
            f"(git clone {spec.repo_url})"
        )
        raise CvefixManifestError(msg)
    fix = _resolve(clone, spec.fix_commit)
    if fix != spec.fix_commit:
        msg = f"{spec.fix_commit} did not resolve to itself"
        raise CvefixManifestError(msg)
    prefix_sha = _resolve(clone, f"{fix}^")
    parents = _git(clone, "rev-list", "--parents", "-n", "1",
                   fix).split()
    if len(parents) != 2:
        msg = (
            f"{fix} is not a single-parent commit "
            f"({len(parents) - 1} parents) — merge fixes need manual "
            "hunk attribution; refuse rather than guess"
        )
        raise CvefixManifestError(msg)

    # --no-ext-diff is REQUIRED under the hardened argv: the
    # overrides pin diff.external to the empty string, which git
    # treats as a command and fails on — deliberate fail-closed
    # for diff call sites that forget to disable external drivers.
    diff = _git(clone, "diff", "--no-ext-diff", f"{fix}^", fix)
    spans = parse_fix_hunks(diff, spec.file_suffixes)
    if not spec.include_tests:
        spans = [h for h in spans
                 if not any(f in f"/{h.file}" for f in _TEST_FRAGMENTS)]
    if not spans:
        msg = (
            "the fix commit touches no files matching "
            f"{spec.file_suffixes} — nothing to label"
        )
        raise CvefixManifestError(msg)

    slug = spec.cve_id.lower().replace("-", "_")
    expected, clean = [], []
    for i, h in enumerate(spans):
        stem = f"{slug}__{Path(h.file).stem}__h{i:02d}"
        if h.pre:
            expected.append(_entry(spec, stem, h.file, h.pre,
                                   review=REVIEW_CANDIDATE))
        if h.post:
            clean.append(_entry(spec, f"{stem}__fixed", h.file, h.post,
                                review=None))
    if not expected:
        msg = (
            "the fix is pure addition — no pre-image span to label as "
            "an expected finding; label this CVE manually or skip it"
        )
        raise CvefixManifestError(msg)

    caveat = (
        "CANDIDATE labels from the fix diff: a fix can touch refactor "
        "lines, and an incomplete fix leaves real vulnerability "
        "behind. Hand-verify every 'review: unreviewed-candidate' "
        "entry before this corpus gates anything — raw labels would "
        "corrupt the FN gate (cvefix_corpus_generator caveat, "
        "inherited).")

    recall_manifest = {
        "schema_version": SCHEMA_VERSION,
        "name": f"cvefix-{spec.cve_id}",
        "target": {
            "repo_url": spec.repo_url,
            "pinned_sha": prefix_sha,
            "local_path": str(clone),
        },
        "language": spec.language,
        "profile": "scan-codeql",
        "tolerance": {"line_drift": _DEFAULT_DRIFT,
                      "cwe_family_match": True},
        "expected": expected,
        "clean_regions": [],
        "notes": {"label_caveat": caveat,
                  "checkout": f"git checkout {prefix_sha} (pre-fix)"},
    }
    fp_twin = {
        "schema_version": SCHEMA_VERSION,
        "name": f"cvefix-{spec.cve_id}-postfix",
        "corpus_kind": "fp-only",
        "target": {
            "repo_url": spec.repo_url,
            "pinned_sha": fix,
            "local_path": str(clone),
        },
        "language": spec.language,
        "profile": "scan-codeql",
        "tolerance": {"line_drift": _DEFAULT_DRIFT,
                      "cwe_family_match": True},
        "expected": [],
        "clean_regions": clean,
        "notes": {
            "label_caveat": caveat,
            "fp_class": (
                "a finding on these regions post-fix is the "
                "missing_sanitizer_model FP class"),
            "checkout": f"git checkout {fix} (post-fix)",
        },
    }
    return recall_manifest, fp_twin


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-recall-measure cvefix-manifest",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--spec", type=Path, required=True,
                   help="cvefix spec JSON (cve_id, repo_url, "
                        "fix_commit, local_clone, language, cwe)")
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args(argv)

    try:
        from core.json import load_json
        spec_doc = load_json(
            args.spec, strict=True, max_bytes=8 * 1024 * 1024)
        if spec_doc is None:
            # strict load_json still returns None for a missing file.
            msg = f"cannot read spec {args.spec}: file not found"
            raise CvefixManifestError(msg)
        spec = CvefixSpec.from_dict(spec_doc)
        recall_m, twin = generate_manifests(spec)
    except (OSError, ValueError, CvefixManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    slug = spec.cve_id.lower()
    pre = args.out_dir / f"{slug}-prefix.json"
    post = args.out_dir / f"{slug}-postfix.json"
    pre.write_text(json.dumps(recall_m, indent=2) + "\n",
                   encoding="utf-8")
    post.write_text(json.dumps(twin, indent=2) + "\n", encoding="utf-8")
    print(f"recall manifest: {pre} ({len(recall_m['expected'])} "
          f"candidate expected — hand-verify before gating)")
    print(f"fp-only twin:    {post} ({len(twin['clean_regions'])} "
          f"clean regions)")
    return 0
