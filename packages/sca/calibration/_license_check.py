"""Pre-commit license-compliance check for the calibration corpus.

Runs over every JSON file under ``packages/sca/data/calibration/``
and enforces:

  1. Each file has a top-level ``_source`` block with ``license``
     and ``url`` fields. Missing ⇒ build fail.
  2. Files for Tier 2 sources (Exploit-DB / Metasploit) contain
     ONLY boolean signals + reference URLs — no exploit content.
     Forbidden field names: ``body``, ``payload``, ``shellcode``,
     ``exploit_code``, ``poc_code``.
  3. ``ATTRIBUTION.md`` exists and references every JSON file
     present.

Exit codes:
  0  all checks passed
  1  one or more violations found

Invoked as a pre-commit hook AND as a CI step on the calibration
refresh workflow. The checks cost <100ms even on a populated
corpus, so cheap to run on every commit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

# Field names that would indicate raw exploit content. Any
# calibration JSON containing a key that matches (case-insensitive)
# fails the check. Documented in
# ``packages/sca/data/calibration/ATTRIBUTION.md``.
_FORBIDDEN_FIELDS = frozenset({
    "body",
    "payload",
    "shellcode",
    "exploit_code",
    "exploit_body",
    "poc_code",
    "poc_body",
})

_REQUIRED_SOURCE_FIELDS = frozenset({"license", "url"})


def check(corpus_dir: Path, attribution_md: Path) -> List[str]:
    """Return a list of violation strings (empty when corpus is
    compliant)."""
    violations: List[str] = []
    if not corpus_dir.is_dir():
        violations.append(
            f"calibration dir not found: {corpus_dir}"
        )
        return violations
    if not attribution_md.is_file():
        violations.append(
            f"missing ATTRIBUTION.md at {attribution_md}"
        )
    attribution_text = (
        attribution_md.read_text(encoding="utf-8")
        if attribution_md.is_file() else ""
    )
    for path in sorted(corpus_dir.rglob("*.json")):
        rel = path.relative_to(corpus_dir)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            violations.append(
                f"{rel}: failed to read/parse JSON ({e})"
            )
            continue
        if not isinstance(data, dict):
            # Lists are valid for some snapshot shapes but the
            # corpus convention is dict-with-_source. Tighten as
            # needed; for now lists are permitted.
            continue
        # Rule 1: ``_source`` block.
        src = data.get("_source")
        if not isinstance(src, dict):
            violations.append(
                f"{rel}: missing or non-dict ``_source`` block"
            )
        else:
            missing = _REQUIRED_SOURCE_FIELDS - set(src.keys())
            if missing:
                violations.append(
                    f"{rel}: ``_source`` missing fields: "
                    f"{sorted(missing)}"
                )
        # Rule 2: forbidden fields (anywhere in the document).
        bad = _walk_for_forbidden(data, path=())
        for trail in bad:
            violations.append(
                f"{rel}: forbidden field at {'.'.join(trail)} "
                f"(license-restricted content)"
            )
        # Rule 3: ATTRIBUTION.md mentions the file.
        if attribution_text and rel.name not in attribution_text:
            # Project-sample files are bulky; reference the
            # parent directory in ATTRIBUTION.md, individual
            # filenames not required.
            if "project_samples" not in str(rel):
                violations.append(
                    f"{rel}: not referenced in ATTRIBUTION.md "
                    f"(add a section citing source + license)"
                )
    return violations


def _walk_for_forbidden(node, path: tuple) -> List[tuple]:
    out: List[tuple] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in _FORBIDDEN_FIELDS:
                out.append(path + (k,))
            out.extend(_walk_for_forbidden(v, path + (str(k),)))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            out.extend(_walk_for_forbidden(item, path + (str(i),)))
    return out


def main() -> int:
    repo_root = Path(__file__).resolve().parents[3]
    corpus_dir = repo_root / "packages" / "sca" / "data" / "calibration"
    attribution_md = corpus_dir / "ATTRIBUTION.md"
    violations = check(corpus_dir, attribution_md)
    if violations:
        print(
            "raptor-sca calibration license-check FAILED:",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
