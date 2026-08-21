"""Recall-corpus manifest: ground-truth targets for FN measurement.

A manifest names one target (pinned to an exact sha), the detection
profile to run against it, and the findings a perfect detector would
produce. Labels require PUBLIC provenance — a benchmark-suite id or a
CVE id plus fix commit — per repo doctrine: no undisclosed
vulnerabilities may be committed as corpus labels.

Shape (``schema_version: 1``)::

    {
      "schema_version": 1,
      "name": "owasp-benchmark-java",
      "target": {
        "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkJava",
        "pinned_sha": "b06d6efa...",
        "local_path": "out/dataflow-corpus-fixtures/owasp-benchmark-java"
      },
      "language": "java",
      "build_command": "mvn -B -DskipTests clean package",
      "profile": "scan-codeql",
      "tolerance": {"line_drift": 5, "cwe_family_match": true},
      "expected": [
        {
          "id": "BenchmarkTest00001",
          "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java",
          "line_start": null,
          "line_end": null,
          "cwe": "CWE-78",
          "provenance": {"kind": "benchmark",
                          "suite": "owasp-benchmark-java",
                          "case": "BenchmarkTest00001"}
        }
      ],
      "clean_regions": [
        {"id": "BenchmarkTest00002",
         "file": "src/main/java/.../BenchmarkTest00002.java",
         "cwe": "CWE-78",
         "provenance": {"kind": "benchmark", "suite": "...",
                         "case": "BenchmarkTest00002"}}
      ]
    }

``line_start: null`` means file-level ground truth (benchmark suites
label whole test files); a finding anywhere in the file with a
matching CWE counts. ``clean_regions`` are labelled-clean locations
(benchmark FP cases): findings there feed the secondary FP counter,
never recall.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

#: Detection profiles the runner knows how to execute. Values document
#: LLM usage so cost is visible before a run starts.
PROFILES: dict[str, dict[str, Any]] = {
    "scan": {"uses_llm": False,
             "description": "semgrep + local rules via raptor.py scan"},
    "scan-codeql": {"uses_llm": False,
                    "description": "scan plus CodeQL suites (scan-only)"},
    "agentic": {"uses_llm": True,
                "description": ("full scan -> dedup -> LLM analysis "
                                 "pipeline — every finding costs LLM "
                                 "tokens")},
}

_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")

DEFAULT_LINE_DRIFT = 5


class ManifestError(ValueError):
    """A manifest failed validation; message lists every reason."""


@dataclass(frozen=True)
class Provenance:
    kind: str  # "benchmark" | "cve"
    suite: str | None = None
    case: str | None = None
    cve_id: str | None = None
    fix_commit: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind}
        for k in ("suite", "case", "cve_id", "fix_commit"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


@dataclass(frozen=True)
class ExpectedFinding:
    id: str
    file: str
    cwe: str
    provenance: Provenance
    line_start: int | None = None
    line_end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file": self.file,
            "cwe": self.cwe,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "provenance": self.provenance.to_dict(),
        }


@dataclass(frozen=True)
class Tolerance:
    line_drift: int = DEFAULT_LINE_DRIFT
    cwe_family_match: bool = True


@dataclass
class RecallManifest:
    name: str
    repo_url: str
    pinned_sha: str
    local_path: str
    language: str
    profile: str
    expected: list[ExpectedFinding]
    clean_regions: list[ExpectedFinding] = field(default_factory=list)
    #: "recall" (default) or "fp-only" — an fp-only manifest labels a
    #: known-clean tree (e.g. the post-CVE-fix twin): expected may be
    #: empty and the report's recall reads None; clean-region FPs are
    #: the measurement.
    corpus_kind: str = "recall"
    build_command: str | None = None
    tolerance: Tolerance = field(default_factory=Tolerance)


def _parse_provenance(raw: Any, where: str, errors: list[str]) -> Provenance:
    if not isinstance(raw, dict):
        errors.append(f"{where}: provenance missing or not an object")
        return Provenance(kind="missing")
    kind = raw.get("kind")
    if kind == "benchmark":
        if not raw.get("suite") or not raw.get("case"):
            errors.append(
                f"{where}: benchmark provenance needs suite and case")
        return Provenance(kind="benchmark", suite=raw.get("suite"),
                          case=raw.get("case"))
    if kind == "cve":
        cve = raw.get("cve_id") or ""
        fix = raw.get("fix_commit") or ""
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            errors.append(f"{where}: cve provenance needs a CVE id")
        if not _SHA_RE.match(fix):
            errors.append(f"{where}: cve provenance needs a fix commit sha")
        return Provenance(kind="cve", cve_id=cve or None,
                          fix_commit=fix or None)
    errors.append(
        f"{where}: provenance.kind must be 'benchmark' or 'cve' — "
        "recall labels require public provenance (no undisclosed "
        "vulnerabilities in corpora)")
    return Provenance(kind=str(kind))


def _parse_expected(raw: Any, where: str,
                    errors: list[str]) -> ExpectedFinding:
    if not isinstance(raw, dict):
        errors.append(f"{where}: not an object")
        return ExpectedFinding(id="", file="", cwe="",
                               provenance=Provenance(kind="missing"))
    eid = raw.get("id") or ""
    file = raw.get("file") or ""
    cwe = raw.get("cwe") or ""
    if not eid:
        errors.append(f"{where}: missing id")
    if not file or Path(file).is_absolute() or ".." in Path(file).parts:
        errors.append(f"{where}: file must be a relative in-repo path")
    if not _CWE_RE.match(cwe):
        errors.append(f"{where}: cwe must look like CWE-NNN (got {cwe!r})")
    line_start = raw.get("line_start")
    line_end = raw.get("line_end")
    for label, v in (("line_start", line_start), ("line_end", line_end)):
        if v is not None and (not isinstance(v, int) or v < 1):
            errors.append(f"{where}: {label} must be a positive int or null")
    if line_start is None and line_end is not None:
        errors.append(f"{where}: line_end without line_start")
    prov = _parse_provenance(raw.get("provenance"), where, errors)
    return ExpectedFinding(id=eid, file=file, cwe=cwe, provenance=prov,
                           line_start=line_start, line_end=line_end)


def parse_manifest(data: Any) -> RecallManifest:
    """Validate a parsed JSON object into a :class:`RecallManifest`.

    Raises :class:`ManifestError` listing every problem found —
    hand-authored manifests should get all their mistakes in one pass.
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be an object")
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION} "
            f"(got {data.get('schema_version')!r})")
    name = data.get("name") or ""
    if not name:
        errors.append("missing name")

    target = data.get("target")
    repo_url = pinned_sha = local_path = ""
    if not isinstance(target, dict):
        errors.append("missing target object")
    else:
        repo_url = target.get("repo_url") or ""
        pinned_sha = (target.get("pinned_sha") or "").lower()
        local_path = target.get("local_path") or ""
        if not repo_url:
            errors.append("target.repo_url required (public provenance)")
        if not _SHA_RE.match(pinned_sha):
            errors.append("target.pinned_sha must be a git sha")
        if not local_path:
            errors.append("target.local_path required")

    language = data.get("language") or ""
    if not language:
        errors.append("missing language")

    profile = data.get("profile") or ""
    if profile not in PROFILES:
        errors.append(
            f"profile must be one of {sorted(PROFILES)} (got {profile!r})")

    tol_raw = data.get("tolerance") or {}
    drift = tol_raw.get("line_drift", DEFAULT_LINE_DRIFT)
    fam = tol_raw.get("cwe_family_match", True)
    if not isinstance(drift, int) or drift < 0:
        errors.append("tolerance.line_drift must be a non-negative int")
        drift = DEFAULT_LINE_DRIFT
    tolerance = Tolerance(line_drift=drift, cwe_family_match=bool(fam))

    corpus_kind = data.get("corpus_kind", "recall")
    if corpus_kind not in ("recall", "fp-only"):
        errors.append("corpus_kind must be 'recall' or 'fp-only'")

    raw_expected = data.get("expected")
    expected: list[ExpectedFinding] = []
    if not isinstance(raw_expected, list) or (
            not raw_expected and corpus_kind != "fp-only"):
        errors.append("expected must be a non-empty list "
                      "(unless corpus_kind is 'fp-only')")
    elif raw_expected:
        expected = [
            _parse_expected(e, f"expected[{i}]", errors)
            for i, e in enumerate(raw_expected)
        ]
        ids = [e.id for e in expected if e.id]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            errors.append(f"duplicate expected ids: {sorted(dupes)}")

    clean: list[ExpectedFinding] = [
        _parse_expected(e, f"clean_regions[{i}]", errors)
        for i, e in enumerate(data.get("clean_regions") or [])
    ]
    if corpus_kind == "fp-only" and not clean:
        errors.append("an fp-only manifest needs clean_regions")

    if errors:
        raise ManifestError(
            "invalid recall manifest:\n  " + "\n  ".join(errors))

    return RecallManifest(
        name=name, repo_url=repo_url, pinned_sha=pinned_sha,
        local_path=local_path, language=language, profile=profile,
        expected=expected, clean_regions=clean,
        build_command=data.get("build_command"), tolerance=tolerance,
        corpus_kind=corpus_kind,
    )


def load_manifest(path: Path) -> RecallManifest:
    """Load and validate a manifest file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    return parse_manifest(data)
