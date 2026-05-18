"""Hand-labelled corpus seeds from Juice Shop + WebGoat.

OWASP Benchmark gives us volume for ``missing_sanitizer_model``; this
script gives the corpus diversity in :data:`fp_category` (framework
mitigations, dead code, type-system guards) — categories the OWASP
benchmark by design doesn't exercise. Each entry was inspected by
hand against the upstream source pinned in
``core/dataflow/corpus/SOURCES.md``.

The "manifest" below is the source of truth: ``(fixture_path,
source_line, sink_line, intermediate_lines, rule_id, message,
verdict, fp_category, rationale)``. The script reads the actual
source line at each coordinate to backfill snippets, builds
:class:`Finding` + :class:`GroundTruth` pairs, and writes paired
JSONs into the corpus directory.

Re-running with the same manifest reproduces the same corpus
entries. Adding entries means appending tuples to :data:`MANIFEST`;
re-running picks them up without affecting unchanged ones (finding
ids are deterministic).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from core.dataflow.adapters.codeql import make_finding_id
from core.dataflow.finding import Finding, Step
from core.dataflow.label import (
    FP_DEAD_CODE,
    FP_FRAMEWORK_MITIGATION,
    FP_TYPE_CONSTRAINT,
    GroundTruth,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)


@dataclass(frozen=True)
class SeedEntry:
    fixture_path: str
    source_line: int
    sink_line: int
    intermediate_lines: Tuple[int, ...]
    producer: str
    rule_id: str
    message: str
    verdict: str
    fp_category: Optional[str]
    rationale: str


_LABELER = "handlabel-juice-shop-webgoat"
_LABELED_AT = "2026-05-10"


# ---------------------------------------------------------------------
# Juice Shop (Node/Express + Sequelize ORM)
# ---------------------------------------------------------------------

_JS = "out/dataflow-corpus-fixtures/juice-shop/data/static/codefixes"

JUICE_SHOP: Tuple[SeedEntry, ...] = (
    # SQL injection: string concatenation into raw query.
    SeedEntry(
        fixture_path=f"{_JS}/dbSchemaChallenge_1.ts",
        source_line=3,
        sink_line=5,
        intermediate_lines=(4,),
        producer="semgrep",
        rule_id="javascript.express.security.audit.express-template-string-sqli",
        message="user input concatenated into Sequelize raw query",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="req.query.q (line 3) flows through length-trim (line 4) to a SQL string built with + concatenation (line 5). Classic CWE-89; Sequelize's raw .query() with concatenated criteria is the textbook SQLi sink.",
    ),
    # Same shape, but parameterised via Sequelize replacements — framework mitigation.
    SeedEntry(
        fixture_path=f"{_JS}/dbSchemaChallenge_2_correct.ts",
        source_line=3,
        sink_line=5,
        intermediate_lines=(4, 6, 7),
        producer="semgrep",
        rule_id="javascript.express.security.audit.express-template-string-sqli",
        message="user input passed to Sequelize raw query",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_FRAMEWORK_MITIGATION,
        rationale="req.query.q is bound via Sequelize's replacements parameter (line 7). Sequelize parameterises the value before substitution — same protection as a prepared statement. Pattern-only producers don't model Sequelize's replacement mechanism.",
    ),
    # SQL injection with a hand-rolled blocklist that's bypassable.
    SeedEntry(
        fixture_path=f"{_JS}/loginAdminChallenge_1.ts",
        source_line=15,
        sink_line=18,
        intermediate_lines=(15, 16),
        producer="semgrep",
        rule_id="javascript.lang.security.audit.sqli.express-sequelize-injection",
        message="email/password concatenated into Sequelize template-string query",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="req.body.email and req.body.password flow into a template-literal SQL on line 18. The regex blocklist on line 15 attempts to filter SQLi metachars but is documented in dbSchemaChallenge.info.yml as bypassable — 'custom-built blocklist mechanism is doomed to fail.' Real CWE-89.",
    ),
    # Same shape, parameterised via Sequelize bind — framework mitigation.
    SeedEntry(
        fixture_path=f"{_JS}/loginAdminChallenge_4_correct.ts",
        source_line=15,
        sink_line=15,
        intermediate_lines=(16,),
        producer="semgrep",
        rule_id="javascript.lang.security.audit.sqli.express-sequelize-injection",
        message="email/password passed to Sequelize bind parameters",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_FRAMEWORK_MITIGATION,
        rationale="req.body.email and req.body.password flow into Sequelize bind: [...] (line 16) — parameterised query. Sequelize binds values before substitution. Pattern matchers see the template-literal SQL and miss that the values come from bind, not interpolation.",
    ),
    # XSS via Angular's bypassSecurityTrustResourceUrl on a string used only as a filter, not innerHTML.
    SeedEntry(
        fixture_path=f"{_JS}/localXssChallenge_1.ts",
        source_line=2,
        sink_line=6,
        intermediate_lines=(4, 5),
        producer="semgrep",
        rule_id="javascript.angular.security.audit.angular-bypass-sanitizer",
        message="user input passed to bypassSecurityTrustResourceUrl",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_TYPE_CONSTRAINT,
        rationale="queryParam (from this.route.snapshot.queryParams.q) is passed to bypassSecurityTrustResourceUrl on line 6. The result is assigned to searchValue but used only as a Material table filter string (this.dataSource.filter is a plain string predicate), never as href/src. Without an HTML render context the bypass is harmless. Pattern matchers fire on bypassSecurityTrust* regardless of usage type.",
    ),
    # XSS where the bypassed value IS rendered via innerHTML — real.
    SeedEntry(
        fixture_path=f"{_JS}/localXssChallenge_3.ts",
        source_line=2,
        sink_line=5,
        intermediate_lines=(3, 4),
        producer="semgrep",
        rule_id="javascript.angular.security.audit.angular-bypass-sanitizer",
        message="user input bypasses sanitizer and reaches DOM",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="queryParam reaches bypassSecurityTrustHtml on line 5 and is used as innerHtml binding in template — XSS. Path documented in juice-shop SOLUTIONS.md as the local XSS challenge solution.",
    ),
    # Forged review: changing author email — IDOR-shaped, but the "fix" actually validates ownership.
    SeedEntry(
        fixture_path=f"{_JS}/forgedReviewChallenge_2_correct.ts",
        source_line=2,
        sink_line=4,
        intermediate_lines=(3,),
        producer="semgrep",
        rule_id="javascript.express.security.express-mass-assignment",
        message="user-controlled review id used in update",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_FRAMEWORK_MITIGATION,
        rationale="req.body.id and review id are used to update a review, but the _correct variant filters by author === user.email so a user can only edit their own reviews. Pattern matcher sees the update with user-controlled id and flags it; the ownership predicate is the framework-side mitigation.",
    ),
    # NoSQL injection: $where clause from user input.
    SeedEntry(
        fixture_path=f"{_JS}/noSqlReviewsChallenge_2.ts",
        source_line=3,
        sink_line=4,
        intermediate_lines=(),
        producer="semgrep",
        rule_id="javascript.lang.security.audit.nosql-injection",
        message="user input passed to MongoDB $where operator",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="req.params.id flows into a Mongo $where query — server-side JS evaluation of attacker-controlled string. CWE-943 (NoSQL injection).",
    ),
    # Direct admin section access without auth check — TP, missing_sanitizer_model (no auth model).
    SeedEntry(
        fixture_path=f"{_JS}/adminSectionChallenge_2.ts",
        source_line=2,
        sink_line=2,
        intermediate_lines=(),
        producer="semgrep",
        rule_id="javascript.express.security.audit.missing-auth",
        message="admin route registered without authentication middleware",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="Admin route declared without auth middleware in the chain — anyone can hit /administration. CWE-862 missing authorization.",
    ),
    # Admin section with the role-check middleware applied — framework mitigation.
    SeedEntry(
        fixture_path=f"{_JS}/adminSectionChallenge_1_correct.ts",
        source_line=2,
        sink_line=2,
        intermediate_lines=(),
        producer="semgrep",
        rule_id="javascript.express.security.audit.missing-auth",
        message="admin route registered",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_FRAMEWORK_MITIGATION,
        rationale="Same admin route, but wrapped with security.isAuthorized() middleware checking admin role. Pattern matchers that only see the route declaration miss the middleware chain.",
    ),
)


# ---------------------------------------------------------------------
# WebGoat (Java/Spring + JDBC)
# ---------------------------------------------------------------------

_WG = "out/dataflow-corpus-fixtures/webgoat/src/main/java/org/owasp/webgoat/lessons"

WEBGOAT: Tuple[SeedEntry, ...] = (
    # SqlInjectionLesson2: classic executeQuery on tainted string.
    SeedEntry(
        fixture_path=f"{_WG}/sqlinjection/introduction/SqlInjectionLesson2.java",
        source_line=42,
        sink_line=49,
        intermediate_lines=(48,),
        producer="codeql",
        rule_id="java/sql-injection",
        message="user-controlled query passed to Statement.executeQuery",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="@RequestParam String query (line 42) is passed through createStatement and into executeQuery (line 49) without sanitisation. WebGoat's introductory SQLi lesson — textbook CWE-89.",
    ),
    # SqlInjectionLesson10a: looks like SQLi-shaped but is pure keyword matching.
    SeedEntry(
        fixture_path=f"{_WG}/sqlinjection/mitigation/SqlInjectionLesson10a.java",
        source_line=32,
        sink_line=43,
        intermediate_lines=(39, 42),
        producer="codeql",
        rule_id="java/sql-injection",
        message="@RequestParam values reach String.contains check",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_DEAD_CODE,
        rationale="The @RequestParam strings are never used as SQL — line 43 is a String.contains() check against a hardcoded keyword list ('getConnection', 'PreparedStatement', etc.), part of a teaching exercise verifying the user typed the right Java keywords. No database query, no taint sink. From a CWE-89 perspective the entire 'sink' is dead.",
    ),
    # SqlInjectionLesson13: PreparedStatement with parameter binding — framework mitigation.
    SeedEntry(
        fixture_path=f"{_WG}/sqlinjection/mitigation/SqlInjectionLesson13.java",
        source_line=43,
        sink_line=49,
        intermediate_lines=(46, 47, 48),
        producer="codeql",
        rule_id="java/sql-injection",
        message="user input bound to PreparedStatement parameter",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_FRAMEWORK_MITIGATION,
        rationale="@RequestParam ip (line 43) is bound via PreparedStatement.setString (line 47), then executeQuery is called on the prepared statement (line 49). PreparedStatement parameterisation is the canonical mitigation pattern matchers don't model — they see the @RequestParam-to-execute path and flag regardless of binding.",
    ),
    # SqlOnlyInputValidation: incomplete validation (only blocks spaces).
    SeedEntry(
        fixture_path=f"{_WG}/sqlinjection/mitigation/SqlOnlyInputValidation.java",
        source_line=31,
        sink_line=35,
        intermediate_lines=(32,),
        producer="codeql",
        rule_id="java/sql-injection",
        message="user input passes minimal validation, reaches injectable query",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="@RequestParam userId (line 31) is checked only for whitespace (line 32 — `userId.contains(\" \")`) and then handed to lesson6a.injectableQuery (line 35), a known-vulnerable executeQuery sink. The lesson is explicitly designed to show that input validation alone is insufficient — bypasses don't need spaces.",
    ),
    # ProfileUploadRemoveUserInput: NOT actually a fix; file.getOriginalFilename() is still attacker-controlled.
    SeedEntry(
        fixture_path=f"{_WG}/pathtraversal/ProfileUploadRemoveUserInput.java",
        source_line=39,
        sink_line=41,
        intermediate_lines=(),
        producer="codeql",
        rule_id="java/path-injection",
        message="MultipartFile filename used as profile filename",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="Despite the file name, this handler still uses attacker-controlled input: `file.getOriginalFilename()` (line 41) returns the original client-supplied name, which can contain path traversal sequences. The 'fix' merely removes the explicit fullName parameter; the implicit filename source is unchanged. CWE-22.",
    ),
    # ProfileUploadFix: attempts replace("../", "") sanitisation on fullName.
    SeedEntry(
        fixture_path=f"{_WG}/pathtraversal/ProfileUploadFix.java",
        source_line=41,
        sink_line=43,
        intermediate_lines=(),
        producer="codeql",
        rule_id="java/path-injection",
        message="user-supplied fullName used in upload path with replace()",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_FRAMEWORK_MITIGATION,
        rationale="@RequestParam fullName (line 41) is filtered via replace(\"../\", \"\") before being passed downstream (line 43). Pattern matchers without path-sanitisation models flag any user-input-to-File-path. The replace() is the project-specific mitigation; whether it's complete (it isn't — `....//` bypasses) is a separate semantic question.",
    ),
    # IDORViewOtherProfile: inverted authorization check — proceeds only when userId differs.
    SeedEntry(
        fixture_path=f"{_WG}/idor/IDORViewOtherProfile.java",
        source_line=43,
        sink_line=51,
        intermediate_lines=(49,),
        producer="codeql",
        rule_id="java/missing-authorization",
        message="userId path variable used to view profile",
        verdict=VERDICT_TRUE_POSITIVE,
        fp_category=None,
        rationale="@PathVariable userId (line 43) flows into UserProfile construction (line 51). The auth check on line 49 — `if (userId != null && !userId.equals(authUserId))` — is INVERTED: it proceeds only when the supplied userId is *different* from the authenticated user, so a user can view another user's profile. WebGoat's intentional IDOR (CWE-639) demo.",
    ),
    # SSRFTask1: regex-match endpoint — no actual URL fetch happens.
    SeedEntry(
        fixture_path=f"{_WG}/ssrf/SSRFTask1.java",
        source_line=24,
        sink_line=32,
        intermediate_lines=(25, 28),
        producer="codeql",
        rule_id="java/ssrf",
        message="@RequestParam url passed through stealTheCheese",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_DEAD_CODE,
        rationale="@RequestParam url is passed to stealTheCheese which does NOT fetch the URL — line 32 only does `url.matches(\"images/tom\\\\.png\")` regex matching against hardcoded strings, then returns hardcoded HTML. Producers seeing @RequestParam-named-url + 'stealTheCheese' might flag SSRF; the actual sink isn't a network call. No CWE-918 here.",
    ),
)


def _load_lines(repo_root: Path, fixture_path: str) -> List[str]:
    full = repo_root / fixture_path
    return full.read_text().splitlines() if full.exists() else []


def _step(
    fixture_path: str,
    line: int,
    role: str,
    repo_root: Path,
) -> Step:
    lines = _load_lines(repo_root, fixture_path)
    if not (1 <= line <= len(lines)):
        raise ValueError(
            f"line {line} out of range for {fixture_path} "
            f"(file has {len(lines)} lines)"
        )
    snippet = lines[line - 1].strip() or f"line {line}"
    return Step(
        file_path=fixture_path,
        line=line,
        column=0,
        snippet=snippet,
        label=role,
    )


def _entry_to_pair(
    entry: SeedEntry, source_label: str, repo_root: Path
) -> Tuple[Finding, GroundTruth]:
    src = _step(entry.fixture_path, entry.source_line, "source", repo_root)
    sink = _step(entry.fixture_path, entry.sink_line, "sink", repo_root)
    intermediate = tuple(
        _step(entry.fixture_path, ln, "step", repo_root)
        for ln in entry.intermediate_lines
        if ln != entry.source_line and ln != entry.sink_line
    )
    base_id = make_finding_id(entry.rule_id, src, sink, producer=entry.producer)
    finding_id = f"{source_label}_{base_id}"

    finding = Finding(
        finding_id=finding_id,
        producer=entry.producer,
        rule_id=entry.rule_id,
        message=entry.message,
        source=src,
        sink=sink,
        intermediate_steps=intermediate,
    )
    label = GroundTruth(
        finding_id=finding_id,
        verdict=entry.verdict,
        fp_category=entry.fp_category,
        rationale=entry.rationale,
        labeler=_LABELER,
        labeled_at=_LABELED_AT,
    )
    return finding, label


def write_seed(out_dir: Path, repo_root: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for source_label, entries in (
        ("juiceshop", JUICE_SHOP),
        ("webgoat", WEBGOAT),
    ):
        for entry in entries:
            finding, label = _entry_to_pair(entry, source_label, repo_root)
            (out_dir / f"{finding.finding_id}.json").write_text(
                finding.to_json(indent=2)
            )
            (out_dir / f"{finding.finding_id}.label.json").write_text(
                label.to_json(indent=2)
            )
            n += 1
    return n


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "corpus" / "findings",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args(argv)
    n = write_seed(args.out_dir, args.repo_root)
    print(f"Wrote {n} hand-labelled corpus entries to {args.out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
