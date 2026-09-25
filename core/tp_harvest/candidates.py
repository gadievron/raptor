"""Semgrep rule CANDIDATES generalised from confirmed findings.

Each harvest record seeds one candidate rule: the concrete seed line
is generalised by metavariable-izing its identifiers while keeping the
structural skeleton (call anchors stay concrete). This is the same
generalisation doctrine the hunt machinery and checker synthesis use
("capture the structural shape, not the exact text" —
``packages/checker_synthesis/prompts.py``; the in-prompt metavariable
grammar lives in ``packages/checker_synthesis/grammars.py``), but
implemented mechanically so the harvest needs no LLM: deterministic,
reviewable, cheap.

Candidates are DRAFTS for a maintainer, never live rules:

* They land in a run-local ``candidates/`` directory, never in-tree.
  Emission into the in-tree rules surface (``engine/``) is refused
  outright — a generated rule that auto-enabled would be a precision
  regression waiting to happen, and its pattern text can leak an
  undisclosed vulnerability.
* Promotion is hand-work: review, corpus + negative-control testing
  (the ``engine/semgrep/tests`` fixture-pair discipline), then an
  ordinary reviewed commit. The runbook README written next to the
  candidates spells this out.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.atomic_fs import write_text_atomically
from core.security.log_sanitisation import escape_nonprintable
from core.source.contained import read_contained
from core.source.lines import split_lines
from core.tp_harvest.records import HarvestRecord

# Skip reasons (manifest vocabulary).
SKIP_LANGUAGE_UNKNOWN = "candidate_language_unknown"
SKIP_SEED_UNREADABLE = "candidate_seed_unreadable"
SKIP_PATTERN_UNDERIVABLE = "candidate_pattern_underivable"
SKIP_SEED_OVERSIZED = "candidate_seed_oversized"

RUNBOOK_FILENAME = "README.md"

# Semgrep language tags by source extension. Deliberately small: a
# candidate for an unmapped language is skipped by name, not guessed.
_LANG_BY_EXT = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
}

# Keywords that must stay concrete (never metavariable-ized, never an
# anchor). Union across the supported languages — over-inclusion only
# keeps a token concrete, which biases candidates tighter, never
# looser.
_KEYWORDS = frozenset({
    "if", "else", "elif", "for", "while", "do", "switch", "case",
    "return", "break", "continue", "goto", "sizeof", "new", "delete",
    "static", "const", "unsigned", "signed", "struct", "union", "enum",
    "void", "char", "short", "int", "long", "float", "double", "bool",
    "true", "false", "None", "True", "False", "def", "lambda", "pass",
    "raise", "try", "except", "finally", "with", "assert", "yield",
    "not", "and", "or", "in", "is", "import", "from", "as", "print",
    "func", "var", "let", "fn", "match", "then", "fi", "public",
    "private", "protected", "final", "throw", "throws", "catch",
    "this", "self", "super", "nil", "null", "nullptr", "NULL",
})

# String-literal collapser. The repeat is BOUNDED ({0,200}) — the
# unbounded form is a scan-restart quadratic: on an unterminated
# string (a planted `"` + `\"`*n line) every start position re-scans
# to end-of-line, and one 64 KB planted line cost ~12 s. The bound
# caps each restart at 200 chars, so matching stays linear in the
# line. Both directions: raising the bound re-opens the quadratic
# (the position-density oracle's pump generator does NOT synthesize
# the unterminated-string shape — do not trust a green census run
# alone); lowering it makes long-but-legitimate string literals fall
# out of the collapse and their contents survive concretely in the
# draft pattern. 200 comfortably covers real literals on a seed line
# already capped at _MAX_SEED_LINE_CHARS.
_STRING_RE = re.compile(
    r"\"(?:\\.|[^\"\\]){0,200}\"|'(?:\\.|[^'\\]){0,200}'")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

# Hard bound on the seed line BEFORE any regex touches it. A line
# longer than this is not a usable rule seed (semgrep patterns are
# reviewed by humans) and is exactly the shape a hostile target
# plants to burn harvest time — the read cap alone admits multi-MB
# single lines. Both directions: raising it buys nothing but attack
# surface; lowering it starts skipping legitimate dense one-liners.
_MAX_SEED_LINE_CHARS = 1024


def language_for(file_path: str) -> str | None:
    """Semgrep language tag for *file_path*, or None when unmapped."""
    return _LANG_BY_EXT.get(Path(file_path).suffix.lower())


def _read_seed_line(target_path: str, file_path: str, line: int) -> str | None:
    """The seed source line from the target tree, or None.

    CONTAINED + guarded read (``core.source.read_contained``): the
    file path is finding-derived and the target tree untrusted — a
    traversal/absolute/symlink path escaping the target refuses (an
    unconfined read would exfiltrate host file content into the
    candidate pattern, whose call anchors stay concrete), a planted
    FIFO must not block the harvest, and a planted huge file must not
    be buffered whole. ``read_contained`` drops the trailing partial
    line of an over-cap read, so any line it CAN index is complete.
    """
    if not target_path or line <= 0:
        return None
    text = read_contained(target_path, file_path)
    if text is None:
        return None
    # \n-only line model: finding line numbers come from external
    # tools that count \n as the sole terminator.
    lines = split_lines(text)
    if line > len(lines):
        return None
    return lines[line - 1]


def generalise_line(line: str) -> str | None:
    """Metavariable-ize *line* into a semgrep pattern skeleton.

    Structural-variant doctrine: call anchors (identifiers applied to
    an argument list) stay concrete — they carry the mechanism; every
    other identifier becomes a metavariable so the pattern matches
    the SHAPE, not the exact text. String literals collapse to
    ``"..."``. Returns None when no anchored, generalisable skeleton
    can be derived (no call anchor, or nothing got generalised — a
    fully-concrete pattern is just the seed line and a fully-abstract
    one matches everything; neither is a useful candidate).
    """
    text = line.strip().rstrip(";").strip()
    if not text or text.startswith(("//", "#", "/*", "*")):
        return None
    text = _STRING_RE.sub('"..."', text)

    mapping: dict[str, str] = {}
    anchors: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(0)
        if name in _KEYWORDS:
            return name
        # An identifier immediately applied to an argument list is a
        # call anchor: keep it concrete.
        rest = text[match.end():]
        if rest.lstrip().startswith("("):
            anchors.append(name)
            return name
        if name not in mapping:
            mapping[name] = f"${chr(ord('A') + (len(mapping) % 26))}" + (
                str(len(mapping) // 26) if len(mapping) >= 26 else "")
        return mapping[name]

    pattern = _IDENT_RE.sub(replace, text)
    if not anchors or not mapping:
        return None
    return pattern


class CandidateEmissionError(RuntimeError):
    """Raised when candidate emission would violate the local-only rule."""


_REPO_ROOT = Path(__file__).resolve().parents[2]
_IN_TREE_RULES_SURFACE = _REPO_ROOT / "engine"


def _refuse_in_tree_rules_surface(candidates_dir: Path) -> None:
    """Refuse emission into the in-tree rules surface.

    Candidates are unreviewed generalisations of (possibly
    undisclosed) confirmed vulnerabilities: a write under ``engine/``
    would put them where the rule loaders and the promotion target
    live. This is the mechanical backstop for the NEVER-auto-enable
    doctrine — promotion is a reviewed commit, not a file copy the
    harvester can perform.
    """
    resolved = candidates_dir.resolve()
    if resolved == _IN_TREE_RULES_SURFACE or (
            _IN_TREE_RULES_SURFACE in resolved.parents):
        raise CandidateEmissionError(
            f"refusing to emit rule candidates under the in-tree rules "
            f"surface {_IN_TREE_RULES_SURFACE} — candidates are "
            f"maintainer-review drafts; promote by hand per the runbook"
        )


def _slug(record: HarvestRecord) -> str:
    base = record.cwe.lower() if record.cwe else (
        re.sub(r"[^a-z0-9_-]+", "-", record.vuln_type.lower()) or "uncat")
    return re.sub(r"[^a-z0-9_-]+", "-", base).strip("-") or "uncat"


def render_candidate_yaml(
    record: HarvestRecord, pattern: str, language: str,
) -> str:
    """Render one candidate rule as YAML text.

    Strings are JSON-encoded (a JSON string is a valid YAML
    double-quoted scalar), so target-derived text cannot inject YAML
    structure; it is additionally escaped via the log-sanitisation
    contract before encoding.
    """
    def scalar(value: str) -> str:
        return json.dumps(escape_nonprintable(value, preserve_newlines=False))

    rule_id = f"candidate.{_slug(record)}.{record.harvest_id[:12]}"
    message = (
        f"CANDIDATE (not enabled): generalised from confirmed finding "
        f"{record.finding_id or record.harvest_id}"
        + (f" ({record.vuln_type})" if record.vuln_type else "")
        + " — review, test against corpus + negative controls, then "
          "hand-promote per README.md"
    )
    lines = [
        "# CANDIDATE rule — NOT enabled anywhere. Generated mechanically by",
        "# raptor-tp-harvest from a confirmed finding. A bad generalisation",
        "# is a precision regression and the pattern may describe an",
        "# undisclosed vulnerability: review + corpus/negative-control test",
        "# + hand-promote per README.md in this directory.",
        "rules:",
        f"  - id: {scalar(rule_id)}",
        f"    message: {scalar(message)}",
        f"    languages: [{scalar(language)}]",
        "    severity: WARNING",
        f"    pattern: {scalar(pattern)}",
        "    metadata:",
    ]
    if record.cwe:
        lines.append(f"      cwe: [{scalar(record.cwe)}]")
    lines += [
        "      raptor_candidate: true",
        '      generated_by: "raptor-tp-harvest"',
        f"      seed_finding_id: {scalar(record.finding_id)}",
        f"      seed_rule_id: {scalar(record.rule_id)}",
        f"      seed_span_sha: {scalar(record.span_sha)}",
        f"      seed_file: {scalar(record.file)}",
        f"      seed_line: {record.line}",
        "",
    ]
    return "\n".join(lines)


def emit_candidate(
    record: HarvestRecord,
    candidates_dir: Path,
) -> tuple[Path | None, str]:
    """Emit one candidate rule file for *record*.

    Returns ``(path, "")`` on success or ``(None, skip_reason)`` with
    an enumerated reason. Raises :class:`CandidateEmissionError` when
    *candidates_dir* sits on the in-tree rules surface.
    """
    _refuse_in_tree_rules_surface(candidates_dir)
    language = language_for(record.file)
    if language is None:
        return None, SKIP_LANGUAGE_UNKNOWN
    seed = _read_seed_line(record.target_path, record.file, record.line)
    if seed is None:
        return None, SKIP_SEED_UNREADABLE
    if len(seed) > _MAX_SEED_LINE_CHARS:
        # Hard input bound BEFORE the regexes: a planted multi-KB
        # single line is a time sink, not a seed.
        return None, SKIP_SEED_OVERSIZED
    pattern = generalise_line(seed)
    if pattern is None:
        return None, SKIP_PATTERN_UNDERIVABLE
    candidates_dir.mkdir(parents=True, exist_ok=True)
    ensure_runbook(candidates_dir)
    path = candidates_dir / f"{record.harvest_id}.candidate.yaml"
    # Atomic tempfile+rename (same discipline as save_json): a bare
    # write_text FOLLOWS a pre-planted symlink at the final component
    # — a hostile run dir aimed one at engine/semgrep/rules/ and the
    # harvest wrote a live rule in-tree. rename() replaces the
    # symlink instead of writing through it.
    write_text_atomically(path, render_candidate_yaml(
        record, pattern, language))
    return path, ""


_RUNBOOK = """\
# Rule candidates — promotion runbook

Files here are `*.candidate.yaml` Semgrep rule DRAFTS, generated
mechanically by `raptor-tp-harvest` from this run's confirmed
findings. They are candidates, not rules:

* Nothing loads this directory. No scan, audit, or CI surface reads
  `*.candidate.yaml`, and the harvester refuses to write into the
  in-tree rules surface (`engine/`).
* A candidate's pattern is a deterministic generalisation of one
  confirmed instance. Expect it to be too tight or too loose — that
  is what review is for.
* Candidate content can describe an undisclosed vulnerability. Treat
  this directory as private until the underlying finding is disclosed
  or fixed.

## Promotion (hand-work, in order)

1. **Review** the pattern against the seed (`metadata.seed_*` keys
   point at the finding, span hash included for staleness checks).
   Tighten with metavariable constraints where the draft is too broad
   (`metavariable-regex`, `metavariable-comparison`, `pattern-not` —
   see `packages/checker_synthesis/grammars.py` for the house grammar
   notes).
2. **Test**: add a positive fixture (must fire) and a negative
   fixture (must stay silent) per the `engine/semgrep/tests`
   fixture-pair discipline, and run the rule against
   `engine/negative_controls/` for its bug family.
3. **Promote** by hand: move the reviewed rule into the appropriate
   `engine/semgrep/rules/<category>/` file with a `raptor.<...>` id
   and `metadata.cwe`, in an ordinary reviewed commit. Never copy a
   candidate in-tree unreviewed, and never point a scanner at this
   directory.
"""


def ensure_runbook(candidates_dir: Path) -> Path:
    """Write the promotion runbook README if missing.

    Atomic rename (never write-through): a pre-planted symlink named
    README.md is REPLACED, not followed — same write-through class as
    the candidate files. ``exists()`` is False for a dangling symlink,
    so the dangling-plant case reaches the atomic write and is
    replaced too.
    """
    path = candidates_dir / RUNBOOK_FILENAME
    if not path.exists():
        candidates_dir.mkdir(parents=True, exist_ok=True)
        write_text_atomically(path, _RUNBOOK)
    return path
