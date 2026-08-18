"""Hardcoded function-name vocabulary guardrail (daily CI scan).

Self-contained, stdlib-only. Flags NEW large literal function-name
lists in Python source — the regression class where a project/library
API vocabulary gets baked into code instead of being learned
(DomainVocabulary / IRIS specs / study loop), shipped as a data pack,
or added to the curated central taxonomy.

What counts as a vocabulary list:

  literal    a list/tuple/set/dict-keys literal whose string elements
             are mostly identifier-like names and number more than
             MAX_SEED_NAMES (the seed-set policy: small curated seed
             sets of <= 9 names per category are fine; big lists are
             the violation)
  alternation a string constant carrying a regex/query alternation
             ("kfree|vfree|kvfree|...") with more than MAX_SEED_NAMES
             identifier-like segments (the embedded-Joern-query /
             hand-built-regex mirror class)

Paths where big name lists are LEGITIMATE are skipped entirely:
the central taxonomy (core/function_taxonomy — curation policy lives
there), data packs and datasets (any ``data`` directory), tests and
fixtures, and recorded corpora (seeds/, corpus dirs).

CI semantics (baseline pattern, cf. ``check_miswiring.py``): findings
are keyed WITHOUT line numbers (relative file + enclosing symbol) and
compared against ``vocab_baseline.json`` next to this script. A key
not in the baseline fails the run — route the vocabulary through the
learned seams or a data pack, or (deliberately, with a note) add the
key to the baseline. Baselined lists that GROW past their recorded
size warn; baseline entries that no longer fire warn as stale.

Usage:
    python3 .github/scripts/check_vocab_lists.py            # CI mode
    python3 .github/scripts/check_vocab_lists.py --root <tree>
    python3 .github/scripts/check_vocab_lists.py --write-baseline
    python3 .github/scripts/check_vocab_lists.py --json out.json

Exit codes: 0 clean (stale/growth warnings only), 1 new findings,
2 usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

# Seed-set policy: census/operator guidance allows curated seed sets
# of up to ~9 names per category. Lists strictly larger are flagged.
MAX_SEED_NAMES = 9

PY_ROOTS = ["core", "packages", "plugins", "libexec", "engine"]

SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", "out", ".out", ".tox", ".venv",
    "venv", "build", "dist", ".claude", "worktrees",
    # Legitimate homes for big name lists:
    "data",       # data packs / packaged datasets
    "tests",      # test files and their fixtures
    "fixtures",
    "seeds",
    "corpus",
    "binary_oracle_corpora",
}

# Files/dirs where large curated name lists are the DESIGN, not a
# regression (relative-path prefixes).
ALLOWED_PREFIXES = (
    "core/function_taxonomy/",   # central catalog w/ curation policy
)

# Identifier-like: C/Python/JS function names, dotted paths
# (os.system), Rust paths (Command::new), leading underscores.
_NAME_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::)[A-Za-z_$][A-Za-z0-9_$]*)*",
)

# Fraction of a literal's string elements that must look like names
# before the literal is treated as a name vocabulary.
_NAME_FRACTION = 0.8

_ALTERNATION_STRIP_RE = re.compile(r"\\[bBsSwWdD]|\(\?:|[()^$?*+\[\]{}\\]")


def _is_name(s: str) -> bool:
    return bool(_NAME_RE.fullmatch(s))


def _alternation_names(s: str) -> list[str]:
    """Identifier segments of a pipe-alternation string constant."""
    if s.count("|") < MAX_SEED_NAMES:
        return []
    names = []
    for seg in s.split("|"):
        seg = _ALTERNATION_STRIP_RE.sub("", seg).strip()
        if seg and _is_name(seg):
            names.append(seg)
        else:
            # A non-name segment (prose, character class remnants)
            # disqualifies the string — natural language and complex
            # regexes both contain pipes.
            return []
    return names


class _Finding:
    def __init__(self, file: str, symbol: str, kind: str,
                 count: int, sample: list[str], line: int):
        self.file = file
        self.symbol = symbol
        self.kind = kind          # "literal" | "alternation"
        self.count = count
        self.sample = sample
        self.line = line

    @property
    def key(self) -> str:
        return f"{self.file}::{self.symbol}"

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "kind": self.kind,
            "count": self.count,
            "line": self.line,
            "sample": self.sample[:6],
        }


def _literal_names(node: ast.AST) -> list[str]:
    """String elements of a list/tuple/set literal or dict keys."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        elts = node.elts
    elif isinstance(node, ast.Dict):
        elts = [k for k in node.keys if k is not None]
    else:
        return []
    strings = [
        e.value for e in elts
        if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]
    if len(strings) <= MAX_SEED_NAMES:
        return []
    names = [s for s in strings if _is_name(s)]
    if len(names) <= MAX_SEED_NAMES:
        return []
    if len(names) / len(strings) < _NAME_FRACTION:
        return []
    return names


class _Scanner(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.scope: list[str] = []
        self.assign: list[str] = []
        self.findings: list[_Finding] = []
        self._seen_nodes: set[int] = set()

    # -- scope tracking ------------------------------------------------
    def _walk_scoped(self, node, label):
        self.scope.append(label)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self._walk_scoped(node, node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._walk_scoped(node, node.name)

    def visit_Assign(self, node):
        target = ""
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                target = tgt.id
                break
            if isinstance(tgt, ast.Attribute):
                target = tgt.attr
                break
        if target == "__all__":
            # Export lists are module metadata, not name vocabulary.
            return
        self.assign.append(target)
        self.generic_visit(node)
        self.assign.pop()

    def visit_AnnAssign(self, node):
        target = node.target.id if isinstance(node.target, ast.Name) else ""
        self.assign.append(target)
        self.generic_visit(node)
        self.assign.pop()

    # -- detection -----------------------------------------------------
    def _symbol(self) -> str:
        for a in reversed(self.assign):
            if a:
                return a
        if self.scope:
            return self.scope[-1]
        return "<module>"

    def _record(self, kind, names, line):
        self.findings.append(_Finding(
            self.rel, self._symbol(), kind, len(names),
            sorted(names)[:6], line,
        ))

    def _check_literal(self, node):
        if id(node) in self._seen_nodes:
            return
        names = _literal_names(node)
        if names:
            self._record("literal", names, node.lineno)
            # Suppress nested re-reports (dict values that are lists...)
            for sub in ast.walk(node):
                self._seen_nodes.add(id(sub))

    def visit_List(self, node):
        self._check_literal(node)
        self.generic_visit(node)

    visit_Tuple = visit_List
    visit_Set = visit_List
    visit_Dict = visit_List

    def visit_Constant(self, node):
        if isinstance(node.value, str) and id(node) not in self._seen_nodes:
            names = _alternation_names(node.value)
            if len(names) > MAX_SEED_NAMES:
                self._record("alternation", names, node.lineno)
        self.generic_visit(node)


def iter_python_files(root: Path):
    for sub in PY_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(root).parts
            if any(part in SKIP_DIR_NAMES for part in rel_parts):
                continue
            if _is_python_file(p):
                yield p


def _is_python_file(p: Path) -> bool:
    if p.suffix == ".py":
        return True
    if p.suffix == "" and p.parent.name == "libexec":
        try:
            head = p.open("rb").read(64)
        except OSError:
            return False
        return b"python" in head.split(b"\n", 1)[0]
    return False


def scan_tree(root: Path) -> list[_Finding]:
    findings: list[_Finding] = []
    for p in iter_python_files(root):
        rel = p.relative_to(root).as_posix()
        if rel.startswith(ALLOWED_PREFIXES):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8",
                                         errors="replace"))
        except SyntaxError:
            continue
        scanner = _Scanner(rel)
        scanner.visit(tree)
        findings.extend(scanner.findings)
    return findings


DEFAULT_BASELINE = Path(__file__).resolve().parent / "vocab_baseline.json"


def load_baseline(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_baseline(path: Path, findings: list[_Finding]) -> None:
    entries = {
        f.key: {"kind": f.kind, "count": f.count}
        for f in findings
    }
    path.write_text(
        json.dumps(entries, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path,
                    default=Path(__file__).resolve().parents[2])
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--write-baseline", action="store_true",
                    help="write the current findings as the new baseline")
    ap.add_argument("--json", type=Path, help="dump findings as JSON")
    args = ap.parse_args()

    if not args.root.is_dir():
        print(f"[vocab] bad --root: {args.root}", file=sys.stderr)
        return 2

    findings = scan_tree(args.root)
    by_key = {f.key: f for f in findings}

    if args.json:
        args.json.write_text(
            json.dumps([f.to_dict() for f in findings], indent=2) + "\n",
            encoding="utf-8",
        )

    if args.write_baseline:
        write_baseline(args.baseline, findings)
        print(f"[vocab] wrote baseline with {len(by_key)} entries "
              f"to {args.baseline}")
        return 0

    baseline = load_baseline(args.baseline)

    new = [f for k, f in sorted(by_key.items()) if k not in baseline]
    grown = [
        (f, baseline[k].get("count", 0))
        for k, f in sorted(by_key.items())
        if k in baseline and f.count > baseline[k].get("count", 0)
    ]
    stale = sorted(set(baseline) - set(by_key))

    for f, old_count in grown:
        print(f"[vocab] WARN grown: {f.key} ({old_count} -> {f.count} "
              f"names) — route additions through DomainVocabulary/IRIS "
              f"or a data pack")
    for k in stale:
        print(f"[vocab] WARN stale baseline entry (no longer fires): {k}")

    if new:
        print(f"[vocab] {len(new)} NEW literal function-name list(s) "
              f"(> {MAX_SEED_NAMES} names) outside the allowed paths:")
        for f in new:
            print(f"  {f.key}  [{f.kind}] {f.count} names at line "
                  f"{f.line}; e.g. {', '.join(f.sample[:4])}")
        print(
            "[vocab] Name vocabularies must be learned (DomainVocabulary, "
            "IRIS specs, study loop), shipped as a data pack, or added to "
            "the central taxonomy. Seed sets of <= "
            f"{MAX_SEED_NAMES} names are fine. If this list is genuinely "
            "one of those, add its key to "
            ".github/scripts/vocab_baseline.json with a review note.",
        )
        return 1

    print(f"[vocab] clean: {len(by_key)} baselined vocabulary lists, "
          f"no new ones ({len(stale)} stale, {len(grown)} grown).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
