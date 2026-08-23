#!/usr/bin/env python3
"""Canonical-JSON byte-form guardrail (daily CI scan).

Self-contained, stdlib-only. Freezes the repo's canonical-serialisation
sites: the ``json.dumps`` calls whose exact bytes feed an HMAC, a
persisted sha256 identity / content address, a digest-keyed cache, or a
byte-stability contract. Those bytes are minted at version N and
verified at version N+1 — ANY drift (separators, key order, escaping,
encoder) flips previously-minted artifacts to "tampered", forks
content addresses, or invalidates whole caches. Each site pins its
exact option form; this checker keeps them pinned.

The one blessed canonical serializer is
``core.json.utils.dumps_canonical`` (stdlib-pinned ``sort_keys=True,
separators=(",", ":"), default=str`` — byte-matching the
review-journal MAC form). Sites whose pinned form matches it call it;
sites pinning a DIFFERENT byte form stay raw forever and live in the
baseline with a note each.

Two detector rules:

  raw_dumps_in_canonical_module
      inside the canonical-module list (CANONICAL_MODULES below), every
      ``json.dumps`` / ``json.dump`` call not routed through
      ``dumps_canonical`` is a finding. New code in those modules must
      either use the substrate (``dumps_canonical`` for hash lanes,
      ``dumps_display`` / ``save_json`` for display/artifacts) or be
      baselined deliberately, with a note.

  dumps_flows_to_hash
      repo-wide heuristic: a ``json.dumps(...)`` result that flows into
      ``hashlib.*`` / ``hmac.*`` within the same function — either
      nested directly in the call or via an intermediate local name —
      is a NEW canonical site that missed the table. Route it through
      ``dumps_canonical`` (or baseline it with the reason its byte
      form must differ).

CI semantics (baseline pattern, cf. ``check_miswiring.py`` /
``check_vocab_lists.py``): findings are keyed WITHOUT line numbers
(rule + relative file + enclosing symbol) and compared against
``canonical_json_baseline.json`` next to this script. A key not in the
baseline fails the run; baseline entries that no longer fire warn as
stale and do not fail.

Usage:
    python3 .github/scripts/check_canonical_json.py            # CI mode
    python3 .github/scripts/check_canonical_json.py --root <tree>
    python3 .github/scripts/check_canonical_json.py --write-baseline
    python3 .github/scripts/check_canonical_json.py --json out.json

Exit codes: 0 clean (stale-only is clean), 1 new findings, 2 usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections.abc import Iterator
from pathlib import Path

PY_ROOTS = ["core", "packages", "plugins", "libexec", "engine"]

SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", "out", ".out", ".tox", ".venv",
    "venv", "build", "dist", ".claude", "worktrees",
    "tests", "fixtures", "seeds", "corpus", "data",
}

# Modules owning canonical byte forms (MAC-verified canonicalisation,
# persisted sha256 identities, digest-keyed caches, prompt-embedded
# bytes hashed into cache keys, byte-stability contracts) — assembled
# by auditing every json.dumps whose bytes are integrity-consumed.
# Paths are relative to the repo root.
CANONICAL_MODULES = frozenset({
    # HMAC-verified canonical forms
    "core/llm/scorecard/integrity.py",
    "core/iris/integrity.py",
    "core/llm/cache_integrity.py",
    "core/coverage/journal_mac.py",
    "core/sandbox/triage.py",
    "core/sandbox/summary.py",
    # persisted sha256 identity / content-address keys
    "core/sarif/parser.py",
    "core/project/report.py",
    "core/evidence/__init__.py",
    "core/witness/provenance.py",
    "packages/hypothesis_validation/provenance.py",
    "packages/llm_analysis/dataflow_validation.py",
    # digest-keyed caches / replay
    "core/llm/client.py",
    "core/sandbox/_landlock_audit.py",
    "core/sandbox/_spawn.py",
    # prompt-embedded bytes hashed into the response-cache key
    "core/llm/multi_model/prompt_helpers.py",
    "packages/llm_analysis/tasks.py",
    # fail-closed byte-stability contracts
    "core/binary/fingerprint.py",
    "packages/binary_analysis/fingerprint.py",
    "core/concepts/model.py",
    "packages/sca/calibration/build.py",
    "core/json/jsonl.py",
})

HASH_MODULE_NAMES = {"hashlib", "hmac"}


def iter_python_files(root: Path) -> Iterator[Path]:
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
            if p.suffix == ".py":
                yield p
            elif p.suffix == "" and p.parent.name == "libexec":
                try:
                    head = p.open("rb").read(64)
                except OSError:
                    continue
                if b"python" in head.split(b"\n", 1)[0]:
                    yield p


def _callee_parts(node: ast.expr) -> tuple[str, ...]:
    """Dotted callee name parts, e.g. json.dumps -> ("json", "dumps")."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return tuple(reversed(parts))


def _is_json_dumps(call: ast.Call, json_aliases: set[str],
                   bare_dumps: set[str] = frozenset()) -> bool:
    parts = _callee_parts(call.func)
    if len(parts) == 2 and parts[0] in json_aliases \
            and parts[1] in ("dumps", "dump"):
        return True
    # `from json import dumps [as X]`
    return len(parts) == 1 and parts[0] in bare_dumps


def _is_hash_call(call: ast.Call) -> bool:
    parts = _callee_parts(call.func)
    return bool(parts) and parts[0] in HASH_MODULE_NAMES


def _json_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """(module aliases, bare dumps/dump names) bound to stdlib json."""
    aliases: set[str] = set()
    bare: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for al in node.names:
                if al.name == "json":
                    aliases.add(al.asname or "json")
        elif isinstance(node, ast.ImportFrom) and node.module == "json" \
                and not node.level:
            for al in node.names:
                if al.name in ("dumps", "dump"):
                    bare.add(al.asname or al.name)
    return aliases, bare


class _FunctionScanner(ast.NodeVisitor):
    """Per-function scan: raw dumps calls + dumps-into-hash flows."""

    def __init__(self, json_aliases: set[str],
                 bare_dumps: set[str]) -> None:
        self.json_aliases = json_aliases
        self.bare_dumps = bare_dumps
        self.qual_stack: list[str] = []
        self.raw_dumps: list[tuple[str, int]] = []       # (qualname, lineno)
        self.hash_flows: list[tuple[str, int]] = []      # (qualname, lineno)
        # per-function name-taint state, pushed/popped with scope
        self._tainted_stack: list[set[str]] = [set()]

    # -- scope handling ---------------------------------------------------
    def _enter(self, name: str, node: ast.AST) -> None:
        self.qual_stack.append(name)
        self._tainted_stack.append(set())
        self.generic_visit(node)
        self._tainted_stack.pop()
        self.qual_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter(node.name, node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter(node.name, node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._enter(node.name, node)

    @property
    def _qualname(self) -> str:
        return ".".join(self.qual_stack) or "<module>"

    @property
    def _tainted(self) -> set[str]:
        return self._tainted_stack[-1]

    # -- helpers ----------------------------------------------------------
    def _contains_json_dumps(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _is_json_dumps(
                    sub, self.json_aliases, self.bare_dumps):
                return True
        return False

    def _references_tainted(self, node: ast.AST) -> bool:
        return any(
            isinstance(sub, ast.Name) and sub.id in self._tainted
            for sub in ast.walk(node))

    # -- detectors ----------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        if self._contains_json_dumps(node.value) \
                or self._references_tainted(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._tainted.add(t.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_json_dumps(node, self.json_aliases, self.bare_dumps):
            self.raw_dumps.append((self._qualname, node.lineno))
        if _is_hash_call(node):
            args = list(node.args) + [kw.value for kw in node.keywords]
            for a in args:
                if self._contains_json_dumps(a) or self._references_tainted(a):
                    self.hash_flows.append((self._qualname, node.lineno))
                    break
        self.generic_visit(node)


def scan_tree(root: Path) -> list[dict]:
    findings = []
    for path in iter_python_files(root):
        rel = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8",
                                            errors="replace"))
        except (SyntaxError, ValueError, OSError):
            continue
        aliases, bare_dumps = _json_aliases(tree)
        scanner = _FunctionScanner(aliases, bare_dumps)
        scanner.visit(tree)
        if rel in CANONICAL_MODULES:
            findings.extend({
                "rule": "raw_dumps_in_canonical_module",
                "file": rel, "line": lineno, "symbol": qual,
                "detail": (
                    f"raw json.dumps/json.dump in canonical module "
                    f"{rel} ({qual}) — use core.json.dumps_canonical "
                    "for hash lanes / dumps_display or save_json for "
                    "display and artifacts, or baseline with a note"),
            } for qual, lineno in scanner.raw_dumps)
        findings.extend({
            "rule": "dumps_flows_to_hash",
            "file": rel, "line": lineno, "symbol": qual,
            "detail": (
                f"json.dumps output flows into hashlib/hmac in {rel} "
                f"({qual}) — a canonical byte form outside the module list; "
                "use core.json.dumps_canonical or baseline with the "
                "reason its byte form must differ"),
        } for qual, lineno in scanner.hash_flows)
    return findings


def finding_key(f: dict) -> str:
    """Stable baseline key: rule + file + symbol (no line numbers)."""
    return f"{f['rule']}:{f['file']}:{f['symbol']}"


DEFAULT_BASELINE = Path(__file__).resolve().parent / \
    "canonical_json_baseline.json"


def load_baseline(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("entries", {})


def write_baseline(path: Path, findings: list[dict]) -> None:
    old = load_baseline(path)
    entries = {}
    for f in findings:
        key = finding_key(f)
        note = (old.get(key) or {}).get("note") or "accepted (triaged)"
        entries[key] = {"note": note}
    payload = {
        "_comment": (
            "Accepted canonical-JSON findings. Keys are "
            "rule:file:symbol (no line numbers). Every entry is a "
            "deliberately-raw json.dumps site whose byte form is "
            "frozen (MAC canonical form, persisted hash identity, "
            "digest-keyed cache, byte-stability contract) or a "
            "display/artifact site inside a canonical module whose "
            "writer surface has not been migrated. Add an entry ONLY with a note; "
            "check_canonical_json.py fails CI on any finding not "
            "listed here and warns on stale entries."
        ),
        "version": 1,
        "entries": dict(sorted(entries.items())),
    }
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path.cwd(),
                    help="repo root to scan (default: cwd)")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--write-baseline", action="store_true",
                    help="write the current findings as the new baseline "
                         "(preserves notes of surviving entries)")
    ap.add_argument("--json", type=Path, default=None,
                    help="dump the structured findings report")
    args = ap.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    findings = scan_tree(root)
    by_key: dict[str, dict] = {}
    for f in findings:
        by_key.setdefault(finding_key(f), f)

    if args.json:
        args.json.write_text(json.dumps(findings, indent=1),
                             encoding="utf-8")
        print(f"[canonical-json] wrote {args.json}", file=sys.stderr)

    if args.write_baseline:
        write_baseline(args.baseline, findings)
        print(f"[canonical-json] wrote baseline with {len(by_key)} entries "
              f"to {args.baseline}")
        return 0

    baseline = load_baseline(args.baseline)
    new = {k: f for k, f in by_key.items() if k not in baseline}
    stale = sorted(set(baseline) - set(by_key))

    for k in stale:
        print(f"[canonical-json] WARN stale baseline entry (no longer "
              f"fires — consider removing): {k}")

    if new:
        print(f"[canonical-json] {len(new)} NEW canonical-JSON finding(s) "
              "not in canonical_json_baseline.json:")
        for k, f in sorted(new.items()):
            print(f"  {k}\n      at {f['file']}:{f['line']}\n"
                  f"      {f['detail']}")
        print(
            "\nRoute the site through core.json.dumps_canonical (hash "
            "lanes) or dumps_display/save_json (display, artifacts), or "
            "— deliberately, with a note — add its key to "
            ".github/scripts/canonical_json_baseline.json.")
        return 1

    print(f"[canonical-json] clean: {len(by_key)} finding(s), all "
          f"baselined"
          + (f"; {len(stale)} stale baseline entrie(s)" if stale else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
