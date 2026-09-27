#!/usr/bin/env python3
"""Run-dir raw-read census — parent-side readers of run artifacts.

Files under a run's output directory are written by sandboxed
children executing (or steered by) untrusted target material:
scanners over hostile repos, instrumented target binaries, dispatched
LLM agents. The PARENT-side code that parses those artifacts back in
(orchestrators, report writers, validators, lifecycle) must read them
on a hardened path — the bounded ``core.json`` loaders or the
``core.source`` capped/gated readers — never with a raw ``open()`` /
``read_text()`` / ``json.load()`` whose size, type, and symlink
posture nothing clamps.

This gate censuses every read of a RUN-ARTIFACT-SHAPED filename
(``*.json`` / ``*.jsonl`` / ``*.sarif`` literals, minus the curated
non-artifact config names) across the runtime-source universe and
classifies the read primitive:

  hardened   the ``core.json`` loader family or the ``core.source``
             capped/gated/contained readers
  raw        builtin/Path ``open`` in a read mode, ``read_text`` /
             ``read_bytes`` / ``readlines``, ``json.load`` /
             ``json.loads`` — with an artifact literal in the same
             statement, or reached through a one-hop local name
             assigned from an expression carrying the literal

CI semantics (baseline pattern, cf. ``check_miswiring.py``): raw
findings are keyed WITHOUT line numbers (``file::artifact::primitive``)
and compared against ``run_dir_reads_baseline.json`` next to this
script. A finding not in the baseline fails the run — harden it (route
through ``core.json.load_json`` / ``core.source``) or, deliberately
and with a note, add its key to the baseline. Baseline entries that no
longer fire are reported as stale warnings and do not fail.

Usage:
    python3 .github/scripts/check_run_dir_reads.py            # CI mode
    python3 .github/scripts/check_run_dir_reads.py --root <tree>
    python3 .github/scripts/check_run_dir_reads.py --write-baseline
    python3 .github/scripts/check_run_dir_reads.py --census   # full table
    python3 .github/scripts/check_run_dir_reads.py --json out.json

Exit codes: 0 clean (stale-only is clean), 1 new findings, 2 usage
error. Precision over recall: only artifact-shaped literals join the
census, and only read-mode primitives fire.

Known blind spots (verified evasions — kept, by design, for
precision): the detector is a RATCHET against accidental raw reads
drifting into the tree, not a defense against adversarial in-repo
code. A contributor deliberately hiding a read defeats it, e.g.:

- ``os.open()`` + ``os.read()``: fd-level primitives are not in the
  raw-read primitive set (they are also what the HARDENED readers are
  built from, so matching them would flag the hardening itself).
- ``getattr(p, "read_text")()``: dynamic attribute dispatch never
  produces the ``ast.Attribute`` node the classifier matches.
- Two-hop aliasing: ``a = run_dir / "x.json"; b = a; open(b)`` — the
  local name map is deliberately ONE-hop (assignment from an
  expression that carries the literal); each extra hop trades
  precision for recall and one hop covers the accidental pattern.
- String concatenation: ``open(d + "/findings" + ".json")`` — only
  whole string literals (incl. f-string/os.path.join/Path operands)
  are matched against the artifact shape, not folded concatenations.

Adversarial-code review is the job of the human/LLM review layers;
this gate keeps the honest paths honest.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

#: Run-artifact filename shape. Anchored on the path BASENAME of the
#: string literal; extensions limited to the machine-parsed artifact
#: classes (md/log/txt reads are render-side, not parse-side).
ARTIFACT_RE = re.compile(
    r"^\.?[A-Za-z0-9._\-{}*]+\.(json|jsonl|sarif)$")

#: Filenames that match the artifact shape but are NOT run-dir
#: content: repo/tool configuration, packaging metadata, and
#: RAPTOR-owned static data. A name here never joins the census.
NON_RUN_ARTIFACTS = frozenset({
    "package.json", "package-lock.json", "tsconfig.json",
    "settings.json", "settings.local.json", "compile_commands.json",
    "pyproject.toml", "config.json", "llm-config.json", "models.json",
    "manifest.json", "plugin.json", "mcp.json", "keybindings.json",
    "devcontainer.json", "qlpack.json", "codeql-pack.lock.json",
    "extensions.json", "launch.json", "tasks.json",
    "composer.json", "bower.json", "deno.json", "jsconfig.json",
    "app.json", "angular.json", "nx.json", "lerna.json",
    "renovate.json", "vercel.json", "firebase.json",
    "cve-env.json",
})

#: Hardened read callables (matched on the trailing attribute /
#: name of the call target). The ``core.json`` loader family is
#: bounded by default (and ``load_json_unbounded`` spellings are
#: adjudicated by ``test_load_json_budget_closure.py``); the
#: ``core.source`` family carries the fd-checked regularity /
#: FIFO-refusal / size-cap gates.
HARDENED_CALLS = frozenset({
    "load_json", "load_json_unbounded", "load_json_with_comments",
    "load_jsonc", "load_json_bounded", "load_jsonl", "iter_jsonl",
    "read_text_gated", "read_text_capped", "read_bytes_capped",
    "read_contained", "open_regular", "open_regular_beneath",
    "load_sarif_capped",
})

#: Raw read primitives: attribute-call spellings.
RAW_ATTR_CALLS = frozenset({
    "read_text", "read_bytes", "readlines", "load", "loads",
})

#: Receiver heads whose ``.load`` / ``.loads`` is a deserialiser call
#: (``pickle.load`` of run-dir content is exactly a finding).
_DESERIALISER_HEADS = frozenset({
    "json", "yaml", "pickle", "marshal", "tomllib", "plistlib",
})

#: The hardened helpers' own homes: the modules that IMPLEMENT the
#: bounded/gated readers necessarily spell the raw idiom.
HELPER_HOMES = frozenset({
    "core/json/utils.py", "core/json/bounded.py", "core/json/jsonl.py",
    "core/json/jsonc.py", "core/source/gated.py",
    "core/source/contained.py", "core/source/beneath.py",
    "core/source/capped.py",
})

BASELINE_NAME = "run_dir_reads_baseline.json"


def _artifact_name(value: str) -> str | None:
    """The run-artifact basename carried by *value*, or ``None``."""
    if not value or len(value) > 200 or "\n" in value:
        return None
    base = value.rsplit("/", 1)[-1]
    if not ARTIFACT_RE.match(base):
        return None
    if base in NON_RUN_ARTIFACTS:
        return None
    # Extension-only or separator-only stems are format strings /
    # suffix constants, not artifact names ("*.json", ".json").
    stem = base.rsplit(".", 1)[0]
    if not re.search(r"[A-Za-z0-9]", stem.strip("*{}.")):
        return None
    return base


def _call_target(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _literals_in(node: ast.AST) -> set[str]:
    """Artifact names carried by string constants under *node*."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            name = _artifact_name(sub.value)
            if name:
                out.add(name)
        elif isinstance(sub, ast.JoinedStr):
            # f-string: reconstruct the constant tail so
            # f"{x}/findings.json" still carries the artifact name.
            tail = "".join(
                v.value for v in sub.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            name = _artifact_name(tail.rsplit("/", 1)[-1])
            if name:
                out.add(name)
    return out


def _open_read_mode(node: ast.Call) -> bool:
    """True when an ``open``-family call is in a read mode.

    The mode's positional slot differs by spelling: ``open(path,
    mode)`` carries it at index 1, ``path.open(mode)`` at index 0.
    """
    mode_idx = 0 if isinstance(node.func, ast.Attribute) else 1
    mode = None
    if (len(node.args) > mode_idx
            and isinstance(node.args[mode_idx], ast.Constant)):
        mode = node.args[mode_idx].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    if mode is None:
        # No literal mode: the default is read; a dynamic mode is
        # ambiguous — treat as read (precision cost adjudicated via
        # baseline, never a silent pass for a hostile-read hole).
        return not (len(node.args) > mode_idx or
                    any(kw.arg == "mode" for kw in node.keywords))
    if not isinstance(mode, str):
        return False
    return not any(c in mode for c in "wax")


#: Inline adjudication marker (shared with the safe-read closure
#: gate): a raw read carrying ``# raw-open: <why>`` on any physical
#: line of the call is a deliberate, reasoned exception and does not
#: fire. New exceptions should prefer the marker over the baseline —
#: the reason lives next to the code.
_ADJUDICATION_MARKER = "# raw-open:"


class _Visitor(ast.NodeVisitor):
    """Single pass: name→artifact one-hop map, then read-call census."""

    def __init__(self, rel: str, lines: list[str]) -> None:
        self.rel = rel
        self.lines = lines
        self.raw: list[tuple[int, str, str]] = []      # lineno, artifact, prim
        self.hardened: list[tuple[int, str, str]] = []
        self._name_artifacts: dict[str, str] = {}

    def _adjudicated(self, node: ast.Call) -> bool:
        end = getattr(node, "end_lineno", None) or node.lineno
        for lineno in range(node.lineno, end + 1):
            if (lineno <= len(self.lines)
                    and _ADJUDICATION_MARKER in self.lines[lineno - 1]):
                return True
        return False

    # -- one-hop local-name tracking ---------------------------------
    # Names are scoped: a function's locals never leak into sibling
    # functions (a ``findings.json`` assignment in one helper must not
    # attribute an unrelated ``open(path)`` elsewhere in the file).
    # Module-level names remain visible inside functions.
    def _visit_scope(self, node: ast.AST) -> None:
        saved = dict(self._name_artifacts)
        self.generic_visit(node)
        self._name_artifacts = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        arts = _literals_in(node.value)
        if arts:
            art = sorted(arts)[0]
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self._name_artifacts[tgt.id] = art
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            arts = _literals_in(node.value)
            if arts:
                self._name_artifacts[node.target.id] = sorted(arts)[0]
        self.generic_visit(node)

    # -- read-call census ---------------------------------------------
    def _artifacts_for_call(self, node: ast.Call) -> set[str]:
        arts = _literals_in(node)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self._name_artifacts:
                arts.add(self._name_artifacts[sub.id])
        return arts

    def visit_Call(self, node: ast.Call) -> None:
        target = _call_target(node)
        if target is not None:
            if target in HARDENED_CALLS:
                for art in sorted(self._artifacts_for_call(node)):
                    self.hardened.append((node.lineno, art, target))
                # Do not descend into a hardened call's arguments
                # looking for raw reads — the loader owns the read.
                for arg in list(node.args) + [
                        kw.value for kw in node.keywords]:
                    self.generic_visit(arg)
                return
            prim: str | None = None
            if target == "open" and _open_read_mode(node):
                prim = "open"
            elif (target in RAW_ATTR_CALLS
                    and isinstance(node.func, ast.Attribute)):
                if target in ("load", "loads"):
                    # Only deserialiser-module receivers count:
                    # ``json.load`` / ``_sca_json.loads`` / ``yaml.load``
                    # / ``pickle.load``. Project class loaders named
                    # ``load`` (ReadingList.load, DomainModel.load) are
                    # censused at their own read primitive instead —
                    # flagging every ``X.load(path)`` call site would
                    # drown the table in the loader's internals.
                    head = _expr_head(node.func.value)
                    if (head in _DESERIALISER_HEADS
                            or "json" in head.lower()):
                        prim = f"{head}.{target}"
                elif target == "readlines":
                    prim = "readlines"
                else:
                    prim = target
            elif target == "open" and isinstance(node.func, ast.Attribute):
                if _open_read_mode(node):
                    prim = "open"
            if prim is not None and not self._adjudicated(node):
                for art in sorted(self._artifacts_for_call(node)):
                    self.raw.append((node.lineno, art, prim))
        self.generic_visit(node)


def _expr_head(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return "?"


def census_file(rel: str, source: str) -> _Visitor | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    v = _Visitor(rel, source.splitlines())
    v.visit(tree)
    return v


def run_census(root: Path) -> tuple[list[dict], list[dict]]:
    """(raw_findings, hardened_readers) over the runtime universe."""
    raw: list[dict] = []
    hardened: list[dict] = []
    for path in runtime_file_universe(root):
        rel = path.relative_to(root).as_posix()
        if rel in HELPER_HOMES:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        v = census_file(rel, source)
        if v is None:
            continue
        for lineno, art, prim in v.raw:
            raw.append({"file": rel, "artifact": art,
                        "primitive": prim, "line": lineno})
        for lineno, art, prim in v.hardened:
            hardened.append({"file": rel, "artifact": art,
                             "helper": prim, "line": lineno})
    return raw, hardened


def finding_key(f: dict) -> str:
    return f"{f['file']}::{f['artifact']}::{f['primitive']}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--baseline", type=Path, default=None)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--census", action="store_true",
                    help="print the full reader table (hardened + raw)")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args(argv)

    root = args.root.resolve() if args.root else repo_root()
    baseline_path = (args.baseline if args.baseline
                     else Path(__file__).resolve().parent / BASELINE_NAME)

    raw, hardened = run_census(root)

    if args.json:
        args.json.write_text(json.dumps(
            {"raw": raw, "hardened": hardened}, indent=2) + "\n",
            encoding="utf-8")

    if args.census:
        print(f"run-dir artifact readers under {root}")
        print(f"  hardened reader sites: {len(hardened)}")
        for h in sorted(hardened, key=lambda x: (x["file"], x["line"])):
            print(f"    {h['file']}:{h['line']}  {h['artifact']}"
                  f"  via {h['helper']}")
        print(f"  raw reader sites: {len(raw)}")
        for f in sorted(raw, key=lambda x: (x["file"], x["line"])):
            print(f"    {f['file']}:{f['line']}  {f['artifact']}"
                  f"  via {f['primitive']}")
        return 0

    keys = sorted({finding_key(f) for f in raw})
    if args.write_baseline:
        baseline_path.write_text(
            json.dumps({"comment": (
                "Adjudicated raw run-artifact reads. Every entry is a "
                "deliberate exception with a reason; new raw reads "
                "must route through core.json / core.source instead "
                "of growing this file."),
                "keys": keys}, indent=2) + "\n",
            encoding="utf-8")
        print(f"wrote {len(keys)} baseline keys to {baseline_path}")
        return 0

    baseline: set[str] = set()
    if baseline_path.is_file():
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline = set(data.get("keys", []))

    new = [f for f in raw if finding_key(f) not in baseline]
    stale = sorted(baseline - {finding_key(f) for f in raw})

    for key in stale:
        print(f"STALE baseline entry (no longer fires): {key}")
    if new:
        print(f"{len(new)} raw run-artifact read(s) not in baseline:")
        for f in sorted(new, key=lambda x: (x["file"], x["line"])):
            print(f"  {f['file']}:{f['line']}  {f['artifact']} read via "
                  f"{f['primitive']} — route through core.json.load_json "
                  f"/ core.source, or baseline with a note in "
                  f"{BASELINE_NAME}")
        return 1
    print(f"run-dir read census clean "
          f"({len(raw)} baselined raw, {len(hardened)} hardened, "
          f"{len(stale)} stale baseline entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
