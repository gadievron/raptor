"""Synthetic cross-file Python fixture generator (Juliet-B-shape).

Generates small Python packages with KNOWN cross-file taint flows —
an HTTP route file, a helper file, and a sink file, the flow crossing
every file boundary — plus a schema-valid recall manifest labelling
the sink lines. Each vulnerable case has a sanitized twin: same
route → helper → sink shape, but the helper applies a canonical
sanitizer, so the (unchanged) sink line is a labelled-clean region —
the cross-file analogue of Juliet's bad/good split, sink-anchored
like the Juliet-B manifest (detectors report at the sink; labelling
a forwarding file would manufacture phantom misses).

MACHINERY, NOT CONTENT: this generator ships in-tree; the packages,
manifest, and label files it produces stay local (an ``out/`` dir or
a private store), exactly like the Juliet clone and the audit-corpus
``labels/`` overlays. Provenance is the ``synthetic`` kind —
generator name + seed + case, kind-separated from ``benchmark`` and
``cve`` — the flaw is generator-authored, so it is public by
construction (the templates below ARE the disclosure).

Determinism: every choice derives from ``random.Random`` streams
keyed on ``(seed, class, index)``, and the fixture tree is committed
with pinned author/committer identity and dates, so the same seed
reproduces the same pinned sha and the manifest's labels stay
sha-bound like every recall corpus.

Seeded mutation varies identifier names, route paths, and benign
intermediate hops so generated labels exercise the engine's
resolution machinery rather than a memorable constant shape; the
FLOWS themselves are fixed ground truth per sink class.
"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.git import get_safe_git_env
from core.json import save_json
from core.recall.manifest import SCHEMA_VERSION
from core.source.lines import split_lines

GENERATOR_NAME = "crossfile-python"

#: Pinned commit identity/dates: the fixture sha must be a pure
#: function of (generator version, seed, case set) so two operators
#: generating the same seed get byte-identical pins.
_GIT_IDENT = {
    "GIT_AUTHOR_NAME": "raptor-fixture-generator",
    "GIT_AUTHOR_EMAIL": "fixtures@raptor.invalid",
    "GIT_COMMITTER_NAME": "raptor-fixture-generator",
    "GIT_COMMITTER_EMAIL": "fixtures@raptor.invalid",
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00 +0000",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00 +0000",
}

#: Identifier pools the seeded rng draws from. Small on purpose —
#: variation exists to defeat constant-shape matching, not to model
#: real naming; the pools are part of the generator's public
#: definition.
_PARAM_POOL = ("entry", "item", "name", "target", "record", "token")
_VAR_POOL = ("data", "value", "payload", "field")
_VERB_POOL = ("prepare", "resolve", "process", "shape", "stage")

_SANITIZER_NOTE = (
    "sanitized twin: the helper applies a canonical sanitizer before "
    "the UNCHANGED sink line — a finding here is a cross-file "
    "sanitizer-blindness FP")


@dataclass(frozen=True)
class SinkClass:
    """One cross-file flow family: sink + canonical helper sanitizer."""

    name: str
    cwe: str
    #: marker substring locating the sink call line in sinks.py
    sink_marker: str
    #: import block for sinks.py ("" = none)
    sink_imports: str
    #: sink function body template ({var} = tainted parameter)
    sink_body: str
    #: import the sanitized helper needs ("" = none)
    sanitizer_import: str
    #: expression the sanitized helper applies ({param} = input)
    sanitizer_expr: str


SINK_CLASSES: dict[str, SinkClass] = {
    "command_injection": SinkClass(
        name="command_injection", cwe="CWE-78",
        sink_marker="subprocess.run(",
        sink_imports="import subprocess\n",
        sink_body=(
            "    proc = subprocess.run(\"archive --name \" + {var}, "
            "shell=True)\n"
            "    return str(proc.returncode)\n"),
        sanitizer_import="import shlex\n",
        sanitizer_expr="shlex.quote({param})",
    ),
    "sql_injection": SinkClass(
        name="sql_injection", cwe="CWE-89",
        sink_marker="cur.execute(",
        sink_imports="import sqlite3\n",
        sink_body=(
            "    conn = sqlite3.connect(\"app.db\")\n"
            "    cur = conn.cursor()\n"
            "    cur.execute(\"SELECT name FROM users WHERE id = '\""
            " + {var} + \"'\")\n"
            "    row = cur.fetchone()\n"
            "    return \"\" if row is None else str(row[0])\n"),
        sanitizer_import="",
        sanitizer_expr="str(int({param}))",
    ),
    "path_traversal": SinkClass(
        name="path_traversal", cwe="CWE-22",
        sink_marker="open(os.path.join(",
        sink_imports="import os\n\nBASE_DIR = \"/srv/appdata\"\n",
        sink_body=(
            "    with open(os.path.join(BASE_DIR, {var})) as fh:\n"
            "        return fh.read()\n"),
        sanitizer_import="import os.path\n",
        sanitizer_expr="os.path.basename({param})",
    ),
    "code_injection": SinkClass(
        name="code_injection", cwe="CWE-95",
        sink_marker="eval(",
        sink_imports="",
        sink_body="    return str(eval({var}))\n",
        sanitizer_import="",
        sanitizer_expr="str(int({param}))",
    ),
}


@dataclass(frozen=True)
class GeneratedCase:
    """One generated package (a vulnerable case or its sanitized twin)."""

    case_id: str
    sink_class: str
    cwe: str
    sanitized: bool
    package_dir: str          # repo-relative
    sink_file: str            # repo-relative
    sink_fn: str
    sink_line: int            # 1-based line of the dangerous call
    sink_fn_start: int        # 1-based def line of the sink function
    sink_fn_end: int          # 1-based last line of the sink function


class CrossfileFixtureError(RuntimeError):
    pass


def _route_py(pkg: str, handler: str, helper: str, param: str,
              route: str) -> str:
    return (
        f'"""HTTP entry points for the {pkg} feature '
        '(generated fixture)."""\n'
        "\n"
        "from flask import Flask, request\n"
        "\n"
        f"from .helpers import {helper}\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "\n"
        f'@app.route("/{route}")\n'
        f"def {handler}():\n"
        f'    {param} = request.args.get("{param}", "")\n'
        f"    return {helper}({param})\n"
    )


def _helper_py(pkg: str, sc: SinkClass, helper: str, sink_fn: str,
               param: str, var: str, *, sanitized: bool) -> str:
    if sanitized:
        imports = sc.sanitizer_import
        assign = sc.sanitizer_expr.format(param=param)
    else:
        imports = ""
        assign = param
    return (
        f'"""Mid-layer plumbing for the {pkg} feature '
        '(generated fixture)."""\n'
        "\n"
        + imports
        + ("\n" if imports else "")
        + f"from .sinks import {sink_fn}\n"
        "\n"
        "\n"
        f"def {helper}({param}):\n"
        f"    {var} = {assign}\n"
        f"    return {sink_fn}({var})\n"
    )


def _sinks_py(pkg: str, sc: SinkClass, sink_fn: str, var: str) -> str:
    imports = sc.sink_imports
    return (
        f'"""Storage layer for the {pkg} feature '
        '(generated fixture)."""\n'
        "\n"
        + imports
        + ("\n" if imports else "")
        + "\n"
        f"def {sink_fn}({var}):\n"
        + sc.sink_body.format(var=var)
    )


def _line_of(text: str, marker: str, path: str) -> int:
    for i, line in enumerate(split_lines(text), 1):
        if marker in line:
            return i
    msg = f"generator bug: marker {marker!r} not found in {path}"
    raise CrossfileFixtureError(msg)


def _fn_span(text: str, fn: str, path: str) -> tuple[int, int]:
    lines = split_lines(text)
    start = _line_of(text, f"def {fn}(", path)
    end = len(lines)
    while end > start and not lines[end - 1].strip():
        end -= 1
    return start, end


def _emit_case(repo: Path, seed: int, sc: SinkClass, index: int, *,
               sanitized: bool) -> GeneratedCase:
    rng = random.Random(
        f"{GENERATOR_NAME}:{seed}:{sc.name}:{index}:{sanitized}")
    case_id = f"xf_{sc.name}_{index:03d}" + ("_safe" if sanitized else "")
    param = rng.choice(_PARAM_POOL)
    var = rng.choice(_VAR_POOL)
    verb = rng.choice(_VERB_POOL)
    helper = f"{verb}_{param}"
    sink_fn = f"apply_{sc.name}_op"
    handler = f"handle_{param}"
    route = f"{sc.name.replace('_', '-')}-{index:03d}" + (
        "-safe" if sanitized else "")

    pkg_dir = repo / case_id
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
    (pkg_dir / "app.py").write_text(
        _route_py(case_id, handler, helper, param, route),
        encoding="utf-8")
    (pkg_dir / "helpers.py").write_text(
        _helper_py(case_id, sc, helper, sink_fn, param, var,
                   sanitized=sanitized), encoding="utf-8")
    sinks_text = _sinks_py(case_id, sc, sink_fn, var)
    (pkg_dir / "sinks.py").write_text(sinks_text, encoding="utf-8")

    rel_sink = f"{case_id}/sinks.py"
    fn_start, fn_end = _fn_span(sinks_text, sink_fn, rel_sink)
    return GeneratedCase(
        case_id=case_id, sink_class=sc.name, cwe=sc.cwe,
        sanitized=sanitized, package_dir=case_id, sink_file=rel_sink,
        sink_fn=sink_fn,
        sink_line=_line_of(sinks_text, sc.sink_marker, rel_sink),
        sink_fn_start=fn_start, sink_fn_end=fn_end,
    )


def _git(repo: Path, *args: str) -> str:
    env = get_safe_git_env()
    env.update(_GIT_IDENT)
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        text=True, timeout=120, check=False, env=env)
    if proc.returncode != 0:
        msg = f"git {args[0]} failed in {repo}: {proc.stderr.strip()}"
        raise CrossfileFixtureError(msg)
    return proc.stdout


def _commit_fixture_repo(repo: Path, seed: int) -> str:
    env = get_safe_git_env()
    env.update(_GIT_IDENT)
    proc = subprocess.run(
        ["git", "init", "-q", "-b", "main", str(repo)],
        capture_output=True, text=True, timeout=120, check=False,
        env=env)
    if proc.returncode != 0:
        msg = f"git init failed in {repo}: {proc.stderr.strip()}"
        raise CrossfileFixtureError(msg)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m",
         f"{GENERATOR_NAME} fixtures seed={seed}")
    return _git(repo, "rev-parse", "HEAD").strip()


def _provenance(seed: int, case_id: str) -> dict[str, Any]:
    return {"kind": "synthetic", "generator": GENERATOR_NAME,
            "seed": seed, "case": case_id}


def generate_fixtures(
    out_dir: Path, *, seed: int = 1, cases_per_class: int = 2,
    classes: list[str] | None = None,
) -> tuple[dict, list[GeneratedCase], str]:
    """Generate the fixture repo; return (manifest, cases, sha).

    Writes ``out_dir/repo`` (a committed git tree of case packages)
    and returns the recall manifest dict labelling it. Each class
    yields ``cases_per_class`` vulnerable packages plus one sanitized
    twin each.
    """
    picked = sorted(classes) if classes else sorted(SINK_CLASSES)
    unknown = [c for c in picked if c not in SINK_CLASSES]
    if unknown:
        msg = (f"unknown sink class(es) {unknown} "
               f"(choose from {sorted(SINK_CLASSES)})")
        raise CrossfileFixtureError(msg)
    if cases_per_class < 1:
        msg = "cases_per_class must be >= 1"
        raise CrossfileFixtureError(msg)
    repo = out_dir / "repo"
    if repo.exists():
        msg = (f"{repo} already exists — generation is "
               "create-only (delete it or pick a fresh --out-dir)")
        raise CrossfileFixtureError(msg)
    repo.mkdir(parents=True)

    cases: list[GeneratedCase] = []
    for cls in picked:
        sc = SINK_CLASSES[cls]
        for i in range(cases_per_class):
            cases.append(_emit_case(repo, seed, sc, i, sanitized=False))
            cases.append(_emit_case(repo, seed, sc, i, sanitized=True))
    sha = _commit_fixture_repo(repo, seed)

    expected = [
        {
            "id": c.case_id,
            "file": c.sink_file,
            "line_start": c.sink_line,
            "line_end": c.sink_line,
            "cwe": c.cwe,
            "provenance": _provenance(seed, c.case_id),
        }
        for c in cases if not c.sanitized
    ]
    clean = [
        {
            "id": c.case_id,
            "file": c.sink_file,
            "line_start": c.sink_line,
            "line_end": c.sink_line,
            "cwe": c.cwe,
            "provenance": _provenance(seed, c.case_id),
        }
        for c in cases if c.sanitized
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "name": f"crossfile-python-seed{seed}",
        "target": {
            "repo_url": f"generated://{GENERATOR_NAME}/seed/{seed}",
            "pinned_sha": sha,
            "local_path": str(repo),
        },
        "language": "python",
        # Baseline profile; the flip-gate candidate run overrides with
        # `--profile agentic-taint` so the pair differs by the engine
        # flag alone.
        "profile": "agentic",
        "tolerance": {"line_drift": 2, "cwe_family_match": True},
        "expected": expected,
        "clean_regions": clean,
        "notes": {
            "generator": GENERATOR_NAME,
            "seed": seed,
            "doctrine": (
                "Synthetic cross-file fixtures: flows are "
                "generator-authored ground truth (route -> helper -> "
                "sink, each in its own file). They measure cross-file "
                "plumbing, never real-world recall — report them "
                "beside, not instead of, benchmark corpora."),
            "sanitized_twins": _SANITIZER_NOTE,
        },
    }
    return manifest, cases, sha


def emit_channel_labels(
    cases: list[GeneratedCase], *, repo: Path, sha: str, seed: int,
    channel: str, bug_class: str, repo_key: str, labels_dir: Path,
    clean_bug_class: str = "clean", labeled_at: str = "",
) -> list[Path]:
    """Write audit-channel micro-corpus labels for the generated cases.

    One ``.label.json`` per case under
    ``labels_dir/<channel>/<bug_class>/`` (sanitized twins under
    ``<clean_bug_class>``), schema-validated through the audit-corpus
    ``FunctionLabel`` dataclass before writing — the single source of
    truth for label validity, no parallel schema here — with the
    ``channel`` field set and the sink-function span
    content-addressed (``span_sha`` over the generated file, the
    repo-wide ``core.staleness`` convention). Content stays local —
    callers point this at a private store, never at the tree.
    """
    from core.audit.corpus.channels import validate_channel_name
    from core.audit.corpus.label import (
        FunctionLabel,
        SourcePin,
        compute_span_sha,
    )

    validate_channel_name(channel)
    if not labeled_at:
        from datetime import datetime, timezone
        labeled_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    written: list[Path] = []
    for c in cases:
        cls = clean_bug_class if c.sanitized else bug_class
        status = "clean" if c.sanitized else "finding"
        out_dir = labels_dir / channel / cls
        out_dir.mkdir(parents=True, exist_ok=True)
        sink_text = (repo / c.sink_file).read_text(encoding="utf-8")
        rationale = (
            f"Generated cross-file flow ({c.sink_class}): HTTP route "
            f"-> helper -> {c.sink_fn} across three files; "
            + (_SANITIZER_NOTE if c.sanitized else
               "no sanitizer on the path — the sink line is the "
               "labelled defect (kind-separated synthetic "
               f"provenance, generator {GENERATOR_NAME}, seed {seed}).")
        )
        label = FunctionLabel(
            function_id=f"{c.sink_file}:{c.sink_fn}",
            bug_class=cls,
            expected_status=status,
            rationale=rationale,
            source=SourcePin(
                repo=repo_key, sha=sha, file=c.sink_file,
                line_start=c.sink_fn_start, line_end=c.sink_fn_end,
                span_sha=compute_span_sha(
                    sink_text, c.sink_fn_start, c.sink_fn_end),
            ),
            labeler=f"{GENERATOR_NAME} seed={seed}",
            labeled_at=labeled_at,
            cwe=c.cwe,
            expected_mechanism=channel,
            channel=channel,
        )
        out = out_dir / f"{c.case_id}.label.json"
        save_json(out, label.to_dict())
        written.append(out)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="recall-measure crossfile-python",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--out-dir", type=Path, required=True,
                   help="output root: repo/ (committed fixture tree) "
                        "+ manifest.json land here")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--cases-per-class", type=int, default=2)
    p.add_argument("--class", dest="classes", action="append",
                   choices=sorted(SINK_CLASSES), default=[],
                   help="restrict to a sink class (repeatable; "
                        "default: all)")
    p.add_argument("--channel", default=None,
                   help="also emit audit-channel micro-corpus labels "
                        "tagged with this channel token (requires "
                        "--bug-class and --repo-key)")
    p.add_argument("--bug-class", default=None,
                   help="audit-corpus bug class for the vulnerable "
                        "labels (validated against the label schema)")
    p.add_argument("--repo-key", default=None,
                   help="sources.json repo key the labels pin against")
    p.add_argument("--labels-dir", type=Path, default=None,
                   help="channel-label output root (default: "
                        "<out-dir>/channel-labels)")
    args = p.parse_args(argv)

    if args.channel and not (args.bug_class and args.repo_key):
        p.error("--channel requires --bug-class and --repo-key")

    try:
        manifest, cases, sha = generate_fixtures(
            args.out_dir, seed=args.seed,
            cases_per_class=args.cases_per_class,
            classes=args.classes or None)
        label_paths: list[Path] = []
        if args.channel:
            label_paths = emit_channel_labels(
                cases, repo=args.out_dir / "repo", sha=sha,
                seed=args.seed, channel=args.channel,
                bug_class=args.bug_class, repo_key=args.repo_key,
                labels_dir=(args.labels_dir
                            or args.out_dir / "channel-labels"))
    except (OSError, ValueError, CrossfileFixtureError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    manifest_path = args.out_dir / "manifest.json"
    save_json(manifest_path, manifest)
    print(f"fixture repo: {args.out_dir / 'repo'} (pinned {sha[:12]})")
    print(f"manifest: {manifest_path} "
          f"({len(manifest['expected'])} expected, "
          f"{len(manifest['clean_regions'])} clean regions)")
    if label_paths:
        print(f"channel labels: {len(label_paths)} under "
              f"{label_paths[0].parent.parent.parent}")
    return 0
