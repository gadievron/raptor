"""Recall-manifest generator for the OWASP NodeGoat JS benchmark.

Pin + wrap, not derive: NodeGoat is the JS-channel benchmark (OWASP
project, tagged releases, stable pinned refs), but its ground truth
is prose — tutorial pages and fix commentary in the source — not a
machine-readable per-case table like the OWASP Benchmark CSV or
Juliet's bad/good file structure. ``expected[]`` therefore cannot be
generated mechanically with location+CWE fidelity; populating it is a
LOCAL labeling step. This generator ships the machinery half: it
verifies the pinned clone, validates a locally-authored labels
overlay, and wraps it into a schema-valid recall manifest. Overlay
content stays local, exactly like the audit-corpus ``labels/`` dir —
the tree commits machinery, never label content.

Overlay shape (``--print-overlay-template`` prints a starter)::

    {
      "label_kind": "...",          # optional; carried VERBATIM
      "corpus_kind": "recall",      # optional; "recall" | "fp-only"
      "tolerance": {"line_drift": 5, "cwe_family_match": true},
      "expected": [
        {"id": "...", "file": "app/routes/....js",
         "line_start": 10, "line_end": 20, "cwe": "CWE-943",
         "provenance": {"kind": "benchmark",
                         "suite": "owasp-nodegoat", "case": "..."}}
      ],
      "clean_regions": []
    }

Entries are carried verbatim (unknown keys included). An entry
without ``provenance`` gets the default benchmark provenance
(suite ``owasp-nodegoat``, case = the entry id) — NodeGoat's flaw
catalog is publicly documented by the project, so benchmark
provenance is the honest default; hand labels anchored on a CVE keep
whatever provenance they declare. ``label_kind`` follows the corpus
meta contract: the overlay-level kind is carried verbatim, kind-less
entries inherit it, an entry kind that contradicts it refuses the
wrap, and an absent kind is never defaulted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from core.json import load_json, save_json
from core.recall.manifest import (
    DEFAULT_LINE_DRIFT,
    ManifestError,
    SCHEMA_VERSION,
    parse_manifest,
)
from core.recall.pinned_clone import verify_pinned_clone

NODEGOAT_REPO_URL = "https://github.com/OWASP/NodeGoat"
#: Release tag v1.4 (lightweight tag; this is the commit sha).
NODEGOAT_PINNED_SHA = "9e35cae25f5c6226c30c7d9b03987005affb2888"
NODEGOAT_DEFAULT_CLONE = "out/recall-corpus/nodegoat"
NODEGOAT_SUITE = "owasp-nodegoat"

# One overlay is a small hand-written file.
_MAX_OVERLAY_BYTES = 8 * 1024 * 1024

_ACQUIRE_HINT = (
    f"git clone {NODEGOAT_REPO_URL} <clone-dir> && "
    f"git -C <clone-dir> checkout {NODEGOAT_PINNED_SHA}"
)

_OVERLAY_TEMPLATE: dict[str, Any] = {
    "corpus_kind": "recall",
    "tolerance": {"line_drift": DEFAULT_LINE_DRIFT,
                  "cwe_family_match": True},
    "expected": [
        {
            "id": "example-entry",
            "file": "app/routes/example.js",
            "line_start": None,
            "line_end": None,
            "cwe": "CWE-79",
            "provenance": {"kind": "benchmark",
                           "suite": NODEGOAT_SUITE,
                           "case": "example-entry"},
        },
    ],
    "clean_regions": [],
}


class NodegoatManifestError(RuntimeError):
    pass


def _verify_clone(clone_dir: Path) -> None:
    if not (clone_dir / "server.js").is_file() or not (
            clone_dir / "app").is_dir():
        msg = (
            f"NodeGoat clone not found or incomplete at {clone_dir} — "
            f"acquire with: {_ACQUIRE_HINT}"
        )
        raise NodegoatManifestError(msg)
    verify_pinned_clone(clone_dir, NODEGOAT_PINNED_SHA,
                        error_cls=NodegoatManifestError,
                        hint=_ACQUIRE_HINT)


def _wrap_entries(raw: Any, where: str,
                  meta_kind: Any) -> list[dict[str, Any]]:
    """Copy overlay entries verbatim, applying the label_kind contract.

    Kind-less entries inherit the overlay-level kind; an entry kind
    that contradicts it refuses; nothing is ever defaulted when both
    are absent. Entry provenance defaults to the suite's benchmark
    provenance only when the entry carries none.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        msg = f"overlay {where} must be a list"
        raise NodegoatManifestError(msg)
    out: list[dict[str, Any]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            msg = f"overlay {where}[{i}] must be an object"
            raise NodegoatManifestError(msg)
        entry = dict(entry)  # never mutate the loaded overlay
        entry_kind = entry.get("label_kind")
        if meta_kind is not None:
            if entry_kind is None:
                entry["label_kind"] = meta_kind
            elif entry_kind != meta_kind:
                msg = (
                    f"overlay {where}[{i}] label_kind {entry_kind!r} "
                    f"contradicts the overlay-level label_kind "
                    f"{meta_kind!r} — refusing to re-wrap (kinds are "
                    "carried verbatim, never reconciled)"
                )
                raise NodegoatManifestError(msg)
        if "provenance" not in entry:
            entry["provenance"] = {
                "kind": "benchmark",
                "suite": NODEGOAT_SUITE,
                "case": str(entry.get("id") or ""),
            }
        out.append(entry)
    return out


def generate_manifest(clone_dir: Path, overlay_path: Path) -> dict:
    """Wrap the local labels overlay into a validated manifest dict."""
    _verify_clone(clone_dir)
    try:
        overlay = load_json(overlay_path, strict=True,
                            max_bytes=_MAX_OVERLAY_BYTES)
    except (OSError, ValueError) as exc:
        msg = f"cannot read labels overlay {overlay_path}: {exc}"
        raise NodegoatManifestError(msg) from exc
    if overlay is None:
        msg = f"cannot read labels overlay {overlay_path}: file not found"
        raise NodegoatManifestError(msg)
    if not isinstance(overlay, dict):
        msg = f"labels overlay {overlay_path} must be a JSON object"
        raise NodegoatManifestError(msg)

    meta_kind = overlay.get("label_kind")
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": NODEGOAT_SUITE,
        "target": {
            "repo_url": NODEGOAT_REPO_URL,
            "pinned_sha": NODEGOAT_PINNED_SHA,
            "local_path": str(clone_dir),
        },
        "language": "javascript",
        "profile": "scan-codeql",
        "tolerance": overlay.get(
            "tolerance", {"line_drift": DEFAULT_LINE_DRIFT,
                          "cwe_family_match": True}),
        "expected": _wrap_entries(overlay.get("expected"), "expected",
                                  meta_kind),
        "clean_regions": _wrap_entries(overlay.get("clean_regions"),
                                       "clean_regions", meta_kind),
    }
    if "corpus_kind" in overlay:
        manifest["corpus_kind"] = overlay["corpus_kind"]
    if meta_kind is not None:
        manifest["label_kind"] = meta_kind

    try:
        parse_manifest(manifest)
    except ManifestError as exc:
        msg = f"overlay {overlay_path} does not wrap cleanly: {exc}"
        raise NodegoatManifestError(msg) from exc
    return manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="recall-measure nodegoat-manifest",
        description=__doc__.splitlines()[0],
    )
    p.add_argument("--clone-dir", type=Path,
                   default=Path(NODEGOAT_DEFAULT_CLONE))
    p.add_argument("--out", type=Path, default=None,
                   help="manifest JSON output path")
    p.add_argument("--labels-overlay", type=Path, default=None,
                   help="locally-authored labels overlay JSON "
                        "(expected[] population is a local labeling "
                        "step; overlays are never committed)")
    p.add_argument("--print-overlay-template", action="store_true",
                   help="print a starter overlay JSON and exit")
    args = p.parse_args(argv)

    if args.print_overlay_template:
        print(json.dumps(_OVERLAY_TEMPLATE, indent=2))
        return 0
    if args.labels_overlay is None or args.out is None:
        print(
            "error: --labels-overlay and --out are required — NodeGoat "
            "ground truth is prose, so expected[] population is a "
            "local labeling step (start from "
            "--print-overlay-template)",
            file=sys.stderr)
        return 2

    try:
        manifest = generate_manifest(args.clone_dir, args.labels_overlay)
    except NodegoatManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    save_json(args.out, manifest)
    print(f"manifest: {args.out} "
          f"({len(manifest['expected'])} expected, "
          f"{len(manifest['clean_regions'])} clean regions)")
    return 0
