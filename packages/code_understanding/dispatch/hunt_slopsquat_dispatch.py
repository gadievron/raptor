"""Slopsquat dispatch for /understand --hunt — supply-chain, any language.

Same ``HuntDispatchFn`` shape as ``hunt_dispatch.default_hunt_dispatch`` and
``hunt_cocci_dispatch.cocci_hunt_dispatch`` — ``(model, pattern, repo_path)``
returning a list of variant dicts — so the ``hunt(...)`` substrate treats it
as a drop-in backend, selected via ``--hunt-tool=slopsquat``.

Unlike the LLM and cocci backends this is **model-independent and
network-free**: it reuses the SCA manifest parsers to enumerate third-party
dependencies and runs the pure-heuristic slopsquat detector
(``packages.sca.supply_chain.slopsquat``) over them, flagging names matching
the LLM-hallucination shape (generic suffix on a popular prefix, lookalike-
character substitution, untrusted scope). ``model`` and ``pattern`` are
ignored — the "pattern" is fixed (the slopsquat shape).

This is the comprehension-time use context from issue #583: surfacing
likely-hallucinated imports *while reading LLM-generated code*, before any
``npm install`` / ``pip install``. Registry verification (publish date,
download counts, maintainer) stays in ``/sca``; this dispatch does no network
— it's a fast, offline "this import looks slopsquatted, verify before
installing" flag.

SCA is an optional dependency of /understand; if it isn't importable the
dispatch returns an error variant (substrate convention for ``failed_models``),
the same way cocci does for a missing ``spatch``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

SLOPSQUAT_MODEL_NAME = "sca-slopsquat"


class _SlopsquatModel:
    """Sentinel ``ModelHandle`` for the offline slopsquat backend.

    The ``hunt()`` substrate only reads ``.model_name`` (it's a Protocol);
    this dispatch ignores the handle entirely. Wrapping a sentinel — exactly
    the pattern the ``ModelHandle`` docstring describes for non-LLM consumers
    — lets ``--hunt-tool=slopsquat`` run with **no LLM key configured**,
    which is the whole point: it's an offline, pre-install check.
    """

    model_name = SLOPSQUAT_MODEL_NAME


SLOPSQUAT_MODEL = _SlopsquatModel()


def _finding_to_variant(finding: Any, repo: Path) -> Dict[str, Any]:
    """Map a ``SlopsquatFinding`` to the variant-dict shape the
    ``VariantAdapter`` expects (file/line/function/snippet/confidence/tool).

    A slopsquat finding is dependency-level, not source-line-level, so
    ``file`` is the manifest it was declared in and ``line`` is 0. The
    package name goes in ``function`` (matching how the SCA→finding row
    uses ``function`` for the package), and the heuristic reasons +
    suspected imitated package go in ``snippet``.
    """
    dep = finding.dependency
    file_rel = str(dep.declared_in)
    try:
        p = Path(dep.declared_in)
        if p.is_absolute():
            file_rel = str(p.resolve().relative_to(repo.resolve()))
    except (ValueError, OSError):
        pass  # cross-FS or non-repo manifest — leave as-is

    snippet = f"slopsquat shape (score {finding.score:.2f}): {', '.join(finding.reasons)}"
    if finding.suspected_root:
        snippet += f"; resembles popular package '{finding.suspected_root}'"

    return {
        "file": file_rel,
        "line": 0,
        "function": f"{dep.ecosystem}:{dep.name}",
        "snippet": snippet,
        "confidence": str(finding.confidence.level),
        "tool": "sca-slopsquat",
    }


def slopsquat_hunt_dispatch(
    model: Any,
    pattern: str,
    repo_path: str,
) -> List[Dict[str, Any]]:
    """``HuntDispatchFn`` backed by the SCA slopsquat detector.

    ``model`` and ``pattern`` are accepted for interface parity but
    ignored — the hunt is for a fixed shape (LLM-hallucinated package
    names), not a caller-supplied pattern. Errors are returned as a
    single-element ``[{"error": ...}]`` list (substrate convention).
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return [{"error": f"invalid repo_path: {repo_path!r} is not a directory"}]

    try:
        from packages.sca.discovery import find_manifests
        from packages.sca.parsers import capture_parse_failures, parse_manifest
        from packages.sca.supply_chain.slopsquat import scan_deps
    except ImportError as exc:
        return [{"error": (
            f"SCA package not importable ({exc}); --hunt-tool=slopsquat needs "
            f"packages/sca. Use --hunt-tool=llm for a natural-language hunt."
        )}]

    try:
        manifests = find_manifests(repo)
        deps = []
        with capture_parse_failures():
            for m in manifests:
                # Inline manifests (Dockerfile RUN apt-get ...) aren't
                # registry packages the slopsquat heuristic reasons about.
                if getattr(m, "ecosystem", "") == "Inline":
                    continue
                deps.extend(parse_manifest(m))
        findings = scan_deps(deps)
    except Exception as exc:  # noqa: BLE001 — any SCA-side failure
        logger.warning("slopsquat_hunt: scan failed for %s: %s", repo_path, exc)
        return [{"error": f"slopsquat scan failed: {type(exc).__name__}: {exc}"}]

    return [_finding_to_variant(f, repo) for f in findings]
