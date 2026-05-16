"""Per-CVE flow-log writer — shared between `cve-diff run` and `cve-diff bench`.

Promoted from ``cli/bench.py::_write_flow`` so both code paths produce
the same per-tool-call artifacts:

  ``<cve>.flow.jsonl``  one JSON line per tool call (structured)
  ``<cve>.flow.md``     human-readable rendering (uses ``render_flow``)

Best-effort: never raises. The caller's pipeline must complete cleanly
even if the report write fails (out-of-disk, permission, etc.).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from cve_diff.report.markdown import render_flow


def write_outcome_patches(
    output_dir: Path,
    cve_id: str,
    *,
    clone_diff_text: str | None,
    api_diff_text: str | None = None,
    api_method: str | None = None,
    extras: "list[tuple[str, str]] | None" = None,
) -> None:
    """Persist each extraction method's raw diff as a ``.patch`` file.

    On a PASS, the user gets up to four diff bodies side by side:

      ``<cve>.clone.patch``       — git-clone-extracted unified diff
      ``<cve>.<method>.patch``    — one per second-source extractor.
                                    ``<method>`` is e.g. ``github_api``,
                                    ``gitlab_api``, or ``patch_url``.

    Why several files: when the extraction-agreement verdict is
    ``majority_agree`` / ``partial`` / ``disagree``, the user opens
    each and runs `diff` to see exactly which bytes differ. The
    clone diff is also embedded in the ``<cve>.md`` report; the
    second-source diffs were previously dropped on the floor.

    ``api_diff_text`` + ``api_method`` are kept as a backward-compatible
    shorthand for the single-extra case. New callers should use
    ``extras`` to pass any number of ``(method, diff_text)`` tuples.

    Best-effort: never raises. Patch-write failures don't abort
    the pipeline.
    """
    try:
        if clone_diff_text:
            (output_dir / f"{cve_id}.clone.patch").write_text(clone_diff_text)
        # Aggregate the (method, text) pairs to write.
        pairs: list[tuple[str, str]] = []
        if api_diff_text and api_method:
            pairs.append((api_method, api_diff_text))
        if extras:
            pairs.extend(extras)
        # De-dupe by method name (last write wins) so the back-compat
        # shorthand and ``extras`` don't both emit the same file.
        seen: dict[str, str] = {}
        for method, text in pairs:
            if text:
                seen[method] = text
        # Sanitize `method` before interpolating into a filename.
        # `method` comes from per-extractor metadata — for the
        # canonical extractors it's always a clean identifier
        # (`source`, `clone`, `tarball`), but extractors are
        # extension points and a malformed entry could carry
        # path-meaningful characters (`/`, `\`, `..`) that would
        # interpolate into the filename and either:
        #   (a) escape `output_dir` via traversal, writing
        #       attacker-supplied patch content to arbitrary
        #       paths, or
        #   (b) corrupt the filename pattern that downstream
        #       consumers (cve_diff oracle, report aggregators)
        #       rely on for parsing back the method.
        # Whitelist `[A-Za-z0-9_-]` for method; anything else
        # gets sanitised to `_`.
        import re
        _method_re = re.compile(r"[^A-Za-z0-9_-]")
        for method, text in seen.items():
            safe_method = _method_re.sub("_", str(method)) or "unknown"
            (output_dir / f"{cve_id}.{safe_method}.patch").write_text(text)
    except Exception:  # noqa: BLE001 — patch writes are best-effort
        pass


def write_flow_files(
    output_dir: Path,
    cve_id: str,
    *,
    tool_calls_with_args: Iterable[tuple[str, str]],
    ok: bool,
    error_class: str | None,
    stage_signals: dict | None = None,
    stage_status: dict | None = None,
) -> None:
    """Emit ``<cve>.flow.jsonl`` and ``<cve>.flow.md`` from per-tool-call
    telemetry.

    ``tool_calls_with_args`` is the agent loop's per-call log:
    ``[(tool_name, args_repr_first_120_chars), ...]``. Each entry maps
    to one JSON line in the .jsonl. The .md is the human-readable
    rendering via ``render_flow``.

    ``stage_signals`` (optional, PASS only): rich per-stage detail
    (acquire layer / resolve before+after / diff sources / consensus).

    ``stage_status`` (optional, PASS *and* FAIL): per-stage outcome —
    ``{stage_key: {"status": "ok"|"fail", "reason": str}}``. Required
    on FAIL paths so the trace renderer can mark Stages 2-5 with ✗
    or ``(not reached)``. User-stated invariant (2026-05-01):
    all 5 stage headers must always render.
    """
    try:
        # Sanitise cve_id locally before interpolating into the
        # filename. cve_id is validated upstream by the cli/main
        # entry point (`_CVE_ID_RE.fullmatch`), but `write_flow_files`
        # is reachable from other entry points (bench, raw library
        # use) where the validator may not have run. Defending here
        # is cheap (single regex sub) and prevents:
        #
        #   * Path traversal: `cve_id="../../etc/passwd"` →
        #     `output_dir / "../../etc/passwd.flow.jsonl"` would
        #     write the trace outside the output directory.
        #   * Filename corruption: `cve_id="CVE-2024-1234\n"`
        #     ending up in `cve-2024-1234\n.flow.jsonl` confuses
        #     downstream parsers.
        #
        # Match the same `[A-Za-z0-9._-]` whitelist that the
        # cve_id validator enforces; replace anything outside with
        # `_`. Empty / whitespace → "unknown" so downstream
        # consumers still see a parseable filename.
        import re
        _safe_cve = re.sub(r"[^A-Za-z0-9._-]", "_", str(cve_id).strip()) or "unknown"
        if _safe_cve != cve_id:
            # Best-effort log; reachable only when caller bypassed
            # the upstream validator. Keep going with the safe
            # form so the trace still lands.
            import logging
            logging.getLogger(__name__).warning(
                "write_flow_files: cve_id contained unsafe chars, "
                "sanitised %r → %r", cve_id, _safe_cve,
            )
        flow_path = output_dir / f"{_safe_cve}.flow.jsonl"
        md_path = output_dir / f"{_safe_cve}.flow.md"
        lines: list[str] = []
        for i, pair in enumerate(tool_calls_with_args or ()):
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            name, args_repr = pair
            try:
                args = (
                    json.loads(args_repr)
                    if isinstance(args_repr, str) and args_repr.startswith("{")
                    else {"_raw": str(args_repr)[:120]}
                )
                # Defensive: if json.loads returned a non-dict, fall back to _raw.
                if not isinstance(args, dict):
                    args = {"_raw": str(args_repr)[:120]}
            except (ValueError, AttributeError):
                args = {"_raw": str(args_repr)[:120]}
            lines.append(json.dumps({
                "i": i, "tool": name, "args": args,
            }, sort_keys=True))
        flow_path.write_text("\n".join(lines) + ("\n" if lines else ""))
        md_path.write_text(render_flow(
            cve_id, lines, ok=ok, error_class=error_class,
            stage_signals=stage_signals,
            stage_status=stage_status,
        ))
    except Exception:  # noqa: BLE001 — report write must not abort pipeline
        pass
