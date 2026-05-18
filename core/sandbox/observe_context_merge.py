"""Merge an ObserveProfile into a /understand context-map.json.

The context map (produced by /understand --map) is a static, ground-
truth model of a codebase: entry points, sinks, trust boundaries.
An ObserveProfile (produced by sandbox(observe=True)) is a runtime
record of what a binary touched: paths read / written / stat'd plus
connect targets.

When both exist for the same target, the runtime evidence corroborates
or contradicts the static map:

  * Entry-point file paths that appear in ``paths_read`` are
    runtime-confirmed — the binary really does consume that input.
  * Sink locations whose file paths appear in ``paths_written``
    are runtime-confirmed write targets.
  * ``connect_targets`` reveal external reach that the static map
    may not have surfaced (e.g. the binary phones home to a host
    no source string mentions).

This module performs a non-destructive merge: a new top-level
``runtime_observation`` key is added to the context map carrying
the profile + correlation summary. The original keys are
untouched, so a caller can drop the augmentation without affecting
downstream consumers (Stage 0 attack-surface bridge, /validate).

Used by:

  * ``/understand --probe <binary>`` — calls this directly after
    the static map is produced.
  * ad-hoc operator workflow: run ``raptor-sandbox-observe --json``
    against a binary, then call this module to merge the JSON into
    a previously-generated context-map.json.
"""

from __future__ import annotations

import datetime
from copy import deepcopy
from typing import Iterable, Optional

from .observe_profile import ObserveProfile


# Top-level key under which the runtime observation lands. Pinned by
# tests so a refactor that renames the key surfaces immediately —
# downstream consumers (Stage 0 bridge, /validate) hard-code this.
RUNTIME_OBSERVATION_KEY = "runtime_observation"


def _now_iso() -> str:
    """UTC ISO-8601 timestamp without microseconds — matches the
    timestamp shape elsewhere in /understand outputs."""
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0,
    ).isoformat().replace("+00:00", "Z")


def _matches_path(observed: str, ep_or_sink: dict,
                  target_dir: Optional[str] = None) -> bool:
    """Decide whether an observed absolute path corresponds to an
    entry point or sink record in the context map.

    Two modes:

    * ``target_dir`` set — STRICT. The observed path must lie under
      the target directory (with a "/" boundary), and after stripping
      the prefix it must equal the recorded relative path exactly.
      Right shape for monorepos where many directories contain a
      ``src/utils.py`` — the suffix heuristic below would falsely
      match all of them.
    * ``target_dir`` unset — SUFFIX HEURISTIC. The observed path is
      checked against the recorded relative path with a "/"-anchored
      endswith match. Backward-compat with callers that don't know
      the target root; documented as approximate.

    Both modes are case-sensitive (POSIX semantics) and lexical only
    — no os.path.realpath / no symlink resolution. Callers that need
    canonical paths should normalise BEFORE constructing the profile
    or context map.
    """
    rel = ep_or_sink.get("file") or ep_or_sink.get("location")
    if not rel:
        return False

    if target_dir is not None:
        norm_target = target_dir.rstrip("/")
        # Strict: observed lives under target_dir, prefix-stripped
        # equals rel. Boundary char prevents `/repo-attacker/...`
        # matching when target_dir is `/repo`.
        prefix = norm_target + "/"
        if observed.startswith(prefix):
            stripped = observed[len(prefix):]
            return stripped == rel.lstrip("/")
        # Allow exact equality when caller pre-normalised both sides
        # to the same shape (relative everywhere or absolute everywhere).
        return observed == rel

    # Heuristic mode: equality OR "/"-anchored suffix match. Useful
    # when caller doesn't know the target root, but accepts cross-
    # directory false positives in monorepos.
    if observed == rel:
        return True
    return observed.endswith("/" + rel.lstrip("/"))


def _correlate_entry_points(profile: ObserveProfile,
                            entry_points: Iterable[dict],
                            target_dir: Optional[str] = None) -> list:
    """Return entry-point IDs whose file appears in paths_read.

    Caller passes the context map's ``entry_points`` list and (when
    available) the target directory the static map was built against.
    Each entry is a dict that should carry an ``id`` and a ``file``
    (or ``location`` as a fallback). Entries without an id are
    skipped — we can't surface an unkeyed correlation usefully.
    """
    confirmed = []
    for ep in entry_points or []:
        ep_id = ep.get("id")
        if not ep_id:
            continue
        for observed in profile.paths_read:
            if _matches_path(observed, ep, target_dir=target_dir):
                confirmed.append(ep_id)
                break
    return confirmed


def _correlate_sinks(profile: ObserveProfile,
                     sink_details: Iterable[dict],
                     target_dir: Optional[str] = None) -> list:
    """Return sink IDs whose file appears in paths_written.

    Same shape as _correlate_entry_points but on the write side.
    """
    confirmed = []
    for sink in sink_details or []:
        sink_id = sink.get("id")
        if not sink_id:
            continue
        for observed in profile.paths_written:
            if _matches_path(observed, sink, target_dir=target_dir):
                confirmed.append(sink_id)
                break
    return confirmed


def _format_external_reach(profile: ObserveProfile) -> list:
    """Compact human-readable list of `ip:port (family)` strings.

    Stable formatting so a downstream diff between two probe runs
    shows new endpoints clearly. Order preserved from the profile
    (first-seen order from the tracer log).
    """
    out = []
    for t in profile.connect_targets:
        out.append(f"{t.ip}:{t.port} ({t.family})")
    return out


def merge_observation_into_context_map(
    context_map: dict,
    profile: ObserveProfile,
    *,
    target_dir: Optional[str] = None,
    binary: Optional[str] = None,
    command: Optional[Iterable[str]] = None,
    captured_at: Optional[str] = None,
) -> dict:
    """Return a new context map with runtime observation merged in.

    Non-destructive: the input ``context_map`` is deep-copied so
    callers can keep their original. The augmentation lives under
    a new top-level ``runtime_observation`` key; existing top-level
    keys are not modified.

    Args:
        context_map: dict loaded from a /understand context-map.json.
        profile: ObserveProfile from a sandbox(observe=True) run.
        target_dir: the project root the static context map was built
            against (e.g. ``/abs/repo``). When supplied, path
            correlation is STRICT: an observed absolute path must
            start with ``target_dir`` (with "/" boundary) and the
            stripped suffix must equal the entry-point/sink relative
            path EXACTLY. When None, falls back to a "/"-anchored
            endswith heuristic that's prone to false positives in
            monorepos with same-named files in many directories
            (e.g. ``services/auth/src/utils.py`` and
            ``services/billing/src/utils.py`` both look like
            ``src/utils.py``). Pass when known; meta.target from
            the context map is the canonical source.
        binary: optional path to the probed binary, recorded for
            traceability so a reader knows which binary produced this
            evidence. None = "unknown" recorded literally.
        command: optional list of argv elements for the spawned probe;
            useful for re-running ("we observed claude --version, not
            claude --print 'hello'"). Coerced to a list before storing.
        captured_at: optional ISO-8601 timestamp; default = now (UTC).

    Returns:
        A new context_map dict with a ``runtime_observation`` key.
        Shape of the new key:

            {
              "binary": "<path or None>",
              "command": [...],
              "captured_at": "2026-05-08T12:34:56Z",
              "paths_read": [...],
              "paths_written": [...],
              "paths_stat": [...],
              "connect_targets": [
                {"ip": "...", "port": ..., "family": "..."},
                ...
              ],
              "correlations": {
                "entry_points_runtime_confirmed": ["EP-...", ...],
                "sinks_runtime_confirmed": ["SINK-...", ...],
                "external_reach": ["1.2.3.4:443 (AF_INET)", ...]
              }
            }
    """
    out = deepcopy(context_map) if context_map else {}

    # Default target_dir from context_map.meta.target when caller
    # didn't supply one. /understand --map writes the absolute target
    # path under meta.target — using it here gives strict matching
    # automatically for callers that load context-map.json.
    effective_target_dir = target_dir
    if effective_target_dir is None:
        meta = out.get("meta")
        if isinstance(meta, dict):
            cand = meta.get("target")
            if isinstance(cand, str) and cand:
                effective_target_dir = cand

    correlations = {
        "entry_points_runtime_confirmed": _correlate_entry_points(
            profile, out.get("entry_points") or [],
            target_dir=effective_target_dir,
        ),
        "sinks_runtime_confirmed": _correlate_sinks(
            profile, out.get("sink_details") or [],
            target_dir=effective_target_dir,
        ),
        "external_reach": _format_external_reach(profile),
    }

    out[RUNTIME_OBSERVATION_KEY] = {
        "binary": binary,
        "command": list(command) if command else [],
        "captured_at": captured_at or _now_iso(),
        "paths_read": list(profile.paths_read),
        "paths_written": list(profile.paths_written),
        "paths_stat": list(profile.paths_stat),
        "connect_targets": [
            {"ip": t.ip, "port": t.port, "family": t.family}
            for t in profile.connect_targets
        ],
        "correlations": correlations,
    }

    return out
