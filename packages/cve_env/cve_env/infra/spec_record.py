"""Record and rediscover replayable ``EnvironmentSpec``s for builds.

A successful agent build already proved a concrete environment: an
image (or a Dockerfile) that launched and passed its verify plan.
Recording that as a ``core.env`` spec next to the outcome sidecar makes
the next ``build`` of the same CVE replayable — ``provision(spec)``
plus the verify DAG, no agent turns, no spend.

Derivation is deliberately conservative: only the two source kinds
``core.env.provision`` can actually consume are recorded —

* ``image``: the last ``docker_run`` image ref before the passing
  ``verify``, and only when it is NOT a session-local build tag (a
  local tag dies with the image cache, so replaying it would fail on
  the next host or after a prune);
* ``dockerfile``: when that image ref WAS built in-session by a
  ``docker_build`` call carrying explicit ``dockerfile_text``.

Compose stacks and source builds are not recorded (the provisioner has
no consumer-facing path for them yet); a build whose winning method
was one of those simply records nothing — replay then falls through to
a normal (pre-filled) build, which is always correct.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from core.env.spec import EnvironmentSpec, RunSpec, SourceSpec
from core.env.store import RUN_SPEC_FILENAME, save_run_spec


def _id_spec_filename(cve_id: str) -> str:
    """Collision-proof per-id spec filename for shared directories.

    The canonical ``environment-spec.json`` is one-per-directory, so on
    a SHARED audit root (the bin/cve-env facade default) a later
    successful build of a different id silently overwrote the earlier
    spec — its $0 replay was lost. Both CVE- and DESC- ids are
    filename-safe; the substitution is defensive.
    """
    import re as _re

    safe = _re.sub(r"[^A-Za-z0-9._-]", "_", cve_id)
    return f"environment-spec.{safe}.json"

logger = logging.getLogger(__name__)

#: Local tags the in-session build tools assign — never replayable.
_LOCAL_TAG_PREFIXES = ("cve-env-local", "raptor-env-local")


def _portable_plan(plan: list[dict]) -> list[dict]:
    """Strip per-run ephemeral endpoint coordinates from recorded
    verify steps.

    The agent's tcp_probe_check steps carry the ORIGINAL run's
    published host port (an ephemeral docker mapping); a replayed
    environment publishes a fresh one, so a recorded port can never
    match again — the probe fails "connection refused" on every
    replay/up. With the coordinates stripped, the verify engine
    resolves the probe against the CURRENT handle's endpoint (the
    executor's documented fallback). The http checks already resolve
    that way (the executor drops their host fields); tcp is the one
    type with a legitimate per-step override, which this recorder's
    universe never needs — docker_run publishes exactly one port.
    """
    out = []
    for step in plan:
        if step.get("type") == "tcp_probe_check":
            step = {k: v for k, v in step.items()
                    if k not in ("host_port", "host_ip", "host", "port",
                                 "port_target")}
        out.append(step)
    return out


def derive_replay_spec(
    cve_id: str,
    version: str,
    tool_uses: list[dict],
) -> EnvironmentSpec | None:
    """Derive a replayable spec from a SUCCESSFUL build's tool calls.

    ``tool_uses`` is the audited call sequence (``{"name", "input"}``
    dicts, in order). Returns ``None`` when the winning method is not
    replayably recordable — never raises.
    """
    verify_input = None
    for use in reversed(tool_uses):
        if use.get("name") == "verify":
            verify_input = use.get("input") or {}
            break
    if verify_input is None:
        return None
    plan = verify_input.get("plan")
    plan = [c for c in plan if isinstance(c, dict)] if isinstance(
        plan, list) else []
    plan = _portable_plan(plan)

    run_input = None
    for use in reversed(tool_uses):
        if use.get("name") == "docker_run":
            run_input = use.get("input") or {}
            break
    if run_input is None:
        return None  # compose / non-docker_run methods: not recorded
    image = str(run_input.get("image") or "")
    if not image:
        return None
    try:
        port = int(run_input.get("container_port") or 0)
    except (TypeError, ValueError):
        port = 0

    source: SourceSpec | None = None
    if image.split(":", maxsplit=1)[0] in _LOCAL_TAG_PREFIXES or _built_in_session(
            image, tool_uses):
        dockerfile = _dockerfile_for(image, tool_uses)
        if dockerfile:
            source = SourceSpec(kind="dockerfile", dockerfile=dockerfile)
        else:
            logger.debug(
                "spec_record: %s built in-session without recoverable "
                "dockerfile_text — not recording", image)
            return None
    else:
        source = SourceSpec(kind="image", image_ref=image)

    return EnvironmentSpec(
        name=f"{cve_id}-replay",
        source=source,
        version=version or "",
        cve_id=cve_id,
        run=RunSpec(port=port),
        verify_plan=plan,
        markers={"origin": {"tool": "cve-env", "verified": True}},
        notes="recorded from a successful agent build for replay",
    )


def _built_in_session(image: str, tool_uses: list[dict]) -> bool:
    return any(
        use.get("name") == "docker_build"
        and (use.get("input") or {}).get("image_tag") == image
        for use in tool_uses
    )


def _dockerfile_for(image: str, tool_uses: list[dict]) -> str:
    for use in reversed(tool_uses):
        if use.get("name") == "docker_build":
            inp = use.get("input") or {}
            if inp.get("image_tag") == image and inp.get("dockerfile_text"):
                return str(inp["dockerfile_text"])
    return ""


def record_run_spec(
    cve_id: str,
    version: str,
    tool_uses: list[dict],
    out_dir: Path | str | None,
) -> Path | None:
    """Best-effort: derive + persist the replay spec into ``out_dir``.

    Called only on ``status == "success"``; never raises (recording is
    telemetry-adjacent — a failure must not taint the build outcome).
    """
    if not out_dir:
        return None
    try:
        spec = derive_replay_spec(cve_id, version, tool_uses)
        if spec is None:
            return None
        path = save_run_spec(spec, out_dir)
        # Collision-proof twin: the canonical name is latest-wins on
        # shared directories; the per-id copy survives later builds of
        # other ids (the reader prefers it).
        from core.atomic_fs import write_text_atomically

        write_text_atomically(Path(out_dir) / _id_spec_filename(cve_id),
                              spec.to_json() + "\n")
        return path
    except Exception:  # noqa: BLE001 — recording must never break a build
        logger.debug("spec_record: recording failed", exc_info=True)
        return None


def find_replayable_spec(
    cve_id: str,
    out_dir: Path | str | None = None,
    project_dir: Path | str | None = None,
) -> EnvironmentSpec | None:
    """Locate the newest recorded replay spec for ``cve_id``.

    Same three-tier search shape as the /cve-diff pre-fill bridge:
    explicit dir, active-project runs, global out/. A spec qualifies
    only when its ``cve_id`` matches and its origin marker says a
    verified build recorded it (specs are only written on success, the
    marker makes that explicit on disk).
    """
    from core.orchestration.cvediff_bridge import (
        _out_root,
        _resolve_project_dir,
    )

    roots: list[tuple[Path, bool]] = []
    if out_dir:
        roots.append((Path(out_dir), True))
    else:
        proj = _resolve_project_dir(project_dir)
        if proj is not None:
            roots.append((proj, False))
        out_root = _out_root()
        if out_root is not None:
            roots.append((out_root, False))

    best: tuple[int, EnvironmentSpec] | None = None
    for root, direct in roots:
        candidates = [root] if direct else _subdirs(root)
        for d in candidates:
            # per-id file first (immune to latest-wins overwrites on
            # shared dirs), canonical name second (older runs).
            path = d / _id_spec_filename(cve_id)
            spec = _load_matching(path, cve_id)
            if spec is None:
                path = d / RUN_SPEC_FILENAME
                spec = _load_matching(path, cve_id)
            if spec is None:
                continue
            spec.markers.setdefault("origin", {})["source_run"] = str(d)
            mtime = _mtime_ns(path)
            if direct:
                return spec
            if best is None or mtime > best[0]:
                best = (mtime, spec)
    return best[1] if best else None


def _subdirs(root: Path) -> list[Path]:
    try:
        return [d for d in root.iterdir() if d.is_dir()]
    except OSError:
        return []


def _mtime_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _load_matching(path: Path, cve_id: str) -> EnvironmentSpec | None:
    try:
        if not path.is_file():
            return None
        spec = EnvironmentSpec.from_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if spec.cve_id != cve_id:
        return None
    origin = (spec.markers or {}).get("origin")
    if not (isinstance(origin, dict) and origin.get("verified")):
        return None
    return spec
