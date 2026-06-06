"""Project-level threat model artefact.

The threat model is operator-owned context, not scanner output. It gives
RAPTOR a stable view of assets, trust boundaries, threat assumptions,
in-scope bug classes, out-of-scope noise, focus areas, and known bug shapes
before an LLM starts reading target code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Iterable, Optional

from core.json import load_json, save_json
from core.security.log_sanitisation import escape_nonprintable

SCHEMA_VERSION = 2
# Range of schema versions ``from_dict`` will accept. Anything
# outside refuses to load rather than silently coerce; an out-of-
# range version usually means the file is from a future RAPTOR
# release or has been tampered with.
SCHEMA_VERSION_MIN = 1
SCHEMA_VERSION_MAX = SCHEMA_VERSION

JSON_FILENAME = "threat-model.json"
MARKDOWN_FILENAME = "THREAT_MODEL.md"
REPORT_FILENAME = "threat-model-report.md"

# Caps applied at adversarial-input boundaries. The threat model
# is a small operator-authored document; sizes well beyond these
# limits almost always mean a hostile or malformed input is
# trying to make RAPTOR allocate forever or smuggle content
# through a markdown / Mermaid / prompt renderer.
_MAX_LIST_ENTRIES = 256                # any *list* field
_MAX_STRING_BYTES = 4 * 1024           # any list entry / field value
_MAX_NOTES_BYTES = 16 * 1024           # operator-prose notes field
_MAX_EVIDENCE_RAW_BYTES = 32 * 1024    # ``raw`` evidence dict per outcome
_EVIDENCE_RAW_KEY_ALLOWLIST = frozenset({
    # Keys ``link_verified_outcomes`` is allowed to copy from
    # ``data["evidence"]`` into the on-disk threat-model JSON.
    # Everything else is dropped so an attacker who pre-stages a
    # malicious evidence blob in ``run_dir`` can't smuggle
    # arbitrary keys (including envelope-marker shaped keys) into
    # the model.
    "summary", "kind", "tool", "command", "exit_code",
    "stdout_excerpt", "stderr_excerpt",
    "url", "path", "line", "duration_ms",
    "sandbox_outcome", "sanitizer", "rule_id",
})


def _clip_str(value: Any, byte_cap: int = _MAX_STRING_BYTES) -> str:
    """Coerce ``value`` to str, strip control chars, cap length.

    Used at every adversarial-input boundary entering the
    threat model. Strips the C1 control-char range
    (``escape_nonprintable``) and bounds total length. Returns
    empty string on None.

    Coarse pre-truncation BEFORE ``escape_nonprintable`` —
    otherwise a hostile 10 MB input made the escape pass do
    proportional work even though we'd discard most of it
    immediately. ``escape_nonprintable`` can expand chars up to
    ~4x (each control byte → ``\\x..`` text); the pre-clip
    accepts that the tail of the cap may be truncated
    mid-escape sequence on hostile inputs, which is safer than
    an O(N) regex pass over an attacker-controlled blob.
    """
    if value is None:
        return ""
    s = str(value)
    if len(s) > byte_cap:
        s = s[:byte_cap]
    s = escape_nonprintable(s)
    if len(s) > byte_cap:
        s = s[:byte_cap]
    return s


def _safe_for_render(value: Any, byte_cap: int = _MAX_STRING_BYTES) -> str:
    """Sanitise a string for inclusion in a markdown bullet,
    Mermaid label, or operator-facing report.

    Strip structural characters BEFORE running
    ``escape_nonprintable`` — otherwise the C1-control escape
    converts real newlines into ``\x0a`` text and the
    structural-strip becomes a no-op.

    Defends against:
    * markdown injection — newlines that could open a forged
      ``## Heading`` section
    * fenced-block escape — backticks
    * markdown table escape — pipes
    * Mermaid statement break — ``]`` / ``;`` / ``{`` / ``}``
      that would let a label close its own node and forge new
      Mermaid statements
    * HTML / angle-bracket runs
    """
    if value is None:
        return ""
    s = str(value)
    # Structural-character strip FIRST, on the raw string.
    s = s.replace("\r", " ").replace("\n", " ")
    s = s.replace("`", "ʼ").replace("|", "ǀ")
    s = s.replace("<", "‹").replace(">", "›")
    s = s.replace("]", "❳").replace("[", "❲")
    s = s.replace("{", "❴").replace("}", "❵")
    s = s.replace(";", "·")
    # NOW apply C1-control-character escape + length cap.
    s = escape_nonprintable(s)
    if len(s) > byte_cap:
        s = s[:byte_cap]
    return s


def _clip_str_list(values: Any) -> list[str]:
    """Variant of ``_coerce_str_list`` that also caps each entry's
    byte length and the total entry count. Defends against
    hostile JSON inputs claiming ``"focus_areas": [str * 1_000_000]``
    or single entries 100 MB long."""
    raw = _coerce_str_list(values)
    capped = [_clip_str(v) for v in raw[:_MAX_LIST_ENTRIES]]
    return capped


def _resolve_inside(path: Path, project_out: Path) -> Optional[Path]:
    """Return ``path.resolve()`` only if it lives inside
    ``project_out.resolve()``. Defends against attacker-tampered
    ``project.threat_model_path`` pointing at ``/etc/shadow`` or
    elsewhere outside the project's expected output area.

    Returns None when the path resolves outside (caller refuses
    the I/O).
    """
    try:
        resolved = Path(path).resolve()
        project_root = Path(project_out).resolve()
        resolved.relative_to(project_root)
        return resolved
    except (OSError, ValueError):
        return None


@dataclass
class ThreatModel:
    """Canonical project threat model.

    Kept deliberately simple: every list is prose-first so operators can keep
    it useful without fighting a giant schema, while the keys are stable enough
    for prompts, reports, and CI to consume.
    """

    project_name: str
    target: str
    summary: str = ""
    assets: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    trusted_inputs: list[str] = field(default_factory=list)
    untrusted_inputs: list[str] = field(default_factory=list)
    in_scope_vuln_classes: list[str] = field(default_factory=list)
    out_of_scope_vuln_classes: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)
    known_bug_shapes: list[str] = field(default_factory=list)
    verification_expectations: list[str] = field(default_factory=list)
    patch_validation_expectations: list[str] = field(default_factory=list)
    methodology: list[str] = field(default_factory=list)
    domain_packs: list[str] = field(default_factory=list)
    actors: list[dict[str, Any]] = field(default_factory=list)
    trust_zones: list[dict[str, Any]] = field(default_factory=list)
    data_flows: list[dict[str, Any]] = field(default_factory=list)
    threats: list[dict[str, Any]] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    accepted_risks: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    source: str = "operator"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "project_name": self.project_name,
            "target": self.target,
            "summary": self.summary,
            "assets": list(self.assets),
            "entry_points": list(self.entry_points),
            "trust_boundaries": list(self.trust_boundaries),
            "trusted_inputs": list(self.trusted_inputs),
            "untrusted_inputs": list(self.untrusted_inputs),
            "in_scope_vuln_classes": list(self.in_scope_vuln_classes),
            "out_of_scope_vuln_classes": list(self.out_of_scope_vuln_classes),
            "focus_areas": list(self.focus_areas),
            "known_bug_shapes": list(self.known_bug_shapes),
            "verification_expectations": list(self.verification_expectations),
            "patch_validation_expectations": list(self.patch_validation_expectations),
            "methodology": list(self.methodology),
            "domain_packs": list(self.domain_packs),
            "actors": _copy_records(self.actors),
            "trust_zones": _copy_records(self.trust_zones),
            "data_flows": _copy_records(self.data_flows),
            "threats": _copy_records(self.threats),
            "controls": _copy_records(self.controls),
            "assumptions": _copy_records(self.assumptions),
            "evidence": _copy_records(self.evidence),
            "accepted_risks": _copy_records(self.accepted_risks),
            "notes": self.notes,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThreatModel":
        def _list(key: str) -> list[str]:
            # Caps each entry's byte length AND the total entry
            # count. Defends against hostile JSON inputs of
            # arbitrary size — see ``_clip_str_list``.
            return _clip_str_list(data.get(key))

        # Validate schema version range. Pre-fix
        # ``int(data.get("version") or SCHEMA_VERSION)`` raised
        # ``ValueError`` uncaught on ``{"version": "evil"}`` and
        # silently accepted any int regardless of how far ahead /
        # behind it was. Anything outside [MIN, MAX] either came
        # from a future RAPTOR release or is tampered.
        raw_version = data.get("version")
        if raw_version is None:
            version = SCHEMA_VERSION
        else:
            try:
                version = int(raw_version)
            except (TypeError, ValueError):
                raise ValueError(
                    f"threat-model version must be an integer, got "
                    f"{type(raw_version).__name__}"
                )
            if not (
                SCHEMA_VERSION_MIN <= version <= SCHEMA_VERSION_MAX
            ):
                raise ValueError(
                    f"threat-model schema version {version} outside "
                    f"supported range "
                    f"[{SCHEMA_VERSION_MIN}, {SCHEMA_VERSION_MAX}]"
                )

        now = datetime.now(timezone.utc).isoformat()
        return cls(
            version=version,
            project_name=_clip_str(data.get("project_name")),
            target=_clip_str(data.get("target")),
            summary=_clip_str(data.get("summary"), byte_cap=_MAX_NOTES_BYTES),
            assets=_list("assets"),
            entry_points=_list("entry_points"),
            trust_boundaries=_list("trust_boundaries"),
            trusted_inputs=_list("trusted_inputs"),
            untrusted_inputs=_list("untrusted_inputs"),
            in_scope_vuln_classes=_list("in_scope_vuln_classes"),
            out_of_scope_vuln_classes=_list("out_of_scope_vuln_classes"),
            focus_areas=_list("focus_areas"),
            known_bug_shapes=_list("known_bug_shapes"),
            verification_expectations=_list("verification_expectations"),
            patch_validation_expectations=_list("patch_validation_expectations"),
            methodology=_list("methodology"),
            domain_packs=_list("domain_packs"),
            actors=_records("actors", data),
            trust_zones=_records("trust_zones", data),
            data_flows=_records("data_flows", data),
            threats=_records("threats", data),
            controls=_records("controls", data),
            assumptions=_records("assumptions", data),
            evidence=_records("evidence", data),
            accepted_risks=_records("accepted_risks", data),
            notes=_clip_str(data.get("notes"), byte_cap=_MAX_NOTES_BYTES),
            source=_clip_str(data.get("source")) or "operator",
            created_at=_clip_str(data.get("created_at")) or now,
            updated_at=_clip_str(data.get("updated_at")) or now,
        )


def project_threat_model_paths(project: Any) -> tuple[Path, Path]:
    """Return ``(json_path, markdown_path)`` for a project-like object."""
    output = Path(project.output_dir)
    return output / JSON_FILENAME, output / MARKDOWN_FILENAME


def project_threat_model_report_path(project: Any) -> Path:
    """Return the default project threat-model report path."""
    return Path(project.output_dir) / REPORT_FILENAME


def blank_for_project(project: Any) -> ThreatModel:
    """Create an operator-editable starter model for ``project``."""
    return ThreatModel(
        project_name=project.name,
        target=project.target,
        summary=(
            "Document what we are protecting, who can influence inputs, "
            "and which bug classes matter for this target."
        ),
        assets=[
            "Primary application behaviour and data handled by the target",
            "Secrets, credentials, tokens, and deployment configuration",
            "Build, release, and dependency integrity",
        ],
        trusted_inputs=[
            "Explicitly list config, internal services, or authenticated actors that are trusted here",
        ],
        untrusted_inputs=[
            "External requests, files, messages, dependency metadata, and user-controlled payloads",
        ],
        in_scope_vuln_classes=[
            "Injection and command execution",
            "Authentication and authorisation bypass",
            "Unsafe deserialisation and parser confusion",
            "Memory corruption where native code or binaries are in scope",
            "Supply-chain and dependency compromise paths",
        ],
        out_of_scope_vuln_classes=[
            "Issues requiring already-compromised privileged operators unless stated otherwise",
            "Purely theoretical findings with no reachable attacker-controlled path",
        ],
        verification_expectations=[
            "Prefer oracle-backed evidence: sandbox replay, CodeQL proof/refutation, fuzzer crash, or live web confirmation",
            "A finding is not confirmed just because an LLM says it looks plausible",
        ],
        patch_validation_expectations=[
            "Replay the original proof of concept after a patch",
            "Run the relevant test/build path",
            "Run a short re-attack or variant-hunt pass for high-impact fixes",
        ],
        methodology=[
            "Map assets, actors, entry points, data flows, trust boundaries, threats, controls, assumptions, and evidence",
            "Use STRIDE-style prompts for each trust-boundary crossing, then let RAPTOR oracles confirm or refute",
            "Treat the model as a living ledger: confirmed evidence changes threat state, not just the report wording",
        ],
        domain_packs=["web", "api", "sca", "native", "cloud", "ai"],
        actors=[
            {
                "id": "ACT-001",
                "name": "External attacker or untrusted caller",
                "trust": "untrusted",
                "description": "Any actor able to influence external inputs, files, messages, dependencies, or HTTP requests.",
            },
            {
                "id": "ACT-002",
                "name": "Operator or maintainer",
                "trust": "trusted",
                "description": "A legitimate maintainer or deployment operator. Abuse by already-compromised operators is out of scope unless documented.",
            },
        ],
        trust_zones=[
            {
                "id": "TZ-001",
                "name": "Untrusted input",
                "description": "External requests, files, messages, dependency metadata, and user-controlled payloads.",
            },
            {
                "id": "TZ-002",
                "name": "Application trust boundary",
                "description": "Application code, framework middleware, parsers, business logic, and internal service calls.",
            },
            {
                "id": "TZ-003",
                "name": "Sensitive execution or data",
                "description": "Secrets, privileged operations, filesystem, database, shell, native memory, and release pipeline state.",
            },
        ],
        controls=[
            {
                "id": "CTRL-001",
                "name": "Input validation and canonicalisation",
                "type": "preventive",
                "status": "expected",
                "tests": ["Trace untrusted input to parsers and sensitive sinks"],
            },
            {
                "id": "CTRL-002",
                "name": "Authentication and authorisation gates",
                "type": "preventive",
                "status": "expected",
                "tests": ["Verify privileged routes and operations reject unauthorised callers"],
            },
            {
                "id": "CTRL-003",
                "name": "Oracle-backed validation",
                "type": "detective",
                "status": "expected",
                "tests": ["Confirm or refute high-risk findings with sandbox, CodeQL, fuzzing, web, or SCA evidence"],
            },
        ],
        assumptions=[
            {
                "id": "ASM-001",
                "statement": "External inputs should be treated as hostile until a boundary check is proven.",
                "status": "active",
                "evidence_ids": [],
            },
            {
                "id": "ASM-002",
                "statement": "Claims such as admin-only, internal-only, or unreachable need evidence before they lower risk.",
                "status": "active",
                "evidence_ids": [],
            },
        ],
    )


def from_context_map(project: Any, context_map: dict[str, Any]) -> ThreatModel:
    """Build a starter model from an ``/understand`` context-map."""
    model = blank_for_project(project)
    model.source = "context-map"
    model.entry_points = _summaries_from_entries(
        context_map.get("entry_points") or context_map.get("sources") or [],
        default_label="entry",
    )
    model.trust_boundaries = _summaries_from_entries(
        context_map.get("trust_boundaries") or [],
        default_label="boundary",
    )
    sinks = _summaries_from_entries(
        context_map.get("sink_details") or context_map.get("sinks") or [],
        default_label="sink",
    )
    model.domain_packs = _derive_domain_packs(context_map)
    model.focus_areas = derive_focus_areas(model.entry_points, sinks)
    unchecked_flows = _summaries_from_unchecked_flows(
        context_map.get("unchecked_flows") or [],
        context_map.get("entry_points") or [],
        context_map.get("sink_details") or [],
    )
    secrets = _summaries_from_entries(
        context_map.get("hardcoded_secrets") or [],
        default_label="secret",
    )
    model.focus_areas = _dedup(unchecked_flows + model.focus_areas + secrets)
    model.known_bug_shapes.extend(unchecked_flows)
    model.known_bug_shapes.extend(
        f"Hardcoded secret or backdoor credential: {s}" for s in secrets
    )
    if sinks:
        model.known_bug_shapes.extend(
            f"Trace attacker-controlled entry points into sink: {s}"
            for s in sinks[:12]
        )
    model.data_flows = _data_flows_from_context_map(context_map)
    model.threats = _threats_from_context_map(context_map, model.data_flows)
    model.controls = _merge_records(model.controls, _controls_from_context_map(context_map))
    model.evidence = _merge_records(model.evidence, _evidence_from_context_map(context_map))
    model.updated_at = datetime.now(timezone.utc).isoformat()
    return model


def enrich_from_context_map(model: ThreatModel, context_map: dict[str, Any]) -> ThreatModel:
    """Backfill v2 structure from ``context-map.json`` without erasing prose.

    Existing project threat models are operator-owned, so refresh-less runs
    must not overwrite the prose lists or summary. They should still gain the
    structured ledger fields introduced in v2, otherwise old project models
    never get threats, controls, drift/report quality, or evidence linkage.
    """
    model.version = SCHEMA_VERSION
    seed = blank_for_project(type("_ThreatProject", (), {
        "name": model.project_name,
        "target": model.target,
        "output_dir": ".",
    })())
    if not model.domain_packs:
        model.domain_packs = _derive_domain_packs(context_map)
    if not model.methodology:
        model.methodology = seed.methodology

    derived_flows = _data_flows_from_context_map(context_map)
    if derived_flows:
        model.data_flows = _merge_records(model.data_flows, derived_flows)

    derived_threats = _threats_from_context_map(context_map, derived_flows)
    if derived_threats:
        model.threats = _merge_records(model.threats, derived_threats)

    if not model.controls:
        model.controls = seed.controls
    model.controls = _merge_records(model.controls, _controls_from_context_map(context_map))
    model.evidence = _merge_records(model.evidence, _evidence_from_context_map(context_map))

    if not model.actors:
        model.actors = seed.actors
    if not model.trust_zones:
        model.trust_zones = seed.trust_zones
    if not model.assumptions:
        model.assumptions = seed.assumptions

    model.updated_at = datetime.now(timezone.utc).isoformat()
    return model


def derive_focus_areas(entry_points: Iterable[str], sinks: Iterable[str]) -> list[str]:
    """Return stable focus areas from mapped entries/sinks."""
    out: list[str] = []
    for value in list(entry_points)[:8]:
        out.append(f"Entry point: {value}")
    for value in list(sinks)[:8]:
        out.append(f"Sensitive sink: {value}")
    return _dedup(out)


def load_model(path: Path) -> Optional[ThreatModel]:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    return ThreatModel.from_dict(data)


def save_model(
    model: ThreatModel,
    json_path: Path,
    markdown_path: Path,
    *,
    expected_mtime: Optional[float] = None,
) -> None:
    """Persist the model to disk. When ``expected_mtime`` is
    provided, refuses to write if the on-disk file's mtime has
    changed — defends against the lost-update race where two
    concurrent /agentic runs (or /agentic + ``threat-model lint``)
    each load, mutate, and save without coordinating.

    Callers that loaded the model should capture
    ``json_path.stat().st_mtime`` at load time and pass it in.
    Callers writing a brand-new model leave ``expected_mtime``
    None (the no-op path).
    """
    if expected_mtime is not None and json_path.exists():
        try:
            actual_mtime = json_path.stat().st_mtime
        except OSError:
            actual_mtime = expected_mtime
        if actual_mtime != expected_mtime:
            raise RuntimeError(
                f"threat model at {json_path} was modified by another "
                f"writer (expected mtime {expected_mtime}, found "
                f"{actual_mtime}); refusing to overwrite. Reload and "
                f"retry."
            )
    model.updated_at = datetime.now(timezone.utc).isoformat()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(json_path, model.to_dict())
    markdown_path.write_text(render_markdown(model), encoding="utf-8")


def save_report(
    model: ThreatModel,
    report_path: Path,
    *,
    lint: Optional[list[dict[str, Any]]] = None,
    drift: Optional[dict[str, Any]] = None,
) -> None:
    """Write the richer operator report for a model."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        render_report(model, lint=lint, drift=drift),
        encoding="utf-8",
    )


def render_markdown(model: ThreatModel) -> str:
    """Render an operator-editable ``THREAT_MODEL.md``."""
    sections = [
        "# Threat Model",
        "",
        f"Project: {model.project_name}",
        f"Target: {model.target}",
        f"Source: {model.source}",
        f"Updated: {model.updated_at}",
        "",
        "## Summary",
        "",
        model.summary or "TBC.",
        "",
        _render_list("Assets", model.assets),
        _render_list("Entry Points", model.entry_points),
        _render_list("Trust Boundaries", model.trust_boundaries),
        _render_list("Trusted Inputs", model.trusted_inputs),
        _render_list("Untrusted Inputs", model.untrusted_inputs),
        _render_list("In Scope Vulnerability Classes", model.in_scope_vuln_classes),
        _render_list("Out Of Scope Vulnerability Classes", model.out_of_scope_vuln_classes),
        _render_list("Focus Areas", model.focus_areas),
        _render_list("Known Bug Shapes", model.known_bug_shapes),
        _render_list("Verification Expectations", model.verification_expectations),
        _render_list("Patch Validation Expectations", model.patch_validation_expectations),
        _render_list("Methodology", model.methodology),
        _render_list("Domain Packs", model.domain_packs),
        _render_records("Actors", model.actors, ("id", "name", "trust", "description")),
        _render_records("Trust Zones", model.trust_zones, ("id", "name", "description")),
        _render_records("Data Flows", model.data_flows, ("id", "source", "sink", "boundary", "risk")),
        _render_records("Threats", model.threats, ("id", "title", "status", "severity", "risk_score", "validation")),
        _render_records("Controls", model.controls, ("id", "name", "type", "status")),
        _render_records("Assumptions", model.assumptions, ("id", "statement", "status", "owner", "expires")),
        _render_records("Evidence", model.evidence, ("id", "oracle", "status", "summary", "reproducible")),
        _render_records("Accepted Risks", model.accepted_risks, ("id", "threat_id", "owner", "accepted_until", "reason")),
    ]
    if model.notes.strip():
        sections.extend(["## Notes", "", model.notes.strip(), ""])
    return "\n".join(sections).rstrip() + "\n"


def render_report(
    model: ThreatModel,
    *,
    lint: Optional[list[dict[str, Any]]] = None,
    drift: Optional[dict[str, Any]] = None,
) -> str:
    """Render a higher-signal threat-model report for assessment output."""
    lint = lint if lint is not None else lint_model(model)
    top_threats = sorted(
        model.threats,
        key=lambda t: int(t.get("risk_score") or 0),
        reverse=True,
    )[:10]
    lines = []
    logo = _read_raptor_logo()
    if logo:
        lines.extend(["```", logo, "```", ""])
    lines.extend([
        "# Threat Model Report",
        "",
        f"Project: {model.project_name}",
        f"Target: {model.target}",
        f"Updated: {model.updated_at}",
        "",
        "## Executive View",
        "",
        f"- Assets: {len(model.assets)}",
        f"- Entry points: {len(model.entry_points)}",
        f"- Trust boundaries: {len(model.trust_boundaries) + len(model.trust_zones)}",
        f"- Data flows: {len(model.data_flows)}",
        f"- Threats: {len(model.threats)}",
        f"- Controls: {len(model.controls)}",
        f"- Evidence records: {len(model.evidence)}",
        f"- Open quality issues: {len([i for i in lint if i.get('severity') in ('error', 'warning')])}",
        "",
        "## Top Threats",
        "",
    ])
    if top_threats:
        for threat in top_threats:
            lines.append(
                "- {id} [{status}] risk={risk} severity={severity}: {title}".format(
                    id=threat.get("id", "?"),
                    status=threat.get("status", "needs_evidence"),
                    risk=threat.get("risk_score", 0),
                    severity=threat.get("severity", "unknown"),
                    title=threat.get("title", "Untitled threat"),
                )
            )
    else:
        lines.append("- No threats recorded yet.")
    lines.extend(["", "## Evidence Loop", ""])
    if model.evidence:
        for ev in model.evidence[:20]:
            lines.append(
                "- {id} [{oracle}/{status}] {summary}".format(
                    id=ev.get("id", "?"),
                    oracle=ev.get("oracle", "?"),
                    status=ev.get("status", "?"),
                    summary=ev.get("summary", "no summary"),
                )
            )
    else:
        lines.append("- No oracle evidence linked yet.")
    lines.extend(["", "## Quality Gates", ""])
    if lint:
        for issue in lint:
            lines.append(
                "- {severity}: {message}".format(
                    severity=str(issue.get("severity", "info")).title(),
                    message=issue.get("message", ""),
                )
            )
    else:
        lines.append("- No quality issues found.")
    if drift:
        lines.extend(["", "## Drift", ""])
        for key in ("new_entry_points", "missing_entry_points", "new_trust_boundaries",
                    "missing_trust_boundaries", "new_unchecked_flows"):
            values = drift.get(key) or []
            lines.append(f"- {key}: {len(values)}")
            for value in values[:8]:
                lines.append(f"  - {value}")
    lines.extend(["", "## Mermaid", "", "```mermaid", "flowchart LR"])
    for flow in model.data_flows[:25]:
        src = _mermaid_id(str(flow.get("source") or flow.get("id") or "source"))
        sink = _mermaid_id(str(flow.get("sink") or "sink"))
        label = str(flow.get("id") or "")
        lines.append(f'  {src}["{_mermaid_label(flow.get("source") or "Source")}"] -->|"{_mermaid_label(label)}"| {sink}["{_mermaid_label(flow.get("sink") or "Sink")}"]')
    if not model.data_flows:
        lines.append('  A["No data flows recorded"]')
    lines.extend(["```", ""])
    return "\n".join(lines)


def prompt_context(model: ThreatModel, *, max_items: int = 8) -> str:
    """Compact trusted context block for LLM prompts."""
    lines = [
        "Project threat model context:",
        f"- Summary: {escape_nonprintable(model.summary or 'not documented')}",
    ]
    for label, values in (
        ("Assets", model.assets),
        ("Trusted inputs", model.trusted_inputs),
        ("Untrusted inputs", model.untrusted_inputs),
        ("In-scope vuln classes", model.in_scope_vuln_classes),
        ("Out-of-scope vuln classes", model.out_of_scope_vuln_classes),
        ("Focus areas", model.focus_areas),
        ("Known bug shapes", model.known_bug_shapes),
        ("Verification expectations", model.verification_expectations),
        ("Patch validation expectations", model.patch_validation_expectations),
        ("Methodology", model.methodology),
        ("Domain packs", model.domain_packs),
    ):
        if values:
            lines.append(f"- {label}: {escape_nonprintable('; '.join(values[:max_items]))}")
    if model.threats:
        rendered = []
        for threat in model.threats[:max_items]:
            rendered.append(
                "{id} {status} risk={risk}: {title}".format(
                    id=threat.get("id", "?"),
                    status=threat.get("status", "needs_evidence"),
                    risk=threat.get("risk_score", 0),
                    title=threat.get("title", "Untitled threat"),
                )
            )
        lines.append(f"- Threat ledger: {escape_nonprintable('; '.join(rendered))}")
    if model.controls:
        rendered = [
            f"{c.get('id', '?')} {c.get('status', 'unknown')}: {c.get('name', 'control')}"
            for c in model.controls[:max_items]
        ]
        lines.append(f"- Control expectations: {escape_nonprintable('; '.join(rendered))}")
    return "\n".join(lines)


def lint_model(model: ThreatModel) -> list[dict[str, Any]]:
    """Return quality-gate issues for a model."""
    issues: list[dict[str, Any]] = []
    if not model.assets:
        _issue(issues, "error", "assets", "No assets documented.")
    if not model.untrusted_inputs and not any(a.get("trust") == "untrusted" for a in model.actors):
        _issue(issues, "warning", "untrusted_inputs", "No untrusted inputs or untrusted actors documented.")
    if not model.entry_points and not model.data_flows:
        _issue(issues, "error", "entry_points", "No entry points or data flows recorded.")
    if not model.trust_boundaries and not model.trust_zones:
        _issue(issues, "warning", "trust_boundaries", "No trust boundaries or trust zones recorded.")
    if not model.threats:
        _issue(issues, "error", "threats", "No native threat records exist yet.")
    if not model.controls:
        _issue(issues, "warning", "controls", "No controls mapped to threats.")

    control_ids = {str(c.get("id")) for c in model.controls if c.get("id")}
    evidence_ids = {str(e.get("id")) for e in model.evidence if e.get("id")}
    accepted_by_threat = {
        str(r.get("threat_id")): r for r in model.accepted_risks if r.get("threat_id")
    }
    for threat in model.threats:
        tid = str(threat.get("id") or "?")
        score = int(threat.get("risk_score") or 0)
        status = str(threat.get("status") or "needs_evidence")
        controls = [str(c) for c in threat.get("control_ids") or []]
        evidence = [str(e) for e in threat.get("evidence_ids") or []]
        if score >= 70 and not threat.get("validation"):
            _issue(issues, "error", f"threats.{tid}", f"High-risk threat {tid} has no validation plan.")
        if score >= 60 and not any(c in control_ids for c in controls):
            _issue(issues, "warning", f"threats.{tid}", f"Threat {tid} is not linked to any known control.")
        if status in {"confirmed", "mitigated", "refuted"} and not any(e in evidence_ids for e in evidence):
            _issue(issues, "warning", f"threats.{tid}", f"Threat {tid} has status {status} without linked evidence.")
        if status == "accepted":
            risk = accepted_by_threat.get(tid)
            if not risk:
                _issue(issues, "error", f"threats.{tid}", f"Threat {tid} is accepted but has no accepted-risk record.")
    for risk in model.accepted_risks:
        rid = str(risk.get("id") or "?")
        if not risk.get("owner"):
            _issue(issues, "error", f"accepted_risks.{rid}", f"Accepted risk {rid} has no owner.")
        if not risk.get("accepted_until"):
            _issue(issues, "warning", f"accepted_risks.{rid}", f"Accepted risk {rid} has no review date.")
    for assumption in model.assumptions:
        aid = str(assumption.get("id") or "?")
        status = str(assumption.get("status") or "active")
        if status == "active" and not assumption.get("evidence_ids"):
            _issue(issues, "info", f"assumptions.{aid}", f"Assumption {aid} has no evidence yet.")
    return issues


def diff_context_map(model: ThreatModel, context_map: dict[str, Any]) -> dict[str, Any]:
    """Compare a model with a fresh ``context-map.json``."""
    fresh_entries = set(_summaries_from_entries(
        context_map.get("entry_points") or context_map.get("sources") or [],
        default_label="entry",
    ))
    fresh_boundaries = set(_summaries_from_entries(
        context_map.get("trust_boundaries") or [],
        default_label="boundary",
    ))
    fresh_flows = set(_summaries_from_unchecked_flows(
        context_map.get("unchecked_flows") or [],
        context_map.get("entry_points") or [],
        context_map.get("sink_details") or [],
    ))
    model_entries = set(model.entry_points)
    model_boundaries = set(model.trust_boundaries)
    model_flows = set(model.known_bug_shapes)
    return {
        "new_entry_points": sorted(fresh_entries - model_entries),
        "missing_entry_points": sorted(model_entries - fresh_entries),
        "new_trust_boundaries": sorted(fresh_boundaries - model_boundaries),
        "missing_trust_boundaries": sorted(model_boundaries - fresh_boundaries),
        "new_unchecked_flows": sorted(fresh_flows - model_flows),
        "is_drifted": bool(
            (fresh_entries - model_entries)
            or (fresh_boundaries - model_boundaries)
            or (fresh_flows - model_flows)
        ),
    }


def _sanitise_raw_evidence(value: Any) -> dict[str, Any]:
    """Bound + key-allowlist the ``raw`` evidence dict that gets
    written into the on-disk threat-model JSON.

    ``link_verified_outcomes`` reads outcome dicts produced by
    ``collect_outcomes(run_dir)``. Pre-fix the entire
    ``data["evidence"]`` dict was pasted verbatim — with no key
    allowlist and no size cap. An attacker who can pre-stage an
    outcome record (e.g. by writing a doctored file under a
    run dir before /agentic processes it) could smuggle arbitrary
    key/value pairs into the model and from there into every
    subsequent ``render_markdown`` / ``render_report`` / ``--json``
    consumer.

    Keep only keys in ``_EVIDENCE_RAW_KEY_ALLOWLIST``; cap each
    string value at ``_MAX_STRING_BYTES`` and the total dict at
    ``_MAX_EVIDENCE_RAW_BYTES``.
    """
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    running = 0
    for k, v in value.items():
        key = str(k)
        if key not in _EVIDENCE_RAW_KEY_ALLOWLIST:
            continue
        if isinstance(v, (int, float, bool)) or v is None:
            sanitised: Any = v
        else:
            sanitised = _clip_str(v)
        running += len(key) + len(str(sanitised))
        if running > _MAX_EVIDENCE_RAW_BYTES:
            # Hit the cap — surface the truncation explicitly so
            # operators reading the model see something happened.
            out["_truncated"] = True
            break
        out[key] = sanitised
    return out


def link_verified_outcomes(model: ThreatModel, outcomes: Iterable[Any]) -> ThreatModel:
    """Attach oracle outcomes to the threat ledger in-place."""
    for outcome in outcomes:
        data = outcome.to_dict() if hasattr(outcome, "to_dict") else dict(outcome)
        evidence_id = _stable_id("EVD", [
            data.get("oracle"),
            data.get("status"),
            data.get("finding_id"),
            data.get("timestamp"),
        ])
        ev = {
            "id": evidence_id,
            "oracle": data.get("oracle"),
            "status": data.get("status"),
            "finding_id": data.get("finding_id"),
            "cwe_id": data.get("cwe_id"),
            "file": data.get("file"),
            "reproducible": bool(data.get("reproducible")),
            "summary": _outcome_summary(data),
            "raw": _sanitise_raw_evidence(data.get("evidence")),
        }
        model.evidence = _merge_records(model.evidence, [ev])
        for threat in model.threats:
            if _outcome_matches_threat(data, threat):
                evidence_ids = set(str(e) for e in threat.get("evidence_ids") or [])
                evidence_ids.add(evidence_id)
                threat["evidence_ids"] = sorted(evidence_ids)
                if data.get("status") == "verified":
                    threat["status"] = "confirmed"
                elif data.get("status") == "refuted":
                    threat["status"] = "refuted"
    model.updated_at = datetime.now(timezone.utc).isoformat()
    return model


def load_for_target(target: Path) -> Optional[ThreatModel]:
    """Find the project-owned threat model for ``target`` if one exists."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        project = mgr.find_project_for_target(str(target))
        if project is None:
            active = mgr.get_active()
            candidate = mgr.load(active) if active else None
            if candidate and _same_path(candidate.target, target):
                project = candidate
        if project is None:
            return None
        json_path = _project_threat_model_json_path(project)
        if json_path is None:
            return None
        return load_model(json_path)
    except Exception:
        return None


def _project_threat_model_json_path(project: Any) -> Optional[Path]:
    """Resolve the threat-model JSON path for ``project`` with
    containment defence.

    ``project.threat_model_path`` is operator/tamper-influenceable
    (it's read from ``~/.raptor/projects/<name>.json``). If an
    attacker writes ``threat_model_path = "/etc/shadow"`` into
    that file, every reader / writer of the threat model would
    otherwise touch that arbitrary path.

    Containment rule: the resolved path MUST live inside
    ``project.output_dir``. Anything outside is refused (returns
    None; caller treats as "no threat model").
    """
    output_dir = Path(getattr(project, "output_dir", "") or "")
    if not str(output_dir):
        return None
    configured = getattr(project, "threat_model_path", "")
    if configured:
        candidate = Path(configured)
        # Reject absolute paths from the JSON outright; only
        # relative paths to be resolved against output_dir are
        # legitimate.
        if candidate.is_absolute():
            resolved = _resolve_inside(candidate, output_dir)
        else:
            resolved = _resolve_inside(output_dir / candidate, output_dir)
        if resolved is None:
            # Attacker-tampered path; refuse rather than fall
            # back silently.
            return None
        return resolved
    return _resolve_inside(
        project_threat_model_paths(project)[0], output_dir,
    )


def _render_list(title: str, values: list[str]) -> str:
    # Escape per-bullet via ``_safe_for_render`` — strips newlines
    # (otherwise a hostile entry could open a forged ``## Heading``
    # section in the operator's markdown), neutralises backticks
    # (fenced-block escape) and pipes (table-row escape). Defends
    # against markdown injection through any field that ingests
    # target-derived prose (focus_areas, known_bug_shapes,
    # entry_points names from the context-map, etc.).
    lines = [f"## {title}", ""]
    if values:
        lines.extend(f"- {_safe_for_render(v)}" for v in values)
    else:
        lines.append("- TBC")
    lines.append("")
    return "\n".join(lines)


def _render_records(title: str, records: list[dict[str, Any]], keys: tuple[str, ...]) -> str:
    lines = [f"## {title}", ""]
    if not records:
        lines.append("- TBC")
        lines.append("")
        return "\n".join(lines)
    for record in records:
        parts = []
        for key in keys:
            value = record.get(key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            parts.append(f"{key}={value}")
        lines.append(f"- {'; '.join(parts) if parts else record}")
    lines.append("")
    return "\n".join(lines)


def _issue(issues: list[dict[str, Any]], severity: str, field: str, message: str) -> None:
    issues.append({"severity": severity, "field": field, "message": message})


def _derive_domain_packs(context_map: dict[str, Any]) -> list[str]:
    text = " ".join(
        str(v).lower()
        for v in (
            context_map.get("frameworks"),
            context_map.get("languages"),
            context_map.get("entry_points"),
            context_map.get("sink_details"),
            context_map.get("sinks"),
        )
    )
    packs = ["web", "api", "sca"]
    if any(token in text for token in ("malloc", "strcpy", "memcpy", "buffer", "asan", "native")):
        packs.append("native")
    if any(token in text for token in ("iam", "s3", "lambda", "gcp", "azure", "aws", "cloud")):
        packs.append("cloud")
    if any(token in text for token in ("prompt", "llm", "model", "embedding", "agent")):
        packs.append("ai")
    return _dedup(packs)


def _data_flows_from_context_map(context_map: dict[str, Any]) -> list[dict[str, Any]]:
    entries = context_map.get("entry_points") or []
    sinks = context_map.get("sink_details") or context_map.get("sinks") or []
    entries_by_id = _records_by_id(entries)
    sinks_by_id = _records_by_id(sinks)
    out: list[dict[str, Any]] = []
    for i, flow in enumerate(context_map.get("unchecked_flows") or []):
        if not isinstance(flow, dict):
            continue
        entry_id = str(flow.get("entry_point") or "")
        sink_id = str(flow.get("sink") or "")
        entry = entries_by_id.get(entry_id, {})
        sink = sinks_by_id.get(sink_id, {})
        out.append({
            "id": str(flow.get("id") or f"DF-{i + 1:03d}"),
            "source": _entry_title(entry, entry_id),
            "sink": _sink_title(sink, sink_id),
            "entry_point_id": entry_id,
            "sink_id": sink_id,
            "boundary": flow.get("missing_boundary") or flow.get("boundary") or "No checked boundary recorded",
            "risk": flow.get("severity") or "medium",
            "attacker_controlled": True,
            "source_location": _location(entry),
            "sink_location": _location(sink),
        })
    return out


def _threats_from_context_map(
    context_map: dict[str, Any],
    data_flows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    threats: list[dict[str, Any]] = []
    for i, flow in enumerate(data_flows):
        severity = _normalise_severity(flow.get("risk"))
        score = _risk_score(severity, has_trust_boundary=True)
        category = _category_from_sink(str(flow.get("sink") or ""))
        threats.append({
            "id": f"T-{i + 1:03d}",
            "title": f"Unchecked flow from {flow.get('source')} to {flow.get('sink')}",
            "category": category,
            "stride": _stride_for_category(category),
            "status": "needs_evidence",
            "severity": severity,
            "risk_score": score,
            "data_flow_ids": [flow.get("id")],
            "entry_point_id": flow.get("entry_point_id"),
            "sink_id": flow.get("sink_id"),
            "control_ids": _controls_for_category(category),
            "evidence_ids": [],
            "validation": "Trace the flow and confirm/refute with the strongest available oracle: web probe, sandbox replay, CodeQL path proof, SCA reachability, or fuzz witness.",
            "source": "context-map.unchecked_flows",
        })
    offset = len(threats)
    for j, secret in enumerate(context_map.get("hardcoded_secrets") or []):
        if not isinstance(secret, dict):
            continue
        threats.append({
            "id": f"T-{offset + j + 1:03d}",
            "title": f"Hardcoded secret or backdoor credential: {_entry_title(secret, 'secret')}",
            "category": "secret_exposure",
            "stride": ["information_disclosure", "elevation_of_privilege"],
            "status": "needs_evidence",
            "severity": "high",
            "risk_score": 75,
            "data_flow_ids": [],
            "entry_point_id": None,
            "sink_id": None,
            "control_ids": ["CTRL-003"],
            "evidence_ids": [],
            "validation": "Confirm whether the secret is live, reachable, and exposed to an attacker-controlled path; avoid printing sensitive values.",
            "source": "context-map.hardcoded_secrets",
        })
    return threats


def _controls_from_context_map(context_map: dict[str, Any]) -> list[dict[str, Any]]:
    controls = []
    if context_map.get("trust_boundaries"):
        controls.append({
            "id": "CTRL-004",
            "name": "Trust-boundary enforcement",
            "type": "preventive",
            "status": "expected",
            "tests": ["For each boundary, prove the required auth, parser, validation, or privilege check executes before sensitive sinks"],
        })
    if context_map.get("hardcoded_secrets"):
        controls.append({
            "id": "CTRL-005",
            "name": "Secret hygiene",
            "type": "preventive",
            "status": "expected",
            "tests": ["Check secrets are not hardcoded, committed, logged, or returned by diagnostic endpoints"],
        })
    return controls


def _evidence_from_context_map(context_map: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = []
    if context_map.get("unchecked_flows"):
        evidence.append({
            "id": "EVD-CONTEXT-001",
            "oracle": "understand",
            "status": "candidate",
            "reproducible": False,
            "summary": f"/understand mapped {len(context_map.get('unchecked_flows') or [])} unchecked flow candidates.",
        })
    return evidence


def _summaries_from_entries(entries: Any, *, default_label: str) -> list[str]:
    out: list[str] = []
    if not isinstance(entries, list):
        return out
    for i, entry in enumerate(entries):
        if isinstance(entry, str):
            out.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        name = (
            entry.get("name")
            or entry.get("id")
            or entry.get("entry")
            or entry.get("boundary")
            or entry.get("operation")
            or f"{default_label}-{i}"
        )
        location = entry.get("file") or entry.get("path") or entry.get("location")
        line = entry.get("line")
        trust = entry.get("trust") or entry.get("trust_level")
        summary = str(name)
        if location:
            summary += f" ({location})"
            if line and ":" not in str(location):
                summary += f":{line}"
        if trust:
            summary += f" - {trust}"
        out.append(summary)
    return _dedup(out)


def _summaries_from_unchecked_flows(
    flows: Any,
    entries: Any,
    sinks: Any,
) -> list[str]:
    if not isinstance(flows, list):
        return []
    entries_by_id = {
        str(e.get("id")): e for e in entries
        if isinstance(e, dict) and e.get("id")
    } if isinstance(entries, list) else {}
    sinks_by_id = {
        str(s.get("id")): s for s in sinks
        if isinstance(s, dict) and s.get("id")
    } if isinstance(sinks, list) else {}

    out: list[str] = []
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        entry_id = str(flow.get("entry_point") or "")
        sink_id = str(flow.get("sink") or "")
        entry = entries_by_id.get(entry_id, {})
        sink = sinks_by_id.get(sink_id, {})
        entry_label = entry_id
        if entry:
            method = entry.get("method")
            route = entry.get("path")
            if method and route:
                entry_label = f"{entry_id} {method} {route}"
        sink_label = sink_id
        if sink:
            loc = sink.get("file") or "?"
            line = sink.get("line")
            sink_type = sink.get("type") or "sink"
            sink_label = f"{sink_id} {sink_type} at {loc}{':' + str(line) if line else ''}"
        issue = flow.get("missing_boundary") or flow.get("notes") or "unchecked flow"
        severity = flow.get("severity")
        label = f"{entry_label} -> {sink_label}: {issue}"
        if severity:
            label += f" ({severity})"
        out.append(label)
    return _dedup(out)


def _same_path(left: str, right: Path) -> bool:
    try:
        return Path(left).expanduser().resolve() == right.expanduser().resolve()
    except Exception:
        return str(left) == str(right)


def _dedup(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _coerce_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if isinstance(v, (str, int, float)) and str(v).strip()]


def _copy_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(r) for r in records if isinstance(r, dict)]


def _records(key: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    value = data.get(key)
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            out.append(dict(item))
        elif isinstance(item, str) and item.strip():
            out.append({"id": _stable_id(key.upper(), [item]), "name": item})
    return out


def _records_by_id(records: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        return {}
    return {
        str(r.get("id")): r
        for r in records
        if isinstance(r, dict) and r.get("id")
    }


def _merge_records(
    left: Iterable[dict[str, Any]],
    right: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in list(left) + list(right):
        if not isinstance(record, dict):
            continue
        key = str(record.get("id") or record.get("name") or record)
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(record))
    return out


def _entry_title(entry: dict[str, Any], fallback: str) -> str:
    if not entry:
        return fallback or "unknown entry"
    method = entry.get("method")
    route = entry.get("path")
    if method and route:
        return f"{method} {route}"
    return str(
        entry.get("name")
        or entry.get("operation")
        or entry.get("id")
        or fallback
        or "unknown entry"
    )


def _sink_title(sink: dict[str, Any], fallback: str) -> str:
    if not sink:
        return fallback or "unknown sink"
    sink_type = sink.get("type") or sink.get("name") or sink.get("id") or fallback
    loc = _location(sink)
    return f"{sink_type} at {loc}" if loc else str(sink_type)


def _location(record: dict[str, Any]) -> str:
    file = record.get("file") or record.get("path") or record.get("location")
    if not file:
        return ""
    line = record.get("line")
    return f"{file}:{line}" if line and ":" not in str(file) else str(file)


def _normalise_severity(value: Any) -> str:
    severity = str(value or "medium").lower()
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    if severity in {"error", "fatal"}:
        return "high"
    if severity in {"warning", "warn"}:
        return "medium"
    return "medium"


def _risk_score(severity: str, *, has_trust_boundary: bool) -> int:
    base = {
        "critical": 90,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }.get(_normalise_severity(severity), 50)
    return min(100, base + (5 if has_trust_boundary else 0))


def _category_from_sink(sink: str) -> str:
    s = sink.lower()
    if any(x in s for x in ("shell", "command", "subprocess", "exec", "system")):
        return "command_execution"
    if any(x in s for x in ("sql", "query", "database", "db")):
        return "sql_injection"
    if any(x in s for x in ("template", "jinja", "ssti")):
        return "server_side_template_injection"
    if any(x in s for x in ("path", "file", "open(", "read", "write")):
        return "path_traversal"
    if any(x in s for x in ("secret", "token", "credential", "env")):
        return "secret_exposure"
    if any(x in s for x in ("malloc", "memcpy", "strcpy", "buffer", "free")):
        return "memory_corruption"
    return "unchecked_trust_boundary"


def _stride_for_category(category: str) -> list[str]:
    return {
        "command_execution": ["tampering", "elevation_of_privilege"],
        "sql_injection": ["tampering", "information_disclosure"],
        "server_side_template_injection": ["tampering", "elevation_of_privilege"],
        "path_traversal": ["information_disclosure", "tampering"],
        "secret_exposure": ["information_disclosure", "elevation_of_privilege"],
        "memory_corruption": ["tampering", "denial_of_service", "elevation_of_privilege"],
    }.get(category, ["tampering", "information_disclosure"])


def _controls_for_category(category: str) -> list[str]:
    controls = ["CTRL-001", "CTRL-003"]
    if category in {"command_execution", "sql_injection", "server_side_template_injection",
                    "path_traversal", "secret_exposure"}:
        controls.append("CTRL-004")
    if category == "secret_exposure":
        controls.append("CTRL-005")
    return _dedup(controls)


def _stable_id(prefix: str, parts: Iterable[Any]) -> str:
    raw = "|".join(str(p) for p in parts if p not in (None, ""))
    digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:10]
    return f"{prefix}-{digest.upper()}"


def _outcome_summary(data: dict[str, Any]) -> str:
    oracle = data.get("oracle") or "oracle"
    status = data.get("status") or "unknown"
    finding = data.get("finding_id") or "unkeyed finding"
    cwe = data.get("cwe_id")
    file = data.get("file")
    bits = [f"{oracle} {status} {finding}"]
    if cwe:
        bits.append(str(cwe))
    if file:
        bits.append(str(file))
    return " - ".join(bits)


def _outcome_matches_threat(data: dict[str, Any], threat: dict[str, Any]) -> bool:
    finding_id = str(data.get("finding_id") or "")
    if finding_id and finding_id in {
        str(threat.get("id") or ""),
        str(threat.get("entry_point_id") or ""),
        str(threat.get("sink_id") or ""),
    }:
        return True
    cwe = str(data.get("cwe_id") or "").lower()
    category = str(threat.get("category") or "").lower()
    if cwe and (
        ("78" in cwe and category == "command_execution")
        or ("89" in cwe and category == "sql_injection")
        or ("79" in cwe and "template" in category)
        or ("22" in cwe and category == "path_traversal")
    ):
        return True
    file = str(data.get("file") or "")
    title = str(threat.get("title") or "")
    return bool(file and file in title)


def _mermaid_id(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    return f"N{digest}"


def _mermaid_label(value: Any) -> str:
    # Defends against Mermaid label-escape attacks where a
    # hostile label like ``"]:::class`` or ``"]; flowchart LR; pwned``
    # would otherwise break out of the node and forge new graph
    # statements. ``_safe_for_render`` strips newlines + pipes +
    # backticks before we apply the Mermaid quote-escape, so the
    # final label can't smuggle a node-terminator + new
    # statement.
    text = _safe_for_render(value)
    return text.replace("\\", "\\\\").replace('"', '\\"')[:90]


def _read_raptor_logo() -> str:
    try:
        from core.config import RaptorConfig
        from core.startup.banner import read_logo
        return read_logo(RaptorConfig.effective_version())
    except Exception:
        return ""
