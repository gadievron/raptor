"""Project model and manager.

A project is a lightweight pointer to a target codebase and its output
directory. Project files live in ~/.raptor/projects/<name>.json.
Output directories live wherever the user specifies (default: out/projects/<name>/).
"""

import contextlib
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from core.config import RaptorConfig
from core.json import load_json, save_json
from core.logging import get_logger

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                                    # pragma: no cover
    _HAS_FCNTL = False

logger = get_logger()

# Default locations
PROJECTS_DIR = Path.home() / ".raptor" / "projects"
# Anchored to the repo-rooted out/ dir. Pre-fix this was the
# cwd-relative Path("out/projects"): create() minted default output
# dirs relative to whatever cwd the process happened to have, the
# purge containment in delete() resolved against that same moving
# target, and is_project_output_dir() misclassified real project
# dirs whenever cwd != repo root.
# Derived through get_out_dir() so RAPTOR_OUT_DIR redirects the
# projects base too (hermetic harnesses; the env is set by the
# launcher before python starts). A bad env value must not turn
# MODULE IMPORT into a traceback — fall back to the static base and
# let the call-time consumers surface the validation error.
try:
    DEFAULT_OUTPUT_BASE = RaptorConfig.get_out_dir() / "projects"
except Exception:  # noqa: BLE001 — invalid RAPTOR_OUT_DIR
    DEFAULT_OUTPUT_BASE = RaptorConfig.BASE_OUT_DIR / "projects"


_PROJECT_SCHEMA_VERSION = 5

#: Generated (non-run) directories that live directly inside a
#: project output dir. Every run-dir enumeration must skip them —
#: `findings` is the merge fold's output; `ghidra-attach` holds
#: attached-.gpr database caches and cannot be dot-prefixed (Ghidra
#: refuses project paths containing hidden elements, and the
#: attach-time headless import works inside the cache dir).
GENERATED_PROJECT_DIRS = frozenset({"findings", "ghidra-attach"})

# URL-shaped targets (/web scans) are stored and matched as opaque
# strings, never Path-resolved. Same pattern as core/run/output.py.
_URL_SCHEME_RE = re.compile(r"\A[a-zA-Z][a-zA-Z0-9+.-]*://")


def _normalize_url_target(target: str) -> str:
    """Light URL-target normalization: trailing slashes only.

    Matches the web scanner's own base_url.rstrip("/"), so a project
    created from "https://x/" still matches a run against
    "https://x". Anything deeper (case folding, port defaults) stays
    verbatim — URL targets otherwise match exactly.
    """
    stripped = target.rstrip("/")
    # Never strip into the scheme separator of a bare authority-less URL.
    return stripped if "://" in stripped else target


# Valid trust markers (schema v4). Operator assertions, never auto-set
# by detection heuristics, persisted in the project JSON under
# ``~/.raptor/projects`` — NEVER read from the scanned repo.
#
#   config  — the ``--trust-repo`` umbrella: BOTH the Claude Code
#             config check (core/security/cc_trust.py) AND the CodeQL
#             pack-config check (core/security/codeql_trust.py) treat
#             the repo's config as operator-reviewed.
#   build   — traced-build C/C++ CodeQL extraction (``--traced-build``):
#             the repo's build system may execute during DB creation.
#   dynamic — dynamic validation (Frida auto-launch / target execution):
#             ``config.dynamic_validation`` defaults on for this project.
#
# ``build`` deliberately does NOT imply ``config`` — a traced run
# hitting unsafe CodeQL pack config must still refuse (see
# packages/codeql/tests/test_buildless_mode.py::
# TestTracedBuildTrustIndependence). A marker may only loosen gates the
# corresponding per-run flag can already loosen; per-run flags always win.
VALID_TRUST_MARKERS = ("config", "build", "dynamic")

_TRUST_MARKER_HELP = {
    "config": "--trust-repo umbrella (cc_trust + codeql_trust overrides)",
    "build": "traced-build C/C++ CodeQL extraction (--traced-build)",
    "dynamic": "dynamic validation (Frida / target execution opt-in)",
}


# Settings registry (schema v4). ``/project set`` only accepts these
# keys — deliberately NOT an open KV store. ``description``, ``notes``
# and ``threat-model`` map onto the existing dataclass fields; the
# rest persist in the ``settings`` dict. Identity fields (name,
# target, output_dir, created) are NOT settable through this surface,
# by design.
VALID_TARGET_KINDS = ("library", "hybrid", "application", "auto", "firmware")

SETTINGS_REGISTRY = {
    "description": "one-line project description (string)",
    "notes": "free-form project notes (string)",
    "threat-model": ("path to an existing threat-model JSON "
                     "(maps to threat_model_path)"),
    "target-kind": "one of: " + "|".join(VALID_TARGET_KINDS),
    "build-command": ("build command (string); per-language form "
                      "``build-command.<lang>`` (bare key sets the "
                      "``default`` language slot)"),
}

# Keys persisted in the ``settings`` dict (the others map to existing
# top-level Project fields).
_DICT_SETTINGS_KEYS = ("target-kind", "build-command")

# Language slot names for ``build-command.<lang>``.
_LANG_SLOT_RE = re.compile(r"\A[a-zA-Z0-9_+#.-]{1,32}\Z")

# Generous cap on setting values so a scripted mistake can't bloat the
# project JSON unboundedly.
_MAX_SETTING_LEN = 4096

# Machine-generated project naming patterns eligible for auto-expiry.
# Projects are operator artifacts: expiry NEVER applies to a name
# outside these prefixes, and even for matching names it applies only
# when the creating machinery ALSO stamped ``expires_at`` (both
# conditions — belt and braces). Currently only the corpus runner's
# throwaway ``corpus-<tag>`` projects (target /tmp) qualify: one left
# active by a crashed run turned every subsequent no-path command into
# an audit of /tmp under the default-target rules.
MACHINE_PROJECT_PREFIXES = ("corpus-",)


def _run_target_path(run_dir: Path) -> Path | str | None:
    """The target a run's ``.raptor-run.json`` records, or ``None``.

    URL-shaped targets (``/web`` runs) come back as the verbatim
    string — resolving them as filesystem paths would anchor the URL
    to the cwd (the adopt/retro-create mangling this guards against).
    """
    meta_path = Path(run_dir) / ".raptor-run.json"
    if not meta_path.is_file():
        return None
    meta = load_json(meta_path, max_bytes=1024 * 1024)
    raw = meta.get("target_path") if isinstance(meta, dict) else None
    if not raw or not isinstance(raw, str):
        return None
    if _URL_SCHEME_RE.match(raw):
        return _normalize_url_target(raw)
    try:
        return Path(raw).resolve()
    except OSError:
        return None


def _same_target(recorded: Path | str, project_target: str) -> bool:
    """Whether a run's recorded target names the project's target.

    URL targets compare as normalized strings on both sides; mixing a
    URL with a filesystem path is never the same target.
    """
    recorded_is_url = isinstance(recorded, str)
    project_is_url = bool(_URL_SCHEME_RE.match(project_target))
    if recorded_is_url != project_is_url:
        return False
    if recorded_is_url:
        return recorded == _normalize_url_target(project_target)
    try:
        return recorded == Path(project_target).resolve()
    except OSError:
        return False


def is_machine_project_name(name: str) -> bool:
    """True when *name* matches a machine-generated naming pattern."""
    return any(name.startswith(p) for p in MACHINE_PROJECT_PREFIXES)


def split_setting_key(key: str):
    """Split ``build-command.<lang>`` into ``("build-command", lang)``.

    Plain registry keys return ``(key, None)``. Raises ValueError for
    unknown keys, listing the valid ones.
    """
    base, sep, lang = key.partition(".")
    if base == "build-command" and sep:
        if not _LANG_SLOT_RE.match(lang):
            msg = f"Invalid language slot {lang!r} in setting key {key!r}"
            raise ValueError(msg)
        return base, lang
    if key in SETTINGS_REGISTRY:
        return key, None
    raise ValueError(
        f"Unknown setting {key!r}. Valid keys: "
        + ", ".join(sorted(SETTINGS_REGISTRY))
        + " (per-language: build-command.<lang>)"
    )


@contextlib.contextmanager
def project_file_lock(project_file: Path):
    """Cross-process exclusive lock guarding a project-JSON
    read-modify-write window.

    Same idiom as ``core.run.metadata._metadata_lock``: flock a sibling
    ``.lock`` file (not the JSON itself, which ``save_json`` atomically
    replaces), hold it across the whole load → mutate → save window,
    degrade to a no-op without fcntl. Without it, concurrent mutators
    (``/project binary add`` racing ``/project trust``, two parallel
    ``set`` invocations) last-writer-wins and one update is silently
    dropped.

    The ``.lock`` file is deliberately left behind — unlinking after
    unlock races and can split lockers across two inodes.
    """
    if not _HAS_FCNTL:
        yield
        return
    path = Path(project_file)
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        # Lock file uncreatable (read-only dir, ENOSPC) — proceed
        # unserialised rather than failing the mutation.
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _validate_trust_marker(marker: str) -> str:
    if marker not in VALID_TRUST_MARKERS:
        raise ValueError(
            f"Unknown trust marker {marker!r}. Valid markers: "
            + ", ".join(VALID_TRUST_MARKERS)
        )
    return marker


@dataclass
class Project:
    """A RAPTOR project."""
    name: str
    target: str
    output_dir: str
    created: str = ""
    description: str = ""
    notes: str = ""
    # Schema version: bumped to 2 when the ``binaries`` field landed
    # (adversarial review Agent D P1-7). v1 readers silently ignore
    # the field, which would mean a project's per-binary-oracle config
    # is dropped when the file round-trips through an older RAPTOR. A
    # version bump makes the change EXPLICIT in the persisted file —
    # older readers can still load the project (back-compat below) but
    # operators inspecting the JSON see the v2 schema.
    #
    # v3 adds a project-owned threat-model artefact path. Older files
    # still load; the next write upgrades them.
    #
    # v4 adds ``trust`` (operator trust markers → ISO timestamp when
    # set) and ``settings`` (registry-validated key/value config).
    # Older files still load with both defaulted; the next write
    # upgrades them.
    #
    # v5 adds ``ghidra_projects`` — operator-attached Ghidra .gpr
    # paths for bidirectional RE sync. Older files still load with
    # the list defaulted; the next write upgrades them.
    version: int = 5
    # Operator-supplied debug binaries for binary_oracle reachability
    # enrichment. Persisted across runs so the operator doesn't re-pass
    # ``--binary`` every invocation. List for ``--target-kind=hybrid``
    # deployments shipping multiple binaries (library + app). Loaded
    # into ``RaptorConfig.BINARY_ORACLE_PATHS`` at /agentic / /codeql
    # start; explicit ``--binary`` on the CLI is additive.
    binaries: list[str] = field(default_factory=list)
    # v5: operator-attached Ghidra projects (.gpr paths) for
    # bidirectional sync — review context injection reads their
    # cached REDatabases; /ghidra sync exports findings back into
    # working copies. Managed via ``/project ghidra add|remove`` and
    # ``raptor-ghidra attach|detach``; never auto-populated from the
    # scanned repo.
    ghidra_projects: list[str] = field(default_factory=list)
    threat_model_path: str = ""
    threat_model_updated: str = ""
    # v4: operator trust markers — marker name → ISO timestamp when the
    # operator set it. Keys restricted to VALID_TRUST_MARKERS. Never
    # auto-set; never read from the scanned repo.
    trust: dict[str, str] = field(default_factory=dict)
    # v4: registry-validated settings that don't map onto an existing
    # field (currently ``target-kind`` and ``build-command``; the
    # latter stored as a lang→cmd dict, bare sets use the ``default``
    # slot). See SETTINGS_REGISTRY.
    settings: dict = field(default_factory=dict)
    # Creation-time auto-expiry marker (ISO timestamp), stamped ONLY by
    # machine creators (corpus runner) on MACHINE_PROJECT_PREFIXES
    # names, consumed at active-project resolution on both layers (ProjectManager.get_active)
    # — an expired machine project silently stops being the active
    # default target. Empty = never expires (every operator-created
    # project). Overridable: an explicit ``/project use <name>`` clears
    # it — the operator choosing the project makes it operator-owned.
    expires_at: str = ""

    def to_dict(self) -> dict:
        return {
            "version": _PROJECT_SCHEMA_VERSION,
            "name": self.name,
            "target": self.target,
            "output_dir": self.output_dir,
            "created": self.created,
            "description": self.description,
            "notes": self.notes,
            "binaries": list(self.binaries),
            "ghidra_projects": list(self.ghidra_projects),
            "threat_model_path": self.threat_model_path,
            "threat_model_updated": self.threat_model_updated,
            "trust": dict(self.trust),
            "settings": {
                k: (dict(v) if isinstance(v, dict) else v)
                for k, v in self.settings.items()
            },
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Project":
        binaries = data.get("binaries") or []
        if not isinstance(binaries, list):
            binaries = []
        ghidra_projects = data.get("ghidra_projects") or []
        if not isinstance(ghidra_projects, list):
            ghidra_projects = []
        try:
            version = int(data.get("version", _PROJECT_SCHEMA_VERSION))
        except (TypeError, ValueError):
            version = _PROJECT_SCHEMA_VERSION
        if version > _PROJECT_SCHEMA_VERSION:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "Project file has schema version %d (current is %d); "
                "fields beyond v%d will be lost on the next save",
                version, _PROJECT_SCHEMA_VERSION, _PROJECT_SCHEMA_VERSION,
            )
        version = max(version, _PROJECT_SCHEMA_VERSION)
        # Back-compat: load v1/v2/v3 files with new fields defaulted.
        # The next save upgrades the file to the current schema.
        return cls(
            name=data.get("name", ""),
            target=data.get("target", ""),
            output_dir=data.get("output_dir", ""),
            created=data.get("created", ""),
            description=data.get("description", ""),
            notes=data.get("notes", ""),
            version=version,
            binaries=[str(b) for b in binaries if isinstance(b, str)],
            ghidra_projects=[str(g) for g in ghidra_projects
                             if isinstance(g, str)],
            threat_model_path=str(data.get("threat_model_path") or ""),
            threat_model_updated=str(data.get("threat_model_updated") or ""),
            trust=cls._parse_trust(data.get("trust")),
            settings=cls._parse_settings(data.get("settings")),
            expires_at=str(data.get("expires_at") or ""),
        )

    @staticmethod
    def _parse_trust(raw) -> dict[str, str]:
        """Lenient read of the persisted ``trust`` dict: unknown markers
        and malformed timestamps are dropped (strict validation happens
        at write time via ``set_trust``)."""
        trust: dict[str, str] = {}
        if isinstance(raw, dict):
            trust.update({marker: ts for marker, ts in raw.items() if marker in VALID_TRUST_MARKERS
                        and isinstance(ts, str) and ts.strip()})
        return trust

    @staticmethod
    def _parse_settings(raw) -> dict:
        """Lenient read of the persisted ``settings`` dict: unknown keys
        and malformed values are dropped (strict validation happens at
        write time via ``set_setting``)."""
        settings: dict = {}
        if not isinstance(raw, dict):
            return settings
        kind = raw.get("target-kind")
        if isinstance(kind, str) and kind in VALID_TARGET_KINDS:
            settings["target-kind"] = kind
        elif kind is not None:
            # Loud, not silent: a project written by a newer RAPTOR
            # (e.g. target-kind added later) must not lose its setting
            # invisibly when read by this checkout.
            logger.warning(
                "project settings: dropping unrecognised target-kind %r "
                "(valid: %s) — written by a newer RAPTOR?",
                kind, "|".join(VALID_TARGET_KINDS),
            )
        build = raw.get("build-command")
        if isinstance(build, dict):
            clean = {
                str(lang): str(cmd)
                for lang, cmd in build.items()
                if isinstance(lang, str) and _LANG_SLOT_RE.match(lang)
                and isinstance(cmd, str) and cmd.strip()
            }
            if clean:
                settings["build-command"] = clean
        elif isinstance(build, str) and build.strip():
            # A bare string form (hand-edited JSON) upgrades to the
            # canonical lang→cmd dict on the default slot.
            settings["build-command"] = {"default": build}
        return settings

    def is_expired_machine_project(self, now: datetime | None = None) -> bool:
        """True iff this is a machine-generated project whose
        auto-expiry timestamp has passed.

        Both conditions are required: the name must match a
        MACHINE_PROJECT_PREFIXES pattern AND ``expires_at`` must be a
        parseable ISO timestamp in the past. Operator-named projects
        never expire regardless of the field; a malformed timestamp
        fails open (no expiry) — projects are operator artifacts and
        expiry must never surprise-delete a real one.
        """
        if not self.expires_at or not is_machine_project_name(self.name):
            return False
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return current >= expiry

    # ------------------------------------------------------------------
    # v4 trust markers — operator assertions. NEVER auto-set from
    # detection heuristics; NEVER read from the scanned repo.
    # ------------------------------------------------------------------

    def set_trust(self, marker: str) -> str:
        """Set a trust marker, stamping the current UTC time. Returns
        the timestamp. Raises ValueError on unknown markers."""
        _validate_trust_marker(marker)
        ts = datetime.now(timezone.utc).isoformat()
        self.trust[marker] = ts
        return ts

    def clear_trust(self, marker: str) -> bool:
        """Remove a trust marker. Returns True if it was set. Raises
        ValueError on unknown markers."""
        _validate_trust_marker(marker)
        return self.trust.pop(marker, None) is not None

    # ------------------------------------------------------------------
    # v4 settings — registry-validated key/value config.
    # ------------------------------------------------------------------

    def set_setting(self, key: str, value: str) -> None:
        """Validated setting write. Raises ValueError for unknown keys
        (listing the valid ones) or invalid values."""
        base, lang = split_setting_key(key)
        if not isinstance(value, str) or not value.strip():
            msg = f"Setting {key!r} needs a non-empty value"
            raise ValueError(msg)
        if len(value) > _MAX_SETTING_LEN:
            msg = f"Setting {key!r} value exceeds {_MAX_SETTING_LEN} chars"
            raise ValueError(msg)
        value = value.strip()
        if base == "description":
            self.description = value
        elif base == "notes":
            self.notes = value
        elif base == "threat-model":
            path = Path(value).expanduser().resolve()
            if not path.is_file():
                msg = (
                    f"threat-model path does not exist or is not a "
                    f"file: {value} (resolved to {path})"
                )
                raise ValueError(msg)
            self.threat_model_path = str(path)
            self.threat_model_updated = datetime.now(timezone.utc).isoformat()
        elif base == "target-kind":
            if value not in VALID_TARGET_KINDS:
                raise ValueError(
                    "target-kind must be one of: "
                    + ", ".join(VALID_TARGET_KINDS) + f" (got {value!r})")
            self.settings["target-kind"] = value
        elif base == "build-command":
            slot = lang or "default"
            commands = self.settings.get("build-command")
            if not isinstance(commands, dict):
                commands = {}
            commands[slot] = value
            self.settings["build-command"] = commands
        else:  # pragma: no cover — split_setting_key guards this
            msg = f"Unknown setting {key!r}"
            raise ValueError(msg)

    def unset_setting(self, key: str) -> bool:
        """Remove a setting. Returns True if it was set. Raises
        ValueError for unknown keys."""
        base, lang = split_setting_key(key)
        if base == "description":
            had = bool(self.description)
            self.description = ""
            return had
        if base == "notes":
            had = bool(self.notes)
            self.notes = ""
            return had
        if base == "threat-model":
            had = bool(self.threat_model_path)
            self.threat_model_path = ""
            self.threat_model_updated = ""
            return had
        if base == "target-kind":
            return self.settings.pop("target-kind", None) is not None
        if base == "build-command":
            commands = self.settings.get("build-command")
            if not isinstance(commands, dict):
                return False
            if lang is None:
                return self.settings.pop("build-command", None) is not None
            had = commands.pop(lang, None) is not None
            if not commands:
                self.settings.pop("build-command", None)
            return had
        return False  # pragma: no cover — split_setting_key guards this

    def get_setting(self, key: str):
        """Read a setting value (None when unset). Raises ValueError
        for unknown keys."""
        base, lang = split_setting_key(key)
        if base == "description":
            return self.description or None
        if base == "notes":
            return self.notes or None
        if base == "threat-model":
            return self.threat_model_path or None
        if base == "target-kind":
            return self.settings.get("target-kind")
        if base == "build-command":
            commands = self.settings.get("build-command")
            if not isinstance(commands, dict):
                return None
            return commands.get(lang or "default")
        return None  # pragma: no cover — split_setting_key guards this

    def settings_view(self) -> dict[str, str]:
        """All registry keys with their current display value ("" when
        unset). ``build-command`` expands to per-language rows."""
        view: dict[str, str] = {}
        for key in sorted(SETTINGS_REGISTRY):
            if key == "build-command":
                commands = self.settings.get("build-command")
                if isinstance(commands, dict) and commands:
                    for lang in sorted(commands):
                        label = ("build-command" if lang == "default"
                                 else f"build-command.{lang}")
                        view[label] = commands[lang]
                else:
                    view["build-command"] = ""
                continue
            view[key] = self.get_setting(key) or ""
        return view

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)

    @property
    def content_id(self) -> str | None:
        """The project's content-equivalence id, read lazily from the durable
        coverage store (``coverage.json``). The store is the single source of
        truth for this id (L2-owned); it is ``None`` until a coverage build has
        stamped one. Two acquisitions of identical source (git checkout vs zip
        extraction) share a ``content_id`` even though their ``target`` paths
        differ — this is what lets them resolve to the same project."""
        try:
            data = load_json(self.output_path / "coverage.json")
        except Exception:  # noqa: BLE001 — any read failure means "no id yet"
            return None
        return data.get("content_id") if isinstance(data, dict) else None

    def _list_run_dirs(self) -> list[Path]:
        """List run directories (unsorted). Shared by get_run_dirs and sweep."""
        if not self.output_path.exists():
            return []
        return [d for d in self.output_path.iterdir()
                if d.is_dir()
                and not d.name.startswith((".", "_"))
                and d.name not in GENERATED_PROJECT_DIRS]

    def get_run_dirs(self, sweep: bool=False) -> list[Path]:
        """List run directories sorted newest-first.

        Uses the timestamp embedded in the directory name when available
        (deterministic), falls back to mtime for non-standard names.
        When sweep=True, marks stale 'running' dirs as failed.
        Inside Claude Code (CLAUDECODE=1), keeps the newest running dir
        (may be active). Outside Claude Code, sweeps all.
        Default is sweep=False to avoid damaging active runs from read-only
        commands (status, findings, coverage).
        """
        from core.run.metadata import parse_timestamp_from_name

        def _sort_key(d: Path) -> str:
            ts = parse_timestamp_from_name(d.name)
            if ts:
                return ts
            return datetime.fromtimestamp(d.stat().st_mtime, tz=timezone.utc).isoformat()

        dirs = self._list_run_dirs()
        if sweep:
            in_session = bool(os.environ.get("CLAUDECODE"))
            self._sweep_stale(dirs, keep_latest=in_session)
        return sorted(dirs, key=_sort_key, reverse=True)

    def sweep_stale_runs(self, keep_latest: bool=False) -> int:
        """Mark stale 'running' run dirs as failed.

        Args:
            keep_latest: if True, skip the most recent 'running' dir
                         (it may be actively running this session).
                         False at startup (nothing is running).

        Returns count of dirs marked failed.
        """
        return self._sweep_stale(self._list_run_dirs(), keep_latest)

    def _sweep_stale(self, dirs: list, keep_latest: bool=False) -> int:
        """Mark 'running' dirs as failed if their session is dead.

        Checks session_pid in metadata — if the PID is still alive, the
        session that started the run is still running and will clean up
        its own runs. Only sweeps runs whose session has died.

        Args:
            dirs: candidate run directories to examine; only those whose
                  metadata records status == "running" are considered.
            keep_latest: if True, skip the most recent 'running' dir even
                         if its session is dead (legacy fallback for runs
                         without session_pid).
        """
        from core.json import load_json
        from core.run.metadata import (
            RUN_METADATA_FILE,
            _session_alive_for_meta,
            fail_run,
        )

        # Find all running dirs with their timestamps and PIDs
        running = []
        for d in dirs:
            meta_file = d / RUN_METADATA_FILE
            if not meta_file.exists():
                continue
            meta = load_json(meta_file)
            if isinstance(meta, dict) and meta.get("status") == "running":
                running.append((meta.get("timestamp", ""), d,
                                meta.get("session_pid"), meta))

        if not running:
            return 0

        swept = 0
        # Sort newest first for keep_latest (tuples compare on the
        # timestamp; the dict tail never participates because (ts, dir)
        # pairs are unique).
        running.sort(key=lambda row: (row[0], str(row[1])), reverse=True)

        for i, (_ts, d, pid, meta) in enumerate(running):
            # Recorded owner still alive (identity-checked when the
            # metadata carries a stamp) — skip; the session cleans up.
            if pid is not None and _session_alive_for_meta(meta):
                continue
            # No PID (legacy run) — use keep_latest heuristic
            if pid is None and keep_latest and i == 0:
                continue
            fail_run(d, "stale — session ended without completion",
                     record_timing=False)
            swept += 1

        return swept

    def get_run_dirs_by_type(self) -> dict[str, list[Path]]:
        """Group run directories by command type.

        Generates .raptor-run.json for any run directory that's missing it
        (JIT metadata for runs that predate the metadata system).
        """
        from core.run import generate_run_metadata, infer_command_type
        from core.run.metadata import RUN_METADATA_FILE
        groups: dict[str, list[Path]] = {}
        for d in self.get_run_dirs(sweep=False):
            if not (d / RUN_METADATA_FILE).exists():
                generate_run_metadata(d)
            cmd_type = infer_command_type(d)
            groups.setdefault(cmd_type, []).append(d)
        return groups


class ProjectManager:
    """Manages project lifecycle."""

    def __init__(self, projects_dir: Path | None = None) -> None:
        self.projects_dir = projects_dir or PROJECTS_DIR
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    # Reserved names that cannot be used as project names
    RESERVED_NAMES: ClassVar[set] = {"none"}

    # Project names must match: alphanumeric, hyphens, dots, underscores
    # (first character must be alphanumeric).
    # This prevents shell metacharacters, control characters, spaces, and
    # path separators from ever appearing in filenames or directory names.
    #
    # `\A` / `\Z` instead of `^` / `$`. Pre-fix `^...$` plus `re.match`
    # would have accepted `"validproject\n"` (or any project name with
    # a trailing newline) — Python's `$` matches just before a trailing
    # newline. The newline-suffixed name then flows into the
    # `<projects_dir>/<name>.json` filename, where the literal newline
    # in the path produces an unreadable file (most filesystems accept
    # newlines in names but downstream tools — shell glob, ls,
    # operator's grep — break on them). The `re.fullmatch` semantics
    # below would also fix this, but anchoring on `\A`/`\Z` keeps the
    # pre-existing `re.match` call site working and makes the strict
    # boundary visible in the pattern itself.
    # Length cap matches core.project.sessions._NAME_RE — a project
    # whose name the session registry rejects could never be
    # session-bound, so refuse it at creation instead. The lookaheads
    # refuse '..' sequences and trailing dots: both coverage hooks'
    # symlink validators reject them (path-shaped), so such projects
    # silently lost legacy-route read attribution.
    _NAME_PATTERN = re.compile(
        r'\A(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}(?<!\.)\Z')

    @classmethod
    def _validate_name(cls, name: str) -> None:
        """Validate project name is safe for use as a filename."""
        if not name or not name.strip():
            msg = "Project name cannot be empty"
            raise ValueError(msg)
        if name.lower() in cls.RESERVED_NAMES:
            msg = f"Project name '{name}' is reserved"
            raise ValueError(msg)
        if len(name) > 100:
            msg = f"Project name too long (max 100 chars): {name}"
            raise ValueError(msg)
        if not cls._NAME_PATTERN.match(name):
            msg = (
                f"Project name '{name}' contains invalid characters. "
                f"Use only letters, numbers, hyphens, dots, and underscores (cannot start with . or _)"
            )
            raise ValueError(msg)

    def create(self, name: str, target: str, description: str = "",
               output_dir: str | None = None, resolve_target: bool = True,
               created: str | None = None,
               binaries: list[str] | None = None) -> Project:
        """Create a new project.

        Args:
            name: project name; validated against the safe-filename
                pattern (alphanumeric first character, then letters,
                digits, dots, hyphens, underscores; reserved names and
                names over 100 chars rejected).
            target: path to the code under analysis; resolved to an
                absolute path when ``resolve_target`` is True.
            description: free-form description stored on the project.
            output_dir: directory for the project's runs; created if
                missing. When falsy, defaults to
                ``DEFAULT_OUTPUT_BASE/<name>`` (resolved).
            resolve_target: If True (default), resolve target to absolute path.
                Set to False for imports where the original path should be preserved.
            created: ISO timestamp override (for imports preserving original date).
            binaries: optional list of debug binary paths for binary_oracle
                enrichment. Persisted on the project; each is resolved to
                an absolute path when ``resolve_target`` is True.
        """
        self._validate_name(name)
        project_file = self.projects_dir / f"{name}.json"
        if project_file.exists():
            msg = f"Project '{name}' already exists"
            raise ValueError(msg)

        if not output_dir:
            output_dir = str((DEFAULT_OUTPUT_BASE / name).resolve())

        resolved_binaries: list[str] = []
        for b in (binaries or []):
            if not isinstance(b, str) or not b.strip():
                continue
            resolved_binaries.append(
                str(Path(b).resolve()) if resolve_target else b)

        # URL targets (/web scans) are opaque strings, not filesystem
        # paths — resolving https://example.com against the cwd would
        # store a nonsense path. Same rule as core/run/output.py.
        if _URL_SCHEME_RE.match(target):
            resolved_target = _normalize_url_target(target)
        elif resolve_target:
            resolved_target = str(Path(target).resolve())
        else:
            resolved_target = target
        project = Project(
            name=name,
            target=resolved_target,
            output_dir=output_dir,
            created=created or datetime.now(timezone.utc).isoformat(),
            description=description,
            binaries=resolved_binaries,
        )

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        save_json(project_file, project.to_dict())
        logger.info("Created project '%s' → %s", name, output_dir)
        return project

    def load(self, name: str) -> Project | None:
        """Load a project by name. Returns None if not found or name invalid."""
        # Reject traversal attempts — load is called with user input
        project_file = (self.projects_dir / f"{name}.json").resolve()
        if not project_file.is_relative_to(self.projects_dir.resolve()):
            return None
        data = load_json(project_file)
        if not isinstance(data, dict):
            return None
        return Project.from_dict(data)

    def list_projects(self) -> list[Project]:
        """List all projects."""
        projects = []
        for f in sorted(self.projects_dir.glob("*.json")):
            data = load_json(f)
            if isinstance(data, dict):
                projects.append(Project.from_dict(data))
        return projects

    def delete(self, name: str, purge: bool = False,
               force: bool = False) -> None:
        """Delete a project. With purge=True, also delete the output
        directory — REFUSED while any run under it is live (another
        session's in-flight run would have its dir deleted underneath
        it; the same ``split_live_runs`` predicate clean/dedup/merge
        already use — purge never had it). ``force=True`` overrides."""
        project = self.load(name)
        if not project:
            msg = f"Project '{name}' not found"
            raise ValueError(msg)

        # Live-run refusal applies to EVERY delete, not only purge:
        # deleting the registry entry alone re-binds sessions to none
        # and orphans the live run's pin ("pinned to missing project"),
        # so its completion-time journal/coverage merges are silently
        # suppressed. force=True overrides, as documented.
        if not force:
            from core.project.clean import split_live_runs
            run_dirs = []
            if project.output_path.exists():
                run_dirs = [d for d in project.output_path.iterdir()
                            if d.is_dir()
                            and not d.name.startswith((".", "_"))]
            # External pinned runs are checked even when the output
            # dir is missing (half-purged, unmounted) — they are the
            # runs a registry-only delete would orphan.
            try:
                from core.project.sessions import ledger_runs_pinned_to
                known = {str(d.resolve()) for d in run_dirs}
                run_dirs.extend(
                    Path(rec["run_dir"])
                    for rec in ledger_runs_pinned_to(name)
                    if rec["run_dir"] not in known
                    and Path(rec["run_dir"]).is_dir())
            except Exception:  # noqa: BLE001 — ledger scan best-effort
                pass
            _rest, live = split_live_runs(run_dirs)
            if live:
                names = ", ".join(d.name for d in live[:3])
                msg = (
                    f"Refusing to delete '{name}': {len(live)} live "
                    f"run(s) under it ({names}{'…' if len(live) > 3 else ''}) "
                    f"— possibly another session's. Wait for them, or "
                    f"pass --force."
                )
                raise ValueError(msg)

        if purge and project.output_path.exists():
            # Safety: refuse to delete paths that could cause serious damage.
            #
            # The existing checks (== home, == /, < 3 parts, ancestor of
            # home) catch the most obvious targets, but an attacker with
            # write access to the project JSON could set
            # `output_dir = "/etc"` or `"/usr/share/foo"` — none of those
            # match the simple checks but rmtree of any of them is
            # catastrophic.
            #
            # Add a containment check: refuse to rmtree any path that
            # ISN'T inside the expected output base (DEFAULT_OUTPUT_BASE
            # — `out/projects` resolved). Operators with custom
            # output_dirs outside that base will need to clean by hand;
            # the trade-off is correct because the alternative (trust
            # the project JSON) is exactly the attack surface.
            output = project.output_path.resolve()
            home = Path.home().resolve()
            if (output == home or output == Path("/")
                    or len(output.parts) < 3
                    or home.is_relative_to(output)):
                msg = f"Refusing to delete suspicious path: {output}"
                raise ValueError(msg)
            expected_base = DEFAULT_OUTPUT_BASE.resolve()
            try:
                output.relative_to(expected_base)
            except ValueError:
                msg = (
                    f"Refusing to delete output path {output} outside the "
                    f"expected base {expected_base}. Use --no-purge or "
                    f"clean the directory by hand."
                )
                raise ValueError(msg) from None
            try:
                shutil.rmtree(project.output_path)
            except FileNotFoundError:
                pass
            logger.info("Deleted output directory: %s", project.output_dir)

        project_file = self.projects_dir / f"{name}.json"
        project_file.unlink(missing_ok=True)

        # Clear .active symlink if it pointed to this project
        active_link = self.projects_dir / ".active"
        if active_link.is_symlink() and os.readlink(active_link) == f"{name}.json":
            active_link.unlink(missing_ok=True)

        # Session-binding hygiene: live sessions bound to
        # the deleted project are re-bound to none — a dangling binding
        # must never fall through to the bookmark layer's (unrelated)
        # project. Warn about each; other sessions get the loud
        # stale-binding warning on their next resolution regardless.
        self._rewrite_bindings(name, None)

        logger.info("Deleted project '%s'", name)

    def _rewrite_bindings(self, old_name: str,
                          new_name: str | None) -> None:
        """Re-point (rename) or null (delete) every LIVE session
        binding naming *old_name*. Best-effort: registry failures never
        block the project mutation itself."""
        try:
            from core.project import sessions
            live = sessions.read_sessions(prune=False)
            candidates = [pid for pid, fields in live.items()
                          if fields.get("v") == sessions.ENTRY_VERSION
                          and fields.get("project") == old_name]
            # Compare-and-swap per entry: only rewrite bindings that
            # STILL name the old project at write time — a session
            # that concurrently bound elsewhere keeps its choice.
            hits = [pid for pid in candidates
                    if sessions.rebind_session_if(pid, old_name,
                                                  new_name)]
            if hits:
                logger.warning(
                    "%d live session(s) were bound to '%s' — %s",
                    len(hits), old_name,
                    f"re-bound to '{new_name}'" if new_name
                    else "re-bound to none (authoritatively projectless)",
                )
        except Exception:  # noqa: BLE001 — hygiene, never blocks mutation
            logger.debug("binding rewrite failed", exc_info=True)

    def rename(self, old_name: str, new_name: str,
               force: bool = False) -> Project:
        """Rename a project. ``force`` overrides the live-run refusal
        (needed for runs whose foreign-stamped metadata reads as
        unverifiable-alive forever — e.g. dirs restored from another
        machine with ``status=running``)."""
        self._validate_name(new_name)
        project = self.load(old_name)
        if not project:
            msg = f"Project '{old_name}' not found"
            raise ValueError(msg)

        new_file = self.projects_dir / f"{new_name}.json"
        if new_file.exists():
            msg = f"Project '{new_name}' already exists"
            raise ValueError(msg)

        # Refuse while runs are live: their owning processes hold the
        # OLD name in their pin freeze caches, and a rewrite under
        # them would drop their completion-time project writes.
        # External runs (--project P --out /elsewhere) are found via
        # the session ledgers' pin witnesses — they are invisible to
        # the child-dir scan.
        try:
            from core.project.clean import split_live_runs
            candidates = list(project.get_run_dirs())
            from core.project.sessions import ledger_runs_pinned_to
            known = {str(Path(d).resolve()) for d in candidates}
            for rec in ledger_runs_pinned_to(old_name):
                if rec["run_dir"] not in known:
                    ext = Path(rec["run_dir"])
                    if ext.is_dir():
                        candidates.append(ext)
            _rest, live = split_live_runs(candidates)
        except Exception:  # noqa: BLE001 — liveness probe best-effort
            live = []
        if live and not force:
            names = ", ".join(d.name for d in live[:3])
            msg = (f"Project '{old_name}' has {len(live)} live run(s) "
                   f"({names}...) — wait for them to finish before "
                   "renaming, or pass --force (unverifiable "
                   "foreign-stamped runs read as live forever)")
            raise ValueError(msg)

        # Update project
        project.name = new_name

        # Save new, delete old — with EXPLICIT error reporting.
        # Pre-fix the unlink used `missing_ok=True` which silently
        # swallowed every OSError including PermissionError. If the
        # save_json succeeded but the unlink failed, the project
        # ended up existing under BOTH names with no signal to the
        # operator — every subsequent list/load saw two entries
        # for what was supposed to be one project. The new file is
        # written first (it becomes the source of truth), then the
        # old file is removed; FileNotFoundError is fine (already
        # gone), any other OSError is logged loudly and re-raised so
        # the operator knows the old file needs manual cleanup.
        save_json(new_file, project.to_dict())
        old_file = self.projects_dir / f"{old_name}.json"
        try:
            old_file.unlink()
        except FileNotFoundError:
            pass  # already gone — fine
        except OSError as e:
            # Don't roll back the new file: it has the renamed
            # content and is the source of truth going forward.
            # But surface the failure so the operator knows the
            # old file is still on disk and they need to clean it
            # up by hand.
            logger.error(
                "rename: wrote new project file %s but failed to remove "
                "old %s: %s. Both files now exist; remove %s manually.",
                new_file, old_file, e, old_file,
            )
            raise

        # Update .active symlink if it pointed to the old name
        active_link = self.projects_dir / ".active"
        if active_link.is_symlink() and os.readlink(active_link) == f"{old_name}.json":
            self.set_active(new_name)

        # Re-point live session bindings: a session bound
        # to the old name must follow the rename, not dangle.
        self._rewrite_bindings(old_name, new_name)

        # Re-point pin WITNESSES across all session ledgers: a witness
        # naming the old project would DISAGREE with the re-pointed
        # markers, and the tamper check would suppress every later
        # projection of the renamed project's runs.
        try:
            from core.project.sessions import ledger_rewrite_pin_project
            ledger_rewrite_pin_project(old_name, new_name)
        except Exception:  # noqa: BLE001 — witnesses are best-effort
            logger.warning(
                "rename: could not re-point ledger pin witnesses from "
                "%r to %r — affected runs' project-store writes will "
                "be suppressed as tamper; repair with "
                "'raptor project add %s <run-dir>'",
                old_name, new_name, new_name, exc_info=True)

        # Re-point every run pin: a pin recording the old name would
        # resolve as authoritatively-projectless forever ("pinned to
        # missing project"), silently suppressing the whole renamed
        # project's journal merges, coverage snapshots, and trust
        # consumption. Best-effort per run — a failure names the dir.
        try:
            from core.json import load_json as _lj
            from core.json import save_json as _sj
            from core.run.metadata import RUN_METADATA_FILE as _MF
            _pin_dirs = list(project.get_run_dirs())
            # External pinned runs join the rewrite via the ledgers'
            # surviving WITNESSES (not witnessed records — a witness
            # outlives its cap-evicted record while the run dir
            # exists, and missing those left markers on the old name
            # with re-pointed witnesses: a manufactured 'tamper'
            # disagreement on a legitimate run).
            try:
                from core.project.sessions import ledger_pinned_dirs
                _known = {str(Path(d).resolve()) for d in _pin_dirs}
                # The witness rewrite above already re-pointed the
                # ledgers to the NEW name — query that, or external
                # runs are invisible here.
                _pin_dirs.extend(
                    Path(rec["run_dir"])
                    for rec in ledger_pinned_dirs(new_name)
                    if rec["run_dir"] not in _known
                    and Path(rec["run_dir"]).is_dir())
            except Exception:  # noqa: BLE001 — ledger scan best-effort
                logger.debug("rename: ledger scan failed", exc_info=True)
            for run_dir in _pin_dirs:
                marker = run_dir / _MF
                try:
                    meta = _lj(marker)
                    if (isinstance(meta, dict)
                            and meta.get("project") == old_name):
                        meta["project"] = new_name
                        _sj(marker, meta)
                except Exception:  # noqa: BLE001 — leave a loud trail
                    logger.warning(
                        "rename: could not re-point the run pin in %s "
                        "— edit its %s 'project' field to %r manually",
                        run_dir, _MF, new_name, exc_info=True)
        except Exception:  # noqa: BLE001 — enumeration failure
            logger.warning(
                "rename: could not enumerate runs under %s to re-point "
                "their pins — runs pinned to %r will resolve "
                "projectless until fixed manually",
                project.output_path, old_name, exc_info=True)

        # Retry the witness rewrite now that the marker loop has run:
        # a ledger lock briefly held during the first pass (a run
        # finishing) has had the loop's duration to be released; a
        # witness left on the old name suppresses that run's
        # projections as tamper.
        try:
            from core.project.sessions import ledger_rewrite_pin_project
            ledger_rewrite_pin_project(old_name, new_name)
        except Exception:  # noqa: BLE001 — best-effort retry
            logger.debug("rename: witness rewrite retry failed",
                         exc_info=True)

        logger.info("Renamed project '%s' → '%s'", old_name, new_name)
        return project

    def _save(self, project: Project) -> None:
        """Persist a loaded project back to its JSON file."""
        save_json(self.projects_dir / f"{project.name}.json",
                  project.to_dict())

    def _load_or_raise(self, name: str) -> Project:
        project = self.load(name)
        if not project:
            msg = f"Project '{name}' not found"
            raise ValueError(msg)
        return project

    def _mutation_lock(self, name: str):
        """Project-JSON RMW lock for the mutators below."""
        return project_file_lock(self.projects_dir / f"{name}.json")

    def set_trust_marker(self, name: str, marker: str) -> str:
        """Set a trust marker on a project. Returns the timestamp.
        Raises ValueError for unknown projects or markers. NEVER call
        this from detection heuristics — operator intent only."""
        with self._mutation_lock(name):
            project = self._load_or_raise(name)
            ts = project.set_trust(marker)
            self._save(project)
        logger.info("Project '%s': trust marker '%s' set", name, marker)
        return ts

    def clear_trust_marker(self, name: str, marker: str) -> bool:
        """Remove a trust marker. Returns True if it was set."""
        with self._mutation_lock(name):
            project = self._load_or_raise(name)
            removed = project.clear_trust(marker)
            if removed:
                self._save(project)
        if removed:
            logger.info("Project '%s': trust marker '%s' removed",
                        name, marker)
        return removed

    def update_setting(self, name: str, key: str, value: str) -> Project:
        """Registry-validated setting write on a project."""
        with self._mutation_lock(name):
            project = self._load_or_raise(name)
            project.set_setting(key, value)
            self._save(project)
        return project

    def remove_setting(self, name: str, key: str) -> bool:
        """Remove a setting. Returns True if it was set."""
        with self._mutation_lock(name):
            project = self._load_or_raise(name)
            removed = project.unset_setting(key)
            if removed:
                self._save(project)
        return removed

    def update_notes(self, name: str, notes: str) -> Project:
        """Update project notes."""
        project = self.load(name)
        if not project:
            msg = f"Project '{name}' not found"
            raise ValueError(msg)

        project.notes = notes
        save_json(self.projects_dir / f"{name}.json", project.to_dict())
        return project

    def adopt_target_for(self, directory: str) -> str | None:
        """Infer a project target from a run dir's recorded metadata.

        The retro-create flow (``raptor project adopt``): the run
        already knows which codebase it analysed, so ``--target`` is
        only needed when no run carries metadata. Returns the first
        recorded ``target_path`` found (the directory itself, or its
        first child run), or ``None``.
        """
        src = Path(directory).resolve()
        recorded = _run_target_path(src)
        if recorded is not None:
            return str(recorded)
        if src.is_dir():
            for child in sorted(src.iterdir()):
                if child.is_dir():
                    recorded = _run_target_path(child)
                    if recorded is not None:
                        return str(recorded)
        return None

    def add_directory(self, name: str, directory: str, target: str | None = None,
                      output_dir: str | None = None) -> int:
        """Add existing run directory (or directory of runs) to a project.

        If project doesn't exist and target is provided, creates it.
        Returns the number of runs added.
        """
        project = self.load(name)
        if not project:
            if not target:
                msg = f"Project '{name}' not found. Use --target to create it."
                raise ValueError(msg)
            project = self.create(name, target, output_dir=output_dir)

        src = Path(directory).resolve()
        if not src.exists():
            msg = f"Directory not found: {directory}"
            raise ValueError(msg)

        from core.run import generate_run_metadata, is_run_directory

        added = 0
        skipped = 0
        adopted: list[Path] = []
        dest_base = project.output_path

        def _adopt_one(run_src: Path) -> bool:
            """Move one run in and re-run its completion projections.

            Refuses a run whose recorded target is a DIFFERENT
            codebase — adopting it would poison the project's
            cross-run verdict reuse and coverage store with foreign
            verdicts (the mirror image of the stale-active-project
            footgun). Runs without recorded metadata are admitted:
            the import is operator-gated and the metadata is
            backfilled below.
            """
            recorded = _run_target_path(run_src)
            if recorded is not None and not _same_target(
                    recorded, project.target):
                logger.warning(
                    "adopt refused for %s: run target %s != project "
                    "target %s", run_src.name, recorded, project.target,
                )
                return False
            # Liveness BEFORE the move: write_run_pin refuses live
            # runs, and raising after the move leaves a half-adopted
            # dir (moved, pin not rewritten, projections skipped).
            try:
                from core.run.metadata import (
                    STATUS_RUNNING,
                    _session_alive_for_meta,
                    load_run_metadata,
                )
                _meta = load_run_metadata(run_src) or {}
                if (_meta.get("status") == STATUS_RUNNING
                        and _session_alive_for_meta(_meta)):
                    logger.warning(
                        "adopt refused for %s: the run is live",
                        run_src.name)
                    return False
            except Exception:  # noqa: BLE001 — write_run_pin backstops
                pass
            dest = dest_base / run_src.name
            try:
                dest.mkdir()
            except FileExistsError:
                # Already in the project — but if its pin records a
                # DIFFERENT project (a rename crashed between the
                # registry move and the pin rewrite), re-point it:
                # `project add` is the natural repair an operator
                # reaches for, and skipping silently left the run's
                # projections suppressed with no discoverable remedy.
                try:
                    from core.json import load_json as _lj
                    _m = _lj(dest / ".raptor-run.json",
                             max_bytes=1024 * 1024)
                    _pin = (_m.get("project")
                            if isinstance(_m, dict) else None)
                    # Repair ONLY a pin naming a MISSING project (the
                    # rename-crash artifact): an authoritative pin to
                    # an EXISTING other project — or an explicit
                    # projectless pin — is the run's identity, and
                    # topology must not override it.
                    if (isinstance(_pin, str) and _pin != project.name
                            and self.load(_pin) is None):
                        from core.run.metadata import write_run_pin
                        write_run_pin(dest, project.name, "adopted")
                        logger.info(
                            "adopt: re-pointed the stale pin on "
                            "already-present run %s (named missing "
                            "project %r)", dest.name, _pin)
                    # Witnesses naming missing projects for this dir
                    # get the same repair — a rename that crashed (or
                    # skipped a held ledger) leaves witness=old vs
                    # marker=new, which reads as tamper.
                    from core.project.sessions import (
                        ledger_repair_witnesses_for_dir,
                    )
                    ledger_repair_witnesses_for_dir(
                        dest, project.name,
                        missing=lambda n: self.load(n) is None)
                except Exception:  # noqa: BLE001 — repair best-effort
                    logger.debug("adopt: stale-pin repair failed",
                                 exc_info=True)
                return False
            dest.rmdir()
            try:
                shutil.move(str(run_src), str(dest))
            except (FileNotFoundError, shutil.Error) as e:
                # A concurrent adopt of the same source won the move —
                # skip this run, keep the batch going.
                logger.warning("adopt skipped for %s: %s",
                               run_src.name, e)
                return False
            generate_run_metadata(dest)
            # The move changed the run's governing project: rewrite
            # the pin to the adopting project so the projections
            # below (and every later consumer) resolve HERE — the
            # pre-move pin (a foreign project, or none) must not
            # keep steering a run that now lives in this project.
            from core.run.metadata import write_run_pin
            write_run_pin(dest, project.name, "adopted")
            # An adopted run already had its completion, so the
            # projections that make its data VISIBLE (journal → index
            # merge, reads-manifest conversion, coverage snapshot)
            # never fired for this project. The journal merge is
            # called DIRECTLY with the known project dir — the
            # completion chokepoint infers the project from the run's
            # parent via checklist.json/coverage.json, which a
            # freshly retro-created project does not have yet.
            try:
                from core.coverage.journal import merge_run_into_index
                merged = merge_run_into_index(dest_base, dest)
                if merged:
                    logger.info(
                        "adopt: %d journal entries merged into the "
                        "project index from %s", merged, dest.name,
                    )
            except Exception:
                logger.debug(
                    "adopt: journal merge failed for %s", dest,
                    exc_info=True,
                )
            # Reads-manifest conversion + coverage snapshot keep the
            # completion chokepoint's best-effort semantics (the
            # snapshot no-ops until the project has a checklist).
            from core.run.metadata import project_run_projections
            project_run_projections(dest, project_dir=dest_base)
            adopted.append(dest)
            return True

        # `add_runs` is the user-facing import path — operators
        # explicitly bring in directories that may not have
        # `.raptor-run.json` yet (legacy runs, manually-copied
        # subsets). `generate_run_metadata` below backfills it.
        # Pass `strict=False` so the lenient match still admits
        # those legacy shapes; the import is gated by an explicit
        # operator action so the over-match risk is acceptable here
        # (unlike sweep / cleanup paths which run automatically).
        # Container detection BEFORE the lenient single-run match: a
        # project output dir carries checklist.json at its top level,
        # so the lenient heuristic classified the WHOLE project dir as
        # one run — the entire tree moved in as a single "run", the
        # real runs nested a level down where get_run_dirs can't see
        # them, and the source project's registry pointed at nothing.
        _has_child_runs = any(
            child.is_dir() and is_run_directory(child, strict=True)
            for child in src.iterdir()
        )
        # Run-marker REMNANTS count as run-dir evidence: a hostile
        # child can delete <run>/.raptor-run.json and plant a marker
        # in its own subdir — container semantics would then ADOPT
        # the plant as a first-class run via the operator's repair
        # command. The metadata lock file survives the deletion.
        _run_remnants = (src / ".raptor-run.json.lock").exists()
        # And a src already INSIDE this project's output dir is a
        # REPAIR, never an import of its subdirectories.
        try:
            _inside_project = src.resolve().is_relative_to(
                project.output_path.resolve())
        except (OSError, ValueError):
            _inside_project = False
        _is_container = (not _inside_project
                         and not _run_remnants
                         and ((src / "project.json").is_file()
                              or (_has_child_runs
                                  and not is_run_directory(
                                      src, strict=True))))
        # Inside-project and remnant-bearing dirs take the single-run
        # (repair) path even when the lenient match fails — a
        # marker-destroyed dir with an unprefixed name otherwise fell
        # through to the child-import loop, and the planted subdir was
        # adopted anyway.
        if (_inside_project or _run_remnants
                or (is_run_directory(src, strict=False)
                    and not _is_container)):
            # Single run directory
            if _adopt_one(src):
                added = 1
            else:
                skipped = 1
        else:
            # Directory containing runs
            for child in sorted(src.iterdir()):
                if child.is_dir() and is_run_directory(child, strict=False):
                    if _adopt_one(child):
                        added += 1
                    else:
                        skipped += 1

        if added:
            logger.info("Added %d run(s) to project '%s'", added, name)
            self._ensure_adopted_coverage(project, adopted)
        if skipped:
            logger.info("Skipped %d run(s) already in project '%s'", skipped, name)
        return added

    def _ensure_adopted_coverage(self, project: Project,
                                 adopted: list[Path]) -> None:
        """Make adopted runs' coverage reach the durable project store.

        ``_snapshot_run_coverage`` no-ops when the project directory has
        no ``checklist.json`` — and a freshly retro-created project has
        none, so the projections re-run at adoption merged the journal
        but never landed the coverage snapshot. Build the project
        checklist from the project target with the same inventory
        builder the run lifecycle uses (one bounded inventory pass —
        the cost the next lifecycle run would have paid anyway), then
        re-run the projections for each adopted run so the snapshot
        lands now instead of silently waiting for a future run.

        Best-effort by contract: adoption already moved the runs, so
        nothing here may raise. A missing target is a silent skip (the
        codebase may have been deleted since the runs completed); a
        checklist build failure logs and leaves the pre-existing
        behaviour (snapshot deferred to the next lifecycle run).
        """
        checklist_path = project.output_path / "checklist.json"
        if checklist_path.exists() or not adopted:
            return
        target = Path(project.target)
        if not target.exists():
            return  # target gone — nothing to inventory
        try:
            from core.inventory import build_inventory
            inventory = build_inventory(str(target), str(project.output_path))
            logger.info(
                "adopt: built project checklist from %s (%d files, "
                "%d items) so adopted coverage reaches the durable store",
                target, inventory.get("total_files", 0),
                inventory.get("total_items", 0),
            )
        except Exception:
            logger.info(
                "adopt: project checklist build failed for %s — adopted "
                "coverage lands on the next lifecycle run instead", target,
            )
            logger.debug("adopt: checklist build failure detail",
                         exc_info=True)
            return
        from core.run.metadata import project_run_projections
        for dest in adopted:
            project_run_projections(dest, project_dir=project.output_path)

    def remove_run(self, name: str, run_name: str,
                   to_path: str | None = None,
                   force: bool = False) -> None:
        """Remove a run from the project directory.

        Moves the run to to_path. Does not delete. ``force`` overrides
        the live-run refusal (foreign-stamped metadata reads as
        unverifiable-alive forever).
        """
        project = self.load(name)
        if not project:
            msg = f"Project '{name}' not found"
            raise ValueError(msg)

        if not to_path:
            msg = "--to is required: specify where to move the run"
            raise ValueError(msg)

        # run_name must be a direct child NAME, never a path: the
        # unvalidated join let "../victim" move an arbitrary directory
        # out from under its owner (and stamp a pin file into it).
        if (os.sep in run_name or (os.altsep and os.altsep in run_name)
                or run_name in (".", "..") or not run_name):
            msg = f"Invalid run name {run_name!r} — pass a run directory name, not a path"
            raise ValueError(msg)
        run_dir = project.output_path / run_name
        if not run_dir.exists():
            msg = f"Run '{run_name}' not found in project '{name}'"
            raise ValueError(msg)
        # Never relocate a run in flight — same live-run protection
        # clean/merge/delete have.
        from core.run.metadata import (
            STATUS_RUNNING,
            _session_alive_for_meta,
            load_run_metadata,
        )
        meta = load_run_metadata(run_dir) or {}
        if (not force and meta.get("status") == STATUS_RUNNING
                and _session_alive_for_meta(meta)):
            # Same session-liveness rule the other live-run guards use
            # — a crashed run stuck at 'running' stays removable.
            msg = (f"Run '{run_name}' is still running — wait for it "
                   "to finish (or fail it) before removing, or pass "
                   "--force")
            raise ValueError(msg)

        dest = Path(to_path)
        dest.mkdir(parents=True, exist_ok=True)
        shutil.move(str(run_dir), str(dest / run_name))
        # The run left the project: clear its pin so consumers of the
        # moved dir don't keep writing into (or reading trust from)
        # a project it no longer belongs to.
        try:
            from core.run.metadata import write_run_pin
            write_run_pin(dest / run_name, None, "none")
        except Exception:  # noqa: BLE001 — the move itself succeeded
            logger.warning(
                "could not clear the project pin on %s — edit its "
                ".raptor-run.json 'project' field manually",
                dest / run_name, exc_info=True)
        logger.info("Moved '%s' to %s", run_name, to_path)

    def set_active(self, name: str | None = None) -> None:
        """Set the active project symlink. Pass None to clear.

        The symlink is the single source of truth for project state.
        Uses atomic create-temp-then-rename to avoid TOCTOU races.

        Per-process tmp-link name + name validation: pre-fix the
        tmp link was a fixed `.active.tmp`, so two concurrent
        `set_active` calls (rare but possible: two parallel
        `/project use X` invocations, or a CLI race with a hook
        fire) collided on the same tmp path. Each call's
        `tmp_link.unlink(missing_ok=True)` then
        `tmp_link.symlink_to(...)` lost the race — the second
        caller's symlink_to would EEXIST against the first's
        symlink in the gap between unlink and symlink_to,
        crashing the second caller. Or worse, if both passed
        their unlinks, both succeeded at symlink_to (different
        targets), and `os.rename` was last-writer-wins with no
        signal which name "won".

        Suffix the tmp link with the PID so concurrent callers
        each get their own tmp slot. The final `os.rename` is
        still atomic and last-writer-wins — that's expected
        semantics for "set the active project" — but the
        intermediate setup no longer races.

        Also validate `name` to refuse path traversal /
        directory-separator injection. Pre-fix `name` flowed
        straight into `f"{name}.json"` symlink target —
        `name="../../../etc/passwd"` would create a symlink
        pointing outside the projects dir. The existing
        `_validate_name` covers project create / load; mirror
        it here for the symlink target.
        """
        import os
        if name is not None:
            self._validate_name(name)
        active_link = self.projects_dir / ".active"
        auto_marker = self.projects_dir / ".auto"
        auto_marker.unlink(missing_ok=True)
        if name is not None:
            # Per-process tmp slot — see docstring.
            # pid+tid suffix — two threads in the same process can race
            # on set_active(); tid disambiguates. Mirrors core/json
            # tempfile pattern.
            import threading
            tmp_link = self.projects_dir / f".active.tmp.{os.getpid()}.{threading.get_ident()}"
            tmp_link.unlink(missing_ok=True)
            tmp_link.symlink_to(f"{name}.json")
            os.rename(str(tmp_link), str(active_link))
        else:
            active_link.unlink(missing_ok=True)

    def get_active(self) -> str | None:
        """The active project for THIS context — layered.

        1. **Session binding** (authoritative v2 registry entry): the
           session's own project. Bound-to-none is authoritative — it
           never falls through to the symlink. A stale binding
           (project deleted) reads as None with a warning, never as
           another layer's project.
        2. **`.active` symlink** — the LAST-ACTIVATED bookmark: serves
           bare shells, pre-series (v1/advisory) sessions, and
           sessions whose entry is absent.

        Consumes machine-project auto-expiry on BOTH layers, and the
        remediation clears only the layer that produced the name: an
        expired binding is re-bound to none (the machine-wide bookmark
        — which may point at a different, healthy project that other
        sessions seed from — is never collateral); an expired symlink
        is unlinked, as before. Operator projects are never expired;
        ``/project use <name>`` clears the marker.
        """
        try:
            from core.project.sessions import bind_session, session_binding
            name, state = session_binding()
        except Exception:  # noqa: BLE001 — registry failure = symlink layer
            logger.debug("session binding resolution failed", exc_info=True)
            name, state = None, "absent"
        if state == "bound" and name is not None:
            project_file = self.projects_dir / f"{name}.json"
            if not project_file.exists():
                logger.warning(
                    "Session is bound to missing project '%s' "
                    "(deleted/renamed?) — authoritatively projectless. "
                    "Re-bind with '/project use <name>'.", name,
                )
                return None
            if is_machine_project_name(name):
                project = self.load(name)
                if (project is not None
                        and project.is_expired_machine_project()):
                    logger.warning(
                        "Session-bound project '%s' is a machine-"
                        "generated project past its auto-expiry (%s) — "
                        "clearing THIS SESSION's binding (the "
                        "last-activated default is untouched). "
                        "Re-activate explicitly with '/project use %s' "
                        "to keep it (this clears the expiry).",
                        name, project.expires_at, name,
                    )
                    with contextlib.suppress(Exception):
                        bind_session(None)
                    return None
            return name
        if state == "none":
            return None

        active_link = self.projects_dir / ".active"
        if active_link.is_symlink():
            target = os.readlink(active_link)
            if target.endswith(".json") and "/" not in target and "\\" not in target:
                project_file = self.projects_dir / target
                if project_file.exists():
                    name = target[:-5]
                    if is_machine_project_name(name):
                        project = self.load(name)
                        if (project is not None
                                and project.is_expired_machine_project()):
                            logger.warning(
                                "Active project '%s' is a machine-"
                                "generated project past its auto-expiry "
                                "(%s) — deactivating. Re-activate "
                                "explicitly with '/project use %s' to "
                                "keep it (this clears the expiry).",
                                name, project.expires_at, name,
                            )
                            active_link.unlink(missing_ok=True)
                            return None
                    return name
                # Dangling — clean up, but only if the link still
                # names the dangling target we just read: another
                # process may have re-pointed it to a healthy project
                # in between, and a path-based unlink would destroy
                # the fresh bookmark.
                with contextlib.suppress(OSError):
                    if os.readlink(active_link) == target:
                        active_link.unlink(missing_ok=True)
        return None

    def find_project_for_target(
        self, target: str, content_id: str | None = None,
    ) -> Project | None:
        """Auto-detect a project for the given target.

        Path match first (unchanged default). When ``content_id`` is supplied
        and no project's path matches, fall back to a content match: a project
        whose durable store carries the same content-equivalence id. This is
        what lets a git checkout and a zip extraction of identical source share
        one project/store even though their ``target`` paths differ. Callers
        that have built an inventory pass its ``content_identity``; callers that
        haven't pass nothing and get the original path-only behaviour."""
        resolved = (
            _normalize_url_target(target)
            if _URL_SCHEME_RE.match(target)
            else str(Path(target).resolve())
        )
        for project in self.list_projects():
            if project.target == resolved:
                return project
        if content_id:
            return self.find_project_by_content_id(content_id)
        return None

    def find_project_by_content_id(self, content_id: str) -> Project | None:
        """Find a project whose durable store carries ``content_id`` (the
        content-equivalence id). Returns ``None`` if none match."""
        if not content_id:
            return None
        for project in self.list_projects():
            if project.content_id == content_id:
                return project
        return None


def is_project_output_dir(directory: Path,
                          exact: bool = False) -> bool:
    """Check whether *directory* is a managed project output directory.

    Returns True when *directory* matches any known project's
    ``output_dir``, or falls under the default project output base
    (``out/projects/``). This is used to decide whether sibling
    directories should share state (strategy weights, project context,
    learnings). When False, sibling enumeration must validate each
    sibling's target path to prevent cross-project contamination.

    ``exact=True`` matches only a project output dir ITSELF (or the
    projects base) — never a descendant. The pin walk's boundary needs
    this: with descendant matching, the walk stopped at the first
    parent for any run inside a project dir, so the NEAREST marker won
    and a child could plant one in its own writable subdir — the exact
    capture the outermost-marker rule exists to kill.
    """
    resolved = directory.resolve()
    default_base = DEFAULT_OUTPUT_BASE.resolve()
    if exact:
        if resolved == default_base:
            return True
        # Direct children of the base are project dirs by convention.
        if resolved.parent == default_base:
            return True
    else:
        try:
            resolved.relative_to(default_base)
            return True
        except ValueError:
            pass
    try:
        mgr = ProjectManager()
        for project in mgr.list_projects():
            if project.output_path.resolve() == resolved:
                return True
    except (OSError, ValueError):
        # Best-effort check, default False. OSError: registry dir /
        # glob / resolve failures; ValueError: NUL bytes in a
        # hand-edited project file's output_dir path.
        pass
    return False
