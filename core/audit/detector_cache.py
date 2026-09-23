"""Cross-run reload cache for the mechanical-detector prep pass.

The mechanical-detector battery (condition chain, structural
detectors, standing Coccinelle rules) is a per-run fixed cost
recomputed over every checklist file even when nothing changed.
Results ride the prep-cache seam (:mod:`core.audit.prep_cache`) in one
artifact under ``<out_dir>/prep-cache/``, keyed at three granularities:

- The prep-cache **fingerprint** is the detector-set identity: a hash
  over the source bytes of every module whose code shapes detector
  output (including the orchestrator glue that formats descriptions,
  and this module). Any detector code change invalidates the whole
  artifact — honest by construction, no per-detector version constants
  to forget to bump.
- Each **lane** (condition / structural / cocci) carries an inputs
  digest over the non-per-file data and environment inputs that can
  change its results (sink vocabulary, solver availability, gap
  spans, call-graph input bytes, learned domain vocabulary, spatch
  version + rule bytes). A stale lane digest drops that lane only.
- **Per-file entries** (condition and cocci lanes) carry the file's
  content hash (and, for cocci, the file's gap spans): unchanged
  files reload, changed files recompute — partial invalidation.

Doctrine (inherited from prep_cache): the key must cover every input
that can change the payload; anything that cannot be fingerprinted
(a live Joern server's whole-program CPG state) must not be cached.
Corrupt or shape-broken entries degrade to recompute, never to an
error and never to a silently-skipped detector.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .prep_cache import (
    content_fingerprint,
    load_prep_cache,
    prep_cache_path,
    source_fingerprint,
    write_prep_cache,
)

logger = logging.getLogger(__name__)

DETECTOR_CACHE_FILENAME = "mechanical-detectors-cache.json"

#: Serialized-payload write cap. Larger: huge trees keep their cache
#: at the cost of a prep-cache artifact that can dominate the run dir
#: and whose json parse on load starts competing with the recompute it
#: replaces. Smaller: big targets silently lose caching and pay the
#: full battery every run. 64 MiB matches the orchestrator's
#: findings-class artifact read budget (_MAX_ARTIFACT_BYTES).
MAX_CACHE_BYTES = 64 * 1024 * 1024

#: The modules whose FUNCTIONS produce cached records: the condition
#: chain, the structural cache_ok detectors, the cocci lane (runner +
#: the dispatch table selecting the standing rules), and the shared
#: cached-input builders (call-graph extraction; the vocabulary
#: builder). return_domain and condition_cpg are deliberately absent:
#: their results never replay from this cache (return_domain always
#: recomputes; condition_cpg only runs under a live Joern server,
#: which makes the condition lane uncacheable).
DETECTOR_ENTRY_POINTS: tuple[str, ...] = (
    "core.audit.condition_extraction",
    "core.audit.condition_adequacy",
    "core.audit.condition_binding",
    "core.audit.condition_smt",
    "core.audit.sentinel_collapse",
    "core.audit.fail_open_detector",
    "core.audit.pattern_completeness",
    "core.audit.callsite_consistency",
    "core.audit.block_sibling_analysis",
    "core.audit.dispatch_completeness",
    "core.audit.transform_sequence",
    "core.audit.value_space_checker",
    "core.audit.type_confusion",
    "core.audit.callback_lifetime",
    "core.audit.auth_witnesses",
    "core.audit.check_then_create",
    "core.audit.asn1_template_mismatch",
    "packages.coccinelle.runner",
    "core.audit.cwe_dispatch",
    "core.inventory.call_graph",
    "core.audit.vocab_packs",
)

#: Glue outside the entry points' import closure that still shapes
#: cached bytes: the orchestrator formats descriptions and runs the
#: attribution loops; this module and the prep-cache seam define the
#: key and payload semantics.
_GLUE_MODULES: tuple[str, ...] = (
    "core.audit.orchestrator",
    "core.audit.detector_cache",
    "core.audit.prep_cache",
)

#: Modules reachable from the entry points that provably do NOT shape
#: cached records — pruned from the closure (and from its traversal,
#: so their private subsystems never over-key the cache). Every entry
#: needs a reachability witness in the tests: an exemption nothing
#: imports any more is stale, and a refactor that moves one onto a
#: result path must be caught in review.
CLOSURE_EXEMPT: dict[str, str] = {
    "core.audit.prompt_defence": (
        "prompt-format-only: imported for sanitise_for_prompt, called "
        "exclusively from the format_*_for_prompt renderers — never on "
        "the detect paths whose records this cache replays"
    ),
    "core.audit.cross_function_verify": (
        "Joern-leg-only: imported inside callsite_consistency's "
        "_extract_callsites_cpg, which runs only with a live server — "
        "and a live server makes the detector uncacheable"
    ),
    "packages.joern.runner": (
        "Joern-leg-only: imported inside type_confusion's CPG "
        "confidence-boost leg, which runs only with a live server — "
        "and a live server makes the detector uncacheable"
    ),
}

_IN_REPO_TOP = ("core", "packages")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_module_file(name: str, root: Path) -> Path | None:
    """In-repo source file for a dotted module name, else None."""
    if not name or name.split(".")[0] not in _IN_REPO_TOP:
        return None
    rel = Path(*name.split("."))
    candidate = root / rel.with_suffix(".py")
    if candidate.is_file():
        return candidate
    candidate = root / rel / "__init__.py"
    if candidate.is_file():
        return candidate
    return None


def _is_type_checking_test(test: ast.expr) -> bool:
    return (
        isinstance(test, ast.Name) and test.id == "TYPE_CHECKING"
    ) or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _module_imports(name: str, path: Path, root: Path) -> set[str]:
    """In-repo modules *name* imports (module-level AND function-local;
    ``if TYPE_CHECKING:`` bodies excluded — they never execute).

    ``from PKG import sub`` where ``sub`` is a module adds ``PKG.sub``
    only; when any imported name is not a submodule the package's
    ``__init__`` is added instead (that is where the name lives).
    Package-``__init__`` re-export side effects of plain submodule
    imports are deliberately NOT traversed — the registry tracks the
    modules whose code the detect paths execute — and dynamic imports
    are a documented residual: both string-based imports
    (``importlib.import_module`` on a computed name) and PEP 562 lazy
    re-exports (module-level ``__getattr__``) are invisible to this
    AST walk. One detect path traverses a PEP 562 hop today:
    vocab_packs' ``from core.json import load_json`` resolves through
    ``core.json.__getattr__`` into ``core.json.utils`` — which stays
    in the closure anyway via unrelated static importers.
    """
    try:
        tree = ast.parse(
            path.read_text(encoding="utf-8", errors="replace"),
        )
    except SyntaxError:
        return set()
    pkg_parts = name.split(".")
    if path.name != "__init__.py":
        pkg_parts = pkg_parts[:-1]
    out: set[str] = set()

    def handle(child: ast.AST) -> None:
        if isinstance(child, ast.Import):
            for alias in child.names:
                if _resolve_module_file(alias.name, root) is not None:
                    out.add(alias.name)
        elif isinstance(child, ast.ImportFrom):
            if child.level:
                base = pkg_parts[: len(pkg_parts) - (child.level - 1)]
                mod = ".".join(
                    base + ([child.module] if child.module else []),
                )
            else:
                mod = child.module or ""
            if not mod:
                return
            any_non_module = False
            for alias in child.names:
                sub = f"{mod}.{alias.name}"
                if _resolve_module_file(sub, root) is not None:
                    out.add(sub)
                else:
                    any_non_module = True
            if any_non_module and _resolve_module_file(
                mod, root,
            ) is not None:
                out.add(mod)

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If) and _is_type_checking_test(
                child.test,
            ):
                for stmt in child.orelse:
                    handle(stmt)
                    visit(stmt)
                continue
            handle(child)
            visit(child)

    visit(tree)
    return out


def import_closure(
    entries: tuple[str, ...],
    *,
    exempt: frozenset[str] = frozenset(),
    root: Path | None = None,
) -> frozenset[str]:
    """Transitive in-repo import closure of *entries*, minus *exempt*
    (exempt modules are pruned from traversal too, so nothing they
    privately import enters the closure through them)."""
    root = root or _repo_root()
    seen: set[str] = set()
    queue = [m for m in entries if m not in exempt]
    while queue:
        name = queue.pop()
        if name in seen or name in exempt:
            continue
        path = _resolve_module_file(name, root)
        if path is None:
            continue
        seen.add(name)
        queue.extend(_module_imports(name, path, root) - seen)
    return frozenset(seen)


_detector_modules_memo: list[tuple[str, ...]] = []


def detector_modules() -> tuple[str, ...]:
    """Every module whose code shapes cached detector records: the
    entry points, their transitive in-repo import closure, and the
    glue. Derived, not hand-listed — a detector growing a helper
    dependency joins the identity automatically, so the registry can
    never silently rot. The walk costs about a second once per
    process, small next to the battery it keys. Transitive
    third-party engines (tree-sitter grammars, z3, spatch) are
    captured as environment markers in the lane keys instead.
    """
    if _detector_modules_memo:
        return _detector_modules_memo[0]
    closure = import_closure(
        DETECTOR_ENTRY_POINTS, exempt=frozenset(CLOSURE_EXEMPT),
    )
    modules = tuple(sorted(closure | set(_GLUE_MODULES)))
    _detector_modules_memo.append(modules)
    return modules


def _module_source_bytes(name: str) -> bytes:
    """Source bytes for a registry module. Repo-path resolution first
    (no import side effects); the ``sys.modules``/import fallback
    covers test doubles. Unreadable modules hash as an explicit
    absence marker — their state still participates in the identity.
    """
    path = _resolve_module_file(name, _repo_root())
    if path is None:
        try:
            mod = importlib.import_module(name)
            path = Path(mod.__file__ or "")
        except Exception:
            return b"<module-unavailable>"
    try:
        return path.read_bytes()
    except OSError:
        return b"<module-unavailable>"


_module_fp_memo: dict[tuple[str, ...], str] = {}


def detector_set_fingerprint(
    modules: tuple[str, ...] | None = None,
) -> str:
    """Hash of the detector-set modules' source bytes (code identity).

    Module source is immutable within a process, so the result is
    memoized per module tuple.
    """
    if modules is None:
        modules = detector_modules()
    memo = _module_fp_memo.get(modules)
    if memo is not None:
        return memo
    fp = content_fingerprint(
        (name, _module_source_bytes(name)) for name in modules
    )
    _module_fp_memo[modules] = fp
    return fp


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# -- environment markers ------------------------------------------------
# Third-party engines whose presence or version changes detector
# output but whose code the module hash cannot see. Memoized per
# process: installs do not change under a running audit.

_env_marker_memo: dict[str, str] = {}


def tree_sitter_marker() -> str:
    """Installed tree-sitter core + grammar distribution versions.

    Grammar availability flips several detectors between tree-sitter
    and regex extraction paths, changing their findings.
    """
    memo = _env_marker_memo.get("ts")
    if memo is not None:
        return memo
    try:
        from importlib.metadata import distributions

        pairs = sorted(
            {
                f"{name}={dist.version}"
                for dist in distributions()
                if (
                    name := (dist.metadata["Name"] or "").lower()
                ).startswith("tree-sitter")
            },
        )
        marker = "ts:" + (",".join(pairs) if pairs else "absent")
    except Exception:
        marker = "ts:unknown"
    _env_marker_memo["ts"] = marker
    return marker


def z3_marker() -> str:
    """z3 availability + version. The SMT checkers degrade to
    arithmetic fallbacks without z3, changing sufficiency verdicts
    (and, through them, guard-clean resolution)."""
    memo = _env_marker_memo.get("z3")
    if memo is not None:
        return memo
    try:
        import importlib.util
        from importlib.metadata import version as _dist_version

        if importlib.util.find_spec("z3") is None:
            marker = "z3:absent"
        else:
            try:
                marker = f"z3:{_dist_version('z3-solver')}"
            except Exception:
                marker = "z3:present-unversioned"
    except Exception:
        marker = "z3:unknown"
    _env_marker_memo["z3"] = marker
    return marker


def spatch_marker() -> str:
    """spatch availability + version (pre-1.3 spatch silently fails
    to parse some standing rules, so the version changes results)."""
    memo = _env_marker_memo.get("spatch")
    if memo is not None:
        return memo
    try:
        from packages.coccinelle.runner import (
            is_available as _spatch_available,
        )
        from packages.coccinelle.runner import (
            version as _spatch_version,
        )

        if not _spatch_available():
            marker = "spatch:absent"
        else:
            marker = (
                f"spatch:{_spatch_version() or 'present-unversioned'}"
            )
    except Exception:
        marker = "spatch:unknown"
    _env_marker_memo["spatch"] = marker
    return marker


def digest_strings(parts: Iterable[str]) -> str:
    """Order-sensitive digest of string parts (callers pre-sort
    order-free inputs).

    Length-prefixed framing: a bare NUL joint collides for parts
    that themselves contain NUL (``("a\\0", "b")`` and
    ``("a", "\\0b")`` hash the same byte stream). Current callers
    feed rule text and gap fields that cannot carry raw NUL, so the
    collision is latent — but these are cache keys over
    target-derived content, and framing by length closes the class
    outright (one-time cache invalidation on upgrade is the cost of
    a cache, not a behaviour change).
    """
    h = hashlib.sha256()
    for part in parts:
        data = part.encode("utf-8", "replace")
        h.update(str(len(data)).encode("ascii"))
        h.update(b":")
        h.update(data)
    return h.hexdigest()


def gap_spans_digest(gaps: Iterable[dict[str, Any]]) -> str:
    """Digest of the gap fields the detectors consume, in gap order.

    Order matters: the attribution loops (asn1, cocci, callback)
    take the FIRST gap whose span contains a finding line. Volatile
    scheduling fields (priority, scores) are deliberately excluded —
    they never reach a detector, and including them would invalidate
    the cache on every reprioritisation.
    """
    return digest_strings(
        json.dumps(
            [
                g.get("file", ""),
                g.get("name", ""),
                g.get("line_start", 0),
                g.get("line_end", 0),
                g.get("kind", ""),
            ],
            default=str,
        )
        for g in gaps
    )


def vocabulary_digest(vocab: Any) -> str | None:
    """Deterministic digest of a DomainVocabulary (or None).

    Field values are frozensets of strings or provenance dicts; the
    per-member ``repr`` is stable for both given the same source
    domain-model file. Returns None when the vocabulary cannot be
    digested — callers must treat that as uncacheable (a constant
    failure marker would collide two DIFFERENT undigestable
    vocabularies into one key component and serve one's records for
    the other).
    """
    if vocab is None:
        return "vocab:none"
    parts: list[str] = []
    try:
        for f in sorted(
            dataclasses.fields(vocab), key=lambda f: f.name,
        ):
            value = getattr(vocab, f.name)
            parts.append(f.name)
            parts.extend(sorted(repr(v) for v in value))
    except Exception:
        logger.debug("vocabulary digest failed", exc_info=True)
        return None
    return digest_strings(parts)


def call_graph_inputs_fingerprint(
    target_path: Path | str,
    checklist: dict[str, Any] | None,
) -> str | None:
    """Fingerprint of the bytes the call-graph build would read.

    Enumerated by the loader's own candidate chain
    (:func:`core.inventory.call_graph.iter_call_graph_candidates`) so
    the fingerprint and the build can never drift. Hashing the bytes
    is a small fraction of re-running the structural battery. None on
    enumeration failure — callers must treat that as uncacheable.
    """
    try:
        from core.inventory.call_graph import (
            CALL_GRAPH_MAX_FILE_BYTES,
            iter_call_graph_candidates,
        )

        def _items() -> Iterable[tuple[str, bytes]]:
            # Over-keys relative to the build's gates in the safe
            # direction: candidates past the build's max_files cap are
            # still fingerprinted (their edits over-invalidate, never
            # under). Oversized files hash as a size marker — the
            # build skips their content, so content edits below the
            # threshold cannot change the graphs, while crossing the
            # threshold flips marker vs bytes.
            for rel, path, decl_language in iter_call_graph_candidates(
                target_path, checklist,
            ):
                try:
                    if path.stat().st_size > CALL_GRAPH_MAX_FILE_BYTES:
                        data = b"<oversized>"
                    else:
                        data = path.read_bytes()
                except OSError:
                    data = b"<unreadable>"
                yield (f"{rel}\0{decl_language or ''}", data)

        return content_fingerprint(_items())
    except Exception:
        logger.debug(
            "call-graph inputs fingerprint failed", exc_info=True,
        )
        return None


def _findings_ok(records: Any) -> bool:
    """Shape check for a cached finding-record list: every record must
    replay through ``_add(file, func, detector, line, description)``."""
    if not isinstance(records, list):
        return False
    for rec in records:
        if not (isinstance(rec, list) and len(rec) == 5):
            return False
        if not all(isinstance(rec[i], str) for i in (0, 1, 2, 4)):
            return False
        # bool is an int subclass; a True line number is a corrupt
        # record, not a replayable one.
        if not isinstance(rec[3], int) or isinstance(rec[3], bool):
            return False
    return True


def _str_list_ok(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(v, str) for v in value
    )


class MechanicalDetectorCache:
    """One run's view of the cross-run mechanical-detector cache.

    ``open`` loads the prior payload (empty on miss / detector-set
    change / corruption); the ``cached_*`` accessors serve entries
    only when every key component matches; the ``store_*`` mutators
    build the NEXT payload from this run's results (so entries for
    files that left the checklist are dropped on write — the artifact
    is self-pruning); ``save`` persists atomically, best-effort,
    size-capped.
    """

    def __init__(
        self,
        out_dir: Path | None,
        fingerprint: str,
        prior: dict[str, Any],
    ) -> None:
        self._out_dir = out_dir
        self._fingerprint = fingerprint
        self._prior = prior
        self._next: dict[str, Any] = {
            "condition": {"inputs": "", "files": {}},
            "structural": {"inputs": "", "detectors": {}},
            "cocci": {"inputs": "", "files": {}},
        }

    # -- construction --------------------------------------------------

    @classmethod
    def open(
        cls, out_dir: Path | str | None,
    ) -> "MechanicalDetectorCache":
        fingerprint = detector_set_fingerprint()
        prior: dict[str, Any] = {}
        if out_dir is not None:
            payload = load_prep_cache(
                out_dir, DETECTOR_CACHE_FILENAME, fingerprint,
                label="mechanical-detectors",
            )
            if isinstance(payload, dict):
                prior = payload
        return cls(
            Path(out_dir) if out_dir is not None else None,
            fingerprint, prior,
        )

    @property
    def enabled(self) -> bool:
        return self._out_dir is not None

    # -- lane helpers ---------------------------------------------------

    def _prior_lane(self, lane: str, inputs_key: str) -> dict[str, Any]:
        """The prior lane dict, or empty when its inputs digest is
        stale (lane-level invalidation)."""
        section = self._prior.get(lane)
        if (
            isinstance(section, dict)
            and section.get("inputs") == inputs_key
        ):
            return section
        return {}

    # -- condition lane -------------------------------------------------

    def cached_condition(
        self, inputs_key: str, rel: str, content_sha: str,
    ) -> dict[str, Any] | None:
        """The per-file condition-lane entry, or None to recompute."""
        files = self._prior_lane("condition", inputs_key).get("files")
        entry = files.get(rel) if isinstance(files, dict) else None
        if not isinstance(entry, dict):
            return None
        if entry.get("content") != content_sha:
            return None
        if not _findings_ok(entry.get("findings")):
            return None
        sufficient = entry.get("sufficient")
        if not isinstance(sufficient, dict) or not all(
            isinstance(k, str) and isinstance(v, bool)
            for k, v in sufficient.items()
        ):
            return None
        for key in ("guarded", "decorative", "smt_insufficient"):
            if not _str_list_ok(entry.get(key)):
                return None
        return entry

    def store_condition(
        self, inputs_key: str, rel: str, entry: dict[str, Any],
    ) -> None:
        self._next["condition"]["inputs"] = inputs_key
        self._next["condition"]["files"][rel] = entry

    # -- structural lane ------------------------------------------------

    def cached_structural(
        self, inputs_key: str, detector: str,
    ) -> list[Any] | None:
        """The named detector's cached records, or None to recompute.

        A detector absent from the stored map is a miss even when the
        lane digest matches (it was uncacheable on the storing run —
        e.g. computed against a live Joern server, or it raised).
        """
        detectors = self._prior_lane("structural", inputs_key).get(
            "detectors",
        )
        if not isinstance(detectors, dict):
            return None
        records = detectors.get(detector)
        if records is None or not _findings_ok(records):
            return None
        return records

    def store_structural(
        self, inputs_key: str, detector: str, records: list[Any],
    ) -> None:
        self._next["structural"]["inputs"] = inputs_key
        self._next["structural"]["detectors"][detector] = records

    # -- cocci lane -----------------------------------------------------

    def cached_cocci(
        self,
        inputs_key: str,
        rel: str,
        content_sha: str,
        gaps_sha: str,
    ) -> list[Any] | None:
        files = self._prior_lane("cocci", inputs_key).get("files")
        entry = files.get(rel) if isinstance(files, dict) else None
        if not isinstance(entry, dict):
            return None
        if entry.get("content") != content_sha:
            return None
        if entry.get("gaps") != gaps_sha:
            return None
        findings = entry.get("findings")
        if not _findings_ok(findings):
            return None
        return findings

    def store_cocci(
        self,
        inputs_key: str,
        rel: str,
        content_sha: str,
        gaps_sha: str,
        findings: list[Any],
    ) -> None:
        self._next["cocci"]["inputs"] = inputs_key
        self._next["cocci"]["files"][rel] = {
            "content": content_sha,
            "gaps": gaps_sha,
            "findings": findings,
        }

    # -- persistence ----------------------------------------------------

    def save(self) -> None:
        """Persist this run's payload (atomic, best-effort, capped)."""
        if self._out_dir is None:
            return
        # A lane this run never stored into (Joern-present condition
        # lane, spatch-absent cocci lane) carries the PRIOR lane
        # forward instead of wiping it: entries are self-validating
        # against their input digests, so keeping them costs only
        # bounded disk while dropping them would cold-start the next
        # run that could have served them.
        for lane in ("condition", "structural", "cocci"):
            if not self._next[lane].get("inputs"):
                prior = self._prior.get(lane)
                if isinstance(prior, dict) and prior.get("inputs"):
                    self._next[lane] = prior
        try:
            blob_len = len(json.dumps(self._next))
        except (TypeError, ValueError):
            logger.debug(
                "mechanical-detector cache payload unserialisable — "
                "not persisted", exc_info=True,
            )
            return
        if blob_len > MAX_CACHE_BYTES:
            logger.debug(
                "mechanical-detector cache payload %d bytes exceeds "
                "the %d-byte cap — not persisted",
                blob_len, MAX_CACHE_BYTES,
            )
            # Declining to persist must also enforce the bound on
            # what is already on disk — otherwise the previous
            # artifact (from when the tree was under the cap) lingers
            # indefinitely. Removal is safe: entries self-validate,
            # so the only cost is one recompute.
            try:
                prep_cache_path(
                    self._out_dir, DETECTOR_CACHE_FILENAME,
                ).unlink(missing_ok=True)
            except OSError:
                logger.debug(
                    "stale mechanical-detector cache unlink failed",
                    exc_info=True,
                )
            return
        write_prep_cache(
            self._out_dir, DETECTOR_CACHE_FILENAME, self._fingerprint,
            self._next, label="mechanical-detectors",
        )


def file_content_sha(text: str) -> str:
    return _sha_text(text)


__all__ = [
    "CLOSURE_EXEMPT",
    "DETECTOR_CACHE_FILENAME",
    "DETECTOR_ENTRY_POINTS",
    "MAX_CACHE_BYTES",
    "MechanicalDetectorCache",
    "call_graph_inputs_fingerprint",
    "detector_modules",
    "detector_set_fingerprint",
    "digest_strings",
    "file_content_sha",
    "gap_spans_digest",
    "import_closure",
    "source_fingerprint",
    "spatch_marker",
    "tree_sitter_marker",
    "vocabulary_digest",
    "z3_marker",
]
