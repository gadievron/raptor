"""CodeQL tool runner for the IRIS refinement loop.

Adapts ``compile_codeql_config`` → temp QL pack → ``run_local_pack``
→ SARIF parse → ``RefinementFeedback``.  Plugs into ``refine_loop``'s
``tool_runner`` slot alongside (or instead of) the Joern runner.
"""

from __future__ import annotations

import logging
import re
from typing import Any, TYPE_CHECKING

from core.run.scratch import scratch_dir
from core.sarif.parser import load_sarif

from .refine import RefinementFeedback
from .specs import (
    CODEQL_QUERY_LANGUAGES,
    TaintSpec,
    compile_codeql_config,
)
from .store import _spec_key

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_QLPACK_TEMPLATE = """\
name: raptor/iris-refinement
version: 0.0.1
dependencies:
  codeql/{lang}-all: "*"
"""


def _write_temp_pack(
    query_text: str,
    language: str,
    tmp_root: Path,
) -> Path:
    """Write a temporary QL pack containing the generated query."""
    pack_dir = tmp_root / "iris-pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "qlpack.yml").write_text(
        _QLPACK_TEMPLATE.replace("{lang}", language),
    )
    (pack_dir / "IrisSpecs.ql").write_text(query_text)
    return pack_dir


def _parse_sarif_matches(sarif_path: Path) -> list[dict[str, Any]] | None:
    """Extract match records from a SARIF file — ``None`` when the
    file is unreadable.

    Bounded canonical loader (100 MiB stat gate before the read): the
    SARIF is CodeQL output over the analysed target, which can inflate
    it through paths and snippets. The refusal must surface as None,
    not an empty match list — an empty list reads downstream as a
    successfully evaluated zero-confirmation round, silently dropping
    every confirmation the analyze actually produced."""
    data = load_sarif(sarif_path)
    if data is None:
        return None
    runs = data.get("runs")
    if not isinstance(runs, list):
        # load_sarif accepts any valid JSON dict — a 0-byte file
        # parses to {} and a wrong-schema document carries no `runs`
        # list. Neither is SARIF: refuse (None), never an empty match
        # list that reads as an evaluated zero-confirmation round.
        return None

    matches = []
    for run in runs:
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                matches.append({
                    "file": art.get("uri", ""),
                    "line": region.get("startLine", 0),
                    "message": result.get("message", {}).get("text", ""),
                    "rule_id": result.get("ruleId", ""),
                })
    return matches


#: ``src=<token>`` / ``sink=<token>`` markers the generated query
#: (``specs.compile_codeql_config``) binds into result messages.
_MESSAGE_TOKEN_RE = re.compile(r"\b(?:src|sink)=([0-9a-f]{12})\b")


def _match_to_spec_keys(match: dict, specs: list[TaintSpec]) -> list[str]:
    """Map a CodeQL match back to the spec(s) that produced it.

    The generated query binds a ``spec_message_token`` for each
    matched endpoint into the result message (``[src=<token>
    sink=<token>]``), bound from the same ``hasName()`` constraint
    its Config predicate uses. The join extracts those tokens and
    maps them back — NOT a free-text function-name search: names are
    LLM-derived from the studied repo, so a spec named after message
    boilerplate ("data", "sink", "IRIS") would confirm on every
    result, and same-named specs in other files/roles would
    cross-bleed. The token hashes the full (file, function, role)
    identity, so only the exact spec confirms. A path result carries
    both endpoint tokens and confirms both specs.

    Keys MUST be built by ``store._spec_key`` — every consumer
    (``refine._promote_confirmed``, ``store._drop_refuted``, the
    scorecard bridge) matches on that format, so a locally-formatted
    key silently never matches any spec: no promotion, no scorecard
    outcome, and a confirmation that cannot cancel a refutation.
    """
    from .specs import spec_message_token

    msg = match.get("message", "")
    token_to_key = {
        spec_message_token(spec): _spec_key(spec) for spec in specs
    }
    keys: list[str] = []
    for token in _MESSAGE_TOKEN_RE.findall(msg):
        key = token_to_key.get(token)
        if key is not None and key not in keys:
            keys.append(key)
    return keys


def make_codeql_tool_runner(
    db_path: Path,
    out_dir: Path,
    language: str | None = None,
):
    """Build a ``ToolRunner`` callable for the IRIS refinement loop.

    Parameters
    ----------
    db_path:
        Path to a CodeQL database.
    out_dir:
        Output directory for SARIF results.
    language:
        Target language (CodeQL canonical name). ``None`` — the
        default — probes the DATABASE's own metadata
        (``codeql-database.yml`` ``primaryLanguage``). A hardcoded
        default here used to pin every caller to ``cpp``: a java /
        python / any-other-language database got a cpp-library query
        and every analyze failed, so the language must come from the
        database unless the caller genuinely knows better.

    Returns
    -------
    A callable ``(specs: list[TaintSpec]) -> RefinementFeedback``.
    Returns ``None`` if the CodeQL CLI is not available, the database
    is missing, or its language has no query template
    (``CODEQL_QUERY_LANGUAGES``).
    """
    try:
        from packages.codeql import is_available as codeql_available
        from packages.codeql.query_runner import QueryRunner as CodeQLRunner
        from packages.codeql.query_runner import vendored_stdlib_roots
    except ImportError:
        logger.debug("CodeQL runner not importable")
        return None

    # Availability is a module-level probe; the runner class itself
    # RAISES from __init__ when the CLI is missing (it has no
    # is_available method), so the gate must run before construction
    # and the constructor stays wrapped — an unconstructible runner
    # must degrade to None per this function's contract, never crash
    # the caller.
    if not codeql_available():
        logger.debug("CodeQL CLI not available for IRIS runner")
        return None
    try:
        runner = CodeQLRunner()
    except RuntimeError:
        logger.debug("CodeQL runner construction failed", exc_info=True)
        return None

    if not db_path.is_dir():
        logger.debug("CodeQL database not found at %s", db_path)
        return None

    if language is None:
        from core.audit.codeql_dbs import database_language
        language = database_language(db_path)
    if language not in CODEQL_QUERY_LANGUAGES:
        # Operator-visible, not DEBUG-buried: an unsupported-language
        # database means the CodeQL confirmation lane is off for the
        # whole run, exactly like a failed construction.
        logger.warning(
            "IRIS CodeQL runner disabled: no query template for "
            "database language %r (%s)", language, db_path,
        )
        return None

    def _run(specs: list[TaintSpec]) -> RefinementFeedback:
        query_text = compile_codeql_config(specs, language=language)
        if not query_text.strip():
            return RefinementFeedback()

        with scratch_dir("raptor-iris-codeql-") as tmp_root:
            try:
                pack_dir = _write_temp_pack(query_text, language, tmp_root)
                # The temp pack pins its stdlib dep as `codeql/
                # <lang>-all: "*"` with no lockfile, and the analyze
                # runs under block_network — registry resolution can
                # never happen there. The vendored `<lang>-all` root
                # inside the cached standard query pack resolves the
                # dep entirely offline (single-version tree, full
                # transitive closure); when nothing is cached,
                # run_local_pack's lazy proxy-routed `pack install`
                # is the fallback that CAN reach the registry.
                vendored = vendored_stdlib_roots(language)
                result = runner.run_local_pack(
                    language,
                    db_path,
                    pack_dir,
                    out_dir,
                    suite_name="raptor-iris-refine",
                    sarif_name=f"codeql_{language}_iris_refine.sarif",
                    label="IRIS refinement",
                    extra_analyze_args=tuple(
                        f"--additional-packs={root}" for root in vendored
                    ),
                    skip_install=bool(vendored),
                )

                if not result.success or not result.sarif_path:
                    return RefinementFeedback(
                        tool_errors=result.errors or ["codeql_analysis_failed"],
                        n_attempts=1,
                    )

                matches = _parse_sarif_matches(result.sarif_path)
                if matches is None:
                    # Defence in depth behind run_local_pack's own
                    # unreadable-SARIF guard (the file can still churn
                    # between the runner's read and ours): a failed
                    # parse is a failed round, never an empty one.
                    return RefinementFeedback(
                        tool_errors=[
                            f"sarif unreadable: {result.sarif_path}",
                        ],
                        n_attempts=1,
                    )
                confirmed_keys = []
                seen = set()
                for match in matches:
                    for key in _match_to_spec_keys(match, specs):
                        if key not in seen:
                            confirmed_keys.append(key)
                            seen.add(key)

                return RefinementFeedback(
                    confirmed_keys=confirmed_keys,
                    n_attempts=1,
                    n_successes=1,
                )
            except Exception as exc:
                logger.debug("IRIS CodeQL runner failed: %s", exc, exc_info=True)
                return RefinementFeedback(
                    tool_errors=[str(exc)], n_attempts=1,
                )

    return _run
