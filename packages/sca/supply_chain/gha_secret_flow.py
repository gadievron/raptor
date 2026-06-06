"""Detector for ``gha_secret_flow`` — a GitHub Actions workflow has
a data path from ``secrets.*`` (or a secret-bound ``env.*``) to a
sink that lets the secret leave the runner: an arbitrary ``run:``
shell block, ``actions/upload-artifact``, an unknown action's
``with:`` input, or a step output.

This is the substrate-level companion to ``gha_drift`` (which checks
action pinning) and ``workflow_signing`` (which checks signing
posture).  Neither of those catches the actual data-flow shape that
Iron Worm and similar exfil-via-CI attacks use; this detector does.

# Adversarial model

What this detector must defend against:

  * **toJSON(secrets) — the unambiguous evasion-by-aggregation** —
    no legitimate workflow has reason to enumerate ALL secrets.  We
    treat any reference to ``toJSON(secrets)`` (or ``toJson``, the
    cased variant) as a high-severity anchor regardless of where it
    flows.  Near-zero FP.

  * **Computed secret access** — ``secrets[github.event.inputs.x]``,
    ``env[name]``.  We can't statically resolve these.  Defence: we
    flag the SHAPE itself — there's no legitimate static reason for
    a workflow to compute the secret name, so the construct is
    suspicious on its own merit.

  * **Env binding then env use** — step A binds ``env: NPM_TOKEN:
    ${{ secrets.NPM_TOKEN }}``; step B uses ``$NPM_TOKEN`` in a
    ``run:`` block.  Defence: we track per-job env bindings derived
    from secrets and treat ``env.NPM_TOKEN`` references in later
    steps as secret-tainted within the same job.  Bindings DON'T
    cross job boundaries.

  * **Nested env JSON** — ``${{ toJSON(env) }}`` after binding a
    secret to env effectively exfiltrates the secret too.  Defence:
    when ANY env binding in the same job derives from a secret, we
    treat ``toJSON(env)`` as a sink.

  * **Custom local actions** — ``uses: ./.github/actions/foo``.
    These bypass the trusted-consumer allowlist because they're
    project-local; we conservatively treat them as UNTRUSTED (the
    action's body is in-tree and could exfiltrate the secret it
    receives) — emit a finding but mark it ``confidence=medium``
    so operators can dismiss after reviewing.  A correct
    interpretation would recurse into ``./.github/actions/foo/action.yml``
    — left for a follow-on.

  * **Reusable workflows** — ``uses: org/repo/.github/workflows/foo.yml@ref``
    with ``secrets: inherit`` or explicit secret passing.  Defence:
    emit a low-severity informational finding (cross-workflow flow
    is out of static scope here).

  * **echo-with-mask** — ``run: echo "::add-mask::${{ secrets.X }}"``
    is the canonical legitimate use of a secret in a ``run:`` body.
    Defence: recognise this exact shape and suppress.

  * **Token-cache-poisoning** — ``actions/cache@save`` with a path
    written by a step that consumed a secret.  We treat
    ``actions/cache`` as a sink unless the secret was consumed
    only by a trusted action earlier in the same job.

  * **Cross-step laundering via ``$GITHUB_ENV``** — an earlier step
    writes ``KEY=<secret-derived>`` to ``$GITHUB_ENV``; subsequent
    steps in the same job see ``KEY`` as a normal env var with no
    obvious secret reference at the call site.  Defence: when we
    see ``KEY=<tainted>`` redirected into ``$GITHUB_ENV``, we add
    ``KEY`` to the job's ``secret_bound_env`` so later sinks treat
    references to it as tainted just like a direct
    ``env: KEY: ${{ secrets.X }}`` binding.  The laundering step
    itself doesn't fire — the downstream sink does.

  * **Cross-step laundering via ``$GITHUB_OUTPUT``** — an earlier
    step (with an ``id:``) writes ``KEY=<secret-derived>`` to
    ``$GITHUB_OUTPUT``; downstream steps reference
    ``${{ steps.<id>.outputs.KEY }}`` — same shape as direct secret
    flow.  Defence: track per-step tainted outputs in the job
    context; treat ``steps.<id>.outputs.KEY`` references as
    secret-tainted in ``with:`` inputs and ``run:`` bodies.

# Soundness invariant

A finding from this detector means: "this workflow has a statically-
visible path from a secret reference to a sink that lets data leave
the runner."  It does NOT mean the workflow is necessarily
malicious — some legitimate publishers DO need to upload signed
artifacts that contain secrets internally — but every such case is
worth review.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

from .._yaml_fast import safe_load
from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)


# DoS bounds — defend against malicious workflow YAML that could
# otherwise exhaust CPU or memory in the redirect-block parser.
# A typical legitimate ``run:`` body is < 5 KB; even very large
# CI scripts rarely exceed 50 KB.  The bounds below are 10x typical
# upper bounds to give legitimate workflows room while ensuring an
# attacker can't drive the parser into pathological territory.
_MAX_RUN_BODY_BYTES = 500_000       # ~500 KB per ``run:`` block
_MAX_EVAL_RECURSION_DEPTH = 4       # eval-of-eval-of-eval-of-eval
_MAX_REDIRECT_BLOCKS_PER_BODY = 200 # cap on extracted blocks per body
_MAX_WORKFLOW_YAML_BYTES = 2_000_000  # ~2 MB workflow file
_MAX_BALANCED_WALK_BYTES = 100_000  # ``_find_balanced`` walk limit
_MAX_HEREDOC_BODY_BYTES = 100_000   # per-heredoc close-search window


# Trusted-consumer allowlist (lazy-loaded).
_TRUSTED: Optional[Set[str]] = None


def _trusted_consumers() -> Set[str]:
    global _TRUSTED
    if _TRUSTED is not None:
        return _TRUSTED
    path = (
        Path(__file__).resolve().parents[1]
        / "data" / "gha_trusted_secret_consumers.json"
    )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _TRUSTED = set()
        return _TRUSTED
    _TRUSTED = set(data.get("trusted", []))
    return _TRUSTED


def _action_name(uses: str) -> str:
    """Strip the ``@ref`` to get the bare action name.  Local actions
    (``./.github/actions/foo``) keep their ``./`` prefix so callers
    can distinguish them from registry actions."""
    return uses.split("@", 1)[0].strip()


# Regex for ``${{ secrets.X }}`` references.  Permissive on whitespace
# inside the ``${{ }}``.  ``toJSON``/``toJson`` (cased / uncased)
# treated identically.
_SECRETS_LITERAL_RE = re.compile(
    r"\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
)
_SECRETS_DICT_RE = re.compile(
    r"\$\{\{\s*secrets\[[^\]]+\]\s*\}\}"          # computed access
)
_TOJSON_SECRETS_RE = re.compile(
    r"\$\{\{\s*toJSON\s*\(\s*secrets\s*\)\s*\}\}",
    re.IGNORECASE,
)
_TOJSON_ENV_RE = re.compile(
    r"\$\{\{\s*toJSON\s*\(\s*env\s*\)\s*\}\}",
    re.IGNORECASE,
)
# Detect a secret-derived env reference like ``env.NPM_TOKEN`` in a
# template expression (uses + with-form), or ``$NPM_TOKEN`` / ``${NPM_TOKEN}``
# in a shell body.
_ENV_TEMPLATE_RE = re.compile(
    r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"
)
_ENV_SHELL_RE = re.compile(
    r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"
)
# Mask-line shape that legitimately consumes a secret in a run block.
_MASK_RE = re.compile(
    r'echo\s+"?::add-mask::\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*'
)
# ``${{ steps.<id>.outputs.<name> }}`` — a downstream reference to
# a previous step's output.  Used in both ``with:`` inputs and
# ``run:`` bodies; we taint the reference when the prior step
# tainted that output.
_STEPS_OUTPUT_RE = re.compile(
    r"\$\{\{\s*steps\.([A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)
# ``KEY=VALUE`` shape within an ``echo "..."`` / ``printf "..."``
# argument or a bare ``KEY=value`` ahead of a redirect.  Captures
# the key and value-up-to-quote-or-newline.
_KEY_VALUE_RE = re.compile(
    r'(?:^|["\s])'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'([^"\n>]*)'
)


def _redirect_target_pattern(target: str) -> str:
    """Regex source for matching ``$TARGET`` / ``${TARGET}`` /
    ``"$TARGET"`` / ``"${TARGET}"`` etc."""
    return rf'"?\$\{{?{target}\}}?"?'


def _multi_redirect_target_pattern(targets: Sequence[str]) -> str:
    """Regex source matching ``$NAME`` or ``${!NAME}`` (bash
    variable-indirection) for ANY name in ``targets``.

    Used after expanding shell-var aliases — when a body does
    ``T=$GITHUB_ENV`` then ``... >> $T``, we want ``$T`` to count as
    a redirect to ``GITHUB_ENV`` too.  ``${!NAME}`` is matched in
    parallel so an attacker who launders via
    ``T=GITHUB_ENV; ... >> ${!T}`` is also caught.  The ``!`` is
    optional in the ``${}`` form via ``!?``.
    """
    alt = "|".join(re.escape(t) for t in targets)
    return rf'"?\$\{{?!?(?:{alt})\}}?"?'


_MAX_ALIAS_CHAIN_DEPTH = 6


def _aliased_targets(body: str, target: str) -> List[str]:
    """Find local shell-var names that hold ``$TARGET`` (transitively)
    or that hold the LITERAL string ``TARGET`` (which bash variable
    indirection ``${!VAR}`` would dereference back to the target).

    Matches three transitive patterns:

      1. **Direct alias**: ``VAR=$TARGET`` / ``VAR="$TARGET"`` /
         ``VAR=${TARGET}`` / ``VAR="${TARGET}"`` and the
         ``export`` / ``declare`` / ``local`` prefixed variants.
      2. **Chained alias**: ``A=$TARGET; B=$A`` — A is in the
         direct-alias set; B then becomes an alias of A.  Iterated
         up to ``_MAX_ALIAS_CHAIN_DEPTH`` hops to defend against
         pathological chain depth without missing realistic shapes.
      3. **Indirection target**: ``T=TARGET`` (literal value match,
         no ``$``) makes ``${!T}`` evaluate to ``$TARGET``.  We
         treat such ``T`` as an alias so a downstream redirect via
         ``${!T}`` is detected.

    Documented gap (out of scope):
      * Quote-concatenation indirection: ``T="$"; ... >> "${T}TARGET"``
        — composed at parse time; would require evaluating arbitrary
        string concatenations.  Attacker using this is in the same
        evasion regime as ``eval``-laundered redirects (cost is
        higher than the protection it adds against detection).

    Returns the list of all alias names (excluding the original
    ``target``).
    """
    # Direct-alias / chained-alias detection — iterated reachability.
    # Use a negative lookahead after the alias name so ``$A1`` doesn't
    # match ``$A10``/``$A11`` (would otherwise cause both an alias-set
    # explosion AND incorrect VAR-name captures).
    aliases = {target}
    for _ in range(_MAX_ALIAS_CHAIN_DEPTH):
        new = set()
        for alias in list(aliases):
            alias_re = re.compile(
                r'(?:^|[\s;&|({])'
                r'(?:export\s+|declare\s+(?:-[\w]+\s+)*|local\s+)?'
                r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
                rf'"?\$\{{?{re.escape(alias)}'
                r'(?![A-Za-z0-9_])'
                r'\}?"?'
            )
            for m in alias_re.finditer(body):
                new.add(m.group(1))
        if not (new - aliases):
            break
        aliases |= new
    # Indirection target — ``T=TARGET`` literal (no leading ``$``).
    # ``${!T}`` then dereferences to the value of TARGET.  Same
    # word-boundary lookahead so ``T=GITHUB_ENVIRONMENT`` doesn't
    # alias.
    indir_re = re.compile(
        r'(?:^|[\s;&|({])'
        r'(?:export\s+|declare\s+(?:-[\w]+\s+)*|local\s+)?'
        rf'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?{re.escape(target)}'
        r'(?![A-Za-z0-9_])'
        r'"?'
        r'(?:\s|;|$)'
    )
    for m in indir_re.finditer(body):
        aliases.add(m.group(1))
    return list(aliases - {target})


_EVAL_RE = re.compile(
    r"""
    \b(?:eval|bash\s+-c|sh\s+-c|/bin/(?:ba)?sh\s+-c)\s+
    (?:"((?:[^"\\]|\\.)*)" | '((?:[^'\\]|\\.)*)')
    """,
    re.VERBOSE,
)


def _eval_arg_strings(body: str) -> List[str]:
    """Extract the QUOTED ARGUMENT of every ``eval``/``bash -c`` /
    ``sh -c`` invocation in ``body``.

    The argument is itself a shell program — an attacker who hides
    a ``>> $GITHUB_ENV`` redirect inside this string evades the
    surface scan.  We extract the strings so the redirect-block
    scanner can recurse over them.

    Handles double-quoted and single-quoted forms with standard
    backslash escapes; misses ``eval $VAR`` and ``eval cmd``
    (unquoted), which are less common in attack writeups.
    """
    out: List[str] = []
    for m in _EVAL_RE.finditer(body):
        arg = m.group(1) or m.group(2) or ""
        # Decode the most common escape sequences without invoking
        # a real shell parser.
        arg = (
            arg.replace("\\n", "\n").replace("\\t", "\t")
               .replace('\\"', '"').replace("\\'", "'")
               .replace("\\$", "$")
        )
        out.append(arg)
    return out


def _find_balanced(masked: str, open_ch: str, close_ch: str,
                   start: int) -> int:
    """Return the index of the matching CLOSE for the bracket at
    ``masked[start]`` (which must equal ``open_ch``), respecting
    nested same-kind brackets.  Returns ``-1`` when unbalanced.

    Pure stdlib substitute for a real bash parser — handles the
    nested-bracket case the regex ``[^{}]*`` couldn't.  Does NOT
    track other shell-syntax niceties (quotes, comments) because
    those are rare-to-absent in workflow ``run:`` bodies.
    """
    depth = 0
    i = start
    n = min(len(masked), start + _MAX_BALANCED_WALK_BYTES)
    while i < n:
        c = masked[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _balanced_blocks(masked: str, body: str,
                     open_ch: str, close_ch: str,
                     redirect_pat: str) -> List[str]:
    """Find every balanced ``open_ch ... close_ch`` region whose
    closer is followed (skipping whitespace) by a match of
    ``redirect_pat``.  Returns the INTERIOR content sliced from
    the ORIGINAL body."""
    redirect_after_re = re.compile(rf"^\s*{redirect_pat}")
    blocks: List[str] = []
    i = 0
    n = len(masked)
    while i < n:
        if masked[i] != open_ch:
            i += 1
            continue
        close = _find_balanced(masked, open_ch, close_ch, i)
        if close < 0:
            break
        # Is the redirect right after the close?
        if redirect_after_re.match(masked[close + 1:]):
            # Slice INTERIOR from ORIGINAL body.
            blocks.append(body[i + 1:close])
        i = close + 1
    return blocks


def _mask_gha_exprs(body: str) -> str:
    """Replace every ``${{ ... }}`` region with same-length filler
    characters that contain no shell brace metachar.

    GHA expression syntax (``${{ secrets.X }}``) embeds literal
    ``{{`` and ``}}`` inside what bash sees as a single
    parameter-expansion-or-text token.  Our non-nested brace
    balancers (``[^{}]*`` for groups, etc.) would otherwise treat
    those braces as bash group/parameter delimiters and break the
    block boundaries.  Masking preserves character positions so the
    caller can re-slice the ORIGINAL body once a boundary is
    found in the masked one.
    """
    out: List[str] = []
    i = 0
    n = len(body)
    while i < n:
        if body[i:i + 3] == "${{":
            close = body.find("}}", i + 3)
            if close == -1:
                out.append(body[i])
                i += 1
                continue
            # Replace the ENTIRE ``${{ ... }}`` region with
            # underscores; same length so positions stay aligned.
            out.append("_" * (close + 2 - i))
            i = close + 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def _extract_redirect_blocks(
    body: str, target: str, _depth: int = 0,
) -> List[str]:
    """Return text blocks whose content flows into ``$TARGET``
    (``GITHUB_ENV`` or ``GITHUB_OUTPUT``) via any of the bash redirect
    shapes commonly used in workflow `run:` blocks.

    Covers:
      * per-line — ``echo "X=Y" >> $TARGET``
      * group — ``{ echo X=Y; echo Z=W; } >> $TARGET`` (nested OK)
      * subshell — ``( ... ) >> $TARGET`` (nested OK)
      * heredoc — ``cat <<EOF >> $TARGET\\n X=Y\\n EOF`` (with
        ``<<-`` and quoted-delim variants)
      * tee — ``echo X=Y | tee -a $TARGET`` (the piped command is
        the block)
      * target-via-variable: ``T=$TARGET; ... >> $T`` (single-hop
        aliasing — chained aliases ``A=$T; B=$A`` are out of scope)
      * dynamic eval: ``eval "echo X=Y >> $TARGET"`` (the eval
        argument is recursively scanned)

    Still NOT covered (documented for the next adversarial pass):
      * Chained alias: ``A=$T; B=$A`` (only ``A`` is followed)
      * Variable indirection: ``T=GITHUB_ENV; ... >> ${!T}``
      * Quote concatenation: ``T="$"; ... >> "${T}GITHUB_ENV"``

    Adversarial: each new evasion shape we close raises the cost of
    the next one.  The remaining gaps require either bash-parser-
    accurate evaluation or shell semantics we won't replicate.

    DoS bounds (enforced here):
      * ``body`` is capped to ``_MAX_RUN_BODY_BYTES`` before parsing
      * eval-recursion depth capped by ``_depth`` parameter
      * total extracted blocks capped by
        ``_MAX_REDIRECT_BLOCKS_PER_BODY``
    """
    # DoS bound — clip oversized run bodies BEFORE any expensive
    # regex work.  An attacker who ships a 100 MB workflow with one
    # giant ``run:`` block can't drive us into pathological territory.
    if len(body) > _MAX_RUN_BODY_BYTES:
        logger.debug(
            "sca.supply_chain.gha_secret_flow: run body of %d bytes "
            "exceeds %d-byte cap; truncating (DoS bound)",
            len(body), _MAX_RUN_BODY_BYTES,
        )
        body = body[:_MAX_RUN_BODY_BYTES]
    if _depth > _MAX_EVAL_RECURSION_DEPTH:
        # An attacker who nests ``eval "eval \"...\""`` many levels
        # deep can't drive us into infinite recursion.  At this
        # depth we stop recursing — outer layers' bindings are
        # already captured.
        return []
    # Mask ``${{ ... }}`` so its embedded braces don't break the
    # bash-syntax brace balancer; positions stay aligned so we can
    # slice the ORIGINAL body for content extraction.
    masked = _mask_gha_exprs(body)
    # Expand to all alias names that point at $TARGET so subsequent
    # redirect-shape matchers treat ``$ALIAS`` and ``$TARGET``
    # interchangeably within this body's scope.
    aliases = _aliased_targets(body, target)
    target_alts = [target, *aliases]
    target_pat = _multi_redirect_target_pattern(target_alts)
    redirect_pat = rf'>>?\s*{target_pat}'
    tee_pat = rf'\|\s*tee\s+(?:-a\s+)?{target_pat}'
    redirect_re = re.compile(redirect_pat)
    tee_re = re.compile(tee_pat)
    blocks: List[str] = []

    # Heredoc — hand-rolled linear scan.  The regex finditer version
    # had an O(n²) worst case when many ``<<DELIM`` openers had no
    # matching close — each opener's ``(.*?)\n\1`` search walked to
    # end-of-body.  We instead advance a cursor; each opener that
    # passes the same-line redirect check looks for the closer in
    # the next ``_MAX_HEREDOC_BODY_BYTES`` bytes only.
    opener_re = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")
    redirect_after_open_re = re.compile(redirect_pat)
    i = 0
    n_masked = len(masked)
    # Cap heredoc-opener processing per body.  Pathological inputs
    # can't trigger thousands of openers worth of work.
    heredocs_processed = 0
    while i < n_masked and heredocs_processed < _MAX_REDIRECT_BLOCKS_PER_BODY:
        # Quick scan for next ``<<``.
        idx = masked.find("<<", i)
        if idx < 0:
            break
        m = opener_re.match(masked, idx)
        if m is None:
            i = idx + 2
            continue
        # Opener line is from ``idx`` to the next newline.  The
        # redirect target MUST appear on this same line.
        line_end = masked.find("\n", m.end())
        if line_end < 0:
            break
        opener_line = masked[idx:line_end]
        if redirect_after_open_re.search(opener_line) is None:
            i = line_end + 1
            continue
        # Found a heredoc that targets us.  Look for the closer on
        # its own line within the next ``_MAX_HEREDOC_BODY_BYTES``.
        delim = m.group(1)
        body_start = line_end + 1
        search_end = min(n_masked, body_start + _MAX_HEREDOC_BODY_BYTES)
        close_re = re.compile(
            rf"\n[ \t]*{re.escape(delim)}[ \t]*(?:\n|$)"
        )
        close = close_re.search(masked, body_start, search_end)
        if close is not None:
            blocks.append(body[body_start:close.start()])
            i = close.end()
        else:
            # No matching close within the bounded search window.
            # Skip past the opener line and continue.
            i = body_start
        heredocs_processed += 1

    # Group write — nesting-aware via manual brace balancer.
    blocks.extend(_balanced_blocks(masked, body, "{", "}", redirect_pat))

    # Subshell write — nesting-aware.
    blocks.extend(_balanced_blocks(masked, body, "(", ")", redirect_pat))

    # Tee — the piped command is the relevant block.  Find the
    # statement-boundary preceding the pipe (newline or ``;``); the
    # command between that boundary and the pipe is the block.
    for m in tee_re.finditer(masked):
        start = max(
            body.rfind("\n", 0, m.start()),
            body.rfind(";", 0, m.start()),
        )
        if start < 0:
            start = 0
        blocks.append(body[start:m.start()])

    # Per-line — catches simple ``<cmd> >> $TARGET`` lines.  Skip
    # heredoc OPENER lines (which carry the redirect but the actual
    # payload is in the heredoc body already captured above).
    # Per-line uses ORIGINAL body — masking doesn't help here and
    # would erase the ``${{ secrets.X }}`` content the KEY=VALUE
    # extractor needs to see.
    for line in body.split("\n"):
        if not redirect_re.search(line):
            continue
        if "<<" in line:
            continue
        blocks.append(line)

    # Dynamic eval: recurse into each eval/bash-c/sh-c argument
    # string.  This catches an attacker hiding the entire redirect
    # shape inside an eval'd string.  Each recursion uses the SAME
    # target so the eval body's bindings inherit the outer body's
    # taint context indirectly through ``_value_is_tainted`` later.
    for eval_arg in _eval_arg_strings(body):
        blocks.extend(
            _extract_redirect_blocks(eval_arg, target, _depth + 1),
        )

    # DoS bound — total extracted blocks capped.  Adversary can't
    # blow up downstream KEY=VALUE scanning by stuffing the body
    # with thousands of redirect targets.
    if len(blocks) > _MAX_REDIRECT_BLOCKS_PER_BODY:
        logger.debug(
            "sca.supply_chain.gha_secret_flow: extracted %d redirect "
            "blocks (cap %d); truncating (DoS bound)",
            len(blocks), _MAX_REDIRECT_BLOCKS_PER_BODY,
        )
        blocks = blocks[:_MAX_REDIRECT_BLOCKS_PER_BODY]

    return blocks


def _extract_redirected_writes(
    body: str, target: str,
) -> List[tuple]:
    """Extract ``[(key, value)]`` pairs written to a target
    (``GITHUB_ENV`` / ``GITHUB_OUTPUT``) across all supported
    redirect shapes."""
    pairs: List[tuple] = []
    for block in _extract_redirect_blocks(body, target):
        for m in _KEY_VALUE_RE.finditer(block):
            key = m.group(1)
            value = m.group(2).strip().strip('"').strip("'")
            # Drop the special token names — these are the redirect
            # destinations, not actual KEY=VALUE writes.
            if key in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"):
                continue
            pairs.append((key, value))
    return pairs


def _value_is_tainted(value: str, job_ctx: "_JobContext") -> Optional[str]:
    """Return the source secret name if ``value`` references any
    currently-tainted thing in this job: a literal
    ``${{ secrets.X }}``, a previously-bound ``$NAME``, or a
    ``${{ steps.<id>.outputs.<name> }}`` whose output is tainted.

    Returns the FIRST matched source secret name (for evidence);
    None if untainted.
    """
    m = re.search(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", value)
    if m:
        return m.group(1)
    for env_m in _ENV_SHELL_RE.finditer(value):
        var = env_m.group(1)
        if var in job_ctx.secret_bound_env:
            return job_ctx.secret_bound_env[var]
    for out_m in _STEPS_OUTPUT_RE.finditer(value):
        step_id = out_m.group(1)
        out_name = out_m.group(2)
        bound = job_ctx.secret_bound_outputs.get(step_id, {})
        if out_name in bound:
            return bound[out_name]
    return None


@dataclass(frozen=True)
class SecretFlowHit:
    """A statically-visible secret → sink edge in a workflow."""

    dependency: Dependency
    workflow_path: Path
    job_id: str
    step_index: int
    sink_kind: str               # "untrusted_action", "run_block",
                                 # "upload_artifact", "cache_save",
                                 # "tojson_secrets", "tojson_env",
                                 # "computed_access", "local_action",
                                 # "reusable_workflow_inherit"
    secret_names: tuple          # tuple of secret names referenced;
                                 # ``("*",)`` for toJSON / computed
    detail: str
    severity: str                # "info" | "low" | "medium" | "high"


@dataclass
class _JobContext:
    """Per-job tracking state.  Reset at job boundary — env bindings
    do NOT cross jobs."""
    secret_bound_env: Dict[str, str] = field(default_factory=dict)
    # name -> source-secret-name for evidence
    secret_bound_outputs: Dict[str, Dict[str, str]] = field(
        default_factory=dict,
    )
    # step_id -> {output_name -> source-secret-name}.  Populated when
    # a ``run:`` body writes ``KEY=<tainted>`` to ``$GITHUB_OUTPUT``;
    # downstream steps' references to ``steps.<id>.outputs.<key>``
    # become tainted via this mapping.
    env_written_to_disk: bool = False
    # True iff some prior step in this job ran a command that wrote
    # env contents OR a secret-bound var to a file.  Required to
    # promote ``actions/upload-artifact`` / ``actions/cache`` sinks
    # from medium (informational) to high (active leak risk):
    # without an env-to-disk write, the artifact / cache carrying
    # the secret would require the SECRET to have already been
    # written to a file the upload covers.  Empirically the
    # high-confidence shape; raw job-level env binding alone
    # produced FP-floods on real workflows (mitmproxy
    # ``upload-artifact`` for unrelated build outputs).


_ENV_DUMP_RE = re.compile(
    r"""
    \b(?:env|printenv|set|export\s+-p)\b   # env-dumping commands
    [^\n|>]*                                # anything except pipe/newline/redirect
    >+(?!>)                                 # all consecutive > (no backtracking past last >)
    \s*
    (?:"|'|)                                # optional quote
    (?!\s*\$\{?GITHUB_(?:ENV|OUTPUT|PATH))  # NOT a GHA-target write
    """,
    re.VERBOSE,
)
_VAR_DUMP_RE_FACTORY = lambda var: re.compile(  # noqa: E731
    rf"""
    \b(?:echo|printf)\s+
    [^\n|]*?
    \$\{{?{re.escape(var)}\}}?
    [^\n|>]*
    >+(?!>)
    \s*
    (?!\s*\$\{{?GITHUB_(?:ENV|OUTPUT|PATH))
    """,
    re.VERBOSE,
)


def _body_writes_env_to_disk(
    body: str, secret_bound_env: Dict[str, str],
) -> bool:
    """True iff ``body`` contains an ``env`` / ``printenv`` / ``set``
    dump to a non-GHA-target file, OR an ``echo $VAR > file`` where
    ``VAR`` is in the job's secret-bound-env mapping.

    Defends against the over-aggressive ``upload-artifact`` /
    ``actions/cache`` sinks: just having ``env: TOK: ${secret}``
    in a job is NOT sufficient evidence of a leak — the secret
    needs to actually reach disk for the artifact to carry it.
    """
    if _ENV_DUMP_RE.search(body):
        return True
    for var in secret_bound_env:
        if _VAR_DUMP_RE_FACTORY(var).search(body):
            return True
    return False


def _strip_bash_full_line_comments(body: str) -> str:
    """Drop bash full-line comments — lines whose first non-whitespace
    character is ``#``.  End-of-line comments (``cmd  # tail``) are
    kept; stripping them accurately requires knowing whether the
    ``#`` is inside a quoted string, which needs a real bash parser.

    Defends against the comment-block FP: a workflow author who
    explains the body's security shape in a comment block at the
    top of the ``run:`` might write ``# we don't reference
    $GH_TOKEN directly because ...``.  That literal text isn't a
    runtime reference but the unstripped scanner sees ``$GH_TOKEN``
    and fires.  Dogfooded against RAPTOR's own ``sca-self-bump.yml``.
    """
    return "\n".join(
        "" if line.lstrip().startswith("#") else line
        for line in body.split("\n")
    )


def _is_truthy_run_body_egress(body: str) -> bool:
    """Heuristic: a ``run:`` body that does network egress or a
    redirect-to-file pattern is a potential exfil sink.  Reuses the
    install-hook dangerous-pattern logic in spirit but applied to
    the run-body content."""
    # Network egress shapes
    if re.search(r"\bcurl\b|\bwget\b|\bnc\b|\bdig\b|\bhost\b", body):
        return True
    # File-write patterns (the secret will leave via cache or
    # artifact uploads later)
    if re.search(r">>?\s*\$?GITHUB_(OUTPUT|ENV)|>>?\s*/tmp/", body):
        return True
    # IFS / base64 / curl-pipe-shell
    if re.search(r"curl.+\|\s*(?:bash|sh)|base64\s+(?:-d|--decode)", body):
        return True
    return False


def _scan_one_step(
    step: dict,
    job_id: str,
    step_index: int,
    job_ctx: _JobContext,
    workflow_path: Path,
    dep: Dependency,
) -> List[SecretFlowHit]:
    """Scan a single workflow step for secret-flow edges.  Mutates
    ``job_ctx`` to record env bindings derived from secrets."""
    if not isinstance(step, dict):
        return []
    hits: List[SecretFlowHit] = []

    # 1) Update env bindings — anything assigned from a secret-flavoured
    #    expression becomes secret-tainted within this job.
    step_env = step.get("env") or {}
    if isinstance(step_env, dict):
        for k, v in step_env.items():
            if not isinstance(v, str):
                continue
            m = _SECRETS_LITERAL_RE.search(v)
            if m:
                # Extract the secret name from the literal reference
                name_match = re.search(
                    r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", v,
                )
                src = name_match.group(1) if name_match else "?"
                job_ctx.secret_bound_env[str(k)] = src

    # 2) toJSON(secrets) — the high-confidence anchor.  Any reference
    #    anywhere in the step's serialised yaml fires.
    step_yaml = json.dumps(step)
    if _TOJSON_SECRETS_RE.search(step_yaml):
        hits.append(SecretFlowHit(
            dependency=dep, workflow_path=workflow_path,
            job_id=job_id, step_index=step_index,
            sink_kind="tojson_secrets", secret_names=("*",),
            detail=(
                "step references ``toJSON(secrets)`` — enumerates "
                "every workflow secret as JSON; no legitimate use"
            ),
            severity="high",
        ))
    # toJSON(env) is a sink only when env bindings include secret-
    # derived values in this job.
    if _TOJSON_ENV_RE.search(step_yaml) and job_ctx.secret_bound_env:
        hits.append(SecretFlowHit(
            dependency=dep, workflow_path=workflow_path,
            job_id=job_id, step_index=step_index,
            sink_kind="tojson_env",
            secret_names=tuple(sorted(job_ctx.secret_bound_env.keys())),
            detail=(
                "step references ``toJSON(env)`` AND this job has "
                "env bindings derived from secrets — same as "
                "toJSON(secrets) in effect"
            ),
            severity="high",
        ))

    # 3) Computed secret access — ``secrets[<expr>]``.  No legitimate
    #    reason to compute the secret name at expression time.
    if _SECRETS_DICT_RE.search(step_yaml):
        hits.append(SecretFlowHit(
            dependency=dep, workflow_path=workflow_path,
            job_id=job_id, step_index=step_index,
            sink_kind="computed_access", secret_names=("*",),
            detail=(
                "step uses computed secret access ``secrets[...]`` — "
                "no static visibility into which secrets flow; high "
                "suspicion shape"
            ),
            severity="medium",
        ))

    # 4) Action use — ``uses:``.
    uses = step.get("uses")
    if isinstance(uses, str):
        action_name = _action_name(uses)
        is_local = action_name.startswith("./") or action_name.startswith("../")
        is_reusable_workflow = action_name.endswith(".yml") or action_name.endswith(".yaml")
        # Trust any first-party ``actions/<name>`` action (GitHub's
        # official org).  The ``actions/`` GitHub org is the
        # canonical source of first-party workflow primitives; any
        # action under it is GitHub-maintained.  Enumerating each
        # one in the data file would inflate the allowlist and
        # break on every new official action GitHub ships.
        is_trusted = (
            action_name in _trusted_consumers()
            or action_name.startswith("actions/")
        )
        # Find secret-tainted inputs flowing into this action
        with_inputs = step.get("with") or {}
        tainted_inputs: List[str] = []
        if isinstance(with_inputs, dict):
            for in_name, in_val in with_inputs.items():
                if not isinstance(in_val, str):
                    continue
                if (_SECRETS_LITERAL_RE.search(in_val)
                        or _TOJSON_SECRETS_RE.search(in_val)):
                    tainted_inputs.append(str(in_name))
                    continue
                # env.X referenced + X is secret-bound in this job
                matched = False
                for m in _ENV_TEMPLATE_RE.finditer(in_val):
                    if m.group(1) in job_ctx.secret_bound_env:
                        tainted_inputs.append(str(in_name))
                        matched = True
                        break
                if matched:
                    continue
                # steps.<id>.outputs.<name> reference + that output
                # was tainted by a prior step in this job.
                for sm in _STEPS_OUTPUT_RE.finditer(in_val):
                    step_id = sm.group(1)
                    out_name = sm.group(2)
                    bound = job_ctx.secret_bound_outputs.get(step_id, {})
                    if out_name in bound:
                        tainted_inputs.append(str(in_name))
                        break
        # Step-level env entries also flow if step.env binds a secret
        # and the action is not trusted.
        env_tainted = bool(job_ctx.secret_bound_env)
        if tainted_inputs:
            if is_trusted:
                # Legitimate — trusted consumer.  No finding.
                pass
            elif is_local:
                hits.append(SecretFlowHit(
                    dependency=dep, workflow_path=workflow_path,
                    job_id=job_id, step_index=step_index,
                    sink_kind="local_action",
                    secret_names=tuple(tainted_inputs),
                    detail=(
                        f"secret-tainted input(s) {tainted_inputs!r} "
                        f"flow into local action ``{action_name}``; "
                        "local actions bypass the trusted-consumer "
                        "allowlist — body is in-tree and should be "
                        "audited"
                    ),
                    severity="medium",
                ))
            elif is_reusable_workflow:
                hits.append(SecretFlowHit(
                    dependency=dep, workflow_path=workflow_path,
                    job_id=job_id, step_index=step_index,
                    sink_kind="reusable_workflow_inherit",
                    secret_names=tuple(tainted_inputs),
                    detail=(
                        f"reusable workflow ``{action_name}`` "
                        f"receives secret-tainted input(s) "
                        f"{tainted_inputs!r}; static scope ends at "
                        "the workflow boundary"
                    ),
                    severity="low",
                ))
            else:
                hits.append(SecretFlowHit(
                    dependency=dep, workflow_path=workflow_path,
                    job_id=job_id, step_index=step_index,
                    sink_kind="untrusted_action",
                    secret_names=tuple(tainted_inputs),
                    detail=(
                        f"secret-tainted input(s) {tainted_inputs!r} "
                        f"flow into non-allowlisted action "
                        f"``{action_name}``"
                    ),
                    severity="high",
                ))
        # Sink: actions/upload-artifact — leak surface tightening.
        # Pre-2026-06: fired ``high`` on any env-tainted job.
        # Post-tightening: fires high ONLY when a prior step in the
        # same job wrote env or a secret-bound var to a file.
        # Otherwise downgrades to medium (informational — the upload
        # carries the secret only if some step writes it to disk
        # first, which we couldn't detect; reviewer triages).
        if action_name == "actions/upload-artifact" and env_tainted:
            if job_ctx.env_written_to_disk:
                severity = "high"
                detail_suffix = (
                    " AND a prior step in this job wrote env / a "
                    "secret-bound var to disk — upload likely carries "
                    "the secret"
                )
            else:
                severity = "medium"
                detail_suffix = (
                    " — no prior env-to-disk write detected; the "
                    "upload only carries the secret if a step "
                    "we couldn't statically resolve persisted it"
                )
            hits.append(SecretFlowHit(
                dependency=dep, workflow_path=workflow_path,
                job_id=job_id, step_index=step_index,
                sink_kind="upload_artifact",
                secret_names=tuple(
                    sorted(job_ctx.secret_bound_env.keys()),
                ),
                detail=(
                    "actions/upload-artifact in a job with env "
                    "bindings derived from secrets" + detail_suffix
                ),
                severity=severity,
            ))
        # Sink: actions/cache@save — same shape (cache outlives
        # the runner, attacker who controls a later run reads it).
        if action_name == "actions/cache" and env_tainted:
            # Only ``save`` mode is the write side, but mode is
            # often implicit (the action saves on success).  Same
            # tightening as upload-artifact: require evidence of an
            # env-to-disk write in this job for medium; otherwise
            # downgrade to low.
            if job_ctx.env_written_to_disk:
                cache_severity = "medium"
                cache_detail = (
                    "actions/cache used in a job with secret-derived "
                    "env bindings AND a prior env-to-disk write — "
                    "cached paths can outlive the runner; review the "
                    "cached file set"
                )
            else:
                cache_severity = "low"
                cache_detail = (
                    "actions/cache used in a job with secret-derived "
                    "env bindings — no prior env-to-disk write "
                    "detected; review whether the cache set could "
                    "include the secret"
                )
            hits.append(SecretFlowHit(
                dependency=dep, workflow_path=workflow_path,
                job_id=job_id, step_index=step_index,
                sink_kind="cache_save",
                secret_names=tuple(
                    sorted(job_ctx.secret_bound_env.keys()),
                ),
                detail=cache_detail,
                severity=cache_severity,
            ))

    # 5) ``run:`` shell body.
    step_id_value = step.get("id")
    step_id_str = step_id_value if isinstance(step_id_value, str) else ""
    run_body = step.get("run")
    if isinstance(run_body, str) and run_body.strip():
        # Track env-to-disk writes so the upload-artifact / cache
        # sinks can require evidence stronger than "env binding
        # alone" before promoting to high severity.  Set once per
        # job; resets only at job boundary.
        if not job_ctx.env_written_to_disk:
            if _body_writes_env_to_disk(
                run_body, job_ctx.secret_bound_env,
            ):
                job_ctx.env_written_to_disk = True
        # Mask-line is the canonical legitimate use of a secret in
        # a run body.  Even when present we still want to update
        # taint bindings from any GITHUB_ENV/OUTPUT writes in the
        # SAME body (a body that masks ONE secret can still leak
        # another via redirect) — but skip emitting a ``run_block``
        # finding so the mask line itself isn't a FP.
        is_masked = bool(_MASK_RE.search(run_body))
        # Strip bash full-line comments before scanning for
        # ``$VAR`` references — a comment explaining what the body
        # does or why the secret-handling pattern is safe must not
        # itself trigger the detector (the literal text ``$GH_TOKEN``
        # inside a ``#`` comment can't leak the secret at runtime).
        # End-of-line comments after a command are not stripped —
        # accurate detection would need a bash parser, which we
        # avoid; the FP-shape we close here is the common "docstring-
        # like full-line comment block at top of run body".
        scan_body = _strip_bash_full_line_comments(run_body)
        # Check whether the body references a secret literal,
        # a secret-tainted env var, or a tainted prior-step output.
        secret_refs_in_body: List[str] = []
        for m in _SECRETS_LITERAL_RE.finditer(scan_body):
            name_match = re.search(
                r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", m.group(0),
            )
            if name_match:
                secret_refs_in_body.append(name_match.group(1))
        for m in _ENV_SHELL_RE.finditer(scan_body):
            var = m.group(1)
            if var in job_ctx.secret_bound_env:
                secret_refs_in_body.append(
                    job_ctx.secret_bound_env[var],
                )
        for sm in _STEPS_OUTPUT_RE.finditer(scan_body):
            step_id = sm.group(1)
            out_name = sm.group(2)
            bound = job_ctx.secret_bound_outputs.get(step_id, {})
            if out_name in bound:
                secret_refs_in_body.append(bound[out_name])
        if secret_refs_in_body and not is_masked:
            severity = (
                "high"
                if _is_truthy_run_body_egress(scan_body)
                else "medium"
            )
            hits.append(SecretFlowHit(
                dependency=dep, workflow_path=workflow_path,
                job_id=job_id, step_index=step_index,
                sink_kind="run_block",
                secret_names=tuple(sorted(set(secret_refs_in_body))),
                detail=(
                    f"``run:`` block references secret(s) "
                    f"{sorted(set(secret_refs_in_body))!r} outside "
                    f"the standard echo-with-mask form"
                ),
                severity=severity,
            ))
        # Cross-step laundering: this body writes ``KEY=<tainted>``
        # to ``$GITHUB_ENV`` or ``$GITHUB_OUTPUT``.  Update the
        # job's taint bindings so DOWNSTREAM steps see the
        # propagated taint at their sinks.  No finding here — the
        # laundering step itself isn't the sink.
        for key, value in _extract_redirected_writes(
            run_body, "GITHUB_ENV",
        ):
            source = _value_is_tainted(value, job_ctx)
            if source is not None:
                job_ctx.secret_bound_env[key] = source
        if step_id_str:
            for key, value in _extract_redirected_writes(
                run_body, "GITHUB_OUTPUT",
            ):
                source = _value_is_tainted(value, job_ctx)
                if source is not None:
                    job_ctx.secret_bound_outputs.setdefault(
                        step_id_str, {},
                    )[key] = source

    return hits


def _scan_workflow(
    workflow_path: Path, dep: Dependency,
) -> List[SecretFlowHit]:
    """Parse one workflow YAML and scan every job's every step."""
    try:
        # Read-cap defends against a pathologically large workflow
        # YAML.  Real GitHub Actions caps workflow files at 1 MB
        # (documented limit); we accept up to 2 MB to be generous
        # for forked workflow tooling that may not enforce the
        # limit locally.
        with workflow_path.open(encoding="utf-8", errors="replace") as f:
            text = f.read(_MAX_WORKFLOW_YAML_BYTES + 1)
        if len(text) > _MAX_WORKFLOW_YAML_BYTES:
            logger.debug(
                "sca.supply_chain.gha_secret_flow: %s exceeds %d bytes "
                "— skipping (DoS bound)",
                workflow_path, _MAX_WORKFLOW_YAML_BYTES,
            )
            return []
    except OSError:
        return []
    try:
        data = safe_load(text)
    except Exception as exc:                          # pragma: no cover
        # PyYAML raises a wide tree of exceptions on malformed input
        # — we don't care which one; just skip the workflow.
        logger.debug(
            "sca.supply_chain.gha_secret_flow: %s failed to parse "
            "(%s); skipping",
            workflow_path, exc,
        )
        return []
    if not isinstance(data, dict):
        return []
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return []
    hits: List[SecretFlowHit] = []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        ctx = _JobContext()
        # Top-level job env bindings (apply to every step in the job).
        job_env = job.get("env") or {}
        if isinstance(job_env, dict):
            for k, v in job_env.items():
                if isinstance(v, str) and _SECRETS_LITERAL_RE.search(v):
                    name_match = re.search(
                        r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", v,
                    )
                    ctx.secret_bound_env[str(k)] = (
                        name_match.group(1) if name_match else "?"
                    )
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            hits.extend(_scan_one_step(
                step, str(job_id), idx, ctx, workflow_path, dep,
            ))
    return hits


def scan_target(
    target: Path,
    manifests: Sequence[Manifest] = (),
    deps: Sequence[Dependency] = (),
) -> List[SecretFlowHit]:
    """Walk ``target/.github/workflows/`` for ``*.yml`` and ``*.yaml``
    files and scan each for secret-flow shapes."""
    target = target.resolve()
    workflow_dir = target / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    dep = _placeholder_dep(target)
    out: List[SecretFlowHit] = []
    for entry in sorted(workflow_dir.iterdir()):
        if entry.is_file() and entry.suffix in (".yml", ".yaml"):
            out.extend(_scan_workflow(entry, dep))
    return out


def _placeholder_dep(target: Path) -> Dependency:
    """Workflow-flow hits don't have a natural dependency-row owner;
    they target the project itself."""
    return Dependency(
        ecosystem="GitHub Actions",
        name="<workflow>",
        version=None,
        declared_in=target,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low", reason="workflow secret-flow finding host",
        ),
    )


__all__ = ["SecretFlowHit", "scan_target"]
