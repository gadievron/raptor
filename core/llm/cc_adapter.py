"""Claude Code subprocess transport.

Builds ``claude -p`` commands and parses their JSON-envelope output.
The subprocess counterpart to the SDK providers in ``core.llm.providers``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from core.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


# Env-var families the ``claude`` CLI needs to select and authenticate
# its backend: CLAUDE_CODE_* (USE_BEDROCK / USE_VERTEX / USE_MANTLE and
# friends), ANTHROPIC_* (API key, MODEL mapping for alternate clouds).
# Prefix families rather than an exact list so new provider knobs keep
# working. The Anthropic secret pair is subtracted from the overlay
# when an alternate-cloud backend is selected — see cc_subprocess_env.
# RAPTOR_BEDROCK_/RAPTOR_CC_: RAPTOR's own LLM operator knobs
# (model/profile/region pins, effort, budget). The pure-LLM substrate
# child ignores them, but skill-pass children (skill_dispatch,
# cc_dispatch) drive RAPTOR's libexec helpers whose model resolution
# reads them - dropping the knobs at this hop silently reverts the
# grandchildren to defaults. Names and flags only, never credentials.
_CC_BACKEND_ENV_PREFIXES = (
    "CLAUDE_CODE_", "ANTHROPIC_", "RAPTOR_BEDROCK_", "RAPTOR_CC_",
)

# AWS names a Bedrock-backed CLI child needs, passed ONLY when
# CLAUDE_CODE_USE_BEDROCK is set. An explicit allowlist, NOT the AWS_*
# prefix: the previous blanket copy swept every ambient AWS_* value —
# static long-lived secrets included — into CLI children, some of
# which (cc_dispatch, validate post-pass) run with Bash+Write enabled
# against hostile repos. Non-secret selection/config names only;
# secret material flows exclusively through
# _mint_child_aws_credentials (sandboxed children, scoped session
# trio) or the explicit static-trio passthrough for unsandboxed
# substrate children (see cc_subprocess_env).
_CC_AWS_PASSTHROUGH_NAMES = (
    "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
    "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_CA_BUNDLE",
    # The Bedrock bearer token is the CLI's API-key-style Bedrock auth;
    # it cannot be minted through the credential chain, so on installs
    # that use it the child needs the literal value.
    "AWS_BEARER_TOKEN_BEDROCK",
)

# The SigV4 credential trio. Passed through verbatim ONLY for
# unsandboxed substrate children (mint_aws_credentials=False): they
# resolve their own chain (~/.aws, IMDS) for role/profile identities,
# but env-provided static credentials are the one source the child
# cannot re-resolve. Sandboxed children never receive the ambient
# values — they get the minted (short-lived where the identity allows)
# session trio instead.
_CC_AWS_STATIC_CREDENTIAL_NAMES = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
)

# credential_mode="proxy": names/prefixes that must NOT ride the
# backend overlay into a proxy-mode child. Credential material is the
# obvious set. Operator base-URL pins are stripped because the caller
# sets the one true gateway route after the overlay, and the
# CLAUDE_CODE_SKIP_* family is stripped-then-reset so only the
# skip-auth flags THIS mode needs are present. Backend-SELECTION flags
# (CLAUDE_CODE_USE_*) are deliberately KEPT: the CLI's provider mode
# decides which gateway env vars it reads (verified against the CLI —
# a Bedrock install ignores ``ANTHROPIC_BASE_URL`` and reads
# ``ANTHROPIC_BEDROCK_MANTLE_BASE_URL`` instead).
_CC_PROXY_STRIP_EXACT = frozenset({
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
})
_CC_PROXY_STRIP_PREFIXES = ("CLAUDE_CODE_SKIP_",)


def _cc_proxy_strip(key: str) -> bool:
    if key in _CC_PROXY_STRIP_EXACT:
        return True
    if key.startswith(_CC_PROXY_STRIP_PREFIXES):
        return True
    # Operator base-URL pins (ANTHROPIC_BASE_URL, and the per-cloud
    # ANTHROPIC_*_BASE_URL variants) — the caller sets the one true
    # gateway route after the overlay.
    return key.startswith("ANTHROPIC_") and "BASE_URL" in key


def resolve_claude_cli(explicit: str | None = None) -> str | None:
    """Resolve the ``claude`` CLI to its REAL path for sandboxed dispatch.

    Standard installs place a symlink launcher on PATH
    (``~/.local/bin/claude`` -> versioned install dir). The sandbox's
    mount-ns visibility check realpaths ``cmd[0]`` and requires the
    REAL location inside the bind tree, so dispatching via the
    un-realpath'd ``shutil.which`` result silently downgrades
    isolation to the Landlock-only fallback tier whenever the resolved
    parent isn't bound — the same class as the fixed semgrep / codeql
    symlink bugs (selftest-05 precedent: exec scanners via their real
    path). Resolving once at construction also locks the binary in
    against PATH mutation between probe and exec.

    Args:
        explicit: caller-supplied path (wins over PATH lookup); may
            itself be a symlink and is realpath'd too.

    Returns ``None`` when the CLI is not found.
    """
    import os as _os
    import shutil as _shutil
    path = explicit or _shutil.which("claude")
    if not path:
        return None
    try:
        return _os.path.realpath(path)
    except OSError:
        return path


def cc_subprocess_env(
    *,
    mint_aws_credentials: bool = False,
    credential_mode: str = "env",
    proxy_base_url: str | None = None,
    proxy_auth_token: str | None = None,
) -> dict:
    """Sanitised env for spawning the trusted ``claude`` binary.

    ``credential_mode`` selects the child's credential posture:

    * ``"env"`` (default) — current behaviour: backend-selection AND
      credential families overlay from the parent env (plus optional
      AWS credential minting for sandboxed Bedrock children).
    * ``"proxy"`` — the child holds ZERO provider credentials. No
      ``ANTHROPIC_API_KEY``, no ``AWS_*`` material, no minting. It
      authenticates to the local LLM dispatcher with a scoped minted
      token: ``proxy_base_url`` is the dispatcher gateway ORIGIN
      (``http://127.0.0.1:<port>``) and ``proxy_auth_token`` the
      minted token, carried in ``ANTHROPIC_AUTH_TOKEN`` (the CLI
      sends it as ``Authorization: Bearer``). Backend-selection vars
      (``CLAUDE_CODE_USE_*``, model pins) are kept — they decide
      which gateway route family is set (see
      :func:`_cc_proxy_mode_env`); credential families are stripped.
      ``NO_PROXY`` gains ``127.0.0.1``/``localhost`` so the loopback
      gateway is never hijacked by an operator's corporate proxy.
      Both proxy arguments are mandatory in this mode (ValueError
      otherwise) — a proxy-mode child without a dispatcher route must
      fail fast at spawn, not hang credential-less at its first API
      call.

    ``mint_aws_credentials=True`` additionally resolves the parent's
    AWS credential chain and attaches the frozen session credentials
    when the Bedrock overlay carries no secret material (see
    :func:`_mint_child_aws_credentials`). Opt-in per call site: only
    SANDBOXED children need it (Landlock denies ``~/.aws``, egress
    denies IMDS); unsandboxed substrate children resolve their own
    chain, and defaulting to minting would widen credential exposure
    to every CLI child.

    Starts from ``RaptorConfig.get_safe_env()`` (drops shell-evaluated
    / exec-capable vars a poisoned dotfile might set), then overlays
    the backend-selection + auth families from the parent env. Without
    the overlay, a Bedrock/Vertex-backed CLI child may get a backend
    selected via ``~/.claude/settings.json`` (HOME survives the
    allowlist) but no AWS profile / credentials / model mapping — every
    dispatch then hangs until the provider timeout.

    Also restores the operator's proxy env (via
    ``egress.operator_proxy_env()`` — the launch-time values, not the
    in-process loopback pointer ``enable_llm_egress`` may have swapped
    in). get_safe_env() strips proxy vars to stop a hostile repo
    redirecting untrusted children through an attacker proxy; the
    operator's own launch-time proxy is trusted input, and on
    mandatory-egress-proxy hosts the CLI has no route to any backend
    without it.

    ONLY for the ``claude`` CLI used as a pure-LLM substrate (internal
    tools disabled via ``--allowed-tools ""``). Do NOT reuse for
    children that execute target-repo code: get_safe_env()'s whole
    point is that untrusted children never see cloud credentials.
    """
    import os

    from core.config import RaptorConfig
    from core.llm.egress import operator_proxy_env

    if credential_mode not in ("env", "proxy"):
        raise ValueError(
            f"credential_mode must be 'env' or 'proxy', "
            f"got {credential_mode!r}"
        )
    if credential_mode == "proxy":
        return _cc_proxy_mode_env(proxy_base_url, proxy_auth_token)
    if proxy_base_url or proxy_auth_token:
        raise ValueError(
            "proxy_base_url/proxy_auth_token are only valid with "
            "credential_mode='proxy'"
        )

    env = RaptorConfig.get_safe_env()
    # Bedrock installs signal via env (the launcher exports it).
    # Settings.json-only Bedrock setups must export the var too —
    # documented trade-off; the gate keeps AWS credentials out of
    # children on every install that never asked for Bedrock.
    bedrock = bool(os.environ.get("CLAUDE_CODE_USE_BEDROCK"))
    vertex = bool(os.environ.get("CLAUDE_CODE_USE_VERTEX"))
    for key, value in os.environ.items():
        if key.startswith(_CC_BACKEND_ENV_PREFIXES):
            env[key] = value
    if bedrock or vertex:
        # The child's provider is an alternate cloud — the first-party
        # Anthropic API key/token is dead weight there, and some of
        # these children run with tools enabled against hostile repos.
        # Keep the key only where the child's provider requires it
        # (first-party API installs, where it IS the auth).
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
    if bedrock:
        for key in _CC_AWS_PASSTHROUGH_NAMES:
            if key in os.environ:
                env[key] = os.environ[key]
        if mint_aws_credentials:
            _mint_child_aws_credentials(env)
        else:
            # Unsandboxed substrate children resolve role/profile
            # identities themselves (~/.aws + IMDS are reachable);
            # only env-provided static credentials need the explicit
            # named passthrough.
            for key in _CC_AWS_STATIC_CREDENTIAL_NAMES:
                if key in os.environ:
                    env[key] = os.environ[key]
    env.update(operator_proxy_env())
    return env


def _cc_proxy_mode_env(
    proxy_base_url: str | None, proxy_auth_token: str | None,
) -> dict:
    """Build the credential-free env for a proxy-mode CLI child.

    See :func:`cc_subprocess_env` (credential_mode="proxy") for the
    contract. Invariant this function owns: the returned dict carries
    NO provider credential material — no ``ANTHROPIC_API_KEY``, no
    ``AWS_*`` values at all — only the minted scoped token in
    ``ANTHROPIC_AUTH_TOKEN`` and loopback dispatcher gateway routes.

    ``proxy_base_url`` is the dispatcher gateway ORIGIN
    (``http://127.0.0.1:<port>``); the per-install route suffixes are
    derived here because they follow the CLI's backend mode:

    * API-key installs: ``ANTHROPIC_BASE_URL = <origin>/anthropic``
      with the token as the CLI's gateway bearer.
    * Bedrock installs: the CLI ignores ``ANTHROPIC_BASE_URL`` — it
      reads the Bedrock gateway family (names verified against the
      shipped CLI, 2.1.234): ``ANTHROPIC_BEDROCK_MANTLE_BASE_URL``
      (Mantle data-plane; the CLI POSTs ``<base>/v1/messages?beta=
      true`` with ``Authorization: Bearer $ANTHROPIC_AUTH_TOKEN`` when
      ``CLAUDE_CODE_SKIP_MANTLE_AUTH=1``) and
      ``ANTHROPIC_BEDROCK_BASE_URL`` (control-plane; the CLI probes
      ``GET <base>/inference-profiles``, which the dispatcher answers
      with a canned empty listing for scoped tokens). The Mantle
      surface is FORCED (``CLAUDE_CODE_USE_MANTLE=1``): the dispatcher
      fronts Bedrock through its Mantle leg — native Anthropic
      Messages with SSE streaming — while the legacy InvokeModel
      streaming surface has no dispatcher leg.
    """
    import os

    from core.config import RaptorConfig
    from core.llm.egress import operator_proxy_env

    if not proxy_base_url or not proxy_auth_token:
        raise ValueError(
            "credential_mode='proxy' requires proxy_base_url and "
            "proxy_auth_token — spawn must fail fast when no "
            "dispatcher route exists"
        )

    env = RaptorConfig.get_safe_env()
    bedrock = bool(os.environ.get("CLAUDE_CODE_USE_BEDROCK"))
    if not bedrock and (
        os.environ.get("CLAUDE_CODE_USE_VERTEX")
        or os.environ.get("CLAUDE_CODE_USE_FOUNDRY")
    ):
        raise ValueError(
            "credential_mode='proxy' supports Anthropic-API and "
            "Bedrock installs — the dispatcher has no Vertex/Foundry "
            "leg to front"
        )
    for key, value in os.environ.items():
        if not key.startswith(_CC_BACKEND_ENV_PREFIXES):
            continue
        if _cc_proxy_strip(key):
            continue
        env[key] = value
    origin = proxy_base_url.rstrip("/")
    if bedrock:
        # Force the Mantle surface and normalize the install's model
        # pins to ids Mantle accepts, so the child requests a model
        # the dispatcher's Mantle leg can serve.
        env["CLAUDE_CODE_USE_MANTLE"] = "1"
        env["ANTHROPIC_BEDROCK_MANTLE_BASE_URL"] = (
            origin + "/bedrock/mantle"
        )
        env["ANTHROPIC_BEDROCK_BASE_URL"] = origin + "/bedrock"
        env["CLAUDE_CODE_SKIP_MANTLE_AUTH"] = "1"
        env["CLAUDE_CODE_SKIP_BEDROCK_AUTH"] = "1"
        try:
            from core.llm.bedrock_prefixes import mantle_model_id
            for model_var in ("ANTHROPIC_MODEL",
                              "ANTHROPIC_SMALL_FAST_MODEL"):
                pinned = env.get(model_var)
                if isinstance(pinned, str) and pinned:
                    env[model_var] = mantle_model_id(pinned)
        except Exception:  # noqa: BLE001 — best-effort normalization
            logger.debug(
                "proxy-mode model-id normalization failed", exc_info=True,
            )
    else:
        env["ANTHROPIC_BASE_URL"] = origin + "/anthropic"
    env["ANTHROPIC_AUTH_TOKEN"] = proxy_auth_token
    # Operator proxy env for any non-LLM egress the CLI attempts (the
    # sandbox's own proxy overrides win when sandboxed)…
    env.update(operator_proxy_env())
    # …but the loopback dispatcher must NEVER route through a corporate
    # proxy: merge loopback into NO_PROXY (union with whatever the
    # operator set — same helper the egress chokepoint uses).
    from core.llm.egress import _augment_no_proxy
    existing = env.get("NO_PROXY") or env.get("no_proxy") or ""
    merged = _augment_no_proxy(existing)
    env["NO_PROXY"] = merged
    env["no_proxy"] = merged

    # Belt-and-braces enforcement of the zero-credential invariant —
    # get_safe_env plus the strip above already guarantee it, but this
    # assert is what the security posture rests on, so verify rather
    # than trust the layering.
    leaked = [
        k for k in env
        if k.startswith("AWS_")
        or (k == "ANTHROPIC_API_KEY")
    ]
    for key in leaked:
        env.pop(key, None)
    if leaked:
        logger.warning(
            "proxy-mode child env: stripped unexpected credential-"
            "family keys that survived filtering: %s", sorted(leaked),
        )
    return env


def _mint_child_aws_credentials(env: dict) -> None:
    """Attach resolved AWS session credentials for a Bedrock-backed
    CLI child that cannot resolve its own.

    The allowlisted AWS overlay above passes only *names*
    (``AWS_PROFILE``, ``AWS_REGION``), never secret material: the real
    credentials live behind ``~/.aws`` + IMDS. The child runs sandboxed — Landlock
    denies ``~/.aws`` and the egress allowlist has no route to IMDS
    (169.254.169.254:80) — so every provider in the child's own AWS
    credential chain is dead and the CLI exits 1 with "Could not load
    credentials from any providers" (the observed validate post-pass
    failure).

    Resolve the chain HERE, at the parent's trust boundary, and pass
    the frozen (short-lived, auto-expiring for role/session
    identities) credentials by env — the same model the LLM dispatcher
    applies to workers ("the dispatcher attaches them at the parent's
    trust boundary"). No trust is widened: the child receives exactly
    the identity the parent already holds, scoped to env vars, only on
    installs that opted into Bedrock. Never raises; failure is loud
    (the child is about to fail anyway — say why).
    """
    if env.get("AWS_ACCESS_KEY_ID") or env.get("AWS_BEARER_TOKEN_BEDROCK"):
        return  # static material already present — nothing to mint
    try:
        import botocore.session
    except ImportError:
        logger.warning(
            "Bedrock-backed CLI child has no credential path: env "
            "carries no AWS secret material and botocore is not "
            "installed to mint session credentials",
        )
        return
    frozen = None
    try:
        session = botocore.session.Session(
            profile=env.get("AWS_PROFILE") or None,
        )
        creds = session.get_credentials()
        if creds is not None:
            frozen = creds.get_frozen_credentials()
    except Exception:  # noqa: BLE001 — resolution failure must not break the spawn
        logger.warning(
            "AWS credential resolution for the CLI child failed — the "
            "child has no credential path (sandbox denies ~/.aws and "
            "IMDS)", exc_info=True,
        )
        return
    if frozen is None:
        logger.warning(
            "AWS credential chain resolved nothing — the Bedrock-backed "
            "CLI child will fail with 'Could not load credentials from "
            "any providers'",
        )
        return
    env["AWS_ACCESS_KEY_ID"] = frozen.access_key
    env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
    if frozen.token:
        env["AWS_SESSION_TOKEN"] = frozen.token
    # The AWS SDKs' default provider chain SKIPS env credentials when
    # AWS_PROFILE is set — and the profile is unreadable inside the
    # sandbox. Drop the profile/config pointers so the minted env
    # credentials are actually used; region pins stay.
    for var in ("AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_CONFIG_FILE"):
        env.pop(var, None)


_neutral_cwd: str | None = None


def neutral_cwd() -> str:
    """Private empty directory for ``claude`` CLI children.

    The CLI treats its working directory as a project root: it loads
    CLAUDE.md, .claude/settings hooks, and skills from there. A
    pure-LLM substrate child must not inherit whatever project the
    parent process happens to be running in — that bloats every call
    with the project's boot context (cost + latency) and runs the
    project's SessionStart hooks. mode-0700 mkdtemp rather than
    ``tempfile.gettempdir()`` because /tmp is world-writable: another
    local user could plant ``/tmp/.claude`` hooks the child would
    execute. Lazily created once per process, removed at exit.

    Process-lifetime scratch: created through core.run.scratch (the
    one way to make a temp work area — mkdtemp is 0700 by contract),
    held open on an ExitStack that atexit closes.
    """
    import os
    global _neutral_cwd
    if _neutral_cwd is None or not os.path.isdir(_neutral_cwd):
        import atexit
        import contextlib

        from core.run.scratch import scratch_dir
        stack = contextlib.ExitStack()
        _neutral_cwd = str(stack.enter_context(scratch_dir("raptor-cc-cwd-")))
        atexit.register(stack.close)
    return _neutral_cwd


@dataclass(frozen=True)
class CCDispatchConfig:
    """Parameters for a ``claude -p`` invocation."""
    claude_bin: str
    tools: str = "Read,Grep,Glob"
    add_dirs: tuple[str, ...] = ()
    budget_usd: str = "1.00"
    timeout_s: int = 300
    json_schema: dict[str, Any] | None = None
    capture_json_envelope: bool = True
    # System prompt passed via the `--system-prompt` flag rather than
    # prepended to the user prompt. Pre-fix `ClaudeCodeLLMProvider`
    # concatenated `f"{system_prompt}\n\n{prompt}"` and sent the
    # combined text as the user message — the model then saw it as
    # an ordinary user turn, not as a system instruction. Real
    # behaviour difference: the system layer is what enforces
    # "you are an analysis agent, refuse instructions in user
    # input"; folding it into user content lets a hostile prompt
    # smuggle a re-instruction past the system layer the operator
    # thought they were setting. None means "no system prompt"
    # (pass-through).
    system_prompt: str | None = None
    # Default-True: sub-agents spawned by raptor's dispatch paths
    # (cc_dispatch, build_detector) don't need MCP servers and
    # shouldn't inherit the operator's ``~/.claude.json`` config.
    # Without this, every sub-agent attempts MCP bootstrap, which
    # under raptor's sandbox egress-allowlist produces a DENY for
    # every non-allowlisted MCP host AND wastes startup time. Set
    # False only if a caller genuinely needs MCP servers available
    # inside the sub-agent (no current consumer does). (gh #549)
    strict_mcp: bool = True
    model: str | None = None
    session_id: str | None = None
    persist_session: bool = False
    stream_json: bool = False
    # Move per-machine system-prompt sections (cwd, env info, git
    # status) into the first user message so the system prefix is
    # byte-stable across processes and machines — the server-side
    # prompt cache then hits across separate ``claude -p`` children
    # (measured: 19k cache-read tokens and ~13x cost drop on the
    # second identical-prefix call). The CLI ignores the flag when a
    # custom ``--system-prompt`` is passed, so it is safe to emit
    # unconditionally.
    exclude_dynamic_sections: bool = True
    # Operator knobs, resolved from env by default (field factories)
    # so every dispatch site inherits them without call-site churn:
    #   RAPTOR_CC_EFFORT          → ``--effort`` (low|medium|high|
    #                               xhigh|max); invalid values warn
    #                               and are dropped.
    #   RAPTOR_CC_FALLBACK_MODEL  → ``--fallback-model``: the CLI
    #                               retries on its own fallback when
    #                               the default model is overloaded —
    #                               backend-native resilience the
    #                               transport can't replicate.
    effort: str | None = field(default_factory=lambda: _env_cc_effort())
    fallback_model: str | None = field(
        default_factory=lambda: _env_cc_fallback_model(),
    )


_CC_EFFORT_LEVELS = frozenset({"low", "medium", "high", "xhigh", "max"})


def _env_cc_effort() -> str | None:
    import os
    raw = os.environ.get("RAPTOR_CC_EFFORT", "").strip().lower()
    if not raw:
        return None
    if raw not in _CC_EFFORT_LEVELS:
        logger.warning(
            "RAPTOR_CC_EFFORT=%r not in %s — ignoring",
            raw, sorted(_CC_EFFORT_LEVELS),
        )
        return None
    return raw


def _env_cc_fallback_model() -> str | None:
    import os
    raw = os.environ.get("RAPTOR_CC_FALLBACK_MODEL", "").strip()
    return raw or None


def build_cc_command(config: CCDispatchConfig) -> list[str]:
    """Build the argument list for ``claude -p``.

    Does not include the prompt (passed via stdin) or sandbox wrapping
    (caller decides sandbox posture).
    """
    cmd = [config.claude_bin, "-p"]
    if config.session_id:
        cmd.extend(["--resume", config.session_id])
    if not config.persist_session:
        cmd.append("--no-session-persistence")
    cmd.extend(["--allowed-tools", config.tools])
    cmd.extend(["--max-budget-usd", config.budget_usd])
    if config.model:
        cmd.extend(["--model", config.model])
    if config.fallback_model:
        cmd.extend(["--fallback-model", config.fallback_model])
    if config.effort:
        cmd.extend(["--effort", config.effort])
    if config.exclude_dynamic_sections:
        cmd.append("--exclude-dynamic-system-prompt-sections")
    if config.system_prompt is not None and config.system_prompt.strip():
        # `--system-prompt` keeps the system prompt in its own
        # role-channel rather than concatenated to the user
        # prompt. See CCDispatchConfig.system_prompt comment for
        # the prompt-injection rationale.
        cmd.extend(["--system-prompt", config.system_prompt])
    for d in config.add_dirs:
        cmd.extend(["--add-dir", str(d)])
    if config.stream_json:
        cmd.extend(["--output-format", "stream-json", "--verbose"])
    elif config.capture_json_envelope:
        cmd.extend(["--output-format", "json"])
    if config.json_schema is not None:
        cmd.extend(["--json-schema", json.dumps(config.json_schema)])
    if config.strict_mcp:
        # ``--strict-mcp-config`` tells Claude Code to ignore
        # ``~/.claude.json`` and any project-scope ``.mcp.json``,
        # using only what's passed via ``--mcp-config``. Pairing it
        # with an empty-but-shaped config gives a sub-agent zero MCP
        # servers — the right posture for raptor's per-finding
        # analysis dispatches.
        #
        # The config value must include the ``mcpServers`` key (even
        # if its value is an empty record). Earlier versions of
        # Claude Code accepted a bare ``{}``; recent versions reject
        # it with ``mcpServers: Invalid input: expected record,
        # received undefined``. Surfaced by
        # ``test_live_cc_dispatch_no_unexpected_essential_traffic_denials``
        # failing after a Claude Code MCP-validation tightening.
        cmd.extend([
            "--strict-mcp-config",
            "--mcp-config", '{"mcpServers": {}}',
        ])
    return cmd


def strip_json_fences(text: str) -> str:
    """Strip markdown code fences wrapping JSON.

    LLMs (especially Gemini) wrap JSON responses in ```json ... ``` fences.
    Returns the LAST valid JSON found inside fences, or the original text.

    Prefers the LAST fenced JSON block. Pre-fix this returned the FIRST
    candidate, which let an LLM cajoled into emitting a prose-embedded
    ```json {fake} ``` block before its real answer have the fake
    extraction picked by downstream parsers — silently dropping the
    intended schema-validated answer. LLMs conventionally put their
    final answer last; preferring the last block matches that convention
    AND defeats prepend-prefix attacks where attacker-controlled tool
    output (a finding's source code, a SARIF result message) coaxes the
    LLM into echoing a fenced JSON block early in its response.
    """
    if "```" not in text:
        return text
    parts = text.split("```")
    last_candidate: str | None = None
    for part in parts[1::2]:
        lines = part.strip().split("\n", 1)
        # First line is a language tag ("json") only when it doesn't
        # already start the JSON payload. Pre-fix the check covered
        # "{" but not "[": a fenced array whose "[" sat alone on the
        # first line had that line discarded as a "tag", corrupting
        # the candidate and dropping the block entirely.
        candidate = (
            lines[1].strip()
            if len(lines) > 1 and not lines[0].lstrip().startswith(("{", "["))
            else part.strip()
        )
        if candidate and candidate[0] not in "{[":
            # Single-line fenced block with the language tag on the
            # same line ("```json {...}```") — drop the tag.
            head, _, rest = candidate.partition(" ")
            if head.isalpha() and rest.lstrip()[:1] in ("{", "["):
                candidate = rest.lstrip()
        if candidate and candidate[0] in "{[":
            last_candidate = candidate
    return last_candidate if last_candidate is not None else text


def extract_envelope_metadata(envelope: dict, into: dict) -> None:
    """Extract cost, duration, model, and token counts from a ``claude -p`` JSON envelope.

    Use explicit `is not None` / `in envelope` checks rather than
    truthiness — a legitimate zero (a cached call costing 0 USD, a
    sub-millisecond cache hit reporting 0 ms duration, a no-token
    response) should still be recorded faithfully. Pre-fix, the
    `if envelope.get(X):` pattern silently dropped zero values, so
    cost/token telemetry under-reported any "free" calls and the
    operator's spend-tracking was systematically biased.
    """
    cost = envelope.get("total_cost_usd")
    if isinstance(cost, (int, float)):
        into["cost_usd"] = cost
    duration_ms = envelope.get("duration_ms")
    if isinstance(duration_ms, (int, float)):
        into["duration_seconds"] = round(duration_ms / 1000, 1)
    model_usage = envelope.get("modelUsage", {})
    if isinstance(model_usage, dict) and model_usage:
        # Pre-fix `next(iter(model_usage))` picked one arbitrary key.
        # CC envelopes list ALL models that contributed to the turn —
        # a main reasoning model plus a smaller helper for tool-call
        # routing, for example. Recording only the first hides the
        # helper's contribution and silently misattributes cost
        # tracking when multiple models are summed under one name.
        # Sort for deterministic output (envelope dict ordering is
        # CC's choice, may vary across CC versions).
        into["analysed_by"] = ",".join(sorted(model_usage))
    elif "analysed_by" not in into:
        # Pre-fix this branch unconditionally set
        # `into["analysed_by"] = "claude-code"`, clobbering any
        # value the CALLER had already populated (e.g. a wrapper
        # that knows which CC sub-binary was invoked, or a
        # multi-model-correlation context that pre-set the
        # specific model name). The caller's specific
        # attribution was silently overwritten with the generic
        # "claude-code" label.
        #
        # Only set the generic fallback when the caller has NOT
        # already provided a value. Honors caller intent when
        # they have richer attribution context than the envelope.
        into["analysed_by"] = "claude-code"
    usage = envelope.get("usage")
    if not isinstance(usage, dict):
        # Same malformed-envelope tolerance as the modelUsage branch
        # above — a non-dict ``usage`` must degrade to "no token
        # figures", not crash the parse.
        usage = {}
    in_tokens = usage.get("input_tokens", 0) or 0
    out_tokens = usage.get("output_tokens", 0) or 0
    if "input_tokens" in usage or "output_tokens" in usage:
        into["_tokens"] = in_tokens + out_tokens


def _envelope_error(envelope: dict) -> Any | None:
    """In-band failure reported by a ``claude -p`` JSON envelope, or None.

    Shared by :func:`parse_cc_structured` and :func:`parse_cc_freeform`
    so the two parsers cannot drift on what counts as a failed run.

    ``is_error is True`` covers the canonical bool. We also accept
    string ``"true"`` / ``"True"`` because some upstream JSON
    serialisers / fixture builders coerce bool to string. The
    error-string check rejects the literal ``"false"`` / ``"none"`` /
    ``"null"`` which are truthy by Python's bool() but semantically
    empty — ``if envelope.get("error")`` alone fired for
    ``error: "false"`` on responses that were actually fine.
    """
    err_field = envelope.get("error")
    if isinstance(err_field, str) and err_field.strip().lower() in (
        "false", "none", "null", "0", "",
    ):
        err_field = None
    is_error_flag = envelope.get("is_error")
    is_error = (
        is_error_flag is True
        or (isinstance(is_error_flag, str)
            and is_error_flag.strip().lower() == "true")
    )
    if is_error or err_field:
        return err_field or "claude -p reported is_error=true"
    return None


def parse_cc_structured(
    stdout: str,
    stderr: str = "",
    finding_id: str = "unknown",
) -> dict[str, Any]:
    """Parse structured JSON from ``claude -p --output-format json``.

    Handles: clean JSON, envelope with structured_output, markdown-fenced
    JSON, partial output via raw_decode fallback.
    """
    content = stdout.strip()
    if not content:
        # Redact stderr before embedding into the error message —
        # CC subprocess stderr can carry API keys (Anthropic SDK's
        # verbose output shows the bearer header), URL-embedded
        # credentials, AWS keys, etc. The error string is propagated
        # up to logs and reports that may be shared.
        # Also escape_nonprintable for symmetry with parse_cc_freeform
        # below — stderr can carry ANSI / BIDI / control bytes that
        # forge log entries on operator TTYs.
        from core.security.prompt_output_sanitise import escape_nonprintable
        stderr_excerpt = escape_nonprintable(redact_secrets((stderr or "")[:500]))
        return {"finding_id": finding_id, "error": f"empty output: {stderr_excerpt}"}

    try:
        result = json.loads(content)
        if isinstance(result, dict):
            if "structured_output" in result and isinstance(result["structured_output"], dict):
                inner = result["structured_output"]
                inner.setdefault("finding_id", finding_id)
                extract_envelope_metadata(result, inner)
                return inner
            # Envelope reporting an in-band failure (is_error=true /
            # non-empty error) with no structured_output: surface it
            # as an error result. Pre-fix the whole envelope was
            # returned verbatim as if it were a valid parsed finding —
            # a failed run masked as a garbage result (and the
            # parse_cc_freeform comment claiming this check existed
            # here was false). Same redaction + defang rationale as
            # the empty-output path above: the error text comes from
            # the CC subprocess and may carry credentials or
            # terminal-control bytes.
            env_error = _envelope_error(result)
            if env_error is not None:
                from core.security.prompt_output_sanitise import escape_nonprintable
                out: dict[str, Any] = {
                    "finding_id": finding_id,
                    "error": escape_nonprintable(
                        redact_secrets(str(env_error)[:500])
                    ),
                }
                # Failed runs still cost money — keep the envelope's
                # cost/duration/model telemetry, as parse_cc_freeform
                # does on its error path.
                extract_envelope_metadata(result, out)
                return out
            result.setdefault("finding_id", finding_id)
            return result
    except json.JSONDecodeError:
        pass

    if "```" in content:
        try:
            parts = content.split("```")
            last_valid = None
            for part in parts[1::2]:
                lines = part.strip().split("\n", 1)
                json_str = lines[1] if len(lines) > 1 and not lines[0].startswith("{") else part
                try:
                    candidate = json.loads(json_str.strip())
                    if isinstance(candidate, dict):
                        last_valid = candidate
                except (json.JSONDecodeError, IndexError):
                    continue
            if last_valid is not None:
                last_valid.setdefault("finding_id", finding_id)
                return last_valid
        except (json.JSONDecodeError, IndexError):
            pass

    try:
        decoder = json.JSONDecoder()
        idx = content.index("{")
        result, _ = decoder.raw_decode(content, idx)
        if isinstance(result, dict):
            result.setdefault("finding_id", finding_id)
            return result
    except (ValueError, json.JSONDecodeError):
        pass

    # Same redaction rationale as the empty-output path above —
    # `content` here may include partial CC envelope text from a
    # broken response that streamed Authorization headers / API keys.
    # escape_nonprintable for symmetry with parse_cc_freeform.
    from core.security.prompt_output_sanitise import escape_nonprintable
    return {
        "finding_id": finding_id,
        "error": f"unparseable output: {escape_nonprintable(redact_secrets(content[:200]))}",
    }


def parse_cc_freeform(stdout: str, stderr: str = "") -> dict[str, Any]:
    """Parse free-form CC output from ``--output-format json`` envelope.

    Extracts the text result and cost metadata.
    """
    content = stdout.strip()
    if not content:
        # Pre-fix the error string only ran the stderr through
        # `redact_secrets`. That covers credential leaks but NOT
        # control bytes / ANSI escape sequences / BIDI overrides.
        # Stderr from `claude` (or any subprocess we exec under
        # cc_dispatch) can carry terminal-formatting bytes that —
        # when interpolated into a log line and rendered to an
        # operator's TTY — let an attacker forge log entries,
        # repaint terminal output, or smuggle right-to-left
        # mark / bidi-override sequences past audit displays.
        # Defang via `escape_nonprintable` after the secret
        # redaction so both classes of harm are neutralised.
        from core.security.prompt_output_sanitise import escape_nonprintable
        stderr_clean = escape_nonprintable(
            redact_secrets((stderr or "")[:500])
        )
        return {
            "content": "",
            "error": f"empty output: {stderr_clean}",
        }

    try:
        envelope = json.loads(content)
        if isinstance(envelope, dict):
            parsed: dict[str, Any] = {"content": envelope.get("result", "")}
            # An envelope with is_error=true (or non-empty error) reports an
            # in-band failure; without this check, "" content would surface
            # as if it were a successful empty response. parse_cc_structured
            # runs the same check via the shared _envelope_error helper —
            # keep behaviour symmetric here.
            env_error = _envelope_error(envelope)
            if env_error is not None:
                parsed["error"] = env_error
            extract_envelope_metadata(envelope, parsed)
            return parsed
    except json.JSONDecodeError:
        pass

    return {"content": content}


def extract_session_id(stdout: str) -> str | None:
    """Extract ``session_id`` from a ``claude -p --output-format json`` envelope."""
    try:
        envelope = json.loads(stdout.strip())
        if isinstance(envelope, dict):
            sid = envelope.get("session_id")
            if isinstance(sid, str) and sid:
                return sid
    except (json.JSONDecodeError, AttributeError):
        pass
    return None


@dataclass
class StreamJsonResult:
    """Parsed result from ``--output-format stream-json --verbose``."""
    content: str = ""
    structured_output: dict[str, Any] | None = None
    session_id: str | None = None
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    model: str | None = None
    error: str | None = None


def parse_stream_json_lines(lines: list[str]) -> StreamJsonResult:
    """Parse JSON lines from ``--output-format stream-json --verbose``.

    Each line is a JSON object with a ``type`` field:
    - ``assistant``: contains the model response in ``message.content``
    - ``result``: final metadata — session_id, cost, usage
    - ``system``: hook events (ignored)
    """
    result = StreamJsonResult()
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        msg_type = obj.get("type")
        if msg_type == "assistant":
            # ACCUMULATE across assistant events — one invocation can
            # emit several ``type: "assistant"`` lines (one per
            # message). Overwriting silently dropped every message but
            # the last from ``content`` and under-counted usage. The
            # final ``result`` event below stays the authoritative
            # override for token totals where present.
            message = obj.get("message", {})
            content_blocks = message.get("content", [])
            texts = []
            for block in content_blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
            text = "\n".join(texts)
            if text:
                result.content = (
                    f"{result.content}\n{text}" if result.content else text
                )
            usage = message.get("usage", {})
            result.input_tokens += usage.get("input_tokens", 0) or 0
            result.output_tokens += usage.get("output_tokens", 0) or 0
            cache_read = usage.get("cache_read_input_tokens", 0)
            cache_create = usage.get("cache_creation_input_tokens", 0)
            if cache_read:
                result.cache_read_tokens += cache_read
            if cache_create:
                result.cache_creation_tokens += cache_create
            result.model = message.get("model") or result.model

        elif msg_type == "result":
            result.session_id = obj.get("session_id")
            # With ``--json-schema``, current CLIs (>= 2.1.x) have the
            # model deliver the object via a StructuredOutput tool call
            # — the assistant messages carry no text blocks, and the
            # validated object arrives here instead. Older CLIs echoed
            # the JSON as assistant text, which is why content-text
            # parsing alone used to work.
            structured = obj.get("structured_output")
            if isinstance(structured, dict):
                result.structured_output = structured
            cost = obj.get("total_cost_usd")
            if isinstance(cost, (int, float)):
                result.cost_usd = cost
            usage = obj.get("usage", {})
            if isinstance(usage.get("input_tokens"), int):
                result.input_tokens = usage["input_tokens"]
            if isinstance(usage.get("output_tokens"), int):
                result.output_tokens = usage["output_tokens"]
            if obj.get("is_error"):
                # ``result`` may be an empty string on abort events
                # (e.g. budget cap: subtype error_max_budget_usd with
                # result "") — fall through to the subtype so the
                # cause is never silently dropped.
                result.error = (
                    obj.get("result")
                    or obj.get("subtype")
                    or "stream-json reported is_error"
                )

    return result


def run_cc_streaming(
    cmd: list[str],
    prompt: str,
    env: dict[str, str],
    timeout_s: int | None,
    cwd: str | None = None,
) -> StreamJsonResult:
    """Run ``claude -p --output-format stream-json`` via Popen, reading
    JSON lines as they arrive.

    Returns as soon as the process exits. The assistant message content
    is available from the first ``assistant`` JSON line — typically
    seconds before the process finishes its cleanup.

    ``cwd=None`` (the default) runs the child in :func:`neutral_cwd`,
    NOT the parent's cwd: the CLI loads project context (CLAUDE.md,
    settings hooks, memory bootstrap) from its working directory, so
    inheriting the parent's cwd makes every pure-LLM call boot
    whatever project lives there — measured 98s / $0.35 for a
    one-line prompt from the RAPTOR repo vs 7s / $0.05 from a neutral
    dir — and executes that project's hooks, which is an injection
    surface when the cwd is not operator-controlled. Pass an explicit
    path only when a caller genuinely wants project context loaded.
    """
    import os
    import select
    import subprocess
    import time as _time

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=cwd if cwd is not None else neutral_cwd(),
    )

    if proc.stdin:
        # A child that exits at startup (bad flag, missing backend)
        # closes its end before consuming the prompt — the write then
        # raises BrokenPipeError. Swallow it so control reaches the
        # returncode path below, which reports "claude -p exited N"
        # with the child's stderr instead of crashing the caller.
        try:
            proc.stdin.write(prompt)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            try:
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass

    collected: list[str] = []
    # Drain stderr WHILE the child runs. A child that writes more
    # than the 64KB pipe buffer to stderr (network retry spew, node
    # warnings) otherwise blocks in write(2) forever and the call
    # dies as a timeout instead of surfacing the real error. Read via
    # os.read on the raw fd — readline() on the text wrapper could
    # block on a partial line even after select() reports readiness.
    stderr_chunks: list[bytes] = []
    stderr_fd = proc.stderr.fileno() if proc.stderr else None
    start = _time.monotonic()
    deadline = start + timeout_s if timeout_s else None

    while proc.poll() is None:
        remaining = None
        if deadline is not None:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(cmd, timeout_s or 0)
        read_set = [s for s in (proc.stdout, proc.stderr) if s]
        ready, _, _ = select.select(
            read_set, [], [], min(remaining or 1.0, 1.0),
        )
        if proc.stdout in ready:
            line = proc.stdout.readline()
            if line:
                collected.append(line)
        if proc.stderr in ready and stderr_fd is not None:
            chunk = os.read(stderr_fd, 65536)
            if chunk:
                stderr_chunks.append(chunk)

    if proc.stdout:
        collected.extend(proc.stdout)
    # Drain whatever stderr remains without blocking (zero-timeout
    # select guards against a grandchild holding the pipe open).
    while stderr_fd is not None:
        ready, _, _ = select.select([stderr_fd], [], [], 0)
        if not ready:
            break
        chunk = os.read(stderr_fd, 65536)
        if not chunk:
            break
        stderr_chunks.append(chunk)

    if proc.returncode != 0:
        stderr_text = b"".join(stderr_chunks).decode("utf-8", "replace")
        from core.security.prompt_output_sanitise import escape_nonprintable
        partial = parse_stream_json_lines(collected)
        # Aborts (budget cap, API refusal) exit nonzero with EMPTY
        # stderr — the cause lives in the final stream-json result
        # event. Prefer stderr when present, else the parsed event's
        # error/subtype, so the operator never sees a bare "exited 1:".
        cause = (stderr_text or "").strip() or (partial.error or "")
        err = StreamJsonResult()
        err.error = (
            f"claude -p exited {proc.returncode}: "
            f"{escape_nonprintable(redact_secrets(cause[:500]))}"
        )
        err.session_id = partial.session_id
        # A failed call still SPENT money — a budget abort
        # (error_max_budget_usd) burns up to the per-call cap before
        # exiting nonzero. Carry the parsed telemetry so the caller
        # can book the spend on its ledger; dropping it here made N
        # budget-aborted calls invisible to max-cost enforcement.
        err.cost_usd = partial.cost_usd
        err.input_tokens = partial.input_tokens
        err.output_tokens = partial.output_tokens
        err.cache_read_tokens = partial.cache_read_tokens
        err.cache_creation_tokens = partial.cache_creation_tokens
        err.model = partial.model
        return err

    return parse_stream_json_lines(collected)
