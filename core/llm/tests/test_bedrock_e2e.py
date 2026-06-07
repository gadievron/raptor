#!/usr/bin/env python3
"""End-to-end live test for Bedrock support — exercises the full
Phase 1 + 1.5 path with a real AWS account.

Runs as either:
  * ``pytest core/llm/tests/test_bedrock_e2e.py`` (auto-skipped
    when no AWS Bedrock credentials are present in env), or
  * ``python core/llm/tests/test_bedrock_e2e.py`` (operator-driven
    direct run with verbose stepwise output and non-zero exit on
    any failed step).

Re-execs itself in ``--worker <model>`` mode as a subprocess spawned
by the dispatcher's ``spawn_worker`` helper, so the worker
inherits ``RAPTOR_LLM_SOCKET`` + ``RAPTOR_LLM_TOKEN_FD`` and the
real LLM call goes through the full credential-isolation path.

Run AFTER setting AWS credentials.  Two supported modes:

  bearer:
    export AWS_BEARER_TOKEN_BEDROCK=<token>
    export AWS_REGION=us-east-1   # or eu-*, ap-*, au-*

  SigV4 (static keys):
    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    export AWS_REGION=us-east-1
    pip install boto3                # required for SigV4 signing

The driver:
  1. Verifies detection picks up the explicit Bedrock signal.
  2. Verifies _build_bedrock_config / _get_default_primary_model
     return a Bedrock-shaped ModelConfig.
  3. Verifies family_of returns ``"anthropic"`` (cross-family safety).
  4. Verifies provider_of returns ``"bedrock"`` (routing).
  5. Starts the dispatcher with the parent's AWS creds.
  6. Makes a REAL LLM call ("ping") through the dispatcher.
  7. Prints response body, token counts, cost estimate, elapsed wall.
  8. Tears down the dispatcher.

Exits non-zero on any failure with a diagnostic.  Designed for
operator-driven verification — no implicit network access except
the explicit Bedrock call.

Cost: < $0.001 per run (single-turn ~50-token ping at Haiku pricing).
"""

from __future__ import annotations

import os
import sys
import time
import traceback


def _section(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def _ok(label: str, value=None) -> None:
    suffix = f" — {value}" if value is not None else ""
    print(f"  [OK]   {label}{suffix}", flush=True)


def _fail(label: str, detail: str) -> None:
    print(f"  [FAIL] {label}", flush=True)
    print(f"         {detail}", flush=True)


def _info(label: str, value=None) -> None:
    suffix = f" — {value}" if value is not None else ""
    print(f"  [INFO] {label}{suffix}", flush=True)


def main() -> int:
    # __file__ → core/llm/tests/test_bedrock_e2e.py — peel 4 levels
    # (file → tests → llm → core → raptor root).
    os.environ["RAPTOR_DIR"] = os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)),
            ),
        ),
    )
    sys.path.insert(0, os.environ["RAPTOR_DIR"])

    _section("0. Environment check")
    bearer = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
    ak = os.environ.get("AWS_ACCESS_KEY_ID")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION",
    )
    if bearer:
        _ok("AWS_BEARER_TOKEN_BEDROCK present", "(bearer mode)")
    elif ak and sk:
        _ok("AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY present",
            "(SigV4 mode)")
    else:
        _fail(
            "No Bedrock auth in env",
            "Set AWS_BEARER_TOKEN_BEDROCK (bearer) OR "
            "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (SigV4).",
        )
        return 2
    if not region:
        _fail("AWS_REGION not set",
              "Set AWS_REGION=us-east-1 (or eu-*/ap-*/au-*)")
        return 2
    _ok("AWS_REGION", region)

    _section("1. Detection — AWS_BEARER_TOKEN_BEDROCK opt-in path")
    from core.llm.detection import detect_llm_availability
    av = detect_llm_availability()
    if not av.external_llm:
        _fail(
            "detect_llm_availability().external_llm",
            f"got {av} — Phase 1 detection didn't pick up Bedrock signal",
        )
        return 3
    _ok("detect_llm_availability().external_llm", av.external_llm)
    _info("llm_available", av.llm_available)

    _section("2. Builder — _build_bedrock_config / "
             "_get_default_primary_model")
    from core.llm.config import (
        _build_bedrock_config,
        _get_default_primary_model,
    )
    cfg = _build_bedrock_config()
    if cfg is None:
        # Bearer may have been popped by dispatcher startup elsewhere;
        # try the primary-model resolver too.
        cfg = _get_default_primary_model()
    # E2E model pin.  Bedrock Mantle accepts bare model IDs only —
    # no date suffix, no ``-v1:0`` version, no regional prefix
    # (regional routing happens via the hostname).  Per AWS docs:
    # ``client.messages.create(model="anthropic.claude-opus-4-8", ...)``
    # Operators can override by setting ``RAPTOR_BEDROCK_E2E_MODEL``
    # to a different bare model name.
    if cfg is not None:
        e2e_bare = os.environ.get(
            "RAPTOR_BEDROCK_E2E_MODEL",
            "claude-haiku-4-5",
        )
        # Bare RAPTOR name (``claude-haiku-4-5``) → Mantle ID
        # (``anthropic.claude-haiku-4-5``).  An override that already
        # carries a provider segment is taken verbatim.
        _has_provider_segment = any(
            p in e2e_bare for p in ("anthropic.", "meta.", "mistral.", "cohere.")
        )
        if _has_provider_segment:
            e2e_model = e2e_bare
        else:
            e2e_model = f"anthropic.{e2e_bare}"
        from dataclasses import replace as _dc_replace
        from core.llm.model_data import MODEL_LIMITS
        e2e_limits = MODEL_LIMITS.get(e2e_bare, {})
        cfg = _dc_replace(
            cfg,
            model_name=e2e_model,
            max_tokens=e2e_limits.get("max_output", cfg.max_tokens),
            max_context=e2e_limits.get("max_context", cfg.max_context),
        )
        _info("E2E pinned model", e2e_model)
    if cfg is None:
        _fail(
            "Bedrock builder returned None",
            "Neither _build_bedrock_config nor "
            "_get_default_primary_model surfaced a Bedrock ModelConfig.",
        )
        return 4
    _ok("ModelConfig.provider", cfg.provider)
    _ok("ModelConfig.model_name", cfg.model_name)
    _ok("ModelConfig.max_context", cfg.max_context)
    _ok("ModelConfig.max_tokens", cfg.max_tokens)
    if "anthropic." not in cfg.model_name:
        _fail("model_name shape",
              f"expected an ``anthropic.<model>`` form, "
              f"got {cfg.model_name!r}")
        return 4

    _section("3. Security invariant — family_of stays anthropic")
    from core.security.llm_family import (
        family_of, provider_of, same_family,
    )
    fam = family_of(cfg.model_name)
    if fam != "anthropic":
        _fail("family_of", f"expected 'anthropic', got {fam!r} — "
              f"cross-family validator broken for Bedrock-Claude")
        return 5
    _ok("family_of(model)", fam)
    bare = cfg.model_name.split("anthropic.", 1)[-1]
    if not same_family(cfg.model_name, bare):
        _fail("same_family Bedrock-vs-direct",
              f"{cfg.model_name!r} and {bare!r} resolve different families "
              f"— would let cross-family validator pair them as 'independent'")
        return 5
    _ok(f"same_family({bare}, Bedrock-prefixed)", "True (security invariant)")

    _section("4. Routing invariant — provider_of returns 'bedrock'")
    prov = provider_of(cfg.model_name)
    if prov != "bedrock":
        _fail("provider_of", f"expected 'bedrock', got {prov!r} — "
              f"routing would go via direct-Anthropic, not Bedrock")
        return 6
    _ok("provider_of(model)", prov)

    _section("5. Dispatcher startup with parent's AWS creds")
    try:
        from core.llm.dispatcher.auth import (
            CredentialStore, seed_from_config,
        )
        from core.llm.dispatcher.server import LLMDispatcher
        import uuid
    except ImportError as e:
        _fail("dispatcher import", str(e))
        return 7
    creds = CredentialStore()
    seed_from_config(creds)
    dispatcher = LLMDispatcher(
        run_id=f"raptor-bedrock-e2e-{uuid.uuid4().hex[:8]}",
        creds=creds,
    )
    _ok("CredentialStore + LLMDispatcher", "started")
    _info("dispatcher.socket_path", str(dispatcher.socket_path))

    # After CredentialStore the bearer is popped from env — verify.
    if os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
        _fail("env scrub", "AWS_BEARER_TOKEN_BEDROCK still in env after "
              "CredentialStore — credential isolation broken")
        dispatcher.shutdown()
        return 7
    _ok("env scrub", "AWS_BEARER_TOKEN_BEDROCK popped post-CredentialStore")

    _section("6. Live LLM round-trip — worker subprocess → "
             "dispatcher → Bedrock → response")
    # Workers run as subprocesses spawned via the dispatcher's helper
    # so they get RAPTOR_LLM_SOCKET + RAPTOR_LLM_TOKEN_FD wired up.
    # This script re-execs itself in --worker mode for that purpose.
    try:
        from core.llm.dispatcher.spawn import spawn_worker
        import json as _json
        t0 = time.monotonic()
        proc = spawn_worker(
            dispatcher,
            cmd=[sys.executable, __file__, "--worker", cfg.model_name],
            label="bedrock_e2e_worker",
            stdout=__import__("subprocess").PIPE,
            stderr=__import__("subprocess").PIPE,
        )
        stdout_b, stderr_b = proc.communicate(timeout=60)
        elapsed = time.monotonic() - t0
        if proc.returncode != 0:
            _fail("worker exit", f"rc={proc.returncode}")
            print(f"         stderr: {stderr_b.decode(errors='replace')[:4000]}",
                  flush=True)
            dispatcher.shutdown()
            return 8
        result = _json.loads(stdout_b.decode())
    except Exception as e:
        _fail("worker spawn", f"{type(e).__name__}: {e}")
        traceback.print_exc()
        dispatcher.shutdown()
        return 8

    _ok("response.content (first 100 chars)",
        repr(result["content"][:100]))
    _ok("response.input_tokens", result["input_tokens"])
    _ok("response.output_tokens", result["output_tokens"])
    _ok("response.cost", f"${result['cost']:.6f}")
    _ok("response.finish_reason", result["finish_reason"])
    _ok("wall-clock (incl. subprocess spawn)", f"{elapsed:.2f}s")

    _section("7. Cost-tracking sanity")
    from core.llm.model_data import price_for, _bedrock_cost_multiplier
    in_per_m, out_per_m = price_for(cfg.model_name)
    mult = _bedrock_cost_multiplier(cfg.model_name)
    _ok("price_for input  per-million USD", f"{in_per_m:.4f}")
    _ok("price_for output per-million USD", f"{out_per_m:.4f}")
    _ok("regional cost multiplier", mult)
    if mult != 1.0:
        _info("surcharge active",
              "model has a known global. CRIS counterpart")

    _section("8. Dispatcher shutdown")
    dispatcher.shutdown()
    _ok("dispatcher.shutdown", "clean")

    print("\n=== E2E PASS — Bedrock fully usable through RAPTOR ===\n",
          flush=True)
    return 0


def _worker_entrypoint(model_name: str) -> int:
    """Worker subprocess: spawned by the parent via the dispatcher's
    ``spawn_worker`` so this process inherits ``RAPTOR_LLM_SOCKET``
    + ``RAPTOR_LLM_TOKEN_FD``.  Makes the real LLM call against
    Bedrock through the dispatcher and emits the response as a
    single-line JSON blob on stdout so the parent can parse it.

    """
    import json
    from core.llm.client import LLMClient
    client = LLMClient(pinned_model=model_name)
    response = client.generate(
        "Reply with exactly one word: pong.",
        task_type="bedrock_e2e",
        max_tokens=20,
    )
    payload = {
        "content": response.content,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "cost": response.cost,
        "finish_reason": response.finish_reason,
        "model": response.model,
        "provider": response.provider,
    }
    print(json.dumps(payload), flush=True)
    return 0


# ---------------------------------------------------------------------------
# pytest entry — auto-skip when no Bedrock credentials in env so the
# test suite stays green in CI / on dev boxes without AWS access.
# Operators with creds get the live verification automatically.
# ---------------------------------------------------------------------------

def _has_bedrock_creds() -> bool:
    if os.environ.get("AWS_BEARER_TOKEN_BEDROCK"):
        return True
    if (os.environ.get("AWS_ACCESS_KEY_ID")
            and os.environ.get("AWS_SECRET_ACCESS_KEY")):
        return True
    return False


try:
    import pytest  # noqa: E402

    @pytest.mark.skipif(
        not _has_bedrock_creds(),
        reason=(
            "Bedrock E2E test requires AWS_BEARER_TOKEN_BEDROCK or "
            "AWS_ACCESS_KEY_ID+AWS_SECRET_ACCESS_KEY in env"
        ),
    )
    def test_bedrock_e2e_live():
        """Live round-trip against real AWS Bedrock — exercises the
        full Phase 1 + 1.5 path through dispatcher + worker."""
        rc = main()
        assert rc == 0, (
            f"Bedrock E2E failed with exit code {rc} — "
            f"see stdout for the failed step"
        )
except ImportError:
    # pytest not available — direct-script mode only.
    pass


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--worker":
        os.environ["RAPTOR_DIR"] = os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__)),
                ),
            ),
        )
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        sys.exit(_worker_entrypoint(sys.argv[2]))
    sys.exit(main())
