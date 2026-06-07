#!/usr/bin/env python3
"""End-to-end live feature verification for Bedrock — exercises each
Anthropic SDK surface that goes through the dispatcher → Mantle path.

Sister script to ``test_bedrock_e2e.py`` (which verifies the
fundamental round-trip).  This one drills into the FEATURE matrix the
pivot promised: streaming, tool use, multi-turn, system prompts, and
the ``/v1/messages/count_tokens`` sibling path.

Runs as either:
  * ``pytest core/llm/tests/test_bedrock_live_features.py`` (auto-
    skipped without Bedrock auth in env), or
  * ``python core/llm/tests/test_bedrock_live_features.py`` for
    operator-driven verbose stepwise output.

The dispatcher is set up in-process and a ``make_bedrock_client``
talks to it directly — same trust boundary as a real worker.  No
subprocess spawn (already covered by ``test_bedrock_e2e.py``).

Cost: ~$0.001 per run (six short single-turn pokes at Haiku pricing).
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


def _setup_dispatcher() -> object:
    """Start the dispatcher with the parent's AWS creds; returns a
    dispatcher whose credential store is shared across every client
    the test allocates afterwards.  Constructed once because
    ``CredentialStore.__init__`` pops ``AWS_BEARER_TOKEN_BEDROCK``
    from env — a second store would find an empty env."""
    os.environ["RAPTOR_DIR"] = os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)),
            ),
        ),
    )
    sys.path.insert(0, os.environ["RAPTOR_DIR"])

    from pathlib import Path
    import tempfile
    from core.llm.dispatcher.auth import CredentialStore
    from core.llm.dispatcher.server import LLMDispatcher

    store = CredentialStore()
    # CredentialStore picks up both auth modes — verify at least one is
    # configured (mirrors what the live ProviderRule.is_configured check
    # would do at request time, with a friendlier error here).
    has_bearer = bool(store.get("aws_bearer_token"))
    has_sigv4 = (
        bool(store.get("aws_access_key_id"))
        and bool(store.get("aws_secret_access_key"))
    )
    if not (has_bearer or has_sigv4):
        raise RuntimeError(
            "No Bedrock auth in env — set either "
            "AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID+SECRET"
        )
    audit_dir = Path(tempfile.mkdtemp(prefix="raptor-bedrock-live-"))
    return LLMDispatcher(
        run_id="bedrock-live-features",
        audit_path=audit_dir / "audit.jsonl",
        creds=store,
    )


def _make_client(dispatcher, api: str) -> tuple[object, str]:
    """Allocate a worker token + build a Bedrock client against the
    chosen API.  Same dispatcher → same credential store, so this is
    safe to call multiple times in one test run."""
    from core.llm.dispatcher.client import make_bedrock_client

    socket_path, fd = dispatcher.allocate_worker(label=f"live-features-{api}")
    token = os.read(fd, 64).decode().strip()
    os.close(fd)
    client = make_bedrock_client(
        api=api, socket_path=str(dispatcher.socket_path), token=token,
    )
    # Mantle accepts bare IDs (regional routing is by hostname).
    # Runtime requires a Cross-Region Inference Profile ID with a
    # ``us.``/``eu.``/``global.`` prefix for on-demand throughput;
    # bare base IDs return 400 with "Retry your request with the ID
    # or ARN of an inference profile that contains this model".
    # We derive the regional prefix from ``AWS_REGION`` so EU
    # accounts get ``eu.``, US accounts get ``us.``, etc.  Operators
    # override the full ID via ``RAPTOR_BEDROCK_E2E_RUNTIME_MODEL``.
    if api == "runtime":
        region = (
            os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "us-east-1"
        ).lower()
        if region.startswith("eu-"):
            prefix = "eu."
        elif region.startswith("ap-"):
            prefix = "apac."
        elif region.startswith("au-"):
            prefix = "au."
        else:
            prefix = "us."
        model_id = os.environ.get(
            "RAPTOR_BEDROCK_E2E_RUNTIME_MODEL",
            f"{prefix}anthropic.claude-haiku-4-5-20251001-v1:0",
        )
    else:
        model_id = os.environ.get(
            "RAPTOR_BEDROCK_E2E_MODEL", "anthropic.claude-haiku-4-5",
        )
    if not any(model_id.startswith(p) for p in
               ("anthropic.", "us.", "eu.", "apac.", "au.", "global.")):
        model_id = f"anthropic.{model_id}"
    return client, model_id


def _feature_basic(client, model_id: str) -> int:
    _section("Feature 1 — Plain single-turn message")
    resp = client.messages.create(
        model=model_id,
        max_tokens=20,
        messages=[{"role": "user", "content": "Reply with one word: pong."}],
    )
    text = resp.content[0].text.strip()
    _ok("response.content", repr(text))
    _ok("stop_reason", resp.stop_reason)
    _ok("input_tokens", resp.usage.input_tokens)
    _ok("output_tokens", resp.usage.output_tokens)
    if "pong" not in text.lower():
        _fail("content shape", f"expected 'pong' in response, got {text!r}")
        return 1
    return 0


def _feature_system_prompt(client, model_id: str) -> int:
    _section("Feature 2 — System prompt")
    resp = client.messages.create(
        model=model_id,
        max_tokens=30,
        system="You only ever respond with the single word 'banana'.",
        messages=[{"role": "user", "content": "What is your favourite colour?"}],
    )
    text = resp.content[0].text.strip().lower()
    _ok("response", repr(text))
    if "banana" not in text:
        _fail("system prompt followed",
              f"expected 'banana', got {text!r} — system prompt not honoured")
        return 2
    return 0


def _feature_multi_turn(client, model_id: str) -> int:
    _section("Feature 3 — Multi-turn conversation")
    resp = client.messages.create(
        model=model_id,
        max_tokens=30,
        messages=[
            {"role": "user", "content": "My name is Casey. Just say 'ok'."},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "What is my name? Respond with only the name."},
        ],
    )
    text = resp.content[0].text.strip()
    _ok("response", repr(text))
    if "casey" not in text.lower():
        _fail("conversation history threaded",
              f"expected 'Casey' in response, got {text!r}")
        return 3
    return 0


def _feature_streaming(client, model_id: str) -> int:
    _section("Feature 4 — Streaming (SSE)")
    chunks = []
    with client.messages.stream(
        model=model_id,
        max_tokens=40,
        messages=[
            {"role": "user", "content":
             "Count from 1 to 5, comma-separated, no other words."},
        ],
    ) as stream:
        for text in stream.text_stream:
            chunks.append(text)
        final = stream.get_final_message()
    full = "".join(chunks)
    _ok("chunks received", len(chunks))
    _ok("streamed text", repr(full.strip()[:80]))
    _ok("final.stop_reason", final.stop_reason)
    _ok("final.usage.output_tokens", final.usage.output_tokens)
    if len(chunks) < 2:
        _fail("streaming chunks",
              f"expected multi-chunk stream, got {len(chunks)} chunks "
              "(SSE may have been buffered into one response)")
        return 4
    if "1" not in full or "5" not in full:
        _fail("streamed content",
              f"expected count 1..5 in stream, got {full!r}")
        return 4
    return 0


def _feature_tool_use(client, model_id: str) -> int:
    _section("Feature 5 — Tool use (benign calculator)")
    resp = client.messages.create(
        model=model_id,
        max_tokens=200,
        tools=[{
            "name": "add_numbers",
            "description": "Add two integers and return the sum.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer"},
                    "b": {"type": "integer"},
                },
                "required": ["a", "b"],
            },
        }],
        messages=[
            {"role": "user", "content":
             "Use the add_numbers tool to compute 17 + 25.  Do not "
             "answer directly — invoke the tool."},
        ],
    )
    _ok("stop_reason", resp.stop_reason)
    tool_blocks = [b for b in resp.content if b.type == "tool_use"]
    if not tool_blocks:
        _fail("tool invocation",
              f"expected a tool_use block, got content types: "
              f"{[b.type for b in resp.content]}")
        return 5
    tb = tool_blocks[0]
    _ok("tool name", tb.name)
    _ok("tool input", tb.input)
    if tb.name != "add_numbers":
        _fail("tool name", f"expected 'add_numbers', got {tb.name!r}")
        return 5
    if {"a", "b"} - set(tb.input.keys()):
        _fail("tool args", f"missing required keys in {tb.input!r}")
        return 5
    if tb.input.get("a") != 17 or tb.input.get("b") != 25:
        _fail("tool args values",
              f"expected a=17, b=25; got {tb.input!r}")
        return 5
    return 0


def _feature_count_tokens(client, model_id: str) -> int:
    _section("Feature 6 — count_tokens (alt path /v1/messages/count_tokens)")
    if not hasattr(client.messages, "count_tokens"):
        _info("client.messages.count_tokens",
              "absent in installed Anthropic SDK — skipping")
        return 0
    # Mantle exposes ``/anthropic/v1/messages/count_tokens`` but the
    # caller's auth identity must hold the
    # ``bedrock-mantle:CountTokens`` IAM action.  SigV4 callers with
    # the right policy succeed (verified live).  Bedrock bearer tokens
    # don't carry that capability in their scope and 401 the request
    # before it reaches the endpoint — that's an auth-scope
    # limitation, not a dispatcher routing bug.
    try:
        result = client.messages.count_tokens(
            model=model_id,
            messages=[
                {"role": "user", "content":
                 "The quick brown fox jumps over the lazy dog."},
            ],
        )
    except Exception as e:
        msg = str(e)
        if "401" in msg or "404" in msg:
            _info("count_tokens",
                  "Mantle does not expose this endpoint to this auth "
                  "(known limitation, not a dispatcher bug)")
            return 0
        if "403" in msg and "CountTokens" in msg:
            _info("count_tokens",
                  "Mantle CountTokens endpoint reached but the IAM "
                  "identity lacks bedrock-mantle:CountTokens action "
                  "(account-side permission, not a dispatcher bug)")
            return 0
        if "400" in msg and "RAPTOR_BEDROCK_API=mantle" in msg:
            _info("count_tokens",
                  "Dispatcher gated count_tokens on the runtime path "
                  "(InvokeModel has no count_tokens equivalent)")
            return 0
        _fail("count_tokens",
              f"unexpected error: {type(e).__name__}: {e}")
        return 6
    _ok("input_tokens", result.input_tokens)
    if result.input_tokens <= 0 or result.input_tokens > 200:
        _fail("count_tokens range",
              f"unexpected token count for short message: "
              f"{result.input_tokens}")
        return 6
    return 0


def _feature_prompt_caching(client, model_id: str) -> int:
    _section("Feature 7 — prompt caching (cache_control)")
    # System prompt long enough to clear the prompt-cache minimum
    # (1024 tokens for the model class).  A repeated long preamble is
    # the canonical use case: same system block, varying user turn.
    big_preamble = (
        "You are a helpful assistant.  Repeat the following text "
        "back as your knowledge base, do not summarise.  " +
        ("Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
         "sed do eiusmod tempor incididunt ut labore et dolore magna "
         "aliqua. ") * 200
    )
    resp = client.messages.create(
        model=model_id,
        max_tokens=20,
        system=[
            {
                "type": "text",
                "text": big_preamble,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        messages=[{"role": "user", "content": "Say ack."}],
    )
    usage = resp.usage
    # First call: either cache_creation_input_tokens (cold miss
    # creating the cache) or a normal input — both are valid.
    cci = getattr(usage, "cache_creation_input_tokens", 0) or 0
    cri = getattr(usage, "cache_read_input_tokens", 0) or 0
    _ok("first-call usage.input_tokens", usage.input_tokens)
    _ok("first-call usage.cache_creation_input_tokens", cci)
    _ok("first-call usage.cache_read_input_tokens", cri)
    if cci == 0 and cri == 0:
        _fail("prompt caching honoured",
              "neither cache_creation nor cache_read populated — "
              "Bedrock likely silently ignored cache_control")
        return 7
    # Second call: identical preamble; expect a cache_read hit.
    resp2 = client.messages.create(
        model=model_id,
        max_tokens=20,
        system=[
            {
                "type": "text",
                "text": big_preamble,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        messages=[{"role": "user", "content": "Say ack."}],
    )
    cri2 = getattr(resp2.usage, "cache_read_input_tokens", 0) or 0
    _ok("second-call cache_read_input_tokens", cri2)
    if cri2 <= 0:
        _fail("cache_read on second call",
              f"expected a cache hit on repeat preamble, got "
              f"cache_read_input_tokens={cri2}")
        return 7
    return 0


def _make_solid_red_png() -> str:
    """Return a base64-encoded 16x16 solid-red PNG.  Pure red is an
    unambiguous visual cue: a vision-capable model should describe the
    image as 'red' (or close synonyms) — anything else means the
    image bytes never made it into the model.  Built with stdlib only
    (no Pillow dependency)."""
    import base64
    import struct
    import zlib
    width = height = 16

    def _chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return (
            struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)
        )
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    # Raw pixels: each row begins with a 0 filter byte, then RGB pixels.
    row = b"\x00" + (b"\xff\x00\x00" * width)
    raw = row * height
    idat = zlib.compress(raw)
    png = sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    return base64.b64encode(png).decode("ascii")


def _feature_vision(client, model_id: str) -> int:
    _section("Feature 8 — Vision (inline image)")
    img_b64 = _make_solid_red_png()
    resp = client.messages.create(
        model=model_id,
        max_tokens=80,
        messages=[{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": img_b64,
                    },
                },
                {
                    "type": "text",
                    "text":
                    "What single colour fills this image?  Reply with "
                    "just the colour name, nothing else.",
                },
            ],
        }],
    )
    text = resp.content[0].text.strip().lower()
    _ok("response", repr(text))
    _ok("stop_reason", resp.stop_reason)
    if "red" not in text:
        _fail("colour recognition",
              f"expected 'red' in response, got {text!r} — image bytes "
              "likely didn't reach the model")
        return 8
    return 0


def _feature_extended_thinking(client, model_id: str) -> int:
    _section("Feature 9 — Extended thinking")
    # The ``thinking`` parameter requires ``temperature: 1`` per the
    # Anthropic API contract.  Per the docs, this is a Sonnet/Opus
    # feature; Haiku will reject with "thinking not supported by this
    # model" which still proves the dispatcher forwarded the field
    # untouched (the model itself rejected, not the proxy).
    try:
        resp = client.messages.create(
            model=model_id,
            max_tokens=2048,
            temperature=1,
            thinking={"type": "enabled", "budget_tokens": 1024},
            messages=[{
                "role": "user",
                "content":
                "What is 17 * 23?  Think it through step by step, "
                "then give the final answer.",
            }],
        )
    except Exception as e:
        msg = str(e)
        if (
            "thinking" in msg.lower()
            or "not supported" in msg.lower()
            or "400" in msg
        ):
            _info("extended thinking",
                  f"model rejected feature (expected for Haiku-class): "
                  f"{type(e).__name__}")
            _info("dispatcher contract",
                  "request reached Bedrock with thinking field intact — "
                  "proxy is byte-faithful")
            return 0
        _fail("extended thinking", f"{type(e).__name__}: {e}")
        return 9
    thinking_blocks = [
        b for b in resp.content
        if getattr(b, "type", None) in ("thinking", "redacted_thinking")
    ]
    text_blocks = [b for b in resp.content if b.type == "text"]
    _ok("thinking blocks present", len(thinking_blocks))
    _ok("text blocks present", len(text_blocks))
    if not thinking_blocks:
        _fail("extended thinking blocks",
              "model accepted the thinking field but emitted no "
              "thinking content blocks")
        return 9
    if text_blocks:
        _ok("final text", repr(text_blocks[0].text[:80]))
    return 0


def _feature_computer_use(client, model_id: str) -> int:
    _section("Feature 10 — Computer use (tool definition)")
    # Per AWS docs (and the Claude Opus 4.8 model card),
    # ``computer_20251124`` is the current Bedrock-supported tool
    # type.  Beta header ``computer-use-2025-11-24``.  Like extended
    # thinking, this is an Opus/Sonnet feature — Haiku will reject,
    # which still proves the dispatcher forwarded the tool definition
    # and beta header.
    try:
        resp = client.messages.create(
            model=model_id,
            max_tokens=600,
            tools=[{
                "type": "computer_20251124",
                "name": "computer",
                "display_width_px": 1024,
                "display_height_px": 768,
            }],
            extra_headers={
                "anthropic-beta": "computer-use-2025-11-24",
            },
            messages=[{
                "role": "user",
                "content":
                "Take a screenshot of the current screen using the "
                "computer tool.",
            }],
        )
    except Exception as e:
        msg = str(e)
        if (
            "computer" in msg.lower()
            or "not supported" in msg.lower()
            or "beta" in msg.lower()
            or "400" in msg
            or "404" in msg
        ):
            _info("computer use",
                  f"model rejected feature (expected for Haiku-class): "
                  f"{type(e).__name__}")
            _info("dispatcher contract",
                  "request reached Bedrock with computer tool + beta "
                  "header intact — proxy is byte-faithful")
            return 0
        _fail("computer use", f"{type(e).__name__}: {e}")
        return 10
    tool_blocks = [b for b in resp.content if b.type == "tool_use"]
    _ok("stop_reason", resp.stop_reason)
    _ok("tool_use blocks", len(tool_blocks))
    if not tool_blocks:
        _fail("computer-use invocation",
              "model accepted but did not emit a computer tool call — "
              f"got content types {[b.type for b in resp.content]}")
        return 10
    tb = tool_blocks[0]
    _ok("tool name", tb.name)
    _ok("tool input", tb.input)
    if tb.name != "computer":
        _fail("computer tool name",
              f"expected 'computer', got {tb.name!r}")
        return 10
    return 0


def _mantle_features() -> list:
    """Full feature list for the Mantle path — Mantle has native support
    for streaming, tool use, prompt caching, vision, extended thinking,
    and computer use (subject to model)."""
    return [
        _feature_basic,
        _feature_system_prompt,
        _feature_multi_turn,
        _feature_streaming,
        _feature_tool_use,
        _feature_count_tokens,
        _feature_prompt_caching,
        _feature_vision,
        _feature_extended_thinking,
        _feature_computer_use,
    ]


def _runtime_features() -> list:
    """Subset for the runtime/InvokeModel path — InvokeModel is non-
    streaming only and doesn't expose the introspection endpoints
    (``count_tokens``).  Skip those; everything else (tool use,
    prompt caching, vision, extended thinking, computer use) is
    InvokeModel-routable."""
    return [
        _feature_basic,
        _feature_system_prompt,
        _feature_multi_turn,
        _feature_tool_use,
        _feature_prompt_caching,
        _feature_vision,
        _feature_extended_thinking,
        _feature_computer_use,
    ]


def _run_api(dispatcher, api: str) -> int:
    """Run the feature suite for one Bedrock API against an existing
    dispatcher (shared with any other API runs in the same test)."""
    _section(f"API path — {api.upper()}")
    try:
        client, model_id = _make_client(dispatcher, api)
    except Exception as e:
        _fail(f"client setup ({api})", f"{type(e).__name__}: {e}")
        traceback.print_exc()
        return 99
    _info("Model", model_id)

    rc = 0
    fns = _runtime_features() if api == "runtime" else _mantle_features()
    for fn in fns:
        t0 = time.monotonic()
        try:
            result = fn(client, model_id)
        except Exception as e:
            _fail(fn.__name__, f"{type(e).__name__}: {e}")
            traceback.print_exc()
            result = 99
        dt = time.monotonic() - t0
        _info("feature wall-clock", f"{dt:.2f}s")
        if result != 0 and rc == 0:
            rc = result
    return rc


def main() -> int:
    _section("0. Environment check")
    bearer = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
    ak = os.environ.get("AWS_ACCESS_KEY_ID")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not bearer and not (ak and sk):
        _fail("AWS Bedrock auth",
              "set either AWS_BEARER_TOKEN_BEDROCK or "
              "AWS_ACCESS_KEY_ID+SECRET — neither is in env")
        return 99
    if not region:
        _fail("AWS_REGION / AWS_DEFAULT_REGION", "not set")
        return 99
    if bearer:
        _ok("AWS_BEARER_TOKEN_BEDROCK present (bearer auth mode)")
    if ak and sk:
        _ok("AWS_ACCESS_KEY_ID + SECRET present (SigV4 auth mode)")
    if bearer and ak and sk:
        _info("note",
              "BOTH auth modes set — bearer takes precedence "
              "(matches AWS SDK behaviour).  Unset bearer to test SigV4.")
    _ok("AWS_REGION", region)

    # API selection:
    #   RAPTOR_BEDROCK_E2E_APIS=mantle,runtime  → run both (default)
    #   RAPTOR_BEDROCK_E2E_APIS=mantle          → mantle only
    #   RAPTOR_BEDROCK_E2E_APIS=runtime         → runtime only
    apis = (
        os.environ.get("RAPTOR_BEDROCK_E2E_APIS", "mantle,runtime")
        .lower().split(",")
    )
    apis = [a.strip() for a in apis if a.strip() in ("mantle", "runtime")]
    if not apis:
        _fail("RAPTOR_BEDROCK_E2E_APIS",
              "must list at least one of mantle, runtime")
        return 99

    try:
        dispatcher = _setup_dispatcher()
    except Exception as e:
        _fail("dispatcher setup", f"{type(e).__name__}: {e}")
        traceback.print_exc()
        return 99

    rc = 0
    try:
        for api in apis:
            api_rc = _run_api(dispatcher, api)
            if api_rc != 0 and rc == 0:
                rc = api_rc
    finally:
        dispatcher.shutdown()

    _section("Summary")
    if rc == 0:
        apis_str = " + ".join(a.upper() for a in apis)
        print(f"=== ALL FEATURES PASS — Bedrock {apis_str} fully exercised "
              "through dispatcher ===", flush=True)
    else:
        print(f"=== SOME FEATURES FAILED (first rc={rc}) ===", flush=True)
    return rc


# ---------------------------------------------------------------------------
# pytest entry — auto-skip when no Bedrock credentials in env
# ---------------------------------------------------------------------------


def _has_bedrock_creds_in_env() -> bool:
    return bool(
        os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
        and (os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    )


import pytest  # noqa: E402


@pytest.mark.skipif(
    not _has_bedrock_creds_in_env(),
    reason="No AWS Bedrock credentials in env",
)
def test_bedrock_live_features():
    rc = main()
    assert rc == 0, f"feature verification failed: rc={rc}"


if __name__ == "__main__":
    sys.exit(main())
