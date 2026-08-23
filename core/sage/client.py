"""
Synchronous SAGE client wrapper for RAPTOR.

Thin wrapper around the sage-agent-sdk sync client with:
- Automatic embedding generation (SAGE REST API requires explicit embeddings)
- Sync health check via httpx
- Graceful degradation — all methods return safe defaults on failure

RAPTOR's pipeline is fully synchronous, so this uses sage_sdk.client.SageClient
(sync, httpx.Client-backed) rather than the async variant. Past incarnations
bridged to the async SDK via _run_async() and a per-call event loop; that
caused httpx.AsyncClient loop-affinity failures ("Event loop is closed") on
the second hook call onwards.
"""

import os
import stat
import threading
from pathlib import Path
from typing import Any

from core.logging import get_logger

from .config import SageConfig, ensure_loopback_no_proxy

logger = get_logger()


def harden_identity_key_perms(identity_path=None) -> None:
    """Clamp the SAGE agent identity key to owner-only permissions.

    The SDK persists the Ed25519 seed with a plain ``open(path, "wb")``,
    so the key file inherits the process umask — deployed keys have been
    observed group-readable. Anyone who can read the seed can sign
    requests as this agent. Until the SDK hardens its own write path,
    every RAPTOR call site that loads or auto-provisions the identity
    (this client, libexec/raptor-sage, and the install-time
    register/seed scripts, which additionally clamp the umask to 0o077
    across creation so a fresh key is never umask-wide even briefly)
    calls this immediately after the ``AgentIdentity`` call: chmod the
    key to 0600 (and its directory to 0700), warning when group/other
    bits were set — the same posture ``core/sage/rowmac.py`` applies to
    the row-MAC key.

    ``identity_path=None`` resolves the SDK's own default
    (``$SAGE_IDENTITY_PATH`` or ``~/.sage/agent.key``). Never raises;
    a missing key (SDK not yet provisioned) is a no-op.
    """
    try:
        if identity_path:
            path = Path(identity_path).expanduser()
        else:
            custom = os.environ.get("SAGE_IDENTITY_PATH", "").strip()
            path = (
                Path(custom).expanduser()
                if custom
                else Path.home() / ".sage" / "agent.key"
            )
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            # Symlink or odd object at the key path — never chase it
            # (chmod through a planted symlink is an attacker-directed
            # write). Same refusal posture as rowmac's key reads.
            logger.warning(
                "SAGE identity key %s is not a regular file — "
                "leaving permissions untouched; investigate",
                path,
            )
            return
        if st.st_mode & 0o077:
            logger.warning(
                "SAGE identity key %s had mode %04o (group/other "
                "access) — clamping to 0600",
                path,
                stat.S_IMODE(st.st_mode),
            )
            os.chmod(path, 0o600)
        parent = path.parent
        # Clamp the containing directory too, but never a shared root
        # like $HOME (an operator pointing SAGE_IDENTITY_PATH at
        # ~/mykey.key must not get their home directory chmodded).
        if parent != Path.home():
            pst = os.stat(parent)
            if pst.st_mode & 0o077:
                os.chmod(parent, 0o700)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.debug("could not harden SAGE identity key perms: %s", exc)

_OLLAMA_EMBED_URL = os.getenv(
    "SAGE_OLLAMA_URL", "http://localhost:11435"
)
_OLLAMA_EMBED_TIMEOUT = 60.0

_direct_embed: bool | None = None
_direct_embed_lock = threading.Lock()


def _use_direct_embed() -> bool:
    """True when we should bypass SAGE's /v1/embed and call Ollama directly.

    Activated on CPU-only machines where SAGE's hardcoded 30s Go HTTP
    client timeout is too short for Ollama under contention. On GPU
    the SDK path is fine — embeds are sub-second.
    """
    global _direct_embed
    if _direct_embed is not None:
        return _direct_embed
    with _direct_embed_lock:
        if _direct_embed is not None:
            return _direct_embed
        from .hooks import _ollama_gpu_available
        _direct_embed = not _ollama_gpu_available()
        if _direct_embed:
            logger.debug(
                "CPU-only: embedding via Ollama directly (60s timeout) "
                "instead of SAGE /v1/embed (30s Go-side ceiling)"
            )
    return _direct_embed


def _embed_via_ollama(text: str) -> list[float] | None:
    """Call Ollama's /api/embed directly with a 60s timeout.

    SAGE's /v1/embed is a pure passthrough — no consensus, no
    validation. Calling Ollama directly removes one network hop and
    avoids the 30s hardcoded timeout in SAGE's Go HTTP client.
    """
    model = os.getenv("SAGE_EMBED_MODEL", "snowflake-arctic-embed:m")
    try:
        import httpx

        resp = httpx.post(
            f"{_OLLAMA_EMBED_URL}/api/embed",
            json={"model": model, "input": text},
            timeout=_OLLAMA_EMBED_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("Ollama embed error (status %d): %s", resp.status_code, resp.text[:200])
            return None
        embeddings = resp.json().get("embeddings")
        if embeddings and len(embeddings) > 0:
            return embeddings[0]
        return None
    except Exception as e:
        logger.warning("Ollama direct embed failed: %s", e)
        return None

# Lazy imports — sage_sdk may not be installed
_SyncSageClient = None
_AgentIdentity = None
_MemoryType = None
_SAGE_SDK_AVAILABLE = False


def _ensure_sdk() -> bool | None:
    """Lazily import sage_sdk modules."""
    global _SyncSageClient, _AgentIdentity, _MemoryType, _SAGE_SDK_AVAILABLE
    if _SAGE_SDK_AVAILABLE:
        return True
    try:
        from sage_sdk.client import SageClient as _SdkSageClient
        from sage_sdk.auth import AgentIdentity
        from sage_sdk.models import MemoryType

        _SyncSageClient = _SdkSageClient
        _AgentIdentity = AgentIdentity
        _MemoryType = MemoryType
        _SAGE_SDK_AVAILABLE = True
        return True
    except ImportError:
        logger.debug("sage-agent-sdk not installed — SAGE memory disabled")
        return False


class SageClient:
    """
    Sync SAGE client with lazy initialisation and graceful degradation.

    Usage::

        client = SageClient(SageConfig.from_env())
        if client.is_available():
            results = client.query("crash patterns for heap overflow", "raptor-crashes")
    """

    def __init__(self, config: SageConfig | None = None) -> None:
        ensure_loopback_no_proxy()
        self._config = config or SageConfig.from_env()
        self._client = None
        self._query_cache: dict[tuple[str, str, int, float | None], tuple[tuple[str, float, str], ...]] = {}
        self._register_with_egress_proxy()

    def _register_with_egress_proxy(self) -> None:
        """Register the configured SAGE host with the in-process egress
        proxy's allowlist when LLM egress is active.

        ``core.llm.egress.enable_llm_egress`` (called from
        ``LLMClient.__init__``) brings up the in-process proxy and
        registers LLM provider hostnames on its allowlist. SAGE's
        host is NOT in that allowlist — without this registration the
        SAGE health check + SDK calls go through the same proxy and
        get refused with a 403.

        We only act when:
          * LLM egress is active (the egress module's own
            ``_enabled`` flag is set, NOT a heuristic on
            ``HTTPS_PROXY`` URL pattern — the latter would
            false-positive on an operator running their own local
            proxy on 127.0.0.1); and
          * SAGE's URL is non-loopback (loopback is bypassed via
            ``NO_PROXY``, no registration needed).

        Failure to register is logged at debug level and falls
        through to SAGE's graceful-degradation contract — never
        raises."""
        from urllib.parse import urlparse

        try:
            from core.llm.egress import _enabled as _llm_egress_enabled
        except ImportError:
            # Defensive — egress module always present in tree, but
            # circular-import safety in pathological setups.
            return
        if not _llm_egress_enabled:
            # LLM egress not active for this process — SAGE's httpx
            # calls go direct, no chokepoint to coordinate with.
            return
        try:
            host = urlparse(self._config.url).hostname or ""
        except (TypeError, ValueError):
            return
        if not host or host in ("localhost", "127.0.0.1"):
            return
        try:
            from core.sandbox.proxy import get_proxy
            get_proxy([host])
        except Exception as e:                          # noqa: BLE001
            logger.debug(
                "Could not register SAGE host %r with egress proxy: %s", host, e
            )

    def is_available(self) -> bool:
        """
        Check if SAGE is reachable. Safe to call from module-level /
        DI container setup.
        """
        if not self._config.enabled:
            return False
        if not _ensure_sdk():
            return False
        try:
            import httpx

            resp = httpx.get(
                f"{self._config.url}/health",
                timeout=min(self._config.timeout, 3.0),
            )
            return resp.status_code == 200 and "status" in resp.json()
        except Exception as e:
            logger.debug("SAGE health check failed: %s", e)
            return False

    def _get_client(self):
        """Get or create the underlying sync SDK client."""
        if not self._config.enabled:
            return None
        if not _ensure_sdk():
            return None
        if self._client is None:
            identity_path = self._config.identity_path
            if identity_path and Path(identity_path).exists():
                identity = _AgentIdentity.from_file(identity_path)
                harden_identity_key_perms(identity_path)
            else:
                identity = _AgentIdentity.default()
                # default() may have just auto-provisioned the key with
                # a umask-wide write — clamp it (resolves the SDK's own
                # default path).
                harden_identity_key_perms(None)

            self._client = _SyncSageClient(
                base_url=self._config.url,
                identity=identity,
                timeout=self._config.timeout,
            )
        return self._client

    def embed(self, text: str) -> list[float] | None:
        """Generate an embedding vector for the given text."""
        if not self._config.enabled:
            return None
        if _use_direct_embed():
            return _embed_via_ollama(text)
        client = self._get_client()
        if client is None:
            return None
        try:
            return client.embed(text)
        except Exception as e:
            logger.warning("SAGE embed failed: %s", e)
            return None

    def propose(
        self,
        content: str,
        memory_type: str = "observation",
        domain_tag: str = "general",
        confidence: float = 0.80,
        embedding: list[float] | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """
        Propose a memory to SAGE. Auto-embeds if no embedding is provided.
        Returns True on success.
        """
        client = self._get_client()
        if client is None:
            return False
        try:
            if embedding is None:
                embedding = self.embed(content)

            # Explicit allowlist via dict membership rather than
            # `getattr(_MemoryType, memory_type, default)`. Pre-fix
            # `getattr` accepted *any* attribute on the enum
            # — including dunder methods (`__init__`, `__class__`,
            # `__hash__`) which would either break the propose call
            # downstream with a cryptic type error or silently
            # succeed with the wrong type. A typo (`observatoin`)
            # also fell through to the `observation` default
            # silently, hiding the bug from the operator.
            #
            # Dict-keyed by the canonical lower-case name so a typo
            # surfaces as an explicit "unknown memory_type ..." log
            # and the call falls back deliberately, not by accident.
            #
            # SAGE MemoryType enum = {fact, observation,
            # inference, task} (docs/reference/python-sdk.md). The
            # 6.6.x extras RAPTOR used to reference (hypothesis,
            # evidence, decision, lesson) no longer exist on the
            # enum. We keep accepting those legacy names as inputs
            # and fold them onto the nearest surviving member so any
            # caller still passing them degrades sensibly instead of
            # silently collapsing to "observation":
            #   hypothesis -> inference (a drawn conclusion)
            #   evidence/decision/lesson -> observation (recorded fact
            #     about what happened)
            allowed = {
                "fact": _MemoryType.fact,
                "observation": _MemoryType.observation,
                "inference": _MemoryType.inference,
                "task": _MemoryType.task,
                # Legacy 6.6.x aliases, mapped onto the current enum.
                "hypothesis": _MemoryType.inference,
                "evidence": _MemoryType.observation,
                "decision": _MemoryType.observation,
                "lesson": _MemoryType.observation,
            }
            mt = allowed.get(memory_type)
            if mt is None:
                if memory_type != "observation":
                    logger.warning(
                        "SAGE propose: unknown memory_type=%r, "
                        "falling back to observation", memory_type,
                    )
                mt = _MemoryType.observation
            propose_kwargs: dict[str, Any] = dict(
                content=content,
                memory_type=mt,
                domain_tag=domain_tag,
                confidence=confidence,
                embedding=embedding,
            )
            if tags is not None:
                propose_kwargs["tags"] = tags
            client.propose(**propose_kwargs)
            return True
        except Exception as e:
            logger.warning("SAGE propose failed: %s", e)
            return False

    def query(
        self,
        text: str,
        domain_tag: str = "general",
        top_k: int = 5,
        min_confidence: float | None = None,
    ) -> list[dict[str, Any]]:
        """
        Query SAGE for semantically similar memories.
        Returns a list of dicts with content, confidence, and domain keys.

        Results are LRU-cached (256 entries) keyed on
        (text, domain_tag, top_k, min_confidence) so repeated queries
        for the same identifier skip both embedding and vector search.
        """
        cached = self._query_cached(text, domain_tag, top_k, min_confidence)
        return [dict(zip(("content", "confidence", "domain"), row)) for row in cached]

    def _query_cached(
        self,
        text: str,
        domain_tag: str,
        top_k: int,
        min_confidence: float | None,
    ) -> tuple[tuple[str, float, str], ...]:
        """Per-instance cached query returning tuples (hashable for the cache)."""
        key = (text, domain_tag, top_k, min_confidence)
        cached = self._query_cache.get(key)
        if cached is not None:
            return cached
        client = self._get_client()
        if client is None:
            return ()
        try:
            embedding = self.embed(text)
            if embedding is None:
                return ()
            query_kwargs: dict[str, Any] = dict(
                embedding=embedding,
                domain_tag=domain_tag,
                top_k=top_k,
                status_filter="committed",
            )
            if min_confidence is not None:
                query_kwargs["min_confidence"] = min_confidence
            response = client.query(**query_kwargs)
            result = tuple(
                (r.content, r.confidence_score, r.domain_tag)
                for r in response.results
            )
        except Exception as e:
            logger.warning("SAGE query failed: %s", e)
            return ()
        if len(self._query_cache) >= 256:
            # Evict oldest entry (first inserted) to bound memory.
            try:
                self._query_cache.pop(next(iter(self._query_cache)))
            except StopIteration:
                pass
        self._query_cache[key] = result
        return result

