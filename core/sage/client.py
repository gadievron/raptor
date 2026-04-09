"""
Async SAGE client wrapper for RAPTOR.

Provides a thin wrapper around the sage-agent-sdk with:
- Lazy client creation to avoid event-loop lifetime issues
- Automatic embedding generation (SAGE REST API requires explicit embeddings)
- Sync health check via httpx (no asyncio.run pollution)
- Graceful degradation — all methods return safe defaults on failure
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .config import SageConfig

logger = get_logger()

# Lazy imports — sage_sdk may not be installed
_AsyncSageClient = None
_AgentIdentity = None
_MemoryType = None
_SAGE_SDK_AVAILABLE = False


def _ensure_sdk():
    """Lazily import sage_sdk modules."""
    global _AsyncSageClient, _AgentIdentity, _MemoryType, _SAGE_SDK_AVAILABLE
    if _SAGE_SDK_AVAILABLE:
        return True
    try:
        from sage_sdk.async_client import AsyncSageClient
        from sage_sdk.auth import AgentIdentity
        from sage_sdk.models import MemoryType

        _AsyncSageClient = AsyncSageClient
        _AgentIdentity = AgentIdentity
        _MemoryType = MemoryType
        _SAGE_SDK_AVAILABLE = True
        return True
    except ImportError:
        logger.debug("sage-agent-sdk not installed — SAGE memory disabled")
        return False


class SageClient:
    """
    Async SAGE client with lazy initialisation and graceful degradation.

    Usage::

        client = SageClient(SageConfig.from_env())
        if client.is_available():
            results = await client.query("crash patterns for heap overflow", "raptor-crashes")
    """

    def __init__(self, config: Optional[SageConfig] = None):
        self._config = config or SageConfig.from_env()
        self._client = None  # Created lazily per event-loop

    # ------------------------------------------------------------------
    # Sync health check (safe to call from DI / startup)
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check if SAGE is reachable (sync, no event-loop required).

        Uses httpx.get so it's safe to call from module-level or
        DI container setup without polluting the event loop.
        """
        if not self._config.enabled:
            return False
        if not _ensure_sdk():
            return False
        try:
            import httpx

            resp = httpx.get(
                f"{self._config.url}/health",
                timeout=self._config.timeout,
            )
            return resp.status_code == 200 and "status" in resp.json()
        except Exception as e:
            logger.debug(f"SAGE health check failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Lazy async client
    # ------------------------------------------------------------------

    def _get_client(self):
        """Get or create an AsyncSageClient bound to the current event loop."""
        if not self._config.enabled:
            return None
        if not _ensure_sdk():
            return None
        if self._client is None:
            identity_path = self._config.identity_path
            if identity_path and Path(identity_path).exists():
                identity = _AgentIdentity.from_file(identity_path)
            else:
                identity = _AgentIdentity.default()

            self._client = _AsyncSageClient(
                base_url=self._config.url,
                identity=identity,
                timeout=self._config.timeout,
            )
        return self._client

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    async def embed(self, text: str) -> Optional[List[float]]:
        """Generate an embedding vector for the given text."""
        client = self._get_client()
        if client is None:
            return None
        try:
            return await client.embed(text)
        except Exception as e:
            logger.warning(f"SAGE embed failed: {e}")
            return None

    async def propose(
        self,
        content: str,
        memory_type: str = "observation",
        domain_tag: str = "general",
        confidence: float = 0.80,
        embedding: Optional[List[float]] = None,
    ) -> bool:
        """
        Propose a memory to SAGE.

        If no embedding is provided, one is generated automatically.
        Returns True on success, False on failure.
        """
        client = self._get_client()
        if client is None:
            return False
        try:
            if embedding is None:
                embedding = await client.embed(content)

            mt = getattr(_MemoryType, memory_type, _MemoryType.observation)
            await client.propose(
                content=content,
                memory_type=mt,
                domain_tag=domain_tag,
                confidence=confidence,
                embedding=embedding,
            )
            return True
        except Exception as e:
            logger.warning(f"SAGE propose failed: {e}")
            return False

    async def query(
        self,
        text: str,
        domain_tag: str = "general",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Query SAGE for semantically similar memories.

        Returns a list of dicts with content, confidence, and domain keys.
        """
        client = self._get_client()
        if client is None:
            return []
        try:
            embedding = await client.embed(text)
            response = await client.query(
                embedding=embedding,
                domain_tag=domain_tag,
                top_k=top_k,
            )
            return [
                {
                    "content": r.content,
                    "confidence": r.confidence_score,
                    "domain": r.domain_tag,
                }
                for r in response.results
            ]
        except Exception as e:
            logger.warning(f"SAGE query failed: {e}")
            return []

    async def register(self, name: str) -> bool:
        """
        Register this agent identity on the SAGE network.

        Note: The sage_sdk AsyncSageClient uses register_agent() or
        the registration happens implicitly on first propose(). This
        method stores a registration memory as a fallback.
        """
        client = self._get_client()
        if client is None:
            return False
        try:
            # Try the SDK method if available
            if hasattr(client, "register"):
                await client.register(name)
            elif hasattr(client, "register_agent"):
                await client.register_agent(name)
            else:
                # Fallback: store agent registration as a memory
                content = f"Agent {name} registered on SAGE network."
                embedding = await client.embed(content)
                await client.propose(
                    content=content,
                    memory_type=_MemoryType.fact,
                    domain_tag="raptor-agents",
                    confidence=0.95,
                    embedding=embedding,
                )
            return True
        except Exception as e:
            logger.warning(f"SAGE register failed: {e}")
            return False
