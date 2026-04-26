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

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .config import SageConfig

logger = get_logger()

# Lazy imports — sage_sdk may not be installed
_SyncSageClient = None
_AgentIdentity = None
_MemoryType = None
_SAGE_SDK_AVAILABLE = False


def _ensure_sdk():
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

    def __init__(self, config: Optional[SageConfig] = None):
        self._config = config or SageConfig.from_env()
        self._client = None

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
                timeout=self._config.timeout,
            )
            return resp.status_code == 200 and "status" in resp.json()
        except Exception as e:
            logger.debug(f"SAGE health check failed: {e}")
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
            else:
                identity = _AgentIdentity.default()

            self._client = _SyncSageClient(
                base_url=self._config.url,
                identity=identity,
                timeout=self._config.timeout,
            )
        return self._client

    def embed(self, text: str) -> Optional[List[float]]:
        """Generate an embedding vector for the given text."""
        client = self._get_client()
        if client is None:
            return None
        try:
            return client.embed(text)
        except Exception as e:
            logger.warning(f"SAGE embed failed: {e}")
            return None

    def propose(
        self,
        content: str,
        memory_type: str = "observation",
        domain_tag: str = "general",
        confidence: float = 0.80,
        embedding: Optional[List[float]] = None,
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
                embedding = client.embed(content)

            mt = getattr(_MemoryType, memory_type, _MemoryType.observation)
            client.propose(
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

    def query(
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
            embedding = client.embed(text)
            response = client.query(
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

