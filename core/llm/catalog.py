"""Explicit public projection of trusted, already-resolved model configs.

This API does not load config, discover credentials, select a transport or
authorise requests. Only PublicCatalog crosses a worker boundary. The caller
retains PreparedCatalog in trusted state. Calling prepare_catalog is opt-in;
existing configuration and provider construction are unchanged.
"""

from __future__ import annotations

import json
import math
import re
import secrets
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

from core.json import dumps_canonical

if TYPE_CHECKING:
    from core.llm.config import ModelConfig

MAX_CATALOG_BYTES = 1024 * 1024
MAX_CATALOG_ROUTES = 1024
_OPAQUE_ID = re.compile(r"[0-9a-f]{32}")


class CatalogError(ValueError):
    """Invalid public configuration; messages never include input values."""


def _validate_text(value: object, field: str, maximum: int = 256) -> None:
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127
                   or 0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise CatalogError(f"Invalid catalog field: {field}")


def _identifier(value: object) -> None:
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise CatalogError("Invalid catalog identifier")


@dataclass(frozen=True, slots=True)
class PublicRoute:
    route_id: str
    provider: str
    model_name: str
    max_tokens: int
    max_context: int
    temperature: float
    timeout: float
    cost_per_1k_tokens: float
    enabled: bool
    role: str | None

    def __post_init__(self) -> None:
        _identifier(self.route_id)
        _validate_text(self.provider, "provider")
        _validate_text(self.model_name, "model_name", 1024)
        if self.role is not None:
            _validate_text(self.role, "role")
        for field in ("max_tokens", "max_context"):
            value = getattr(self, field)
            if type(value) is not int or not 0 < value <= 2**53 - 1:
                raise CatalogError(f"Invalid catalog field: {field}")
        for field in ("temperature", "timeout", "cost_per_1k_tokens"):
            value = getattr(self, field)
            if (type(value) not in (int, float)
                    or value < 0 or value > 2**53 - 1 or not math.isfinite(value)):
                raise CatalogError(f"Invalid catalog field: {field}")
        if self.timeout == 0 or type(self.enabled) is not bool:
            raise CatalogError("Invalid catalog timeout or enabled field")

    def _payload(self) -> dict:
        # Explicit projection: a future private config field cannot leak by
        # being added to a dataclass or dict and automatically serialised.
        return {
            "route_id": self.route_id, "provider": self.provider,
            "model_name": self.model_name, "max_tokens": self.max_tokens,
            "max_context": self.max_context, "temperature": self.temperature,
            "timeout": self.timeout, "cost_per_1k_tokens": self.cost_per_1k_tokens,
            "enabled": self.enabled, "role": self.role,
        }


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("Duplicate catalog field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class PublicCatalog:
    generation: str
    routes: tuple[PublicRoute, ...]

    def __post_init__(self) -> None:
        _identifier(self.generation)
        if type(self.routes) is not tuple or len(self.routes) > MAX_CATALOG_ROUTES:
            raise CatalogError("Invalid catalog routes")
        if any(type(route) is not PublicRoute for route in self.routes):
            raise CatalogError("Invalid catalog route")
        if len({route.route_id for route in self.routes}) != len(self.routes):
            raise CatalogError("Duplicate catalog route identifier")

    def to_bytes(self) -> bytes:
        payload = {
            "schema_version": 1, "generation": self.generation,
            "routes": [route._payload() for route in self.routes],
        }
        raw = dumps_canonical(payload).encode("utf-8")
        if len(raw) > MAX_CATALOG_BYTES:
            raise CatalogError("Catalog exceeds size limit")
        return raw

    @classmethod
    def from_bytes(cls, raw: bytes) -> PublicCatalog:
        if type(raw) is not bytes or len(raw) > MAX_CATALOG_BYTES:
            raise CatalogError("Invalid catalog bytes or size")
        try:
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            if type(payload) is not dict or set(payload) != {"schema_version", "generation", "routes"}:
                raise CatalogError("Invalid catalog envelope")
            if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
                raise CatalogError("Unsupported catalog schema")
            routes = payload["routes"]
            if type(routes) is not list or len(routes) > MAX_CATALOG_ROUTES:
                raise CatalogError("Invalid catalog routes")
            return cls(payload["generation"], tuple(PublicRoute(**route) for route in routes))
        except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
            # JSON/constructor exceptions may echo complete input. Keep them
            # off the diagnostic chain, including unexpected fields/versions.
            raise CatalogError("Invalid public model catalog") from None


class PreparedCatalog:
    """Trusted private routes and their public projection; never send this object.

    A route ID is an identity, not an authorisation token. Access checks remain
    the dispatcher's responsibility. No route is declared proxy-capable here.
    """

    __slots__ = ("__public", "__configs")

    def __init__(self, public: PublicCatalog, configs: dict[str, ModelConfig]):
        if type(public) is not PublicCatalog or set(configs) != {r.route_id for r in public.routes}:
            raise CatalogError("Private routes do not match catalog")
        self.__public = public
        self.__configs = deepcopy(configs)

    @property
    def public(self) -> PublicCatalog:
        return self.__public

    def private_config(self, generation: str, route_id: str) -> ModelConfig:
        _identifier(generation)
        _identifier(route_id)
        if generation != self.public.generation or route_id not in self.__configs:
            raise CatalogError("Unknown catalog route or generation")
        return deepcopy(self.__configs[route_id])


def prepare_catalog(configs: Iterable[ModelConfig]) -> PreparedCatalog:
    """Project resolved configs without changing credential precedence or routes.

    Validation failure is an opt-in preparation error, not permission to weaken
    policy or reload credentials in a worker. This does not probe provider SDKs.
    """
    from core.llm.config import ModelConfig

    routes: list[PublicRoute] = []
    private = {}
    for config in configs:
        if len(routes) >= MAX_CATALOG_ROUTES:
            raise CatalogError("Too many catalog routes")
        if type(config) is not ModelConfig:
            raise CatalogError("Expected resolved ModelConfig")
        route_id = secrets.token_hex(16)
        if route_id in private:
            raise CatalogError("Duplicate generated route identifier")
        copy = deepcopy(config)
        route = PublicRoute(
            route_id=route_id, provider=copy.provider, model_name=copy.model_name,
            max_tokens=copy.max_tokens, max_context=copy.max_context,
            temperature=copy.temperature, timeout=copy.timeout,
            cost_per_1k_tokens=copy.cost_per_1k_tokens,
            enabled=copy.enabled, role=copy.role,
        )
        private[route_id] = copy
        routes.append(route)
    public = PublicCatalog(secrets.token_hex(16), tuple(routes))
    public.to_bytes()  # Enforce the byte bound before publication as well as receipt.
    return PreparedCatalog(public, private)


def model_config_from_catalog(catalog: PublicCatalog, route_id: str) -> ModelConfig:
    """Build a keyless model from advertised metadata, without discovery."""
    from core.llm.config import ModelConfig

    for route in catalog.routes:
        if route.route_id == route_id:
            return ModelConfig(
                provider=route.provider, model_name=route.model_name,
                max_tokens=route.max_tokens, max_context=route.max_context,
                temperature=route.temperature, timeout=route.timeout,
                cost_per_1k_tokens=route.cost_per_1k_tokens,
                enabled=route.enabled, role=route.role,
            )
    raise CatalogError("Unknown public catalog route")


def llm_config_from_catalog(catalog: PublicCatalog, route_id: str):
    """Explicit single-route configuration; no auto-discovered fallback models."""
    from core.llm.config import LLMConfig

    model = model_config_from_catalog(catalog, route_id)
    config = LLMConfig(
        primary_model=model, fallback_models=[], enable_fallback=False,
        enable_caching=False, scorecard_enabled=False, max_retries=1,
    )
    # Legacy configuration seeds pure fast-tier metadata. Those models are not
    # advertised by this catalogue, so remove them before publishing the config.
    config.specialized_models.clear()
    return config
