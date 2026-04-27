"""JSON utilities — one-shot load/save + TTL'd disk cache."""

from .cache import CacheEnvelope, JsonCache, TTL_FOREVER
from .utils import load_json, save_json, load_json_with_comments

__all__ = [
    "CacheEnvelope",
    "JsonCache",
    "TTL_FOREVER",
    "load_json",
    "save_json",
    "load_json_with_comments",
]
