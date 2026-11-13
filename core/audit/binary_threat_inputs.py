"""Currency of rendered threat-model material, never its truth or authority."""
from __future__ import annotations

from hashlib import sha256


def binary_threat_material_digest(material: object) -> str | None:
    """Version the renderer's text or empty/unavailable output distinctly.

    An empty renderer result is not proof that a project has no threat model.
    Existing reader/render limits and attribution rules remain unchanged.
    """
    if material is None:
        return sha256(b"binary-threat-material/v1\0none").hexdigest()
    if not isinstance(material, str):
        return None
    try:
        return sha256(b"binary-threat-material/v1\0text\0" + material.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        return None
