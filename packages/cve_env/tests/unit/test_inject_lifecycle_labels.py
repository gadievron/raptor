"""Phase 43.1.4 (2026-05-16): coverage gap closure for `_inject_lifecycle_labels`.

Per Phase 42.5 coverage report — MED-risk no-test gap on Phase 20A.2's
compose-service label injector at `src/cve_env/tools/docker_compose_up.py:239`.

Function adds `cve-env.owner=cve-env` + `cve-env.cve-id={cve_id}` labels
to a compose service spec (in-place). Used by ``lifecycle.cleanup_containers``
to find + remove this CVE's compose containers post-build.

Tests cover:
- No labels key → dict created with our 2 keys
- Existing dict labels → merged + our 2 keys
- Existing list labels → converted to dict form + our 2 keys (Phase 20A.2 normalization)
- Collision on our keys → ours wins (cleanup-matching reliability)
- Idempotency: 2nd call has no effect (same result)
- List item without `=` → key with empty string value
- cve_id preserved verbatim (CVE-2024-X format)
- Non-string keys/values stringified

Location: src/cve_env/tools/docker_compose_up.py:239-269.
"""

from __future__ import annotations

from cve_env.tools.docker_compose_up import _inject_lifecycle_labels


def test_inject_when_labels_absent() -> None:
    """No existing labels key → dict created with our 2 keys."""
    spec: dict = {"image": "redis:7"}
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0001")
    assert spec["labels"] == {
        "cve-env.owner": "cve-env",
        "cve-env.cve-id": "CVE-2024-0001",
    }


def test_inject_preserves_existing_dict_labels() -> None:
    """Existing dict labels merged; our 2 keys added."""
    spec: dict = {
        "image": "redis:7",
        "labels": {"app": "demo", "tier": "cache"},
    }
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0002")
    assert spec["labels"] == {
        "app": "demo",
        "tier": "cache",
        "cve-env.owner": "cve-env",
        "cve-env.cve-id": "CVE-2024-0002",
    }


def test_inject_converts_list_labels_to_dict() -> None:
    """Existing list labels (key=value form) → normalized to dict."""
    spec: dict = {
        "image": "redis:7",
        "labels": ["app=demo", "tier=cache"],
    }
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0003")
    assert spec["labels"] == {
        "app": "demo",
        "tier": "cache",
        "cve-env.owner": "cve-env",
        "cve-env.cve-id": "CVE-2024-0003",
    }


def test_inject_list_item_without_equals_becomes_empty_value() -> None:
    """List items without `=` separator → key with empty string value
    (matches the else-branch at docker_compose_up.py:265-266)."""
    spec: dict = {
        "image": "redis:7",
        "labels": ["bare_flag", "real=value"],
    }
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0004")
    assert spec["labels"]["bare_flag"] == ""
    assert spec["labels"]["real"] == "value"
    assert spec["labels"]["cve-env.owner"] == "cve-env"


def test_inject_our_keys_win_on_collision() -> None:
    """User supplied `cve-env.owner` is overwritten with our value.
    Docstring: 'collisions on our keys resolve in favor of ours to keep
    cleanup matching reliable.'"""
    spec: dict = {
        "labels": {
            "cve-env.owner": "user-tampered",
            "cve-env.cve-id": "user-tampered-cve",
        },
    }
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0005")
    assert spec["labels"]["cve-env.owner"] == "cve-env"
    assert spec["labels"]["cve-env.cve-id"] == "CVE-2024-0005"


def test_inject_is_idempotent() -> None:
    """Calling twice yields the same result; no duplicated labels.
    Critical for compose-reread / regen scenarios."""
    spec: dict = {"image": "redis:7"}
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0006")
    snapshot = dict(spec["labels"])
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0006")
    assert spec["labels"] == snapshot


def test_inject_non_string_keys_stringified() -> None:
    """If existing labels has non-string keys (unusual but possible via
    YAML number-as-key), they're stringified (line 258 `str(k)`)."""
    spec: dict = {"labels": {1: "value"}}
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0007")
    # The int key 1 becomes string "1"
    assert spec["labels"]["1"] == "value"
    assert spec["labels"]["cve-env.owner"] == "cve-env"


def test_inject_cve_id_preserved_verbatim() -> None:
    """cve_id is opaque — preserved exactly as passed (including any
    legacy format variations)."""
    cve_id = "CVE-2024-12345"
    spec: dict = {}
    _inject_lifecycle_labels(spec, cve_id=cve_id)
    assert spec["labels"]["cve-env.cve-id"] == cve_id


def test_inject_list_label_with_whitespace_stripped() -> None:
    """List item key/value have whitespace stripped (line 264 `.strip()`)."""
    spec: dict = {"labels": ["  spaced.key  =  spaced.value  "]}
    _inject_lifecycle_labels(spec, cve_id="CVE-2024-0008")
    assert spec["labels"]["spaced.key"] == "spaced.value"
