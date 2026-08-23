"""Tests for ``core.oci.image_ref``.

The reference grammar has many shapes operators write naturally;
each test pins one shape to its canonical form so future grammar
tweaks don't silently change behaviour.
"""

from __future__ import annotations

import pytest

from core.oci.image_ref import ImageRef, parse_image_ref, split_image_ref


# ---------------------------------------------------------------------------
# Short-form shortcuts (Docker Hub conventions)
# ---------------------------------------------------------------------------


def test_bare_name_defaults_to_dockerhub_library_latest():
    """``python`` → ``docker.io/library/python:latest``. The two
    Docker Hub conventions (``library/`` namespace + ``:latest``
    default) apply."""
    ref = parse_image_ref("python")
    assert ref == ImageRef(
        registry="docker.io",
        repository="library/python",
        tag="latest",
        digest=None,
    )


def test_name_with_tag_defaults_dockerhub_library():
    ref = parse_image_ref("python:3.11")
    assert ref == ImageRef("docker.io", "library/python", "3.11", None)


def test_user_namespaced_skips_library_prefix():
    """``alice/myapp:1.2.3`` is a user-namespaced Docker Hub image
    — does NOT get prefixed with ``library/``."""
    ref = parse_image_ref("alice/myapp:1.2.3")
    assert ref.registry == "docker.io"
    assert ref.repository == "alice/myapp"
    assert ref.tag == "1.2.3"


# ---------------------------------------------------------------------------
# Fully-qualified registries
# ---------------------------------------------------------------------------


def test_explicit_dockerhub_with_registry_prefix():
    ref = parse_image_ref("docker.io/library/python:3.11")
    assert ref == ImageRef("docker.io", "library/python", "3.11", None)


def test_ghcr_image():
    ref = parse_image_ref("ghcr.io/anthropics/claude-code:0.1")
    assert ref.registry == "ghcr.io"
    assert ref.repository == "anthropics/claude-code"
    assert ref.tag == "0.1"


def test_ecr_image():
    ref = parse_image_ref(
        "1234.dkr.ecr.us-east-1.amazonaws.com/myapp:v2",
    )
    assert ref.registry == "1234.dkr.ecr.us-east-1.amazonaws.com"
    assert ref.repository == "myapp"
    assert ref.tag == "v2"


def test_localhost_registry_with_port():
    """``localhost:5000/myimg:tag`` — the colon in the registry part
    is NOT a tag separator. Catches a classic parser-confusion bug."""
    ref = parse_image_ref("localhost:5000/myimg:tag")
    assert ref.registry == "localhost:5000"
    assert ref.repository == "myimg"
    assert ref.tag == "tag"


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------


def test_digest_only():
    """``python@sha256:abc...`` — digest pin without explicit tag.
    No ``latest`` default is applied (the digest IS the
    immutable identity)."""
    ref = parse_image_ref(
        "python@sha256:" + "a" * 64,
    )
    assert ref.tag is None
    assert ref.digest == "sha256:" + "a" * 64


def test_tag_plus_digest():
    """``python:3.11@sha256:abc...`` — both tag (mutable label) and
    digest (immutable identity) given. Both retained; the
    ``reference`` property returns the digest."""
    ref = parse_image_ref(
        "python:3.11@sha256:" + "b" * 64,
    )
    assert ref.tag == "3.11"
    assert ref.digest == "sha256:" + "b" * 64
    assert ref.reference == "sha256:" + "b" * 64


def test_malformed_digest_raises():
    with pytest.raises(ValueError, match="malformed digest"):
        parse_image_ref("python@notavaliddigest")


def test_too_short_hex_digest_rejected():
    """The digest hex part must be at least 32 chars (covers SHA-1
    fallbacks); shorter is malformed input rather than a quietly-
    accepted typo."""
    with pytest.raises(ValueError, match="malformed digest"):
        parse_image_ref("python@sha256:abc")


# ---------------------------------------------------------------------------
# Round-trip + reference property
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("input_ref,expected_canonical", [
    ("python", "docker.io/library/python:latest"),
    ("python:3.11", "docker.io/library/python:3.11"),
    (
        "ghcr.io/anthropics/claude-code:0.1",
        "ghcr.io/anthropics/claude-code:0.1",
    ),
    (
        "1234.dkr.ecr.us-east-1.amazonaws.com/myapp:v2",
        "1234.dkr.ecr.us-east-1.amazonaws.com/myapp:v2",
    ),
])
def test_canonical_round_trips_through_parser(
    input_ref, expected_canonical,
):
    """Canonical form must re-parse to the same :class:`ImageRef`."""
    parsed = parse_image_ref(input_ref)
    assert parsed.to_canonical() == expected_canonical
    assert parse_image_ref(parsed.to_canonical()) == parsed


def test_reference_property_prefers_digest_over_tag():
    """The HTTP-API reference (used in ``/v2/<name>/manifests/<ref>``)
    should be the digest when both are present — digest is immutable,
    so cache + dedup is correctness-preserving."""
    ref = parse_image_ref("python:3.11@sha256:" + "c" * 64)
    assert ref.reference == "sha256:" + "c" * 64


def test_reference_falls_back_to_tag():
    ref = parse_image_ref("python:3.11")
    assert ref.reference == "3.11"


def test_reference_falls_back_to_latest_when_neither():
    """Defensive: ``ImageRef`` constructed without tag or digest
    (e.g. via direct dataclass instantiation, bypassing the parser)
    still produces a usable reference."""
    ref = ImageRef("docker.io", "library/python", None, None)
    assert ref.reference == "latest"


# ---------------------------------------------------------------------------
# Empty / malformed input
# ---------------------------------------------------------------------------


def test_empty_string_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_image_ref("")


def test_whitespace_only_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_image_ref("   ")


def test_repository_only_digest_with_no_repo_part_rejected():
    """``@sha256:...`` with no repository preceding it is malformed —
    we reject rather than silently producing an empty repository."""
    with pytest.raises(ValueError, match="repository"):
        parse_image_ref("@sha256:" + "d" * 64)


# ---------------------------------------------------------------------------
# split_image_ref — the light, lossy splitter used by manifest parsers
# ---------------------------------------------------------------------------

def test_split_tag_pin():
    assert split_image_ref("postgres:16") == ("postgres", "16")


def test_split_registry_path_tag():
    assert split_image_ref("ghcr.io/x/y:1.2") == ("ghcr.io/x/y", "1.2")


def test_split_no_tag_returns_none():
    assert split_image_ref("alpine") == ("alpine", None)


def test_split_digest_pin():
    sha = "sha256:" + "a" * 64
    assert split_image_ref(f"foo@{sha}") == ("foo", sha)


def test_split_tag_plus_digest_drops_tag():
    sha = "sha256:" + "b" * 64
    assert split_image_ref(f"foo:1.2@{sha}") == ("foo", sha)


def test_split_registry_port_not_confused_with_tag():
    assert split_image_ref("localhost:5000/app") == (
        "localhost:5000/app", None,
    )
    assert split_image_ref("localhost:5000/app:2.0") == (
        "localhost:5000/app", "2.0",
    )


def test_split_never_canonicalises():
    # No library/ prefix, no docker.io default, no latest default.
    assert split_image_ref("python") == ("python", None)

# ---------------------------------------------------------------------------
# Digest algorithm allowlist — only sha256 pins are verifiable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("digest", [
    "sha512:" + "a" * 128,
    "md5:" + "b" * 32,
    "sha1:" + "c" * 40,
    "blake2b-256:" + "d" * 64,
])
def test_non_sha256_digest_algorithms_rejected(digest):
    """The client recomputes content addresses as sha256 only, so a
    pin in any other algorithm would be fetched and used with no
    content authentication. Refuse loudly at parse time."""
    with pytest.raises(ValueError, match="unsupported digest algorithm"):
        parse_image_ref(f"python@{digest}")


def test_sha256_digest_case_canonicalised():
    """Uppercase hex is operator-equivalent; canonicalise instead of
    refusing (registries emit lowercase)."""
    ref = parse_image_ref("python@SHA256:" + "A" * 64)
    assert ref.digest == "sha256:" + "a" * 64
