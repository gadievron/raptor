"""Extract a single binary from an OCI image to a local path.

Companion to :mod:`packages.sca.bump.binary_capability_delta` — the
detector compares two binaries, but doesn't know how to pull them
out of container images. This module owns that path:

  1. Resolve the image ref → manifest → (if multi-arch) drill
     platform → single-platform manifest.
  2. Fetch the image config blob, parse its ``Entrypoint`` /
     ``Cmd`` to identify the main binary path inside the image.
  3. Walk layers in order, ``extract_files_from_layer`` for the
     target path. Later layers override earlier ones (overlay-fs
     semantics) — exactly the same pattern as
     ``fetch_image_sbom`` for package-state files.
  4. Write the resulting bytes to ``out_dir`` (or a system
     tempfile) and return the local ``Path``.

The detector then receives two such local paths and runs the
capability diff.

Failure modes are routine when scanning multi-image-source
projects (private registries, missing tags, malformed configs,
rate-limited anonymous pulls). Every failure returns ``None`` with
a debug-level log — the caller (bump orchestrator) treats it as
"no binary-tier signal for this bump", which is the right verdict
because we have no evidence to escalate on.

Caller-supplied ``binary_path`` (absolute path inside the image)
overrides the entrypoint-auto-detection step. Useful for images
where ``Entrypoint`` is a shell wrapper but the load-bearing
binary is e.g. ``/usr/local/bin/server`` (operator knows; we
don't).
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path

from core.oci.blob import extract_files_from_layer
from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref
from core.oci.manifest import (
    is_image_index,
    is_image_manifest,
    parse_image_index,
    parse_image_manifest,
)

logger = logging.getLogger(__name__)


# Maximum compressed bytes of any single layer we'll stream when
# looking for the binary. Same cap as ``fetch_image_sbom``'s
# default — base images are small (alpine ~5 MB, debian-slim
# ~30 MB); a multi-GB layer is almost always an app blob that
# wouldn't carry the entrypoint binary anyway.
DEFAULT_MAX_LAYER_BYTES = 256 * 1024 * 1024


def fetch_image_binary(
    image_ref_str: str,
    *,
    client: OciRegistryClient,
    binary_path: str | None = None,
    platform_os: str = "linux",
    platform_arch: str = "amd64",
    out_dir: Path | None = None,
    max_layer_bytes: int = DEFAULT_MAX_LAYER_BYTES,
) -> Path | None:
    """Pull one binary out of ``image_ref_str``.

    ``binary_path`` is an absolute in-image path. When ``None``,
    we read the image config's ``Entrypoint`` / ``Cmd`` and use
    the first absolute path we find there.

    Returns the local ``Path`` containing the extracted bytes
    (under ``out_dir`` or a system tempdir), or ``None`` on any
    resolution / extraction failure.
    """
    try:
        ref = parse_image_ref(image_ref_str)
    except Exception as e:                            # noqa: BLE001
        logger.debug(
            "sca.bump.image_binary_extract: cannot parse %r: %s",
            image_ref_str, e,
        )
        return None

    try:
        manifest_resp = client.fetch_manifest(ref)
    except (RegistryError, Exception) as e:           # noqa: BLE001
        logger.debug(
            "sca.bump.image_binary_extract: manifest fetch failed "
            "for %s: %s", image_ref_str, e,
        )
        return None

    # Multi-arch index → drill to the platform.
    parsed = manifest_resp.parsed
    if is_image_index(manifest_resp.content_type):
        entries = parse_image_index(parsed)
        target = _select_platform(entries, platform_os, platform_arch)
        if target is None:
            logger.debug(
                "sca.bump.image_binary_extract: no %s/%s entry in "
                "index for %s",
                platform_os, platform_arch, image_ref_str,
            )
            return None
        try:
            manifest_resp = client.fetch_manifest(
                ref, reference=target.digest,
            )
        except (RegistryError, Exception) as e:       # noqa: BLE001
            logger.debug(
                "sca.bump.image_binary_extract: platform manifest "
                "fetch failed for %s@%s: %s",
                image_ref_str, target.digest, e,
            )
            return None
        parsed = manifest_resp.parsed

    if not is_image_manifest(manifest_resp.content_type):
        logger.debug(
            "sca.bump.image_binary_extract: unexpected manifest "
            "media type %s for %s",
            manifest_resp.content_type, image_ref_str,
        )
        return None

    try:
        image_manifest = parse_image_manifest(parsed)
    except ValueError as e:
        logger.debug(
            "sca.bump.image_binary_extract: manifest parse failed "
            "for %s: %s", image_ref_str, e,
        )
        return None

    if binary_path is None:
        binary_path = _resolve_entrypoint_path(
            client=client, ref=ref,
            config_digest=image_manifest.config_digest,
        )
        if binary_path is None:
            logger.debug(
                "sca.bump.image_binary_extract: could not resolve "
                "entrypoint path for %s",
                image_ref_str,
            )
            return None

    # Layers in order — earliest first. Later layers can replace
    # the same file (overlay-fs semantics); take whichever the
    # final-state path resolves to. Overlay-fs whiteout markers
    # (.wh.<basename>) delete the file from the final image.
    wanted_path = binary_path.lstrip("/")
    wanted_dir = os.path.dirname(wanted_path)
    wanted_base = os.path.basename(wanted_path)
    whiteout_path = (os.path.join(wanted_dir, f".wh.{wanted_base}")
                     if wanted_base else None)
    extract_set = {wanted_path}
    if whiteout_path:
        extract_set.add(whiteout_path)
    final_bytes: bytes | None = None
    for layer in image_manifest.layers:
        if layer.size and layer.size > max_layer_bytes:
            continue
        try:
            chunks = client.stream_blob(ref, layer.digest)
            files = extract_files_from_layer(
                chunks, extract_set, compressed_size=layer.size,
            )
        except Exception as e:                        # noqa: BLE001
            logger.debug(
                "sca.bump.image_binary_extract: layer %s extract "
                "failed for %s: %s",
                layer.digest, image_ref_str, e,
            )
            continue
        if whiteout_path and whiteout_path in files:
            final_bytes = None
        elif wanted_path in files:
            final_bytes = files[wanted_path]
        elif binary_path in files:
            # Tolerate both leading-/ and stripped forms — the tar
            # entry-name normaliser in core/oci/blob already
            # canonicalises but the dict key reflects what the
            # caller asked for.
            final_bytes = files[binary_path]

    if final_bytes is None:
        logger.debug(
            "sca.bump.image_binary_extract: %s not found in any "
            "layer of %s", binary_path, image_ref_str,
        )
        return None

    created_dir: Path | None = None
    handed_out = False
    try:
        if out_dir is None:
            # Fresh mode-0700 directory per extraction — NEVER the
            # shared system tempdir directly: the content hash of a
            # public image is attacker-predictable, so on a multi-user
            # host another user could pre-create the predicted file,
            # keep ownership, and rewrite the bytes between our write
            # and the capability diff (verdict steering), or use
            # fs.protected_regular to deterministically suppress the
            # detector. mkdtemp is owned by us and unreadable to
            # others by construction.
            out_dir = Path(tempfile.mkdtemp(prefix=_OWNED_DIR_PREFIX))
            created_dir = out_dir
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
        # Name the file by the CONTENT hash + a sanitised basename so
        # two different versions of the same image can coexist on disk
        # without collision when the same out_dir is reused. The
        # manifest digest header and the binary path are both
        # remote-influenced strings, so neither feeds the filename
        # unsanitised: the hash comes from the bytes we actually hold,
        # and the basename is reduced to a safe character set.
        import hashlib
        content_hash = hashlib.sha256(final_bytes).hexdigest()[:32]
        basename = _sanitise_filename_component(
            os.path.basename(binary_path),
        )
        out_path = out_dir / f"{content_hash}-{basename}"
        # Belt and braces: the joined path must stay inside out_dir.
        resolved_dir = out_dir.resolve()
        if not out_path.resolve().is_relative_to(resolved_dir):
            logger.debug(
                "sca.bump.image_binary_extract: refusing out-of-dir "
                "write for %s", image_ref_str,
            )
            return None
        # O_EXCL|O_NOFOLLOW: never truncate or follow a pre-existing
        # entry (a plain write_bytes was O_CREAT|O_TRUNC and followed
        # symlinks — a resolve-then-write ordering an attacker's
        # pre-created file or link wins). A pre-existing file is only
        # reused when it is verifiably OUR earlier extraction of the
        # same bytes.
        try:
            fd = os.open(
                str(out_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            if _is_reusable_extraction(out_path, final_bytes):
                handed_out = True
                return out_path
            logger.debug(
                "sca.bump.image_binary_extract: refusing pre-existing "
                "path %s (not our extraction)", out_path,
            )
            return None
        with os.fdopen(fd, "wb") as fh:
            fh.write(final_bytes)
        handed_out = True
        return out_path
    except OSError as e:
        logger.debug(
            "sca.bump.image_binary_extract: write failed for %s: %s",
            image_ref_str, e,
        )
        return None
    finally:
        if created_dir is not None and not handed_out:
            # Failure after we created the owned dir (ENOSPC-class
            # os.open/write errors): the caller gets None and can
            # never route the dir to cleanup_extracted_binary, so it
            # leaks one dir per failed extraction. Remove it — and
            # any partial write — here.
            try:
                for child in created_dir.iterdir():
                    child.unlink()
                created_dir.rmdir()
            except OSError:
                pass


# Prefix for the per-extraction directories this module owns.
# ``cleanup_extracted_binary`` only removes directories carrying it.
_OWNED_DIR_PREFIX = "raptor-sca-bump-"


def _is_reusable_extraction(path: Path, expected: bytes) -> bool:
    """True when ``path`` is verifiably OUR earlier extraction of the
    same bytes: a regular non-symlink file, owned by this uid, not
    group/other-writable, byte-identical content. Anything else —
    another owner, looser mode, different bytes — is refused (a
    predictable-name plant on a shared out_dir)."""
    import stat as _stat
    try:
        st = path.lstat()
    except OSError:
        return False
    if not _stat.S_ISREG(st.st_mode):
        return False
    if st.st_uid != os.getuid():
        return False
    if st.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
        return False
    if st.st_size != len(expected):
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(len(expected) + 1) == expected
    except OSError:
        return False


def cleanup_extracted_binary(path: Path | None) -> None:
    """Remove an extracted binary and, when it sits in a directory
    this module created (``mkdtemp`` with our prefix), the directory
    too. Callers invoke this after the capability diff / fingerprint
    — extracted binaries previously accumulated in the system tempdir
    across runs, unbounded."""
    if path is None:
        return
    try:
        path.unlink()
    except OSError:
        pass
    parent = path.parent
    if parent.name.startswith(_OWNED_DIR_PREFIX):
        try:
            parent.rmdir()
        except OSError:
            pass


# Characters allowed to pass through from a remote-influenced binary
# path into an on-disk filename. Everything else is replaced.
_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_MAX_FILENAME_COMPONENT = 64

# Image CONFIG blobs are small JSON documents (a few KB in the
# wild); 4 MiB is generous headroom. Deliberately far below the
# shared 2 GiB stream_blob budget, which is sized for image LAYERS
# — every other remote read on this lane carries its own tight cap
# (action.yml 256 KB, layer extraction double-bounded).
_MAX_CONFIG_BLOB_BYTES = 4 * 1024 * 1024


def _sanitise_filename_component(name: str) -> str:
    """Reduce a remote-influenced basename to ``[A-Za-z0-9._-]``.

    Also strips leading dots (no hidden / relative-looking names) and
    caps length so the joined path stays a plain single component.
    Empty results fall back to ``"binary"``.
    """
    cleaned = _SAFE_FILENAME_CHARS.sub("_", name).lstrip(".")
    cleaned = cleaned[:_MAX_FILENAME_COMPONENT]
    return cleaned or "binary"


def _select_platform(
    entries: list, platform_os: str, platform_arch: str,
):
    """Pick the index entry matching ``(platform_os,
    platform_arch)``. Ignores variant — first match wins."""
    for e in entries:
        if e.os == platform_os and e.architecture == platform_arch:
            return e
    return None


def _resolve_entrypoint_path(
    *, client: OciRegistryClient, ref, config_digest: str,
) -> str | None:
    """Fetch the image config blob and read ``Entrypoint`` /
    ``Cmd`` to find the main binary's in-image path.

    OCI image config shape:
        {"config": {"Entrypoint": ["/usr/bin/foo", "--flag"],
                    "Cmd": ["--default"], ...}, ...}

    Returns the first absolute path found in Entrypoint, or the
    first absolute path in Cmd, or None if neither yields one.
    """
    try:
        chunks = client.stream_blob(ref, config_digest)
        # Config blobs are JSON, not gzipped tar — read raw bytes,
        # bounded: real image configs are a few KB, and the only
        # limit below this one is the client's 2 GiB LAYER budget.
        # A hostile or compromised registry (exactly the artefact
        # class this detector inspects) serving a huge "config"
        # must degrade to None, not get buffered twice (join +
        # decoded copy) per image ref.
        pieces: list[bytes] = []
        received = 0
        for chunk in chunks:
            received += len(chunk)
            if received > _MAX_CONFIG_BLOB_BYTES:
                logger.warning(
                    "sca.bump.image_binary_extract: config blob %s "
                    "exceeds %d bytes — refusing (real image configs "
                    "are a few KB)",
                    config_digest, _MAX_CONFIG_BLOB_BYTES,
                )
                return None
            pieces.append(chunk)
        blob = b"".join(pieces)
        config = json.loads(blob.decode("utf-8", errors="replace"))
    except Exception as e:                            # noqa: BLE001
        logger.debug(
            "sca.bump.image_binary_extract: config blob fetch / "
            "parse failed for digest %s: %s",
            config_digest, e,
        )
        return None

    inner = config.get("config") if isinstance(config, dict) else None
    if not isinstance(inner, dict):
        return None
    for key in ("Entrypoint", "Cmd"):
        seq = inner.get(key)
        if not isinstance(seq, list):
            continue
        for item in seq:
            if isinstance(item, str) and item.startswith("/"):
                return item
    return None


__all__ = [
    "DEFAULT_MAX_LAYER_BYTES",
    "fetch_image_binary",
]
