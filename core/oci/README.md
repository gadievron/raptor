# `core/oci/` — OCI / Docker registry primitives

Shared infrastructure for inspecting container images. Several raptor consumers want this:

- **`packages/sca`** — base-image SBOM as a Dependency source for CVE matching
- **`packages/cve_diff`** — image-vs-image diff for security advisories
- **`packages/llm_analysis`** (`/scan`, `/agentic`) — surface base-image context for analysis prompts
- **`packages/oss_forensics`** — registry attestations (cosign, in-toto) for supply-chain investigation
- **`packages/code_understanding`** (`/audit`) — include base-image SBOMs in code review

Building those primitives once under `core/oci/` mirrors the pattern that `core/http`, `core/llm`, `core/inventory` already follow.

## Module map

| Module | What |
|---|---|
| `image_ref.py` | Parse + canonicalise image references (`python:3.11` → `docker.io/library/python:3.11`) |
| `registry_hosts.py` | image_ref → list[str] of HTTPS hosts the sandbox must allow |
| `auth.py` | Three-layer credential chain: env vars → docker config → anonymous |
| `client.py` | Registry HTTP API v2 client built on `core.http.HttpClient` |
| `manifest.py` | OCI Image Manifest v1 + Docker Manifest Schema 2 + multi-arch index |
| `blob.py` | gzipped layer-tar streaming with targeted file extraction |
| `sbom.py` | Per-layer SBOM extraction: dpkg / apk / rpm-sqlite parsers |

## Quick example

```python
from core.http import HttpClient
from core.oci import parse_image_ref, registry_hosts_for
from core.oci.client import OciRegistryClient
from core.oci.manifest import (
    parse_image_manifest, parse_image_index, is_image_index,
    select_platform,
)
from core.oci.blob import extract_files_from_layer
from core.oci.sbom import packages_from_layer_files, LAYER_FILE_PATHS

ref = parse_image_ref("python:3.11-slim")
hosts = registry_hosts_for(ref)             # used to set sandbox allowlist

http = HttpClient(allowed_hosts=hosts)
client = OciRegistryClient(http)

# Resolve to digest, fetch manifest, pick a platform if multi-arch.
mr = client.fetch_manifest(ref)
if is_image_index(mr.content_type):
    pick = select_platform(parse_image_index(mr.parsed))
    mr = client.fetch_manifest(ref, reference=pick.digest)

# Walk layers, extract package state, parse to InstalledPackage list.
manifest = parse_image_manifest(mr.parsed)
all_packages: list = []
for layer in manifest.layers:
    chunks = client.stream_blob(ref, layer.digest)
    files = extract_files_from_layer(chunks, set(LAYER_FILE_PATHS))
    all_packages.extend(packages_from_layer_files(files))
```

## Authentication

Three-layer credential chain, tried in order:

1. **Per-registry env vars** — `RAPTOR_OCI_<HOST_UPPER>_USER` / `RAPTOR_OCI_<HOST_UPPER>_PASSWORD`. Host with `.` and `-` becomes `_`. Example: `ghcr.io` → `RAPTOR_OCI_GHCR_IO_USER`. Designed for CI / ad-hoc credentials.
2. **`~/.docker/config.json` inline `auths`** — the artefact `docker login` produces. Honours `auths.<host>.auth` (base64'd `user:password`) and `auths.<host>.username`/`password`. Honoured key shapes: bare host, `https://<host>`, `https://<host>/v1/`.
3. **Anonymous bearer token** — for public images on `docker.io/library/*`, public `ghcr.io`, `public.ecr.aws`, etc. Always tried as the last resort.

`DOCKER_CONFIG` env var (alternate config dir) is honoured per Docker convention.

### Deliberately refused

- **`credsStore`** — would require shelling out to `docker-credential-<name>` (osxkeychain, secretservice, wincred, …). Expanding raptor's trust surface to exec another binary on every registry call is too much for marginal convenience. Operators using credsStore fall back to the env-var path.
- **`credHelpers`** — same reasoning. Per-registry helpers refused.

## Registry support

Tested + working:

| Registry | Auth shape | Notes |
|---|---|---|
| `docker.io` | Anonymous bearer for public; basic for private | Manifests on `registry-1.docker.io`, tokens on `auth.docker.io` (both must be on the sandbox allowlist) |
| `ghcr.io` | Anonymous for public; basic for private | Single host; `GITHUB_TOKEN` works as the password with any username |
| `public.ecr.aws` | Anonymous | Single host |
| `quay.io` | Anonymous for public; basic for private | Single host |
| `<account>.dkr.ecr.<region>.amazonaws.com` | AWS-SDK-issued tokens | The regional STS + ECR endpoints must be on the sandbox allowlist |
| `gcr.io` / `*.pkg.dev` (GCP Artifact Registry) | Bearer tokens via service-account exchange | Requires GCP-side auth setup; raptor reads the resulting JWT via env vars |
| `<name>.azurecr.io` | Bearer | Azure AD or admin-account credentials |
| `registry.gitlab.com` | Bearer for public; basic for private | |
| Self-hosted / private registries | Whatever the registry advertises | Falls through to "host is its own host" allowlist; auth surfaces clearly when it fails |

## Multi-arch images

Images on Docker Hub (`python:3.11`, `node:20`, etc.) typically ship as multi-arch image indexes (linux/amd64, linux/arm64, linux/s390x, linux/ppc64le, …). The default platform is **`linux/amd64`**. Operators on Apple Silicon scanning for ARM64-only deployments override via `select_platform(entries, architecture="arm64")`.

## Sandbox host allowlist

`core.sandbox.run` takes a static `proxy_hosts=` allowlist. For OCI work you compute it from the image references being inspected:

```python
hosts = []
for image in images_to_scan:
    hosts.extend(registry_hosts_for(image))
sandbox_run(cmd, proxy_hosts=list(set(hosts)))
```

## Limitations & follow-ups

These are deliberate scope decisions, not bugs:

1. **Berkeley DB-format RPM databases** (used through CentOS 7) are not parsed; only modern SQLite-backed `rpmdb.sqlite` (CentOS 8+, RHEL 8+, Fedora 36+, Rocky/Alma). Operators scanning legacy images get "no SBOM found" — which is accurate.
2. **APK v3** (the future Alpine package format) isn't yet stable; we parse v2 only. Alpine still ships v2.
3. **No cosign / sigstore signature verification** — image-pull works, but we don't verify in-toto attestations or cosign signatures. A separate signing layer is the right home for that work.
4. **No multi-arch SBOM merging** — we pull one platform per image. Operators wanting "scan every architecture's SBOM" call the helpers in a loop.
5. **No streaming-decompress for non-gzip layers** — zstd compression (`application/vnd.oci.image.layer.v1.tar+zstd`) isn't yet supported. Most images still ship gzip; zstd adoption is recent.
6. **No `ARG` / `ENV` variable substitution** in Dockerfile parsing — instructions carry raw text. Consumers needing substitution (`FROM ${BASE_IMAGE}`) do their own ARG-tracking.
7. **Heredoc syntax (`<<EOF`)** in Dockerfile is parsed as raw text; we don't interpret the contained shell.
8. **No image-cache invalidation by tag mutation** — when an operator's `python:3.11` tag re-points (Docker Hub does this on minor releases), our cache continues to serve the old digest until manually refreshed. Acceptable for SBOM purposes (the previous digest's CVEs are still valid for the historical scan).

## Testing

107 unit tests, no network: `pytest core/oci/tests/ core/dockerfile/tests/`. The tests use fixture data captured from real registries (manifest JSON, layer tar contents, dpkg/apk/rpm-sqlite samples) so no live HTTP is needed. Integration tests against `docker.io/library/alpine` (small, public, anonymous-OK) live in a separate suite that's gated behind a `RAPTOR_OCI_INTEGRATION` env var so they don't run in default CI.
