"""Perlasm generator detection and sandboxed generated-asm inventory.

OpenSSL-family repos build shipped runtime assembly from Perl
generators (``crypto/*/asm/*.pl`` driven through a ``*-xlate.pl``
translator). The asm lives in heredoc strings, invisible to every
source extractor — the inventory could not even enumerate those
kernels. This module closes that hole with the bounded option:
*run the generators, analyse what they emit* — never the Perl itself.

Pipeline (all best-effort, every miss recorded loudly):

1. **Detect** — structural content signature, not path matching: a
   ``$xlate = "...-xlate.pl"`` driver reference plus ``$flavour`` /
   ``$output`` argv handling. ``*-xlate.pl`` translators themselves
   are excluded.
2. **Derive flavour** — from build metadata when present (a generated
   ``configdata.pm``'s ``perlasm_scheme``), else a per-driver-family
   default: ``arm-xlate.pl`` → ``linux64`` (the AArch64 flavour of the
   observed findings), ``x86_64-xlate.pl`` → ``elf``. Families with no
   derivable flavour (ppc, ...) are recorded as coverage gaps, never
   executed blind.
3. **Execute sandboxed** — the ``.pl`` is repo content: list-argv
   ``perl`` under :func:`core.sandbox.run_untrusted` with
   ``profile="strict"`` (fail-closed: namespace + Landlock + network
   deny or no execution at all), reads confined to the target tree,
   writes confined to the cache dir. Emitted assembly is untrusted
   data to every consumer.
4. **Cache** — keyed on generator content hash + resolved xlate driver
   hash + flavour (the build-id/source-hash cache precedent); repeat
   inventory runs skip execution entirely.
5. **Inventory** — the emitted ``.S`` goes through the existing
   ``AsmExtractor`` so the kernels become enumerable, reviewable units:
   synthetic file records under ``.perlasm-generated/`` with
   ``language == "asm-generated"`` and full provenance (generator,
   flavour, hashes, cached path).
6. **Gap flagging** — generators detected but not analysed (no perl,
   sandbox refusal, no flavour, execution failure, cap) append to
   ``inventory['limitations']`` and warn — a detected generator is
   never silently missed.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Virtual path prefix for generated-file records in the checklist.
# Distinct top-level namespace so synthetic records can never collide
# with real target paths.
GENERATED_PREFIX = ".perlasm-generated"

# Bounded work: read caps mirror the builder's bounded reads; the
# generator cap matches the design's ~50 x ~1s envelope.
_MAX_PL_BYTES = 2 * 1024 * 1024
_MAX_ASM_BYTES = 8 * 1024 * 1024
MAX_GENERATORS = 50
_GEN_TIMEOUT_S = 30

# Structural perlasm preamble signature (content, not path): an xlate
# driver reference + flavour argv + output argv.
_XLATE_REF_RE = re.compile(r"\$xlate\s*=[^\n]{0,120}?([\w-]+-xlate)\.pl")
_FLAVOUR_RE = re.compile(r"\$flavour\s*=[^\n]{0,160}(?:shift|ARGV)")
_OUTPUT_RE = re.compile(r"\$output\s*=[^\n]{0,160}(?:pop|shift|ARGV)")

# Flavour defaults per xlate driver family, used when the target
# carries no build metadata. linux64 == AArch64 GAS — the flavour of
# the two observed findings; elf == linux x86_64. Families absent
# here (ppc-xlate, ...) become coverage gaps, not blind runs.
DRIVER_DEFAULT_FLAVOURS = {
    "arm-xlate": "linux64",
    "x86_64-xlate": "elf",
}

# configdata.pm (present only in configured build trees) records the
# scheme the real build would pass.
_PERLASM_SCHEME_RE = re.compile(r'"perlasm_scheme"\s*=>\s*"(\w+)"')

_SKIP_DIR_NAMES = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__",
})


@dataclass
class PerlasmGenerator:
    """One detected perlasm generator (structural match)."""

    path: Path            # absolute
    rel_path: str         # relative to target root
    driver: str           # xlate family, e.g. "arm-xlate"
    sha256: str


@dataclass
class PerlasmResult:
    """Outcome of the detection + generation pass."""

    generators: list[PerlasmGenerator] = field(default_factory=list)
    file_records: list[dict] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    flavours: dict[str, str] = field(default_factory=dict)  # rel_path -> flavour


def detect_perlasm_generators(target: Path) -> list[PerlasmGenerator]:
    """Walk *target* for ``.pl`` files matching the perlasm preamble.

    Structural detection only — no path hardcoding. Symlinks are
    skipped (same discipline as the inventory walk); ``*-xlate.pl``
    translators are the drivers, not generators.
    """
    found: list[PerlasmGenerator] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(
            d for d in dirs
            if not d.startswith(".") and d not in _SKIP_DIR_NAMES
            and not Path(root, d).is_symlink()
        )
        for name in sorted(files):
            if not name.endswith(".pl") or name.endswith("-xlate.pl"):
                continue
            fpath = Path(root, name)
            if fpath.is_symlink():
                continue
            try:
                fd = os.open(fpath, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    raw = fh.read(_MAX_PL_BYTES)
            except OSError:
                continue
            content = raw.decode("utf-8", "replace")
            m = _XLATE_REF_RE.search(content)
            if not m or not _FLAVOUR_RE.search(content) \
                    or not _OUTPUT_RE.search(content):
                continue
            found.append(PerlasmGenerator(
                path=fpath,
                rel_path=str(fpath.relative_to(target)),
                driver=m.group(1),
                sha256=hashlib.sha256(raw).hexdigest(),
            ))
    return found


def derive_flavour(gen: PerlasmGenerator, target: Path,
                   ) -> tuple[str | None, str]:
    """Return ``(flavour, source)`` for *gen*.

    Resolution order: build metadata (``configdata.pm``'s
    ``perlasm_scheme`` — present only in configured trees), then the
    per-driver-family default. ``(None, reason)`` when neither
    applies.
    """
    configdata = target / "configdata.pm"
    if configdata.is_file():
        try:
            m = _PERLASM_SCHEME_RE.search(
                configdata.read_text(errors="replace")[:4 * 1024 * 1024]
            )
            if m:
                return m.group(1), "build-metadata (configdata.pm)"
        except OSError:
            pass
    flavour = DRIVER_DEFAULT_FLAVOURS.get(gen.driver)
    if flavour:
        return flavour, f"driver-family default for {gen.driver}"
    return None, f"no derivable flavour for driver family {gen.driver!r}"


def default_cache_dir() -> Path:
    """Generated-asm cache root (build-id-cache resolution precedent):
    ``RAPTOR_PERLASM_CACHE_DIR`` env, else ``<repo>/.cache/perlasm``.
    """
    env = os.environ.get("RAPTOR_PERLASM_CACHE_DIR")
    if env:
        return Path(env)
    from core.config import RaptorConfig
    return Path(RaptorConfig.REPO_ROOT) / ".cache" / "perlasm"


def _resolve_driver_sha(gen: PerlasmGenerator) -> str:
    """Hash the xlate driver the generator will load, when locatable.

    The emitted asm is a function of generator + driver + flavour, so
    the driver content belongs in the cache key. Mirrors the
    generator's own lookup: alongside it, then ``../../perlasm/``.
    """
    for cand in (
        gen.path.parent / f"{gen.driver}.pl",
        gen.path.parent / ".." / ".." / "perlasm" / f"{gen.driver}.pl",
    ):
        try:
            if cand.is_file() and not cand.is_symlink():
                return hashlib.sha256(cand.read_bytes()).hexdigest()
        except OSError:
            continue
    return "driver-unresolved"


def _cache_key(gen: PerlasmGenerator, flavour: str) -> str:
    driver_sha = _resolve_driver_sha(gen)
    return hashlib.sha256(
        f"{gen.sha256}\0{driver_sha}\0{flavour}".encode()
    ).hexdigest()[:24]


def generate_asm(gen: PerlasmGenerator, flavour: str, target: Path,
                 cache_dir: Path) -> tuple[Path | None, str | None]:
    """Run *gen* sandboxed for *flavour*; return ``(cached .S, None)``
    or ``(None, gap reason)``.

    Cache hit skips execution. Execution is fail-closed: strict
    sandbox profile (namespace + Landlock + network deny) or nothing.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / f"{_cache_key(gen, flavour)}.S"
    if cached.is_file():
        return cached, None

    from core.sandbox.context import run_untrusted
    from core.sandbox.errors import SandboxSetupError

    fd, tmp_name = tempfile.mkstemp(suffix=".S", dir=cache_dir)
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        try:
            proc = run_untrusted(
                ["perl", str(gen.path), flavour, str(tmp_path)],
                target=str(target),
                output=str(cache_dir),
                profile="strict",
                caller_label="perlasm_generate",
                capture_output=True,
                text=True,
                timeout=_GEN_TIMEOUT_S,
            )
        except SandboxSetupError as exc:
            return None, (
                f"{gen.rel_path}: sandbox refused (strict isolation "
                f"unavailable: {exc}) — generator NOT executed"
            )
        except (OSError, ValueError) as exc:
            return None, f"{gen.rel_path}: perl invocation failed: {exc}"
        except Exception as exc:  # timeout etc.
            return None, f"{gen.rel_path}: generation failed: {exc}"
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip()[-200:]
            return None, (
                f"{gen.rel_path}: generator exited {proc.returncode} "
                f"for flavour {flavour!r}: {tail}"
            )
        if not tmp_path.is_file() or tmp_path.stat().st_size == 0:
            return None, (
                f"{gen.rel_path}: generator produced no output for "
                f"flavour {flavour!r}"
            )
        os.replace(tmp_path, cached)
        return cached, None
    finally:
        tmp_path.unlink(missing_ok=True)


def _sloc(text: str) -> int:
    return sum(
        1 for line in text.split("\n")
        if line.strip() and not line.strip().startswith(("//", "#", "/*", "*"))
    )


def _build_file_record(gen: PerlasmGenerator, flavour: str,
                       flavour_source: str, cached: Path) -> dict | None:
    """AsmExtractor pass over the emitted asm -> synthetic file record."""
    from core.inventory.extractors import AsmExtractor

    try:
        with open(cached, "rb") as fh:
            raw = fh.read(_MAX_ASM_BYTES)
    except OSError as exc:
        logger.warning("perlasm: cannot read cached asm %s: %s", cached, exc)
        return None
    text = raw.decode("utf-8", "replace")
    virtual_path = f"{GENERATED_PREFIX}/{gen.rel_path}.{flavour}.S"
    items = AsmExtractor().extract(virtual_path, text)
    return {
        "path": virtual_path,
        "language": "asm-generated",
        "lines": text.count("\n") + 1,
        "sloc": _sloc(text),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "items": [fi.to_dict() for fi in items],
        "perlasm": {
            "generator": gen.rel_path,
            "generator_sha256": gen.sha256,
            "driver": gen.driver,
            "flavour": flavour,
            "flavour_source": flavour_source,
            "generated_path": str(cached),
        },
    }


def run_perlasm_pass(target: Path, *, cache_dir: Path | None = None,
                     max_generators: int = MAX_GENERATORS) -> PerlasmResult:
    """Full detect -> derive -> generate -> extract pass over *target*."""
    result = PerlasmResult()
    result.generators = detect_perlasm_generators(target)
    if not result.generators:
        return result

    if shutil.which("perl") is None:
        result.gaps.append(
            f"perl not installed — {len(result.generators)} perlasm "
            f"generator(s) detected but NOT analysed (generated runtime "
            f"assembly is unreviewed)"
        )
        return result

    todo = result.generators[:max_generators]
    overflow = result.generators[max_generators:]
    if overflow:
        result.gaps.append(
            f"generator cap ({max_generators}) reached — "
            f"{len(overflow)} generator(s) NOT analysed: "
            + ", ".join(g.rel_path for g in overflow[:5])
            + (" ..." if len(overflow) > 5 else "")
        )

    cache = cache_dir or default_cache_dir()
    for gen in todo:
        flavour, flavour_source = derive_flavour(gen, target)
        if flavour is None:
            result.gaps.append(
                f"{gen.rel_path}: {flavour_source} — generator NOT "
                f"analysed"
            )
            continue
        cached, gap = generate_asm(gen, flavour, target, cache)
        if cached is None:
            result.gaps.append(gap or f"{gen.rel_path}: generation failed")
            continue
        record = _build_file_record(gen, flavour, flavour_source, cached)
        if record is None:
            result.gaps.append(
                f"{gen.rel_path}: emitted asm unreadable — NOT inventoried"
            )
            continue
        result.file_records.append(record)
        result.flavours[gen.rel_path] = flavour
    return result


def enrich_inventory_with_perlasm(inventory: dict, target_path: str | Path,
                                  *, cache_dir: Path | None = None) -> None:
    """Builder seam: append generated-asm records + gap notes in place.

    Best-effort by contract with the caller (the builder wraps this in
    try/except like the binary-oracle enrichment); mutates
    ``inventory['files']``, the totals, ``inventory['perlasm']`` and
    ``inventory['limitations']``. ``RAPTOR_NO_PERLASM=1`` disables.
    """
    if os.environ.get("RAPTOR_NO_PERLASM"):
        return
    from core.config import RaptorConfig
    if not getattr(RaptorConfig, "PERLASM_INVENTORY", True):
        return

    result = run_perlasm_pass(Path(target_path), cache_dir=cache_dir)
    if not result.generators:
        return

    files = inventory.setdefault("files", [])
    existing = {f.get("path") for f in files}
    added_items = added_functions = added_sloc = 0
    for record in result.file_records:
        if record["path"] in existing:
            continue
        files.append(record)
        added_items += len(record["items"])
        added_functions += len(record["items"])
        added_sloc += record["sloc"]
    if result.file_records:
        inventory["total_files"] = inventory.get("total_files", 0) + len(
            result.file_records
        )
        inventory["total_items"] = inventory.get("total_items", 0) + added_items
        inventory["total_functions"] = (
            inventory.get("total_functions", 0) + added_functions
        )
        inventory["total_sloc"] = inventory.get("total_sloc", 0) + added_sloc

    inventory["perlasm"] = {
        "generators_detected": len(result.generators),
        "analysed": len(result.file_records),
        "flavours": result.flavours,
        "gaps": result.gaps,
    }
    if result.gaps:
        limitations = inventory.setdefault("limitations", [])
        for gap in result.gaps:
            note = f"perlasm coverage gap: {gap}"
            limitations.append(note)
            logger.warning("%s", note)
    logger.info(
        "perlasm: %d generator(s) detected, %d analysed (%d kernels "
        "inventoried), %d gap(s)",
        len(result.generators), len(result.file_records),
        added_functions, len(result.gaps),
    )
