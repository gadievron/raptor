"""Sample-corpus format profiler: byte statistics over hostile samples.

``/binary corpus <dir>`` points RAPTOR at a directory of input samples
harvested from a target install (configuration blobs, channel files,
protocol captures) and recovers the parts of the wire format that pure
byte statistics can prove: per-offset constancy (magic / reserved
bytes), enum-candidate offsets, size-field candidates cross-checked
against actual file lengths, an entropy profile, and a repeating
length-prefixed-record (TLV) likelihood. It emits a seed min-set and a
``fuzz.dict`` for the fuzzing lane.

Discipline:

- ZERO semantic parsing and ZERO execution. Every fact is a statistic
  over raw bytes; the profiler never interprets a sample with a format
  library and never runs the target.
- Samples are HOSTILE for their whole life here: they may themselves
  be attacker-written (a compromised install can plant samples that
  steer the profile). Facts are corpus-tier — the profile carries its
  own internal ``confidence`` and an ``uncorroborated`` corroboration
  status; only a future parser-corroboration join (the BINARY-side
  format inference in ``packages/autonomous/corpus_generator.py`` is
  the complementary witness) upgrades them.
- Every artifact field whose content derives from sample bytes or
  sample filenames is marked ``derived_from_target: true``, filenames
  are escaped at capture, and sample bytes are rendered as hex only.
- Filename grouping uses a FIXED TEMPLATE LANGUAGE (character-class
  runs + literal separators) — never a regex compiled from an
  attacker-controlled filename, which would be a ReDoS/injection
  primitive.
- Seed files are COPIED, never hard-linked: a hard link aliases the
  run-dir artifact to the hostile source inode (TOCTOU via inode
  identity, cleanup and cross-mount hazards) — a later mutation of the
  source would silently rewrite the run artifact.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import math
import os
import stat as stat_module
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from core.atomic_fs import open_exclusive_artifact, write_text_atomically
from core.hash import sha256_file
from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal
from core.security.markdown_render import md_inline

from packages.binary_analysis._artifact_lock import run_artifacts_lock

# fuzz.dict handoff follows the existing auto-discovery convention:
# /fuzz picks up <run_dir>/fuzz.dict when no --dict is passed
# (packages/fuzzing/audit_dict.py), and refuses files above its byte
# cap — emitting under the same name and cap is the only path on which
# "consumed by /fuzz unchanged" is true.
from packages.fuzzing.audit_dict import DICT_FILENAME, MAX_DICT_BYTES

PROFILE_JSON_NAME = "format-profile.json"
PROFILE_REPORT_NAME = "format-profile.md"
SEED_DIR_NAME = "corpus-seeds"
SEED_MANIFEST_SOURCE = "raptor_corpus_profile_seed_minset"

# ─── caps (each carries its both-direction rationale) ───────────────

# Header statistics window. Larger windows would profile deeper into
# variable payload bytes where per-offset statistics are noise and the
# field table becomes unreadable; smaller windows miss size fields that
# real formats place after a 64-128 byte preamble. 256 covers every
# header layout seen in the motivating corpus class while keeping
# memory at samples x window bytes.
DEFAULT_HEADER_WINDOW = 256

# Sample-count cap. More samples sharpen agreement ratios but cost a
# linear walk per offset and let a flooded drop directory starve the
# run; fewer samples make enum cardinality and size-field agreement
# statistically meaningless. 2048 keeps the full pass under a second
# while any real corpus subset that size is representative.
DEFAULT_MAX_SAMPLES = 2048

# Per-sample byte cap (streaming bounded read). Reading more inflates
# the entropy pass and lets one crafted multi-GiB sample eat the total
# budget; reading less would misclassify large structured bodies as
# "short". 4 MiB bounds worst-case memory per sample while covering
# the sample sizes the profiler is for (config/protocol blobs).
DEFAULT_MAX_BYTES_PER_SAMPLE = 4 * 1024 * 1024

# Total read budget across the whole corpus. Without it, max_samples x
# max_bytes_per_sample admits an 8 GiB walk on a hostile directory;
# tighter budgets would truncate legitimate mid-size corpora. 256 MiB
# is ~an order of magnitude above the motivating 460-sample corpus.
DEFAULT_TOTAL_BYTE_BUDGET = 256 * 1024 * 1024

# Family cap. Every family costs per-offset counters (window x
# Counter); unbounded families let a directory of unique-magic noise
# files allocate without limit. Fewer would merge genuinely distinct
# formats in multi-format sample trees. Overflow families are counted,
# named in the summary, and skipped — never silently dropped.
MAX_FAMILIES = 64

# An offset is an enum candidate when its distinct-value count is in
# [2, 16]. Higher cardinality is indistinguishable from variable data
# on small corpora (byte noise reaches 17+ values fast); 16 covers
# real type/version/flag enums.
ENUM_MAX_CARDINALITY = 16
# Observation floor for enum claims: every claimed value must be seen
# at least twice AND cardinality must not exceed half the
# observations. Without this, any family of n <= 16 samples turns
# every varying offset into a "full-confidence enum" — noise floods
# the dictionary to its cap and the seed "min-set" degenerates to
# copy-all. Demanding more repetition than 2x would miss real sparse
# enums on legitimately small corpora.
ENUM_MIN_VALUE_COUNT = 2
# Below this many observations an offset's statistics are anecdote,
# not evidence: with 2 samples every varying byte is a plausible
# "enum" and every agreeing byte a plausible "constant". 3 is the
# minimum that can distinguish agreement from coincidence at all —
# raising it would blank the field table on legitimately tiny corpora.
MIN_OFFSET_OBSERVATIONS = 3

# Size-field discovery: value at offset must satisfy
# ``file_size - value == k`` for one modal k across >= 90% of the
# family. Lower agreement admits coincidences on small corpora; higher
# rejects families with a few truncated/corrupt members (which real
# harvested corpora contain).
SIZE_FIELD_MIN_AGREEMENT = 0.9
SIZE_FIELD_MIN_SAMPLES = 3
# Plausible k (header/trailer accounted by the size field). Negative k
# beyond a small slack means value > file size (not a size field);
# k above 1024 would mean a >1 KiB unexplained envelope — beyond any
# header this profiler can also see in its window. Both directions
# trade false positives against missing exotic envelopes.
SIZE_FIELD_DELTA_MIN = -16
SIZE_FIELD_DELTA_MAX = 1024

# Shannon entropy (bits/byte) above which a body region is treated as
# compressed/encrypted. Lower thresholds misflag dense binary
# structures (bitmaps, packed records); higher misses weaker stream
# ciphers/compressors. 7.2 is the conventional compressed-data floor.
HIGH_ENTROPY_THRESHOLD = 7.2

# TLV probing re-reads a bounded number of members per family: each
# probe is a full walk over the sample bytes, so probing every member
# multiplies the IO budget; probing fewer than 3 cannot distinguish a
# per-file coincidence from a family property.
TLV_SAMPLE_CAP = 8
# Minimum records for a walk to count: 1-2 records fit almost any
# random file by luck. Cap bounds the walk on crafted samples whose
# length fields describe millions of empty records.
TLV_MIN_RECORDS = 3
TLV_MAX_RECORDS = 4096
# A successful walk must land within this many bytes of EOF: exact-EOF
# only would reject legitimate padded formats; a large slack lets a
# walk that explains half the file claim success.
TLV_TAIL_SLACK = 3

# Seed min-set budget. A larger copy budget duplicates the corpus into
# the run dir (the run dir gets shared/archived); smaller budgets drop
# coverage of large size classes. 8 MiB / 128 files carries the
# representative envelope set for any header-profiled family.
DEFAULT_SEED_BUDGET_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_SEED_FILES = 128

# Dictionary entry cap under the 1 MiB audit_dict convention cap: AFL
# slows badly past a few thousand tokens, and enum-cardinality
# flooding (a hostile corpus fabricating hundreds of "enum" values)
# must not bloat the dictionary; too few entries would drop real magic
# tokens on multi-family corpora.
DEFAULT_MAX_DICT_ENTRIES = 512

# Directory-walk entry budget, counting FILES AND DIRECTORIES (an
# empty-directory flood is as cheap to plant as a file flood). Without
# it a hostile drop directory with millions of entries makes the
# enumeration itself the DoS; a lower cap would under-count
# `samples_seen` on large legitimate corpora. 50k is ~25x the sample
# cap — enough to see and honestly report a much larger corpus.
# Residual (inherent to os.walk/scandir): one directory's listing is
# materialised at a time before the budget can bite — the cap bounds
# retention and descent, not the kernel's per-listing allocation.
WALK_ENTRY_CAP = 50_000

# Corpus-tier confidence ceiling: byte statistics over a corpus that
# may itself be attacker-written are never proof, so NO reported
# confidence (family or per-field) reaches 1.0. Raising it toward 1.0
# would let a profile fact read as verified; lowering it would
# compress the useful ranking range.
_CONFIDENCE_CEILING = 0.95

# Skip-record example bound: the summary keeps full COUNTS, but only
# this many per-file skip examples — unbounded example lists are their
# own flood channel on capped runs.
_MAX_SKIP_EXAMPLES = 64

# Escaped-filename render bound: long hostile names must not flood
# reports (and any LLM later reading them); shorter bounds would
# cripple legitimate nested sample paths.
_NAME_RENDER_MAX = 160

# Name-template render bound: templates collapse runs, so anything
# longer is pathological; unbounded templates would let a crafted
# filename with thousands of class alternations bloat every family key.
_TEMPLATE_MAX = 64

# Per-family list bounds in the artifact (readability + flood
# resistance; the counts always carry the true totals).
_MAX_TEMPLATES_PER_FAMILY = 8
_MAX_SIZE_FIELD_CANDIDATES = 8
_MAX_ENUM_VALUES_RENDERED = ENUM_MAX_CARDINALITY

_READ_CHUNK = 64 * 1024

# Literal separators preserved by the fixed template language. A
# character outside the separator set and outside [A-Za-z0-9] maps to
# the opaque class — never interpreted, never compiled.
_TEMPLATE_SEPARATORS = frozenset(".-_ +~()[]")


@dataclass(frozen=True)
class CorpusProfileOptions:
    """Options for one corpus-profiling pass."""

    samples_dir: Path
    out_dir: Path
    family_glob: str | None = None
    max_samples: int = DEFAULT_MAX_SAMPLES
    max_bytes_per_sample: int = DEFAULT_MAX_BYTES_PER_SAMPLE
    total_byte_budget: int = DEFAULT_TOTAL_BYTE_BUDGET
    header_window: int = DEFAULT_HEADER_WINDOW
    seed_budget_bytes: int = DEFAULT_SEED_BUDGET_BYTES
    max_seed_files: int = DEFAULT_MAX_SEED_FILES
    max_dict_entries: int = DEFAULT_MAX_DICT_ENTRIES


@dataclass
class _Sample:
    rel_name: str
    path: Path
    size: int
    header: bytes
    entropy_header: float | None
    entropy_body: float | None
    truncated_read: bool


def _escaped_name(rel_name: str) -> str:
    """Escape-at-capture for attacker-chosen sample names.

    Every artifact/report slot that carries a sample filename goes
    through this: control bytes become inert ``\\xHH`` escapes and the
    length is bounded with an explicit elision marker.
    """
    return sanitise_for_terminal(rel_name, max_len=_NAME_RENDER_MAX)


def _name_template(name: str) -> str:
    """Fixed-template-language name schema (character-class runs +
    literal separators).

    NEVER a regex compiled from the attacker-controlled filename — a
    crafted name must not become an executable pattern (ReDoS /
    injection primitive). ``a`` = ASCII letter run, ``9`` = digit run,
    ``?`` = any other byte run; separators pass through literally.
    Shared vocabulary with the planned tree-triage data-family census.
    """
    out: list[str] = []
    prev = ""
    for ch in name:
        if ch in _TEMPLATE_SEPARATORS:
            out.append(ch)
            prev = ""
            continue
        if ch.isascii() and ch.isalpha():
            cls = "a"
        elif ch.isascii() and ch.isdigit():
            cls = "9"
        else:
            cls = "?"
        if cls != prev:
            out.append(cls)
        prev = cls
        if len(out) >= _TEMPLATE_MAX:
            break
    return "".join(out[:_TEMPLATE_MAX])


def _safe_extension(name: str) -> str:
    """Charset-validated extension for the family key.

    Only ``[a-z0-9]{1,8}`` extensions are embedded literally (safe by
    validation); anything else collapses to ``other`` so hostile bytes
    never ride the key. The raw (escaped) name still appears in the
    per-sample records.
    """
    suffix = Path(name).suffix.lower()
    if not suffix.startswith("."):
        return "noext"
    body = suffix[1:]
    if 1 <= len(body) <= 8 and all(c.isascii() and (c.isalnum() and not c.isupper()) for c in body):
        return body
    return "other"


def _size_class(size: int) -> int:
    """Log2 size bucket (exponent). Sizes 0 and 1 share bucket 0."""
    return max(size, 1).bit_length() - 1


def _conf(value: float) -> float:
    """Clamp a confidence to the corpus-tier ceiling and round."""
    return round(min(value, _CONFIDENCE_CEILING), 3)


def _shannon_entropy(counts: Counter[int], total: int) -> float | None:
    if total <= 0:
        return None
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _open_regular_nofollow(path: Path) -> int | None:
    """Hardened open for files in a hostile directory.

    Pre-open lstat refuses non-regular entries (a device node's open
    has side effects, a FIFO blocks), O_NOFOLLOW + O_NONBLOCK closes
    the swap-to-symlink/FIFO race, and a post-open fstat re-verifies
    the file the descriptor actually landed on. O_NONBLOCK on a
    regular file does not affect reads.
    """
    try:
        pre = os.lstat(path)
        if not stat_module.S_ISREG(pre.st_mode):
            return None
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        post = os.fstat(fd)
        if not stat_module.S_ISREG(post.st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    return fd


def _bounded_read(path: Path, cap: int) -> bytes | None:
    """Read at most ``cap`` bytes of a regular file; None on refusal."""
    fd = _open_regular_nofollow(path)
    if fd is None:
        return None
    chunks: list[bytes] = []
    remaining = cap
    try:
        while remaining > 0:
            chunk = os.read(fd, min(_READ_CHUNK, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    return b"".join(chunks)


def _iter_sample_paths(samples_dir: Path) -> Iterator[tuple[str, Path | None, bool]]:
    """Deterministic streaming walk: sorted, symlink-free, entry-capped.

    Yields ``(rel_posix, path, walk_truncated)``. Directories count
    toward the entry budget too (an empty-directory flood must not
    bypass it); on exhaustion, descent is pruned and a final
    ``("", None, True)`` sentinel is yielded.
    """
    budget = WALK_ENTRY_CAP
    for dirpath, dirnames, filenames in os.walk(samples_dir, followlinks=False):
        budget -= 1  # the directory itself is an entry
        dirnames[:] = sorted(
            d for d in dirnames
            if not (Path(dirpath) / d).is_symlink()
        )
        if budget <= 0:
            dirnames[:] = []
            yield "", None, True
            return
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            try:
                rel = path.relative_to(samples_dir).as_posix()
            except ValueError:
                continue
            budget -= 1
            if budget <= 0:
                dirnames[:] = []
                yield rel, path, True
                return
            yield rel, path, False


def _collect_samples(
    options: CorpusProfileOptions,
) -> tuple[list[_Sample], int, list[dict[str, Any]], list[str], int]:
    """Streaming bounded collection pass.

    Returns (samples, skipped_count, skip-examples, caps_hit,
    samples_seen). Every drop is counted (bounded examples carry the
    reasons) — the profile never hides how much of the corpus it
    actually saw.
    """
    samples: list[_Sample] = []
    skipped: list[dict[str, Any]] = []
    skipped_count = 0
    caps_hit: list[str] = []
    budget = options.total_byte_budget
    seen = 0

    def _skip(rel: str, reason: str) -> None:
        nonlocal skipped_count
        skipped_count += 1
        if len(skipped) < _MAX_SKIP_EXAMPLES:
            skipped.append({"name": _escaped_name(rel), "reason": reason})

    for rel, path, walk_truncated in _iter_sample_paths(options.samples_dir):
        if walk_truncated:
            caps_hit.append("walk_entry_cap")
        if path is None:  # budget-exhaustion sentinel, no file attached
            continue
        seen += 1
        if options.family_glob and not fnmatch.fnmatch(rel, options.family_glob):
            continue
        if len(samples) >= options.max_samples:
            caps_hit.append("max_samples")
            _skip(rel, "sample-count cap")
            continue
        if budget <= 0:
            caps_hit.append("total_byte_budget")
            _skip(rel, "total byte budget exhausted")
            continue

        fd = _open_regular_nofollow(path)
        if fd is None:
            _skip(rel, "not a readable regular file")
            continue
        try:
            size = os.fstat(fd).st_size
            read_cap = min(options.max_bytes_per_sample, budget)
            header = b""
            header_counts: Counter[int] = Counter()
            body_counts: Counter[int] = Counter()
            read_total = 0
            failed = False
            while read_total < read_cap:
                try:
                    chunk = os.read(fd, min(_READ_CHUNK, read_cap - read_total))
                except OSError:
                    failed = True
                    break
                if not chunk:
                    break
                if len(header) < options.header_window:
                    take = options.header_window - len(header)
                    header += chunk[:take]
                    header_counts.update(chunk[:take])
                    body_counts.update(chunk[take:])
                else:
                    body_counts.update(chunk)
                read_total += len(chunk)
        finally:
            os.close(fd)
        if failed:
            _skip(rel, "read error")
            continue

        budget -= read_total
        body_total = read_total - len(header)
        samples.append(_Sample(
            rel_name=rel,
            path=path,
            size=size,
            header=header,
            entropy_header=_shannon_entropy(header_counts, len(header)),
            entropy_body=_shannon_entropy(body_counts, body_total),
            truncated_read=read_total >= read_cap and size > read_total,
        ))
    return samples, skipped_count, skipped, sorted(set(caps_hit)), seen


def _magic4(sample: _Sample) -> str:
    return sample.header[:4].hex() if len(sample.header) >= 4 else "short"


def _group_families(samples: list[_Sample]) -> tuple[dict[str, list[_Sample]], list[dict[str, Any]]]:
    """Group by (validated extension, name template), splitting by
    leading-4-byte magic only when the magic is shared evidence.

    A headerless format's first bytes are payload — splitting every
    (ext, template) group by them fragments the family into
    singletons and blinds all the per-family statistics. The magic
    component therefore only splits a group when at least two
    distinct 4-byte prefixes EACH have MIN_OFFSET_OBSERVATIONS
    members (a genuinely mixed directory); otherwise the group stays
    whole and per-offset constancy recovers whatever magic exists.

    Size class is deliberately NOT part of the key: size-field
    discovery needs size variance INSIDE one family; keying on size
    class would split every family into trivially-uniform buckets and
    blind the file_size - value cross-check.
    """
    prelim: dict[str, list[_Sample]] = {}
    for sample in samples:
        name = Path(sample.rel_name).name
        prelim.setdefault(
            f"{_safe_extension(name)}|{_name_template(name)}", []
        ).append(sample)

    grouped: dict[str, list[_Sample]] = {}
    for base_key, members in prelim.items():
        magic_counts = Counter(_magic4(s) for s in members)
        strong = {
            magic for magic, count in magic_counts.items()
            if count >= MIN_OFFSET_OBSERVATIONS
        }
        if len(strong) >= 2:
            for sample in members:
                magic = _magic4(sample)
                bucket = magic if magic in strong else "mixed"
                grouped.setdefault(f"{bucket}|{base_key}", []).append(sample)
        else:
            magic = next(iter(magic_counts)) if len(magic_counts) == 1 else "mixed"
            grouped[f"{magic}|{base_key}"] = members
    ordered = sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    kept = dict(ordered[:MAX_FAMILIES])
    # Example list bounded like the skip examples — an overflow of
    # thousands of noise families must not flood the artifact; the
    # count always carries the true total.
    overflow = {
        "count": max(0, len(ordered) - MAX_FAMILIES),
        "examples": [
            {"key_escaped": _escaped_name(key), "sample_count": len(members)}
            for key, members in ordered[MAX_FAMILIES:MAX_FAMILIES + _MAX_SKIP_EXAMPLES]
        ],
    }
    return kept, overflow


def _offset_fields(members: list[_Sample], window: int) -> list[dict[str, Any]]:
    """Per-offset statistics folded into field rows.

    Contiguous constant offsets merge into one field; enum-candidate
    and variable offsets are reported per offset (enums) or as merged
    spans (variable). Confidence is the observation coverage — the
    fraction of family members long enough to have the offset at all.
    """
    n = len(members)
    counters: list[Counter[bytes]] = [Counter() for _ in range(window)]
    coverage = [0] * window
    for sample in members:
        header = sample.header
        for offset in range(min(len(header), window)):
            counters[offset][header[offset:offset + 1]] += 1
            coverage[offset] += 1

    kinds: list[str] = []
    for offset in range(window):
        distinct = len(counters[offset])
        if coverage[offset] < MIN_OFFSET_OBSERVATIONS:
            kinds.append("unobserved")
        elif distinct == 1:
            kinds.append("constant")
        elif (
            distinct <= ENUM_MAX_CARDINALITY
            # Observation floor (see ENUM_MIN_VALUE_COUNT): an enum
            # claim needs repetition evidence, not mere variation.
            and distinct <= coverage[offset] // 2
            and min(counters[offset].values()) >= ENUM_MIN_VALUE_COUNT
        ):
            kinds.append("enum_candidate")
        else:
            kinds.append("variable")

    fields: list[dict[str, Any]] = []
    offset = 0
    while offset < window:
        kind = kinds[offset]
        if kind == "unobserved":
            offset += 1
            continue
        if kind == "enum_candidate":
            values = counters[offset].most_common(_MAX_ENUM_VALUES_RENDERED)
            fields.append({
                "offset": offset,
                "length": 1,
                "kind": "enum_candidate",
                # Sample bytes rendered as hex only — hex is inert in
                # JSON, markdown, and terminals.
                "values": [
                    {"value_hex": value.hex(), "count": count}
                    for value, count in sorted(values, key=lambda vc: vc[0])
                ],
                "cardinality": len(counters[offset]),
                "confidence": _conf(coverage[offset] / n),
                "evidence": f"{coverage[offset]}/{n} members observed",
                "derived_from_target": True,
            })
            offset += 1
            continue
        end = offset
        while end + 1 < window and kinds[end + 1] == kind:
            end += 1
        span = end - offset + 1
        row: dict[str, Any] = {
            "offset": offset,
            "length": span,
            "kind": kind,
            "confidence": _conf(min(coverage[offset:end + 1]) / n),
            "evidence": f"{min(coverage[offset:end + 1])}/{n} members observed",
            "derived_from_target": True,
        }
        if kind == "constant":
            run = b"".join(next(iter(counters[o])) for o in range(offset, end + 1))
            row["value_hex"] = run.hex()
            classification = "magic" if offset == 0 else "reserved_or_fixed"
            row["classification"] = classification
        fields.append(row)
        offset = end + 1
    return fields


def _size_field_candidates(
    members: list[_Sample], window: int,
) -> tuple[list[dict[str, Any]], str]:
    """u16/u32 offsets where ``file_size - value`` is one modal k.

    Honesty guards:
    - a candidate whose observed field VALUE never varies among the
      delta-matching members cannot evidence a varying size — on a
      near-uniform corpus (e.g. 95% of members one size) every
      constant-byte offset would otherwise mint a full-confidence
      candidate. Such candidates are kept visible but flagged
      ``value_varies: false`` (which subsumes the all-sizes-equal
      case) with confidence scaled down, never presented as proven;
    - the endianness vote counts only value-varying candidates —
      vacuous candidates must not fabricate a vote;
    - one candidate per (offset, endianness, delta) — a u32 field
      whose high half is zero also matches as u16 at the same offset,
      and listing both double-counts one piece of evidence (widest
      wins).
    """
    candidates: list[dict[str, Any]] = []
    le_weight = 0.0
    be_weight = 0.0
    for width in (2, 4):
        for endian in ("little", "big"):
            for offset in range(0, window - width + 1):
                deltas: Counter[int] = Counter()
                considered = 0
                for sample in members:
                    if len(sample.header) < offset + width:
                        continue
                    value = int.from_bytes(sample.header[offset:offset + width], endian)
                    delta = sample.size - value
                    considered += 1
                    if SIZE_FIELD_DELTA_MIN <= delta <= SIZE_FIELD_DELTA_MAX:
                        deltas[delta] += 1
                if considered < SIZE_FIELD_MIN_SAMPLES or not deltas:
                    continue
                modal_delta, modal_count = deltas.most_common(1)[0]
                agreement = modal_count / considered
                if agreement < SIZE_FIELD_MIN_AGREEMENT:
                    continue
                matching_values = {
                    int.from_bytes(sample.header[offset:offset + width], endian)
                    for sample in members
                    if len(sample.header) >= offset + width
                    and sample.size - int.from_bytes(
                        sample.header[offset:offset + width], endian) == modal_delta
                }
                value_varies = len(matching_values) > 1
                confidence = _conf(agreement * (1.0 if value_varies else 0.25))
                evidence = (
                    f"file_size - value == {modal_delta} for "
                    f"{modal_count}/{considered} members"
                )
                if not value_varies:
                    evidence += (
                        "; field value constant across matching members"
                        " — cross-check vacuous"
                    )
                candidates.append({
                    "offset": offset,
                    "width": width,
                    "endianness": "le" if endian == "little" else "be",
                    "delta_k": modal_delta,
                    "agreement": round(agreement, 3),
                    "value_varies": value_varies,
                    "confidence": confidence,
                    "evidence": evidence,
                    "derived_from_target": True,
                })

    # Dedupe: widest evidence wins per (offset, endianness, delta).
    best: dict[tuple[int, str, int], dict[str, Any]] = {}
    for cand in candidates:
        key = (cand["offset"], cand["endianness"], cand["delta_k"])
        kept = best.get(key)
        if kept is None or (cand["value_varies"], cand["width"], cand["agreement"]) > (
            kept["value_varies"], kept["width"], kept["agreement"]
        ):
            best[key] = cand
    deduped = list(best.values())
    for cand in deduped:
        if cand["value_varies"]:
            if cand["endianness"] == "le":
                le_weight += cand["confidence"]
            else:
                be_weight += cand["confidence"]
    deduped.sort(key=lambda c: (-c["confidence"], c["offset"], c["width"]))
    if le_weight > be_weight:
        vote = "le"
    elif be_weight > le_weight:
        vote = "be"
    else:
        vote = "unknown"
    return deduped[:_MAX_SIZE_FIELD_CANDIDATES], vote


def _entropy_profile(members: list[_Sample], window: int) -> dict[str, Any]:
    header_vals = [s.entropy_header for s in members if s.entropy_header is not None]
    body_vals = [s.entropy_body for s in members if s.entropy_body is not None]
    header_mean = round(sum(header_vals) / len(header_vals), 3) if header_vals else None
    body_mean = round(sum(body_vals) / len(body_vals), 3) if body_vals else None
    if body_mean is None:
        classification = "no_body"
        note = f"members fit inside the {window}-byte header window"
    elif body_mean >= HIGH_ENTROPY_THRESHOLD:
        classification = "high_entropy_body"
        note = (
            "body is compressed or encrypted — only the envelope "
            "(header fields) is meaningfully fuzzable from this corpus"
        )
    else:
        classification = "structured_body"
        note = "body entropy is consistent with structured plaintext data"
    return {
        "header_entropy_mean": header_mean,
        "body_entropy_mean": body_mean,
        "classification": classification,
        "note": note,
        "derived_from_target": True,
    }


# Record shapes probed. A bare u8-length stream with NO type byte
# (0,1) is excluded: it matches large classes of non-TLV byte noise
# (any stream whose bytes happen to chain to EOF — constant-fill
# bodies literally self-describe under it), and real one-byte-length
# TLV formats carry a type byte. Adding shapes broadens recall but
# every extra shape is another coincidence channel on small corpora.
_TLV_SHAPES: tuple[tuple[int, int, str, bool], ...] = tuple(
    (type_size, len_size, endian, includes_header)
    for type_size in (0, 1, 2, 4)
    for len_size in (1, 2, 4)
    if not (type_size == 0 and len_size == 1)
    for endian in (("little",) if len_size == 1 else ("little", "big"))
    for includes_header in (False, True)
)


def _tlv_walk(data: bytes, start: int, shape: tuple[int, int, str, bool]) -> tuple[int, int]:
    """Walk one record shape over the sample bytes.

    Returns (record_count, distinct_length_count) on a successful walk
    to (near-)EOF, else (0, 0).
    """
    type_size, len_size, endian, includes_header = shape
    header_size = type_size + len_size
    pos = start
    records = 0
    lengths: set[int] = set()
    n = len(data)
    while pos + header_size <= n and records < TLV_MAX_RECORDS:
        length = int.from_bytes(data[pos + type_size:pos + header_size], endian)
        value_len = (length - header_size) if includes_header else length
        if value_len < 0:
            return 0, 0
        total = header_size + value_len
        if total <= 0:  # zero-advance would loop forever
            return 0, 0
        if pos + total > n:
            break
        lengths.add(length)
        pos += total
        records += 1
    if records >= TLV_MIN_RECORDS and n - pos <= TLV_TAIL_SLACK:
        return records, len(lengths)
    return 0, 0


def _tlv_profile(
    members: list[_Sample],
    options: CorpusProfileOptions,
    start_hints: list[int],
) -> dict[str, Any]:
    """Repeating length-prefixed record detection (bounded re-read).

    A shape only scores when it walks >= TLV_MIN_RECORDS records to
    (near-)EOF AND sees enough distinct record lengths — an all-zero
    or constant-length file trivially satisfies almost any shape and
    must not read as TLV evidence.

    ``start_hints`` lets the caller add header-derived probe starts
    (end of the leading constant run; the byte after a size-field
    candidate) — the common [magic][total-size][records...] layout is
    invisible from start 0 because the header is not a record.
    """
    starts = sorted({0, *(h for h in start_hints if 0 < h <= 64)})
    probe_set = [
        s for s in sorted(members, key=lambda s: s.size)[:TLV_SAMPLE_CAP]
        if s.size <= options.max_bytes_per_sample
    ]
    probed = 0
    shape_hits: Counter[tuple[int, tuple[int, int, str, bool]]] = Counter()
    for sample in probe_set:
        data = _bounded_read(sample.path, options.max_bytes_per_sample)
        if data is None or not data:
            continue
        probed += 1
        for start in starts:
            for shape in _TLV_SHAPES:
                records, distinct = _tlv_walk(data, start, shape)
                # u8-length shapes are the easiest to satisfy by
                # coincidence, so they need more length diversity
                # (3+) than the wider shapes (2+); requiring 3+ of
                # everything would miss legitimate two-record-kind
                # formats with u16/u32 lengths. Below 3 probed
                # samples the per-sample bar rises to 3+ for every
                # shape: a "1.0" earned from two files must carry
                # more in-file evidence than the corpus can supply.
                min_distinct = 3 if (shape[1] == 1 or len(probe_set) < 3) else 2
                if records and distinct >= min_distinct:
                    shape_hits[(start, shape)] += 1
    if not probed or not shape_hits:
        return {
            "likelihood": 0.0,
            "samples_probed": probed,
            "shape": None,
        }
    (start, shape), hits = shape_hits.most_common(1)[0]
    type_size, len_size, endian, includes_header = shape
    return {
        "likelihood": round(hits / probed, 3),
        "samples_probed": probed,
        "shape": {
            "start_offset": start,
            "type_size": type_size,
            "length_size": len_size,
            "endianness": "le" if endian == "little" else "be",
            "length_includes_header": includes_header,
        },
    }


def _select_seed_minset(
    families: dict[str, dict[str, Any]],
    members_by_family: dict[str, list[_Sample]],
    options: CorpusProfileOptions,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Greedy coverage pick: observed enum values x size classes.

    Smallest-first inside each family (more coverage per budget byte);
    a sample is kept when it contributes an unseen size class or an
    unseen (enum offset, value) pair, and each family always
    contributes at least its smallest member. Byte-budget enforcement
    lives in the WRITER against the bytes actually read at copy time —
    the collection-time sizes used here are stale by construction
    (hostile files can grow between stat and copy), so this pass only
    applies the file-count cap.
    """
    picks: list[dict[str, Any]] = []
    caps_hit: list[str] = []
    for family_id in sorted(families, key=lambda fid: families[fid]["sample_count"], reverse=True):
        profile = families[family_id]
        enum_offsets = [
            f["offset"] for f in profile["fields"] if f["kind"] == "enum_candidate"
        ]
        seen_classes: set[int] = set()
        seen_enum: set[tuple[int, bytes]] = set()
        first = True
        for sample in sorted(members_by_family[profile["key"]], key=lambda s: s.size):
            contributes = first
            size_class = _size_class(sample.size)
            if size_class not in seen_classes:
                contributes = True
            new_pairs = [
                (offset, sample.header[offset:offset + 1])
                for offset in enum_offsets
                if len(sample.header) > offset
                and (offset, sample.header[offset:offset + 1]) not in seen_enum
            ]
            if new_pairs:
                contributes = True
            if not contributes:
                continue
            if len(picks) >= options.max_seed_files:
                caps_hit.append("max_seed_files")
                break
            first = False
            seen_classes.add(size_class)
            seen_enum.update(new_pairs)
            picks.append({
                "family": family_id,
                "sample": sample,
                "covers": {
                    "size_class": size_class,
                    "enum_values": [
                        {"offset": offset, "value_hex": value.hex()}
                        for offset, value in new_pairs
                    ],
                },
            })
        if len(picks) >= options.max_seed_files:
            break
    return picks, sorted(set(caps_hit))


def _write_seed_bytes(dest: Path, data: bytes) -> str | None:
    """Exclusive, symlink-refusing seed write. Returns a skip reason
    on refusal, None on success.

    ``open_exclusive_artifact`` (O_CREAT|O_EXCL|O_NOFOLLOW): the reset
    phase owns every pre-existing name, so anything occupying the
    destination at write time — e.g. a concurrently planted symlink
    aimed at a victim file — makes the write fail closed with a
    manifest record instead of following/truncating the target (plain
    ``write_bytes`` opens with O_TRUNC and follows symlinks).
    """
    try:
        fd = open_exclusive_artifact(dest)
    except OSError as exc:
        return f"destination not exclusively creatable: {type(exc).__name__}"
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    except OSError as exc:
        return f"write failed: {type(exc).__name__}"
    finally:
        os.close(fd)
    return None


def _reset_seed_dir(seed_dir: Path, manifest_path: Path) -> None:
    """Provenance-gated reset (seed_corpus's idiom), hardened:

    - only a directory a previous run's manifest proves is ours is
      cleared; anything else is refused loudly rather than deleted;
    - inside an owned directory, symlinks are removed like files
      (skipping them would leave a planted link occupying a
      deterministic destination name);
    - a subdirectory is refused loudly: this writer only ever emits
      flat files, so a directory is foreign by construction and
      removing it recursively could destroy operator data.
    """
    if not seed_dir.exists():
        return
    ours = False
    if manifest_path.is_file():
        previous = load_json(manifest_path, max_bytes=8 * 1024 * 1024)
        ours = isinstance(previous, dict) and previous.get("source") == SEED_MANIFEST_SOURCE
    if not ours and any(seed_dir.iterdir()):
        msg = (
            f"refusing to reset {seed_dir}: no manifest proves its "
            "content came from a previous corpus-profile run"
        )
        raise ValueError(msg)
    for entry in seed_dir.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            msg = (
                f"refusing to reset {seed_dir}: "
                f"{_escaped_name(entry.name)!r} is a directory — this "
                "writer only emits flat seed files, so it was not "
                "written by a previous corpus-profile run"
            )
            raise ValueError(msg)
        entry.unlink()


def _write_seed_minset(
    picks: list[dict[str, Any]],
    options: CorpusProfileOptions,
) -> tuple[dict[str, Any], list[str]]:
    """COPY the picked samples under RAPTOR-generated names.

    - Copies, never hard-links (module docstring records why).
    - Destination names are RAPTOR-generated — an attacker-chosen
      sample filename never lands in the run dir.
    - Provenance-gated reset + exclusive no-follow writes (see
      :func:`_reset_seed_dir` / :func:`_write_seed_bytes`).
    - Grow-guard AND byte budget enforced HERE against the bytes
      actually read: the selection pass's sizes are stale by
      construction, and a hostile file grown between the collection
      stat and this copy must neither ship unprofiled bytes nor blow
      the run-dir budget. Any growth drops the seed (the bytes are no
      longer what was profiled); every drop carries a manifest record.
    """
    seed_dir = options.out_dir / SEED_DIR_NAME
    manifest_path = seed_dir / "manifest.json"
    _reset_seed_dir(seed_dir, manifest_path)
    seed_dir.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    caps_hit: list[str] = []
    counters: Counter[str] = Counter()
    remaining = options.seed_budget_bytes
    for pick in picks:
        sample: _Sample = pick["sample"]

        def _skip(reason: str, *, rel_name: str = sample.rel_name) -> None:
            entries.append({
                "source": _escaped_name(rel_name),
                "derived_from_target": True,
                "skipped": reason,
            })

        # Read exactly one byte past the collection-time size: any
        # growth is detectable without paying for the grown bytes.
        data = _bounded_read(
            sample.path, min(options.max_bytes_per_sample, sample.size + 1),
        )
        if data is None:
            _skip("unreadable at copy time")
            continue
        if len(data) > sample.size:
            caps_hit.append("seed_source_grew")
            _skip("grew since collection — bytes no longer match the profile")
            continue
        if len(data) > remaining:
            caps_hit.append("seed_budget_bytes")
            _skip("seed byte budget exhausted")
            continue
        counters[pick["family"]] += 1
        dest = seed_dir / f"{pick['family']}-{counters[pick['family']]:03d}.bin"
        write_error = _write_seed_bytes(dest, data)
        if write_error is not None:
            _skip(write_error)
            continue
        remaining -= len(data)
        entries.append({
            "source": _escaped_name(sample.rel_name),
            "derived_from_target": True,
            "destination": dest.name,
            "size": len(data),
            "sha256": sha256_file(dest),
            "covers": pick["covers"],
        })
    manifest = {
        "source": SEED_MANIFEST_SOURCE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Seed bytes are copied from HOSTILE corpus samples "
            "(derived_from_target); consumers are fuzzers only — "
            "never parse, render, or execute these as trusted input."
        ),
        "seed_count": sum(1 for e in entries if "destination" in e),
        "seeds": entries,
    }
    save_json(manifest_path, manifest, sort_keys=True)
    return {
        "seed_dir": str(seed_dir),
        "seed_manifest": str(manifest_path),
        "seed_count": manifest["seed_count"],
    }, sorted(set(caps_hit))


def _dict_escape(data: bytes) -> str:
    """AFL dictionary value escaping (smt_seed's convention: printable
    ASCII passes, everything else — and quote/backslash — is \\xHH)."""
    out: list[str] = []
    for b in data:
        if 32 <= b <= 126 and b not in (0x22, 0x5C):
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _build_dictionary(
    families: dict[str, dict[str, Any]],
    max_entries: int,
) -> tuple[dict[str, str], list[str]]:
    """Magic + constant-run + enum tokens, entry-capped.

    Token NAMES are RAPTOR-generated ASCII; token VALUES are sample
    bytes escaped with the AFL convention. Enum flooding is bounded by
    the entry cap (and the emitted file by the 1 MiB convention cap).
    Two passes, magic/constant tokens FIRST across all families: one
    enum-rich family must not evict every other family's magic at the
    cap — a magic token is worth more to a fuzzer than the marginal
    enum value.
    """
    entries: dict[str, str] = {}
    caps_hit: list[str] = []

    def _add(name: str, value: bytes) -> None:
        if not value:
            return
        if len(entries) >= max_entries:
            caps_hit.append("max_dict_entries")
            return
        entries.setdefault(name, _dict_escape(value))

    for family_id in sorted(families):
        for fld in families[family_id]["fields"]:
            if fld["kind"] == "constant" and fld["length"] >= 2:
                value = bytes.fromhex(fld["value_hex"])[:8]
                label = "magic" if fld.get("classification") == "magic" else f"const_{fld['offset']}"
                _add(f"corpus_{family_id}_{label}", value)
    for family_id in sorted(families):
        for fld in families[family_id]["fields"]:
            if fld["kind"] == "enum_candidate":
                for idx, item in enumerate(fld["values"]):
                    _add(
                        f"corpus_{family_id}_enum_{fld['offset']}_{idx}",
                        bytes.fromhex(item["value_hex"]),
                    )
    return entries, sorted(set(caps_hit))


def _write_fuzz_dict(out_dir: Path, entries: dict[str, str]) -> tuple[str | None, list[str]]:
    """Merge tokens into the run's ``fuzz.dict`` (audit_dict handoff).

    Existing lines (audit-mined or SMT-witness tokens) are preserved,
    duplicates dropped, and the merged file is refused growth past the
    convention cap — an oversized fuzz.dict would make audit_dict's
    discovery reject the whole file, silently losing the other
    producers' tokens too.

    Degrade, never destroy: the run dir is shared, so a foreign
    fuzz.dict that is oversized, non-UTF-8, or unreadable is left
    byte-untouched and the merge is SKIPPED with a caps record —
    reading it unbounded would buffer attacker-sized bytes, and
    raising here would abort the run after seeds are written but
    before format-profile.json lands.
    """
    if not entries:
        return None, []
    target = out_dir / DICT_FILENAME
    existing: list[str] = []
    caps_hit: list[str] = []
    try:
        if target.is_file():
            if target.stat().st_size > MAX_DICT_BYTES:
                caps_hit.append("dict_merge_skipped_oversized")
                return None, caps_hit
            existing = target.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        caps_hit.append("dict_merge_failed")
        return None, caps_hit
    seen = set(existing)
    budget = MAX_DICT_BYTES - sum(len(line) + 1 for line in existing)
    added: list[str] = []
    for name, value in sorted(entries.items()):
        line = f'{name}="{value}"'
        if line in seen:
            continue
        if len(line) + 1 > budget:
            caps_hit.append("dict_byte_cap")
            break
        budget -= len(line) + 1
        added.append(line)
    if not added:
        return (str(target) if target.is_file() else None), caps_hit
    try:
        # Atomic read-merge-write commit: the dict lives in the same
        # reused, target-writable dir as the hardened seed writer —
        # the is_file() gate above follows symlinks and the plain
        # write_text would too; os.replace over a planted symlink
        # replaces the symlink itself, never follows it.
        write_text_atomically(
            target, "\n".join([*existing, *added]) + "\n")
    except OSError:
        caps_hit.append("dict_merge_failed")
        return None, caps_hit
    return str(target), caps_hit


def _render_markdown(profile: dict[str, Any]) -> str:
    """Operator report. Every sample-derived string goes through
    md_inline (escape + bound); byte values are hex-only."""
    lines: list[str] = []
    summary = profile["summary"]
    lines.append("# Corpus Format Profile")
    lines.append("")
    lines.append(f"Samples dir: `{md_inline(profile['samples_dir'])}`")
    lines.append(
        f"Profiled {summary['samples_profiled']} of {summary['samples_seen']} "
        f"samples into {summary['family_count']} family(s)."
    )
    lines.append("")
    lines.append(
        "> Corpus-tier evidence: every fact below is a byte statistic "
        "over samples that may themselves be attacker-written. "
        "Fields need parser corroboration before they are trusted "
        "format facts."
    )
    lines.append("")
    for family in profile["families"]:
        lines.append(
            f"## Family {md_inline(family['id'])} "
            f"({family['sample_count']} samples)"
        )
        lines.append("")
        lines.append(f"- Key: `{md_inline(family['key'])}`")
        templates = ", ".join(f"`{md_inline(t)}`" for t in family["name_templates"])
        lines.append(f"- Name templates: {templates or '(none)'}")
        lines.append(
            f"- Sizes: {family['size_min']}-{family['size_max']} bytes, "
            f"{len(family['size_classes'])} size class(es)"
        )
        if family["truncated_reads"]:
            lines.append(
                f"- {family['truncated_reads']} member(s) exceeded the "
                "per-sample read cap — entropy/TLV statistics cover "
                "only their read prefix"
            )
        entropy = family["entropy"]
        # classification/note are RAPTOR-authored constants, not
        # target text — no escaping slot needed.
        lines.append(
            f"- Entropy: header {entropy['header_entropy_mean']}, "
            f"body {entropy['body_entropy_mean']} — "
            f"{entropy['classification']} ({entropy['note']})"
        )
        lines.append(f"- Endianness vote: {family['endianness_vote']}")
        tlv = family["tlv"]
        if tlv["shape"]:
            shape = tlv["shape"]
            lines.append(
                f"- TLV likelihood: {tlv['likelihood']} "
                f"(type={shape['type_size']}B len={shape['length_size']}B "
                f"{shape['endianness']} start={shape['start_offset']} "
                f"over {tlv['samples_probed']} probed)"
            )
        else:
            lines.append(f"- TLV likelihood: {tlv['likelihood']} ({tlv['samples_probed']} probed)")
        lines.append("")
        lines.append("| Offset | Len | Kind | Value | Confidence | Evidence |")
        lines.append("|---|---|---|---|---|---|")
        # The Value cell is RAPTOR-composed from hex digits (the inert
        # form for sample bytes) with deliberate backtick spans, which
        # md_inline would entity-escape — it stays composed. The plain
        # cells go through md_inline like every other writer's cells.
        for fld in family["fields"]:
            if fld["kind"] == "constant":
                value = f"`{fld['value_hex']}` ({fld['classification']})"
            elif fld["kind"] == "enum_candidate":
                shown = ", ".join(f"`{v['value_hex']}`" for v in fld["values"][:6])
                value = f"{fld['cardinality']} values: {shown}"
            else:
                value = "-"
            lines.append(
                f"| {fld['offset']} | {fld['length']} | {md_inline(fld['kind'])} "
                f"| {value} | {md_inline(fld['confidence'])} "
                f"| {md_inline(fld['evidence'])} |"
            )
        if family["size_field_candidates"]:
            lines.append("")
            lines.append("Size-field candidates:")
            for cand in family["size_field_candidates"]:
                lines.append(
                    f"- u{cand['width'] * 8}{cand['endianness']} at offset "
                    f"{cand['offset']}: file_size - value == {cand['delta_k']} "
                    f"(agreement {cand['agreement']}, confidence "
                    f"{md_inline(cand['confidence'])}"
                    + ("" if cand["value_varies"] else "; field value constant — vacuous")
                    + ")"
                )
        lines.append("")
    artifacts = profile["artifacts"]
    lines.append("## Artifacts")
    lines.append("")
    lines.append(f"- Profile JSON: `{md_inline(artifacts['profile_json'])}`")
    lines.append(f"- Seed min-set: {artifacts['seed_count']} file(s) in `{md_inline(artifacts['seed_dir'])}`")
    if artifacts["fuzz_dict"]:
        lines.append(f"- Dictionary: `{md_inline(artifacts['fuzz_dict'])}` ({artifacts['dict_entries']} tokens)")
    else:
        lines.append("- Dictionary: (no tokens recovered)")
    if summary["caps_hit"]:
        lines.append(f"- Caps hit: {', '.join(summary['caps_hit'])}")
    lines.append("")
    return "\n".join(lines)


def profile_corpus(options: CorpusProfileOptions) -> dict[str, Any]:
    """Profile a sample corpus; write artifacts; return the profile.

    Writes ``format-profile.json``, ``format-profile.md``, the seed
    min-set under ``corpus-seeds/``, and merges dictionary tokens into
    the run's ``fuzz.dict`` — all under the run-artifact lock (the
    fuzz.dict merge is a read-modify-write against a file other
    producers also append to).
    """
    samples_dir = Path(options.samples_dir).resolve()
    if not samples_dir.is_dir():
        msg = f"samples directory not found: {options.samples_dir}"
        raise FileNotFoundError(msg)
    out_dir = Path(options.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    options = dataclasses.replace(options, samples_dir=samples_dir, out_dir=out_dir)

    samples, skipped_count, skip_examples, caps_hit, seen = _collect_samples(options)
    grouped, overflow = _group_families(samples)
    if overflow["count"]:
        caps_hit = sorted({*caps_hit, "max_families"})

    families: dict[str, dict[str, Any]] = {}
    members_by_family: dict[str, list[_Sample]] = {}
    for idx, (key, members) in enumerate(
        sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])), start=1,
    ):
        family_id = f"F{idx:02d}"
        fields = _offset_fields(members, options.header_window)
        size_candidates, endian_vote = _size_field_candidates(members, options.header_window)
        # TLV probe-start hints: the modal size delta (records often
        # start where the header the delta accounts for ends), the
        # byte after the best size-field candidate, and the end of the
        # leading constant run — the common [magic][total-size]
        # [records...] layout is invisible from start 0.
        tlv_hints: list[int] = []
        if size_candidates:
            tlv_hints.append(size_candidates[0]["delta_k"])
            tlv_hints.append(size_candidates[0]["offset"] + size_candidates[0]["width"])
        if fields and fields[0]["offset"] == 0 and fields[0]["kind"] == "constant":
            tlv_hints.append(fields[0]["length"])
        template_counts = Counter(_name_template(Path(s.rel_name).name) for s in members)
        sizes = [s.size for s in members]
        truncated_reads = sum(1 for s in members if s.truncated_read)
        # Family confidence: observation depth. Statistics over a
        # handful of samples are directional at best; 30+ members is
        # where agreement ratios stop moving. Bounded to
        # [0.1, _CONFIDENCE_CEILING] — no corpus-tier confidence
        # (family or per-field) reaches 1.0 by construction.
        confidence = _conf(max(0.1, len(members) / 30))
        families[family_id] = {
            "id": family_id,
            "key": key,
            "sample_count": len(members),
            "name_templates": [t for t, _ in template_counts.most_common(_MAX_TEMPLATES_PER_FAMILY)],
            "samples": [
                {"name": _escaped_name(s.rel_name), "size": s.size,
                 "derived_from_target": True}
                for s in members
            ],
            "size_min": min(sizes),
            "size_max": max(sizes),
            "size_classes": sorted({_size_class(s) for s in sizes}),
            # Cap-truncated members: their entropy/TLV statistics
            # cover only the read prefix — the profile says so rather
            # than presenting prefix statistics as whole-file facts.
            "truncated_reads": truncated_reads,
            "fields": fields,
            "size_field_candidates": size_candidates,
            "endianness_vote": endian_vote,
            "entropy": _entropy_profile(members, options.header_window),
            "tlv": _tlv_profile(members, options, tlv_hints),
            "confidence": confidence,
            "corroboration": {
                "status": "uncorroborated",
                "note": (
                    "corpus-tier statistics only; the binary-side "
                    "format inference (autonomous corpus generator) is "
                    "the complementary witness for a future join"
                ),
            },
            "derived_from_target": True,
        }
        members_by_family[key] = members

    with run_artifacts_lock(out_dir):
        picks, seed_caps = _select_seed_minset(families, members_by_family, options)
        seed_info, seed_write_caps = _write_seed_minset(picks, options)
        dict_entries, dict_caps = _build_dictionary(families, options.max_dict_entries)
        dict_path, dict_write_caps = _write_fuzz_dict(out_dir, dict_entries)
        caps_hit = sorted(
            {*caps_hit, *seed_caps, *seed_write_caps, *dict_caps, *dict_write_caps},
        )

        profile: dict[str, Any] = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "samples_dir": str(samples_dir),
            "options": {
                "family_glob": options.family_glob,
                "max_samples": options.max_samples,
                "max_bytes_per_sample": options.max_bytes_per_sample,
                "total_byte_budget": options.total_byte_budget,
                "header_window": options.header_window,
                "seed_budget_bytes": options.seed_budget_bytes,
                "max_seed_files": options.max_seed_files,
                "max_dict_entries": options.max_dict_entries,
            },
            "provenance": {
                "tier": "corpus_statistic",
                "derived_from_target": True,
                "note": (
                    "Samples harvested from a target install may "
                    "themselves be attacker-written; every fact here is "
                    "a byte statistic over that corpus and stays "
                    "corpus-tier until parser corroboration."
                ),
            },
            "summary": {
                "samples_seen": seen,
                "samples_profiled": len(samples),
                "samples_skipped": skipped_count,
                "skipped": skip_examples,
                "family_count": len(families),
                "families_over_cap": overflow,
                "caps_hit": caps_hit,
            },
            "families": [families[fid] for fid in sorted(families)],
            "artifacts": {
                "profile_json": str(out_dir / PROFILE_JSON_NAME),
                "report": str(out_dir / PROFILE_REPORT_NAME),
                "seed_dir": seed_info["seed_dir"],
                "seed_manifest": seed_info["seed_manifest"],
                "seed_count": seed_info["seed_count"],
                "fuzz_dict": dict_path,
                "dict_entries": len(dict_entries),
            },
        }
        save_json(out_dir / PROFILE_JSON_NAME, profile, sort_keys=True)
        # Atomic like the save_json beside it (planted-symlink
        # defence at the predictable report name).
        write_text_atomically(
            out_dir / PROFILE_REPORT_NAME, _render_markdown(profile),
        )
    return profile


__all__ = [
    "CorpusProfileOptions",
    "PROFILE_JSON_NAME",
    "PROFILE_REPORT_NAME",
    "SEED_DIR_NAME",
    "profile_corpus",
]
