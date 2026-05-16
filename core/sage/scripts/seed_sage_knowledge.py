#!/usr/bin/env python3
"""
Seed RAPTOR institutional knowledge into SAGE.

Extracts hardcoded expert knowledge from Raptor's codebase and stores it
in SAGE for persistent, consensus-validated memory that improves over time.

Usage:
    python3 core/sage/scripts/seed_sage_knowledge.py [--sage-url http://localhost:8090] [--dry-run] [--force]

Requires:
    pip install sage-agent-sdk
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

try:
    from sage_sdk.async_client import AsyncSageClient
    from sage_sdk.auth import AgentIdentity
    from sage_sdk.models import MemoryType
except ImportError:
    print("ERROR: sage-agent-sdk not installed.")
    print("  pip install sage-agent-sdk")
    sys.exit(1)

from core.sage.scripts._common import async_memory_exists

# Parallelism cap — see register_agents.py for rationale.
_PROPOSE_CONCURRENCY = 8


# ─────────────────────────────────────────────────────────────────────────────
# Knowledge extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_primitives() -> list[dict]:
    """Extract exploitation primitives from primitives.py."""
    memories = []

    from packages.exploit_feasibility.primitives import (
        get_primitive_definitions,
        PrimitiveID,
        MitigationID,
    )

    primitives = get_primitive_definitions()
    for pid, prim in primitives.items():
        blocked = ", ".join(prim.blocked_by) if prim.blocked_by else "none"
        complicated = ", ".join(prim.complicated_by) if prim.complicated_by else "none"
        provides = ", ".join(prim.provides) if prim.provides else "none"
        requires = ", ".join(prim.requires) if prim.requires else "none"
        requires_any = ", ".join(prim.requires_any) if prim.requires_any else "none"

        content = (
            f"Exploitation primitive: {prim.name} — {prim.description}. "
            f"Type: {prim.primitive_type.value}. "
            f"Provides: {provides}. "
            f"Requires (all): {requires}. "
            f"Requires (any): {requires_any}. "
            f"Blocked by: {blocked}. "
            f"Complicated by: {complicated}. "
            f"Reliability: {prim.reliability}%. "
            f"Notes: {prim.notes}"
        )
        memories.append({
            "content": content,
            "domain": "raptor-primitives",
            "memory_type": "fact",
            "confidence": 0.95,
            "label": f"primitive:{prim.name}",
        })

    # Also extract mitigation IDs
    mitigations = []
    for mid in MitigationID:
        mitigations.append(f"{mid.name}: {mid.value}")
    mitigation_content = (
        "RAPTOR mitigation identifiers for exploit feasibility analysis: "
        + "; ".join(mitigations)
    )
    memories.append({
        "content": mitigation_content,
        "domain": "raptor-primitives",
        "memory_type": "fact",
        "confidence": 0.95,
        "label": "mitigations:all",
    })

    return memories


def extract_llm_prompts() -> list[dict]:
    """Extract LLM system prompts."""
    memories = []

    from packages.llm_analysis.prompts.analysis import ANALYSIS_SYSTEM_PROMPT
    from packages.llm_analysis.prompts.exploit import EXPLOIT_SYSTEM_PROMPT
    from packages.llm_analysis.prompts.patch import PATCH_SYSTEM_PROMPT

    for name, prompt in [
        ("analysis", ANALYSIS_SYSTEM_PROMPT),
        ("exploit", EXPLOIT_SYSTEM_PROMPT),
        ("patch", PATCH_SYSTEM_PROMPT),
    ]:
        content = f"RAPTOR {name} system prompt: {prompt.strip()}"
        memories.append({
            "content": content[:2000],  # Truncate for embedding quality
            "domain": "raptor-prompts",
            "memory_type": "fact",
            "confidence": 0.95,
            "label": f"prompt:{name}",
        })

    return memories


def extract_personas() -> list[dict]:
    """Extract expert persona definitions."""
    memories = []
    personas_dir = REPO_ROOT / "tiers" / "personas"

    if not personas_dir.exists():
        return memories

    for persona_file in sorted(personas_dir.glob("*.md")):
        if persona_file.name == "README.md":
            continue

        persona_name = persona_file.stem.replace("_", " ").replace("-", " ")
        # Cap before reading. Pre-fix `read_text()` was unbounded; a
        # legitimate persona is <50 KB, but a corrupted .md file or
        # an inadvertent log paste into the personas dir could be
        # tens of MB and we'd then chunk-load the whole thing into
        # SAGE — wallclock + memory penalty for what's almost
        # certainly bad data. 5 MB cap leaves headroom for unusually
        # rich personas while refusing pathological input.
        if not _read_capped(persona_file, max_bytes=5 * 1024 * 1024):
            continue
        content = _read_capped(persona_file, max_bytes=5 * 1024 * 1024).strip()

        # Chunk long personas into ~1500 char segments
        if len(content) > 1500:
            chunks = _chunk_text(content, max_chars=1500)
            for i, chunk in enumerate(chunks):
                memories.append({
                    "content": f"Expert persona: {persona_name} (part {i+1}/{len(chunks)}) — {chunk}",
                    "domain": "raptor-personas",
                    "memory_type": "fact",
                    "confidence": 0.90,
                    "label": f"persona:{persona_file.stem}:part{i+1}",
                })
        else:
            memories.append({
                "content": f"Expert persona: {persona_name} — {content}",
                "domain": "raptor-personas",
                "memory_type": "fact",
                "confidence": 0.90,
                "label": f"persona:{persona_file.stem}",
            })

    return memories


def extract_methodology() -> list[dict]:
    """Extract analysis/exploit/validation methodology docs."""
    memories = []
    tiers_dir = REPO_ROOT / "tiers"

    guidance_files = [
        "analysis-guidance.md",
        "exploit-guidance.md",
        "validation-recovery.md",
        "recovery.md",
    ]

    for fname in guidance_files:
        fpath = tiers_dir / fname
        if not fpath.exists():
            continue

        capped = _read_capped(fpath, max_bytes=5 * 1024 * 1024)
        if not capped:
            continue
        content = capped.strip()
        doc_name = fname.replace(".md", "").replace("-", " ")

        chunks = _chunk_text(content, max_chars=1500)
        for i, chunk in enumerate(chunks):
            memories.append({
                "content": f"RAPTOR methodology — {doc_name} (part {i+1}/{len(chunks)}): {chunk}",
                "domain": "raptor-methodology",
                "memory_type": "fact",
                "confidence": 0.90,
                "label": f"methodology:{fname}:part{i+1}",
            })

    return memories


def extract_signal_heuristics() -> list[dict]:
    """Extract signal→exploitability probability heuristics."""
    content = (
        "Crash signal exploitability heuristics: "
        "SIGSEGV (memory corruption) — 70% likely exploitable. "
        "SIGABRT (heap issues) — 50% likely exploitable. "
        "SIGILL (illegal instruction) — 40% likely exploitable. "
        "SIGFPE (arithmetic) — 20% likely exploitable. "
        "Unknown signals — default 30% exploitability. "
        "These are baseline priors; historical data from SAGE should override them."
    )
    return [{
        "content": content,
        "domain": "raptor-fuzzing",
        "memory_type": "fact",
        "confidence": 0.90,
        "label": "heuristics:signal_probs",
    }]


def extract_semgrep_config() -> list[dict]:
    """Extract Semgrep configuration knowledge."""
    memories = []

    from core.config import RaptorConfig

    # Baseline packs
    packs = ", ".join(f"{name} ({pack})" for name, pack in RaptorConfig.BASELINE_SEMGREP_PACKS)
    memories.append({
        "content": f"RAPTOR baseline Semgrep packs (always included in scans): {packs}.",
        "domain": "raptor-config",
        "memory_type": "fact",
        "confidence": 0.95,
        "label": "config:semgrep_baseline",
    })

    # Policy group mappings
    mappings = "; ".join(
        f"{group} → {name} ({pack})"
        for group, (name, pack) in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.items()
    )
    memories.append({
        "content": f"RAPTOR Semgrep policy group mappings: {mappings}.",
        "domain": "raptor-config",
        "memory_type": "fact",
        "confidence": 0.95,
        "label": "config:semgrep_policy_groups",
    })

    return memories


def _read_capped(path: Path, *, max_bytes: int) -> str:
    """Read a text file with a byte cap. Returns "" on read failure or
    if the file exceeds ``max_bytes`` (logging a warning on the
    oversize path so an operator sees what was skipped).

    Pre-fix every `read_text` call here was unbounded. A corrupted
    .md file in the personas/methodology dir, or an inadvertent log
    paste, could be tens of MB and we'd chunk-load the whole thing
    into SAGE — wallclock + memory + bandwidth penalty for what's
    almost certainly bad data.
    """
    try:
        st = path.stat()
    except OSError:
        return ""
    if st.st_size > max_bytes:
        import logging
        logging.getLogger(__name__).warning(
            "seed_sage: skipping %s (size %s exceeds cap %s)",
            path.name, st.st_size, max_bytes,
        )
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _chunk_text(text: str, max_chars: int = 1500) -> list[str]:
    """Split text into chunks at paragraph or section boundaries.

    Hard-splits any single line longer than ``max_chars``. Pre-fix the
    line-by-line path appended `current = line` whenever the current
    chunk would exceed `max_chars` — but if `line` itself was longer
    than `max_chars` (e.g. a wrapped log entry, a long URL, a
    minified JSON paste), the function emitted that single
    over-budget line as its own "chunk" without any further split,
    silently sending an oversized payload to SAGE that the embed
    layer then rejected with an opaque token-limit error.
    """
    chunks = []
    current = ""

    def _hard_split(line: str) -> list[str]:
        # Greedy fixed-width split on `max_chars` boundaries.
        return [line[i:i + max_chars] for i in range(0, len(line), max_chars)] or [""]

    for line in text.split("\n"):
        # Hard-split any line that, on its own, exceeds the budget.
        # The flush of `current` happens first so we don't merge an
        # oversized line into the previous paragraph's chunk.
        if len(line) > max_chars:
            if current.strip():
                chunks.append(current.strip())
                current = ""
            for piece in _hard_split(line):
                chunks.append(piece)
            continue
        if len(current) + len(line) + 1 > max_chars and current:
            chunks.append(current.strip())
            current = line
        else:
            current += "\n" + line if current else line

    if current.strip():
        chunks.append(current.strip())

    return chunks if chunks else [text[:max_chars]]


# ─────────────────────────────────────────────────────────────────────────────
# Seeding
# ─────────────────────────────────────────────────────────────────────────────

async def _seed_one(
    client: AsyncSageClient,
    mem: dict,
    force: bool,
    sem: asyncio.Semaphore,
) -> tuple[str, str]:
    """Propose a single knowledge memory. Returns (label, status).

    status ∈ {"stored", "skipped", "failed: <err>"}.
    """
    async with sem:
        label = mem["label"]
        domain = mem["domain"]
        try:
            if not force and await async_memory_exists(client, domain, label):
                return (label, "skipped")

            embedding = await client.embed(mem["content"])
            mt = getattr(MemoryType, mem["memory_type"], MemoryType.observation)
            await client.propose(
                content=mem["content"],
                memory_type=mt,
                domain_tag=domain,
                confidence=mem["confidence"],
                embedding=embedding,
                tags=[label],
            )
            return (label, "stored")
        except Exception as e:
            return (label, f"failed: {e}")


async def seed(sage_url: str, dry_run: bool = False, force: bool = False):
    """Extract all knowledge and seed into SAGE."""

    print("=" * 60)
    print("RAPTOR Knowledge Seeder for SAGE")
    print("=" * 60)
    print()

    # Collect all knowledge
    all_memories = []

    print("Extracting exploitation primitives...")
    try:
        all_memories.extend(extract_primitives())
    except Exception as e:
        print(f"  WARNING: Failed to extract primitives: {e}")

    print("Extracting LLM system prompts...")
    try:
        all_memories.extend(extract_llm_prompts())
    except Exception as e:
        print(f"  WARNING: Failed to extract prompts: {e}")

    print("Extracting expert personas...")
    try:
        all_memories.extend(extract_personas())
    except Exception as e:
        print(f"  WARNING: Failed to extract personas: {e}")

    print("Extracting methodology docs...")
    try:
        all_memories.extend(extract_methodology())
    except Exception as e:
        print(f"  WARNING: Failed to extract methodology: {e}")

    print("Extracting signal heuristics...")
    all_memories.extend(extract_signal_heuristics())

    print("Extracting Semgrep configuration...")
    try:
        all_memories.extend(extract_semgrep_config())
    except Exception as e:
        print(f"  WARNING: Failed to extract Semgrep config: {e}")

    print(f"\nTotal knowledge entries: {len(all_memories)}")
    print()

    if dry_run:
        print("DRY RUN — printing knowledge without storing:\n")
        for i, mem in enumerate(all_memories, 1):
            print(f"[{i}/{len(all_memories)}] [{mem['domain']}] {mem['label']}")
            print(f"  Type: {mem['memory_type']}, Confidence: {mem['confidence']}")
            print(f"  Content: {mem['content'][:120]}...")
            print()
        return

    # Connect to SAGE
    print(f"Connecting to SAGE at {sage_url}...")
    identity = AgentIdentity.default()
    client = AsyncSageClient(
        base_url=sage_url,
        identity=identity,
        timeout=30.0,
    )

    # Register as raptor-seed agent
    try:
        # See register_agents.py for on_chain_height rationale — same
        # SAGE 6.6.0 type-mismatch fix.
        reg = await client.register_agent("raptor-seed")
        height = getattr(reg, "on_chain_height", None)
        print(f"Registered as raptor-seed (on-chain height {height})")
    except Exception as e:
        print(f"Registration note: {e}")

    # Warm the ollama embedding sidecar so the first real embed below
    # doesn't pay cold-model-load latency. Best-effort; does NOT touch
    # CometBFT consensus — /v1/embed is a local ollama roundtrip.
    try:
        await client.embed("wake")
    except Exception:
        pass

    sem = asyncio.Semaphore(_PROPOSE_CONCURRENCY)
    # `return_exceptions=True` so a single _seed_one failure doesn't
    # abort the entire batch. Pre-fix the gather would raise on the
    # first exception, leaving the rest of the all_memories list
    # un-seeded — operator had to re-run, again hitting the same
    # failure and again losing visibility into the rest. Now each
    # failed task surfaces as an Exception in `results`; the
    # downstream classifier (status == "stored" / "skipped" /
    # starts-with "failed") needs a None-or-Exception handling
    # branch.
    raw_results = await asyncio.gather(
        *(_seed_one(client, mem, force, sem) for mem in all_memories),
        return_exceptions=True,
    )
    results = []
    for mem, r in zip(all_memories, raw_results):
        if isinstance(r, BaseException):
            label = getattr(mem, "label", str(mem))
            results.append((label, f"failed: {type(r).__name__}: {r}"))
        else:
            results.append(r)

    stored = sum(1 for _, status in results if status == "stored")
    skipped = sum(1 for _, status in results if status == "skipped")
    failed = [(label, status) for label, status in results if status.startswith("failed")]

    for label, status in results:
        if status == "stored":
            print(f"  stored:  {label}")
        elif status == "skipped":
            print(f"  skipped: {label} (already seeded)")
        else:
            print(f"  {status.upper()}: {label}")

    print()
    print("=" * 60)
    print(f"Stored: {stored}/{len(all_memories)}  Skipped: {skipped}  Failed: {len(failed)}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Seed RAPTOR institutional knowledge into SAGE"
    )
    parser.add_argument(
        "--sage-url",
        default="http://localhost:8090",
        help="SAGE API URL (default: http://localhost:8090)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print knowledge without storing in SAGE",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-propose even if memories with the same label are already seeded",
    )
    args = parser.parse_args()

    asyncio.run(seed(args.sage_url, args.dry_run, args.force))


if __name__ == "__main__":
    main()
