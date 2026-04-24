#!/usr/bin/env python3
"""
Register RAPTOR agents on the SAGE network.

Each agent gets a registered identity and role definition stored
as consensus-validated fact memories in the raptor-agents domain.

Usage:
    python3 core/sage/scripts/register_agents.py [--sage-url http://localhost:8090] [--dry-run] [--force]

Requires:
    pip install sage-agent-sdk
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

try:
    from sage_sdk.async_client import AsyncSageClient
    from sage_sdk.auth import AgentIdentity
    from sage_sdk.models import MemoryType
except ImportError:
    print("ERROR: sage-agent-sdk not installed.")
    print("  pip install sage-agent-sdk")
    sys.exit(1)

from core.sage.scripts._common import async_memory_exists

# Parallelism cap for SAGE proposes. CometBFT batches concurrent txs into
# the same block, so N sequential rounds collapse to ~1-2 blocks wall time.
# 8 is conservative enough for 2-core laptops, aggressive enough to matter.
_PROPOSE_CONCURRENCY = 8


# ─────────────────────────────────────────────────────────────────────────────
# Agent definitions
# ─────────────────────────────────────────────────────────────────────────────

RAPTOR_AGENTS = [
    {
        "name": "raptor-crash-analysis",
        "role": "Crash Analysis Orchestrator",
        "description": (
            "Orchestrates crash root-cause analysis for C/C++ security bugs. "
            "Fetches bug reports, clones repos, reproduces crashes, dispatches "
            "sub-agents for tracing and coverage analysis."
        ),
        "domains": ["raptor-crashes", "raptor-findings"],
        "capabilities": [
            "bug report fetching", "crash reproduction",
            "rr recording", "sub-agent orchestration",
        ],
    },
    {
        "name": "raptor-crash-analyzer",
        "role": "Crash Root-Cause Analyst",
        "description": (
            "Performs deep root-cause analysis of crashes using rr recordings, "
            "function traces, and coverage data. Tracks pointer chains from "
            "allocation to crash point."
        ),
        "domains": ["raptor-crashes"],
        "capabilities": [
            "rr trace analysis", "pointer chain tracking",
            "assembly analysis", "memory access validation",
        ],
    },
    {
        "name": "raptor-crash-checker",
        "role": "Crash Analysis Validator",
        "description": (
            "Validates crash analysis reports by mechanically checking format "
            "and verifying all claims against empirical data (RR traces, "
            "coverage data, code). Writes rebuttals for rejected analyses."
        ),
        "domains": ["raptor-crashes"],
        "capabilities": [
            "format validation", "claim verification",
            "empirical data checking", "rebuttal generation",
        ],
    },
    {
        "name": "raptor-coverage-analyzer",
        "role": "Code Coverage Generator",
        "description": (
            "Generates gcov coverage data for C/C++ projects to track which "
            "code paths execute during a crash. Rebuilds with coverage flags "
            "and validates results."
        ),
        "domains": ["raptor-crashes"],
        "capabilities": [
            "gcov instrumentation", "coverage report generation",
            "path validation",
        ],
    },
    {
        "name": "raptor-function-tracer",
        "role": "Function Trace Generator",
        "description": (
            "Generates function-level execution traces using "
            "-finstrument-functions instrumentation. Converts traces to "
            "Perfetto JSON format for visualization."
        ),
        "domains": ["raptor-crashes"],
        "capabilities": [
            "function instrumentation", "trace generation",
            "Perfetto conversion",
        ],
    },
    {
        "name": "raptor-exploitability-validator",
        "role": "Exploitability Validator",
        "description": (
            "Multi-stage pipeline that validates vulnerability findings are "
            "real, reachable, and exploitable. Runs 7 phases from inventory "
            "through feasibility analysis to reporting."
        ),
        "domains": ["raptor-exploits", "raptor-findings"],
        "capabilities": [
            "vulnerability validation", "binary analysis",
            "exploit feasibility assessment", "multi-stage pipeline",
        ],
    },
    {
        "name": "raptor-offsec-specialist",
        "role": "Offensive Security Researcher",
        "description": (
            "Comprehensive offensive security operations including vulnerability "
            "research, penetration testing, exploit development, and security "
            "code review."
        ),
        "domains": ["raptor-exploits", "raptor-findings"],
        "capabilities": [
            "web testing", "network pentesting", "binary exploitation",
            "fuzzing", "exploit PoC creation",
        ],
    },
    {
        "name": "raptor-oss-evidence-verifier",
        "role": "Evidence Integrity Verifier",
        "description": (
            "Verifies forensic evidence against original sources (GH Archive, "
            "GitHub API, Wayback Machine, git) to ensure integrity and prevent "
            "tainted evidence."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "evidence verification", "BigQuery re-query",
            "GitHub API validation", "Wayback confirmation",
        ],
    },
    {
        "name": "raptor-oss-hypothesis-checker",
        "role": "Hypothesis Validator",
        "description": (
            "Rigorously validates forensic hypotheses ensuring all claims are "
            "supported by verified evidence with proper citations. Checks "
            "timeline consistency and attribution sufficiency."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "hypothesis validation", "citation verification",
            "timeline analysis", "attribution assessment",
        ],
    },
    {
        "name": "raptor-oss-hypothesis-former",
        "role": "Hypothesis Formation Analyst",
        "description": (
            "Analyzes collected forensic evidence to form evidence-backed "
            "hypotheses about security incidents. Answers research questions "
            "about timeline, attribution, intent, and impact."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "evidence analysis", "hypothesis formation",
            "research question answering", "evidence gap identification",
        ],
    },
    {
        "name": "raptor-oss-gh-archive",
        "role": "GH Archive Investigator",
        "description": (
            "Queries GitHub Archive via BigQuery for tamper-proof forensic "
            "evidence of GitHub events (pushes, PRs, issues). Handles "
            "force-push recovery and multi-table queries."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "BigQuery queries", "GH Archive analysis",
            "force-push recovery", "event timeline reconstruction",
        ],
    },
    {
        "name": "raptor-oss-github",
        "role": "GitHub API Investigator",
        "description": (
            "Collects forensic evidence from live GitHub API including "
            "repository state, commits, and recovery of deleted commits "
            "via direct SHA access."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "GitHub API queries", "commit recovery",
            "PR/issue analysis", "rate limit management",
        ],
    },
    {
        "name": "raptor-oss-ioc-extractor",
        "role": "IOC Extractor",
        "description": (
            "Extracts Indicators of Compromise from vendor security reports — "
            "commit SHAs, usernames, repos, domains, IPs, file paths, and "
            "other forensic artifacts."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "IOC extraction", "vendor report parsing",
            "artifact identification",
        ],
    },
    {
        "name": "raptor-oss-local-git",
        "role": "Local Git Forensics Analyst",
        "description": (
            "Performs forensic analysis on cloned git repositories — finds "
            "dangling commits, analyzes reflogs, detects author/committer "
            "mismatches and forgery."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "dangling commit recovery", "reflog analysis",
            "forgery detection", "git fsck",
        ],
    },
    {
        "name": "raptor-oss-wayback",
        "role": "Wayback Machine Recovery Specialist",
        "description": (
            "Recovers deleted GitHub content via Wayback Machine for repos, "
            "issues, and PRs no longer accessible through normal channels."
        ),
        "domains": ["raptor-forensics"],
        "capabilities": [
            "Wayback CDX API", "archived snapshot recovery",
            "deleted content retrieval",
        ],
    },
    {
        "name": "raptor-oss-report-generator",
        "role": "Forensic Report Generator",
        "description": (
            "Generates comprehensive forensic investigation reports from "
            "confirmed hypotheses and verified evidence. Produces timeline, "
            "attribution, intent, impact analysis, and IOCs."
        ),
        "domains": ["raptor-forensics", "raptor-reports"],
        "capabilities": [
            "report generation", "timeline synthesis",
            "attribution summary", "IOC compilation",
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

async def _register_one(
    client: AsyncSageClient,
    agent: dict,
    force: bool,
    sem: asyncio.Semaphore,
) -> tuple[str, str]:
    """Propose an agent's role + xref memories. Returns (name, status).

    status ∈ {"stored", "skipped", "failed: <err>"}. Skipped when both
    memories are already present in SAGE and --force isn't set.
    """
    async with sem:
        name = agent["name"]
        caps = ", ".join(agent["capabilities"])
        domains = ", ".join(agent["domains"])
        primary_domain = agent["domains"][0]
        role_tag = f"agent:{name}"
        xref_tag = f"agent-xref:{name}"

        try:
            # Check each memory independently so a previous partial failure
            # (e.g. role stored, xref crashed) re-proposes only the missing
            # half rather than duplicating what already landed.
            if force:
                role_exists = xref_exists = False
            else:
                role_exists = await async_memory_exists(client, "raptor-agents", role_tag)
                xref_exists = await async_memory_exists(client, primary_domain, xref_tag)

            if role_exists and xref_exists:
                return (name, "skipped")

            if not role_exists:
                role_content = (
                    f"RAPTOR agent: {name}. "
                    f"Role: {agent['role']}. "
                    f"Description: {agent['description']} "
                    f"Domains: {domains}. "
                    f"Capabilities: {caps}."
                )
                role_embedding = await client.embed(role_content)
                await client.propose(
                    content=role_content,
                    memory_type=MemoryType.fact,
                    domain_tag="raptor-agents",
                    confidence=0.95,
                    embedding=role_embedding,
                    tags=[role_tag],
                )

            if not xref_exists:
                xref_content = (
                    f"Agent {name} ({agent['role']}) operates in this domain. "
                    f"Capabilities: {caps}."
                )
                xref_embedding = await client.embed(xref_content)
                await client.propose(
                    content=xref_content,
                    memory_type=MemoryType.fact,
                    domain_tag=primary_domain,
                    confidence=0.90,
                    embedding=xref_embedding,
                    tags=[xref_tag],
                )

            if role_exists or xref_exists:
                return (name, "partial")  # one half was already present
            return (name, "stored")
        except Exception as e:
            return (name, f"failed: {e}")


async def register_agents(sage_url: str, dry_run: bool = False, force: bool = False):
    """Register all RAPTOR agents on the SAGE network."""

    print("=" * 60)
    print("RAPTOR Agent Registration for SAGE")
    print(f"Agents: {len(RAPTOR_AGENTS)}")
    if force:
        print("Mode: --force (re-propose even if memories already exist)")
    print("=" * 60)
    print()

    if dry_run:
        for i, agent in enumerate(RAPTOR_AGENTS, 1):
            caps = ", ".join(agent["capabilities"])
            domains = ", ".join(agent["domains"])
            print(f"[{i}/{len(RAPTOR_AGENTS)}] {agent['name']}")
            print(f"  Role: {agent['role']}")
            print(f"  Domains: {domains}")
            print(f"  Capabilities: {caps}")
            print(f"  {agent['description'][:100]}...")
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

    # Register the registrar agent first
    try:
        # AgentRegistration.on_chain_height (int64) was renamed from
        # `registered_at` in SAGE 6.6.0 to fix a 3-way type mismatch
        # (Go int64 vs OpenAPI date-time string vs SDK `str | None`).
        # Surface it so a grep for "raptor-registrar" in debug logs
        # confirms the registration actually landed on-chain.
        reg = await client.register_agent("raptor-registrar")
        height = getattr(reg, "on_chain_height", None)
        print(f"Registered as raptor-registrar (on-chain height {height})\n")
    except Exception as e:
        print(f"Registration note: {e}\n")

    # Warm the ollama embedding sidecar so the first real embed below
    # doesn't pay cold-model-load latency. Best-effort; ollama may not be
    # reachable on some setups and that's fine — the first actual embed
    # will cold-start normally. (Does NOT touch CometBFT consensus —
    # /v1/embed is a local ollama roundtrip, nothing on-chain.)
    try:
        await client.embed("wake")
    except Exception:
        pass

    sem = asyncio.Semaphore(_PROPOSE_CONCURRENCY)
    results = await asyncio.gather(
        *(_register_one(client, agent, force, sem) for agent in RAPTOR_AGENTS)
    )

    stored = sum(1 for _, status in results if status == "stored")
    partial = sum(1 for _, status in results if status == "partial")
    skipped = sum(1 for _, status in results if status == "skipped")
    failed = [(name, status) for name, status in results if status.startswith("failed")]

    for name, status in results:
        if status == "stored":
            print(f"  stored:  {name}")
        elif status == "partial":
            print(f"  partial: {name} (filled in missing half from a prior partial run)")
        elif status == "skipped":
            print(f"  skipped: {name} (already registered)")
        else:
            print(f"  {status.upper()}: {name}")

    print()
    print("=" * 60)
    print(
        f"Stored: {stored}/{len(RAPTOR_AGENTS)}  "
        f"Partial: {partial}  Skipped: {skipped}  Failed: {len(failed)}"
    )
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Register RAPTOR agents on the SAGE network"
    )
    parser.add_argument(
        "--sage-url",
        default="http://localhost:8090",
        help="SAGE API URL (default: http://localhost:8090)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print agent definitions without registering",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-propose even if the agent's memories are already present in SAGE",
    )
    args = parser.parse_args()

    asyncio.run(register_agents(args.sage_url, args.dry_run, args.force))


if __name__ == "__main__":
    main()
