# Design Proposal: ZKPoX — Zero-Knowledge Proof of Exploit Module for RAPTOR

*Status: Design proposal for community review. Targets inclusion alongside `/exploit` and `/patch` in the Raptor agentic workflow.*

*Author: [your name]*
*Discussion: https://github.com/gadievron/raptor/issues (open issue first)*

---

## 1. The Pitch in One Paragraph

RAPTOR already finds bugs, generates working PoCs, and proposes patches. What it does not yet do is help the researcher **disclose** those findings safely. Today, an autonomous workflow that produces a real exploit at 3am leaves the researcher with two bad options: drop the PoC publicly and arm attackers before vendors patch, or hand it privately to a vendor who can sit on it indefinitely. **ZKPoX adds a third option to RAPTOR: a `/prove-exploit` command that converts a PoC into a publicly-verifiable zero-knowledge proof of exploitability, plus a vendor-only encrypted disclosure bundle on a Coordinated Vulnerability Disclosure (CVD) timer.** Anyone can verify the bug is real; only the vendor (or anyone, after the time-lock expires) can reproduce it. This closes the loop on autonomous security research: discover, exploit, prove, disclose — without picking sides between attackers and laggard vendors.

---

## 2. Why This Belongs in RAPTOR Specifically

Three reasons this is a natural fit, not a graft:

1. **RAPTOR already has the witness.** The output of `/fuzz`, `/exploit`, and `/agentic` is exactly the input ZKPoX needs — a target binary plus a concrete crashing/exploiting input. Every other ZK-proof-of-exploit project (Cheesecloth, Trail of Bits' MSP430 work) had to manually obtain witnesses; in RAPTOR they fall out of the existing pipeline.
2. **RAPTOR's scale demand a disclosure layer.** A researcher running RAPTOR autonomously across a hundred targets cannot sensibly file a hundred private CVD reports and wait. ZKPoX makes mass autonomous disclosure responsible: the public record is verifiable, vendors get private details, and timelines are enforced cryptographically.
3. **RAPTOR already integrates LLM analysis with traditional crypto/tools.** Adding a zkVM-backed proving step is consistent with RAPTOR's "agentic orchestration of established security tooling" thesis. The zkVMs (RISC Zero, SP1) are mature open-source infrastructure exactly analogous to AFL++, Semgrep, CodeQL — battle-tested external tools, orchestrated by RAPTOR.

The "killer demo" is FFmpeg-shaped: RAPTOR already has FFmpeg-specific patching for the recent Google disclosure. Cheesecloth (Galois, USENIX 2023) demonstrated ZK proofs of FFmpeg memory vulnerabilities. Joining those threads gives RAPTOR a flagship public demonstration: *"we found a memory corruption bug in FFmpeg, here is the CVE, here is the patch, and here is a 256-byte cryptographic proof anyone can verify that the bug is real, generated automatically."*

---

## 3. Background

A full literature review and architectural reasoning is in the companion brief (see `docs/research/zk-proof-of-exploit-research.md` if accepted). The condensed background:

- **ZK proofs of exploitability (ZKPoX)** let a prover convince anyone that they possess an input causing a public program to violate a property, without revealing the input.
- DARPA's SIEVE programme (2020–2024, prime contractors Galois and Trail of Bits) brought this from theory to working software, including proofs of CVE-2014-0160 (Heartbleed) and FFmpeg memory bugs.
- The reference open-source tool is **Cheesecloth** (Galois, USENIX Security 2023, ACM TOPS 2025), which compiles C/C++/Rust source via LLVM into a ZK statement.
- The practical alternative since Cheesecloth is **zkVMs** — RISC Zero and SP1 in particular — which prove the correct execution of arbitrary RISC-V code. This collapses the "build a custom circuit per vuln class" problem into "write Rust, compile to RISC-V, prove."

ZKPoX-in-RAPTOR builds on the zkVM path because it is dramatically more practical for an alpha product and aligns with RAPTOR's "orchestrate, don't reimplement" philosophy.

---

## 4. Scope: MVP and Roadmap

### MVP (v0.1) — Memory-safety bugs in C/C++ with AFL++ witnesses

The MVP targets exactly the workflow RAPTOR is best at today. Specifically:

- **Targets:** Linux x86-64 ELF binaries, single-process, deterministic re-execution (which AFL++ corpora already imply).
- **Vulnerability classes:** stack/heap buffer overflows, OOB reads/writes, use-after-free, double-free, NULL deref. These are the bugs AFL++ surfaces in RAPTOR's existing `/fuzz`.
- **Violation property:** memory-safety violation as detected by an in-zkVM AddressSanitizer-style monitor (or the simpler "PC reaches a crash handler" predicate).
- **Witness:** the AFL crashing input, exactly as RAPTOR already produces it.
- **Proof system:** SP1 zkVM, Groth16 wrap, ~256-byte on-chain-friendly proof artifact.
- **Disclosure bundle:** CBOR envelope with proof + Drand-tlock-encrypted witness + Sigstore Rekor anchor.

Why these choices:

- AFL++ already produces a small, deterministic witness — perfect for a zkVM trace.
- Memory-safety bugs have a clean, well-studied violation predicate that doesn't depend on subtle program semantics.
- SP1 is audited (Veridise, Cantina, Zellic, KALOS) and recommended for production use.
- The MVP can ship without an x86 emulator if we accept the Cheesecloth compromise: prove the LLVM IR execution rather than the x86 binary execution. This requires the source (which RAPTOR usually has, since it scans repos), but cuts circuit size by ~50–100×.

### v0.2 — EVM smart contract exploits

Add a `/prove-exploit --target evm` mode that proves a transaction sequence drains a contract or bypasses authorization. EVM-class exploits are dramatically cheaper to prove (revm runs cleanly inside SP1; zk-rollups have already done the engineering work) and there is a ready audience: the smart-contract bug-bounty platforms (Immunefi, Sherlock, HackenProof) all require working PoCs as a precondition for payout, and a ZK-proof variant is a clean superset.

### v0.3 — Embedded firmware (Cortex-M / RISC-V)

Add an embedded mode using a small open-source emulator inside the zkVM. This is the Trail of Bits / DARPA SIEVE demonstration replicated, but inside RAPTOR's autonomy.

### v0.4 — x86-64 binary-only

The hardest case. Defer until SP1/RISC0 GPU acceleration matures, and even then accept hours of proving time per witness.

### Out of scope, indefinitely

- Side channels (timing, cache, power, EM). The zkVM models software, not silicon.
- Speculative execution bugs (Spectre, Meltdown, downfall, etc.) for the same reason.
- Bugs requiring concurrency or weak memory models (TOCTOU, data races) — possible in principle, hard in practice; out of MVP.
- Web exploits where the violation predicate depends on browser/server behaviour. RAPTOR's `/web` is already labelled stub/alpha; ZKPoX inherits that limitation.

---

## 5. Architecture Within RAPTOR

ZKPoX follows RAPTOR's existing layering:

```
.claude/
├── commands/
│   ├── prove-exploit.md           # NEW: /prove-exploit command
│   └── verify-exploit-proof.md    # NEW: /verify-exploit-proof command
├── skills/
│   └── zkpox/
│       ├── SKILL.md               # NEW: progressive disclosure for the agent
│       ├── violation-gadgets/     # NEW: catalogue of in-zkVM checks
│       │   ├── memory-safety.md
│       │   ├── control-flow-hijack.md
│       │   ├── info-leak.md
│       │   └── evm-balance-drain.md
│       ├── disclosure-bundle.md   # NEW: CBOR envelope spec
│       └── examples/
└── agents/
    └── disclosure-engineer.md     # NEW: persona for CVD-aware drafting

packages/
└── zkpox/                         # NEW: Python orchestration layer
    ├── __init__.py
    ├── prove.py                   # builds harness, invokes prover
    ├── verify.py                  # standalone verification entry point
    ├── envelope.py                # CBOR bundle, Sigstore anchoring
    ├── timelock.py                # Drand tlock integration
    └── README.md

core/
└── zkpox/                         # NEW: Rust crate (workspace member)
    ├── Cargo.toml
    ├── harness/                   # SP1 guest program
    │   ├── memory-safety/
    │   ├── evm-balance-drain/
    │   └── ...
    ├── violation-gadgets/         # the actual predicate library
    └── verifier/                  # standalone verifier binary

engine/
└── zkpox/                         # NEW: prover service config
    └── sp1.toml

tiers/personas/
└── disclosure-engineer.md         # NEW: a 10th persona

raptor.py                          # MODIFIED: add `prove-exploit` subcommand
raptor_zkpox.py                    # NEW: standalone Python entry point
```

This mirrors `raptor_fuzzing.py`, `raptor_codeql.py`, and `raptor_agentic.py` exactly — same pattern, new capability.

---

## 6. Command Surface and UX

### 6.1 Standalone use

```
/prove-exploit
```

When invoked with no arguments, drops the agent into a guided flow: detect target type (binary vs EVM contract), locate the witness (most recent AFL crash, an `/exploit` output, or user-provided), select a violation gadget, confirm public/private parameters, run the prover, emit the bundle.

```
/prove-exploit --target /path/to/binary --witness /path/to/poc --gadget memory-safety
```

Direct invocation suitable for CI or scripting.

### 6.2 Composed with the existing autonomy loop

The point at which this gets exciting is in `/agentic`. Today `/agentic` does scan → analyse → exploit → patch. Proposed additions:

```
/agentic --with-disclosure
```

After `/exploit` succeeds, automatically chain into `/prove-exploit` and produce the CVD bundle. Result of an autonomous run becomes:

1. A working exploit (private to the researcher).
2. A patch suggestion (public, normal output).
3. A ZK proof of the exploit (public, verifiable).
4. A vendor-encrypted disclosure envelope (private to vendor, time-locked to public).
5. A Sigstore-anchored timestamp.
6. A draft CVE record / advisory text.

That bundle is the "publishable" artifact RAPTOR currently does not produce. It also provides researcher legal cover: the public artifact is just maths, the vendor receives full details under their published CVD policy, and the time-lock enforces the disclosure norm without manual follow-through.

### 6.3 Verification

```
/verify-exploit-proof <bundle.cbor>
```

Validates the proof, checks the Sigstore anchor, prints a summary. Designed to run without RAPTOR's full toolchain — the verifier is a small standalone Rust binary so vendors and CVE numbering authorities can verify proofs without installing RAPTOR.

### 6.4 New persona

Add a 10th expert persona — **Disclosure Engineer** — alongside Mark Dowd, Halvar Flake, etc. Specialises in:

- Drafting CVE/CWE/CVSS records from a proof bundle.
- Knowing which CVD framework applies (ISO 29147, FIRST, EU CRA, Project Zero 90-day, ZDI 120-day).
- Composing safe-harbor citations.
- Choosing public-vs-private gadget parameters.

This persona is the natural collaborator for the new commands and reflects RAPTOR's existing "load expert on demand" pattern.

---

## 7. The Violation Gadget Catalogue

The single most important design choice. Each gadget is a small Rust module that lives inside the zkVM guest program and asserts the violation predicate. The researcher picks a gadget; the zkVM proves "running the target on the witness causes this gadget to return true."

Following Cheesecloth's lessons, every gadget specifies what it leaks beyond "exploit exists":

| Gadget | What it proves | What is leaked | Cost (rough) |
|---|---|---|---|
| `memory-safety::oob-write` | A write occurred outside any allocated region | Vulnerable function name (optional) | Medium |
| `memory-safety::stack-canary` | A stack canary was overwritten | Function with the canary | Low |
| `memory-safety::uaf` | A read/write hit freed memory | Allocation site (optional) | Medium |
| `cfi::pc-attacker-controlled` | The instruction pointer took a value from witness-controlled memory | Nothing extra | Low |
| `info-leak::secret-to-public-sink` | Witness-controlled read crossed a labelled secret→public boundary | Sink function | High (Cheesecloth-style) |
| `evm::balance-drain` | Contract X's balance dropped by ≥ N tokens | Contract address, token, amount threshold | Low |
| `evm::auth-bypass` | A function gated on `onlyOwner` / role check executed without satisfying the check | Function selector | Low |
| `evm::reentrancy` | A re-entrant call modified state mid-callback | Vulnerable function selector | Medium |
| `crash-only` | The target crashed | Nothing | Lowest |

The `crash-only` gadget is deliberately the cheapest and most boring — for many low-severity bugs that's all the researcher wants to prove, and it sets a strong floor on what RAPTOR can claim publicly.

The catalogue is the **product surface**. New gadgets are PRs to `core/zkpox/violation-gadgets/`. This is also the design surface where security review concentrates: a bug in a gadget undermines the proofs that depend on it. Each gadget ships with its own test corpus of known-good and known-bad witnesses.

---

## 8. Disclosure Bundle Format

Single CBOR file (~256 bytes proof + ~few KB metadata + encrypted witness):

```cbor
{
  "version": "zkpox-1.0",
  "target": {
    "kind": "elf|wasm|evm|llvm-ir",
    "hash": "sha256:…",
    "url": "https://…",            # optional, for retrieval
    "metadata": { … }              # ELF arch, EVM chain id, etc.
  },
  "vulnerability": {
    "class": "memory-safety|cfi|info-leak|evm-balance-drain|…",
    "gadget_id": "memory-safety::oob-write@1.2.0",
    "gadget_hash": "sha256:…",     # commits to gadget code
    "leaked_fields": ["function_name"]   # explicit per gadget
  },
  "proof": {
    "system": "sp1-groth16-bn254|risc0-stark|…",
    "bytes": <bstr>,
    "verifier_key_hash": "sha256:…"
  },
  "harness": {
    "git_url": "…",
    "rev": "…",
    "hash": "sha256:…"
  },
  "vendor_envelope": {
    "scheme": "tlock-drand-quicknet+aes-256-gcm",
    "drand_round": 12345678,        # decryptable after this round
    "ciphertext": <bstr>,
    "vendor_pubkey_fingerprint": "…", # additional encryption layer
    "vendor_pubkey_url": "…"
  },
  "timestamp": {
    "rekor_log_index": 1234567890,
    "rekor_log_id": "…",
    "inclusion_proof": <bstr>
  },
  "researcher": {
    "pubkey": "…",
    "signature_over_bundle": <bstr>,
    "contact": "…"                  # optional, can be omitted for anonymity
  }
}
```

Two design choices to flag for review:

1. **Time-lock layered with vendor-key encryption, not either/or.** Default flow: encrypt witness with AES key. Encrypt AES key both to the vendor's public key *and* to a Drand round T-from-now. Vendor can decrypt immediately; everyone else can decrypt at round T (≈ 90 days). This handles vendors going dark or refusing to acknowledge. It also makes Project Zero's 90-day norm an automated property of the artifact, not a promise the researcher has to manually keep.

2. **Anonymous mode is supported but not the default.** The `researcher` field can be omitted, in which case priority is established only by the Rekor timestamp. Default is signed because most legitimate disclosure benefits from attribution and bug-bounty tracking.

---

## 9. Trust Model and Threats

Worth being explicit about who has to trust what.

**The verifier (anyone)** trusts:
- The zkVM verifier binary (small, formally verifiable in principle, audited in practice for SP1/RISC0).
- The hash function and curve choices (SHA-256, BN254 or BLS12-381 for Groth16, FRI hashes for STARKs).
- That the `target.hash` in the bundle is the binary they care about. They check this themselves.
- The Sigstore Rekor log for the timestamp (or another transparency log of their choice).

**The verifier does not have to trust:**
- The researcher (the proof is checkable).
- RAPTOR (RAPTOR is the prover, not the verifier; verification works without RAPTOR installed).
- The vendor (the public proof stands regardless of vendor cooperation).

**The researcher (RAPTOR operator) trusts:**
- Their own machine.
- The zkVM prover (Veridise/Cantina/Zellic/KALOS-audited for SP1; less so for cutting-edge zkVMs).
- The vendor's published encryption key.

**Live threats to plan for:**

- **Prover bugs.** Zero-knowledge VMs ship soundness bugs. Trail of Bits forged a Google ZK proof in April 2026 by exploiting Rust memory bugs in Google's prover. Tools like Arguzz, zkFuzz, and Circuzz routinely find issues even in audited zkVMs. Mitigation: pin to specific audited zkVM releases; subscribe to security advisories; cross-verify with two independent verifier implementations where stakes warrant; update the gadget catalogue and prover atomically.

- **Gadget bugs.** A bug in a violation predicate could let a researcher prove a non-bug, or prevent proving a real bug. Mitigation: each gadget ships with positive and negative test corpora; gadgets are versioned; the bundle commits to `gadget_hash`; verifiers can pin which gadget versions they trust.

- **Witness-encryption misuse.** Some users will want "encrypt the exploit to its own ZK proof so anyone holding a valid witness can decrypt." This is *witness encryption* and it is **not deployable in 2026** for arbitrary NP relations (Garg-Gentry-Sahai-Waters relies on multilinear maps that are broken). Refuse this feature even if requested. The hybrid encrypt-to-vendor-key + time-lock is the practical alternative.

- **Dual use.** The same primitive that helps a white-hat helps a 0-day broker prove a vulnerability to a buyer. The MVP mitigates this in three ways: (a) public-disclosure-by-default with vendor envelope, (b) the time-lock is mandatory in default mode (so the witness becomes public eventually), (c) integration with established CVD platforms is a first-class output. A `--no-public-anchor` flag would be a deliberate choice with prominent UX warnings; consider whether to ship it at all.

- **Legal posture.** Producing a ZK proof requires running the exploit. This is "access" under CFAA-equivalent laws in most jurisdictions. The Disclosure Engineer persona produces draft text citing safe harbors (vendor CVD policy, EU CRA Article 13, the recent Belgian CVD framework, the US DMCA §1201 security-research exemption, the EU Cybercrime Directive amendments ENISA recommended). The tool itself does not perform legal evaluation; that's on the operator.

---

## 10. Performance Realism

What a researcher should expect, given current zkVM benchmarks (RISC0/SP1, late 2025/early 2026, Galois SIEVE final numbers as the upper-fidelity reference):

- **EVM exploits:** seconds to minutes on a workstation, often sub-minute with GPU.
- **Memory-safety bug in 1k-LOC C program (LLVM IR mode):** minutes.
- **Memory-safety bug in 50k-LOC C program (LLVM IR mode):** tens of minutes to hours.
- **Cortex-M firmware exploit:** minutes to tens of minutes.
- **Full x86-64 binary:** hours, expected to drop to under an hour over the next 18–24 months.
- **Verification:** milliseconds (Groth16 wrap), under a second (raw STARK).
- **Proof size:** ~256 bytes (Groth16 wrap), ~200 KB (raw STARK), low MB (uncompressed VOLE-based).

These numbers improve roughly 2–5× per year and the trend is steady. The MVP should be designed to swap proving backends without API changes, because in 24 months there will be at least one zkVM that's clearly best for this workload that does not exist yet.

---

## 11. SKILL.md Sketch (for `.claude/skills/zkpox/SKILL.md`)

To match RAPTOR's progressive-disclosure pattern:

```markdown
# ZKPoX: Zero-Knowledge Proof of Exploit

## When to use this skill

Trigger this skill whenever:
- The user has a working exploit / PoC / AFL crash and wants a publicly
  shareable demonstration that protects exploit details.
- The user is preparing a coordinated vulnerability disclosure and needs
  to prove severity to a vendor or the public without arming attackers.
- `/agentic --with-disclosure` is invoked and `/exploit` has succeeded.
- The user mentions ZK proofs, zero-knowledge, witness encryption,
  responsible disclosure, CVD, Project Zero, ZDI, Immunefi, Cheesecloth,
  SIEVE, or similar terms.

## When NOT to use this skill

- The PoC is for a side-channel or speculative-execution bug. ZKPoX models
  software, not microarchitecture. Tell the user explicitly.
- The vulnerability requires concurrency / weak memory models. Out of MVP.
- The user wants witness encryption ("decryptable by anyone with a valid
  exploit"). This is not deployable in 2026; redirect to the time-lock
  + vendor key flow.

## Workflow

1. Verify the witness reproduces the violation locally (call the
   target, observe the crash / state transition).
2. Pick a violation gadget from the catalogue
   (.claude/skills/zkpox/violation-gadgets/). If none fits, ask before
   defaulting to `crash-only`.
3. Build the harness:
   - For ELF/Linux targets, prefer LLVM IR mode (need source).
   - For EVM, run revm-on-SP1.
   - For embedded, pick the matching emulator.
4. Run the prover. Stream progress; this can take minutes-to-hours.
5. Encrypt the witness to the vendor's published key + a Drand tlock
   round 90 days out (configurable per CVD framework).
6. Anchor the bundle in Sigstore Rekor.
7. Hand off to the Disclosure Engineer persona to draft the advisory.

## Files this skill writes

All under the user's chosen output directory:
- `<bug-id>-bundle.cbor` — the disclosure bundle.
- `<bug-id>-advisory.md` — draft advisory text.
- `<bug-id>-receipt.json` — Rekor inclusion proof receipt.
```

---

## 12. Sample Command File (`.claude/commands/prove-exploit.md`)

```markdown
# /prove-exploit

Generate a publicly-verifiable zero-knowledge proof of a working exploit.

## Required inputs

- `--target <path>`: the vulnerable binary, contract, or LLVM IR.
- `--witness <path>`: the exploit input (AFL crash, PoC bytes, calldata).
- `--gadget <id>`: which violation predicate to use.

If invoked with no arguments, RAPTOR will detect a recent /exploit or
/fuzz output and offer to use it.

## Optional inputs

- `--vendor-key <path|url>`: vendor's published encryption key for the
  private envelope. Defaults to looking up the vendor in the
  vendors-cvd-keys registry.
- `--timer <90d|120d|custom>`: time-lock duration. Defaults to 90d
  (Project Zero norm).
- `--anonymous`: omit researcher signature; rely on Rekor timestamp only.
- `--no-public-anchor`: suppress public publication. Generates a private
  bundle only. Intended for testing; carries warnings.
- `--proof-system <sp1|risc0>`: defaults to sp1.
- `--harness <path>`: override the auto-built harness for advanced users.

## Outputs

A directory containing the bundle, draft advisory, Rekor receipt, and
an HTML one-pager suitable for posting to a public CVE record.
```

---

## 13. Implementation Phases and Effort Estimate

**Phase 0 — research spike (1–2 weeks).**
- Stand up SP1 locally, build the smallest possible harness that proves a buffer overflow in a 100-LOC C program.
- Validate the LLVM-IR-mode shortcut empirically.
- Pick the time-lock implementation (tlock-rs from Drand is the obvious choice).

**Phase 1 — MVP (4–6 weeks).**
- `core/zkpox/` Rust crate with the SP1 guest program and 3 gadgets (`crash-only`, `memory-safety::oob-write`, `memory-safety::stack-canary`).
- `packages/zkpox/` Python orchestration.
- `/prove-exploit` and `/verify-exploit-proof` commands, basic `.claude/skills/zkpox/`.
- CBOR bundle + Sigstore anchoring + Drand tlock.
- `disclosure-engineer.md` persona.
- One concrete end-to-end demo: a known FFmpeg memory bug, RAPTOR `/agentic --with-disclosure`, output bundle posted to Sigstore.
- Tests: 5 known-vulnerable / 5 known-safe binaries per gadget.

**Phase 2 — EVM (3–4 weeks).**
- revm-on-SP1 harness.
- Three EVM gadgets (`balance-drain`, `auth-bypass`, `reentrancy`).
- Integration with at least one bounty platform's submission flow (target Immunefi).
- Demos against known historical exploits in the DefiHackLabs corpus.

**Phase 3 — Embedded (4–6 weeks).**
- Cortex-M emulator inside zkVM (or wrap an existing one).
- Reproduce DARPA's MSP430 demonstrations.
- Embedded-specific gadgets (firmware update bypass, etc.).

**Phase 4 — x86-64 binary-only (open-ended).**
- Wait for SP1/RISC0 GPU pipelines to mature.
- Use Cheesecloth-style preprocessing on public input.
- Accept hours-per-witness for now.

Total to MVP: roughly 2 person-months. The hard parts are the gadget design (which is mostly research) and integration testing (which is mostly engineering). The proving system itself is delegated to SP1.

---

## 14. Open Design Questions

These deserve community input before committing to v1.

1. **Should ZKPoX live inside RAPTOR or as a sister project?** Argument for inside: tight integration with `/exploit` and `/agentic`, single tool experience. Argument for sister: the Rust crate is reusable beyond RAPTOR (other tools, CI integrations, third-party verifiers). My current preference is to have the Rust crate as a separate workspace with permissive licensing and the orchestration/skills/commands inside RAPTOR.

2. **Is `crash-only` strong enough as a default?** It avoids researcher overclaim and is cheapest to prove, but a "we proved it crashes" bundle is weaker than a CVE record. Maybe make `crash-only` the public default and prompt for a stronger gadget interactively.

3. **Vendor key registry.** Who curates the mapping from vendor (Mozilla, Google, Microsoft, FFmpeg upstream, Aave) to their published CVD encryption key? Initial proposal: a separate small repo, PR-driven, with verifiable signatures from the vendor's existing CVD contacts. CISA and FIRST may eventually offer this; until then, community-maintained.

4. **What happens if the time-lock fires but the vendor has not published a fix?** Default behaviour should be: the witness becomes publicly decryptable, full stop. The researcher is exonerated by the timestamp; the vendor's failure to act is on the vendor. But there are good arguments for a configurable extension mechanism. Project Zero famously refused such extensions; ZDI sometimes grants them. The MVP should probably mirror Project Zero (rigid) and let policy evolve.

5. **Bug-bounty platform integration.** Should ZKPoX talk directly to Immunefi/HackerOne/HackenProof APIs to file bundles? Probably yes for v0.2 EVM mode; the platforms already accept structured PoC submissions. This is a meaningful differentiator vs other ZK PoX work, none of which has integrated with disclosure platforms.

6. **Cost / quota integration with RAPTOR's LiteLLM cost layer.** Proving consumes compute, not LLM tokens, but it's still a real cost line item. Should `--max-cost` apply across both? My read: yes, present the user with a single budget covering analysis, exploit, prove, and patch, rather than hiding proving cost in a separate flow.

---

## 15. Why Now

ZK proofs of exploitability have been theoretically possible since the 1986 GMW result that all of NP has ZK proofs. They have been *practically* possible since CHEESECLOTH in 2023 and the SIEVE wrap-up in 2024. They have been *easy* — for someone with good engineering — only since SP1 and RISC Zero stabilised in 2024–2025. RAPTOR is exactly the kind of higher-level orchestration tool that turns "easy for an expert" into "available to working security researchers." The window to ship this and have it become a default expectation in coordinated disclosure — alongside CVE records, CVSS scores, and patches — is now.

---

## 16. Acknowledgements

This proposal builds directly on:
- Galois's CHEESECLOTH (Cuéllar, Harris, Parker, Pernsteiner, Tromer, USENIX 2023; ACM TOPS 2025).
- Trail of Bits' work on MSP430 ZK exploit proofs (eprint 2022/1223).
- The DARPA SIEVE programme (2020–2024), particularly the prover-performance push that made all this practical.
- The SP1 and RISC Zero teams.
- The Drand network and tlock implementations.
- The Sigstore project.
- And RAPTOR itself, whose architecture made this design easy to write.
