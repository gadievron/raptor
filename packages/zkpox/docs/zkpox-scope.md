# ZKPoX — What This Proves, What It Doesn't, What You Trust

Written for engineers and security reviewers who are not cryptographers.
For the full design rationale see `proposals/raptor-zkpox-design.md`; for
benchmarks and Phase 0 findings see `research/zkpox-phase0-findings.md`.

This document is the source of truth for the **scope claim**. If the
README, the PR body, the proposal, or `/prove-exploit`'s output ever
claim more than what's below, treat the discrepancy as a bug in the
wrapper text, not in this document.

---

## What this MVP proves

For each of the three current C targets, the proof establishes the
following statement and nothing more:

> Under SP1's STARK verifier, when target `T` (a specific freestanding
> C function whose bytes hash to a known value) is invoked with the
> witness committed in the bundle, the redzone gadget observes one or
> more bytes outside the caller-supplied buffer that no longer match
> the canary/pattern fill applied before the call. The byte count and
> first offset of that violation are committed as public values.

In plain English: **"a specific input causes a specific function to
write outside a specific buffer."** That is a memory-safety violation
predicate.

The five public values committed by the SP1 guest, in order:

| Field                  | Type | Meaning                                                                  |
|------------------------|------|--------------------------------------------------------------------------|
| `target_id`            | u32  | Which of the three C targets was invoked (1, 2, or 3).                   |
| `crash_only_crashed`   | bool | Uniform-canary gadget verdict (cheap baseline).                          |
| `oob_detected`         | bool | Position-varying gadget verdict (stronger; harder to false-negative).    |
| `oob_count`            | u32  | Number of redzone bytes that changed.                                    |
| `oob_first_offset`     | i32  | Signed offset (from `buf[0]`) of the first changed byte. Negative ⇒ under-run. |

A verifier who trusts the proof learns exactly those five numbers,
plus the bundle's plaintext metadata (target hash, gadget id, proof
system version). They do **not** learn the witness bytes themselves
(those are AES-encrypted with the key wrapped to a Drand future round
and to the vendor's age public key).

---

## What this MVP does NOT prove

A reviewer dropping in cold will read "proof of exploit" and assume the
bundle establishes one or more of the following. None of them are in
this MVP:

- **Control-flow hijack.** The redzone gadget proves a write past the
  buffer end. It does **not** prove that the bytes written are
  attacker-controlled, that they land on a return address or function
  pointer, or that the resulting control transfer is exploitable
  under ASLR/CET/CFG/stack canaries/RELRO.
- **Code execution / RCE.** Out of scope. The proposal §7 catalogues
  the gadgets that would prove this (`memory-safety::indirect-call`,
  `cfi-bypass`). None are implemented yet.
- **Info-leak with attacker-chosen target.** The redzone primitive is
  write-detection only. Reading past the buffer doesn't trip it.
- **Exploit reliability.** The proof says "this input produced an OOB
  write on this run inside the SP1 zkVM." It does not characterise
  how that result varies with ASLR, with kernel version, with
  compiler flags, or with allocator state.
- **Anything about the vulnerability *class* you think you're
  proving.** Today the gadget catches "this function wrote past *its
  own* buffer." Whether that's a stack BOF, a heap BOF, an off-by-one,
  or a strcat-stale-len bug is a *labelling* convention applied by the
  producer to the bundle's `vulnerability.class` field. The proof
  itself is class-agnostic.

If your disclosure pipeline needs any of the above, this MVP is not
yet the right tool. Track the proposal §7 roadmap (memory-safety
shadow-allocation, control-flow, info-leak, EVM gadgets) for when it
becomes one.

---

## What you trust when you trust a bundle

Every assurance the bundle gives you depends on at least one of these
parties being honest and at least one of these cryptographic primitives
holding. None of these dependencies are unique to ZKPoX — they're the
same surface any disclosure-and-anchoring pipeline lives on — but they
deserve to be enumerated.

### SP1 (the zkVM that produces the proof)

You trust that the SP1 prover's STARK is sound: a verifying proof
implies the guest program produced the committed public values from
*some* witness. Audited by Veridise, Cantina, Zellic, and KALOS for the
v6 release pinned in `core/zkpox/versions.txt`. Soundness bugs in SP1
itself would invalidate every bundle ever produced; that's the largest
single risk in the trust chain.

### The compiled guest binary

You trust that the guest ELF embedded by the prover matches the source
you can inspect at `core/zkpox/guest/`. The verifier checks
`proof.verifier_key_hash` against the SDK-derived verifying key digest;
that key is itself a function of the ELF. *Phase 1.5 caveat: this hash
is a placeholder in the bundles produced today. Phase 1.5.x wires it
to the real `sp1-sdk` digest.* Until then, `zkpox-verify` refuses to
write a bundle without `--allow-placeholder-hashes` and emits a loud
warning when that flag is on.

### age (the vendor envelope)

You trust that age's X25519+ChaCha20-Poly1305 construction is sound,
and that the vendor's published age public key actually belongs to
them. The latter is a *registry* problem the MVP does not solve — the
proposal §14 open-questions list flags vendor-key curation as
unresolved. For Phase 1 you pass `--vendor-pubkey` directly; in
practice you'd want CISA/FIRST or a community-maintained mapping.

### Drand (the time-lock)

You trust the Drand quicknet beacon's threshold BLS signing scheme:
no minority of the threshold can publish a round signature before its
genesis-defined time, and the majority eventually does. If the Drand
network goes away entirely, **the time-lock branch never opens** — the
witness becomes recoverable only through the vendor (age) path. That's
a graceful-degradation property of the layered envelope, not a bug.
Conversely, if a Drand soundness bug let a minority forge a future
round's signature, the time-lock would open early.

### Sigstore Rekor (the timestamp anchor)

You trust either (a) the public Sigstore Rekor log's signed tree head,
or (b) whatever Rekor instance you configured via `ZKPOX_REKOR_URL`.
Rekor binds `bundle_hash_pre_timestamp(bundle)` to the integration
time it reports. *Phase 1.4 caveat: this verifier currently only does
a structural check of the timestamp field. Full Merkle inclusion-proof
validation + STH signature checking lands in Phase 1.4.x. Until then,
the timestamp tells you "Rekor recorded this hash" but not "Rekor's
recorded hash is in the canonical tree at integration time."*

### Your local clock at anchor time

The producer signs `bundle_hash_pre_timestamp` and sends it to Rekor.
Rekor's response includes `integratedTime`. The producer trusts that
this number is approximately correct (within Rekor's own clock skew
tolerance). Verifiers don't trust the producer's clock; they use
Rekor's recorded time.

---

## Failure modes

### Vendor loses their age secret key before the time-lock fires

The witness is unrecoverable via the vendor path. Verifiers can still
check the public proof + Rekor anchor. The witness eventually becomes
public when the Drand round finalises (default T+90d). For
high-severity bugs where the vendor needs the witness *now* and has
lost their key, the producer can re-seal a new bundle to a fresh
vendor key — but the existing bundle's timer cannot be cancelled.

### Drand network unavailable

The time-lock branch never opens. The vendor path still works if the
vendor still has their age key. Researchers waiting for "auto-disclose
at T+90d" must publish manually (or re-anchor a new bundle with a
working alternative time-lock service).

### Vendor patches before T+90d

The producer can issue a follow-up `/prove-exploit` with the same
witness and a shorter `--tlock-duration` (or `--no-anchor` for a
purely-vendor-side bundle). The original published bundle continues to
exist and its time-lock continues to count down; ZKPoX does not have
a "cancel" primitive because that would require a trusted authority
to retract Rekor entries.

### Vendor refuses to patch / disappears / sells the company

The bundle's time-lock fires on its original schedule regardless. The
researcher is exonerated by the timestamp; the public learns the
witness. This is the Project Zero model intentionally — rigid timers
are the only credible disclosure deterrent.

### sp1-sdk has a soundness bug post-MVP

Every existing bundle's proof is suspect. There is no mechanism in
Phase 1 to re-prove existing bundles against a patched SP1; producers
have to re-issue. The verifier's `proof.system` field records the
exact SP1 version used so verifiers can detect "this bundle was
produced under a vulnerable prover release."

### Producer lies about `target_id` in the bundle metadata

The bundle's `vendor_envelope.scheme`, `vulnerability.class`, and
`target.kind` fields are plaintext metadata. **They are not committed
to the proof.** A producer could ship a bundle whose plaintext claims
"target #3 / CVE-2017-9047" while the actual proof was generated
against target #1.

What *is* committed to the proof is `target_id` (one of the five
public values). Once Phase 1.5.x wires real STARK verification, a
verifier that reads the public values will catch this lie immediately
— the public-value `target_id` won't match the plaintext claim. *Until
then, this is the most important reason to wait for 1.5.x before
relying on a ZKPoX bundle for a real disclosure.*

---

## The redzone gadget's false-positive / false-negative profile

The redzone primitive fills memory around the buffer with a known
pattern, runs the C function, and scans the redzone afterwards. Two
gadget variants:

- **`crash-only`** (uniform `0xA5` canary). False-negative whenever
  the bug overwrites a redzone byte with the value `0xA5` exactly.
  False-positive whenever the *legitimate* function semantics involve
  writing `0xA5` outside the supplied buffer (no current target does
  this, but a future heap-aware target might).
- **`memory-safety::oob-write`** (position-varying pattern
  `pattern_byte(p) = 0xA5 XOR ((p * 0x9E37_79B1) >> 24)`). Distinct
  expected byte at every offset. An attacker who didn't pre-compute
  the pattern table matches any single position with probability
  `1/256`; matching `N` consecutive overflow bytes drops to
  `(1/256)^N` because the expected byte differs per position.

For 14-byte overflows (the maximum target-03 can produce at
`buf_size=32`), the position-varying gadget's false-negative probability
under uniform-random witness bytes is `(1/256)^14 ≈ 2^-112`. For
1-byte overflows it's `1/256 ≈ 2^-8`. Witnesses that deliberately
match the pattern (the `-fn` corpus entries) exist to probe this
behaviour and confirm the gadget catches them.

**Adversarial witness generators** — i.e., a producer who has the
pattern table and crafts a witness specifically to match it — defeat
the probabilistic redzone. Phase 1.x's planned shadow-allocation table
(ASan-equivalent) eliminates this; until then the bundle's
`vulnerability.notes` field should disclose whether the witness was
adversarially generated.

---

## Roadmap for the next vulnerability classes

Named explicitly so reviewers know what isn't here:

- **Shadow-allocation table.** Replaces the probabilistic redzone with
  per-store instrumentation; ASan-equivalent. Eliminates the
  adversarial-pattern-matching attack. Phase 1.x research priority.
- **Heap-aware gadgets.** Currently every target is a stack buffer.
  UAF and double-free require allocation-state tracking inside the
  zkVM. Open scope.
- **Control-flow gadgets.** `memory-safety::indirect-call` and
  `cfi-bypass` — proves the gadget redirected execution via an
  attacker-controlled pointer. Proposal §7.
- **Info-leak gadgets.** Symmetric to OOB-write but for OOB-read.
  Different shadow-table interaction. Proposal §7.
- **EVM gadgets.** Smart-contract exploits (`balance-drain`,
  `auth-bypass`, `reentrancy`). v0.2 per the roadmap.
- **Embedded / x86-64 binary-only.** v0.3 / v0.4 per the roadmap;
  the latter is gated on SP1 (or RISC0) GPU pipelines stabilising.

---

## How to read a bundle as a non-cryptographer

```bash
./core/zkpox/target/release/zkpox-verify path/to/bundle.cbor --json
```

The output JSON includes a `structural_checks_passed` boolean and a
human-readable rendering of every field. *In Phase 1.5*, exit code 0
means "the CBOR parses, the lengths look right, the fingerprints
match" — NOT "the STARK is valid" or "Rekor's anchor is in the tree."
The `stark_verification` and `rekor_inclusion_verification` fields
make this explicit ("DEFERRED" strings).

To force the verifier to fail loudly on any deferred check, pass
`--strict`. That flag becomes the default in Phase 1.5.x once the
deferred checks land.

What you're checking, as a non-cryptographer:

- Does the bundle parse? (`structural_checks_passed`)
- Does the gadget id match the claim in the disclosure? (Compare
  `gadget_id` to the vendor's spec.)
- Does the proof system match a release you trust? (`proof.system`,
  e.g. `sp1-stark-core/v6.1.0`.)
- Was it anchored, and how long ago? (`timestamp.integrated_time` if
  present; convert from Unix epoch.)
- For a real assurance pass, wait until 1.5.x — at which point
  `zkpox-verify --strict` will also (a) reproduce the SP1 STARK
  verification, (b) reconstruct the Rekor Merkle inclusion proof, and
  (c) confirm `bundle_hash_pre_timestamp` matches what Rekor recorded.
