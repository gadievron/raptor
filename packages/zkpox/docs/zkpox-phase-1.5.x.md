# Design Proposal: ZKPoX Phase 1.5.x — Closing the Credibility Gap

*Status: Design proposal. Targets the work that moves ZKPoX from "the
surface ships" (Phase 1.5) to "the proof actually verifies"
(Phase 1.5.x).*

*Related: `docs/proposals/raptor-zkpox-design.md` (original design),
`docs/zkpox-scope.md` (scope-of-trust), `packages/zkpox/README.md`
(tier model).*

---

## 1. Goal in One Paragraph

Phase 1.5 shipped the full ZKPoX surface — the CLI, the bundle format,
the envelope, the anchor, and a structural-only verifier — under a
loud `--allow-placeholder-hashes` gate. Every bundle today carries two
placeholder strings (`verifier_key_hash`, `harness.hash`), and the
standalone verifier accepts a bundle without re-running the SP1 proof
or validating the Rekor inclusion path. **Phase 1.5.x removes the
gates.** When 1.5.x lands, a bundle produced by `/zkpox prove`
contains hashes that bind to the real SP1 verifying key and the real
harness binary, and the standalone `zkpox-verify` independently
re-runs the STARK verification and validates the Rekor Merkle path.
The "do NOT use for real disclosure" warning comes off.

The work is **integration, not research.** Everything 1.5.x needs
exists in the workspace today: the prover already links `sp1-sdk
6.0.1` with the full proving / verifying-key API. The verifier
deliberately omits it (compile-time concern, noted in
`core/zkpox/verifier/Cargo.toml`). 1.5.x is wiring + design choices,
not novel cryptography.

---

## 2. What 1.5 Shipped vs What 1.5.x Owes

| Concern | 1.5 (today) | 1.5.x (this proposal) |
|---|---|---|
| `proof.verifier_key_hash` | `sha256("placeholder-vk-1.5")` | `sha256(SP1 vkey bytes)` from `sp1-sdk` |
| `harness.hash` | `sha256("harness-1.5")` | `sha256(guest ELF bytes)` |
| `gadget_id_hash` | hash of the gadget identifier string | unchanged |
| `gadget_code_hash` | (absent) | **new field** — hash of gadget implementation files |
| Standalone verifier — STARK | `"DEFERRED"` | runs `sp1-sdk` verify |
| Standalone verifier — Rekor | `"DEFERRED"` (hash match only) | Merkle inclusion + STH signature |
| `--strict` flag | off by default; off in CI | **default-on**; `--insecure-bypass` reserved for tests |
| `--allow-placeholder-hashes` | required to write a bundle | **removed** (kept as deprecation alias one cycle) |
| `BUNDLE_VERSION` | `"zkpox-1.0"` | `"zkpox-1.1"` (new required field forces a bump) |
| Backward compat | n/a | verifier reads both `1.0` (non-strict only) and `1.1` |

---

## 3. Non-Goals

Explicit, so this proposal stays bounded:

- **Post-quantum migration.** The Groth16/BN254 wrap + drand BLS+IBE
  time-lock + age X25519 vendor envelope all stay classical.
  Multi-year, research-gated; tracked separately.
- **Witness encryption.** Not deployable from standard assumptions in
  2026; the time-lock + vendor-key shape stays.
- **New target architectures.** ELF only. EVM / WASM / binary-only
  are Phase 2 (per the original proposal).
- **Real-disclosure scope expansion.** The bounded claims in
  `docs/zkpox-scope.md` (what the MVP proves vs doesn't) are not
  expanded by 1.5.x — that document still defines the ceiling. 1.5.x
  makes the bounded claim verifiable; it does not enlarge it.
- **Rekor v1 sunset.** v1 is still supported for read; producers
  default to v2.

---

## 4. Trust Model Deltas

Three changes to the trust story, all tightening it:

**A. Producer no longer asserts the vkey.** In 1.5 the bundle's
`proof.verifier_key_hash` is a placeholder string the verifier
accepts without comparison. In 1.5.x the verifier *re-derives* the
SP1 verifying key from a known harness ELF, hashes it, and compares
to the bundle's claim. Mismatch → hard fail. This means a producer
who tampers with the vkey field cannot pass strict verify, even
without the verifier touching the network.

**B. Producer no longer asserts the harness binary.** Same shape
for `harness.hash`. The verifier hashes a harness ELF it trusts (see
§7 for *where that trust comes from*) and compares.

**C. Verifier no longer trusts the producer for the Rekor anchor.**
1.5 confirms the recorded hash matches a locally-computed hash; it
does NOT validate the Merkle inclusion path or check the STH
signature. 1.5.x adds both: reconstructs the path from
`inclusion_proof_hashes` + `tree_size` + `root_hash`, validates the
STH signature against Rekor's published log public key, and (for
Rekor v2) checks witness cosignatures.

Layer that doesn't change: **verifiers still don't trust the
researcher, RAPTOR, or the vendor.** The original trust model from
the design proposal §9 stays intact — 1.5.x just makes more of it
actually enforced.

---

## 5. Wire Format Changes

Minimal — one new required field, one version bump:

```diff
 @dataclass(frozen=True)
 class Vulnerability:
     cls: str
     gadget_id: str
     gadget_id_hash: str       # commits to the identifier (1.5)
+    gadget_code_hash: str     # commits to the implementation (1.5.x)
     leaked_fields: list[str]
```

```diff
-BUNDLE_VERSION = "zkpox-1.0"
+BUNDLE_VERSION = "zkpox-1.1"
```

`_to_dict` / `_from_dict` in `packages/zkpox/disclosure.py` gain one
key per direction. The Rust verifier (`core/zkpox/verifier/src/main.rs`)
already walks the CBOR map by name and ignores unknown keys, so 1.5.x
bundles are readable by older verifiers — they just can't enforce the
new gadget binding (which is why `--strict` requires `1.1` and rejects
`1.0`).

No changes to: `Target`, `Proof`, `HarnessRef`, `VendorEnvelope`,
`Researcher`, `Timestamp`, `provenance`. The 1.5 provenance field
(carrying the manifest's Tier 0/1 + 1.5 evidence into the disclosure
bundle) stays exactly as is.

---

## 6. Component-by-Component Changes

### 6.1 `core/zkpox/prover/src/main.rs` (Rust prover)

Add two lines to the JSON record emitted by `--record`:

```rust
record["vkey_digest"]      = sha256(proving_key.vk().bytes()).hex();
record["guest_elf_hash"]   = sha256(GUEST_ELF).hex();
```

Both surface in `prove-record.json` for the Python wrapper to read.
No other prover changes; the proving path itself is unchanged.

### 6.2 `packages/zkpox/prove.py` + `raptor_zkpox.py`

- Extend `_record_to_result` (the pure parser landed in 1.5.x's de-flake
  work) to map `vkey_digest` and `guest_elf_hash` into `ProveResult`.
- In `cmd_prove`:
  - Replace `zkpox.sha256_bytes(_PLACEHOLDER_VK_DIGEST.encode())` with
    the value from the prove record.
  - Replace `zkpox.sha256_bytes(_PLACEHOLDER_HARNESS_DIGEST.encode())`
    with the value from the prove record.
  - Drop `_PLACEHOLDER_VK_DIGEST` and `_PLACEHOLDER_HARNESS_DIGEST`
    module constants.
  - Drop the `--allow-placeholder-hashes` SystemExit; the flag becomes
    a deprecated no-op for one cycle (logs a warning, then removed).
- Add `_compute_gadget_code_hash(gadget_id)`: resolves the gadget
  implementation file(s) under `.claude/skills/zkpox/violation-gadgets/`
  by `gadget_id`, hashes them deterministically (canonical sort, NFC,
  newline-normalised), returns `sha256:HEX`. Pin the file-set per
  `gadget_id` so a gadget bump is a content bump.

### 6.3 `packages/zkpox/disclosure.py`

- Add `gadget_code_hash: str` to `Vulnerability`.
- Update `_to_dict` / `_from_dict` symmetrically.
- Bump `BUNDLE_VERSION = "zkpox-1.1"`.
- Update `disclosure_from_manifest` signature to require
  `gadget_code_hash` alongside `gadget_id_hash`.

### 6.4 `core/zkpox/verifier/src/main.rs` (Rust verifier — the rock)

Add two Cargo features:

```toml
[features]
default = ["full-verify"]
structural = []            # 1.5 behaviour; no sp1-sdk; fast CI
full-verify = ["dep:sp1-sdk"]

[dependencies]
sp1-sdk = { version = "6.0.1", optional = true, default-features = false }
```

Under `full-verify`:

1. Read `harness.hash` from the bundle.
2. Load a trusted guest ELF (see §7 for source-of-trust) and hash it;
   compare to `harness.hash`. FAIL on mismatch.
3. Run SP1 SDK setup against that ELF to derive the verifying key.
   Hash the vkey bytes; compare to `proof.verifier_key_hash`. FAIL
   on mismatch.
4. Deserialise `proof.bytes` according to `proof.system`
   (`sp1-groth16/v6.1.0` or `sp1-stark-core/v6.1.0`).
5. Call the appropriate `sp1-sdk` verify (`Groth16` is gnark-backed,
   ~ms; `core` is heavier).
6. `summary.stark_verification` becomes either
   `"OK (sp1-groth16/v6.1.0; vkey sha256:…)"` or a precise failure.

The `structural` feature path keeps today's behaviour exactly, for
CI's fast tier and for environments without the SP1 build chain.

### 6.5 `packages/zkpox/anchor.py`

Add Merkle + STH verification:

```python
def verify_inclusion_proof(
    ts: Timestamp,
    *,
    leaf_hash: bytes,       # bundle_hash_pre_timestamp(bundle)
    log_pubkey: bytes,
) -> bool:
    """Validate the Merkle inclusion path + STH signature against the
    log's public key (RFC 6962 §2.1.1)."""
    ...
```

- `confirm_anchor_matches` calls `verify_inclusion_proof` in addition
  to the existing hash-match.
- For Rekor v2: validate witness cosignatures over the checkpoint.
  Witness set comes from Sigstore TUF root (read once, cached).
- `DEFAULT_REKOR_URL` migrates to the current annual shard
  (`log2026-1.rekor.sigstore.dev` at write time; operator-overridable
  via `ZKPOX_REKOR_URL`).

### 6.6 `core/zkpox/verifier/src/main.rs` (Rekor side)

Mirror the Python Merkle verification in Rust so the standalone
verifier doesn't require Python at verify time, and can optionally
operate offline (operator passes the checkpoint + witness signatures
as a side-input).

### 6.7 `--strict` flips to default

CLI + tests + docs. `--strict` becomes the default in both verifiers
(Python `verify-exploit-proof` path and Rust `zkpox-verify`). A new
opt-in `--insecure-bypass-verification` reserved for fixture / test
use only; documented as such.

---

## 7. The Open Design Question: Where Does the Verifier's Trust Root Come From?

This is the *single* substantive design decision in 1.5.x. Everything
else is mechanical. **The standalone verifier needs to derive the
SP1 verifying key without trusting the producer.** Three options:

**Option A: Embed the guest ELF in the verifier binary.**
The verifier ships with the guest ELF baked in (`include_bytes!`).
On verify, it hashes the embedded ELF + derives the vkey from it.
The bundle's `harness.hash` and `proof.verifier_key_hash` are
checked against the *embedded* derivations. Trust root: the verifier
binary itself.

- *Pro:* Fully self-contained. The verifier is a single hash-pinnable
  artifact. No network, no operator input, no ambiguity.
- *Con:* The verifier is per-harness. A new gadget or guest revision
  ships a new verifier. Cross-version compatibility requires the
  verifier to embed *every* supported guest ELF (versioned dispatch),
  which gets unwieldy fast.
- *Best for:* a stable, small set of guests; the canonical operator
  workflow today.

**Option B: Operator supplies the harness ELF.**
Verifier takes `--harness PATH` (the guest ELF for this gadget version)
and derives the vkey from it. Bundle's `harness.hash` is checked
against the operator-supplied ELF.

- *Pro:* One verifier supports any harness. Operator chooses what to
  trust.
- *Con:* Verifier no longer self-contained. Operator must source the
  harness from somewhere they trust (which is the harness git repo
  pinned by `harness.git_url` + `harness.rev` in the bundle).
- *Best for:* a multi-harness future, expert operators.

**Option C: Versioned dispatch with TUF-anchored harness manifest.**
Verifier carries a small lookup table: `gadget_id → harness ELF
hash`, signed via Sigstore TUF root. On verify, it looks up the
expected harness hash for the bundle's `gadget_id`, then either uses
an embedded copy (subset of A) or downloads from a content-addressed
mirror.

- *Pro:* Scales to many gadgets without re-shipping the verifier;
  trust is rooted in Sigstore TUF (already trusted for Rekor).
- *Con:* More moving parts. Requires a published, signed harness
  manifest.

**Recommendation: A for 1.5.x, design-doc C for 1.6.** Start
self-contained (one harness, one verifier) and lift the constraint
when there's actually >1 gadget version in the wild. Build the seam
(`#[cfg(feature = "embedded-harness")]` vs `#[cfg(feature =
"operator-harness")]`) so the eventual migration is mechanical.

---

## 8. Work Items + Effort

Three milestones, ordered by credibility-per-day. Each is shippable
on its own.

Four phases, each independently shippable, numbered as point-releases
of 1.5. Cross-references in the rest of this proposal use
`Phase 1.5.N §M` to point at a specific item.

### Phase 1.5.1 — Real Hashes (~1 week)

Removes the two biggest teeth from the "not for real disclosure"
warning. Bundles go from "asserted" to "binding to the real key +
harness" even before the verifier independently re-runs anything.

| § | Item | Files | Effort |
|---|---|---|---|
| 1 | Emit `vkey_digest` + `guest_elf_hash` in `prove-record.json` | `core/zkpox/prover/src/main.rs` | 1 d |
| 2 | Thread both into `ProveResult`; `cmd_prove` uses them | `prove.py`, `raptor_zkpox.py` | 1 d |
| 3 | Compute `gadget_code_hash` from gadget files | `raptor_zkpox.py` + new helper | 1–2 d |
| 4 | Add `gadget_code_hash` to schema; bump `BUNDLE_VERSION` to `1.1` | `disclosure.py`, tests | 1 d |
| 5 | Drop `_PLACEHOLDER_*` constants; `--allow-placeholder-hashes` deprecated | `raptor_zkpox.py` | ½ d |
| 6 | Tests + invariant: no placeholder string survives into a produced bundle | `test_disclosure.py`, new `test_no_placeholders.py` | 1 d |

**Phase 1.5.1 exit criteria:** every newly-produced bundle's
`proof.verifier_key_hash` equals `sha256(real vkey bytes)`; every
`harness.hash` equals `sha256(guest ELF)`; every `vulnerability`
carries `gadget_code_hash`. The verifier still runs in structural
mode; `--strict` not yet flipped.

### Phase 1.5.2 — STARK Verification (~1–2 weeks)

The biggest rock. Dominated by Cargo-features + the §7 design call,
not by crypto.

| § | Item | Files | Effort |
|---|---|---|---|
| 1 | Decide §7 trust root (recommend **A**: embedded ELF) | design call | 1 d |
| 2 | Cargo features: `structural` + `full-verify` (gated `sp1-sdk` dep) | `verifier/Cargo.toml`, `verifier/src/main.rs` | 1 d |
| 3 | Embed guest ELF; vkey derivation + hash check | `verifier/src/main.rs` | 2–3 d |
| 4 | `sp1-sdk` proof verify (`Groth16` + `core` paths) | `verifier/src/main.rs` | 1–2 d |
| 5 | Update `summary.stark_verification` JSON; flip `--strict` default | `verifier/src/main.rs` | ½ d |
| 6 | Extend `core/zkpox/test/run-tests.sh` to cover `full-verify` against the corpus | `core/zkpox/test/` | 1 d |
| 7 | Build-cache strategy for `full-verify` verifier; CI fast tier uses `structural` | `.github/workflows/`, `Cargo.toml` | 1 d |

**Phase 1.5.2 exit criteria:** `zkpox-verify --strict bundle.cbor`
returns 0 iff the STARK proof verifies against a vkey derived from
the embedded guest ELF, and the bundle's vkey/harness hashes match.
A tampered `proof.bytes` or tampered `harness.hash` produces a clean
non-zero exit.

### Phase 1.5.3 — Rekor Merkle + STH (~1–2 weeks; v2 retarget = the wildcard)

| § | Item | Files | Effort |
|---|---|---|---|
| 1 | Decide Rekor v1-only vs v1+v2 (recommend **v2 default, v1 read-only**) | design call | 1 d |
| 2 | Python: Merkle inclusion proof verify (RFC 6962 §2.1.1) | `anchor.py` | 2 d |
| 3 | Python: STH signature verify against log pubkey (TUF-rooted) | `anchor.py` | 2 d |
| 4 | Python: Rekor v2 witness cosignature verify | `anchor.py` | 2 d |
| 5 | Rust: mirror Merkle + STH (no `core.http` dep — operator passes checkpoint) | `verifier/src/main.rs` | 2–3 d |
| 6 | `DEFAULT_REKOR_URL` → annual shard; document override | `anchor.py`, docs | ½ d |
| 7 | Tests: golden inclusion proofs, tampered paths, signature failures, witness scenarios | `test_anchor.py` | 1–2 d |

**Phase 1.5.3 exit criteria:** a producer-side anchored bundle
round-trips through the verifier with `rekor_inclusion_verification:
"OK"` (not `"DEFERRED"`), and any tampering — wrong leaf, wrong path,
wrong root, unsigned STH, missing witness — produces a clean fail.

### Phase 1.5.4 — Strict Default + Docs Cleanup (~½ day)

| § | Item | Files | Effort |
|---|---|---|---|
| 1 | `--strict` → default in both verifiers | `raptor_zkpox.py`, `verifier/src/main.rs` | ¼ d |
| 2 | `--allow-placeholder-hashes` removed (was no-op since Phase 1.5.1 §5) | `raptor_zkpox.py` | ¼ d |
| 3 | Docs: drop "do NOT use for real disclosure" from scope/SKILL; bump version refs | `docs/zkpox-scope.md`, `.claude/skills/zkpox/SKILL.md`, `.claude/commands/zkpox.md` | ¼ d |

**Total estimated effort:** ~3–4 focused weeks. Phase 1.5.1 is the
highest-value first move (real binding, no schema churn after);
1.5.2 and 1.5.3 are the two rocks; 1.5.4 is the "1.5.x ships" signal.

---

## 9. Backward Compatibility

- A `zkpox-1.0` bundle (produced under 1.5) is **readable** by a
  1.5.x verifier in non-strict mode. The verifier flags the placeholder
  vkey/harness hashes explicitly and refuses under `--strict`.
- A `zkpox-1.1` bundle is **readable** by a 1.5 verifier — the
  verifier's CBOR walk ignores `gadget_code_hash`, and structural
  checks still pass (deferred fields still deferred).
- Producers default to `1.1` after Phase 1.5.1. The flag
  `--bundle-version 1.0` exists for one cycle to support the rare
  case of a producer needing to interoperate with an unupgraded
  verifier; logs a deprecation warning.

---

## 10. Testing Strategy

| Layer | Coverage |
|---|---|
| Unit | Schema round-trip (1.0 + 1.1 both round-trip via `to_cbor`/`from_cbor`); hash invariants (no placeholder string survives); Merkle math (RFC 6962 test vectors); STH signature verify (golden + tampered) |
| Integration | `run-tests.sh` extended to cover `full-verify`: prove → verify on every corpus witness; `--strict` exit 0 |
| Adversarial | Tampered `verifier_key_hash` / `harness.hash` / `proof.bytes` / Merkle path / STH sig / witness cosig — all FAIL `--strict` verify with a clear message |
| Regression | 1.5-produced bundles verify in non-strict mode (kept as fixtures); fail in strict mode with `gadget_code_hash: missing` |
| Build | CI runs `structural` feature on the fast tier; `full-verify` on the zkpox-regression tier (already SP1-heavy) |

---

## 11. Risks + Wildcards

Two genuine sources of slip; one nuisance.

**The §7 trust-root call (Phase 1.5.2 §1).** If Option B
(operator-supplied harness) wins instead of A, Phase 1.5.2 §3 expands
to ~3–4 days for the flag plumbing + harness-on-disk handling.
Recommend A; not load-bearing.

**Rekor v2 retargeting (Phase 1.5.3 §1, §4).** The witnessing model
is new (post-2025) and the published witness set is itself tracked via
Sigstore TUF. If the TUF integration turns out to need more than a
read-once-cache, Phase 1.5.3 §3 and §4 each grow by ~2 days.
Mitigation: ship Phase 1.5.3 targeting Rekor v2 producers but leave a
`--rekor-version 1` read path for the transition window.

**SP1-SDK build time in the verifier (Phase 1.5.2 §2, §7).** Already
flagged in the existing Cargo comment. Mitigation is the `structural`
Cargo feature — keeps CI fast tier fast, full verifier builds once
per release.

**No PQC or witness-encryption risk:** explicitly out of scope (§3).
The X25519 vendor envelope and BLS time-lock are unchanged by 1.5.x.

---

## 12. Sequencing Recommendation

```
Week 1   Phase 1.5.1          (de-placeholder; ships standalone)
Week 2-3 Phase 1.5.2          (STARK verification; the big rock)
Week 3-4 Phase 1.5.3          (Rekor Merkle + STH; v2-targeted)
Week 4   Phase 1.5.4          (--strict default; warning comes off)
```

Land Phase 1.5.1 on its own — it's a real, shippable, advisable step
that makes today's bundles materially stronger (real key/harness
binding) without waiting for 1.5.2 and 1.5.3. 1.5.2 and 1.5.3 can run
in parallel across two engineers (no shared files except the verifier
`main.rs`, which is naturally splittable into STARK and Rekor
sections). Default `--strict` flip at end of 1.5.4 is the "1.5.x is
complete" signal.

---

## 13. What 1.5.x Does NOT Imply About 1.6+

- **No PQC.** The Groth16/BN254 wrap, drand BLS+IBE time-lock, and
  age X25519 vendor envelope stay classical. Multi-year research
  horizon. Separate proposal.
- **No witness encryption.** GGSW broken; no LWE-based replacement
  deployable today. Separate proposal if/when the construction
  becomes practical.
- **No new target arches.** EVM / WASM beyond ELF are Phase 2 per
  the original design.
- **No expanded scope claim.** The bounded statement in
  `docs/zkpox-scope.md` (what the MVP proves vs doesn't) is
  *unchanged* by 1.5.x. 1.5.x makes the bounded statement
  cryptographically verifiable; it does not enlarge what's being
  claimed.
