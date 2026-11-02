# ZKPoX v2: statement and trust boundaries

The optional SP1 backend proves a canary-observed memory-safety violation in
one of three exact curated C sources. The verifier embeds the expected guest
ELF, derives its verifying key, checks those identities and verifies a genuine
SP1 6.5.0 Groth16 proof. It rejects Core proofs, benign executions presented as
violations, and substitutions of the target, selected predicate or commitment.

The statement is exactly 88 bytes:

| Offset | Encoding | Meaning |
| --- | --- | --- |
| 0 | u32 LE | Statement version: 2 |
| 4 | u32 LE | Target selector: 1, 2 or 3 |
| 8 | u32 LE | Predicate: uniform canary (1) or varying canary (2) |
| 12 | u32 LE | Uniform/varying dirty flags in bits 0/1 |
| 16 | u32 LE | Number of changed bytes in the varying scan |
| 20 | i32 LE | First changed offset; MIN when the varying scan is clean |
| 24 | 32 bytes | Salted witness commitment |
| 56 | 32 bytes | SHA-256 of the exact curated C source |

The hiding commitment is SHA-256 of `raptor-zkpox-witness-v2` followed by a NUL,
target selector (u32 LE), predicate (u32 LE), random 32-byte salt and witness.
The salt and witness are private guest inputs. The public statement deliberately
reveals target/predicate, verdict flags, count and first offset. Public output
omits the raw witness hash and private Tier 0/1 attestation claim.

## What a successful verification means

A valid execution of the embedded guest on some private input produced the
specified statement, and the selected canary scan reported a violation. The
public target source, predicate and commitment match the proven values.
`harness.hash` is SHA-256 of the embedded guest ELF; `verifier_key_hash` uses
`sp1-vk:` because SP1's `bytes32()` identity is not a SHA-256 digest.

It does not establish remote code execution, exploit reliability against an
arbitrary binary, or that the complete upstream libxml2 is vulnerable. Target
03 is a freestanding bug-shape extraction. Native witness reproduction remains
a separate sandboxed Tier 1.5 observation. The uniform predicate's historical
`crash_only` name describes a canary observation, not an operating-system crash.

The canary detector can miss writes that restore the original pattern. A
positive result shows changed redzone bytes; a negative result does not prove
memory safety. The proof inherits SP1/Groth16's cryptographic assumptions,
trusted setup, compiler correctness and correctness of the embedded guest.

## Encryption and delivery

Delivery encrypts `salt || witness` with AES-256-GCM. Its associated data is
`raptor-zkpox-delivery-v2` followed by a NUL and the exact 88-byte statement.
The AES key is wrapped independently to an age recipient and a Drand time lock.

Public verification labels encrypted delivery `encrypted_unchecked`: it cannot
prove that ciphertext decrypts to the committed witness. `open` first verifies
the proof over a private snapshot, decrypts and authenticates the payload, then
recomputes the witness commitment. Only that successful opening establishes
delivery consistency. Replacing an envelope cannot make a substituted witness
pass this check. A dishonest producer can still withhold or corrupt delivery;
this protocol does not contain an encryption-consistency zero-knowledge proof.

## Anchors and authorship

Optional Rekor v2 inclusion uses an explicit endpoint and operator-pinned log
key/origin. Verification authenticates the checkpoint, artifact signature,
commitment to the complete unanchored disclosure and Merkle inclusion. The
entry's artifact signing key is ephemeral: it does not authenticate a researcher's
identity. Researcher metadata is not an authenticated identity claim.

Rekor v2 inclusion is not a timestamp. The implementation does not infer time
from `integratedTime`, a SET, or the client clock. RFC3161 time evidence and
automatic TUF root/service discovery are outside this version's implementation.
Legacy v1 anchors are distinct and cannot be mixed into a v2 inclusion result.

## Parsing and inspection

Both readers require canonical CBOR, text map keys, bounded size/depth and the
same restricted type profile. Duplicate keys, trailing objects, nonminimal
integers, indefinite containers, floats and tags are rejected. Proof decoding
uses bounded bincode with fixed-width integer encoding and rejects trailing
bytes. File readers reject nonregular files to avoid blocking on named pipes.

Inspection reports metadata without verification. A structural-only native
build requires explicit `--inspect` for success; ordinary verification fails
when the cryptographic backend is unavailable. A successful proof verification
never implicitly authenticates optional log evidence or encrypted delivery.
