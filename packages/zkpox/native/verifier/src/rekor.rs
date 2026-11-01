// The Phase 1.5.3 primitives below are exercised by the inline
// ``#[cfg(test)]`` block — they're correct and pinned by tests — but
// not yet called from the verifier's main flow. That integration
// is the Phase 1.5.3.x follow-up (waiting on the bundle schema
// extension to carry the Rekor entry body bytes; without those, the
// standalone verifier can't reconstruct the leaf hash on its own).
// Until that lands, suppress the dead-code lint at the module level
// so the structural / full-verify builds stay clean. The lint will
// silently start firing again once 1.5.3.x wires these in and the
// allow becomes vestigial — at which point delete this attribute.
#![allow(dead_code)]

//! Phase 1.5.3 — Rekor Merkle inclusion-proof verification (RFC 6962).
//!
//! Mirrors ``packages/zkpox/anchor.verify_inclusion_proof``: pure
//! sha2 walk, no new crate deps. Same Trillian-shaped algorithm,
//! same domain prefixes (``0x00`` for leaves, ``0x01`` for nodes).
//! The two implementations are pinned to agree by a shared golden
//! test vector (see ``tests/`` and the Python ``test_anchor.py``).
//!
//! What this module does NOT cover (yet):
//!   - Reading the leaf bytes from the bundle. The Phase 1.5.3
//!     ``DisclosureBundle.Timestamp`` doesn't carry the Rekor entry
//!     body, so the standalone offline verifier can't run inclusion
//!     verify end-to-end from a bundle alone. That schema extension
//!     is reserved for Phase 1.5.3.x; until then the verify primitive
//!     here is exercised via the unit tests + the Python integration.
//!   - SET signature verification. Adds another crate dep
//!     (ed25519-dalek / p256); deferred to Phase 1.5.3.x.

use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum InclusionProofError {
    OutOfRange { index: u64, tree_size: u64 },
    BadAuditEntry { len: usize },
    BadRoot { len: usize },
    PathTooLong { consumed: usize },
    PathTooShort { sn: u64, consumed: usize },
}

impl fmt::Display for InclusionProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { index, tree_size } => write!(
                f,
                "log_index {index} out of range for tree_size {tree_size}",
            ),
            Self::BadAuditEntry { len } => {
                write!(f, "audit path entry is not a 32-byte sha256 (len={len})")
            }
            Self::BadRoot { len } => {
                write!(f, "expected_root is not a 32-byte sha256 (len={len})")
            }
            Self::PathTooLong { consumed } => write!(
                f,
                "audit path longer than tree depth (consumed {consumed} before tree exhausted)",
            ),
            Self::PathTooShort { sn, consumed } => write!(
                f,
                "audit path shorter than tree depth (sn={sn} after consuming {consumed})",
            ),
        }
    }
}

impl std::error::Error for InclusionProofError {}

/// sha256(0x00 || leaf_bytes) — the RFC 6962 leaf-hash domain.
pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(leaf);
    h.finalize().into()
}

/// sha256(0x01 || left || right) — the RFC 6962 inner-node domain.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verify an RFC 6962 Merkle audit path against a claimed root.
///
/// Returns ``Ok(true)`` iff the path reconstructs to ``expected_root``;
/// ``Ok(false)`` on a structurally-valid but non-matching proof
/// (tampered path / wrong leaf / wrong root). Returns ``Err`` on a
/// malformed input (out-of-range index, wrong-sized hashes, path
/// length disagreeing with the tree depth implied by ``tree_size``).
///
/// Trillian-shaped walk: ``fn`` = current path index; ``sn`` = last
/// index at the current level. The inner promote-loop after a left-
/// sibling hash handles odd-sized subtrees where the just-computed
/// node has no right sibling and propagates unchanged.
pub fn verify_inclusion_proof(
    leaf: &[u8],
    log_index: u64,
    tree_size: u64,
    audit_path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<bool, InclusionProofError> {
    if tree_size == 0 || log_index >= tree_size {
        return Err(InclusionProofError::OutOfRange {
            index: log_index,
            tree_size,
        });
    }
    let mut fn_ = log_index;
    let mut sn = tree_size - 1;
    let mut current = leaf_hash(leaf);
    let mut consumed: usize = 0;
    for p in audit_path {
        if sn == 0 {
            return Err(InclusionProofError::PathTooLong { consumed });
        }
        if fn_ & 1 == 1 || fn_ == sn {
            current = node_hash(p, &current);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            current = node_hash(&current, p);
        }
        fn_ >>= 1;
        sn >>= 1;
        consumed += 1;
    }
    if sn != 0 {
        return Err(InclusionProofError::PathTooShort { sn, consumed });
    }
    Ok(&current == expected_root)
}

// ---------------------------------------------------------------------------
// Tests — small synthetic trees + RFC-6962 vector parity with Python.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Recursive RFC 6962 tree builder mirroring the Python reference
    /// in ``test_anchor.py``. Returns (root, audit_path_for_idx).
    fn build_tree(leaves: &[&[u8]], idx: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();
        recurse(&hashes, idx)
    }

    fn recurse(level: &[[u8; 32]], idx: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        if level.len() == 1 {
            return (level[0], vec![]);
        }
        // Split at largest power of 2 strictly less than n.
        let mut k: usize = 1;
        while k * 2 < level.len() {
            k *= 2;
        }
        let (left, right) = level.split_at(k);
        if idx < k {
            let (lh, mut lp) = recurse(left, idx);
            let (rh, _) = recurse(right, 0);
            lp.push(rh);
            (node_hash(&lh, &rh), lp)
        } else {
            let (lh, _) = recurse(left, 0);
            let (rh, mut rp) = recurse(right, idx - k);
            rp.push(lh);
            (node_hash(&lh, &rh), rp)
        }
    }

    #[test]
    fn verifies_every_leaf_across_tree_sizes() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 11, 23] {
            let leaves_owned: Vec<Vec<u8>> = (0..n)
                .map(|i| format!("leaf-{i}").into_bytes())
                .collect();
            let leaves: Vec<&[u8]> = leaves_owned.iter().map(|v| v.as_slice()).collect();
            for i in 0..n {
                let (root, path) = build_tree(&leaves, i);
                let ok = verify_inclusion_proof(
                    leaves[i],
                    i as u64,
                    n as u64,
                    &path,
                    &root,
                )
                .expect("structurally valid proof");
                assert!(ok, "n={n} i={i}");
            }
        }
    }

    #[test]
    fn rejects_tampered_path() {
        let leaves_owned: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let leaves: Vec<&[u8]> = leaves_owned.iter().map(|v| v.as_slice()).collect();
        let (root, mut path) = build_tree(&leaves, 2);
        assert!(!path.is_empty());
        path[0] = [0u8; 32];
        let ok = verify_inclusion_proof(leaves[2], 2, 5, &path, &root).unwrap();
        assert!(!ok, "tampered path[0] must NOT verify");
    }

    #[test]
    fn rejects_tampered_leaf() {
        let leaves_owned: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let leaves: Vec<&[u8]> = leaves_owned.iter().map(|v| v.as_slice()).collect();
        let (root, path) = build_tree(&leaves, 2);
        let ok = verify_inclusion_proof(b"different", 2, 5, &path, &root).unwrap();
        assert!(!ok, "tampered leaf must NOT verify");
    }

    #[test]
    fn out_of_range_index_errors() {
        let leaves_owned: Vec<Vec<u8>> = (0..4)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let leaves: Vec<&[u8]> = leaves_owned.iter().map(|v| v.as_slice()).collect();
        let (root, path) = build_tree(&leaves, 0);
        let r = verify_inclusion_proof(leaves[0], 4, 4, &path, &root);
        assert!(matches!(r, Err(InclusionProofError::OutOfRange { .. })));
    }
}
