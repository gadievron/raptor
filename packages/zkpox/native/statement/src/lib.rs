//! Shared, fixed-width public statement. No host/guest serde ambiguity.
#![no_std]
use sha2::{Digest, Sha256};

pub const VERSION: u32 = 2;
pub const PUBLIC_LEN: usize = 88;
pub const INPUT_HEADER_LEN: usize = 44;
pub const MAX_WITNESS: usize = 1024 * 1024;
pub const COMMIT_DOMAIN: &[u8] = b"raptor-zkpox-witness-v2\0";
pub const SYSTEM: &str = "sp1-groth16/6.5.0";

pub fn target_source(target: u32) -> Result<&'static [u8], &'static str> {
    match target {
        1 => Ok(include_bytes!("../../targets/01-stack-bof.c")),
        2 => Ok(include_bytes!("../../targets/02-off-by-one.c")),
        3 => Ok(include_bytes!("../../targets/03-libxml2-cve-2017-9047.c")),
        _ => Err("unsupported target selector"),
    }
}
pub fn target_hash(target: u32) -> Result<[u8; 32], &'static str> {
    Ok(Sha256::digest(target_source(target)?).into())
}
pub fn commitment(target: u32, gadget: u32, salt: &[u8; 32], witness: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    h.update(target.to_le_bytes());
    h.update(gadget.to_le_bytes());
    h.update(salt);
    h.update(witness);
    h.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub target: u32,
    pub gadget: u32,
    pub flags: u32,
    pub count: u32,
    pub first_offset: i32,
    pub witness_commitment: [u8; 32],
    pub target_hash: [u8; 32],
}
impl Statement {
    pub fn encode(&self) -> [u8; PUBLIC_LEN] {
        let mut out = [0; PUBLIC_LEN];
        for (i, value) in [VERSION, self.target, self.gadget, self.flags, self.count,
                           self.first_offset as u32].iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        out[24..56].copy_from_slice(&self.witness_commitment);
        out[56..88].copy_from_slice(&self.target_hash);
        out
    }
    pub fn decode(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() != PUBLIC_LEN { return Err("incorrect public statement length"); }
        let word = |i: usize| u32::from_le_bytes(raw[i*4..i*4+4].try_into().unwrap());
        if word(0) != VERSION { return Err("unsupported statement version"); }
        Ok(Self {target: word(1), gadget: word(2), flags: word(3), count: word(4),
                 first_offset: word(5) as i32,
                 witness_commitment: raw[24..56].try_into().unwrap(),
                 target_hash: raw[56..88].try_into().unwrap()})
    }
    /// A valid execution proof alone is insufficient: require the claimed violation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.target_hash != target_hash(self.target)? { return Err("target source hash mismatch"); }
        if self.flags & !3 != 0 { return Err("unknown verdict flags"); }
        let positive = match self.gadget {
            1 => self.flags & 1 != 0,
            2 => self.flags & 2 != 0,
            _ => return Err("unsupported gadget selector"),
        };
        if !positive { return Err("execution did not demonstrate the claimed violation"); }
        // Count/offset describe the varying-pattern scan (flag 2), independently
        // of which predicate was requested. The uniform scan can differ.
        let varying = self.flags & 2 != 0;
        let buf_size = if self.target == 3 { 32 } else { 16 };
        if varying {
            if self.count == 0 || self.count > MAX_WITNESS as u32 + 64
                || self.first_offset < -16 || self.first_offset >= MAX_WITNESS as i32 + 64
                || (self.first_offset >= 0 && self.first_offset < buf_size) {
                return Err("inconsistent violation count/offset");
            }
        } else if self.count != 0 || self.first_offset != i32::MIN {
            return Err("inconsistent clean count/offset");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn positive() -> Statement {
        Statement {target:1,gadget:2,flags:3,count:1,first_offset:16,
                   witness_commitment:[7;32],target_hash:target_hash(1).unwrap()}
    }
    #[test] fn roundtrip() { let s=positive(); assert_eq!(Statement::decode(&s.encode()).unwrap(),s); }
    #[test] fn rejects_benign() { let mut s=positive();s.flags=0;s.count=0;s.first_offset=i32::MIN;assert!(s.validate().is_err()); }
    #[test] fn rejects_relabelled_target() {let mut s=positive();s.target=3;assert!(s.validate().is_err());}
    #[test] fn rejects_wrong_gadget() {let mut s=positive();s.gadget=99;assert!(s.validate().is_err());}
    #[test] fn rejects_inside_offset() {let mut s=positive();s.first_offset=0;assert!(s.validate().is_err());}
    #[test] fn rejects_trailing_bytes() {let mut raw=positive().encode().to_vec();raw.push(0);assert!(Statement::decode(&raw).is_err());}
    #[test] fn commitment_is_bound() {assert_ne!(commitment(1,2,&[1;32],b"a"),commitment(1,2,&[1;32],b"b"));assert_ne!(commitment(1,2,&[1;32],b"a"),commitment(2,2,&[1;32],b"a"));}
}
