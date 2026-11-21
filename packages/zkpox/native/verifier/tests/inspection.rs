//! A structural build must never report an unverified proof as verified.
#![cfg(not(feature = "full-verify"))]
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

fn text(value: &str) -> Value { Value::Text(value.into()) }
fn map(entries: Vec<(&str, Value)>) -> Value {
    let mut entries: Vec<_> = entries.into_iter().map(|(key, value)| (text(key), value)).collect();
    entries.sort_by(|(a,_),(b,_)| {
        let (Value::Text(a), Value::Text(b)) = (a,b) else { unreachable!() };
        a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });
    Value::Map(entries)
}
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(self.0.parent().unwrap()); }
}
fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!("zkpox-inspect-test-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("bundle.cbor");
    let empty = Value::Bytes(vec![]);
    let hash = format!("sha256:{}", hex::encode(zkpox_statement::target_hash(1).unwrap()));
    let fingerprint = format!("sha256:{:x}", Sha256::digest(b""));
    let value = map(vec![
        ("version", text("zkpox-2.0")),
        ("target", map(vec![("kind", text("source")), ("hash", text(&hash))])),
        ("vulnerability", map(vec![("class", text("memory-safety")), ("gadget_id", text("oob_write")), ("gadget_id_hash", text("sha256:identifier"))])),
        ("proof", map(vec![("system", text(zkpox_statement::SYSTEM)), ("bytes", Value::Bytes(b"not-a-proof".to_vec())), ("verifier_key_hash", text(&format!("sp1-vk:{}", "00".repeat(32))))])),
        ("harness", map(vec![("hash", text(&format!("sha256:{}", "00".repeat(32))))])),
        ("vendor_envelope", map(vec![("scheme", text("zkpox-none/v2")), ("aes_blob", empty.clone()), ("ct_K_age", empty.clone()), ("ct_K_tlock", empty), ("vendor_pubkey", text("")), ("vendor_pubkey_fingerprint", text(&fingerprint))])),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    fs::write(&path, bytes).unwrap();
    Fixture(path)
}
#[test]
fn structural_default_rejects_unverified_proof() {
    let fixture = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_zkpox-verify")).arg(&fixture.0).arg("--json").output().unwrap();
    assert!(!output.status.success());
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["proof_verification_status"], "not_verified");
}
#[test]
fn explicit_inspection_reports_not_verified() {
    let fixture = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_zkpox-verify")).arg(&fixture.0).args(["--inspect", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["proof_verification_status"], "not_verified");
}
