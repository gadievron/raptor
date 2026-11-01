//! Bounded, canonical disclosure-CBOR profile shared with the Python encoder.
use anyhow::{bail, ensure, Context, Result};
use ciborium::Value;
use std::{collections::HashSet, fs::OpenOptions, io::Read, path::Path};
pub const MAX_BUNDLE: u64 = 64 * 1024 * 1024;

pub fn read(path: &Path) -> Result<Value> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).context("opening bundle")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "bundle must be a regular file");
    ensure!(metadata.len() <= MAX_BUNDLE, "bundle is too large");
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_BUNDLE, "bundle is too large");
    decode(&bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() as u64 <= MAX_BUNDLE, "bundle is too large");
    let mut value: Value = ciborium::de::from_reader(bytes).context("decoding CBOR")?;
    normalize(&mut value, 0)?;
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded)?;
    ensure!(encoded == bytes, "bundle must use canonical CBOR without trailing data");
    Ok(value)
}
fn normalize(value: &mut Value, depth: usize) -> Result<()> {
    ensure!(depth <= 64, "CBOR nesting exceeds limit");
    match value {
        Value::Map(entries) => {
            let mut keys = HashSet::new();
            for (key, value) in entries.iter_mut() {
                let Value::Text(text) = key else { bail!("CBOR map keys must be text") };
                ensure!(keys.insert(text.clone()), "duplicate CBOR map key");
                normalize(value, depth + 1)?;
            }
            // Text-key CBOR encoding length is monotonic in UTF-8 length;
            // equal-length encodings sort in UTF-8 byte order.
            entries.sort_by(|(a,_),(b,_)| {
                let (Value::Text(a), Value::Text(b)) = (a,b) else { unreachable!() };
                a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes()))
            });
        }
        Value::Array(items) => for item in items { normalize(item, depth + 1)?; },
        Value::Integer(_) | Value::Text(_) | Value::Bytes(_) | Value::Bool(_) | Value::Null => (),
        _ => bail!("unsupported CBOR type in disclosure profile"),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn canonical_map() { assert!(decode(b"\xa1\x61a\x01").is_ok()); }
    #[test] fn duplicate_key() { assert!(decode(b"\xa2\x61a\x01\x61a\x02").is_err()); }
    #[test] fn trailing_data() { assert!(decode(b"\xa1\x61a\x01\x00").is_err()); }
    #[test] fn nonminimal_integer() { assert!(decode(b"\xa1\x61a\x18\x01").is_err()); }
    #[test] fn indefinite_map() { assert!(decode(b"\xbf\x61a\x01\xff").is_err()); }
    #[test] fn noncanonical_order() { assert!(decode(b"\xa2\x61b\x01\x61a\x02").is_err()); }
    #[test] fn floats_rejected() { assert!(decode(b"\xfa\x00\x00\x00\x00").is_err()); }
}
