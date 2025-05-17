// Base58 encoding/decoding implementation inspired by bitcoin-cpp v0.1.5
// Rewritten in Rust.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes as a base58 string.
pub fn encode_base58(data: &[u8]) -> String {
    // Count leading zeros.
    let zeros = data.iter().take_while(|b| **b == 0).count();
    // Allocate enough space in big-endian base58 representation.
    let mut digits = vec![0u8; data.len() * 138 / 100 + 1];
    let mut length = 0usize;

    for byte in &data[zeros..] {
        let mut carry = *byte as u32;
        let mut i = 0usize;
        for d in digits[..length].iter_mut().rev() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
            i += 1;
        }
        while carry > 0 {
            digits[length] = (carry % 58) as u8;
            length += 1;
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(zeros + length);
    for _ in 0..zeros {
        result.push('1');
    }
    for d in digits[..length].iter().rev() {
        result.push(ALPHABET[*d as usize] as char);
    }
    result
}

/// Decode a base58 string into bytes. Returns `None` on invalid input.
pub fn decode_base58(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_start();
    if s.is_empty() {
        return Some(Vec::new());
    }
    let bytes = s.as_bytes();
    let zeros = bytes.iter().take_while(|&&b| b == ALPHABET[0]).count();
    let mut b256 = vec![0u8; s.len() * 733 / 1000 + 1];
    let mut length = 0usize;

    for &ch in &bytes[zeros..] {
        let val = match ALPHABET.iter().position(|&c| c == ch) {
            Some(v) => v as u32,
            None => return None,
        };
        let mut carry = val;
        for d in b256[..length].iter_mut().rev() {
            carry += (*d as u32) * 58;
            *d = (carry % 256) as u8;
            carry /= 256;
        }
        while carry > 0 {
            b256[length] = (carry % 256) as u8;
            length += 1;
            carry /= 256;
        }
    }

    let mut result = Vec::with_capacity(zeros + length);
    result.extend(std::iter::repeat(0u8).take(zeros));
    for b in b256[..length].iter().rev() {
        result.push(*b);
    }
    Some(result)
}

/// Compute double SHA256 (sha256d) of the data.
fn sha256d(data: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256d, Hash};
    let hash = sha256d::Hash::hash(data);
    hash.into_inner()
}

/// Encode data in base58 with a 4-byte checksum.
pub fn encode_base58_check(data: &[u8]) -> String {
    let checksum = sha256d(data);
    let mut extended = Vec::with_capacity(data.len() + 4);
    extended.extend_from_slice(data);
    extended.extend_from_slice(&checksum[0..4]);
    encode_base58(&extended)
}

/// Decode base58 string with checksum verification.
/// Returns `None` if decoding fails or checksum mismatch occurs.
pub fn decode_base58_check(s: &str) -> Option<Vec<u8>> {
    let mut data = decode_base58(s)?;
    if data.len() < 4 {
        return None;
    }
    let checksum = sha256d(&data[..data.len() - 4]);
    if checksum[0..4] != data[data.len() - 4..] {
        return None;
    }
    data.truncate(data.len() - 4);
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_hello_world() {
        let encoded = encode_base58(b"hello world");
        assert_eq!(encoded, "StV1DL6CwTryKyV");
    }

    #[test]
    fn roundtrip_base58_check() {
        let data = b"rust-base58";
        let enc = encode_base58_check(data);
        let dec = decode_base58_check(&enc).expect("decode failed");
        assert_eq!(dec, data);
    }
}

