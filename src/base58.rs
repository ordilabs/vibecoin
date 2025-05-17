// Base58 encoding/decoding implementation inspired by bitcoin-cpp v0.1.5
// Rewritten in Rust.

use base58ck as base58;

/// Encode bytes as a base58 string.
pub fn encode_base58(data: &[u8]) -> String {
    base58::encode(data)
}

/// Decode a base58 string into bytes. Returns `None` on invalid input.
pub fn decode_base58(s: &str) -> Option<Vec<u8>> {
    base58::decode(s).ok()
}

/// Encode data in base58 with a 4-byte checksum.
pub fn encode_base58_check(data: &[u8]) -> String {
    base58::encode_check(data)
}

/// Decode base58 string with checksum verification.
/// Returns `None` if decoding fails or checksum mismatch occurs.
pub fn decode_base58_check(s: &str) -> Option<Vec<u8>> {
    base58::decode_check(s).ok()
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

