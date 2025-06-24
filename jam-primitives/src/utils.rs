//! # SCALE Codec for JAM Protocol
//!

use anyhow::Result;
use parity_scale_codec::{Compact, Decode, Encode, Input};

/// Codec trait combining Encode and Decode (re-exported from parity-scale-codec)
pub trait Codec: Encode + Decode {}

/// Blanket impl for re-use where required
impl<T: Encode + Decode> Codec for T {}

/// Encode a compact u32 (using parity-scale-codec)
pub fn encode_compact_u32(value: u32) -> Vec<u8> {
    Compact(value).encode()
}

/// Decode a compact u32 (using parity-scale-codec)
pub fn decode_compact_u32<I: Input>(input: &mut I) -> Result<u32> {
    let compact = Compact::<u32>::decode(input)?;
    Ok(compact.0)
}

// Basic tests for codec use
#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn test_basic_codec() {
        let value = 42u32;
        let encoded = value.encode();
        let decoded = u32::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_compact_codec() {
        let value = 42u32;
        let encoded = encode_compact_u32(value);
        let decoded = decode_compact_u32(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, value);
    }
}
