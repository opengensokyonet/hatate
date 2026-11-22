//! The HPACK static Huffman code used by QPACK (RFC 7541 §5.2, Appendix B).

mod codes;

use crate::InsufficientCapacityError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use codes::CODES;
use snafu::Snafu;

/// A Huffman literal violates its code or the supplied output limit.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum DecodeError {
    /// The reserved EOS symbol occurred in the input.
    #[snafu(display("Huffman data contains the EOS symbol"))]
    EndOfString,
    /// More than seven bits remained after the last symbol.
    #[snafu(display("Huffman padding exceeds seven bits"))]
    ExcessPadding,
    /// The trailing bits differ from the leading bits of EOS.
    #[snafu(display("Huffman padding differs from the EOS prefix"))]
    InvalidPadding,
    /// Another symbol would exceed the maximum decoded length.
    #[snafu(display("Huffman output exceeds {limit} bytes"))]
    OutputTooLong {
        /// Maximum allowed decoded length.
        limit: usize,
    },
}

// The complete binary code has 257 leaves and thus 256 internal nodes.
// Values below LEAF address an internal node; the others identify a symbol.
const LEAF: u16 = 256;
const EOS: u16 = LEAF + 256;

static TREE: [[u16; 2]; LEAF as usize] = {
    let mut tree = [[0; 2]; LEAF as usize];
    let mut next = 1;
    let mut symbol = 0;
    while symbol < CODES.len() {
        let (code, mut bits) = CODES[symbol];
        let mut node = 0;
        while bits > 0 {
            bits -= 1;
            let bit = ((code >> bits) & 1) as usize;
            let child = &mut tree[node][bit];
            if bits == 0 {
                assert!(*child == 0);
                *child = LEAF + symbol as u16;
            } else {
                if *child == 0 {
                    *child = next;
                    next += 1;
                }
                node = *child as usize;
            }
        }
        symbol += 1;
    }
    assert!(next == LEAF);
    tree
};

/// Decode one complete Huffman payload into at most `limit` bytes.
/// Checks the EOS and padding rules even for a partial final octet.
pub fn decode(mut src: impl Buf, limit: usize) -> Result<Bytes, DecodeError> {
    let mut output = BytesMut::new();
    let mut node = 0;
    let mut tail_bits = 0;
    let mut tail_is_ones = true;
    while src.has_remaining() {
        let byte = src.get_u8();
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            node = TREE[usize::from(node)][usize::from(bit)];
            tail_bits += 1;
            tail_is_ones &= bit == 1;
            if node >= LEAF {
                if node == EOS {
                    return Err(DecodeError::EndOfString);
                }
                if output.len() == limit {
                    return Err(DecodeError::OutputTooLong { limit });
                }
                output.put_u8((node - LEAF) as u8);
                node = 0;
                tail_bits = 0;
                tail_is_ones = true;
            }
        }
    }
    if tail_bits > 7 {
        return Err(DecodeError::ExcessPadding);
    }
    if !tail_is_ones {
        return Err(DecodeError::InvalidPadding);
    }
    Ok(output.freeze())
}

/// The encoded payload length, including its final padding. A slice on a
/// 64-bit target can have more bits in its encoding than fit in a u64.
pub(crate) fn encoded_len(input: &[u8]) -> u128 {
    input
        .iter()
        .map(|&byte| u128::from(CODES[usize::from(byte)].1))
        .sum::<u128>()
        .div_ceil(8)
}

/// Encode octets with the RFC 7541 code and pad to an octet boundary.
/// An undersized destination is left unchanged. The string length prefix
/// and H bit belong to the enclosing format.
pub fn encode(dst: &mut impl BufMut, input: &[u8]) -> Result<(), InsufficientCapacityError> {
    // Every symbol takes at most 30 bits. A growing sink generally satisfies
    // this bound without a separate pass to count the exact encoded length.
    let available = dst.remaining_mut();
    if (input.len() as u128 * 30).div_ceil(8) > available as u128 {
        InsufficientCapacityError::check(encoded_len(input), available)?;
    }
    let mut pending = 0u64;
    let mut bits = 0;
    for &byte in input {
        let (code, width) = CODES[usize::from(byte)];
        // At most seven pending bits precede a code of at most 30 bits.
        pending = (pending << width) | u64::from(code);
        bits += width;
        while bits >= 8 {
            bits -= 8;
            dst.put_u8((pending >> bits) as u8);
        }
    }
    if bits > 0 {
        let padding = 8 - bits;
        dst.put_u8((pending as u8) << padding | ((1 << padding) - 1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appendix_c_strings() {
        let vectors: &[(&[u8], &[u8])] = &[
            (
                b"www.example.com",
                &[
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ],
            ),
            (b"no-cache", &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
            (
                b"custom-key",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
            ),
            (
                b"custom-value",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            ),
            (b"", &[]),
        ];
        for &(plain, encoded) in vectors {
            let mut output = BytesMut::new();
            encode(&mut output, plain).unwrap();
            assert_eq!(&output[..], encoded);
            assert_eq!(&decode(encoded, plain.len()).unwrap()[..], plain);
        }
    }

    #[test]
    fn all_octets_individually_and_consecutively() {
        let mut alphabet = [0; 256];
        for byte in 0..=255u8 {
            alphabet[usize::from(byte)] = byte;
            let mut encoded = BytesMut::new();
            encode(&mut encoded, &[byte]).unwrap();
            assert_eq!(&decode(encoded.freeze(), usize::MAX).unwrap()[..], &[byte]);
        }
        let mut encoded = BytesMut::new();
        encode(&mut encoded, &alphabet).unwrap();
        assert_eq!(
            &decode(encoded.freeze(), usize::MAX).unwrap()[..],
            &alphabet
        );
    }

    #[test]
    fn rejects_eos_and_invalid_or_excess_fill() {
        assert_eq!(
            decode(&[0xff; 4][..], usize::MAX),
            Err(DecodeError::EndOfString)
        );
        assert_eq!(
            decode(&[0xff][..], usize::MAX),
            Err(DecodeError::ExcessPadding)
        );
        assert_eq!(
            decode(&[0x18][..], usize::MAX),
            Err(DecodeError::InvalidPadding)
        );
    }
}
