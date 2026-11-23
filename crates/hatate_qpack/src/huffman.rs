//! The HPACK static Huffman code used by QPACK (RFC 7541 §5.2, Appendix B).

mod codes;

use crate::InsufficientCapacityError;
use alloc::{collections::TryReserveError, vec::Vec};
use bytes::{Buf, BufMut, Bytes};
use codes::CODES;
use snafu::{ResultExt, Snafu};

/// A Huffman literal could not be decoded into the bounded output buffer.
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
    /// The output buffer could not grow to receive another symbol.
    #[snafu(display("could not grow Huffman output"))]
    ReserveOutput {
        /// Failure to reserve space for the decoded bytes.
        source: TryReserveError,
    },
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
/// A symbol beyond the limit yields [`DecodeError::OutputTooLong`]. If the
/// decoded buffer needs to grow within the limit and reservation fails, the
/// error is [`DecodeError::ReserveOutput`].
pub fn decode(mut src: impl Buf, limit: usize) -> Result<Bytes, DecodeError> {
    let mut output = Vec::new();
    let mut decoder = SymbolDecoder::new(limit);
    while src.has_remaining() {
        let byte = src.get_u8();
        for shift in (0..8).rev() {
            if let Some(symbol) = decoder.bit((byte >> shift) & 1)? {
                if output.len() == output.capacity() {
                    let additional = 1;
                    #[cfg(test)]
                    let additional = tests::reservation_size(additional);
                    output.try_reserve(additional).context(ReserveOutputSnafu)?;
                }
                output.push(symbol);
            }
        }
    }
    decoder.finish()?;
    Ok(Bytes::from(output))
}

// Carries a partial code across encoded input octets and buffer boundaries.
// Only the end of the entire literal is a padding boundary.
//
// Callers stop at the first error, after which the decoder has no meaningful
// state. An error still returns the partial code to the root, so another
// call to `bit` neither indexes past `TREE` nor overflows `tail_bits`.
pub(crate) struct SymbolDecoder {
    node: u16,
    tail_bits: u8,
    tail_is_ones: bool,
    produced: usize,
    limit: usize,
}

impl SymbolDecoder {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            node: 0,
            tail_bits: 0,
            tail_is_ones: true,
            produced: 0,
            limit,
        }
    }

    pub(crate) fn bit(&mut self, bit: u8) -> Result<Option<u8>, DecodeError> {
        self.node = TREE[usize::from(self.node)][usize::from(bit)];
        self.tail_bits += 1;
        self.tail_is_ones &= bit == 1;
        if self.node < LEAF {
            return Ok(None);
        }
        if self.node == EOS {
            self.reset_code();
            return Err(DecodeError::EndOfString);
        }
        if self.produced == self.limit {
            self.reset_code();
            return Err(DecodeError::OutputTooLong { limit: self.limit });
        }
        let symbol = (self.node - LEAF) as u8;
        self.produced += 1;
        self.reset_code();
        Ok(Some(symbol))
    }

    fn reset_code(&mut self) {
        self.node = 0;
        self.tail_bits = 0;
        self.tail_is_ones = true;
    }

    pub(crate) fn finish(&self) -> Result<usize, DecodeError> {
        if self.tail_bits > 7 {
            return Err(DecodeError::ExcessPadding);
        }
        if !self.tail_is_ones {
            return Err(DecodeError::InvalidPadding);
        }
        Ok(self.produced)
    }
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
    for byte in EncodedOctets::new(input) {
        dst.put_u8(byte);
    }
    Ok(())
}

/// The code stream including the final EOS-prefix padding. Used both for
/// standalone encoding and for transferring a complete measured section.
pub(crate) struct EncodedOctets<'a> {
    input: core::slice::Iter<'a, u8>,
    pending: u64,
    bits: u8,
}

impl<'a> EncodedOctets<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self {
            input: input.iter(),
            pending: 0,
            bits: 0,
        }
    }
}

impl Iterator for EncodedOctets<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        while self.bits < 8 {
            let Some(&byte) = self.input.next() else {
                if self.bits == 0 {
                    return None;
                }
                let padding = 8 - self.bits;
                self.bits = 0;
                return Some((self.pending as u8) << padding | ((1 << padding) - 1));
            };
            let (code, width) = CODES[usize::from(byte)];
            self.pending = (self.pending << width) | u64::from(code);
            self.bits += width;
        }
        self.bits -= 8;
        Some((self.pending >> self.bits) as u8)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use bytes::BytesMut;
    use core::cell::Cell;

    // A capacity overflow in try_reserve is deterministic, even for empty
    // vectors. Only the armed test thread changes the next growth request.
    std::thread_local! {
        static FAIL_NEXT_GROWTH: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn reservation_size(additional: usize) -> usize {
        if FAIL_NEXT_GROWTH.replace(false) {
            usize::MAX
        } else {
            additional
        }
    }

    #[test]
    fn failed_growth_reaches_the_independent_name_and_value_readers() {
        use crate::{field_line, string_literal};
        use core::error::Error;

        FAIL_NEXT_GROWTH.set(true);
        let direct = decode(&[0x1f][..], 1).unwrap_err();
        assert!(matches!(direct, DecodeError::ReserveOutput { .. }));
        assert!(direct.source().unwrap().is::<TryReserveError>());

        for (wire, is_name) in [
            (&[0x29, 0x1f, 0][..], true),
            (&[0x40, 0x81, 0x1f][..], false),
        ] {
            FAIL_NEXT_GROWTH.set(true);
            let err = field_line::read_field_line(&mut &*wire, 1).unwrap_err();
            let source = match (is_name, err) {
                (true, field_line::ReadError::Name { source })
                | (false, field_line::ReadError::Value { source }) => source,
                (_, other) => panic!("unexpected error: {other}"),
            };
            assert!(matches!(
                source,
                string_literal::ReadError::Huffman {
                    source: DecodeError::ReserveOutput { .. }
                }
            ));
        }
        FAIL_NEXT_GROWTH.set(true);
        assert_eq!(
            decode(&[0x1f][..], 0),
            Err(DecodeError::OutputTooLong { limit: 0 })
        );
        assert!(FAIL_NEXT_GROWTH.replace(false));
    }

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

    #[test]
    fn a_bit_after_an_error_does_not_index_past_the_tree() {
        // 'a' is the 5-bit code 00011.
        let mut limited = SymbolDecoder::new(0);
        let mut result = Ok(None);
        for bit in [0, 0, 0, 1, 1] {
            result = limited.bit(bit);
        }
        assert_eq!(result, Err(DecodeError::OutputTooLong { limit: 0 }));
        assert_eq!(limited.bit(0), Ok(None));

        // EOS is 30 one bits.
        let mut eos = SymbolDecoder::new(100);
        for _ in 0..29 {
            assert_eq!(eos.bit(1), Ok(None));
        }
        assert_eq!(eos.bit(1), Err(DecodeError::EndOfString));
        assert_eq!(eos.bit(0), Ok(None));

        // Repeated errors would overflow a code length that kept counting.
        let mut repeated = SymbolDecoder::new(100);
        for _ in 0..20 {
            for _ in 0..29 {
                assert_eq!(repeated.bit(1), Ok(None));
            }
            assert_eq!(repeated.bit(1), Err(DecodeError::EndOfString));
        }
    }
}
