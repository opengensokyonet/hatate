//! The HPACK static Huffman code used by QPACK (RFC 7541 §5.2, Appendix B).

mod codes;

use crate::InsufficientCapacityError;
use bytes::{Buf, BufMut};
use codes::CODES;
use snafu::Snafu;

/// A Huffman literal could not be decoded within the length limit.
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

/// Decode one complete Huffman payload into at most `limit` bytes, collected
/// in `H` (for example `Vec<u8>` or `BytesMut`). Checks the EOS and padding
/// rules even for a partial final octet. A symbol beyond the limit yields
/// [`DecodeError::OutputTooLong`]; `H` never receives more than `limit`
/// octets. `H` grows through [`Extend`], which does not report allocation
/// failure.
pub fn decode<H: Default + Extend<u8>>(src: impl Buf, limit: usize) -> Result<H, DecodeError> {
    decode_counted(src, limit).map(|(output, _)| output)
}

/// [`decode`], also returning the number of decoded octets.
pub(crate) fn decode_counted<H: Default + Extend<u8>>(
    mut src: impl Buf,
    limit: usize,
) -> Result<(H, usize), DecodeError> {
    let mut output = H::default();
    let mut decoder = SymbolDecoder::new(limit);
    // Hand symbols over in batches rather than one `extend` call each.
    let mut batch = [0; 64];
    let mut filled = 0;
    while src.has_remaining() {
        let byte = src.get_u8();
        for shift in (0..8).rev() {
            if let Some(symbol) = decoder.bit((byte >> shift) & 1)? {
                batch[filled] = symbol;
                filled += 1;
                if filled == batch.len() {
                    output.extend(batch.iter().copied());
                    filled = 0;
                }
            }
        }
    }
    let produced = decoder.finish()?;
    output.extend(batch[..filled].iter().copied());
    Ok((output, produced))
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

/// The encoded payload length, including its final padding. A buffer on a
/// 64-bit target can have more bits in its encoding than fit in a u64.
pub(crate) fn encoded_len(mut src: impl Buf) -> u128 {
    let mut bits = 0u128;
    while src.has_remaining() {
        let chunk = src.chunk();
        bits += chunk
            .iter()
            .map(|&byte| u128::from(CODES[usize::from(byte)].1))
            .sum::<u128>();
        let count = chunk.len();
        src.advance(count);
    }
    bits.div_ceil(8)
}

/// Encode the octets of `src` with the RFC 7541 code and pad to an octet
/// boundary. An undersized destination is left unchanged. The string length
/// prefix and H bit belong to the enclosing format.
pub fn encode(dst: &mut impl BufMut, src: impl Buf) -> Result<(), InsufficientCapacityError> {
    // Every symbol takes at most 30 bits. A growing sink generally satisfies
    // this bound without a separate pass to count the exact encoded length.
    let available = dst.remaining_mut();
    if (src.remaining() as u128 * 30).div_ceil(8) <= available as u128 {
        let mut octets = Encoder::new(src);
        while let Some(octet) = octets.next_octet() {
            dst.put_u8(octet);
        }
        return Ok(());
    }
    // Measuring consumes the input, so take it as shared bytes first:
    // without a copy if it already is `Bytes`.
    let mut src = src;
    let src = src.copy_to_bytes(src.remaining());
    let length = encoded_len(src.clone());
    InsufficientCapacityError::check(length, available)?;
    dst.put(EncodedBuf::new(src, length as u64));
    Ok(())
}

/// The code stream of a buffer, including the final EOS-prefix padding.
struct Encoder<B> {
    src: B,
    pending: u64,
    bits: u8,
}

impl<B: Buf> Encoder<B> {
    fn new(src: B) -> Self {
        Self {
            src,
            pending: 0,
            bits: 0,
        }
    }

    fn next_octet(&mut self) -> Option<u8> {
        while self.bits < 8 {
            if !self.src.has_remaining() {
                if self.bits == 0 {
                    return None;
                }
                let padding = 8 - self.bits;
                self.bits = 0;
                return Some((self.pending as u8) << padding | ((1 << padding) - 1));
            }
            let (code, width) = CODES[usize::from(self.src.get_u8())];
            self.pending = (self.pending << width) | u64::from(code);
            self.bits += width;
        }
        self.bits -= 8;
        Some((self.pending >> self.bits) as u8)
    }
}

/// The encoding of a buffer whose encoded length was measured beforehand,
/// as a [`Buf`] for one transfer into a destination.
///
/// It yields exactly the measured number of octets. A buffer whose octets
/// changed since it was measured yields different content, but neither more
/// nor fewer octets: excess output is dropped, and missing output is filled
/// with all-ones octets.
pub(crate) struct EncodedBuf<B> {
    encoder: Encoder<B>,
    out: [u8; 64],
    start: u8,
    end: u8,
    left: u64,
}

impl<B: Buf> EncodedBuf<B> {
    pub(crate) fn new(src: B, encoded_len: u64) -> Self {
        let mut buf = Self {
            encoder: Encoder::new(src),
            out: [0; 64],
            start: 0,
            end: 0,
            left: encoded_len,
        };
        buf.refill();
        buf
    }

    fn refill(&mut self) {
        self.start = 0;
        self.end = 0;
        while self.left > 0 && usize::from(self.end) < self.out.len() {
            self.out[usize::from(self.end)] = self.encoder.next_octet().unwrap_or(0xff);
            self.end += 1;
            self.left -= 1;
        }
    }
}

impl<B: Buf> Buf for EncodedBuf<B> {
    fn remaining(&self) -> usize {
        let buffered = u64::from(self.end - self.start);
        usize::try_from(self.left + buffered).unwrap_or(usize::MAX)
    }

    fn chunk(&self) -> &[u8] {
        &self.out[usize::from(self.start)..usize::from(self.end)]
    }

    fn advance(&mut self, mut count: usize) {
        while count > 0 {
            let buffered = usize::from(self.end - self.start);
            assert!(buffered > 0, "advance past the encoded octets");
            let step = count.min(buffered);
            self.start += step as u8;
            count -= step;
            if self.start == self.end {
                self.refill();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use bytes::BytesMut;

    fn decode_vec(src: impl Buf, limit: usize) -> Result<Vec<u8>, DecodeError> {
        decode(src, limit)
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
            assert_eq!(decode_vec(encoded, plain.len()).unwrap(), plain);
        }
    }

    #[test]
    fn all_octets_individually_and_consecutively() {
        let mut alphabet = [0; 256];
        for byte in 0..=255u8 {
            alphabet[usize::from(byte)] = byte;
            let mut encoded = BytesMut::new();
            encode(&mut encoded, &[byte][..]).unwrap();
            assert_eq!(decode_vec(encoded.freeze(), usize::MAX).unwrap(), [byte]);
        }
        let mut encoded = BytesMut::new();
        encode(&mut encoded, &alphabet[..]).unwrap();
        assert_eq!(decode_vec(encoded.freeze(), usize::MAX).unwrap(), alphabet);
    }

    #[test]
    fn measured_encoding_yields_exactly_its_length() {
        let plain = &b"www.example.com"[..];
        let mut whole = Vec::new();
        encode(&mut whole, plain).unwrap();
        let collect = |mut buf: EncodedBuf<&[u8]>| {
            let mut out = Vec::new();
            while buf.has_remaining() {
                let chunk = buf.chunk();
                assert!(!chunk.is_empty());
                out.extend_from_slice(chunk);
                let count = chunk.len();
                buf.advance(count);
            }
            out
        };
        assert_eq!(collect(EncodedBuf::new(plain, 12)), whole);
        // Longer than one internal chunk.
        let long = [b'a'; 1000];
        let mut expected = Vec::new();
        encode(&mut expected, &long[..]).unwrap();
        let buf = EncodedBuf::new(&long[..], expected.len() as u64);
        assert_eq!(buf.remaining(), expected.len());
        assert_eq!(collect(buf), expected);
        // A source that changed after measuring keeps the measured length.
        assert_eq!(collect(EncodedBuf::new(plain, 10)), whole[..10]);
        let padded = collect(EncodedBuf::new(plain, 14));
        assert_eq!(
            (&padded[..12], &padded[12..]),
            (&whole[..], &[0xff, 0xff][..])
        );
    }

    #[test]
    fn rejects_eos_and_invalid_or_excess_fill() {
        assert_eq!(
            decode_vec(&[0xff; 4][..], usize::MAX),
            Err(DecodeError::EndOfString)
        );
        assert_eq!(
            decode_vec(&[0xff][..], usize::MAX),
            Err(DecodeError::ExcessPadding)
        );
        assert_eq!(
            decode_vec(&[0x18][..], usize::MAX),
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
