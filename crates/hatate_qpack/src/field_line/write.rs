use super::{FieldLine, StringLiteral, TableIndex};
use crate::{InsufficientCapacityError, huffman, integer};
use bytes::{Buf, BufMut};
use core::num::TryFromIntError;
use snafu::{ResultExt, Snafu};

/// A field line cannot be written to the given destination.
#[derive(Debug, Snafu)]
pub enum WriteError {
    /// The exact wire size exceeds the available capacity.
    #[snafu(transparent)]
    InsufficientCapacity {
        /// Exact required and available capacities in octets.
        source: InsufficientCapacityError,
    },
    /// The encoded literal name length exceeds u64::MAX.
    #[snafu(display("encoded field name length exceeds the supported prefixed integer range"))]
    NameLengthOverflow {
        /// Failure to represent the encoded length as a u64.
        source: TryFromIntError,
    },
    /// The encoded literal value length exceeds u64::MAX.
    #[snafu(display("encoded field value length exceeds the supported prefixed integer range"))]
    ValueLengthOverflow {
        /// Failure to represent the encoded length as a u64.
        source: TryFromIntError,
    },
}

// Each representation is either a single prefixed integer or two prefixed
// integers with their associated payloads. Measuring their wire sizes lets
// a bounded sink reject the whole line before writing its first byte.
struct Part<'a> {
    prefix: [u8; integer::MAX_ENCODED_LEN],
    prefix_len: usize,
    payload: StringLiteral<&'a [u8], &'a [u8]>,
    payload_len: u64,
}

impl<'a> Part<'a> {
    fn integer<const N: u8>(flags: u8, value: u64) -> Self {
        let mut prefix = [0; integer::MAX_ENCODED_LEN];
        let mut rest = &mut prefix[..];
        integer::write::<N>(&mut rest, flags, value)
            .expect("the prefix buffer fits every encoded u64");
        let prefix_len = integer::MAX_ENCODED_LEN - rest.len();
        Self {
            prefix,
            prefix_len,
            payload: StringLiteral::Raw(&[]),
            payload_len: 0,
        }
    }

    fn literal<const N: u8, S: AsRef<[u8]>, H: AsRef<[u8]>>(
        flags: u8,
        literal: &'a StringLiteral<S, H>,
        encoded_len: impl FnOnce(&[u8]) -> u128,
    ) -> Result<Self, TryFromIntError> {
        let (flags, payload, length) = match literal {
            StringLiteral::Raw(data) => {
                let data = data.as_ref();
                (flags, StringLiteral::Raw(data), data.len() as u64)
            }
            StringLiteral::Huffman(data) => {
                let data = data.as_ref();
                let length = u64::try_from(encoded_len(data))?;
                (flags | (1 << N), StringLiteral::Huffman(data), length)
            }
        };
        Ok(Self {
            payload,
            payload_len: length,
            ..Self::integer::<N>(flags, length)
        })
    }

    fn len(&self) -> u128 {
        self.prefix_len as u128 + u128::from(self.payload_len)
    }

    fn octets(self) -> impl Iterator<Item = u8> + 'a {
        let (raw, coded) = match self.payload {
            StringLiteral::Raw(data) => (data, &[][..]),
            StringLiteral::Huffman(data) => (&[][..], data),
        };
        self.prefix
            .into_iter()
            .take(self.prefix_len)
            .chain(raw.iter().copied())
            .chain(huffman::EncodedOctets::new(coded))
    }
}

/// Write one field line using the given references, N bit and string coding.
/// Integer encodings use the shortest representation. Errors leave the
/// destination unchanged, including when a fixed-size buffer is too small.
pub fn write_field_line<S: AsRef<[u8]>, H: AsRef<[u8]>>(
    dst: &mut impl BufMut,
    line: &FieldLine<S, H>,
) -> Result<(), WriteError> {
    let prepared = Prepared::new(line)?;
    transfer(dst, prepared.len(), prepared.octets())?;
    Ok(())
}

// Borrow the exact payloads used for measuring this representation. This
// also lets a whole-section writer prepare each AsRef payload just once.
pub(crate) struct Prepared<'a> {
    head: Part<'a>,
    value: Option<Part<'a>>,
}

impl<'a> Prepared<'a> {
    pub(crate) fn new<S: AsRef<[u8]>, H: AsRef<[u8]>>(
        line: &'a FieldLine<S, H>,
    ) -> Result<Self, WriteError> {
        let (head, value) = prepare(line, huffman::encoded_len)?;
        Ok(Self { head, value })
    }

    pub(crate) fn len(&self) -> u128 {
        self.head.len() + self.value.as_ref().map_or(0, Part::len)
    }

    pub(crate) fn octets(self) -> impl Iterator<Item = u8> + 'a {
        self.head
            .octets()
            .chain(self.value.into_iter().flat_map(Part::octets))
    }
}

/// Submit the entire measured source in one BufMut operation. A segmented
/// destination may report a more conservative capacity after its cursor moves.
pub(crate) fn transfer(
    dst: &mut impl BufMut,
    required: u128,
    octets: impl Iterator<Item = u8>,
) -> Result<(), InsufficientCapacityError> {
    InsufficientCapacityError::check(required, dst.remaining_mut())?;
    let mut src = WireBuf {
        octets,
        remaining: required as usize,
        chunk: [0; 256],
        start: 0,
        end: 0,
    };
    src.refill();
    dst.put(src);
    Ok(())
}

// Materialize a bounded chunk of an encoding for Buf::chunk. Its exact
// remaining length was measured from the same borrowed payloads.
struct WireBuf<I> {
    octets: I,
    remaining: usize,
    chunk: [u8; 256],
    start: usize,
    end: usize,
}

impl<I: Iterator<Item = u8>> WireBuf<I> {
    fn refill(&mut self) {
        self.start = 0;
        self.end = self.remaining.min(self.chunk.len());
        for byte in &mut self.chunk[..self.end] {
            *byte = self
                .octets
                .next()
                .expect("measured encoding contains this octet");
        }
    }
}

impl<I: Iterator<Item = u8>> Buf for WireBuf<I> {
    fn remaining(&self) -> usize {
        self.remaining
    }
    fn chunk(&self) -> &[u8] {
        &self.chunk[self.start..self.end]
    }
    fn advance(&mut self, mut count: usize) {
        assert!(count <= self.remaining);
        while count > 0 {
            let step = count.min(self.end - self.start);
            self.remaining -= step;
            self.start += step;
            count -= step;
            if self.start == self.end {
                self.refill();
            }
        }
    }
}

fn prepare<S: AsRef<[u8]>, H: AsRef<[u8]>>(
    line: &FieldLine<S, H>,
    encoded_len: impl Fn(&[u8]) -> u128,
) -> Result<(Part<'_>, Option<Part<'_>>), WriteError> {
    Ok(match line {
        FieldLine::Indexed(index) => {
            let head = match index {
                TableIndex::Static(i) => Part::integer::<6>(0xc0, u64::from(i.get())),
                TableIndex::Relative(i) => Part::integer::<6>(0x80, *i),
                TableIndex::PostBase(i) => Part::integer::<4>(0x10, *i),
            };
            (head, None)
        }
        FieldLine::LiteralWithNameReference {
            never_index,
            name,
            value,
        } => {
            let n = u8::from(*never_index);
            let head = match name {
                TableIndex::Static(i) => Part::integer::<4>(0x50 | n << 5, u64::from(i.get())),
                TableIndex::Relative(i) => Part::integer::<4>(0x40 | n << 5, *i),
                TableIndex::PostBase(i) => Part::integer::<3>(n << 3, *i),
            };
            (
                head,
                Some(
                    Part::literal::<7, _, _>(0, value, &encoded_len)
                        .context(ValueLengthOverflowSnafu)?,
                ),
            )
        }
        FieldLine::LiteralWithLiteralName {
            never_index,
            name,
            value,
        } => {
            let flags = 0x20 | u8::from(*never_index) << 4;
            (
                Part::literal::<3, _, _>(flags, name, &encoded_len)
                    .context(NameLengthOverflowSnafu)?,
                Some(
                    Part::literal::<7, _, _>(0, value, &encoded_len)
                        .context(ValueLengthOverflowSnafu)?,
                ),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_length_overflow_identifies_the_field() {
        let raw = StringLiteral::Raw(&b""[..]);
        let coded = StringLiteral::Huffman(&b"x"[..]);
        for (line, is_name) in [
            (
                FieldLine::LiteralWithNameReference {
                    never_index: false,
                    name: TableIndex::Relative(0),
                    value: coded.clone(),
                },
                false,
            ),
            (
                FieldLine::LiteralWithLiteralName {
                    never_index: false,
                    name: raw.clone(),
                    value: coded.clone(),
                },
                false,
            ),
            (
                FieldLine::LiteralWithLiteralName {
                    never_index: false,
                    name: coded,
                    value: raw,
                },
                true,
            ),
        ] {
            let max = u128::from(u64::MAX);
            assert!(prepare(&line, |_| max).is_ok());
            assert!(matches!(
                (is_name, prepare(&line, |_| max + 1)),
                (true, Err(WriteError::NameLengthOverflow { .. }))
                    | (false, Err(WriteError::ValueLengthOverflow { .. }))
            ));
        }
    }
}
