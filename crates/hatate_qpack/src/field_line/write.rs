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

    fn chunks(&self) -> impl Iterator<Item = WireChunk<'_>> {
        let (raw, coded) = match self.payload {
            StringLiteral::Raw(data) => (data, &[][..]),
            StringLiteral::Huffman(data) => (&[][..], data),
        };
        core::iter::once(WireChunk::Borrowed(&self.prefix[..self.prefix_len]))
            .chain((!raw.is_empty()).then_some(WireChunk::Borrowed(raw)))
            .chain(huffman_chunks(coded))
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
    transfer(dst, prepared.len(), &[], core::iter::once(&prepared))?;
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

    fn chunks(&self) -> impl Iterator<Item = WireChunk<'_>> {
        self.head
            .chunks()
            .chain(self.value.iter().flat_map(Part::chunks))
    }
}

// Prefixes and raw literals are contiguous and can be lent directly to the
// destination. Only Huffman output needs an intermediate chunk.
enum WireChunk<'a> {
    Borrowed(&'a [u8]),
    Huffman { bytes: [u8; 128], len: usize },
}

impl WireChunk<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Huffman { bytes, len } => &bytes[..*len],
        }
    }
}

fn huffman_chunks(data: &[u8]) -> impl Iterator<Item = WireChunk<'_>> {
    let mut octets = huffman::EncodedOctets::new(data);
    core::iter::from_fn(move || {
        let first = octets.next()?;
        let mut bytes = [0; 128];
        bytes[0] = first;
        let mut len = 1;
        for (out, byte) in bytes[1..].iter_mut().zip(&mut octets) {
            *out = byte;
            len += 1;
        }
        Some(WireChunk::Huffman { bytes, len })
    })
}

/// Submit the entire measured source in one BufMut operation. A segmented
/// destination may report a more conservative capacity after its cursor moves.
pub(crate) fn transfer<'a>(
    dst: &mut impl BufMut,
    required: u128,
    prefix: &'a [u8],
    lines: impl Iterator<Item = &'a Prepared<'a>>,
) -> Result<(), InsufficientCapacityError> {
    InsufficientCapacityError::check(required, dst.remaining_mut())?;
    let mut chunks = (!prefix.is_empty())
        .then_some(WireChunk::Borrowed(prefix))
        .into_iter()
        .chain(lines.flat_map(Prepared::chunks));
    let current = chunks.next().unwrap_or(WireChunk::Borrowed(&[]));
    dst.put(WireBuf {
        chunks,
        current,
        start: 0,
        remaining: required as usize,
    });
    Ok(())
}

struct WireBuf<'a, I> {
    chunks: I,
    current: WireChunk<'a>,
    start: usize,
    remaining: usize,
}

impl<'a, I: Iterator<Item = WireChunk<'a>>> Buf for WireBuf<'a, I> {
    fn remaining(&self) -> usize {
        self.remaining
    }
    fn chunk(&self) -> &[u8] {
        &self.current.as_slice()[self.start..]
    }
    fn advance(&mut self, mut count: usize) {
        assert!(count <= self.remaining);
        self.remaining -= count;
        while count > 0 {
            let available = self.chunk().len();
            if count < available {
                self.start += count;
                return;
            }
            count -= available;
            self.current = self.chunks.next().unwrap_or(WireChunk::Borrowed(&[]));
            self.start = 0;
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
    fn raw_literals_reach_the_transfer_as_whole_borrowed_chunks() {
        let name = [b'n'; 1024];
        let value = [b'x'; 8192];
        let line = FieldLine::<&[u8]>::LiteralWithLiteralName {
            never_index: false,
            name: StringLiteral::Raw(&name),
            value: StringLiteral::Raw(&value),
        };
        let prepared = Prepared::new(&line).unwrap();
        let mut chunks = prepared.chunks();
        let _name_prefix = chunks.next().unwrap();
        let name_chunk = chunks.next().unwrap();
        assert!(core::ptr::eq(name_chunk.as_slice(), name.as_slice()));
        let _value_prefix = chunks.next().unwrap();
        let value_chunk = chunks.next().unwrap();
        assert!(core::ptr::eq(value_chunk.as_slice(), value.as_slice()));
        assert!(chunks.next().is_none());
    }

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
