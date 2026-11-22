use super::{FieldLine, StringLiteral, TableIndex};
use crate::{InsufficientCapacityError, huffman, integer};
use bytes::BufMut;
use snafu::Snafu;

/// A field line cannot be written to the given destination.
#[derive(Debug, Snafu)]
pub enum WriteError {
    /// The exact wire size exceeds the available capacity.
    #[snafu(transparent)]
    InsufficientCapacity {
        /// Exact required and available capacities in octets.
        source: InsufficientCapacityError,
    },
    /// The length of a literal's Huffman encoding exceeds u64::MAX.
    #[snafu(display("Huffman payload exceeds the supported prefixed integer range"))]
    LiteralLengthOverflow,
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
    ) -> Result<Self, WriteError> {
        let (flags, payload, length) = match literal {
            StringLiteral::Raw(data) => {
                let data = data.as_ref();
                (flags, StringLiteral::Raw(data), data.len() as u64)
            }
            StringLiteral::Huffman(data) => {
                let data = data.as_ref();
                let length = u64::try_from(huffman::encoded_len(data))
                    .map_err(|_| WriteError::LiteralLengthOverflow)?;
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

    fn write(&self, dst: &mut impl BufMut) -> Result<(), InsufficientCapacityError> {
        dst.put_slice(&self.prefix[..self.prefix_len]);
        match self.payload {
            StringLiteral::Raw(data) => dst.put_slice(data),
            StringLiteral::Huffman(data) => huffman::encode(dst, data)?,
        }
        Ok(())
    }
}

/// Write one field line using the given references, N bit and string coding.
/// Integer encodings use the shortest representation. Errors leave the
/// destination unchanged, including when a fixed-size buffer is too small.
pub fn write_field_line<S: AsRef<[u8]>, H: AsRef<[u8]>>(
    dst: &mut impl BufMut,
    line: &FieldLine<S, H>,
) -> Result<(), WriteError> {
    let (head, value) = match line {
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
            (head, Some(Part::literal::<7, _, _>(0, value)?))
        }
        FieldLine::LiteralWithLiteralName {
            never_index,
            name,
            value,
        } => {
            let flags = 0x20 | u8::from(*never_index) << 4;
            (
                Part::literal::<3, _, _>(flags, name)?,
                Some(Part::literal::<7, _, _>(0, value)?),
            )
        }
    };
    let required = head.len() + value.as_ref().map_or(0, Part::len);
    InsufficientCapacityError::check(required, dst.remaining_mut())?;
    head.write(dst)?;
    if let Some(value) = value {
        value.write(dst)?;
    }
    Ok(())
}
