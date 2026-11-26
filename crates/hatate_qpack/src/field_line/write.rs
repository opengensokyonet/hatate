use super::{FieldLine, TableIndex};
use crate::InsufficientCapacityError;
use crate::huffman::EncodedBuf;
use crate::integer::{self, Encoded, PaddingError, PrefixedField, PrefixedInt};
use crate::string_literal::{self, LiteralBytes, StringLiteral};
use bytes::buf::Chain;
use bytes::{Buf, BufMut};
use snafu::{ResultExt, Snafu};

/// A field line cannot be written to the given destination.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum WriteError {
    /// The exact wire size exceeds the available capacity.
    #[snafu(transparent)]
    InsufficientCapacity {
        /// Exact required and available capacities in octets.
        source: InsufficientCapacityError,
    },
    /// The table index's padding has no encoding at the prefix width of
    /// this representation.
    #[snafu(display("invalid index padding"))]
    Index {
        /// The index and the prefix width.
        source: PaddingError,
    },
    /// The literal field name cannot be written.
    #[snafu(display("invalid literal field name"))]
    Name {
        /// The literal failure.
        source: string_literal::WriteError,
    },
    /// The literal field value cannot be written.
    #[snafu(display("invalid literal field value"))]
    Value {
        /// The literal failure.
        source: string_literal::WriteError,
    },
}

/// Write one field line with the encodings it carries: the padding of each
/// integer and length prefix, and each literal's H bit. Raw literals are
/// copied from their buffers, Huffman literals encoded from theirs. The
/// whole line is validated and measured before the first write, so errors
/// leave the destination unchanged, including when a fixed-size buffer is
/// too small.
pub fn write_field_line<S: Buf, H: Buf>(
    dst: &mut impl BufMut,
    line: FieldLine<S, H>,
) -> Result<(), WriteError> {
    let prepared = Prepared::new(line)?;
    transfer(dst, prepared.len, core::iter::once(prepared.buf))?;
    Ok(())
}

/// One prefixed integer and, for a literal, the payload that follows it.
pub(crate) struct Part<S, H> {
    prefix: Encoded,
    at: u8,
    payload: Payload<S, H>,
    len: u128,
}

enum Payload<S, H> {
    None,
    Raw(S),
    Huffman(EncodedBuf<H>),
}

impl<S: Buf, H: Buf> Part<S, H> {
    pub(crate) fn integer<const N: u8, T: Copy + Into<PrefixedInt>>(
        flags: u8,
        field: PrefixedField<T>,
    ) -> Result<Self, PaddingError> {
        let prefix = integer::encode::<N, T>(flags, field)?;
        Ok(Self {
            len: prefix.as_slice().len() as u128,
            prefix,
            at: 0,
            payload: Payload::None,
        })
    }

    fn literal<const N: u8>(
        flags: u8,
        literal: StringLiteral<S, H>,
    ) -> Result<Self, string_literal::WriteError> {
        let (huffman, length, bytes) = literal.into_wire::<N>()?;
        let flags = if huffman { flags | 1 << N } else { flags };
        let mut part = Self::integer::<N, _>(flags, length)
            .expect("the literal checked its length prefix at this width");
        part.len += u128::from(length.value().get());
        part.payload = match bytes {
            LiteralBytes::Raw(bytes) => Payload::Raw(bytes),
            LiteralBytes::Huffman(decoded) => {
                Payload::Huffman(EncodedBuf::new(decoded, length.value().get()))
            }
        };
        Ok(part)
    }

    pub(crate) fn empty() -> Self {
        Self {
            prefix: Encoded::EMPTY,
            at: 0,
            payload: Payload::None,
            len: 0,
        }
    }

    fn prefix_rest(&self) -> &[u8] {
        &self.prefix.as_slice()[usize::from(self.at)..]
    }
}

impl<S: Buf, H: Buf> Buf for Part<S, H> {
    fn remaining(&self) -> usize {
        let payload = match &self.payload {
            Payload::None => 0,
            Payload::Raw(bytes) => bytes.remaining(),
            Payload::Huffman(encoded) => encoded.remaining(),
        };
        self.prefix_rest().len().saturating_add(payload)
    }

    fn chunk(&self) -> &[u8] {
        let prefix = self.prefix_rest();
        if !prefix.is_empty() {
            return prefix;
        }
        match &self.payload {
            Payload::None => &[],
            Payload::Raw(bytes) => bytes.chunk(),
            Payload::Huffman(encoded) => encoded.chunk(),
        }
    }

    fn advance(&mut self, mut count: usize) {
        let prefix = self.prefix_rest().len().min(count);
        self.at += prefix as u8;
        count -= prefix;
        if count == 0 {
            return;
        }
        match &mut self.payload {
            Payload::None => panic!("advance past the end of an integer"),
            Payload::Raw(bytes) => bytes.advance(count),
            Payload::Huffman(encoded) => encoded.advance(count),
        }
    }
}

/// A representation's integer or literal head and its optional value literal.
pub(crate) type LineBuf<S, H> = Chain<Part<S, H>, Part<S, H>>;

// The validated octets of one representation and their exact count, so that
// a whole-section writer can measure every line before writing any of them.
pub(crate) struct Prepared<S, H> {
    pub(crate) buf: LineBuf<S, H>,
    pub(crate) len: u128,
}

impl<S: Buf, H: Buf> Prepared<S, H> {
    pub(crate) fn from_parts(head: Part<S, H>, value: Part<S, H>) -> Self {
        Self {
            len: head.len + value.len,
            buf: head.chain(value),
        }
    }

    pub(crate) fn new(line: FieldLine<S, H>) -> Result<Self, WriteError> {
        let (head, value) = match line {
            FieldLine::Indexed { index } => {
                let head = match index {
                    TableIndex::Static { index } => Part::integer::<6, _>(0xc0, index),
                    TableIndex::Relative { index } => Part::integer::<6, _>(0x80, index),
                    TableIndex::PostBase { index } => Part::integer::<4, _>(0x10, index),
                };
                (head.context(IndexSnafu)?, Part::empty())
            }
            FieldLine::LiteralWithNameReference {
                never_index,
                name,
                value,
            } => {
                let n = u8::from(never_index);
                let head = match name {
                    TableIndex::Static { index } => Part::integer::<4, _>(0x50 | n << 5, index),
                    TableIndex::Relative { index } => Part::integer::<4, _>(0x40 | n << 5, index),
                    TableIndex::PostBase { index } => Part::integer::<3, _>(n << 3, index),
                };
                (
                    head.context(IndexSnafu)?,
                    Part::literal::<7>(0, value).context(ValueSnafu)?,
                )
            }
            FieldLine::LiteralWithLiteralName {
                never_index,
                name,
                value,
            } => {
                let flags = 0x20 | u8::from(never_index) << 4;
                (
                    Part::literal::<3>(flags, name).context(NameSnafu)?,
                    Part::literal::<7>(0, value).context(ValueSnafu)?,
                )
            }
        };
        Ok(Self::from_parts(head, value))
    }
}

/// Submit all measured representations in one `BufMut` operation. A
/// segmented destination may report a more conservative capacity after its
/// cursor moves.
pub(crate) fn transfer<B: Buf>(
    dst: &mut impl BufMut,
    required: u128,
    bufs: impl Iterator<Item = B>,
) -> Result<(), InsufficientCapacityError> {
    InsufficientCapacityError::check(required, dst.remaining_mut())?;
    // The check bounds the total by the destination's usize capacity.
    dst.put(Sequence::new(bufs, required as usize));
    Ok(())
}

/// Consecutive buffers as one, with their total length known in advance.
pub(crate) struct Sequence<I, B> {
    current: Option<B>,
    rest: I,
    remaining: usize,
}

impl<B: Buf, I: Iterator<Item = B>> Sequence<I, B> {
    pub(crate) fn new(mut bufs: I, remaining: usize) -> Self {
        let current = bufs.next();
        let mut sequence = Self {
            current,
            rest: bufs,
            remaining,
        };
        sequence.settle();
        sequence
    }

    // Keep a current buffer with octets left, so that `chunk` is nonempty
    // while octets remain.
    fn settle(&mut self) {
        while self
            .current
            .as_ref()
            .is_some_and(|buf| !buf.has_remaining())
        {
            self.current = self.rest.next();
        }
    }
}

impl<B: Buf, I: Iterator<Item = B>> Buf for Sequence<I, B> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        match &self.current {
            Some(current) => current.chunk(),
            None => &[],
        }
    }

    fn advance(&mut self, mut count: usize) {
        assert!(
            count <= self.remaining,
            "advance past the end of the sequence"
        );
        self.remaining -= count;
        while count > 0 {
            let current = self
                .current
                .as_mut()
                .expect("the measured length covers every buffer");
            let step = count.min(current.remaining());
            current.advance(step);
            count -= step;
            self.settle();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_literals_reach_the_transfer_as_whole_borrowed_chunks() {
        let name = [b'n'; 1024];
        let value = [b'x'; 8192];
        let line = FieldLine::<&[u8], &[u8]>::LiteralWithLiteralName {
            never_index: false,
            name: crate::test_support::raw(&name),
            value: crate::test_support::raw(&value),
        };
        let prepared = Prepared::new(line).unwrap();
        let mut buf = prepared.buf;
        let mut chunks = alloc::vec::Vec::new();
        while buf.has_remaining() {
            let chunk = buf.chunk();
            chunks.push((chunk.as_ptr(), chunk.len()));
            let count = chunk.len();
            buf.advance(count);
        }
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[1], (name.as_ptr(), name.len()));
        assert_eq!(chunks[3], (value.as_ptr(), value.len()));
    }
}
