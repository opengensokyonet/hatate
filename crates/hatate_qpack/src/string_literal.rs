//! QPACK string literals (RFC 9204 §4.1.2).
//!
//! A [`StringLiteral`] records its H bit, its length prefix and its octets:
//! a raw literal keeps the octets on the wire, a Huffman literal its decoded
//! octets, whose encoding is unique. Reading one and writing it back yields
//! the octets it was read from.

mod containers;

use bytes::{Buf, Bytes};
use nitori_codec::EncodedLen;
use nitori_io::{SplitTo, SplitToError};
use snafu::{ResultExt, Snafu};

use crate::huffman;
use crate::integer::{self, PaddingError, PrefixedField, PrefixedInt};

pub use containers::{CopiedBytes, JoinedBytes};

/// A string literal: its H bit, its length prefix and its octets.
///
/// A raw literal holds the octets on the wire in `S`; a Huffman literal
/// holds the decoded octets in `H`. The length prefix is the length on the
/// wire, of the encoded octets for a Huffman literal, and the constructors
/// derive it from the octets: the fields are private, so the prefix always
/// matches them. The literal does not know the width of its length prefix,
/// which the enclosing format determines; methods that need it take it as
/// `N`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringLiteral<S, H = Bytes>(Repr<S, H>);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Repr<S, H> {
    Raw {
        bytes: S,
        length: PrefixedField,
    },
    Huffman {
        decoded: H,
        decoded_len: u64,
        length: PrefixedField,
    },
}

/// The octets of a [`StringLiteral`], by its H bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteralBytes<S, H> {
    /// The octets on the wire, sent without Huffman coding.
    Raw(S),
    /// The decoded octets of a Huffman-coded literal.
    Huffman(H),
}

impl<S: AsRef<[u8]>, H: AsRef<[u8]>> AsRef<[u8]> for LiteralBytes<S, H> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Raw(bytes) => bytes.as_ref(),
            Self::Huffman(bytes) => bytes.as_ref(),
        }
    }
}

/// The length of a new literal could not be determined.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(module(literal_length_error))]
pub enum LiteralLengthError<E> {
    /// The octets could not report their length.
    #[snafu(display("could not determine the literal length"))]
    Length {
        /// The error of the octets' [`EncodedLen`].
        source: E,
    },
    /// The length on the wire exceeds the range of a prefixed integer.
    #[snafu(display("literal length {length} exceeds the prefixed integer range"))]
    TooLong {
        /// The length on the wire, in octets.
        length: u128,
    },
}

impl<S, H> StringLiteral<S, H> {
    /// A raw literal of `bytes`, with the shortest length prefix. The length
    /// is the [`EncodedLen`] of `bytes`.
    ///
    /// # Errors
    ///
    /// [`LiteralLengthError::Length`] if `bytes` cannot report its length.
    pub async fn raw(mut bytes: S) -> Result<Self, LiteralLengthError<S::LengthError>>
    where
        S: EncodedLen,
    {
        let length = bytes
            .encoded_len()
            .await
            .context(literal_length_error::LengthSnafu)?;
        Ok(Self(Repr::Raw {
            bytes,
            length: PrefixedField::shortest(PrefixedInt::from(length)),
        }))
    }

    /// A Huffman literal of the decoded octets `decoded`, with the shortest
    /// length prefix. Computing the encoded length reads a clone of
    /// `decoded`, which must yield the same octets as `decoded` itself.
    ///
    /// # Errors
    ///
    /// [`LiteralLengthError::TooLong`] if the encoded length exceeds the
    /// prefixed integer range.
    pub fn huffman(decoded: H) -> Result<Self, LiteralLengthError<!>>
    where
        H: Buf + Clone,
    {
        let decoded_len = decoded.remaining() as u64;
        let encoded = huffman::encoded_len(decoded.clone());
        let length =
            u64::try_from(encoded).map_err(|_| LiteralLengthError::TooLong { length: encoded })?;
        Ok(Self(Repr::Huffman {
            decoded,
            decoded_len,
            length: PrefixedField::shortest(PrefixedInt::from(length)),
        }))
    }

    /// The literal with `padding` additional zero groups in its length
    /// prefix of `N` bits.
    ///
    /// # Errors
    ///
    /// [`PaddingError`] if the length has no such encoding at `N`.
    pub fn with_length_padding<const N: u8>(mut self, padding: u8) -> Result<Self, PaddingError> {
        let length = match &mut self.0 {
            Repr::Raw { length, .. } | Repr::Huffman { length, .. } => length,
        };
        *length = PrefixedField::new::<N>(length.value(), padding)?;
        Ok(self)
    }

    /// The length prefix: the length on the wire and its padding.
    pub fn length(&self) -> PrefixedField {
        match &self.0 {
            Repr::Raw { length, .. } | Repr::Huffman { length, .. } => *length,
        }
    }

    /// Whether the literal is Huffman-coded on the wire (the H bit).
    pub fn is_huffman(&self) -> bool {
        matches!(self.0, Repr::Huffman { .. })
    }

    /// The number of decoded octets.
    pub fn decoded_len(&self) -> u64 {
        match &self.0 {
            Repr::Raw { length, .. } => length.value().get(),
            Repr::Huffman { decoded_len, .. } => *decoded_len,
        }
    }

    /// The octets on the wire with a length prefix of `N` bits, including the
    /// prefix's first octet. Saturates at `u64::MAX`.
    pub fn wire_len<const N: u8>(&self) -> u64 {
        let length = self.length();
        (length.encoded_len::<N>() as u64).saturating_add(length.value().get())
    }

    /// The octets, borrowed.
    pub fn bytes(&self) -> LiteralBytes<&S, &H> {
        match &self.0 {
            Repr::Raw { bytes, .. } => LiteralBytes::Raw(bytes),
            Repr::Huffman { decoded, .. } => LiteralBytes::Huffman(decoded),
        }
    }

    /// The octets, taken out of the literal.
    pub fn into_bytes(self) -> LiteralBytes<S, H> {
        match self.0 {
            Repr::Raw { bytes, .. } => LiteralBytes::Raw(bytes),
            Repr::Huffman { decoded, .. } => LiteralBytes::Huffman(decoded),
        }
    }

    /// Validate the literal for a length prefix of `N` bits and split it for
    /// writing: the first octet's H bit, the length prefix and the payload.
    pub(crate) fn into_wire<const N: u8>(
        self,
    ) -> Result<(bool, PrefixedField, LiteralBytes<S, H>), WriteError>
    where
        S: Buf,
        H: Buf,
    {
        let length = self.length();
        length.check::<N>().context(PaddingSnafu)?;
        let (expected, actual) = match &self.0 {
            Repr::Raw { bytes, length } => (length.value().get(), bytes.remaining()),
            Repr::Huffman {
                decoded,
                decoded_len,
                ..
            } => (*decoded_len, decoded.remaining()),
        };
        if expected != actual as u64 {
            return Err(WriteError::PayloadLength { expected, actual });
        }
        Ok((self.is_huffman(), length, self.into_bytes()))
    }
}

impl<S: AsRef<[u8]>, H: AsRef<[u8]>> AsRef<[u8]> for StringLiteral<S, H> {
    /// The decoded octets.
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            Repr::Raw { bytes, .. } => bytes.as_ref(),
            Repr::Huffman { decoded, .. } => decoded.as_ref(),
        }
    }
}

/// An uncompressed literal whose wire length exceeds the decoded limit.
/// Its measurements can only be obtained from an actual failed check.
///
/// ```compile_fail
/// use hatate_qpack::string_literal::RawLengthError;
/// let error = RawLengthError { length: 8, limit: 8 };
/// ```
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("raw literal of {length} bytes exceeds limit {limit}"))]
pub struct RawLengthError {
    length: u64,
    limit: usize,
}

impl RawLengthError {
    fn check(length: u64, limit: usize) -> Result<(), Self> {
        if u128::from(length) > limit as u128 {
            Err(Self { length, limit })
        } else {
            Ok(())
        }
    }

    /// The peer's declared length, strictly greater than [`Self::limit`].
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// The caller's limit in decoded octets.
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

/// A length or payload of a string literal could not be decoded.
#[derive(Debug, Snafu)]
pub enum ReadError {
    /// Invalid or incomplete length after the first octet.
    #[snafu(display("invalid literal length"))]
    Length {
        /// Prefixed integer error.
        source: integer::ReadError,
    },
    /// Raw payload exceeds the caller's limit on decoded bytes.
    #[snafu(display("raw string literal too long"))]
    RawTooLong {
        /// The peer's declared length and the limit it exceeded.
        source: RawLengthError,
    },
    /// The announced length cannot be addressed on this host.
    #[snafu(display("literal length exceeds addressable memory"))]
    AddressSpace,
    /// The input buffer could not supply the announced payload.
    #[snafu(display("incomplete literal payload"))]
    Payload {
        /// Failure to split the input.
        source: SplitToError,
    },
    /// Huffman data violates the code or exceeds the decoded limit.
    #[snafu(display("invalid Huffman literal"))]
    Huffman {
        /// Decoder failure.
        source: huffman::DecodeError,
    },
}

/// A string literal cannot be written in its position.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum WriteError {
    /// The length prefix's padding has no encoding at this prefix width.
    #[snafu(display("invalid literal length padding"))]
    Padding {
        /// The length and the prefix width.
        source: PaddingError,
    },
    /// The octets left in the payload differ from the length the literal
    /// was constructed with: the decoded length for a Huffman literal.
    #[snafu(display("literal payload holds {actual} octets instead of {expected}"))]
    PayloadLength {
        /// The length recorded at construction.
        expected: u64,
        /// The octets remaining in the payload.
        actual: usize,
    },
}

pub(crate) fn read<const N: u8, S: Buf + SplitTo, H: Default + Extend<u8>>(
    first: u8,
    src: &mut S,
    limit: usize,
) -> Result<StringLiteral<S, H>, ReadError> {
    let length = integer::read::<N>(first, src).context(LengthSnafu)?;
    let encoded = first & (1 << N) != 0;
    if !encoded {
        RawLengthError::check(length.value().get(), limit).context(RawTooLongSnafu)?;
    }
    let count = usize::try_from(length.value().get()).map_err(|_| ReadError::AddressSpace)?;
    let data = src.split_to(count).context(PayloadSnafu)?;
    if encoded {
        let (decoded, decoded_len) = huffman::decode_counted(data, limit).context(HuffmanSnafu)?;
        Ok(StringLiteral(Repr::Huffman {
            decoded,
            decoded_len: decoded_len as u64,
            length,
        }))
    } else {
        Ok(StringLiteral(Repr::Raw {
            bytes: data,
            length,
        }))
    }
}

#[cfg(test)]
mod tests;
