//! QPACK string literals. Both variants carry the decoded octets.

use bytes::{Buf, Bytes};
use nitori_io::{SplitTo, SplitToError};
use snafu::{ResultExt, Snafu};

use crate::{huffman, integer};

/// The H bit determines the wire representation.
/// On input a raw payload is split from its source and a Huffman payload is
/// decoded into owned bytes. When writing, both variants take plain bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StringLiteral<S, H = Bytes> {
    /// Verbatim octets.
    Raw(S),
    /// Decoded octets that use Huffman coding on the wire.
    Huffman(H),
}

impl<S: AsRef<[u8]>, H: AsRef<[u8]>> AsRef<[u8]> for StringLiteral<S, H> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Raw(data) => data.as_ref(),
            Self::Huffman(data) => data.as_ref(),
        }
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
    #[snafu(display("raw literal of {length} bytes exceeds limit {limit}"))]
    RawTooLong {
        /// Number of octets declared by the peer.
        length: u64,
        /// Maximum decoded size.
        limit: usize,
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

pub(crate) fn read<const N: u8, S: Buf + SplitTo>(
    first: u8,
    src: &mut S,
    limit: usize,
) -> Result<StringLiteral<S>, ReadError> {
    let length = integer::read::<N>(first, src).context(LengthSnafu)?;
    let encoded = first & (1 << N) != 0;
    if !encoded && u128::from(length) > limit as u128 {
        return Err(ReadError::RawTooLong { length, limit });
    }
    let length = usize::try_from(length).map_err(|_| ReadError::AddressSpace)?;
    let data = src.split_to(length).context(PayloadSnafu)?;
    if encoded {
        Ok(StringLiteral::Huffman(
            huffman::decode(data, limit).context(HuffmanSnafu)?,
        ))
    } else {
        Ok(StringLiteral::Raw(data))
    }
}
