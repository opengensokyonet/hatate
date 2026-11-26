//! Reading whole encoder instructions from a stream.
use super::{
    EncoderInstruction, EncoderStream, NAME_INDEX_BITS, NAME_LENGTH_BITS, NameReference,
    VALUE_LENGTH_BITS,
};
use crate::{
    huffman::{self, BatchingDecoder, Decoded},
    instruction::{self, NumberError, OctetError, WireBudget, WireLimitError},
    static_table,
    string_literal::StringLiteral,
};
use bytes::Buf;
use core::num::NonZeroUsize;
use nitori_call::{AsAccess, ReceiverAccess};
use nitori_codec::DecodeFrom;
use nitori_io::{
    Combine, Read, ReadChunk,
    adapters::{MergedMetadata, MergingSource},
    calls::ReadValue,
    prelude::*,
};
use snafu::{ResultExt, Snafu};

/// Reads the next instruction whole. The stream's [`EncoderStreamLimits`]
/// apply to all of its wire octets and to the sum of its decoded literal
/// octets, respectively; each is checked as early as the octets read tell
/// that it would be exceeded: a raw literal's length before its octets, a
/// Huffman literal's decoded octets before the one beyond the limit.
///
/// A raw literal collects the source's chunks in `S`, without copying them
/// if `S` keeps them, such as
/// [`JoinedBytes`](crate::string_literal::JoinedBytes) does with `Bytes`
/// chunks. A Huffman literal collects its decoded octets in `H`.
///
/// The value is `None` if the stream ends at the instruction boundary.
/// Whether that is an error is a question for the stream's place in the
/// connection. Otherwise the metadata is the merged metadata of all the
/// octets of the instruction. A failure does not return the metadata of the
/// octets read before it.
///
/// # Errors
///
/// [`DecodeEncoderInstructionError`]. A failure before the first octet,
/// such as of the stream or of a wire limit of zero, has read nothing and
/// leaves the stream at the boundary; after any other, and after
/// [`DecodeEncoderInstructionError::Interrupted`] itself, the stream is
/// interrupted.
///
/// [`EncoderStreamLimits`]: super::EncoderStreamLimits
impl<'s, A, S, H, M> DecodeFrom<&'s mut EncoderStream<A>>
    for Option<ReadValue<EncoderInstruction<S, H>, M>>
where
    A: ReceiverAccess<Family: ReadChunk<Metadata = M>>,
    S: Default + Extend<<A::Family as ReadChunk>::Chunk>,
    H: Default + Extend<u8>,
    M: Combine + Unpin,
{
    type Error = DecodeEncoderInstructionError<<A::Family as Read>::Error>;

    async fn decode_from(stream: &'s mut EncoderStream<A>) -> Result<Self, Self::Error> {
        if !stream.position.at_boundary() {
            return Err(DecodeEncoderInstructionError::Interrupted);
        }
        let limits = stream.limits;
        // A call dropped before the first octet, or failing before it, has
        // read nothing: the stream stays at the boundary.
        let mut wire = WireBudget::new(limits.max_wire_len);
        let mut merged = MergedMetadata(M::default());
        let mut source = MergingSource::new(&mut stream.io, &mut merged);
        let first = match instruction::octet(&mut source.access(), &mut wire).await {
            Ok(first) => first,
            Err(error) if error.ended_before_first_octet() => return Ok(None),
            Err(source) => return Err(DecodeEncoderInstructionError::Prefix { source }),
        };
        // Until the instruction is complete, a failure or dropping this call
        // leaves the stream interrupted.
        stream.position.interrupt();
        let value =
            read_instruction(source.access(), &mut wire, limits.max_decoded_len, first).await?;
        stream.position.finish();
        Ok(Some(ReadValue {
            value,
            metadata: merged.0,
        }))
    }
}

async fn read_instruction<F, S, H>(
    io: &mut impl ReceiverAccess<Family = F>,
    wire: &mut WireBudget,
    decoded_max: usize,
    first: u8,
) -> Result<EncoderInstruction<S, H>, DecodeEncoderInstructionError<F::Error>>
where
    F: ReadChunk<Metadata = ()>,
    S: Default + Extend<F::Chunk>,
    H: Default + Extend<u8>,
{
    use decode_encoder_instruction_error::*;
    Ok(match first {
        0x80..=0xff => {
            // An unfinished index needs its next digit and the value prefix.
            let index = instruction::checked_number::<NAME_INDEX_BITS, F, _>(
                io,
                wire,
                first,
                |wire, _| Ok(wire.check(2)?),
                |source| DecodeEncoderInstructionError::NameIndex { source },
            )
            .await?;
            // Even an empty value needs its length prefix.
            wire.check(1)?;
            let name = if first & 0x40 != 0 {
                NameReference::Static {
                    index: index
                        .try_map(static_table::Index::try_from)
                        .context(StaticNameSnafu)?,
                }
            } else {
                NameReference::Relative { index }
            };
            let value = read_value(io, wire, decoded_max).await?;
            EncoderInstruction::InsertWithNameReference { name, value }
        }
        0x40..=0x7f => {
            let name = read_literal::<NAME_LENGTH_BITS, F, S, H>(io, wire, first, decoded_max, 1)
                .await
                .context(NameSnafu)?;
            // The name is within the limit, so it leaves the rest of it.
            let decoded_left = decoded_max - name.decoded_len() as usize;
            let value = read_value(io, wire, decoded_left).await?;
            EncoderInstruction::InsertWithLiteralName { name, value }
        }
        0x20..=0x3f => EncoderInstruction::SetDynamicTableCapacity {
            capacity: instruction::number::<{ super::CAPACITY_BITS }, F>(io, wire, first)
                .await
                .context(CapacitySnafu)?,
        },
        0..=0x1f => EncoderInstruction::Duplicate {
            index: instruction::number::<{ super::DUPLICATE_BITS }, F>(io, wire, first)
                .await
                .context(DuplicateSnafu)?,
        },
    })
}

/// Reads the value of an insertion, from its first octet on.
async fn read_value<F, S, H>(
    io: &mut impl ReceiverAccess<Family = F>,
    wire: &mut WireBudget,
    decoded_left: usize,
) -> Result<StringLiteral<S, H>, DecodeEncoderInstructionError<F::Error>>
where
    F: ReadChunk<Metadata = ()>,
    S: Default + Extend<F::Chunk>,
    H: Default + Extend<u8>,
{
    use decode_encoder_instruction_error::*;
    let first = instruction::octet(io, wire)
        .await
        .context(ValuePrefixSnafu)?;
    read_literal::<VALUE_LENGTH_BITS, F, S, H>(io, wire, first, decoded_left, 0)
        .await
        .context(ValueSnafu)
}

/// Reads a literal whose length prefix of `N` bits begins in `first`, with
/// `decoded_left` decoded octets allowed. A name is followed by at least
/// `tail` octets, the value's length prefix, which its wire checks count.
async fn read_literal<const N: u8, F, S, H>(
    io: &mut impl ReceiverAccess<Family = F>,
    wire: &mut WireBudget,
    first: u8,
    decoded_left: usize,
    tail: u64,
) -> Result<StringLiteral<S, H>, DecodeLiteralError<F::Error>>
where
    F: ReadChunk<Metadata = ()>,
    S: Default + Extend<F::Chunk>,
    H: Default + Extend<u8>,
{
    let raw = first & (1 << N) == 0;
    // The accumulated length is a lower bound even before its last digit.
    // Leave room for that digit and what follows, and a raw literal's
    // decoded octets are at least as many.
    let length = instruction::checked_number::<N, F, _>(
        io,
        wire,
        first,
        |wire, minimum| {
            wire.check(u128::from(minimum) + 1 + u128::from(tail))?;
            if raw {
                DecodedLengthError::check(minimum, decoded_left)?;
            }
            Ok(())
        },
        |source| DecodeLiteralError::Length { source },
    )
    .await?;
    let declared = length.value().get();
    wire.check(u128::from(declared) + u128::from(tail))?;
    wire.take(declared)?;
    // The complete payload fits the usize-sized wire budget.
    let count = declared as usize;
    if raw {
        DecodedLengthError::check(declared, decoded_left)?;
        let bytes = read_raw(io, count).await?;
        Ok(StringLiteral::read_raw(bytes, length))
    } else {
        let decoded: Decoded<H> = read_huffman(io, count, decoded_left).await?;
        Ok(StringLiteral::read_huffman(
            decoded.octets,
            decoded.len as u64,
            length,
        ))
    }
}

/// Collects `count` octets in the chunks the source hands out.
async fn read_raw<F: ReadChunk<Metadata = ()>, S: Default + Extend<F::Chunk>>(
    io: &mut impl ReceiverAccess<Family = F>,
    count: usize,
) -> Result<S, DecodeLiteralError<F::Error>> {
    let mut bytes = S::default();
    let mut remaining = count;
    while let Some(missing) = NonZeroUsize::new(remaining) {
        match io.read_chunk(missing).await {
            Ok(Some(segment)) => {
                let taken = segment.chunk.remaining();
                // invariant: `read_chunk` hands out a nonempty chunk of at
                // most the octets requested, by the contract of nitori_io;
                // only a host that breaks it, not the peer, reaches this, as
                // with the same assertion in nitori's own adapters.
                assert!(taken > 0 && taken <= remaining, "invalid chunk length");
                remaining -= taken;
                bytes.extend(core::iter::once(segment.chunk));
            }
            Ok(None) => return Err(DecodeLiteralError::Truncated { missing }),
            Err(source) => return Err(DecodeLiteralError::Read { source }),
        }
    }
    Ok(bytes)
}

/// Decodes `count` octets of Huffman code into at most `limit` octets.
async fn read_huffman<F: Read<Metadata = ()>, H: Default + Extend<u8>>(
    io: &mut impl ReceiverAccess<Family = F>,
    count: usize,
    limit: usize,
) -> Result<Decoded<H>, DecodeLiteralError<F::Error>> {
    use decode_literal_error::HuffmanSnafu;
    let mut decoder = BatchingDecoder::new(limit);
    let mut encoded = [0; 64];
    let mut remaining = count;
    while let Some(missing) = NonZeroUsize::new(remaining) {
        let request = remaining.min(encoded.len());
        let read = match io.read(&mut &mut encoded[..request]).await {
            Ok(Some(segment)) => segment.count.get(),
            Ok(None) => return Err(DecodeLiteralError::Truncated { missing }),
            Err(source) => return Err(DecodeLiteralError::Read { source }),
        };
        remaining -= read;
        for &octet in &encoded[..read] {
            decoder.octet(octet).context(HuffmanSnafu)?;
        }
    }
    decoder.finish().context(HuffmanSnafu)
}

/// The decoded octets of a literal, or of the literals of an instruction,
/// exceed the decoded limit, or what is left of it.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "decoded literal length {length} exceeds the remaining decoded limit {remaining}"
))]
pub struct DecodedLengthError {
    length: u64,
    remaining: usize,
}

impl DecodedLengthError {
    pub(super) fn check(length: u64, remaining: usize) -> Result<(), Self> {
        if u128::from(length) > remaining as u128 {
            Err(Self { length, remaining })
        } else {
            Ok(())
        }
    }

    /// The decoded length: a raw literal's length when reading, or a lower
    /// bound of it from the digits of its length read so far; the
    /// instruction's [`decoded_len`](EncoderInstruction::decoded_len) when
    /// writing.
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// The decoded octets still permitted: at the start of the literal when
    /// reading, the whole limit when writing.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }
}

/// A literal of an encoder instruction could not be read.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeLiteralError<E> {
    /// The length prefix could not be read.
    #[snafu(display("invalid instruction literal length"))]
    Length {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// The literal, or what must follow it, would exceed the wire limit.
    #[snafu(transparent)]
    WireLimit {
        /// Wire-size shortfall.
        source: WireLimitError,
    },
    /// A raw literal's length exceeds the decoded limit.
    #[snafu(transparent)]
    DecodedLength {
        /// The length and the decoded octets left.
        source: DecodedLengthError,
    },
    /// The stream ended inside the literal.
    #[snafu(display("literal ended with {missing} octets missing"))]
    Truncated {
        /// Declared octets that have not arrived.
        missing: NonZeroUsize,
    },
    /// The stream failed inside the literal.
    #[snafu(display("could not read literal"))]
    Read {
        /// The stream's error.
        source: E,
    },
    /// The Huffman code is invalid, or decodes to more than the decoded
    /// limit allows.
    #[snafu(display("invalid Huffman literal"))]
    Huffman {
        /// Decoder failure.
        source: huffman::DecodeError,
    },
}

/// An encoder instruction could not be read.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeEncoderInstructionError<E> {
    /// An earlier instruction was not finished, or failed: the stream is
    /// inside it and is abandoned.
    #[snafu(display("encoder stream is inside an unfinished or failed instruction"))]
    Interrupted,
    /// The shortest insertion that the octets read so far allow already
    /// exceeds the wire limit.
    #[snafu(transparent)]
    WireLimit {
        /// The lower bound and the limit.
        source: WireLimitError,
    },
    /// The first octet could not be read.
    #[snafu(display("could not read encoder instruction prefix"))]
    Prefix {
        /// The octet's failure.
        source: OctetError<E>,
    },
    /// The capacity of Set Dynamic Table Capacity could not be read.
    #[snafu(display("invalid dynamic table capacity encoding"))]
    Capacity {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// The index of Duplicate could not be read.
    #[snafu(display("invalid duplicate index encoding"))]
    Duplicate {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// The index of a name reference could not be read.
    #[snafu(display("invalid insert name index encoding"))]
    NameIndex {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// A static name reference is beyond the static table.
    #[snafu(display("invalid static name reference"))]
    StaticName {
        /// The index.
        source: static_table::IndexError,
    },
    /// The literal name could not be read.
    #[snafu(display("invalid literal name"))]
    Name {
        /// The literal's failure.
        source: DecodeLiteralError<E>,
    },
    /// The first octet of the value could not be read.
    #[snafu(display("missing value header"))]
    ValuePrefix {
        /// The octet's failure.
        source: OctetError<E>,
    },
    /// The value could not be read.
    #[snafu(display("invalid literal value"))]
    Value {
        /// The literal's failure.
        source: DecodeLiteralError<E>,
    },
}

impl<E> DecodeLiteralError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Length { source } => source.host_error(),
            Self::Read { source } => Some(source),
            Self::WireLimit { .. }
            | Self::DecodedLength { .. }
            | Self::Truncated { .. }
            | Self::Huffman { .. } => None,
        }
    }
}

impl<E> DecodeEncoderInstructionError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Prefix { source } | Self::ValuePrefix { source } => source.host_error(),
            Self::Capacity { source } | Self::Duplicate { source } | Self::NameIndex { source } => {
                source.host_error()
            }
            Self::Name { source } | Self::Value { source } => source.host_error(),
            Self::WireLimit { .. } | Self::Interrupted | Self::StaticName { .. } => None,
        }
    }
}
