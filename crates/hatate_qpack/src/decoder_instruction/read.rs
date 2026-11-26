//! Reading whole decoder instructions from a stream.
use super::{
    ACKNOWLEDGMENT_BITS, CANCELLATION_BITS, DecoderInstruction, DecoderStream, INCREMENT_BITS,
    Increment, StreamId, StreamIdError,
};
use crate::instruction::{self, NumberError, OctetError, WireBudget};
use nitori_call::{AsAccess, ReceiverAccess};
use nitori_codec::DecodeFrom;
use nitori_io::{
    Combine, Read,
    adapters::{MergedMetadata, MergingSource},
    calls::ReadValue,
};
use snafu::{ResultExt, Snafu};

/// Reads the next instruction. The stream's
/// [`DecoderStreamLimits`](super::DecoderStreamLimits) count the first octet
/// and all continuations.
///
/// The value is `None` if the stream ends at the instruction boundary.
/// Whether that is an error is a question for the stream's place in the
/// connection. Otherwise the metadata is the merged metadata of the octets of
/// the instruction. A failure does not return the metadata of the octets read
/// before it.
///
/// # Errors
///
/// [`DecodeDecoderInstructionError`]; after any of them the stream is
/// interrupted. EOF inside a number is attributed to that instruction's
/// field.
impl<'s, A, M> DecodeFrom<&'s mut DecoderStream<A>> for Option<ReadValue<DecoderInstruction, M>>
where
    A: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    type Error = DecodeDecoderInstructionError<<A::Family as Read>::Error>;

    async fn decode_from(stream: &'s mut DecoderStream<A>) -> Result<Self, Self::Error> {
        if !stream.position.at_boundary() {
            return Err(DecodeDecoderInstructionError::Interrupted);
        }
        // A call dropped before the first octet has read nothing: the stream
        // stays at the boundary.
        let mut budget = WireBudget::new(stream.limits.max_wire_len);
        let mut merged = MergedMetadata(M::default());
        let mut source = MergingSource::new(&mut stream.io, &mut merged);
        let first = match instruction::octet(&mut source.access(), &mut budget).await {
            Ok(first) => first,
            Err(error) if error.ended_before_first_octet() => return Ok(None),
            Err(source) => {
                stream.position.interrupt();
                return Err(DecodeDecoderInstructionError::Prefix { source });
            }
        };
        stream.position.interrupt();
        let instruction = read_instruction(source.access(), budget, first).await?;
        stream.position.finish();
        Ok(Some(ReadValue {
            value: instruction,
            metadata: merged.0,
        }))
    }
}

/// Read the rest of one RFC 9204 §4.4 instruction whose first octet `first`
/// was read. `budget` has already counted the first octet. EOF inside a
/// number is attributed to that instruction's field.
async fn read_instruction<F: Read<Metadata = ()>>(
    io: &mut impl ReceiverAccess<Family = F>,
    mut budget: WireBudget,
    first: u8,
) -> Result<DecoderInstruction, DecodeDecoderInstructionError<F::Error>> {
    use decode_decoder_instruction_error::*;
    Ok(match first {
        0x80..=0xff => DecoderInstruction::SectionAcknowledgment {
            stream_id: instruction::number::<ACKNOWLEDGMENT_BITS, F>(io, &mut budget, first)
                .await
                .context(AcknowledgmentNumberSnafu)?
                .try_map(StreamId::try_from)
                .context(AcknowledgmentStreamSnafu)?,
        },
        0x40..=0x7f => DecoderInstruction::StreamCancellation {
            stream_id: instruction::number::<CANCELLATION_BITS, F>(io, &mut budget, first)
                .await
                .context(CancellationNumberSnafu)?
                .try_map(StreamId::try_from)
                .context(CancellationStreamSnafu)?,
        },
        0x00..=0x3f => DecoderInstruction::InsertCountIncrement {
            increment: instruction::number::<INCREMENT_BITS, F>(io, &mut budget, first)
                .await
                .context(IncrementNumberSnafu)?
                .try_map(Increment::try_from)
                .map_err(|_| DecodeDecoderInstructionError::ZeroIncrement)?,
        },
    })
}

/// A decoder instruction could not be read.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeDecoderInstructionError<E> {
    /// The first octet could not be read.
    #[snafu(display("could not read decoder instruction prefix"))]
    Prefix {
        /// The octet's failure.
        source: OctetError<E>,
    },
    /// The stream ID of Section Acknowledgment could not be read.
    #[snafu(display("invalid section acknowledgment stream number"))]
    AcknowledgmentNumber {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// The stream ID of Section Acknowledgment exceeds 62 bits.
    #[snafu(display("invalid section acknowledgment stream ID"))]
    AcknowledgmentStream {
        /// The value.
        source: StreamIdError,
    },
    /// The stream ID of Stream Cancellation could not be read.
    #[snafu(display("invalid stream cancellation number"))]
    CancellationNumber {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// The stream ID of Stream Cancellation exceeds 62 bits.
    #[snafu(display("invalid cancellation stream ID"))]
    CancellationStream {
        /// The value.
        source: StreamIdError,
    },
    /// The increment of Insert Count Increment could not be read.
    #[snafu(display("invalid insert count increment encoding"))]
    IncrementNumber {
        /// The integer's failure.
        source: NumberError<E>,
    },
    /// The increment of Insert Count Increment is zero.
    #[snafu(display("insert count increment is zero"))]
    ZeroIncrement,
    /// An earlier instruction failed, or its read or write was dropped: the
    /// stream is inside it and is abandoned.
    #[snafu(display("decoder stream is inside an unfinished or failed instruction"))]
    Interrupted,
}

impl<E> DecodeDecoderInstructionError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Prefix { source } => source.host_error(),
            Self::AcknowledgmentNumber { source }
            | Self::CancellationNumber { source }
            | Self::IncrementNumber { source } => source.host_error(),
            Self::AcknowledgmentStream { .. }
            | Self::CancellationStream { .. }
            | Self::ZeroIncrement
            | Self::Interrupted => None,
        }
    }
}
