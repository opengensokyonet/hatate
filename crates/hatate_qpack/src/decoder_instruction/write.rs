//! Writing whole decoder instructions to a stream.
use super::{
    ACKNOWLEDGMENT_BITS, CANCELLATION_BITS, DecoderInstruction, DecoderStream, INCREMENT_BITS,
};
use crate::{
    instruction::{self, WireBudget, WireLimitError},
    integer::{self, PaddingError},
};
use nitori_call::ReceiverAccess;
use nitori_codec::EncodeInto;
use nitori_io::{Combine, Write, calls::WriteAllError};
use snafu::{ResultExt, Snafu};

/// Writes the instruction whole and returns the merged report of its octets.
///
/// Before it writes the first octet, it checks that the integer has an
/// encoding in its position and that the instruction's
/// [`wire_len`](DecoderInstruction::wire_len) is within the stream's
/// `max_wire_len`. A failed check writes nothing and leaves the stream at the
/// boundary.
///
/// # Errors
///
/// [`EncodeDecoderInstructionError`]. A failure after the stream accepted
/// an octet of the instruction leaves the stream interrupted.
impl<'s, A> EncodeInto<&'s mut DecoderStream<A>> for DecoderInstruction
where
    A: ReceiverAccess<Family: Write<Report: Combine>>,
{
    type Output = <A::Family as Write>::Report;
    type Error = EncodeDecoderInstructionError<<A::Family as Write>::Error>;

    async fn encode_into(
        self,
        stream: &'s mut DecoderStream<A>,
    ) -> Result<Self::Output, Self::Error> {
        use encode_decoder_instruction_error::*;
        if !stream.position.at_boundary() {
            return Err(EncodeDecoderInstructionError::Interrupted);
        }
        let encoded = match self {
            Self::SectionAcknowledgment { stream_id } => {
                integer::encode::<ACKNOWLEDGMENT_BITS, _>(0x80, stream_id)
            }
            Self::StreamCancellation { stream_id } => {
                integer::encode::<CANCELLATION_BITS, _>(0x40, stream_id)
            }
            Self::InsertCountIncrement { increment } => {
                integer::encode::<INCREMENT_BITS, _>(0, increment)
            }
        }
        .context(IntegerSnafu)?;
        let bytes = encoded.as_slice();
        WireBudget::new(stream.limits.max_wire_len).check(bytes.len() as u128)?;
        let unwritten = stream.position.begin_write(bytes.len());
        match instruction::put(&mut stream.io, unwritten, bytes).await {
            Ok(report) => {
                stream.position.finish();
                Ok(report)
            }
            Err(source) => {
                stream.position.settle();
                Err(EncodeDecoderInstructionError::Send { source })
            }
        }
    }
}

/// A decoder instruction could not be written to a stream whose failures are
/// `W`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeDecoderInstructionError<W> {
    /// An earlier instruction was not finished, or failed after the stream
    /// accepted some of it: the stream is inside it and is abandoned.
    #[snafu(display("decoder stream is inside an unfinished or failed instruction"))]
    Interrupted,
    /// The instruction exceeds the wire limit. Nothing was written.
    #[snafu(transparent)]
    WireLimit {
        /// The instruction's wire length and the limit.
        source: WireLimitError,
    },
    /// The integer has no encoding in its prefix. Nothing was written.
    #[snafu(display("invalid instruction integer padding"))]
    Integer {
        /// The integer and the prefix width.
        source: PaddingError,
    },
    /// The stream did not accept the octets of the instruction.
    #[snafu(display("could not write decoder instruction"))]
    Send {
        /// Write failure and the octets accepted before it.
        source: WriteAllError<W>,
    },
}
