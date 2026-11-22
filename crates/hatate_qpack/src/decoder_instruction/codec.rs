//! Stream calls for exactly one decoder instruction.
use super::{DecoderInstruction, StreamId, StreamIdError};
use crate::instruction::{
    self, EncodedInteger, NumberError, OctetError, WireBudget, WireLimitError,
};
use core::num::NonZeroU64;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{calls::WriteAllError, prelude::*};
use snafu::{ResultExt, Snafu};

/// Read exactly one RFC 9204 §4.4 instruction. The limit counts the first
/// octet and all continuations. EOF before the opcode is a prefix error;
/// EOF inside a number is attributed to that instruction's field.
/// Resume the same future across waits. If it is dropped after consuming an
/// octet, abandon the input stream: the cursor may point to a continuation.
#[call(sync)]
pub async fn read_decoder_instruction<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    max_wire_len: usize,
) -> Result<DecoderInstruction, ReadError<F::Error>> {
    let mut budget = WireBudget::new(max_wire_len);
    let first = instruction::octet(io, &mut budget)
        .await
        .context(PrefixSnafu)?;
    Ok(match first {
        0x80..=0xff => {
            let value = instruction::number::<7, F>(io, &mut budget, first)
                .await
                .context(AcknowledgmentNumberSnafu)?;
            DecoderInstruction::SectionAcknowledgment(
                StreamId::try_from(value).context(AcknowledgmentStreamSnafu)?,
            )
        }
        0x40..=0x7f => {
            let value = instruction::number::<6, F>(io, &mut budget, first)
                .await
                .context(CancellationNumberSnafu)?;
            DecoderInstruction::StreamCancellation(
                StreamId::try_from(value).context(CancellationStreamSnafu)?,
            )
        }
        0x00..=0x3f => {
            let value = instruction::number::<6, F>(io, &mut budget, first)
                .await
                .context(IncrementNumberSnafu)?;
            DecoderInstruction::InsertCountIncrement(
                NonZeroU64::new(value).ok_or(ReadError::ZeroIncrement)?,
            )
        }
    })
}

/// Failures reading one decoder instruction.
#[derive(Debug, Snafu)]
pub enum ReadError<E> {
    #[snafu(display("could not read decoder instruction prefix"))]
    Prefix { source: OctetError<E> },
    #[snafu(display("invalid section acknowledgment stream number"))]
    AcknowledgmentNumber { source: NumberError<E> },
    #[snafu(display("invalid section acknowledgment stream ID"))]
    AcknowledgmentStream { source: StreamIdError },
    #[snafu(display("invalid stream cancellation number"))]
    CancellationNumber { source: NumberError<E> },
    #[snafu(display("invalid cancellation stream ID"))]
    CancellationStream { source: StreamIdError },
    #[snafu(display("invalid insert count increment encoding"))]
    IncrementNumber { source: NumberError<E> },
    #[snafu(display("insert count increment is zero"))]
    ZeroIncrement,
}

/// Encode one complete instruction. The wire limit is checked before any
/// write. A write error retains the number of bytes accepted by the host.
/// Resume the same future across waits. If cancelled after accepting a prefix,
/// abandon the output stream: the integer may be incomplete.
#[call(sync)]
pub async fn write_decoder_instruction<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    instruction: DecoderInstruction,
    max_wire_len: usize,
) -> Result<(), WriteError<F::Error>> {
    let encoded = match instruction {
        DecoderInstruction::SectionAcknowledgment(id) => EncodedInteger::new::<7>(0x80, id.get()),
        DecoderInstruction::StreamCancellation(id) => EncodedInteger::new::<6>(0x40, id.get()),
        DecoderInstruction::InsertCountIncrement(n) => EncodedInteger::new::<6>(0, n.get()),
    };
    let bytes = encoded.as_slice();
    WireBudget::new(max_wire_len).take(bytes.len() as u64)?;
    io.write_all(bytes).await.context(SendSnafu)
}

/// Failures writing one decoder instruction.
#[derive(Debug, Snafu)]
pub enum WriteError<E> {
    #[snafu(transparent)]
    WireLimit { source: WireLimitError },
    #[snafu(display("could not write decoder instruction"))]
    Send { source: WriteAllError<E> },
}
