//! Writing whole encoder instructions to a stream.
use super::{
    CAPACITY_BITS, DUPLICATE_BITS, DecodedLengthError, EncoderInstruction, EncoderStream,
    EncoderStreamLimits, NAME_INDEX_BITS, NAME_LENGTH_BITS, NameReference, VALUE_LENGTH_BITS,
};
use crate::{
    huffman::EncodedBuf,
    instruction::{self, Sink, WireBudget, WireLimitError},
    integer::{self, PaddingError},
    string_literal::{self, LiteralBytes, StringLiteral},
};
use bytes::Buf;
use nitori_call::{Composed, ReceiverAccess};
use nitori_codec::EncodeInto;
use nitori_io::{Combine, Write, adapters::WriteLimit, calls::WriteAllError};
use snafu::{ResultExt, Snafu};

/// Writes the instruction whole and returns the merged report of its octets
/// and of what its raw literals reported.
///
/// Before it writes the first octet, it checks that every integer and
/// literal length has an encoding in its position, that each Huffman
/// literal holds the decoded octets it was constructed with, and that the
/// instruction is within the stream's [`EncoderStreamLimits`]: its
/// [`wire_len`](EncoderInstruction::wire_len) within `max_wire_len` and its
/// [`decoded_len`](EncoderInstruction::decoded_len) within
/// `max_decoded_len`. A failed check writes nothing and leaves the stream at
/// the boundary.
///
/// A raw literal writes itself into the stream's access, held to the
/// octets of the instruction not written yet ([`WriteLimit`]); it must
/// write as many octets as its length prefix says, or the instruction fails.
/// A Huffman literal is encoded as it is written.
///
/// # Errors
///
/// [`EncodeEncoderInstructionError`]. A failure after the stream accepted
/// an octet of the instruction leaves the stream interrupted.
impl<'s, A, S, H, P> EncodeInto<&'s mut EncoderStream<A>> for EncoderInstruction<S, H>
where
    A: ReceiverAccess<Family: Write<Report: Combine>>,
    S: for<'a> EncodeInto<
            Composed<&'a mut A, &'a mut WriteLimit>,
            Output = <A::Family as Write>::Report,
            Error = P,
        >,
    H: Buf,
{
    type Output = <A::Family as Write>::Report;
    type Error = EncodeEncoderInstructionError<<A::Family as Write>::Error, P>;

    async fn encode_into(
        self,
        stream: &'s mut EncoderStream<A>,
    ) -> Result<Self::Output, Self::Error> {
        if !stream.position.at_boundary() {
            return Err(EncodeEncoderInstructionError::Interrupted);
        }
        self.check(stream.limits)?;
        // invariant: the check bounds the length by the usize limit.
        let length = self.wire_len() as usize;
        stream.position.begin_write(length);
        match write_instruction(self, &mut stream.io, &mut stream.position.unwritten).await {
            Ok(report) => {
                stream.position.finish();
                Ok(report)
            }
            Err(error) => {
                stream.position.settle();
                Err(error)
            }
        }
    }
}

impl<S, H: Buf> EncoderInstruction<S, H> {
    /// The checks before writing.
    fn check<W, P>(
        &self,
        limits: EncoderStreamLimits,
    ) -> Result<(), EncodeEncoderInstructionError<W, P>> {
        use encode_encoder_instruction_error::*;
        match self {
            Self::SetDynamicTableCapacity { capacity } => {
                capacity.check::<CAPACITY_BITS>().context(IntegerSnafu)?;
            }
            Self::Duplicate { index } => index.check::<DUPLICATE_BITS>().context(IntegerSnafu)?,
            Self::InsertWithNameReference { name, value } => {
                match name {
                    NameReference::Static { index } => index.check::<NAME_INDEX_BITS>(),
                    NameReference::Relative { index } => index.check::<NAME_INDEX_BITS>(),
                }
                .context(IntegerSnafu)?;
                value
                    .check_stream::<VALUE_LENGTH_BITS>()
                    .context(ValueSnafu)?;
            }
            Self::InsertWithLiteralName { name, value } => {
                name.check_stream::<NAME_LENGTH_BITS>().context(NameSnafu)?;
                value
                    .check_stream::<VALUE_LENGTH_BITS>()
                    .context(ValueSnafu)?;
            }
        }
        WireBudget::new(limits.max_wire_len).check(u128::from(self.wire_len()))?;
        DecodedLengthError::check(self.decoded_len(), limits.max_decoded_len)?;
        Ok(())
    }
}

/// invariant: `check` found an encoding for each integer and literal length
/// in its position before anything is written.
const CHECKED: &str = "checked before writing";

async fn write_instruction<A, S, H, P>(
    instruction: EncoderInstruction<S, H>,
    io: &mut A,
    unwritten: &mut WriteLimit,
) -> Result<
    <A::Family as Write>::Report,
    EncodeEncoderInstructionError<<A::Family as Write>::Error, P>,
>
where
    A: ReceiverAccess<Family: Write<Report: Combine>>,
    S: for<'a> EncodeInto<Sink<'a, A>, Output = <A::Family as Write>::Report, Error = P>,
    H: Buf,
{
    use encode_encoder_instruction_error::*;
    match instruction {
        EncoderInstruction::SetDynamicTableCapacity { capacity } => {
            let head = integer::encode::<CAPACITY_BITS, _>(0x20, capacity).expect(CHECKED);
            instruction::put(io, unwritten, head.as_slice())
                .await
                .context(SendSnafu)
        }
        EncoderInstruction::Duplicate { index } => {
            let head = integer::encode::<DUPLICATE_BITS, _>(0, index).expect(CHECKED);
            instruction::put(io, unwritten, head.as_slice())
                .await
                .context(SendSnafu)
        }
        EncoderInstruction::InsertWithNameReference { name, value } => {
            let head = match name {
                NameReference::Static { index } => {
                    integer::encode::<NAME_INDEX_BITS, _>(0xc0, index)
                }
                NameReference::Relative { index } => {
                    integer::encode::<NAME_INDEX_BITS, _>(0x80, index)
                }
            }
            .expect(CHECKED);
            let report = instruction::put(io, unwritten, head.as_slice())
                .await
                .context(SendSnafu)?;
            let value =
                write_literal::<VALUE_LENGTH_BITS, _, _, _, _>(io, unwritten, 0, value, |source| {
                    EncodeEncoderInstructionError::Value { source }
                })
                .await?;
            Ok(report.combine(value))
        }
        EncoderInstruction::InsertWithLiteralName { name, value } => {
            let name = write_literal::<NAME_LENGTH_BITS, _, _, _, _>(
                io,
                unwritten,
                0x40,
                name,
                |source| EncodeEncoderInstructionError::Name { source },
            )
            .await?;
            let value =
                write_literal::<VALUE_LENGTH_BITS, _, _, _, _>(io, unwritten, 0, value, |source| {
                    EncodeEncoderInstructionError::Value { source }
                })
                .await?;
            Ok(name.combine(value))
        }
    }
}

/// Writes a literal whose length prefix of `N` bits begins in an octet with
/// the high bits `flags`; `which` tells which literal a failure of it is.
async fn write_literal<const N: u8, A, S, H, P>(
    io: &mut A,
    unwritten: &mut WriteLimit,
    flags: u8,
    literal: StringLiteral<S, H>,
    which: impl FnOnce(
        string_literal::WriteError,
    ) -> EncodeEncoderInstructionError<<A::Family as Write>::Error, P>,
) -> Result<
    <A::Family as Write>::Report,
    EncodeEncoderInstructionError<<A::Family as Write>::Error, P>,
>
where
    A: ReceiverAccess<Family: Write<Report: Combine>>,
    S: for<'a> EncodeInto<Sink<'a, A>, Output = <A::Family as Write>::Report, Error = P>,
    H: Buf,
{
    use encode_encoder_instruction_error::*;
    let length = literal.length();
    let coded = if literal.is_huffman() { 1 << N } else { 0 };
    let head = integer::encode::<N, _>(flags | coded, length).expect(CHECKED);
    match literal.into_bytes() {
        LiteralBytes::Raw(bytes) => {
            let report = instruction::put(io, unwritten, head.as_slice())
                .await
                .context(SendSnafu)?;
            let before = unwritten.0;
            let output = bytes
                .encode_into(Composed::new(&mut *io, &mut *unwritten))
                .await
                .context(PayloadSnafu)?;
            let written = before - unwritten.0;
            if written as u64 != length.value().get() {
                return Err(which(string_literal::WriteError::PayloadLength {
                    expected: length.value().get(),
                    actual: written,
                }));
            }
            Ok(report.combine(output))
        }
        LiteralBytes::Huffman(decoded) => {
            let payload = EncodedBuf::new(decoded, length.value().get());
            instruction::put(io, unwritten, head.as_slice().chain(payload))
                .await
                .context(SendSnafu)
        }
    }
}

/// An encoder instruction could not be written to a stream whose failures
/// are `W`, with raw literals whose failures are `P`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeEncoderInstructionError<W, P> {
    /// An earlier instruction was not finished, or failed after the stream
    /// accepted some of it: the stream is inside it and is abandoned.
    #[snafu(display("encoder stream is inside an unfinished or failed instruction"))]
    Interrupted,
    /// The instruction exceeds the wire limit. Nothing was written.
    #[snafu(transparent)]
    WireLimit {
        /// The instruction's wire length and the limit.
        source: WireLimitError,
    },
    /// The decoded octets of the instruction's literals exceed the decoded
    /// limit. Nothing was written.
    #[snafu(transparent)]
    DecodedLength {
        /// The decoded length and the limit.
        source: DecodedLengthError,
    },
    /// The capacity or index of the instruction has no encoding in its
    /// prefix. Nothing was written.
    #[snafu(display("invalid instruction integer padding"))]
    Integer {
        /// The integer and the prefix width.
        source: PaddingError,
    },
    /// The literal name cannot be written: its length has no encoding in its
    /// prefix or its payload does not hold its length, which is found before
    /// anything is written except for a raw payload.
    #[snafu(display("invalid literal name"))]
    Name {
        /// The literal's failure.
        source: string_literal::WriteError,
    },
    /// The value cannot be written, as for [`Self::Name`].
    #[snafu(display("invalid literal value"))]
    Value {
        /// The literal's failure.
        source: string_literal::WriteError,
    },
    /// The stream did not accept the octets of the instruction.
    #[snafu(display("could not write encoder instruction"))]
    Send {
        /// Write failure and progress within this write.
        source: WriteAllError<W>,
    },
    /// A raw literal failed to write itself.
    #[snafu(display("could not write raw literal"))]
    Payload {
        /// The literal's failure.
        source: P,
    },
}
