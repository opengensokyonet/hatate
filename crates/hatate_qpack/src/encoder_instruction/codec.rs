//! Wire operations used by the encoder stream's parsing states.
use super::{NameReference, literal::Literal};
use crate::{
    instruction::{self, NumberError, OctetError, WireBudget, WireLimitError},
    static_table,
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use snafu::{ResultExt, Snafu};

pub(crate) enum Head {
    Capacity(u64),
    Duplicate(u64),
    Reference(NameReference),
    Literal(Literal),
}

/// An uncompressed literal length exceeded the decoded budget.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "raw instruction literal length {length} exceeds its remaining decoded budget {remaining}"
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
    /// The on-wire length of the uncompressed data.
    pub const fn length(&self) -> u64 {
        self.length
    }
    /// Decoded bytes still permitted at the start of this literal.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }
}

/// An instruction string header was invalid.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LiteralHeaderError<E> {
    #[snafu(display("invalid instruction literal length"))]
    Length { source: NumberError<E> },
    #[snafu(transparent)]
    WireLimit { source: WireLimitError },
    #[snafu(transparent)]
    DecodedLength { source: DecodedLengthError },
}

fn literal_payload<const N: u8, E>(
    wire: &mut WireBudget,
    first: u8,
    length: u64,
    decoded_left: usize,
) -> Result<Literal, LiteralHeaderError<E>> {
    wire.take(length)?;
    let coded = first & (1 << N) != 0;
    if !coded {
        DecodedLengthError::check(length, decoded_left)?;
    }
    // The complete payload fits the caller's usize-sized wire budget.
    Ok(Literal::new(coded, length as usize, decoded_left))
}

/// Failures encountered while starting an encoder instruction.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum StartError<E> {
    /// The shortest possible insertion already exceeds the wire budget.
    /// The name payload and the value prefix have not been consumed.
    #[snafu(transparent)]
    WireLimit { source: WireLimitError },
    /// An earlier instruction was not finished, or failed: the stream is
    /// inside it and is abandoned.
    #[snafu(display("encoder stream is inside an unfinished or failed instruction"))]
    Interrupted,
    #[snafu(display("could not read encoder instruction prefix"))]
    Prefix { source: OctetError<E> },
    #[snafu(display("invalid dynamic table capacity encoding"))]
    Capacity { source: NumberError<E> },
    #[snafu(display("invalid duplicate index encoding"))]
    Duplicate { source: NumberError<E> },
    #[snafu(display("invalid insert name index encoding"))]
    NameIndex { source: NumberError<E> },
    #[snafu(display("invalid static name reference"))]
    StaticName { source: static_table::IndexError },
    #[snafu(display("invalid literal name header"))]
    Name { source: LiteralHeaderError<E> },
}

#[call(sync)]
pub(crate) async fn read_head<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    budget: &mut WireBudget,
    decoded_left: usize,
    first: u8,
) -> Result<Head, StartError<F::Error>> {
    use start_error::*;
    Ok(match first {
        0x80..=0xff => {
            // An unfinished index needs its next digit and the value prefix.
            let index = instruction::checked_number::<6, F, _>(
                io,
                budget,
                first,
                |wire, _| Ok(wire.check(2)?),
                |source| StartError::NameIndex { source },
            )
            .await?;
            budget.check(1)?;
            let name = if first & 0x40 != 0 {
                NameReference::Static(
                    static_table::Index::try_from(index).context(StaticNameSnafu)?,
                )
            } else {
                NameReference::Relative(index)
            };
            Head::Reference(name)
        }
        0x40..=0x7f => {
            // The accumulated name length is a lower bound even before its
            // last digit. Leave room for that digit and the value prefix.
            let length = instruction::checked_number::<5, F, _>(
                io,
                budget,
                first,
                |wire, minimum| Ok(wire.check(u128::from(minimum) + 2)?),
                |source| StartError::Name {
                    source: LiteralHeaderError::Length { source },
                },
            )
            .await?;
            budget.check(u128::from(length) + 1)?;
            Head::Literal(
                literal_payload::<5, _>(budget, first, length, decoded_left).context(NameSnafu)?,
            )
        }
        0x20..=0x3f => Head::Capacity(
            instruction::number::<5, F>(io, budget, first)
                .await
                .context(CapacitySnafu)?,
        ),
        0..=0x1f => Head::Duplicate(
            instruction::number::<5, F>(io, budget, first)
                .await
                .context(DuplicateSnafu)?,
        ),
    })
}

/// Failures reading an insertion's value header.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ValueError<E> {
    #[snafu(display("missing value header"))]
    Prefix { source: OctetError<E> },
    #[snafu(display("invalid literal value header"))]
    Value { source: LiteralHeaderError<E> },
}

#[call(sync)]
pub(crate) async fn read_value_header<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    budget: &mut WireBudget,
    decoded_left: usize,
) -> Result<Literal, ValueError<F::Error>> {
    let first = instruction::octet(io, budget)
        .await
        .context(value_error::PrefixSnafu)?;
    let length = instruction::number::<7, F>(io, budget, first)
        .await
        .context(literal_header_error::LengthSnafu)
        .context(value_error::ValueSnafu)?;
    literal_payload::<7, _>(budget, first, length, decoded_left).context(value_error::ValueSnafu)
}

impl<E> LiteralHeaderError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Length { source } => source.host_error(),
            Self::WireLimit { .. } | Self::DecodedLength { .. } => None,
        }
    }
}

impl<E> StartError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Prefix { source } => source.host_error(),
            Self::Capacity { source } | Self::Duplicate { source } | Self::NameIndex { source } => {
                source.host_error()
            }
            Self::Name { source } => source.host_error(),
            Self::WireLimit { .. } | Self::Interrupted | Self::StaticName { .. } => None,
        }
    }
}

impl<E> ValueError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Prefix { source } => source.host_error(),
            Self::Value { source } => source.host_error(),
        }
    }
}
