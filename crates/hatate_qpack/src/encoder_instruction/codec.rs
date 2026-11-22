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

async fn literal_header<const N: u8, F: Read>(
    io: &mut impl ReceiverAccess<Family = F>,
    wire: &mut WireBudget,
    first: u8,
    decoded_left: usize,
) -> Result<Literal, LiteralHeaderError<F::Error>> {
    let length = instruction::number::<N, F>(io, wire, first)
        .await
        .context(literal_header_error::LengthSnafu)?;
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
    #[snafu(display("encoder stream is inside an unfinished or failed instruction"))]
    NotAtBoundary,
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
            let index = instruction::number::<6, F>(io, budget, first)
                .await
                .context(NameIndexSnafu)?;
            let name = if first & 0x40 != 0 {
                NameReference::Static(
                    static_table::Index::try_from(index).context(StaticNameSnafu)?,
                )
            } else {
                NameReference::Relative(index)
            };
            Head::Reference(name)
        }
        0x40..=0x7f => Head::Literal(
            literal_header::<5, F>(io, budget, first, decoded_left)
                .await
                .context(NameSnafu)?,
        ),
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
    literal_header::<7, F>(io, budget, first, decoded_left)
        .await
        .context(value_error::ValueSnafu)
}
