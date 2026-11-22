//! Shared limits and stream operations for QPACK instructions.
use core::ops::ControlFlow;
use nitori_call::ReceiverAccess;
use nitori_io::{calls::ReadArrayError, prelude::*};
use snafu::{ResultExt, Snafu};

use crate::integer;

/// A read would cross the wire-size limit of the current instruction.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("instruction needs at least {required} wire bytes, limit is {limit}"))]
pub struct WireLimitError {
    required: u128,
    limit: usize,
}

impl WireLimitError {
    /// Minimum number of bytes required by the operation that failed.
    pub const fn required(&self) -> u128 {
        self.required
    }
    /// Caller-supplied wire-size limit for one instruction.
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

pub(crate) struct WireBudget {
    maximum: usize,
    consumed: usize,
}

impl WireBudget {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            maximum,
            consumed: 0,
        }
    }

    pub(crate) fn check(&self, bytes: u128) -> Result<(), WireLimitError> {
        let required = self.consumed as u128 + bytes;
        if required > self.maximum as u128 {
            return Err(WireLimitError {
                required,
                limit: self.maximum,
            });
        }
        Ok(())
    }

    pub(crate) fn take(&mut self, bytes: u64) -> Result<(), WireLimitError> {
        self.check(u128::from(bytes))?;
        self.consumed += bytes as usize;
        Ok(())
    }
}

/// Reading one octet of an instruction failed.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum OctetError<E> {
    /// The next octet would exceed the instruction's wire budget.
    #[snafu(transparent)]
    WireLimit {
        /// Wire-size shortfall.
        source: WireLimitError,
    },
    /// EOF or a host error occurred while reading this octet.
    #[snafu(display("could not read an instruction octet"))]
    Read {
        /// Underlying read failure.
        source: ReadArrayError<E>,
    },
}

pub(crate) async fn octet<F: Read>(
    io: &mut impl ReceiverAccess<Family = F>,
    budget: &mut WireBudget,
) -> Result<u8, OctetError<F::Error>> {
    budget.take(1)?;
    let [byte] = io.read_array::<1>().await.context(octet_error::ReadSnafu)?;
    Ok(byte)
}

/// Reading continuation octets or interpreting their value failed.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum NumberError<E> {
    /// A continuation octet could not be read.
    #[snafu(display("could not read an integer continuation"))]
    Continuation {
        /// Underlying read or limit failure.
        source: OctetError<E>,
    },
    /// The numeric value or its encoding exceeds its implementation limit.
    #[snafu(display("invalid prefixed integer in instruction"))]
    Integer {
        /// The integer decoding failure.
        source: integer::ReadError,
    },
}

pub(crate) async fn number<const N: u8, F: Read>(
    io: &mut impl ReceiverAccess<Family = F>,
    budget: &mut WireBudget,
    first: u8,
) -> Result<u64, NumberError<F::Error>> {
    checked_number::<N, F, _>(io, budget, first, |_, _| Ok(()), core::convert::identity).await
}

// The containing representation can already imply a minimum size while the
// integer still needs another digit. Run its check before requesting that digit.
pub(crate) async fn checked_number<const N: u8, F: Read, E>(
    io: &mut impl ReceiverAccess<Family = F>,
    budget: &mut WireBudget,
    first: u8,
    before_digit: impl Fn(&WireBudget, u64) -> Result<(), E>,
    number_error: impl Fn(NumberError<F::Error>) -> E,
) -> Result<u64, E> {
    let mut state = match integer::Continuation::start::<N>(first) {
        ControlFlow::Break(value) => return Ok(value),
        ControlFlow::Continue(state) => state,
    };
    loop {
        before_digit(budget, state.minimum())?;
        let byte = octet(io, budget)
            .await
            .context(number_error::ContinuationSnafu)
            .map_err(&number_error)?;
        if let Some(value) = state
            .push(byte)
            .context(number_error::IntegerSnafu)
            .map_err(&number_error)?
        {
            return Ok(value);
        }
    }
}

/// Shortest wire encoding of one QPACK prefixed integer.
pub(crate) struct EncodedInteger {
    bytes: [u8; integer::MAX_ENCODED_LEN],
    len: usize,
}

impl EncodedInteger {
    pub(crate) fn new<const N: u8>(prefix: u8, value: u64) -> Self {
        let mut bytes = [0; integer::MAX_ENCODED_LEN];
        let mut rest = &mut bytes[..];
        integer::write::<N>(&mut rest, prefix, value).expect("buffer fits every encoded u64");
        let len = integer::MAX_ENCODED_LEN - rest.len();
        Self { bytes, len }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
