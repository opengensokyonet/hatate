//! Shared limits and stream operations for QPACK instructions.
use bytes::Buf;
use core::ops::ControlFlow;
use nitori_call::{Composed, ReceiverAccess};
use nitori_io::{
    Combine, Write,
    adapters::WriteLimit,
    calls::{ReadArrayError, WriteAllError},
    prelude::*,
};
use snafu::{ResultExt, Snafu};

use crate::integer::{self, PrefixedField};

/// An instruction would cross the wire-size limit of its stream.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("instruction needs at least {required} wire bytes, limit is {limit}"))]
pub struct WireLimitError {
    required: u128,
    limit: usize,
}

impl WireLimitError {
    /// Minimum number of bytes required by the operation that failed: the
    /// whole instruction when writing, a lower bound when reading.
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

impl<E> OctetError<E> {
    /// Whether the stream ended cleanly before this octet, with nothing of it
    /// read: at an instruction boundary, the end of the stream.
    pub(crate) fn ended_before_first_octet(&self) -> bool {
        matches!(self, Self::Read { source: ReadArrayError::Incomplete { source } } if source.completed() == 0)
    }
}

pub(crate) async fn octet<F: Read<Metadata = ()>>(
    io: &mut impl ReceiverAccess<Family = F>,
    budget: &mut WireBudget,
) -> Result<u8, OctetError<F::Error>> {
    budget.take(1)?;
    let [byte] = io
        .read_array::<1>()
        .await
        .context(octet_error::ReadSnafu)?
        .value;
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

/// Reads the rest of a prefixed integer of `N` prefix bits whose first octet
/// is `first`, keeping the padding of its encoding.
pub(crate) async fn number<const N: u8, F: Read<Metadata = ()>>(
    io: &mut impl ReceiverAccess<Family = F>,
    budget: &mut WireBudget,
    first: u8,
) -> Result<PrefixedField, NumberError<F::Error>> {
    checked_number::<N, F, _>(io, budget, first, |_, _| Ok(()), core::convert::identity).await
}

// The containing representation can already imply a minimum size while the
// integer still needs another digit. Run its check before requesting that digit.
pub(crate) async fn checked_number<const N: u8, F: Read<Metadata = ()>, E>(
    io: &mut impl ReceiverAccess<Family = F>,
    budget: &mut WireBudget,
    first: u8,
    before_digit: impl Fn(&WireBudget, u64) -> Result<(), E>,
    number_error: impl Fn(NumberError<F::Error>) -> E,
) -> Result<PrefixedField, E> {
    let mut state = match integer::Continuation::start::<N>(first) {
        ControlFlow::Break(value) => {
            return Ok(PrefixedField::shortest(integer::PrefixedInt::from(value)));
        }
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
            return Ok(state.field::<N>(value));
        }
    }
}

impl<E> OctetError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Read { source } => source.host_error(),
            Self::WireLimit { .. } => None,
        }
    }
}

impl<E> NumberError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Continuation { source } => source.host_error(),
            Self::Integer { .. } => None,
        }
    }
}

/// Where an instruction stream is, for its reads and its writes.
///
/// A read is inside an instruction from its first octet on. A write is
/// inside one once the stream has accepted an octet of it: what is left of
/// the instruction is counted down in `unwritten`, the composition state of
/// the sink it is written to, which outlives a write that is dropped.
#[derive(Debug)]
pub(crate) struct Position {
    state: State,
    /// The octets of the instruction being written that the stream has not
    /// accepted yet.
    pub(crate) unwritten: WriteLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// At an instruction boundary.
    Boundary,
    /// Inside an instruction that was not finished, or one that failed.
    Interrupted,
    /// Writing an instruction of `length` octets, or a write of one that
    /// ended before it finished.
    Writing { length: usize },
}

impl Position {
    pub(crate) const fn new() -> Self {
        Self {
            state: State::Boundary,
            unwritten: WriteLimit(0),
        }
    }

    /// Settle a write that ended without finishing: at the boundary if the
    /// stream accepted none of its octets, interrupted otherwise.
    pub(crate) fn settle(&mut self) {
        if let State::Writing { length } = self.state {
            self.state = if self.unwritten.0 == length {
                State::Boundary
            } else {
                State::Interrupted
            };
        }
    }

    /// Whether the stream is at an instruction boundary, after settling a
    /// write that was dropped.
    pub(crate) fn at_boundary(&mut self) -> bool {
        self.settle();
        self.state == State::Boundary
    }

    /// Enter an instruction being read.
    pub(crate) fn interrupt(&mut self) {
        self.state = State::Interrupted;
    }

    /// Return to the boundary after a whole instruction.
    pub(crate) fn finish(&mut self) {
        self.state = State::Boundary;
    }

    /// Start writing an instruction of `length` octets.
    pub(crate) fn begin_write(&mut self, length: usize) {
        self.unwritten = WriteLimit(length);
        self.state = State::Writing { length };
    }
}

/// The sink an instruction is written into: the stream's access, held to the
/// octets of the instruction not written yet.
pub(crate) type Sink<'a, A> = Composed<&'a mut A, &'a mut WriteLimit>;

/// Writes `bytes` whole into the stream's access, counting them off
/// `unwritten`.
pub(crate) async fn put<A: ReceiverAccess<Family: Write<Report: Combine>>>(
    io: &mut A,
    unwritten: &mut WriteLimit,
    bytes: impl Buf,
) -> Result<<A::Family as Write>::Report, WriteAllError<<A::Family as Write>::Error>> {
    let mut sink: Sink<'_, A> = Composed::new(io, unwritten);
    sink.write_all(bytes).await
}
