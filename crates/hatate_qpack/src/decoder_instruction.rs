//! Instructions on the QPACK decoder stream (RFC 9204 §4.4).
//!
//! A [`DecoderInstruction`] is the same type whether it was read or is to be
//! written; its integers keep the padding of their encoding, so an
//! instruction read and written back yields the octets it was read from.
//! A [`DecoderStream`] reads them or writes them, one at a time.
mod read;
mod write;

pub use read::DecodeDecoderInstructionError;
pub use write::EncodeDecoderInstructionError;

use crate::{
    instruction::Position,
    integer::{self, PrefixedField, PrefixedInt},
};
use core::num::NonZeroU64;
use snafu::Snafu;

/// A QUIC stream ID (RFC 9000 §2.1), carried as a QPACK prefixed integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// Numeric stream identifier, at most 2^62 − 1.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for StreamId {
    type Error = StreamIdError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value < 1 << 62 {
            Ok(Self(value))
        } else {
            Err(StreamIdError { value })
        }
    }
}

impl TryFrom<PrefixedInt> for StreamId {
    type Error = StreamIdError;
    fn try_from(value: PrefixedInt) -> Result<Self, Self::Error> {
        Self::try_from(value.get())
    }
}

impl From<StreamId> for PrefixedInt {
    fn from(id: StreamId) -> Self {
        Self::from(id.0)
    }
}

/// A QPACK integer that exceeds the QUIC stream ID range.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("stream ID {value} exceeds 62 bits"))]
pub struct StreamIdError {
    value: u64,
}

impl StreamIdError {
    /// The value received on the wire or passed to the constructor.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// The increment of Insert Count Increment (RFC 9204 §4.4.3): the number of
/// insertions the decoder received since its last increment, never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Increment(NonZeroU64);

impl Increment {
    /// The increment `value`.
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// The number of insertions.
    pub const fn get(self) -> NonZeroU64 {
        self.0
    }
}

impl TryFrom<PrefixedInt> for Increment {
    type Error = ZeroIncrementError;
    fn try_from(value: PrefixedInt) -> Result<Self, Self::Error> {
        NonZeroU64::new(value.get())
            .map(Self)
            .ok_or(ZeroIncrementError)
    }
}

impl From<Increment> for PrefixedInt {
    fn from(increment: Increment) -> Self {
        Self::from(increment.0.get())
    }
}

/// An increment of zero, which Insert Count Increment may not carry (RFC
/// 9204 §4.4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("insert count increment is zero"))]
pub struct ZeroIncrementError;

/// One decoder-stream instruction. Connection state determines whether a
/// stream reference or the resulting known insert count is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecoderInstruction {
    /// Section Acknowledgment (RFC 9204 §4.4.1): a field section on this
    /// stream has been processed.
    SectionAcknowledgment {
        /// The stream of the field section.
        stream_id: PrefixedField<StreamId>,
    },
    /// Stream Cancellation (RFC 9204 §4.4.2): the decoder abandoned
    /// processing of this stream.
    StreamCancellation {
        /// The stream.
        stream_id: PrefixedField<StreamId>,
    },
    /// Insert Count Increment (RFC 9204 §4.4.3): additional dynamic table
    /// insertions received by the decoder.
    InsertCountIncrement {
        /// The number of insertions.
        increment: PrefixedField<Increment>,
    },
}

/// The prefix widths of the three instructions' integers.
const ACKNOWLEDGMENT_BITS: u8 = 7;
const CANCELLATION_BITS: u8 = 6;
const INCREMENT_BITS: u8 = 6;

impl DecoderInstruction {
    /// The octets of the instruction on the wire. Exact for an instruction
    /// whose integer has an encoding in its position, as one read or
    /// constructed for it has.
    pub fn wire_len(&self) -> u64 {
        (match self {
            Self::SectionAcknowledgment { stream_id } => {
                stream_id.encoded_len::<ACKNOWLEDGMENT_BITS>()
            }
            Self::StreamCancellation { stream_id } => stream_id.encoded_len::<CANCELLATION_BITS>(),
            Self::InsertCountIncrement { increment } => increment.encoded_len::<INCREMENT_BITS>(),
        }) as u64
    }
}

/// The limit on the instructions of one decoder stream.
///
/// A stream that reads checks it as each instruction is read; a stream that
/// writes checks it before it writes an instruction. It applies to the
/// instructions after it is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderStreamLimits {
    /// The most wire octets one instruction may take: its first octet and all
    /// continuations.
    pub max_wire_len: usize,
}

/// The longest an instruction can be: one prefixed integer, of at most 11
/// octets, the longest encoding a stream reads.
impl Default for DecoderStreamLimits {
    fn default() -> Self {
        Self {
            max_wire_len: integer::MAX_ENCODED_LEN,
        }
    }
}

/// One decoder stream, read or written instruction by instruction from
/// within a call.
///
/// It is made at an instruction boundary and does nothing until asked for
/// the next instruction. An instruction is decoded from the stream as an
/// `Option<ReadValue<DecoderInstruction, M>>`, `M` being the metadata of the
/// stream's octets, or encoded into it. Each instruction is read whole and
/// handed over by value, or written whole.
///
/// A read dropped before the first octet of an instruction has read nothing,
/// and a write dropped before the stream accepted an octet, or refused
/// before it wrote one, has written nothing: the stream stays at the
/// boundary. An instruction that fails, or whose read or write is dropped
/// after it began, leaves the stream interrupted: it reports an error on
/// every later instruction and is abandoned; [`into_io`](Self::into_io)
/// gives the access back.
#[derive(Debug)]
pub struct DecoderStream<A> {
    io: A,
    position: Position,
    limits: DecoderStreamLimits,
}

impl<A> DecoderStream<A> {
    /// The stream on `io`, an access or an exclusive borrow of one, at an
    /// instruction boundary, with the instructions within `limits`. Nothing
    /// is read or written.
    pub fn new(io: A, limits: DecoderStreamLimits) -> Self {
        Self {
            io,
            position: Position::new(),
            limits,
        }
    }

    /// The limit of the next instruction.
    pub const fn limits(&self) -> DecoderStreamLimits {
        self.limits
    }

    /// Reads or writes the instructions after this call within `limits`.
    pub fn set_limits(&mut self, limits: DecoderStreamLimits) {
        self.limits = limits;
    }

    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.io
    }
}
